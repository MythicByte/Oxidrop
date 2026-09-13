use std::sync::Arc;

use axum::{
    body::Body,
    extract::Request,
    http::{
        Method,
        StatusCode,
    },
};
use axum_login::AuthManagerLayerBuilder;
use aya::maps::{
    Array,
    HashMap,
    LpmTrie,
};
use oxidrop::{
    Opt,
    db::{
        ActionPermissions,
        Database,
        RolesUser,
    },
    state::{
        FirewallState,
        LogStore,
        config_router,
    },
};
use oxidrop_common::{
    Action,
    AllowListState,
    FirewallConfig,
    Ipv4Packet,
    Ipv6Packet,
    TokenBucketState,
};
use sqlx::Row;
use tower::ServiceExt;
use tower_sessions::{
    MemoryStore,
    SessionManagerLayer,
};

async fn state() -> FirewallState {
    let db = Database::new("sqlite::memory:")
        .await
        .expect("workflow database must initialize");
    db.bootstrap_default_admin()
        .await
        .expect("workflow database must bootstrap");
    let mut config = Array::create(1, 0).expect("workflow CONFIG map must initialize");
    let allow_v4 = HashMap::create(4096, 0).expect("workflow IPv4 state map must initialize");
    let allow_v6 = HashMap::create(4096, 0).expect("workflow IPv6 state map must initialize");
    let counts_v4 = HashMap::create(4096, 0).expect("workflow IPv4 counter map must initialize");
    let counts_v6 = HashMap::create(4096, 0).expect("workflow IPv6 counter map must initialize");
    let subnet_v4 = LpmTrie::create(2048, 1).expect("workflow IPv4 subnet map must initialize");
    let subnet_v6 = LpmTrie::create(2048, 1).expect("workflow IPv6 subnet map must initialize");
    config
        .set(0, FirewallConfig::default(), 0)
        .expect("workflow CONFIG map must accept defaults");

    FirewallState {
        db: db.clone(),
        config: Arc::new(tokio::sync::RwLock::new(config)),
        allow_list_v4: Arc::new(tokio::sync::RwLock::new(allow_v4)),
        allow_list_v6: Arc::new(tokio::sync::RwLock::new(allow_v6)),
        packet_counts_v4: Arc::new(tokio::sync::RwLock::new(counts_v4)),
        packet_counts_v6: Arc::new(tokio::sync::RwLock::new(counts_v6)),
        subnet_matching_v4: Arc::new(tokio::sync::RwLock::new(subnet_v4)),
        subnet_matching_v6: Arc::new(tokio::sync::RwLock::new(subnet_v6)),
        logs: Arc::new(LogStore::new(db)),
        ebpf: None,
        opt: Opt {
            http_port: 0,
            incoming_adapter: None,
            output_adapter: None,
        },
    }
}

async fn request(
    state: FirewallState,
    method: Method,
    path: &str,
    body: Option<String>,
    permissions: ActionPermissions,
) -> (StatusCode, String) {
    let has_body = body.is_some();
    let username = format!("workflow_{}", uuid_suffix());
    sqlx::query(
        "INSERT INTO users (username, password_hash, role, action_permissions, password_must_be_changed, is_active) VALUES (?, ?, ?, ?, 0, 1)",
    )
    .bind(&username)
    .bind("test")
    .bind("admin")
    .bind(permissions.bits())
    .execute(&state.db.pool)
    .await
    .expect("workflow user must be insertable");
    let row = sqlx::query("SELECT id FROM users WHERE username = ?")
        .bind(&username)
        .fetch_one(&state.db.pool)
        .await
        .expect("workflow user id must be queryable");
    let user = oxidrop::auth::AppUser {
        id: row.get("id"),
        username,
        role: RolesUser::Admin,
        permissions,
        password_hash: "test".to_string(),
        password_must_be_changed: false,
    };
    let sessions = SessionManagerLayer::new(MemoryStore::default());
    let auth = AuthManagerLayerBuilder::new(state.db.clone(), sessions).build();
    let app = config_router()
        .route(
            "/__login",
            axum::routing::get({
                let user = user.clone();
                move |mut session: axum_login::AuthSession<Database>| async move {
                    session
                        .login(&user)
                        .await
                        .expect("workflow login must succeed");
                    StatusCode::OK
                }
            }),
        )
        .with_state(state)
        .layer(auth);
    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/__login")
                .body(Body::empty())
                .expect("workflow login request must build"),
        )
        .await
        .expect("workflow login request must execute");
    let cookie = login
        .headers()
        .get("set-cookie")
        .expect("workflow login must return a session cookie")
        .clone();
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("cookie", cookie)
        .body(Body::from(body.unwrap_or_default()))
        .expect("workflow request must build");
    if has_body {
        request.headers_mut().insert(
            "content-type",
            "application/json".parse().expect("content type must parse"),
        );
    }
    let response = app
        .oneshot(request)
        .await
        .expect("workflow request must execute");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("workflow response body must be readable");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn uuid_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after epoch")
        .as_nanos()
}

#[tokio::test]
async fn api_workflow_persists_config_and_rejects_invalid_transitions() {
    let state = state().await;
    let admin = ActionPermissions::MODIFY | ActionPermissions::DELETE;
    let patch = serde_json::json!({
        "subnet_activated": true,
        "ddos_activated": true,
        "tcp_profile": {"rate_shift": 20, "burst": 3}
    });
    let (status, body) = request(
        state.clone(),
        Method::POST,
        "/",
        Some(patch.to_string()),
        admin,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "valid config update must succeed: {body}"
    );
    let (status, body) = request(state.clone(), Method::GET, "/", None, admin).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "config must remain readable: {body}"
    );
    let config: FirewallConfig = serde_json::from_str(&body).expect("config response must decode");
    assert!(config.subnet_activated, "subnet activation must persist");
    assert_eq!(config.tcp_profile.burst, 3, "TCP burst must persist");

    let invalid = serde_json::json!({
        "tcp_profile": {"rate_shift": 64, "burst": 0}
    });
    let (status, body) = request(
        state.clone(),
        Method::POST,
        "/",
        Some(invalid.to_string()),
        admin,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid rate profile must be rejected without mutation: {body}"
    );
    let subnet = serde_json::json!({
        "network": u32::from_be_bytes([10, 20, 30, 0]),
        "prefix_len": 24,
        "action": "Allow"
    });
    let (status, body) = request(
        state.clone(),
        Method::POST,
        "/subnet/v4",
        Some(subnet.to_string()),
        admin,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "valid subnet must be persisted: {body}"
    );
    let (status, body) = request(
        state.clone(),
        Method::DELETE,
        "/subnet/v4",
        Some(subnet.to_string()),
        admin,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "subnet deletion must be persisted: {body}"
    );
}

#[tokio::test]
async fn api_workflow_enforces_permissions_and_clears_state() {
    let state = state().await;
    let entry = serde_json::json!({
        "key": {
            "source_addr": 10,
            "destination_addr": 20,
            "source_port": 1234,
            "destination_port": 443,
            "protocol": 6
        },
        "state": {"action": "Allow", "last_seen": 0}
    });
    let no_modify = ActionPermissions::DELETE;
    let (status, body) = request(
        state.clone(),
        Method::POST,
        "/allow_list/v4",
        Some(entry.to_string()),
        no_modify,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "user without MODIFY must not insert flow state: {body}"
    );

    let admin = ActionPermissions::MODIFY | ActionPermissions::DELETE;
    let (status, body) = request(
        state.clone(),
        Method::POST,
        "/allow_list/v4",
        Some(entry.to_string()),
        admin,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin must insert flow state: {body}"
    );
    let (status, body) = request(state.clone(), Method::GET, "/allow_list/v4", None, admin).await;
    assert_eq!(status, StatusCode::OK, "admin must list flow state: {body}");
    let entries: Vec<(Ipv4Packet, AllowListState)> =
        serde_json::from_str(&body).expect("flow state response must decode");
    assert_eq!(entries.len(), 1, "exactly one flow state must be present");

    let (status, body) =
        request(state.clone(), Method::DELETE, "/allow_list/v4", None, admin).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin must clear flow state: {body}"
    );
    let (status, body) = request(state.clone(), Method::GET, "/allow_list/v4", None, admin).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "cleared state must remain readable: {body}"
    );
    let entries: Vec<(Ipv4Packet, AllowListState)> =
        serde_json::from_str(&body).expect("cleared flow response must decode");
    assert!(
        entries.is_empty(),
        "clearing flow state must remove every entry"
    );

    let _ = (
        Action::Allow,
        Ipv6Packet::new([0; 4], [0; 4], 0, 0, 58),
        TokenBucketState {
            tokens: 0,
            last_update: 0,
        },
    );
}

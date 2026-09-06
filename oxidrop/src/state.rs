use std::sync::Arc;

use axum::{
    Json,
    Router,
    extract::State,
    response::IntoResponse,
    routing::{
        get,
        post,
    },
};
use aya::maps::{
    Array,
    HashMap,
    LpmTrie,
    MapData,
    lpm_trie::Key,
};
use hyper::StatusCode;
use oxidrop_common::{
    Action,
    ActivaterEtherTypes,
    AllowListState,
    FirewallConfig,
    Ipv4Packet,
    Ipv6Packet,
    RateProfile,
    TokenBucketState,
};
use serde::{
    Deserialize,
    Serialize,
};
use tokio::sync::RwLock;

use crate::db::Database;

/// Firewall internal state
#[derive(Clone)]
pub struct FirewallState {
    pub db: Database,
    pub config: Arc<RwLock<Array<MapData, FirewallConfig>>>,
    pub allow_list_v4: Arc<RwLock<HashMap<MapData, Ipv4Packet, AllowListState>>>,
    pub allow_list_v6: Arc<RwLock<HashMap<MapData, Ipv6Packet, AllowListState>>>,
    pub packet_counts_v4: Arc<RwLock<HashMap<MapData, Ipv4Packet, TokenBucketState>>>,
    pub packet_counts_v6: Arc<RwLock<HashMap<MapData, Ipv6Packet, TokenBucketState>>>,
    pub subnet_matching_v4: Arc<RwLock<LpmTrie<MapData, u32, Action>>>,
    pub subnet_matching_v6: Arc<RwLock<LpmTrie<MapData, [u32; 4], Action>>>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AllowListV4Update {
    pub key: Ipv4Packet,
    pub state: AllowListState,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AllowListV6Update {
    pub key: Ipv6Packet,
    pub state: AllowListState,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PacketCountV4Update {
    pub key: Ipv4Packet,
    pub state: TokenBucketState,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PacketCountV6Update {
    pub key: Ipv6Packet,
    pub state: TokenBucketState,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SubnetMatchV4Update {
    pub network: u32,
    pub prefix_len: u32,
    pub action: Action,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubnetMatchV6Update {
    pub network: [u32; 4],
    pub prefix_len: u32,
    pub action: Action,
}

// But we need a "patch-style" request type that allows partial updates
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigPatch {
    // All fields optional — only specified fields get updated
    #[serde(default)]
    pub tcp_profile: Option<RateProfile>,
    #[serde(default)]
    pub udp_profile: Option<RateProfile>,
    #[serde(default)]
    pub icmp_profile: Option<RateProfile>,
    #[serde(default)]
    pub default_profile: Option<RateProfile>,
    #[serde(default)]
    pub protcol_allowed: Option<ActivaterEtherTypes>,
    #[serde(default)]
    pub ddos_activated: Option<bool>,
    #[serde(default)]
    pub incoming_ethernet_adapter: Option<u32>,
    #[serde(default)]
    pub output_ethernet_adapter: Option<u32>,
}

const MAX_RATE_SHIFT: u64 = 63;

impl ConfigPatch {
    fn validate(&self) -> Result<(), &'static str> {
        let profiles = [
            &self.tcp_profile,
            &self.udp_profile,
            &self.icmp_profile,
            &self.default_profile,
        ];
        for profile in profiles.into_iter().flatten() {
            if profile.rate_shift > MAX_RATE_SHIFT {
                return Err("rate_shift must be between 0 and 63");
            }
        }
        Ok(())
    }

    fn apply(self, cfg: &mut FirewallConfig) {
        if let Some(p) = self.tcp_profile {
            cfg.tcp_profile = p;
        }
        if let Some(p) = self.udp_profile {
            cfg.udp_profile = p;
        }
        if let Some(p) = self.icmp_profile {
            cfg.icmp_profile = p;
        }
        if let Some(p) = self.default_profile {
            cfg.default_profile = p;
        }
        if let Some(types) = self.protcol_allowed {
            cfg.protocol_allowed = types;
        }
        if let Some(activated) = self.ddos_activated {
            cfg.ddos_activated = activated;
        }
        if let Some(adapter) = self.incoming_ethernet_adapter {
            cfg.incoming_ethernet_adapter = Some(adapter);
        }
        if let Some(adapter) = self.output_ethernet_adapter {
            cfg.output_ethernet_adapter = Some(adapter);
        }
    }
}

/// get config from the firewall
pub async fn get_config(State(state): State<FirewallState>) -> impl IntoResponse {
    match state.config.read().await.get(&0, 0) {
        Ok(cfg) => Json(cfg).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "CONFIG map not initialized",
        )
            .into_response(),
    }
}

/// update firewall config
pub async fn update_config(
    State(state): State<FirewallState>,
    Json(patch): Json<ConfigPatch>,
) -> impl IntoResponse {
    if let Err(msg) = patch.validate() {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    let mut config = state.config.write().await;
    let mut cfg = match config.get(&0, 0) {
        Ok(cfg) => cfg,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CONFIG map not initialized",
            )
                .into_response();
        }
    };

    patch.apply(&mut cfg);

    if config.set(0, &cfg, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update CONFIG map",
        )
            .into_response();
    }

    Json(cfg).into_response()
}
/// GET: Fetch all items in the IPv4 Allow List
pub async fn get_allow_list_v4(State(state): State<FirewallState>) -> impl IntoResponse {
    let map = state.allow_list_v4.read().await;

    let mut entries = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, value)) = item {
            entries.push((key, value));
        }
    }

    Json(entries).into_response()
}

/// POST/PUT: Insert or update an item
pub async fn modify_allow_list_v4(
    State(state): State<FirewallState>,
    Json(payload): Json<AllowListV4Update>,
) -> impl IntoResponse {
    let mut map = state.allow_list_v4.write().await;

    if map.insert(&payload.key, &payload.state, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to insert into ALLOW_LIST_V4 map",
        )
            .into_response();
    }

    StatusCode::OK.into_response()
}

/// DELETE: Clear all entries in the list
pub async fn clear_allow_list_v4(State(state): State<FirewallState>) -> impl IntoResponse {
    let mut map = state.allow_list_v4.write().await;

    let mut keys_to_remove = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, _)) = item {
            keys_to_remove.push(key);
        }
    }

    for key in keys_to_remove {
        let _ = map.remove(&key);
    }

    StatusCode::OK.into_response()
}

/// GET: Fetch all items in the IPv4 Allow List
pub async fn get_allow_list_v6(State(state): State<FirewallState>) -> impl IntoResponse {
    let map = state.allow_list_v6.read().await;

    let mut entries = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, value)) = item {
            entries.push((key, value));
        }
    }

    Json(entries).into_response()
}

/// POST/PUT: Insert or update an item
pub async fn modify_allow_list_v6(
    State(state): State<FirewallState>,
    Json(payload): Json<AllowListV6Update>,
) -> impl IntoResponse {
    let mut map = state.allow_list_v6.write().await;

    if map.insert(&payload.key, &payload.state, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to insert into ALLOW_LIST_V6 map",
        )
            .into_response();
    }

    StatusCode::OK.into_response()
}

/// DELETE: Clear all entries in the list
pub async fn clear_allow_list_v6(State(state): State<FirewallState>) -> impl IntoResponse {
    let mut map = state.allow_list_v6.write().await;

    let mut keys_to_remove = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, _)) = item {
            keys_to_remove.push(key);
        }
    }

    for key in keys_to_remove {
        let _ = map.remove(&key);
    }

    StatusCode::OK.into_response()
}

pub async fn get_packet_counts_v4(State(state): State<FirewallState>) -> impl IntoResponse {
    let map = state.packet_counts_v4.read().await;

    let mut entries = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, value)) = item {
            entries.push((key, value));
        }
    }
    Json(entries).into_response()
}

pub async fn modify_packet_counts_v4(
    State(state): State<FirewallState>,
    Json(payload): Json<PacketCountV4Update>,
) -> impl IntoResponse {
    let mut map = state.packet_counts_v4.write().await;

    if map.insert(&payload.key, &payload.state, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to insert into PACKET_COUNTS_V4 map",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}

pub async fn clear_packet_counts_v4(State(state): State<FirewallState>) -> impl IntoResponse {
    let mut map = state.packet_counts_v4.write().await;

    let mut keys_to_remove = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, _)) = item {
            keys_to_remove.push(key);
        }
    }
    for key in keys_to_remove {
        let _ = map.remove(&key);
    }
    StatusCode::OK.into_response()
}
pub async fn get_packet_counts_v6(State(state): State<FirewallState>) -> impl IntoResponse {
    let map = state.packet_counts_v6.read().await;

    let mut entries = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, value)) = item {
            entries.push((key, value));
        }
    }
    Json(entries).into_response()
}

pub async fn modify_packet_counts_v6(
    State(state): State<FirewallState>,
    Json(payload): Json<PacketCountV6Update>,
) -> impl IntoResponse {
    let mut map = state.packet_counts_v6.write().await;

    if map.insert(&payload.key, &payload.state, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to insert into PACKET_COUNTS_V6 map",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}

pub async fn clear_packet_counts_v6(State(state): State<FirewallState>) -> impl IntoResponse {
    let mut map = state.packet_counts_v6.write().await;

    let mut keys_to_remove = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, _)) = item {
            keys_to_remove.push(key);
        }
    }
    for key in keys_to_remove {
        let _ = map.remove(&key);
    }
    StatusCode::OK.into_response()
}
pub async fn modify_subnet_matching_v4(
    State(state): State<FirewallState>,
    Json(payload): Json<SubnetMatchV4Update>,
) -> impl IntoResponse {
    if payload.prefix_len > 32 {
        return (
            StatusCode::BAD_REQUEST,
            "prefix_len must be between 0 and 32 for an IPv4 subnet",
        )
            .into_response();
    }

    let mut map = state.subnet_matching_v4.write().await;

    let key = Key::new(payload.prefix_len, payload.network);
    if map.insert(&key, payload.action, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to insert into SUBNET_MATCHING_V4",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}

pub async fn remove_subnet_matching_v4(
    State(state): State<FirewallState>,
    Json(payload): Json<SubnetMatchV4Update>,
) -> impl IntoResponse {
    if payload.prefix_len > 32 {
        return (
            StatusCode::BAD_REQUEST,
            "prefix_len must be between 0 and 32 for an IPv4 subnet",
        )
            .into_response();
    }

    let mut map = state.subnet_matching_v4.write().await;

    let key = Key::new(payload.prefix_len, payload.network);
    if map.remove(&key).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to remove from SUBNET_MATCHING_V4",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}

pub async fn modify_subnet_matching_v6(
    State(state): State<FirewallState>,
    Json(payload): Json<SubnetMatchV6Update>,
) -> impl IntoResponse {
    if payload.prefix_len > 128 {
        return (
            StatusCode::BAD_REQUEST,
            "prefix_len must be between 0 and 128 for an IPv6 subnet",
        )
            .into_response();
    }

    let mut map = state.subnet_matching_v6.write().await;

    let key = Key::new(payload.prefix_len, payload.network);
    if map.insert(&key, payload.action, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to insert into SUBNET_MATCHING_V6",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}

pub async fn remove_subnet_matching_v6(
    State(state): State<FirewallState>,
    Json(payload): Json<SubnetMatchV6Update>,
) -> impl IntoResponse {
    if payload.prefix_len > 128 {
        return (
            StatusCode::BAD_REQUEST,
            "prefix_len must be between 0 and 128 for an IPv6 subnet",
        )
            .into_response();
    }

    let mut map = state.subnet_matching_v6.write().await;

    let key = Key::new(payload.prefix_len, payload.network);
    if map.remove(&key).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to remove from SUBNET_MATCHING_V6",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}
/// Router for config
pub fn config_router() -> Router<FirewallState> {
    Router::new()
        .route("/", get(get_config).post(update_config))
        .route(
            "/allow_list/v4",
            get(get_allow_list_v4)
                .post(modify_allow_list_v4)
                .delete(clear_allow_list_v4),
        )
        .route(
            "/allow_list/v6",
            get(get_allow_list_v6)
                .post(modify_allow_list_v6)
                .delete(clear_allow_list_v6),
        )
        // Packet Counts
        .route(
            "/packet_counts/v4",
            get(get_packet_counts_v4)
                .post(modify_packet_counts_v4)
                .delete(clear_packet_counts_v4),
        )
        .route(
            "/packet_counts/v6",
            get(get_packet_counts_v6)
                .post(modify_packet_counts_v6)
                .delete(clear_packet_counts_v6),
        )
        // Subnets (Notice: No GET or bulk DELETE)
        .route(
            "/subnet/v4",
            post(modify_subnet_matching_v4).delete(remove_subnet_matching_v4),
        )
        .route(
            "/subnet/v6",
            post(modify_subnet_matching_v6).delete(remove_subnet_matching_v6),
        )
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{
            Body,
            to_bytes,
        },
        extract::Request,
    };
    use hyper::Method;
    use tower::ServiceExt;

    use super::*;
    const BPF_F_NO_PREALLOC: u32 = 1;

    // Helper to create a test firewall state
    async fn create_test_state() -> FirewallState {
        let mut config_map = Array::<MapData, FirewallConfig>::create(1, 0).unwrap();
        let default_config = FirewallConfig::default();
        config_map.set(0, &default_config, 0).unwrap();

        let allow_list_v4 =
            HashMap::<MapData, Ipv4Packet, AllowListState>::create(4096, 0).unwrap();
        let allow_list_v6 =
            HashMap::<MapData, Ipv6Packet, AllowListState>::create(4096, 0).unwrap();
        let packet_counts_v4 =
            HashMap::<MapData, Ipv4Packet, TokenBucketState>::create(4096, 0).unwrap();
        let packet_counts_v6 =
            HashMap::<MapData, Ipv6Packet, TokenBucketState>::create(4096, 0).unwrap();
        let subnet_matching_v4 =
            LpmTrie::<MapData, u32, Action>::create(2048, BPF_F_NO_PREALLOC).unwrap();
        let subnet_matching_v6 =
            LpmTrie::<MapData, [u32; 4], Action>::create(2048, BPF_F_NO_PREALLOC).unwrap();

        // Actually initialize an in-memory database instead of pretending it implements Default
        let db = crate::db::Database::new("sqlite::memory:")
            .await
            .expect("Failed to create test DB");

        FirewallState {
            db,
            config: Arc::new(RwLock::new(config_map)),
            allow_list_v4: Arc::new(RwLock::new(allow_list_v4)),
            allow_list_v6: Arc::new(RwLock::new(allow_list_v6)),
            packet_counts_v4: Arc::new(RwLock::new(packet_counts_v4)),
            packet_counts_v6: Arc::new(RwLock::new(packet_counts_v6)),
            subnet_matching_v4: Arc::new(RwLock::new(subnet_matching_v4)),
            subnet_matching_v6: Arc::new(RwLock::new(subnet_matching_v6)),
        }
    }

    // Helper to make HTTP requests to the router
    async fn make_request(
        router: &axum::Router,
        method: Method,
        path: &str,
        body_opt: Option<String>,
    ) -> (StatusCode, String) {
        let has_body = body_opt.is_some();
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::from(body_opt.unwrap_or_default()))
            .unwrap();

        if has_body {
            req.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
        }

        // Axum routers implement tower::Service. Use oneshot for tests.
        let response = router.clone().oneshot(req).await.unwrap();
        let status = response.status();

        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);

        (status, body_str.to_string())
    }

    #[tokio::test]
    async fn test_config_endpoint() {
        let state = create_test_state().await;
        let router = config_router().with_state(state.clone());

        let (status, body) = make_request(&router, Method::GET, "/", None).await;
        assert_eq!(status, StatusCode::OK);

        let config: FirewallConfig = serde_json::from_str(&body).unwrap();
        assert!(config.ddos_activated);
        assert_eq!(
            config.protocol_allowed,
            ActivaterEtherTypes::IPV4 | ActivaterEtherTypes::IPV6
        );

        let patch = serde_json::json!({
            "tcp_profile": {
                "rate_shift": 21,
                "burst": 500
            },
            "ddos_activated": false
        });

        let (status, _) = make_request(&router, Method::POST, "/", Some(patch.to_string())).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = make_request(&router, Method::GET, "/", None).await;
        assert_eq!(status, StatusCode::OK);
        let config: FirewallConfig = serde_json::from_str(&body).unwrap();
        assert_eq!(config.tcp_profile.rate_shift, 21);
        assert_eq!(config.tcp_profile.burst, 500);
        assert!(!config.ddos_activated);
    }

    #[tokio::test]
    async fn test_allow_list_v4_lifecycle() {
        let state = create_test_state().await;
        let router = config_router().with_state(state.clone());

        let entry = serde_json::json!({
            "key": {
                "source_addr": 16843264,
                "destination_addr": 16843265,
                "source_port": 12345,
                "destination_port": 80,
                "protocol": 6
            },
            "state": {
                "action": "Allow",
                "last_seen": 1000000000
            }
        });

        let (status, _) = make_request(
            &router,
            Method::POST,
            "/allow_list/v4",
            Some(entry.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = make_request(&router, Method::GET, "/allow_list/v4", None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv4Packet, AllowListState)> = serde_json::from_str(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.source_addr, 16843264);
        assert_eq!(entries[0].1.action, Action::Allow);

        let (status, _) = make_request(&router, Method::DELETE, "/allow_list/v4", None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = make_request(&router, Method::GET, "/allow_list/v4", None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv4Packet, AllowListState)> = serde_json::from_str(&body).unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_subnet_matching_v4() {
        let state = create_test_state().await;
        let router = config_router().with_state(state.clone());

        let rule = serde_json::json!({
            "network": 16843264,
            "prefix_len": 24,
            "action": "Allow"
        });

        let (status, _) =
            make_request(&router, Method::POST, "/subnet/v4", Some(rule.to_string())).await;
        assert_eq!(status, StatusCode::OK);

        let key = aya::maps::lpm_trie::Key::new(24, 16843264);
        {
            let subnet_map = state.subnet_matching_v4.read().await;
            let action = subnet_map.get(&key, 0).unwrap();
            assert_eq!(action, Action::Allow);
        }

        let (status, _) = make_request(
            &router,
            Method::DELETE,
            "/subnet/v4",
            Some(rule.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let subnet_map = state.subnet_matching_v4.read().await;
        assert!(subnet_map.get(&key, 0).is_err());
    }

    #[tokio::test]
    async fn test_rate_limiting_state() {
        let state = create_test_state().await;
        let router = config_router().with_state(state.clone());

        let entry = serde_json::json!({
            "key": {
                "source_addr": 16843264,
                "destination_addr": 16843265,
                "source_port": 12345,
                "destination_port": 80,
                "protocol": 6
            },
            "state": {
                "tokens": 100,
                "last_update": 1000000000
            }
        });

        let (status, _) = make_request(
            &router,
            Method::POST,
            "/packet_counts/v4",
            Some(entry.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = make_request(&router, Method::GET, "/packet_counts/v4", None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv4Packet, TokenBucketState)> = serde_json::from_str(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.tokens, 100);

        let (status, _) = make_request(&router, Method::DELETE, "/packet_counts/v4", None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = make_request(&router, Method::GET, "/packet_counts/v4", None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv4Packet, TokenBucketState)> = serde_json::from_str(&body).unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_invalid_config_updates() {
        let state = create_test_state().await;
        let router = config_router().with_state(state.clone());

        let (status, _) =
            make_request(&router, Method::POST, "/", Some("invalid json".to_string())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let patch = serde_json::json!({
            "tcp_profile": {
                "rate_shift": 1000,
                "burst": 500
            }
        });

        let (status, _) = make_request(&router, Method::POST, "/", Some(patch.to_string())).await;
        assert_ne!(status, StatusCode::OK); // Expect invalid rate_shift to be rejected

        let rule = serde_json::json!({
            "network": 16843264,
            "prefix_len": 33,
            "action": "Allow"
        });

        let (status, _) =
            make_request(&router, Method::POST, "/subnet/v4", Some(rule.to_string())).await;
        assert_ne!(status, StatusCode::OK); // Expect invalid prefix_len (33) to be rejected

        let subnet_map = state.subnet_matching_v4.read().await;
        let key = aya::maps::lpm_trie::Key::new(33, 16843264);
        assert!(subnet_map.get(&key, 0).is_err());
    }

    #[tokio::test]
    async fn test_concurrent_config_updates() {
        let state = create_test_state().await;
        let router = config_router().with_state(state.clone());

        let mut handles = Vec::new();
        for i in 0..10 {
            let router_clone = router.clone();
            let handle = tokio::spawn(async move {
                let patch = serde_json::json!({
                    "tcp_profile": {
                        "rate_shift": 20 + i as u64,
                        "burst": 1000 + i as u64
                    }
                });

                let (status, _) =
                    make_request(&router_clone, Method::POST, "/", Some(patch.to_string())).await;
                status
            });
            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        for result in results {
            assert_eq!(result, StatusCode::OK);
        }

        let (status, body) = make_request(&router, Method::GET, "/", None).await;
        assert_eq!(status, StatusCode::OK);
        let config: FirewallConfig = serde_json::from_str(&body).unwrap();

        let valid_update = (0..10).any(|i| {
            config.tcp_profile.rate_shift == 20 + i as u64
                && config.tcp_profile.burst == 1000 + i as u64
        });
        assert!(valid_update);
    }

    #[tokio::test]
    async fn test_ipv6_allow_list() {
        let state = create_test_state().await;
        let router = config_router().with_state(state.clone());

        let entry = serde_json::json!({
            "key": {
                "source_addr": [16843264, 0, 0, 1],
                "destination_addr": [16843265, 0, 0, 1],
                "source_port": 12345,
                "destination_port": 80,
                "protocol": 6
            },
            "state": {
                "action": "Allow",
                "last_seen": 1000000000
            }
        });

        let (status, _) = make_request(
            &router,
            Method::POST,
            "/allow_list/v6",
            Some(entry.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = make_request(&router, Method::GET, "/allow_list/v6", None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv6Packet, AllowListState)> = serde_json::from_str(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.source_addr, [16843264, 0, 0, 1]);
        assert_eq!(entries[0].1.action, Action::Allow);

        let (status, _) = make_request(&router, Method::DELETE, "/allow_list/v6", None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = make_request(&router, Method::GET, "/allow_list/v6", None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv6Packet, AllowListState)> = serde_json::from_str(&body).unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_subnet_matching_v6() {
        let state = create_test_state().await;
        let router = config_router().with_state(state.clone());

        let rule = serde_json::json!({
            "network": [16843264, 0, 0, 0],
            "prefix_len": 96,
            "action": "Allow"
        });

        let (status, _) =
            make_request(&router, Method::POST, "/subnet/v6", Some(rule.to_string())).await;
        assert_eq!(status, StatusCode::OK);

        let key = aya::maps::lpm_trie::Key::new(96, [16843264, 0, 0, 0]);
        {
            let subnet_map = state.subnet_matching_v6.read().await;
            let action = subnet_map.get(&key, 0).unwrap();
            assert_eq!(action, Action::Allow);
        }

        let (status, _) = make_request(
            &router,
            Method::DELETE,
            "/subnet/v6",
            Some(rule.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let subnet_map = state.subnet_matching_v6.read().await;
        assert!(subnet_map.get(&key, 0).is_err());
    }

    #[tokio::test]
    async fn test_packet_counts_v6() {
        let state = create_test_state().await;
        let router = config_router().with_state(state.clone());

        let entry = serde_json::json!({
            "key": {
                "source_addr": [16843264, 0, 0, 1],
                "destination_addr": [16843265, 0, 0, 1],
                "source_port": 12345,
                "destination_port": 80,
                "protocol": 6
            },
            "state": {
                "tokens": 100,
                "last_update": 1000000000
            }
        });

        let (status, _) = make_request(
            &router,
            Method::POST,
            "/packet_counts/v6",
            Some(entry.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = make_request(&router, Method::GET, "/packet_counts/v6", None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv6Packet, TokenBucketState)> = serde_json::from_str(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.tokens, 100);

        let (status, _) = make_request(&router, Method::DELETE, "/packet_counts/v6", None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = make_request(&router, Method::GET, "/packet_counts/v6", None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv6Packet, TokenBucketState)> = serde_json::from_str(&body).unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_boundary_conditions() {
        let state = create_test_state().await;
        let router = config_router().with_state(state.clone());

        let rule = serde_json::json!({
            "network": 4294967295_u32,
            "prefix_len": 32,
            "action": "Deny"
        });

        let (status, _) =
            make_request(&router, Method::POST, "/subnet/v4", Some(rule.to_string())).await;
        assert_eq!(status, StatusCode::OK);

        {
            let subnet_map = state.subnet_matching_v4.read().await;
            let key = aya::maps::lpm_trie::Key::new(32, u32::MAX);
            let action = subnet_map.get(&key, 0).unwrap();
            assert_eq!(action, Action::Deny);
        }

        let rule = serde_json::json!({
            "network": [4294967295_u32, 4294967295_u32, 4294967295_u32, 4294967295_u32],
            "prefix_len": 128,
            "action": "Deny"
        });

        let (status, _) =
            make_request(&router, Method::POST, "/subnet/v6", Some(rule.to_string())).await;
        assert_eq!(status, StatusCode::OK);

        let subnet_map = state.subnet_matching_v6.read().await;
        let key = aya::maps::lpm_trie::Key::new(128, [4294967295u32; 4]);
        let action = subnet_map.get(&key, 0).unwrap();
        assert_eq!(action, Action::Deny);
    }

    #[tokio::test]
    async fn test_empty_operations() {
        let state = create_test_state().await;
        let router = config_router().with_state(state.clone());

        let (status, _) = make_request(&router, Method::DELETE, "/allow_list/v4", None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = make_request(&router, Method::DELETE, "/packet_counts/v4", None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = make_request(&router, Method::DELETE, "/allow_list/v6", None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = make_request(&router, Method::DELETE, "/packet_counts/v6", None).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_config_persistence() {
        let state = create_test_state().await;
        let router = config_router().with_state(state.clone());

        let patch = serde_json::json!({
            "tcp_profile": {
                "rate_shift": 21,
                "burst": 500
            },
            "ddos_activated": false
        });

        let (status, _) = make_request(&router, Method::POST, "/", Some(patch.to_string())).await;
        assert_eq!(status, StatusCode::OK);

        for _ in 0..5 {
            let (status, body) = make_request(&router, Method::GET, "/", None).await;
            assert_eq!(status, StatusCode::OK);
            let config: FirewallConfig = serde_json::from_str(&body).unwrap();
            assert_eq!(config.tcp_profile.rate_shift, 21);
            assert_eq!(config.tcp_profile.burst, 500);
            assert!(!config.ddos_activated);
        }
    }
}

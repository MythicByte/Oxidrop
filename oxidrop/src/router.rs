use std::net::SocketAddr;

use axum::{
    Router,
    body::Body,
    extract::{
        ConnectInfo,
        Request,
        State,
    },
    middleware::{
        Next,
        from_fn,
        from_fn_with_state,
    },
    response::{
        IntoResponse,
        Response,
    },
    routing::{
        delete,
        get,
        patch,
        post,
        put,
    },
};
use axum_login::{
    AuthSession,
    login_required,
};
use mime_guess::from_path;
use oxidrop_common::FirewallConfig;
use rust_embed::RustEmbed;
use utoipa::OpenApi;

use crate::{
    api::{
        CreateUserReq,
        DeleteUserReq,
        ModifyUserReq,
        RenameUserReq,
        create_user_endpoint,
        delete_user_endpoint,
        list_users,
        modify_user_endpoint,
        rename_user_endpoint,
    },
    auth::{
        AppUser,
        Credentials,
        Permission,
    },
    db::{
        Database,
        RolesUser,
        UserRow,
    },
    state::{
        AllowListV4Entry,
        AllowListV4Update,
        AllowListV6Entry,
        AllowListV6Update,
        ConfigPatch,
        FirewallState,
        PacketCountV4Entry,
        PacketCountV4Update,
        PacketCountV6Entry,
        PacketCountV6Update,
        SubnetMatchV4Update,
        SubnetMatchV6Update,
        TrafficCounters,
        TrafficStatsResponse,
        config_router,
    },
};

#[derive(RustEmbed)]
#[folder = "../frontend/dist/"]
struct FrontendAssets;

async fn frontend_fallback(request: Request) -> Response {
    let path = request.uri().path().trim_start_matches('/');
    let Some((asset_path, asset)) = FrontendAssets::get(path)
        .map(|asset| (path, asset))
        .or_else(|| FrontendAssets::get("index.html").map(|asset| ("index.html", asset)))
    else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            "frontend assets are unavailable",
        )
            .into_response();
    };

    (
        [(
            axum::http::header::CONTENT_TYPE,
            from_path(asset_path).first_or_octet_stream().as_ref(),
        )],
        Body::from(asset.data.into_owned()),
    )
        .into_response()
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Oxidrop Firewall API",
        version = "1.0.0",
        description = "Core API for the Oxidrop firewall system"
    ),
    paths(
        // Auth
        crate::auth::login,
        crate::auth::logout,
        crate::auth::get_user,
        crate::auth::get_role_and_permissions,

        // Users
        crate::api::create_user_endpoint,
        crate::api::modify_user_endpoint,
        crate::api::rename_user_endpoint,
        crate::api::delete_user_endpoint,
        crate::api::list_users,

        // Config
        crate::state::get_config,
        crate::state::update_config,
        crate::state::get_traffic_stats,
        crate::state::get_logs,
        crate::ebpf::get_ebpf_adapters,

        // Allow Lists
        crate::state::get_allow_list_v4,
        crate::state::modify_allow_list_v4,
        crate::state::clear_allow_list_v4,
        crate::state::get_allow_list_v6,
        crate::state::modify_allow_list_v6,
        crate::state::clear_allow_list_v6,

        // Packet Counts
        crate::state::get_packet_counts_v4,
        crate::state::modify_packet_counts_v4,
        crate::state::clear_packet_counts_v4,
        crate::state::get_packet_counts_v6,
        crate::state::modify_packet_counts_v6,
        crate::state::clear_packet_counts_v6,

        // Subnets
        crate::state::list_subnet_matching_v4,
        crate::state::modify_subnet_matching_v4,
        crate::state::remove_subnet_matching_v4,
        crate::state::list_subnet_matching_v6,
        crate::state::modify_subnet_matching_v6,
        crate::state::remove_subnet_matching_v6,
    ),
    components(schemas(
        CreateUserReq,
        ModifyUserReq,
        RenameUserReq,
        DeleteUserReq,
        Credentials,
        AppUser,
        RolesUser,
        Permission,
        AllowListV4Update,
        AllowListV6Update,
        PacketCountV4Update,
        PacketCountV6Update,
        SubnetMatchV4Update,
        SubnetMatchV6Update,
        ConfigPatch,
        FirewallConfig,
        UserRow,
        TrafficCounters,
        TrafficStatsResponse,
        AllowListV4Entry,
        AllowListV6Entry,
        PacketCountV4Entry,
        PacketCountV6Entry
    ))
)]
pub struct ApiDoc;
/// combines all router to one, gives back to axum to serve it
pub fn combined_router(state: FirewallState) -> Router {
    // Router::new().merge(unsafe_router()).merge(safe_router())
    let router = Router::new().merge(unsafe_router()).merge(safe_router());
    // .merge(unsafe_router());
    Router::new()
        .nest("/api/v1", router)
        .fallback(frontend_fallback)
        .layer(from_fn_with_state(state.clone(), log_failed_requests))
        .with_state(state)
}

async fn log_failed_requests(
    State(state): State<FirewallState>,
    request: Request,
    next: Next,
) -> Response {
    let client_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let method = request.method().clone();
    let uri = request.uri().clone();
    let response = next.run(request).await;

    if response.status().is_server_error() {
        let message = format!("{method} {uri} returned {}", response.status());
        state
            .logs
            .record_details(
                "ERROR",
                &message,
                Some(&client_ip),
                Some(&client_ip),
                None,
                None,
                None,
                None,
                Some("DROP"),
            )
            .await;
    }
    response
}
/// # User is **NOT** Authenticated
///
/// seperate the unsafe route, where a User is not logged in
fn unsafe_router() -> Router<FirewallState> {
    Router::new()
        .without_v07_checks()
        .route("/login", post(crate::auth::login))
        .route("/get_user", get(crate::auth::get_user))
}
/// # User **is** Authenticated
///
/// A user must be authenticated to use this route
fn safe_router() -> Router<FirewallState> {
    let user_routes = Router::new()
        .route("/create_user", post(create_user_endpoint))
        .route("/modify_user", put(modify_user_endpoint))
        .route("/delete_user", delete(delete_user_endpoint))
        .route("/rename_user", patch(rename_user_endpoint))
        .route("/get_all_user", get(list_users));

    let password_change_route = Router::new()
        .route(
            "/change_password",
            post(crate::api::change_password_endpoint),
        )
        .route_layer(login_required!(Database, login_url = "/api/v1/login"));

    let restricted_routes = Router::new()
        .route(
            "/role_and_permissions",
            get(crate::auth::get_role_and_permissions),
        )
        .nest("/config", config_router())
        .route("/logs", get(crate::state::get_logs))
        .route("/logs/ws", get(crate::state::log_websocket))
        .nest("/users", user_routes)
        .route_layer(from_fn(require_completed_password_change))
        .route_layer(login_required!(Database, login_url = "/api/v1/login"));

    Router::new()
        .without_v07_checks()
        .route("/logout", get(crate::auth::logout))
        .route_layer(login_required!(Database, login_url = "/api/v1/login"))
        .merge(password_change_route)
        .merge(restricted_routes)
}

async fn require_completed_password_change(
    auth_session: AuthSession<Database>,
    request: Request,
    next: Next,
) -> Response {
    if auth_session
        .user
        .as_ref()
        .is_some_and(|user| !user.password_must_be_changed)
    {
        return next.run(request).await;
    }

    (
        axum::http::StatusCode::FORBIDDEN,
        "Password change required before using this service",
    )
        .into_response()
}
#[cfg(test)]
mod openapi_tests {
    use utoipa::OpenApi;

    use super::*;

    #[test]
    fn generate_openapi_spec() -> anyhow::Result<()> {
        let doc = ApiDoc::openapi();
        std::fs::write("../frontend/openapi.json", doc.to_pretty_json()?)?;
        Ok(())
    }
}

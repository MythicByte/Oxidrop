use axum::{
    Router,
    routing::{
        delete,
        get,
        patch,
        post,
        put,
    },
};
use axum_login::login_required;
use tower_http::services::ServeDir;
use utoipa::OpenApi;

use crate::{
    api::{
        CreateUserReq,
        DeleteUserReq,
        ModifyUserReq,
        RenameUserReq,
        create_user_endpoint,
        delete_user_endpoint,
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
    },
    state::{
        AllowListV4Update,
        AllowListV6Update,
        ConfigPatch,
        FirewallState,
        PacketCountV4Update,
        PacketCountV6Update,
        SubnetMatchV4Update,
        SubnetMatchV6Update,
        config_router,
    },
};
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

        // Users
        crate::api::create_user_endpoint,
        crate::api::modify_user_endpoint,
        crate::api::rename_user_endpoint,
        crate::api::delete_user_endpoint,

        // Config
        crate::state::get_config,
        crate::state::update_config,

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
        crate::state::modify_subnet_matching_v4,
        crate::state::remove_subnet_matching_v4,
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
        ConfigPatch
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
        .fallback_service(ServeDir::new("frontend/dist"))
        .with_state(state)
}
/// # User is **NOT** Authenticated
///
/// seperate the unsafe route, where a User is not logged in
fn unsafe_router() -> Router<FirewallState> {
    Router::new()
        .without_v07_checks()
        .route("/login", post(crate::auth::login))
}
/// # User **is** Authenticated
///
/// A user must be authenticated to use this route
fn safe_router() -> Router<FirewallState> {
    let user_routes = Router::new()
        .route("/create_user", post(create_user_endpoint))
        .route("/modify_user", put(modify_user_endpoint))
        .route("/delete_user", delete(delete_user_endpoint))
        .route("/rename_user", patch(rename_user_endpoint));

    Router::new()
        .without_v07_checks()
        .route("/logout", get(crate::auth::logout))
        .nest("/config", config_router())
        .nest("/users", user_routes)
        .route_layer(login_required!(Database, login_url = "/api/v1/login"))
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

use axum::{
    Router,
    routing::{
        get,
        post,
    },
};
use axum_login::login_required;
use tower_http::services::ServeDir;

use crate::{
    db::Database,
    state::{
        FirewallState,
        config_router,
    },
};

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
    Router::new()
        .without_v07_checks()
        .route("/logout", get(crate::auth::logout))
        .nest("/config", config_router())
        .route_layer(login_required!(Database, login_url = "/api/v1/login"))
}

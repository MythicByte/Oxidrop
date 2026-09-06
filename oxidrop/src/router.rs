use axum::Router;
use tower_http::services::ServeDir;

use crate::state::{
    FirewallState,
    config_router,
};

/// combines all router to one, gives back to axum to serve it
pub(crate) fn combined_router(state: FirewallState) -> Router {
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
    Router::new().without_v07_checks()
}
/// # User **is** Authenticated
///
/// A user must be authenticated to use this route
fn safe_router() -> Router<FirewallState> {
    Router::new()
        .without_v07_checks()
        .nest("/config", config_router())
    // .route("/", todo!())
    // // removes the session id
    // .route("/logout", todo!())
}

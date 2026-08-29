use axum::{
    Router,
    response::IntoResponse,
    routing::get,
};
use tower_http::services::ServeDir;

/// combines all router to one, gives back to axum to serve it
pub(crate) fn combined_router() -> Router {
    // Router::new().merge(unsafe_router()).merge(safe_router())
    let router = Router::new().merge(unsafe_router()).merge(safe_router());
    // .merge(unsafe_router());
    Router::new()
        .nest("/api", router)
        .fallback_service(ServeDir::new("frontend/dist"))
}
/// # User is **NOT** Authenticated
///
/// seperate the unsafe route, where a User is not logged in
fn unsafe_router() -> Router {
    Router::new()
        .without_v07_checks()
        .route("/test", get(hello_axum))
    // .route("/login", todo!())
}
/// # User **is** Authenticated
///
/// A user must be authenticated to use this route
fn safe_router() -> Router {
    Router::new().without_v07_checks()
    // .route("/", todo!())
    // // removes the session id
    // .route("/logout", todo!())
}
async fn hello_axum() -> impl IntoResponse {
    "Hello from axum"
}

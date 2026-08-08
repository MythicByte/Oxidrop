use axum::{
    Router,
    response::Redirect,
    routing::get,
};

/// combines all router to one, gives back to axum to serve it
pub(crate) fn combined_router() -> Router {
    // Router::new().merge(unsafe_router()).merge(safe_router())
    Router::new().route("/", get(|| async { "Hello world" }))
}
/// # User is **NOT** Authenticated
///
/// seperate the unsafe route, where a User is not logged in
fn unsafe_router() -> Router {
    Router::new()
        .without_v07_checks()
        .route("/login", todo!())
        .fallback(Redirect::to("/login"))
}
/// # User **is** Authenticated
///
/// A user must be authenticated to use this route
fn safe_router() -> Router {
    Router::new()
        .without_v07_checks()
        .route("/", todo!())
        // removes the session id
        .route("/logout", todo!())
        .fallback(Redirect::to("/"))
}

use axum::{
    Json,
    extract::State,
    response::IntoResponse,
};
use axum_login::AuthSession;
use hyper::StatusCode;
use serde::Deserialize;
use tracing::error;

use crate::{
    db::{
        ActionPermissions,
        CallerContext,
        Database,
        RolesUser,
        UserError,
    },
    state::FirewallState,
};

#[derive(Deserialize)]
pub struct CreateUserReq {
    pub username: String,
    pub password: String,
    pub role: RolesUser,
    pub permissions: ActionPermissions,
}

#[derive(Deserialize)]
pub struct ModifyUserReq {
    pub target_username: String,
    pub role: RolesUser,
    pub permissions: ActionPermissions,
    pub is_active: i64,
}

#[derive(Deserialize)]
pub struct RenameUserReq {
    pub current_username: String,
    pub new_username: String,
}

#[derive(Deserialize)]
pub struct DeleteUserReq {
    pub target_username: String,
}

fn map_user_error(err: UserError) -> StatusCode {
    match err {
        UserError::UserExists(_) => StatusCode::CONFLICT,
        UserError::InvalidCredentials => StatusCode::UNAUTHORIZED,
        UserError::NotFound(_) => StatusCode::NOT_FOUND,
        UserError::LackingPermission => StatusCode::FORBIDDEN,
        UserError::WeakPassword(_) | UserError::TooLongPassword(_) => StatusCode::BAD_REQUEST,
        UserError::Database(e) => {
            error!("Database error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
        UserError::Internal(e) => {
            error!("Internal error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

pub async fn create_user_endpoint(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(payload): Json<CreateUserReq>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };

    match state
        .db
        .create_user(
            &caller,
            &payload.username,
            &payload.password,
            payload.role,
            payload.permissions,
        )
        .await
    {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(e) => map_user_error(e).into_response(),
    }
}

pub async fn modify_user_endpoint(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(payload): Json<ModifyUserReq>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };

    match state
        .db
        .modify_user(
            &caller,
            &payload.target_username,
            payload.role,
            payload.permissions,
            payload.is_active,
        )
        .await
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => map_user_error(e).into_response(),
    }
}

pub async fn rename_user_endpoint(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(payload): Json<RenameUserReq>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };

    match state
        .db
        .change_username(&caller, &payload.current_username, &payload.new_username)
        .await
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => map_user_error(e).into_response(),
    }
}

pub async fn delete_user_endpoint(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(payload): Json<DeleteUserReq>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };

    match state
        .db
        .delete_user(&payload.target_username, &caller)
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => map_user_error(e).into_response(),
    }
}

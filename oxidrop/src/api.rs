use axum::{
    Json,
    extract::State,
    response::IntoResponse,
};
use axum_login::AuthSession;
use hyper::StatusCode;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{
    db::{
        ActionPermissions,
        CallerContext,
        Database,
        RolesUser,
        UserRow,
    },
    state::FirewallState,
};

#[derive(Deserialize, ToSchema)]
pub struct CreateUserReq {
    pub username: String,
    pub password: String,
    pub role: RolesUser,
    #[schema(value_type = u8)]
    pub permissions: ActionPermissions,
}

#[derive(Deserialize, ToSchema)]
pub struct ModifyUserReq {
    pub target_username: String,
    pub role: RolesUser,
    #[schema(value_type = u8)]
    pub permissions: ActionPermissions,
    pub is_active: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct RenameUserReq {
    pub current_username: String,
    pub new_username: String,
}

#[derive(Deserialize, ToSchema)]
pub struct DeleteUserReq {
    pub target_username: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/users/create_user",
    request_body = CreateUserReq,
    responses(
        (status = 201, description = "User created successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 409, description = "User already exists")
    ),
    security(
        ("cookie_auth" = [])
    )
)]
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
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/users/modify_user",
    request_body = ModifyUserReq,
    responses((status = 200, description = "User modified"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
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
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(
    patch,
    path = "/api/v1/users/rename_user",
    request_body = RenameUserReq,
    responses((status = 200, description = "User renamed"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
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
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/users/delete_user",
    request_body = DeleteUserReq,
    responses((status = 204, description = "User deleted"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
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
        Err(e) => e.into_response(),
    }
}
#[utoipa::path(
    get,
    path = "/api/v1/users/get_all_user",
    responses(
        (status = 200, description = "List all users successfully", body = Vec<UserRow>),
        (status = 401, description = "Unauthorized - User is not logged in or lacks Admin role"),
        (status = 500, description = "Internal server error - Database failure")
    ),
    security(
        ("cookie_auth" = [])
    )
)]
pub async fn list_users(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
) -> Result<Json<Vec<UserRow>>, StatusCode> {
    let user = match auth_session.user {
        Some(u) => u,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin {
        match state.db.get_all_users().await {
            Ok(users) => Ok(Json(users)),
            Err(e) => {
                eprintln!("Database error while fetching users: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

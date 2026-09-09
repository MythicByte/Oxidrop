use std::{
    collections::HashSet,
    sync::OnceLock,
    time::{
        SystemTime,
        UNIX_EPOCH,
    },
};

use argon2::{
    Argon2,
    PasswordHash,
    PasswordHasher,
    PasswordVerifier,
    password_hash::phc::SaltString,
};
use axum::{
    Form,
    Json,
    response::{
        IntoResponse,
        Redirect,
    },
};
use axum_login::{
    AuthUser,
    AuthnBackend,
    AuthzBackend,
    UserId,
};
use hyper::StatusCode;
use secrecy::{
    ExposeSecret,
    SecretString,
};
use serde::{
    Deserialize,
    Serialize,
};
use utoipa::ToSchema;

use crate::db::{
    ActionPermissions,
    Database,
    RolesUser,
    UserError,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum Permission {
    Create,
    Modify,
    Delete,
}
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AppUser {
    pub id: i64,
    pub username: String,
    pub role: RolesUser,
    #[schema(value_type = u8)]
    pub permissions: ActionPermissions,
    pub password_hash: String,
}

impl AuthUser for AppUser {
    type Id = i64;
    fn id(&self) -> Self::Id {
        self.id
    }
    fn session_auth_hash(&self) -> &[u8] {
        self.password_hash.as_bytes()
    }
}

#[derive(Clone, Deserialize, ToSchema)]
pub struct Credentials {
    pub username: String,
    #[schema(value_type = String)]
    pub password: SecretString,
}

impl AuthnBackend for Database {
    type User = AppUser;
    type Credentials = Credentials;
    type Error = UserError;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let record = sqlx::query!(
            r#"
            SELECT id, username, password_hash, role, action_permissions, is_active
            FROM users
            WHERE username = ?
            "#,
            creds.username
        )
        .fetch_optional(&self.pool)
        .await?;

        let user = match record {
            Some(u) => u,
            None => {
                burn_verify_time(&creds.password);
                return Err(UserError::InvalidCredentials);
            }
        };

        if user.is_active == 0 {
            return Err(UserError::InvalidCredentials);
        }

        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| UserError::Internal("Invalid hash stored in DB".to_string()))?;

        // Expose the secret explicitly to verify it
        if Argon2::default()
            .verify_password(creds.password.expose_secret().as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err(UserError::InvalidCredentials);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query!(
            r#"UPDATE users SET last_login_at = ? WHERE id = ?"#,
            now,
            user.id
        )
        .execute(&self.pool)
        .await?;

        let parsed_role = if user.role == "admin" {
            RolesUser::Admin
        } else {
            RolesUser::Viewer
        };

        Ok(Some(AppUser {
            id: user.id,
            username: user.username,
            role: parsed_role,
            permissions: ActionPermissions::from_bits_truncate(user.action_permissions as u8),
            password_hash: user.password_hash,
        }))
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        // This is called by the middleware on every authenticated request to re-hydrate the user.
        let record = sqlx::query!(
            r#"SELECT id, username, password_hash, role, action_permissions FROM users WHERE id = ? AND is_active = 1"#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;

        let user = match record {
            Some(u) => u,
            None => return Ok(None),
        };

        let parsed_role = if user.role == "admin" {
            RolesUser::Admin
        } else {
            RolesUser::Viewer
        };

        Ok(Some(AppUser {
            id: user.id,
            username: user.username,
            role: parsed_role,
            permissions: ActionPermissions::from_bits_truncate(user.action_permissions as u8),
            password_hash: user.password_hash,
        }))
    }
}
impl AuthzBackend for Database {
    type Permission = Permission;

    async fn get_all_permissions(
        &self,
        user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        let mut permissions = HashSet::new();

        if user.permissions.contains(ActionPermissions::CREATE) {
            permissions.insert(Permission::Create);
        }
        if user.permissions.contains(ActionPermissions::MODIFY) {
            permissions.insert(Permission::Modify);
        }
        if user.permissions.contains(ActionPermissions::DELETE) {
            permissions.insert(Permission::Delete);
        }

        Ok(permissions)
    }
}
type AuthSession = axum_login::AuthSession<Database>;

#[utoipa::path(
    post,
    path = "/api/v1/login",
    request_body(content = Credentials, content_type = "application/x-www-form-urlencoded"),
    responses((status = 200, description = "Login successful"), (status = 401, description = "Unauthorized"))
)]
pub async fn login(
    mut auth_session: AuthSession,
    Form(creds): Form<Credentials>,
) -> impl IntoResponse {
    let user = match auth_session.authenticate(creds.clone()).await {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if auth_session.login(&user).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    StatusCode::OK.into_response()
}
#[utoipa::path(
    get,
    path = "/api/v1/logout",
    responses((status = 303, description = "Logout successful")),
    security(("cookie_auth" = []))
)]
pub async fn logout(mut auth_session: AuthSession) -> impl IntoResponse {
    match auth_session.logout().await {
        Ok(_) => Redirect::to("/login").into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
#[utoipa::path(
    get,
    path = "/api/v1/get_user",
    responses(
        (status = 200, description = "Session valid", body = AppUser),
        (status = 401, description = "Unauthorized")
    ),
    security(("cookie_auth" = []))
)]
pub async fn get_user(auth_session: AuthSession) -> impl IntoResponse {
    match auth_session.user {
        Some(user) => (StatusCode::OK, Json(user)).into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}
fn dummy_password_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        let salt = SaltString::generate();
        Argon2::default()
            .hash_password_with_salt(b"correct horse battery staple", salt.as_bytes())
            .expect("hashing a fixed constant password cannot fail")
            .to_string()
    })
    .as_str()
}

fn burn_verify_time(password: &SecretString) {
    if let Ok(hash) = PasswordHash::new(dummy_password_hash()) {
        let _ = Argon2::default().verify_password(password.expose_secret().as_bytes(), &hash);
    }
}

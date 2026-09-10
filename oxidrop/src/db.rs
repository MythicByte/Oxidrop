use std::str::FromStr;

use argon2::{
    Argon2,
    PasswordHasher,
    password_hash::phc::SaltString,
};
use axum::{
    Json,
    response::{
        IntoResponse,
        Response,
    },
};
use bitflags::bitflags;
use hyper::StatusCode;
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::json;
use sqlx::{
    SqlitePool,
    prelude::FromRow,
    sqlite::{
        SqliteConnectOptions,
        SqlitePoolOptions,
    },
};
use thiserror::Error;
use tracing::warn;
use utoipa::ToSchema;
#[derive(Serialize, Deserialize, FromRow, ToSchema)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub permissions: i32, // Stored as integer for the bitmask
    pub is_active: bool,
}
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq,Serialize,Deserialize,)]
    pub struct ActionPermissions: u8 {
        const NONE   = 0;
        const CREATE = 1; // 001
        const MODIFY = 2; // 010
        const DELETE = 4; // 100
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub enum RolesUser {
    Viewer = 0,
    Admin = 1,
}
impl std::fmt::Display for RolesUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RolesUser::Viewer => write!(f, "Viewer"),
            RolesUser::Admin => write!(f, "Admin"),
        }
    }
}
impl RolesUser {
    fn as_str(&self) -> &'static str {
        match self {
            RolesUser::Admin => "admin",
            RolesUser::Viewer => "viewer",
        }
    }
}
#[derive(Debug, Clone)]
pub struct CallerContext {
    pub role: RolesUser,
    pub permissions: ActionPermissions,
}
#[derive(Debug, Error)]
pub enum UserError {
    #[error("User already exists: {0}")]
    UserExists(String),
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("User not found: {0}")]
    NotFound(String),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("lacking permission")]
    LackingPermission,
    #[error("Password does not meet security requirements: {0}")]
    WeakPassword(String),
    #[error("Password does not meet security requirements: {0}")]
    TooLongPassword(String),
}

#[derive(Clone, Debug)]
pub struct Database {
    pub pool: SqlitePool,
}

impl Database {
    /// Initializes the database connection and saves it to disk if it doesn't exist.
    pub async fn new(db_url: &str) -> Result<Self, sqlx::Error> {
        // create_if_missing(true) ensures the file is saved to disk upon creation
        let options = SqliteConnectOptions::from_str(db_url)?.create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(100)
            .connect_with(options)
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self { pool })
    }
    /// Enforces length and blocks common dictionary garbage.
    pub fn validate_password(password: &str) -> Result<(), UserError> {
        if password.len() < 12 {
            return Err(UserError::WeakPassword(
                "Password must be at least 12 characters long.".into(),
            ));
        }
        if password.len() > 120 {
            return Err(UserError::WeakPassword(
                "Password must not be bigger then 120 characters long.".into(),
            ));
        }

        //  This is a basic blacklist of idiots.
        let blacklist = [
            "password123",
            "password1234",
            "admin1234",
            "admin12345",
            "qwertyuiop",
            "letmein123!",
            "Winter2024!",
        ];

        if blacklist.contains(&password.to_lowercase().as_str()) {
            return Err(UserError::WeakPassword(
                "Password is too common or easily guessable.".into(),
            ));
        }

        Ok(())
    }
    /// Creates a new user using Argon2id for password hashing.
    pub async fn create_user(
        &self,
        caller: &CallerContext,
        target_username: &str,
        target_password: &str,
        target_role: RolesUser,
        target_permissions: ActionPermissions,
    ) -> Result<(), UserError> {
        match caller.role {
            RolesUser::Admin if caller.permissions.contains(ActionPermissions::CREATE) => {
                // Force password reset for newly created users by default
                self.internal_insert_user(
                    target_username,
                    target_password,
                    target_role,
                    target_permissions,
                    1,
                    false,
                )
                .await
            }
            _ => return Err(UserError::LackingPermission),
        }
    }
    /// Checks if the users table is empty. If it is, creates a default admin.
    pub async fn bootstrap_default_admin(&self) -> Result<(), UserError> {
        let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;

        if count == 0 {
            let temp_password = "password";
            warn!("WARN: Database empty. Bootstrapping default user 'admin'.");
            warn!("WARN: Temporary password is: {}", temp_password);

            let insert_result = self
                .internal_insert_user(
                    "admin",
                    temp_password,
                    RolesUser::Admin,
                    ActionPermissions::all(),
                    1, // password_must_be_changed = 1
                    true,
                )
                .await;

            // Handle the race condition where another thread beat us to the insertion
            match insert_result {
                Ok(_) => {}
                Err(UserError::UserExists(_)) => {
                    // Another thread just created the admin user. This is fine.
                }
                Err(e) => return Err(e), // Bubble up actual database/internal errors
            }
        }
        Ok(())
    }
    /// Internal function handling the actual DB insertion to avoid duplicating code.
    async fn internal_insert_user(
        &self,
        username: &str,
        password: &str,
        role: RolesUser,
        action_permissions: ActionPermissions,
        must_change_pw: i64,
        ignore_password_check: bool,
    ) -> Result<(), UserError> {
        if !ignore_password_check {
            Self::validate_password(password)?;
        }

        let salt = SaltString::generate();
        let password_hash = PasswordHasher::hash_password_with_salt(
            &Argon2::default(),
            password.as_bytes(),
            salt.as_bytes(),
        )
        .map_err(|e| UserError::Internal(e.to_string()))?
        .to_string();

        let result = sqlx::query!(
            r#"
            INSERT INTO users (username, password_hash, role, action_permissions, password_must_be_changed, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
            "#,
            username,
            password_hash,
            role.as_str(),
            action_permissions.bits(),
            must_change_pw
        )
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(UserError::UserExists(username.to_string()))
            }
            Err(e) => Err(UserError::Database(e)),
        }
    }

    /// Deletes a user by their username.
    pub async fn delete_user(
        &self,
        username: &str,
        caller: &CallerContext,
    ) -> Result<(), UserError> {
        match caller.role {
            RolesUser::Admin if caller.permissions.contains(ActionPermissions::DELETE) => {
                let rows_affected =
                    sqlx::query!(r#"DELETE FROM users WHERE username = ?"#, username)
                        .execute(&self.pool)
                        .await?
                        .rows_affected();

                if rows_affected == 0 {
                    Err(UserError::NotFound(username.to_string()))
                } else {
                    Ok(())
                }
            }
            _ => return Err(UserError::LackingPermission),
        }
    }
    /// Modifies an existing user.
    /// Ensures caller has MODIFY permission.
    pub async fn modify_user(
        &self,
        caller: &CallerContext,
        target_username: &str,
        new_role: RolesUser,
        new_permissions: ActionPermissions,
        is_active: i64,
    ) -> Result<(), UserError> {
        // Enforce the caller's permissions
        match caller.role {
            RolesUser::Admin if caller.permissions.contains(ActionPermissions::MODIFY) => {
                let rows_affected = sqlx::query!(
                    r#"
            UPDATE users 
            SET role = ?, action_permissions = ?, is_active = ? 
            WHERE username = ?
            "#,
                    new_role.as_str(),
                    new_permissions.bits(),
                    is_active,
                    target_username
                )
                .execute(&self.pool)
                .await?
                .rows_affected();

                if rows_affected == 0 {
                    return Err(UserError::NotFound(target_username.to_string()));
                }

                Ok(())
            }
            _ => return Err(UserError::LackingPermission),
        }
    }
    /// Changes a user's username.
    /// Ensures caller has MODIFY permission and that the new username isn't already taken.
    pub async fn change_username(
        &self,
        caller: &CallerContext,
        current_username: &str,
        new_username: &str,
    ) -> Result<(), UserError> {
        // Enforce the caller's permissions cleanly
        match caller.role {
            RolesUser::Admin if caller.permissions.contains(ActionPermissions::MODIFY) => {
                // We do NOT check if the user exists first. We just try the UPDATE.
                // The UNIQUE constraint in the schema will catch duplicates.
                let result = sqlx::query!(
                    r#"UPDATE users SET username = ? WHERE username = ?"#,
                    new_username,
                    current_username
                )
                .execute(&self.pool)
                .await;

                match result {
                    Ok(res) if res.rows_affected() == 0 => {
                        // If 0 rows were affected, the user we are trying to rename doesn't exist.
                        Err(UserError::NotFound(current_username.to_string()))
                    }
                    Ok(_) => Ok(()),
                    Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                        // Someone else already has the new username.
                        Err(UserError::UserExists(new_username.to_string()))
                    }
                    Err(e) => Err(UserError::Database(e)),
                }
            }
            _ => return Err(UserError::LackingPermission),
        }
    }
    pub async fn get_all_users(&self) -> Result<Vec<UserRow>, sqlx::Error> {
        let query = "SELECT id, username, role, action_permissions AS permissions, is_active FROM users ORDER BY id ASC;";

        sqlx::query_as::<_, UserRow>(query)
            .fetch_all(&self.pool)
            .await
    }
}
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// Helper to spin up a fresh, migrated in-memory database for each test.
    async fn setup_test_db() -> Database {
        // We use a memory database so tests run fast and isolated.
        // The create_if_missing flag in Database::new will handle this seamlessly.
        let db = Database::new("sqlite::memory:")
            .await
            .expect("Failed to initialize in-memory database");

        db
    }

    /// Helper to get a standard Admin context with all permissions.
    fn admin_ctx() -> CallerContext {
        CallerContext {
            role: RolesUser::Admin,
            permissions: ActionPermissions::all(),
        }
    }

    #[tokio::test]
    async fn test_rbac_only_admin_with_create_can_create_users() {
        let db = setup_test_db().await;

        // Viewer attempting to create a user should fail.
        let viewer_ctx = CallerContext {
            role: RolesUser::Viewer,
            permissions: ActionPermissions::all(), // Even with flags, role denies it
        };
        let err_viewer = db
            .create_user(
                &viewer_ctx,
                "user1",
                "ValidPassword123!",
                RolesUser::Viewer,
                ActionPermissions::NONE,
            )
            .await
            .unwrap_err();
        assert!(matches!(err_viewer, UserError::LackingPermission));

        // Admin WITHOUT 'CREATE' permission should fail.
        let admin_no_create_ctx = CallerContext {
            role: RolesUser::Admin,
            permissions: ActionPermissions::MODIFY | ActionPermissions::DELETE,
        };
        let err_admin = db
            .create_user(
                &admin_no_create_ctx,
                "user2",
                "ValidPassword123!",
                RolesUser::Viewer,
                ActionPermissions::NONE,
            )
            .await
            .unwrap_err();
        assert!(matches!(err_admin, UserError::LackingPermission));

        // Admin WITH 'CREATE' permission should succeed.
        let admin_create_ctx = CallerContext {
            role: RolesUser::Admin,
            permissions: ActionPermissions::CREATE,
        };
        let res = db
            .create_user(
                &admin_create_ctx,
                "user3",
                "ValidPassword123!",
                RolesUser::Viewer,
                ActionPermissions::NONE,
            )
            .await;
        assert!(
            res.is_ok(),
            "Admin with CREATE permission failed to create user"
        );
    }

    #[tokio::test]
    async fn test_crud_rename_user_enforces_unique_constraint() {
        let db = setup_test_db().await;
        let ctx = admin_ctx();

        // Provision two distinct users
        db.create_user(
            &ctx,
            "alpha",
            "ValidPassword123!",
            RolesUser::Viewer,
            ActionPermissions::NONE,
        )
        .await
        .unwrap();
        db.create_user(
            &ctx,
            "beta",
            "ValidPassword123!",
            RolesUser::Viewer,
            ActionPermissions::NONE,
        )
        .await
        .unwrap();

        // Attempt to rename "alpha" to "beta" (which already exists)
        let err = db.change_username(&ctx, "alpha", "beta").await.unwrap_err();

        assert!(
            matches!(err, UserError::UserExists(name) if name == "beta"),
            "Renaming to an existing username did not throw the expected UserExists error"
        );
    }

    #[tokio::test]
    async fn test_security_weak_passwords_are_rejected() {
        let db = setup_test_db().await;
        let ctx = admin_ctx();

        //  Password under 12 characters
        let err_short = db
            .create_user(
                &ctx,
                "user1",
                "short",
                RolesUser::Viewer,
                ActionPermissions::NONE,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err_short, UserError::WeakPassword(_)),
            "System accepted a password shorter than 12 characters"
        );

        //  Password on the blacklist
        let err_dict = db
            .create_user(
                &ctx,
                "user2",
                "password123",
                RolesUser::Viewer,
                ActionPermissions::NONE,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err_dict, UserError::WeakPassword(_)),
            "System accepted a blacklisted dictionary password"
        );
    }

    #[tokio::test]
    async fn test_crud_operations_on_nonexistent_user_yield_not_found() {
        let db = setup_test_db().await;
        let ctx = admin_ctx();
        let ghost = "ghost_user";

        // Modify
        let err_mod = db
            .modify_user(&ctx, ghost, RolesUser::Viewer, ActionPermissions::NONE, 1)
            .await
            .unwrap_err();
        assert!(matches!(err_mod, UserError::NotFound(name) if name == ghost));

        // Delete
        let err_del = db.delete_user(ghost, &ctx).await.unwrap_err();
        assert!(matches!(err_del, UserError::NotFound(name) if name == ghost));

        // Rename
        let err_ren = db
            .change_username(&ctx, ghost, "new_ghost")
            .await
            .unwrap_err();
        assert!(matches!(err_ren, UserError::NotFound(name) if name == ghost));
    }

    #[tokio::test]
    async fn test_concurrency_race_condition_on_user_creation() {
        let db = Arc::new(setup_test_db().await);
        let ctx = Arc::new(admin_ctx());
        let username = "concurrent_user";
        let password = "ValidPassword123!";

        // Spawn 10 concurrent tasks all trying to create the exact same username at the same time
        let mut handles = vec![];
        for _ in 0..10 {
            let db_clone = Arc::clone(&db);
            let ctx_clone = Arc::clone(&ctx);

            let handle = tokio::spawn(async move {
                db_clone
                    .create_user(
                        &ctx_clone,
                        username,
                        password,
                        RolesUser::Viewer,
                        ActionPermissions::NONE,
                    )
                    .await
            });
            handles.push(handle);
        }

        let mut successes = 0;
        let mut exists_errors = 0;

        for handle in handles {
            let result = handle.await.unwrap();
            match result {
                Ok(_) => successes += 1,
                Err(UserError::UserExists(_)) => exists_errors += 1,
                Err(e) => panic!("Unexpected error during concurrent creation: {:?}", e),
            }
        }

        assert_eq!(successes, 1, "Expected exactly one creation to succeed");
        assert_eq!(
            exists_errors, 9,
            "Expected exactly nine creations to fail with UserExists"
        );
    }

    #[tokio::test]
    async fn test_concurrency_race_condition_on_bootstrap() {
        let db = Arc::new(setup_test_db().await);

        // Spawn multiple threads trying to bootstrap the database simultaneously
        let mut handles = vec![];
        for _ in 0..5 {
            let db_clone = Arc::clone(&db);
            handles.push(tokio::spawn(async move {
                db_clone.bootstrap_default_admin().await
            }));
        }

        for handle in handles {
            handle
                .await
                .unwrap()
                .expect("Bootstrap concurrent execution failed");
        }

        // Verify only ONE admin user was created, despite concurrent attempts
        let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM users")
            .fetch_one(&db.pool)
            .await
            .unwrap();

        assert_eq!(
            count, 1,
            "Concurrent bootstrap resulted in duplicate admin users"
        );
    }

    // --- Exhaustive RBAC Tests ---

    #[tokio::test]
    async fn test_rbac_modify_rename_delete_requires_exact_permissions() {
        let db = setup_test_db().await;
        let target = "target_user";

        // Setup: Create a user to operate on
        db.create_user(
            &admin_ctx(),
            target,
            "ValidPassword123!",
            RolesUser::Viewer,
            ActionPermissions::NONE,
        )
        .await
        .unwrap();

        // Context: Admin who ONLY has CREATE permissions
        let no_mod_del_ctx = CallerContext {
            role: RolesUser::Admin,
            permissions: ActionPermissions::CREATE, // Missing MODIFY and DELETE
        };

        // Attempt Modify
        let err_mod = db
            .modify_user(
                &no_mod_del_ctx,
                target,
                RolesUser::Admin,
                ActionPermissions::NONE,
                1,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err_mod, UserError::LackingPermission),
            "Modify succeeded without MODIFY permission"
        );

        // Attempt Rename
        let err_ren = db
            .change_username(&no_mod_del_ctx, target, "new_name")
            .await
            .unwrap_err();
        assert!(
            matches!(err_ren, UserError::LackingPermission),
            "Rename succeeded without MODIFY permission"
        );

        // Attempt Delete
        let err_del = db.delete_user(target, &no_mod_del_ctx).await.unwrap_err();
        assert!(
            matches!(err_del, UserError::LackingPermission),
            "Delete succeeded without DELETE permission"
        );
    }
}
impl IntoResponse for UserError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            UserError::UserExists(_) => (StatusCode::CONFLICT, "User already exists".to_string()),

            UserError::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())
            }

            UserError::NotFound(_) => (StatusCode::NOT_FOUND, "User not found".to_string()),

            UserError::LackingPermission => (
                StatusCode::FORBIDDEN,
                "Insufficient permissions".to_string(),
            ),

            UserError::WeakPassword(reason) | UserError::TooLongPassword(reason) => (
                StatusCode::BAD_REQUEST,
                format!("Password requirement not met: {}", reason),
            ),

            UserError::Database(e) => {
                tracing::error!(error = %e, "Database query failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                )
            }

            UserError::Internal(e) => {
                tracing::error!(error = %e, "Internal application error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                )
            }
        };

        let body = Json(json!({
            "error": error_message
        }));

        (status, body).into_response()
    }
}

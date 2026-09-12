use axum_login::AuthnBackend;
use oxidrop::{
    auth::{
        AppUser,
        Credentials,
    },
    db::{
        ActionPermissions,
        CallerContext,
        Database,
        RolesUser,
        UserError,
    },
};
use oxidrop_common::{
    ActivaterEtherTypes,
    FirewallConfig,
};
use secrecy::SecretString;

const ADMIN_PASSWORD: &str = "password";
const VALID_PASSWORD: &str = "ValidPassword123!";

async fn database_with_admin() -> Database {
    let database = Database::new("sqlite::memory:")
        .await
        .expect("database setup should succeed");
    database
        .bootstrap_default_admin()
        .await
        .expect("default admin bootstrap should succeed");
    database
}

fn credentials(username: &str, password: &str) -> Credentials {
    Credentials {
        username: username.to_owned(),
        password: SecretString::from(password.to_owned()),
    }
}

async fn authenticate(database: &Database, username: &str, password: &str) -> AppUser {
    database
        .authenticate(credentials(username, password))
        .await
        .expect("authentication query should succeed")
        .expect("valid credentials should authenticate")
}

fn admin_context() -> CallerContext {
    CallerContext {
        role: RolesUser::Admin,
        permissions: ActionPermissions::all(),
    }
}

#[tokio::test]
async fn bootstrap_creates_forced_change_admin_and_authentication_updates_login_time() {
    let database = database_with_admin().await;

    let user = authenticate(&database, "admin", ADMIN_PASSWORD).await;
    assert_eq!(user.role, RolesUser::Admin);
    assert_eq!(user.permissions, ActionPermissions::all());
    assert!(user.password_must_be_changed);

    let last_login_at: Option<i64> =
        sqlx::query_scalar!("SELECT last_login_at FROM users WHERE username = 'admin'")
            .fetch_one(&database.pool)
            .await
            .expect("last-login query should succeed");
    assert!(
        last_login_at.is_some(),
        "successful login must update last_login_at"
    );
}

#[tokio::test]
async fn password_change_invalidates_old_password_and_clears_forced_change() {
    let database = database_with_admin().await;
    let admin = authenticate(&database, "admin", ADMIN_PASSWORD).await;
    let new_password = "AnotherValidPassword123!";

    database
        .change_password(admin.id, new_password)
        .await
        .expect("password change should succeed");

    let changed_user = authenticate(&database, "admin", new_password).await;
    assert!(!changed_user.password_must_be_changed);

    let old_password = database
        .authenticate(credentials("admin", ADMIN_PASSWORD))
        .await
        .expect_err("old password must be rejected");
    assert!(matches!(old_password, UserError::InvalidCredentials));
}

#[tokio::test]
async fn create_user_persists_password_change_policy_and_enforces_password_validation() {
    let database = database_with_admin().await;
    let caller = admin_context();

    database
        .create_user(
            &caller,
            "operator",
            VALID_PASSWORD,
            RolesUser::Viewer,
            ActionPermissions::NONE,
            true,
        )
        .await
        .expect("user creation should succeed");
    database
        .create_user(
            &caller,
            "auditor",
            "DifferentValidPassword123!",
            RolesUser::Viewer,
            ActionPermissions::NONE,
            false,
        )
        .await
        .expect("user creation should succeed");

    assert!(
        authenticate(&database, "operator", VALID_PASSWORD)
            .await
            .password_must_be_changed
    );
    assert!(
        !authenticate(&database, "auditor", "DifferentValidPassword123!")
            .await
            .password_must_be_changed
    );

    let weak_password = database
        .create_user(
            &caller,
            "weak",
            "short",
            RolesUser::Viewer,
            ActionPermissions::NONE,
            true,
        )
        .await
        .expect_err("weak passwords must be rejected");
    assert!(matches!(weak_password, UserError::WeakPassword(_)));
}

#[tokio::test]
async fn inactive_user_cannot_authenticate_after_account_is_disabled() {
    let database = database_with_admin().await;
    let caller = admin_context();

    database
        .create_user(
            &caller,
            "disabled-user",
            VALID_PASSWORD,
            RolesUser::Viewer,
            ActionPermissions::NONE,
            false,
        )
        .await
        .expect("user creation should succeed");

    let user = authenticate(&database, "disabled-user", VALID_PASSWORD).await;
    database
        .modify_user(
            &caller,
            "disabled-user",
            RolesUser::Viewer,
            ActionPermissions::NONE,
            0,
            None,
        )
        .await
        .expect("disabling an existing user should succeed");

    let error = database
        .authenticate(credentials("disabled-user", VALID_PASSWORD))
        .await
        .expect_err("inactive users must not authenticate");
    assert!(matches!(error, UserError::InvalidCredentials));
    assert_eq!(user.username, "disabled-user");
}

#[tokio::test]
async fn firewall_config_round_trip_preserves_all_persisted_fields() {
    let database = Database::new("sqlite::memory:")
        .await
        .expect("database setup should succeed");
    let mut expected = FirewallConfig::default();
    expected.tcp_profile.rate_shift = 17;
    expected.tcp_profile.burst = 777;
    expected.udp_profile.rate_shift = 12;
    expected.udp_profile.burst = 333;
    expected.icmp_profile.rate_shift = 8;
    expected.icmp_profile.burst = 99;
    expected.default_profile.rate_shift = 4;
    expected.default_profile.burst = 55;
    expected.protocol_allowed = ActivaterEtherTypes::IPV4 | ActivaterEtherTypes::ARP;
    expected.ddos_activated = false;
    expected.incoming_ethernet_adapter = Some(2);
    expected.output_ethernet_adapter = Some(3);

    database
        .save_firewall_config(&expected)
        .await
        .expect("configuration save should succeed");
    let actual = database
        .load_firewall_config()
        .await
        .expect("configuration load should succeed")
        .expect("saved configuration should exist");

    assert_eq!(
        actual.tcp_profile.rate_shift,
        expected.tcp_profile.rate_shift
    );
    assert_eq!(actual.tcp_profile.burst, expected.tcp_profile.burst);
    assert_eq!(
        actual.udp_profile.rate_shift,
        expected.udp_profile.rate_shift
    );
    assert_eq!(actual.udp_profile.burst, expected.udp_profile.burst);
    assert_eq!(
        actual.icmp_profile.rate_shift,
        expected.icmp_profile.rate_shift
    );
    assert_eq!(actual.icmp_profile.burst, expected.icmp_profile.burst);
    assert_eq!(
        actual.default_profile.rate_shift,
        expected.default_profile.rate_shift
    );
    assert_eq!(actual.default_profile.burst, expected.default_profile.burst);
    assert_eq!(actual.protocol_allowed, expected.protocol_allowed);
    assert_eq!(actual.ddos_activated, expected.ddos_activated);
    assert_eq!(
        actual.incoming_ethernet_adapter,
        expected.incoming_ethernet_adapter
    );
    assert_eq!(
        actual.output_ethernet_adapter,
        expected.output_ethernet_adapter
    );
}

#[tokio::test]
async fn firewall_log_schema_rejects_invalid_enum_values_without_inserting() {
    let database = Database::new("sqlite::memory:")
        .await
        .expect("database setup should succeed");

    let result = sqlx::query!(
        r#"INSERT INTO firewall_logs (timestamp, level, message)
           VALUES (unixepoch(), 'INVALID', 'must not persist')"#
    )
    .execute(&database.pool)
    .await;

    assert!(
        result.is_err(),
        "invalid log level must fail the schema check"
    );
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM firewall_logs WHERE message = 'must not persist'"
    )
    .fetch_one(&database.pool)
    .await
    .expect("log count query should succeed");
    assert_eq!(count, 0);
}

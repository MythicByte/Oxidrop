use axum_login::AuthnBackend;
use oxidrop::{
    auth::Credentials,
    db::Database,
};
use secrecy::SecretString;

const DEFAULT_USERNAME: &str = "admin";
const DEFAULT_PASSWORD: &str = "password";

async fn setup_db() -> Database {
    let db = Database::new("sqlite::memory:")
        .await
        .expect("failed to set up test database");

    db.bootstrap_default_admin()
        .await
        .expect("failed to bootstrap default admin");

    db
}

fn creds(username: &str, password: &str) -> Credentials {
    Credentials {
        username: username.to_string(),
        password: SecretString::from(password.to_string()),
    }
}

#[tokio::test]
async fn default_admin_login_succeeds() {
    let db = setup_db().await;

    let result = db
        .authenticate(creds(DEFAULT_USERNAME, DEFAULT_PASSWORD))
        .await;

    let user = result
        .expect("authenticate() returned an Err instead of Ok")
        .expect("authenticate() returned Ok(None) — default admin login was rejected");

    assert_eq!(user.username, DEFAULT_USERNAME);
}

#[tokio::test]
async fn default_admin_wrong_password_is_denied() {
    let db = setup_db().await;

    let result = db
        .authenticate(creds(DEFAULT_USERNAME, "definitely-not-the-password"))
        .await;

    assert!(
        result.is_err(),
        "wrong password should return Err(InvalidCredentials), got: {result:?}"
    );
}

#[tokio::test]
async fn nonexistent_user_is_denied() {
    let db = setup_db().await;

    let result = db
        .authenticate(creds("this-user-does-not-exist", "whatever"))
        .await;

    assert!(
        result.is_err(),
        "non-existent user should return Err(InvalidCredentials), got: {result:?}"
    );
}

#[tokio::test]
async fn nonexistent_user_and_real_user_take_similar_time() {
    // Basic timing-attack sanity check: authenticate() calls burn_verify_time()
    // for unknown users specifically so that a missing user doesn't respond
    // measurably faster than a wrong-password attempt on a real user. This
    // isn't a rigorous statistical test, just a smoke check with generous slack.
    use std::time::Instant;

    let db = setup_db().await;

    // Warm-up: burn_verify_time() lazily builds+hashes a dummy password on its
    // very first call (via OnceLock), which costs one extra Argon2 hash on top
    // of the verify. Trigger that lazy init once, untimed, so it doesn't skew
    // the very first measurement below.
    let _ = db.authenticate(creds("warmup-user", "warmup")).await;

    let t0 = Instant::now();
    let _ = db.authenticate(creds("no-such-user", "whatever")).await;
    let unknown_user_elapsed = t0.elapsed();

    let t1 = Instant::now();
    let _ = db
        .authenticate(creds(DEFAULT_USERNAME, "wrong-password"))
        .await;
    let known_user_wrong_pw_elapsed = t1.elapsed();

    let ratio =
        unknown_user_elapsed.as_secs_f64() / known_user_wrong_pw_elapsed.as_secs_f64().max(0.0001);
    assert!(
        (0.5..2.0).contains(&ratio),
        "timing differs too much between unknown user ({unknown_user_elapsed:?}) \
         and known-user-wrong-password ({known_user_wrong_pw_elapsed:?}); ratio={ratio:.2}"
    );
}

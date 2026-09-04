use std::str::FromStr;

use sqlx::{
    SqlitePool,
    sqlite::{
        SqliteConnectOptions,
        SqlitePoolOptions,
    },
};

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
}

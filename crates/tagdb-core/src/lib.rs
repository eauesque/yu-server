pub mod db;
pub mod error;
pub mod import;

use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

pub use db::file::{upsert_file, FileRow, UpsertFileParams};
pub use db::mark_deleted;
pub use db::migrate::apply_pending_rust_migrations;
pub use db::CURRENT_PARSER_VERSION;
pub use db::{connect, connect_readonly};
pub use error::TagdbError;

/// Connect to a SQLCipher-encrypted database, mirroring the Python
/// core/services_core/db_cipher.py behavior (key + mmap_size=0).
pub async fn connect_encrypted(path: &str, key: &str) -> Result<SqlitePool, sqlx::Error> {
    let escaped_key = key.replace('\'', "''");
    let key_pragma = format!("'{escaped_key}'");
    let opts = SqliteConnectOptions::from_str(path)?
        .pragma("cipher_memory_security", "OFF")
        .pragma("key", key_pragma)
        .pragma("mmap_size", "0")
        .busy_timeout(Duration::from_millis(5000))
        .create_if_missing(false);

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
}

pub async fn connect_encrypted_readonly(path: &str, key: &str) -> Result<SqlitePool, sqlx::Error> {
    let escaped_key = key.replace('\'', "''");
    let key_pragma = format!("'{escaped_key}'");
    let opts = SqliteConnectOptions::from_str(path)?
        .read_only(true)
        .pragma("cipher_memory_security", "OFF")
        .pragma("key", key_pragma)
        .pragma("mmap_size", "0")
        .busy_timeout(Duration::from_millis(5000))
        .create_if_missing(false);

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
}

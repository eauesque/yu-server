use crate::TagdbError;
use sqlx::SqlitePool;

struct Migration {
    version: i64,
    description: &'static str,
    sql: &'static str,
}

static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        description: "rust runner init marker",
        sql: include_str!("../migrations/084_rust_runner_init.sql"),
    },
    Migration {
        version: 2,
        description: "scheduler execution history",
        sql: include_str!("../migrations/085_scheduler_history.sql"),
    },
    Migration {
        version: 3,
        description: "agent session scopes (Scope Fence, parity with Python schema migration 84)",
        sql: include_str!("../migrations/003_agent_session_scopes.sql"),
    },
];

pub async fn apply_pending_rust_migrations(pool: &SqlitePool) -> Result<(), TagdbError> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    let result: Result<(), TagdbError> = async {
        sqlx::raw_sql(
            "
            CREATE TABLE IF NOT EXISTS rust_schema_version(
                version INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL,
                description TEXT
            )
            ",
        )
        .execute(&mut *conn)
        .await?;

        let current: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM rust_schema_version")
                .fetch_one(&mut *conn)
                .await?;

        for m in MIGRATIONS {
            if m.version <= current {
                continue;
            }

            tracing::info!("Applying Rust migration {}: {}", m.version, m.description);
            sqlx::raw_sql(m.sql).execute(&mut *conn).await?;
            sqlx::query(
                "INSERT OR IGNORE INTO rust_schema_version(version, applied_at, description) \
                 VALUES(?, CAST(strftime('%s','now') AS INTEGER), ?)",
            )
            .bind(m.version)
            .bind(m.description)
            .execute(&mut *conn)
            .await?;
        }

        sqlx::query(
            "
            DELETE FROM schema_version
            WHERE version IN (84, 85)
              AND description IN ('rust runner init marker', 'scheduler execution history')
            ",
        )
        .execute(&mut *conn)
        .await?;

        Ok(())
    }
    .await;

    match result {
        Ok(()) => {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            Ok(())
        }
        Err(e) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;
    use tempfile::NamedTempFile;

    async fn pool_with_schema_version() -> (NamedTempFile, SqlitePool) {
        let f = NamedTempFile::new().unwrap();
        let path = format!("sqlite:{}", f.path().display());
        let opts = SqliteConnectOptions::from_str(&path)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::raw_sql(
            "
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL,
                description TEXT
            )
            ",
        )
        .execute(&pool)
        .await
        .unwrap();
        (f, pool)
    }

    #[tokio::test]
    async fn test_applies_migration_84() {
        let (_f, pool) = pool_with_schema_version().await;
        apply_pending_rust_migrations(&pool).await.unwrap();

        let ver: i64 = sqlx::query_scalar("SELECT MAX(version) FROM rust_schema_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(ver, 3);

        let old_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(old_count, 0);

        let scopes_table_exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'agent_session_scopes'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(scopes_table_exists, 1);
    }

    #[tokio::test]
    async fn test_idempotent() {
        let (_f, pool) = pool_with_schema_version().await;
        apply_pending_rust_migrations(&pool).await.unwrap();
        apply_pending_rust_migrations(&pool).await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rust_schema_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_skips_already_applied() {
        let (_f, pool) = pool_with_schema_version().await;
        sqlx::query(
            "CREATE TABLE rust_schema_version(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL, description TEXT)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO rust_schema_version(version, applied_at, description) VALUES(1, 0, 'pre')",
        )
        .execute(&pool)
        .await
        .unwrap();

        apply_pending_rust_migrations(&pool).await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rust_schema_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn migrates_existing_rust_84_85_rows_to_new_table() {
        let (_f, pool) = pool_with_schema_version().await;
        sqlx::query(
            "INSERT INTO schema_version(version, applied_at, description) VALUES(84, 0, 'rust runner init marker')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO schema_version(version, applied_at, description) VALUES(85, 0, 'scheduler execution history')",
        )
        .execute(&pool)
        .await
        .unwrap();

        apply_pending_rust_migrations(&pool).await.unwrap();

        let rust_ver: i64 = sqlx::query_scalar("SELECT MAX(version) FROM rust_schema_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rust_ver, 3);

        let old_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM schema_version WHERE version IN (84, 85)")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(old_count, 0);
    }

    #[tokio::test]
    async fn creates_scheduler_history_table_even_if_python_recorded_85_without_creating_it() {
        let (_f, pool) = pool_with_schema_version().await;
        sqlx::query(
            "INSERT INTO schema_version(version, applied_at, description) VALUES(85, 0, 'scheduler execution history')",
        )
        .execute(&pool)
        .await
        .unwrap();

        apply_pending_rust_migrations(&pool).await.unwrap();

        let exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'scheduler_history'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(exists, 1);
    }

    #[tokio::test]
    async fn rolls_back_partial_rust_schema_version_records_on_failure() {
        let (_f, pool) = pool_with_schema_version().await;
        sqlx::query("CREATE TABLE scheduler_history(id INTEGER PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();

        // Pre-existing table lacks job_id/timestamp, so the migration's
        // CREATE INDEX statement fails with a "no such column" error (SQLite
        // reports the missing column, not the table name).
        let err = apply_pending_rust_migrations(&pool).await.unwrap_err();
        assert!(format!("{err}").contains("no such column"));

        let exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'rust_schema_version'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(exists, 0);
    }
}

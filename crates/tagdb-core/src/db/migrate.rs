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
    Migration {
        version: 4,
        description: "repair legacy Rust meta_source identifiers",
        sql: include_str!("../migrations/004_meta_source_vocabulary.sql"),
    },
    Migration {
        version: 5,
        description: "requeue NovelAI metadata for canonical parsing",
        sql: include_str!("../migrations/005_requeue_nai_meta_reextraction.sql"),
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
            );
            CREATE TABLE files (
                path TEXT PRIMARY KEY,
                meta_source TEXT,
                parser_version INTEGER NOT NULL DEFAULT 1
            );
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
        assert_eq!(ver, 5);

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
        assert_eq!(count, 5);
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
        assert_eq!(count, 5);
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
        assert_eq!(rust_ver, 5);

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

    #[tokio::test]
    async fn repairs_only_legacy_rust_meta_sources_idempotently() {
        let (_f, pool) = pool_with_schema_version().await;
        let cases = [
            ("nai-v4.WEBP", "nai_v4", "novelai_v4_webp"),
            ("nai-v4.png", "nai_v4", "novelai_v4_png"),
            ("nai-v4.avif", "nai_v4", "novelai_v4"),
            ("nai-v3.webp", "nai_v3", "novelai_webp"),
            ("nai-v3.png", "nai_v3", "novelai_png"),
            ("comfy.webm", "comfy", "comfy_webm"),
            ("comfy.webp", "comfy", "comfy_webp"),
            ("comfy.flac", "comfy", "comfy_flac"),
            ("comfy.png", "comfy", "comfy_png"),
            ("a1111.jpg", "a1111", "a1111_jpg"),
            ("a1111.jpeg", "a1111", "a1111_jpg"),
            ("a1111.webp", "a1111", "a1111_webp"),
            ("a1111.png", "a1111", "a1111_png"),
            ("a1111.jxl", "a1111", "a1111"),
            ("python-comfy.png", "comfyui", "comfyui"),
            ("sidecar.txt", "txt", "txt"),
            ("canonical.png", "novelai_v4_png", "novelai_v4_png"),
        ];
        for (path, source, _) in cases {
            sqlx::query("INSERT INTO files(path, meta_source) VALUES(?, ?)")
                .bind(path)
                .bind(source)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::raw_sql(
            "
            CREATE TABLE excluded_source_updates(path TEXT);
            CREATE TRIGGER audit_excluded_source_updates
            BEFORE UPDATE OF meta_source ON files
            WHEN OLD.meta_source IN ('comfyui', 'txt')
            BEGIN
                INSERT INTO excluded_source_updates(path) VALUES(OLD.path);
            END;
            ",
        )
        .execute(&pool)
        .await
        .unwrap();

        apply_pending_rust_migrations(&pool).await.unwrap();

        for (path, _, expected) in cases {
            let actual: String = sqlx::query_scalar("SELECT meta_source FROM files WHERE path = ?")
                .bind(path)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(actual, expected, "unexpected meta_source for {path}");
        }
        let excluded_updates: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM excluded_source_updates")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(excluded_updates, 0);

        let once: Vec<(String, String)> =
            sqlx::query_as("SELECT path, meta_source FROM files ORDER BY path")
                .fetch_all(&pool)
                .await
                .unwrap();
        apply_pending_rust_migrations(&pool).await.unwrap();
        let twice: Vec<(String, String)> =
            sqlx::query_as("SELECT path, meta_source FROM files ORDER BY path")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(twice, once);
    }

    #[tokio::test]
    async fn requeues_only_nai_sources_for_reextraction_idempotently() {
        let (_f, pool) = pool_with_schema_version().await;
        let cases = [
            ("novelai-v4.png", "novelai_v4_png", 6, 0),
            ("novelai-v4.webp", "novelai_v4_webp", 6, 0),
            ("novelai-v4.avif", "novelai_v4", 6, 0),
            ("novelai-v3.png", "novelai_png", 6, 0),
            ("novelai-v3.webp", "novelai_webp", 6, 0),
            ("nai.webp", "nai_webp", 6, 0),
            ("comfy.png", "comfy_png", 6, 6),
            ("a1111.png", "a1111_png", 6, 6),
            ("tensor-art.png", "tensor_art", 6, 6),
            ("sidecar.txt", "txt", 6, 6),
            ("unknown.bin", "unknown", 6, 6),
            ("already-zero.png", "novelai_v4_png", 0, 0),
        ];
        for (path, source, parser_version, _) in cases {
            sqlx::query("INSERT INTO files(path, meta_source, parser_version) VALUES(?, ?, ?)")
                .bind(path)
                .bind(source)
                .bind(parser_version)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::raw_sql(
            "
            CREATE TABLE parser_version_updates(path TEXT);
            CREATE TRIGGER audit_parser_version_updates
            BEFORE UPDATE OF parser_version ON files
            BEGIN
                INSERT INTO parser_version_updates(path) VALUES(OLD.path);
            END;
            ",
        )
        .execute(&pool)
        .await
        .unwrap();

        apply_pending_rust_migrations(&pool).await.unwrap();

        for (path, _, _, expected) in cases {
            let actual: i64 = sqlx::query_scalar("SELECT parser_version FROM files WHERE path = ?")
                .bind(path)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(actual, expected, "unexpected parser_version for {path}");
        }
        let updated_paths: Vec<String> =
            sqlx::query_scalar("SELECT path FROM parser_version_updates ORDER BY path")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            updated_paths,
            [
                "nai.webp",
                "novelai-v3.png",
                "novelai-v3.webp",
                "novelai-v4.avif",
                "novelai-v4.png",
                "novelai-v4.webp",
            ]
        );

        let once: Vec<(String, i64)> =
            sqlx::query_as("SELECT path, parser_version FROM files ORDER BY path")
                .fetch_all(&pool)
                .await
                .unwrap();
        sqlx::raw_sql(include_str!(
            "../migrations/005_requeue_nai_meta_reextraction.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        let twice: Vec<(String, i64)> =
            sqlx::query_as("SELECT path, parser_version FROM files ORDER BY path")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(twice, once);
        let update_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM parser_version_updates")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(update_count, 6);
    }
}

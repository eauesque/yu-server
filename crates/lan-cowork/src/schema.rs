//! LAN Cowork's own DB schema (peers / peer_tokens / peer_pairing_requests /
//! lan_cowork_identity / import_* tables), applied only for standalone
//! (Python-absent) deployments.
//!
//! This lived in `tagdb-core` until the crate split's S4 plan revisited that
//! choice; see `docs/superpowers/plans/2026-08-06-lan-cowork-s4-crate-split.md`
//! §3.10 (5) and its dated revision note for why it moved here.

use sqlx::SqlitePool;

/// Create the LAN Cowork peer-family schema (peers / peer_tokens /
/// peer_pairing_requests / lan_cowork_identity) for standalone deployments where
/// Python (which owns these tables via its migration chain) never runs.
///
/// Idempotent (`CREATE TABLE IF NOT EXISTS`). MUST NOT be added to
/// `tagdb-core`'s unconditional `MIGRATIONS` array: in hybrid mode Python
/// solely owns these tables and their schema_version, so creating them from
/// Rust too would double-own the schema and desync versions during the
/// migration period. standalone == Python absent, so there Rust is the sole
/// owner. Call this ONLY when standalone.
pub async fn apply_standalone_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(include_str!("../migrations/086_lan_cowork_peer_family.sql"))
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lan_cowork_standalone_schema_creates_peer_family_and_import_tables_idempotently() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        // apply twice to prove idempotency.
        apply_standalone_schema(&pool).await.unwrap();
        apply_standalone_schema(&pool).await.unwrap();
        for table in [
            "peers",
            "peer_tokens",
            "peer_pairing_requests",
            "lan_cowork_identity",
        ] {
            let exists: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            )
            .bind(table)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(exists, 1, "table {table} must exist");
        }
        // peers must be exactly the 13-column post-migration-75 schema (no allow_legacy_auth).
        let cols: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info('peers')")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(cols.len(), 13, "peers must have 13 columns, got {cols:?}");
        assert!(
            !cols.iter().any(|c| c == "allow_legacy_auth"),
            "allow_legacy_auth must be dropped"
        );
        assert!(cols.iter().any(|c| c == "last_reached_at"));
        assert!(cols.iter().any(|c| c == "x25519_pk"));

        for table in [
            "import_session",
            "import_file_id_map",
            "import_collection_id_map",
        ] {
            let exists: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            )
            .bind(table)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(exists, 1, "table {table} must exist");
        }

        let session_cols: Vec<(String, String, i64, Option<String>, i64)> = sqlx::query_as(
            "SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info('import_session')",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            session_cols,
            vec![
                ("id".into(), "TEXT".into(), 0, None, 1),
                ("peer_id".into(), "TEXT".into(), 1, None, 0),
                ("peer_name".into(), "TEXT".into(), 1, None, 0),
                ("mode".into(), "TEXT".into(), 1, None, 0),
                (
                    "status".into(),
                    "TEXT".into(),
                    1,
                    Some("'pending'".into()),
                    0
                ),
                ("last_seen_rowid".into(), "INTEGER".into(), 0, None, 0),
                ("snapshot_max_rowid".into(), "INTEGER".into(), 0, None, 0),
                ("total_files".into(), "INTEGER".into(), 0, None, 0),
                (
                    "done_files".into(),
                    "INTEGER".into(),
                    1,
                    Some("0".into()),
                    0
                ),
                ("import_folder".into(), "TEXT".into(), 1, None, 0),
                (
                    "options".into(),
                    "TEXT".into(),
                    1,
                    Some("'{\"include_favorites\":false,\"merge_metadata\":false}'".into()),
                    0
                ),
                ("created_at".into(), "INTEGER".into(), 1, None, 0),
                ("updated_at".into(), "INTEGER".into(), 1, None, 0),
            ]
        );

        for (table, expected) in [
            (
                "import_file_id_map",
                vec![
                    ("session_id", "TEXT", 1, None, 1),
                    ("remote_peer_id", "TEXT", 1, None, 2),
                    ("remote_file_id", "INTEGER", 1, None, 3),
                    ("local_file_id", "INTEGER", 1, None, 0),
                    ("status", "TEXT", 1, Some("'done'"), 0),
                ],
            ),
            (
                "import_collection_id_map",
                vec![
                    ("session_id", "TEXT", 1, None, 1),
                    ("remote_peer_id", "TEXT", 1, None, 2),
                    ("remote_collection_id", "INTEGER", 1, None, 3),
                    ("local_collection_id", "INTEGER", 1, None, 0),
                ],
            ),
        ] {
            let actual: Vec<(String, String, i64, Option<String>, i64)> = sqlx::query_as(&format!(
                "SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info('{table}')"
            ))
            .fetch_all(&pool)
            .await
            .unwrap();
            let expected: Vec<(String, String, i64, Option<String>, i64)> = expected
                .into_iter()
                .map(|(name, ty, notnull, default, pk)| {
                    (name.into(), ty.into(), notnull, default.map(Into::into), pk)
                })
                .collect();
            assert_eq!(actual, expected, "{table} must match the production schema");
        }
    }
}

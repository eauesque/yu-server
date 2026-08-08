//! LAN Cowork remote-import planner and session read queries.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Map, Value};
use sqlx::{QueryBuilder, Row, Sqlite, SqliteConnection, SqlitePool};

use super::lan_cowork_import_meta::{chunks, unique_file_ids, IN_CHUNK_SIZE};

const SESSION_COLUMNS: &str = "id,peer_id,peer_name,mode,status,last_seen_rowid,snapshot_max_rowid,total_files,done_files,import_folder,options,created_at,updated_at";
const UPDATE_COLUMNS: [&str; 5] = [
    "status",
    "last_seen_rowid",
    "snapshot_max_rowid",
    "total_files",
    "done_files",
];
const DOWNLOAD_BUDGET_PATH: &str = "$._lan_import_download_remaining";

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs() as i64
}

fn file_hash(file: &Value) -> Option<&str> {
    file.get("hash")?.as_str().filter(|hash| !hash.is_empty())
}

fn session_to_value(row: &sqlx::sqlite::SqliteRow) -> Result<Value, sqlx::Error> {
    let options = row
        .try_get::<Option<String>, _>("options")?
        .unwrap_or_default();
    let options = if options.is_empty() {
        json!({})
    } else {
        serde_json::from_str(&options).map_err(|error| sqlx::Error::Decode(Box::new(error)))?
    };
    Ok(json!({
        "id": row.try_get::<String, _>("id")?,
        "peer_id": row.try_get::<String, _>("peer_id")?,
        "peer_name": row.try_get::<String, _>("peer_name")?,
        "mode": row.try_get::<String, _>("mode")?,
        "status": row.try_get::<String, _>("status")?,
        "last_seen_rowid": row.try_get::<Option<i64>, _>("last_seen_rowid")?,
        "snapshot_max_rowid": row.try_get::<Option<i64>, _>("snapshot_max_rowid")?,
        "total_files": row.try_get::<Option<i64>, _>("total_files")?,
        "done_files": row.try_get::<i64, _>("done_files")?,
        "import_folder": row.try_get::<String, _>("import_folder")?,
        "options": options,
        "created_at": row.try_get::<i64, _>("created_at")?,
        "updated_at": row.try_get::<i64, _>("updated_at")?,
    }))
}

pub async fn plan(
    pool: &SqlitePool,
    remote_files: &[Value],
) -> Result<(Vec<Value>, Vec<Value>), sqlx::Error> {
    if remote_files.is_empty() {
        return Ok((vec![], vec![]));
    }

    let hashes = unique_file_ids(
        &remote_files
            .iter()
            .filter_map(file_hash)
            .map(str::to_owned)
            .collect::<Vec<_>>(),
    );
    let mut existing: HashMap<String, i64> = HashMap::new();
    for chunk in chunks(&hashes, IN_CHUNK_SIZE) {
        let mut query = QueryBuilder::<Sqlite>::new("SELECT hash,id FROM files WHERE hash IN (");
        let mut separated = query.separated(",");
        for hash in chunk {
            separated.push_bind(hash);
        }
        separated.push_unseparated(") AND is_deleted=0");
        for row in query.build().fetch_all(pool).await? {
            existing.insert(row.try_get("hash")?, row.try_get("id")?);
        }
    }

    let mut to_import = Vec::new();
    let mut to_skip = Vec::new();
    for file in remote_files {
        if let Some(local_id) = file_hash(file).and_then(|hash| existing.get(hash)) {
            let remote_id = file
                .get("id")
                .and_then(Value::as_i64)
                .ok_or_else(|| sqlx::Error::Protocol("invalid remote file id".into()))?;
            to_skip.push(json!({
                "remote_id": remote_id,
                "local_id": local_id,
            }));
        } else {
            to_import.push(file.clone());
        }
    }
    Ok((to_import, to_skip))
}

pub async fn get(pool: &SqlitePool, session_id: &str) -> Result<Option<Value>, sqlx::Error> {
    sqlx::query(&format!(
        "SELECT {SESSION_COLUMNS} FROM import_session WHERE id=?"
    ))
    .bind(session_id)
    .fetch_optional(pool)
    .await?
    .map(|row| session_to_value(&row))
    .transpose()
}

pub async fn list_all(pool: &SqlitePool) -> Result<Vec<Value>, sqlx::Error> {
    sqlx::query(&format!(
        "SELECT {SESSION_COLUMNS} FROM import_session ORDER BY created_at DESC"
    ))
    .fetch_all(pool)
    .await?
    .iter()
    .map(session_to_value)
    .collect()
}

pub async fn is_file_processed(
    pool: &SqlitePool,
    session_id: &str,
    remote_peer_id: &str,
    remote_id: i64,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT 1 FROM import_file_id_map WHERE session_id=? AND remote_peer_id=? AND remote_file_id=?",
    )
    .bind(session_id)
    .bind(remote_peer_id)
    .bind(remote_id)
    .fetch_optional(pool)
    .await?
    .is_some())
}

pub async fn get_local_file_id(
    pool: &SqlitePool,
    session_id: &str,
    remote_peer_id: &str,
    remote_id: i64,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query(
        "SELECT local_file_id FROM import_file_id_map WHERE session_id=? AND remote_peer_id=? AND remote_file_id=?",
    )
    .bind(session_id)
    .bind(remote_peer_id)
    .bind(remote_id)
    .fetch_optional(pool)
    .await?
    .map(|row| row.try_get("local_file_id"))
    .transpose()
}

/// Creates an import session on the caller-owned connection.
///
/// Core write functions never issue `BEGIN`, `COMMIT`, or `ROLLBACK`; the caller
/// must keep related writes in one transaction.
pub async fn create(
    conn: &mut SqliteConnection,
    peer_id: &str,
    peer_name: &str,
    mode: &str,
    import_folder: &str,
    options: &Map<String, Value>,
) -> Result<String, sqlx::Error> {
    let sid = uuid::Uuid::new_v4().to_string();
    let mut merged = Map::from_iter([
        ("include_favorites".to_owned(), Value::Bool(false)),
        ("merge_metadata".to_owned(), Value::Bool(false)),
    ]);
    merged.extend(options.clone());
    let options =
        serde_json::to_string(&merged).map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
    let now = now_secs();
    sqlx::query(
        "INSERT INTO import_session (id,peer_id,peer_name,mode,status,last_seen_rowid,snapshot_max_rowid,total_files,done_files,import_folder,options,created_at,updated_at) VALUES (?,?,?,?,'pending',NULL,NULL,NULL,0,?,?,?,?)",
    )
    .bind(&sid)
    .bind(peer_id)
    .bind(peer_name)
    .bind(mode)
    .bind(import_folder)
    .bind(options)
    .bind(now)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    Ok(sid)
}

fn row_update_value(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<Value, sqlx::Error> {
    match column {
        "status" => Ok(json!(row.try_get::<String, _>(column)?)),
        "last_seen_rowid" | "snapshot_max_rowid" | "total_files" | "done_files" => {
            Ok(json!(row.try_get::<Option<i64>, _>(column)?))
        }
        _ => unreachable!("UPDATE_COLUMNS is the only caller"),
    }
}

fn push_json_bind(query: &mut QueryBuilder<Sqlite>, value: &Value) -> Result<(), sqlx::Error> {
    match value {
        Value::Null => {
            query.push_bind(Option::<i64>::None);
        }
        Value::Bool(value) => {
            query.push_bind(*value);
        }
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                query.push_bind(value);
            } else if let Some(value) = value.as_u64() {
                query.push_bind(
                    i64::try_from(value).map_err(|_| {
                        sqlx::Error::Protocol("integer outside SQLite range".into())
                    })?,
                );
            } else {
                return Err(sqlx::Error::Protocol("non-integer SQLite value".into()));
            }
        }
        Value::String(value) => {
            query.push_bind(value.clone());
        }
        Value::Array(_) | Value::Object(_) => {
            return Err(sqlx::Error::Protocol("unsupported SQLite value".into()))
        }
    }
    Ok(())
}

/// Updates only the import-session fields in `UPDATE_COLUMNS` on a caller-owned connection.
///
/// Core write functions never issue `BEGIN`, `COMMIT`, or `ROLLBACK`; the dirty
/// check and update therefore run in the caller's single transaction.
pub async fn update(
    conn: &mut SqliteConnection,
    session_id: &str,
    fields: &Map<String, Value>,
) -> Result<(), sqlx::Error> {
    let requested = UPDATE_COLUMNS
        .into_iter()
        .filter(|column| fields.contains_key(*column))
        .collect::<Vec<_>>();
    if requested.is_empty() {
        return Ok(());
    }

    let Some(row) = sqlx::query(
        "SELECT status,last_seen_rowid,snapshot_max_rowid,total_files,done_files FROM import_session WHERE id=?",
    )
    .bind(session_id)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(());
    };
    let mut dirty = Vec::new();
    for column in requested {
        if row_update_value(&row, column)? != fields[column] {
            dirty.push(column);
        }
    }
    if dirty.is_empty() {
        return Ok(());
    }

    let mut query = QueryBuilder::<Sqlite>::new("UPDATE import_session SET ");
    for (index, column) in dirty.iter().enumerate() {
        if index != 0 {
            query.push(",");
        }
        query.push(*column).push("=");
        push_json_bind(&mut query, &fields[*column])?;
    }
    query
        .push(",updated_at=")
        .push_bind(now_secs())
        .push(" WHERE id=")
        .push_bind(session_id);
    query.build().execute(&mut *conn).await?;
    Ok(())
}

/// Registers one file mapping on a caller-owned, already-active transaction.
///
/// Core write functions never issue `BEGIN`, `COMMIT`, or `ROLLBACK`. Do not call
/// this on a bare autocommit connection: its insert and progress update must be
/// atomic, so standalone callers must use `register_file_standalone`.
pub(crate) async fn register_file(
    conn: &mut SqliteConnection,
    session_id: &str,
    remote_peer_id: &str,
    remote_id: i64,
    local_id: i64,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let inserted = sqlx::query(
        "INSERT INTO import_file_id_map (session_id,remote_peer_id,remote_file_id,local_file_id,status) VALUES (?,?,?,?,?) ON CONFLICT(session_id,remote_peer_id,remote_file_id) DO NOTHING",
    )
    .bind(session_id)
    .bind(remote_peer_id)
    .bind(remote_id)
    .bind(local_id)
    .bind(status)
    .execute(&mut *conn)
    .await?
    .rows_affected()
        > 0;
    if inserted {
        sqlx::query("UPDATE import_session SET done_files=done_files+1, updated_at=? WHERE id=?")
            .bind(now_secs())
            .bind(session_id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(inserted)
}

/// Returns or creates a local collection mapping on a caller-owned transaction.
///
/// Core write functions never issue `BEGIN`, `COMMIT`, or `ROLLBACK`; standalone
/// callers must use `get_or_create_collection_standalone` so all seven steps share
/// one transaction.
pub(crate) async fn get_or_create_collection(
    conn: &mut SqliteConnection,
    session_id: &str,
    remote_peer_id: &str,
    remote_collection_id: i64,
    collection_name: &str,
) -> Result<i64, sqlx::Error> {
    if let Some(local_id) = sqlx::query_scalar::<_, i64>(
        "SELECT local_collection_id FROM import_collection_id_map WHERE session_id=? AND remote_peer_id=? AND remote_collection_id=?",
    )
    .bind(session_id)
    .bind(remote_peer_id)
    .bind(remote_collection_id)
    .fetch_optional(&mut *conn)
    .await?
    {
        return Ok(local_id);
    }

    let name_clean = collection_name.trim();
    let existing =
        sqlx::query("SELECT id FROM collections WHERE LOWER(TRIM(name))=LOWER(?) ORDER BY id")
            .bind(name_clean)
            .fetch_all(&mut *conn)
            .await?;
    if existing.len() > 1 {
        // collection names originate from peers; log only the ambiguity count.
        tracing::warn!(
            matches = existing.len(),
            "multiple import collection matches; using first"
        );
    }
    let local_id = if let Some(row) = existing.first() {
        row.try_get("id")?
    } else {
        sqlx::query("INSERT INTO collections (name, sort_order, created_at) VALUES (?, 0, ?)")
            .bind(name_clean)
            .bind(now_secs())
            .execute(&mut *conn)
            .await?
            .last_insert_rowid()
    };
    sqlx::query(
        "INSERT INTO import_collection_id_map (session_id,remote_peer_id,remote_collection_id,local_collection_id) VALUES (?,?,?,?) ON CONFLICT(session_id,remote_peer_id,remote_collection_id) DO NOTHING",
    )
    .bind(session_id)
    .bind(remote_peer_id)
    .bind(remote_collection_id)
    .bind(local_id)
    .execute(&mut *conn)
    .await?;
    Ok(local_id)
}

pub(crate) async fn finish_write<T>(
    conn: &mut SqliteConnection,
    result: Result<T, sqlx::Error>,
) -> Result<T, sqlx::Error> {
    match result {
        Ok(value) => {
            if let Err(error) = sqlx::query("COMMIT").execute(&mut *conn).await {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(error);
            }
            Ok(value)
        }
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(error)
        }
    }
}

pub async fn create_standalone(
    pool: &SqlitePool,
    peer_id: &str,
    peer_name: &str,
    mode: &str,
    import_folder: &str,
    options: &Map<String, Value>,
) -> Result<String, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let result = create(&mut conn, peer_id, peer_name, mode, import_folder, options).await;
    finish_write(&mut conn, result).await
}

pub async fn update_standalone(
    pool: &SqlitePool,
    session_id: &str,
    fields: &Map<String, Value>,
) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let result = update(&mut conn, session_id, fields).await;
    finish_write(&mut conn, result).await
}

pub async fn claim_execution(
    pool: &SqlitePool,
    session_id: &str,
    download_limit: u64,
) -> Result<bool, sqlx::Error> {
    let download_limit = i64::try_from(download_limit)
        .map_err(|_| sqlx::Error::Protocol("download limit outside SQLite range".into()))?;
    Ok(sqlx::query(
        "UPDATE import_session SET status='running', options=json_set(COALESCE(NULLIF(options,''),'{}'), ?, ?), updated_at=? WHERE id=? AND status='pending'",
    )
    .bind(DOWNLOAD_BUDGET_PATH)
    .bind(download_limit)
    .bind(now_secs())
    .bind(session_id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn consume_download_budget(
    pool: &SqlitePool,
    session_id: &str,
    size: u64,
) -> Result<bool, sqlx::Error> {
    let size = i64::try_from(size)
        .map_err(|_| sqlx::Error::Protocol("download size outside SQLite range".into()))?;
    Ok(sqlx::query(
        "UPDATE import_session SET options=json_set(options, ?, json_extract(options, ?) - ?), updated_at=? WHERE id=? AND status='running' AND json_type(options, ?)='integer' AND json_extract(options, ?) >= ?",
    )
    .bind(DOWNLOAD_BUDGET_PATH)
    .bind(DOWNLOAD_BUDGET_PATH)
    .bind(size)
    .bind(now_secs())
    .bind(session_id)
    .bind(DOWNLOAD_BUDGET_PATH)
    .bind(DOWNLOAD_BUDGET_PATH)
    .bind(size)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn register_file_standalone(
    pool: &SqlitePool,
    session_id: &str,
    remote_peer_id: &str,
    remote_id: i64,
    local_id: i64,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let result = register_file(
        &mut conn,
        session_id,
        remote_peer_id,
        remote_id,
        local_id,
        status,
    )
    .await;
    finish_write(&mut conn, result).await
}

pub async fn get_or_create_collection_standalone(
    pool: &SqlitePool,
    session_id: &str,
    remote_peer_id: &str,
    remote_collection_id: i64,
    collection_name: &str,
) -> Result<i64, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let result = get_or_create_collection(
        &mut conn,
        session_id,
        remote_peer_id,
        remote_collection_id,
        collection_name,
    )
    .await;
    finish_write(&mut conn, result).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    const DDL: &str = r#"
        CREATE TABLE files (
          id INTEGER PRIMARY KEY,
          path TEXT NOT NULL UNIQUE,
          mtime INTEGER NOT NULL,
          size INTEGER NOT NULL,
          hash TEXT,
          phash TEXT,
          is_deleted INTEGER NOT NULL DEFAULT 0,
          meta_source TEXT,
          not_modified INTEGER NOT NULL DEFAULT 0,
          parser_version INTEGER NOT NULL DEFAULT 1,
          is_zip_member INTEGER NOT NULL DEFAULT 0,
          extracted_from_zip TEXT,
          extracted_from_internal TEXT,
          extraction_date INTEGER,
          extracted_to_file_id INTEGER,
          width INTEGER,
          height INTEGER,
          imported_from_peer TEXT,
          has_sweep INTEGER NOT NULL DEFAULT 0,
          file_ext TEXT GENERATED ALWAYS AS (
            CASE
                WHEN path LIKE '%.png' THEN '.png'
                WHEN path LIKE '%.jpg' THEN '.jpg'
                WHEN path LIKE '%.jpeg' THEN '.jpeg'
                WHEN path LIKE '%.webp' THEN '.webp'
                WHEN path LIKE '%.gif' THEN '.gif'
                WHEN path LIKE '%.bmp' THEN '.bmp'
                WHEN path LIKE '%.tif' THEN '.tif'
                WHEN path LIKE '%.tiff' THEN '.tiff'
                WHEN path LIKE '%.avif' THEN '.avif'
                WHEN path LIKE '%.heif' THEN '.heif'
                WHEN path LIKE '%.heic' THEN '.heic'
                WHEN path LIKE '%.jxl' THEN '.jxl'
                WHEN path LIKE '%.svg' THEN '.svg'
                WHEN path LIKE '%.webm' THEN '.webm'
                WHEN path LIKE '%.mp4' THEN '.mp4'
                WHEN path LIKE '%.mov' THEN '.mov'
                WHEN path LIKE '%.m4v' THEN '.m4v'
                WHEN path LIKE '%.avi' THEN '.avi'
                WHEN path LIKE '%.mkv' THEN '.mkv'
                WHEN path LIKE '%.ogv' THEN '.ogv'
                WHEN path LIKE '%.ts' THEN '.ts'
                WHEN path LIKE '%.m2ts' THEN '.m2ts'
                WHEN path LIKE '%.mp3' THEN '.mp3'
                WHEN path LIKE '%.wav' THEN '.wav'
                WHEN path LIKE '%.ogg' THEN '.ogg'
                WHEN path LIKE '%.opus' THEN '.opus'
                WHEN path LIKE '%.m4a' THEN '.m4a'
                WHEN path LIKE '%.aac' THEN '.aac'
                WHEN path LIKE '%.flac' THEN '.flac'
            END
          ) STORED,
          FOREIGN KEY (extracted_to_file_id) REFERENCES files(id)
        );
        CREATE TABLE collections (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          sort_order INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL,
          query_json TEXT
        );
        CREATE TABLE import_session (
          id TEXT PRIMARY KEY,
          peer_id TEXT NOT NULL,
          peer_name TEXT NOT NULL,
          mode TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          last_seen_rowid INTEGER,
          snapshot_max_rowid INTEGER,
          total_files INTEGER,
          done_files INTEGER NOT NULL DEFAULT 0,
          import_folder TEXT NOT NULL,
          options TEXT NOT NULL DEFAULT '{"include_favorites":false,"merge_metadata":false}',
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE TABLE import_file_id_map (
          session_id TEXT NOT NULL REFERENCES import_session(id) ON DELETE CASCADE,
          remote_peer_id TEXT NOT NULL,
          remote_file_id INTEGER NOT NULL,
          local_file_id INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'done',
          PRIMARY KEY (session_id, remote_peer_id, remote_file_id)
        );
        CREATE TABLE import_collection_id_map (
          session_id TEXT NOT NULL REFERENCES import_session(id) ON DELETE CASCADE,
          remote_peer_id TEXT NOT NULL,
          remote_collection_id INTEGER NOT NULL,
          local_collection_id INTEGER NOT NULL,
          PRIMARY KEY (session_id, remote_peer_id, remote_collection_id)
        );
    "#;

    async fn mem_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        for statement in DDL
            .split(';')
            .filter(|statement| !statement.trim().is_empty())
        {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
        pool
    }

    async fn add_file(pool: &SqlitePool, id: i64, hash: &str, is_deleted: i64) {
        sqlx::query("INSERT INTO files (id,path,mtime,size,hash,is_deleted) VALUES (?,?,?,?,?,?)")
            .bind(id)
            .bind(format!("/{id}.png"))
            .bind(0)
            .bind(0)
            .bind(hash)
            .bind(is_deleted)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn add_session(pool: &SqlitePool, id: &str, created_at: i64, options: &str) {
        sqlx::query(
            "INSERT INTO import_session (id,peer_id,peer_name,mode,status,last_seen_rowid,snapshot_max_rowid,total_files,done_files,import_folder,options,created_at,updated_at) VALUES (?,'peer','Peer','full','running',3,4,5,2,'/imports',?,?,?)",
        )
        .bind(id)
        .bind(options)
        .bind(created_at)
        .bind(created_at + 1)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn plan_empty_input_returns_empty_lists() {
        assert_eq!(
            plan(&mem_pool().await, &[]).await.unwrap(),
            (vec![], vec![])
        );
    }

    #[tokio::test]
    async fn plan_skips_matching_hashes() {
        let pool = mem_pool().await;
        add_file(&pool, 7, "same", 0).await;
        assert_eq!(
            plan(&pool, &[json!({"id": 9, "hash": "same"})])
                .await
                .unwrap(),
            (vec![], vec![json!({"remote_id": 9, "local_id": 7})])
        );
    }

    #[tokio::test]
    async fn plan_rejects_matching_hash_without_integer_id() {
        let pool = mem_pool().await;
        add_file(&pool, 7, "same", 0).await;
        assert!(plan(&pool, &[json!({"hash": "same"})]).await.is_err());
    }

    #[tokio::test]
    async fn plan_imports_unknown_hashes() {
        let pool = mem_pool().await;
        let remote = json!({"id": 9, "hash": "new"});
        assert_eq!(
            plan(&pool, std::slice::from_ref(&remote)).await.unwrap(),
            (vec![remote], vec![])
        );
    }

    #[tokio::test]
    async fn plan_always_imports_files_without_truthy_hashes() {
        let pool = mem_pool().await;
        add_file(&pool, 7, "same", 0).await;
        let remote = vec![
            json!({"id": 1}),
            json!({"id": 2, "hash": ""}),
            json!({"id": 3, "hash": null}),
        ];
        assert_eq!(plan(&pool, &remote).await.unwrap(), (remote, vec![]));
    }

    #[tokio::test]
    async fn plan_ignores_deleted_hashes() {
        let pool = mem_pool().await;
        add_file(&pool, 7, "same", 1).await;
        let remote = json!({"id": 9, "hash": "same"});
        assert_eq!(
            plan(&pool, std::slice::from_ref(&remote)).await.unwrap(),
            (vec![remote], vec![])
        );
    }

    #[test]
    fn generic_dedup_keeps_first_seen_order() {
        assert_eq!(
            unique_file_ids(&["second".to_owned(), "first".to_owned(), "second".to_owned()]),
            vec!["second", "first"]
        );
    }

    #[tokio::test]
    async fn plan_propagates_database_errors() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        assert!(plan(&pool, &[json!({"id": 1, "hash": "same"})])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn get_returns_all_columns_with_parsed_options() {
        let pool = mem_pool().await;
        add_session(
            &pool,
            "session",
            10,
            r#"{"include_favorites":true,"extra":"x"}"#,
        )
        .await;
        assert_eq!(
            get(&pool, "session").await.unwrap(),
            Some(json!({
                "id": "session", "peer_id": "peer", "peer_name": "Peer", "mode": "full",
                "status": "running", "last_seen_rowid": 3, "snapshot_max_rowid": 4,
                "total_files": 5, "done_files": 2, "import_folder": "/imports",
                "options": {"include_favorites": true, "extra": "x"}, "created_at": 10,
                "updated_at": 11,
            }))
        );
    }

    #[tokio::test]
    async fn get_propagates_invalid_options_json() {
        let pool = mem_pool().await;
        add_session(&pool, "session", 10, "{").await;
        assert!(get(&pool, "session").await.is_err());
    }

    #[tokio::test]
    async fn get_returns_none_for_unknown_session() {
        assert_eq!(get(&mem_pool().await, "missing").await.unwrap(), None);
    }

    #[tokio::test]
    async fn list_all_orders_by_created_at_descending() {
        let pool = mem_pool().await;
        add_session(&pool, "older", 1, "{}").await;
        add_session(&pool, "newer", 2, "{}").await;
        assert_eq!(
            list_all(&pool)
                .await
                .unwrap()
                .into_iter()
                .map(|session| session["id"].clone())
                .collect::<Vec<_>>(),
            vec![json!("newer"), json!("older")]
        );
    }

    #[tokio::test]
    async fn file_id_map_reads_use_the_three_column_key() {
        let pool = mem_pool().await;
        add_session(&pool, "session", 1, "{}").await;
        sqlx::query(
            "INSERT INTO import_file_id_map (session_id,remote_peer_id,remote_file_id,local_file_id,status) VALUES ('session','peer',9,42,'done')",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(is_file_processed(&pool, "session", "peer", 9)
            .await
            .unwrap());
        assert!(!is_file_processed(&pool, "session", "peer", 10)
            .await
            .unwrap());
        assert_eq!(
            get_local_file_id(&pool, "session", "peer", 9)
                .await
                .unwrap(),
            Some(42)
        );
        assert_eq!(
            get_local_file_id(&pool, "session", "peer", 10)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn register_file_is_idempotent_and_rolls_back_as_one_transaction() {
        let pool = mem_pool().await;
        let session_id = create_standalone(&pool, "peer", "Peer", "full", "/imports", &Map::new())
            .await
            .unwrap();
        let mut conn = pool.acquire().await.unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert!(
            register_file(&mut conn, &session_id, "remote", 9, 42, "done")
                .await
                .unwrap()
        );
        assert!(
            !register_file(&mut conn, &session_id, "remote", 9, 42, "done")
                .await
                .unwrap()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT done_files FROM import_session WHERE id=?")
                .bind(&session_id)
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            1
        );
        sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM import_file_id_map")
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT done_files FROM import_session WHERE id=?")
                .bind(&session_id)
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn update_allowlists_dirty_checks_and_ignores_missing_sessions() {
        let pool = mem_pool().await;
        let session_id = create_standalone(&pool, "peer", "Peer", "full", "/imports", &Map::new())
            .await
            .unwrap();
        let fields = Map::from_iter([
            ("status".to_owned(), json!("running")),
            ("done_files".to_owned(), json!(3)),
            ("options".to_owned(), json!({"ignored": true})),
        ]);
        update_standalone(&pool, &session_id, &fields)
            .await
            .unwrap();

        let mut conn = pool.acquire().await.unwrap();
        let row = sqlx::query("SELECT status,done_files,options FROM import_session WHERE id=?")
            .bind(&session_id)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(row.try_get::<String, _>("status").unwrap(), "running");
        assert_eq!(row.try_get::<i64, _>("done_files").unwrap(), 3);
        assert_eq!(
            row.try_get::<String, _>("options").unwrap(),
            "{\"include_favorites\":false,\"merge_metadata\":false}"
        );
        sqlx::query("UPDATE import_session SET updated_at=1 WHERE id=?")
            .bind(&session_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);

        let unchanged = Map::from_iter([("status".to_owned(), json!("running"))]);
        update_standalone(&pool, &session_id, &unchanged)
            .await
            .unwrap();
        let mut conn = pool.acquire().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT updated_at FROM import_session WHERE id=?")
                .bind(&session_id)
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            1
        );
        drop(conn);
        update_standalone(&pool, "missing", &fields).await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM import_session")
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn execution_claim_is_one_shot_and_budget_is_persistent() {
        let pool = mem_pool().await;
        let session_id = create_standalone(&pool, "peer", "Peer", "full", "/imports", &Map::new())
            .await
            .unwrap();
        let (first, second) = tokio::join!(
            claim_execution(&pool, &session_id, 5),
            claim_execution(&pool, &session_id, 5)
        );
        assert_eq!(
            [first.unwrap(), second.unwrap()]
                .into_iter()
                .filter(|claimed| *claimed)
                .count(),
            1
        );
        assert!(consume_download_budget(&pool, &session_id, 3)
            .await
            .unwrap());
        assert!(!consume_download_budget(&pool, &session_id, 3)
            .await
            .unwrap());
        assert!(!claim_execution(&pool, &session_id, 5).await.unwrap());
        let options =
            sqlx::query_scalar::<_, String>("SELECT options FROM import_session WHERE id=?")
                .bind(&session_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&options).unwrap()["_lan_import_download_remaining"],
            json!(2)
        );
    }

    #[tokio::test]
    async fn create_merges_options_and_initializes_session_fields() {
        let pool = mem_pool().await;
        let default_session =
            create_standalone(&pool, "peer", "Peer", "full", "/imports", &Map::new())
                .await
                .unwrap();
        let mut conn = pool.acquire().await.unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(
                &sqlx::query_scalar::<_, String>("SELECT options FROM import_session WHERE id=?")
                    .bind(default_session)
                    .fetch_one(&mut *conn)
                    .await
                    .unwrap(),
            )
            .unwrap(),
            json!({"include_favorites": false, "merge_metadata": false})
        );
        drop(conn);
        let options = Map::from_iter([
            ("include_favorites".to_owned(), json!(true)),
            ("extra".to_owned(), json!("value")),
        ]);
        let session_id = create_standalone(&pool, "peer", "Peer", "full", "/imports", &options)
            .await
            .unwrap();
        let mut conn = pool.acquire().await.unwrap();
        let row = sqlx::query(
            "SELECT status,done_files,options,created_at,updated_at FROM import_session WHERE id=?",
        )
        .bind(session_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        assert_eq!(row.try_get::<String, _>("status").unwrap(), "pending");
        assert_eq!(row.try_get::<i64, _>("done_files").unwrap(), 0);
        assert_eq!(
            serde_json::from_str::<Value>(&row.try_get::<String, _>("options").unwrap()).unwrap(),
            json!({"include_favorites": true, "merge_metadata": false, "extra": "value"})
        );
        assert_eq!(
            row.try_get::<i64, _>("created_at").unwrap(),
            row.try_get::<i64, _>("updated_at").unwrap()
        );
    }

    #[tokio::test]
    async fn collection_mapping_reuses_sqlite_case_rules_and_preserves_existing_map() {
        let pool = mem_pool().await;
        let session_id = create_standalone(&pool, "peer", "Peer", "full", "/imports", &Map::new())
            .await
            .unwrap();
        let mut conn = pool.acquire().await.unwrap();
        sqlx::query("INSERT INTO import_collection_id_map (session_id,remote_peer_id,remote_collection_id,local_collection_id) VALUES (?,?,?,77)")
            .bind(&session_id)
            .bind("remote")
            .bind(1)
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        assert_eq!(
            get_or_create_collection_standalone(&pool, &session_id, "remote", 1, "ignored")
                .await
                .unwrap(),
            77
        );
        let mut conn = pool.acquire().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM collections")
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            0
        );
        sqlx::query(
            "INSERT INTO collections (name,sort_order,created_at) VALUES (' Existing ',9,1)",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        let existing_id =
            sqlx::query_scalar::<_, i64>("SELECT id FROM collections WHERE name=' Existing '")
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        drop(conn);
        assert_eq!(
            get_or_create_collection_standalone(&pool, &session_id, "remote", 2, "existing")
                .await
                .unwrap(),
            existing_id
        );
        assert_eq!(
            get_or_create_collection_standalone(&pool, &session_id, "remote", 3, "  ExIsTiNg ")
                .await
                .unwrap(),
            existing_id
        );
        let mut conn = pool.acquire().await.unwrap();
        sqlx::query("INSERT INTO collections (name,sort_order,created_at) VALUES ('EXISTING',9,1)")
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        assert_eq!(
            get_or_create_collection_standalone(&pool, &session_id, "remote", 7, "existing")
                .await
                .unwrap(),
            existing_id
        );
        let mut conn = pool.acquire().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM collections")
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            2
        );
        drop(conn);
        let accented_lower =
            get_or_create_collection_standalone(&pool, &session_id, "remote", 4, "école")
                .await
                .unwrap();
        let accented_upper =
            get_or_create_collection_standalone(&pool, &session_id, "remote", 5, "ÉCOLE")
                .await
                .unwrap();
        assert_ne!(accented_lower, accented_upper);
        let created = get_or_create_collection_standalone(&pool, &session_id, "remote", 6, "new")
            .await
            .unwrap();
        assert_eq!(
            get_or_create_collection_standalone(&pool, &session_id, "remote", 6, "different")
                .await
                .unwrap(),
            created
        );
        let mut conn = pool.acquire().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT sort_order FROM collections WHERE id=?")
                .bind(created)
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn standalone_wrappers_rollback_after_commit_and_core_errors() {
        let pool = mem_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("PRAGMA defer_foreign_keys=ON")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert!(register_file(&mut conn, "missing", "remote", 1, 1, "done")
            .await
            .unwrap());
        assert!(sqlx::query("COMMIT").execute(&mut *conn).await.is_err());
        sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
        drop(conn);
        assert!(
            register_file_standalone(&pool, "missing", "remote", 1, 1, "done")
                .await
                .is_err()
        );
        let mut conn = pool.acquire().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM import_file_id_map")
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            0
        );
        sqlx::query(
            "CREATE TRIGGER reject_collection_map BEFORE INSERT ON import_collection_id_map BEGIN SELECT RAISE(ABORT, 'test'); END",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        drop(conn);
        assert!(
            get_or_create_collection_standalone(&pool, "missing", "remote", 1, "new")
                .await
                .is_err()
        );
        let mut conn = pool.acquire().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM collections")
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            0
        );
    }
}

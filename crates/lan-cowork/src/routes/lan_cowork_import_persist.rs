//! LAN Cowork downloaded-file persistence helpers.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{Map, Value};
use sqlx::{QueryBuilder, Row, Sqlite, SqliteConnection, SqlitePool};

use super::lan_cowork_import_state;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs() as i64
}

fn invalid_value(message: &'static str) -> sqlx::Error {
    sqlx::Error::Protocol(message.into())
}

fn push_json_bind(query: &mut QueryBuilder<Sqlite>, value: &Value) -> Result<(), sqlx::Error> {
    match value {
        Value::Null => {
            query.push_bind(Option::<String>::None);
        }
        Value::Bool(value) => {
            query.push_bind(*value);
        }
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                query.push_bind(value);
            } else if let Some(value) = value.as_u64() {
                query.push_bind(
                    i64::try_from(value)
                        .map_err(|_| invalid_value("integer outside SQLite range"))?,
                );
            } else if let Some(value) = value.as_f64() {
                query.push_bind(value);
            } else {
                return Err(invalid_value("invalid JSON number"));
            }
        }
        Value::String(value) => {
            query.push_bind(value.clone());
        }
        Value::Array(_) | Value::Object(_) => {
            return Err(invalid_value("unsupported SQLite value"))
        }
    }
    Ok(())
}

fn annotation_value(annotation: &Map<String, Value>) -> Result<&Value, sqlx::Error> {
    static EMPTY: Value = Value::String(String::new());
    Ok(annotation.get("value").unwrap_or(&EMPTY))
}

fn annotation_string<'a>(
    annotation: &'a Map<String, Value>,
    field: &str,
    default: &'static str,
) -> Result<&'a str, sqlx::Error> {
    match annotation.get(field) {
        None => Ok(default),
        Some(Value::String(value)) => Ok(value),
        Some(_) => Err(invalid_value("invalid annotation text field")),
    }
}

fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

/// Inserts a downloaded file or returns the existing row for its path.
///
/// This deliberately selects by path after `INSERT OR IGNORE`: SQLite's last
/// insert rowid can refer to an unrelated earlier insert when the insert is ignored.
pub async fn insert_file(
    conn: &mut SqliteConnection,
    path: &str,
    peer_id: &str,
    file_meta: &Map<String, Value>,
) -> Result<i64, sqlx::Error> {
    let now = Value::from(now_secs());
    let zero = Value::from(0);
    let null = Value::Null;
    let mut query = QueryBuilder::<Sqlite>::new(
        "INSERT OR IGNORE INTO files (path,hash,phash,mtime,size,width,height,meta_source,imported_from_peer,is_deleted,not_modified,parser_version) VALUES (",
    );
    query.push_bind(path).push(",");
    push_json_bind(&mut query, file_meta.get("hash").unwrap_or(&null))?;
    query.push(",");
    push_json_bind(&mut query, file_meta.get("phash").unwrap_or(&null))?;
    query.push(",");
    push_json_bind(&mut query, file_meta.get("mtime").unwrap_or(&now))?;
    query.push(",");
    push_json_bind(&mut query, file_meta.get("size").unwrap_or(&zero))?;
    query.push(",");
    push_json_bind(&mut query, file_meta.get("width").unwrap_or(&null))?;
    query.push(",");
    push_json_bind(&mut query, file_meta.get("height").unwrap_or(&null))?;
    query.push(",");
    push_json_bind(&mut query, file_meta.get("meta_source").unwrap_or(&null))?;
    query.push(",").push_bind(peer_id).push(",0,0,1)");
    query.build().execute(&mut *conn).await?;

    sqlx::query_scalar("SELECT id FROM files WHERE path=?")
        .bind(path)
        .fetch_one(&mut *conn)
        .await
}

/// Writes peer metadata on a caller-owned transaction.
///
/// Base64 annotation values are decoded once and inserted verbatim, preserving
/// compressed payloads emitted by the R1 metadata exporter.
// Keep the public persistence signature stable; grouping arguments would break callers.
#[allow(clippy::too_many_arguments)]
pub async fn write_metadata(
    conn: &mut SqliteConnection,
    session_id: &str,
    peer_id: &str,
    remote_id: i64,
    local_id: i64,
    tags: &Map<String, Value>,
    ratings: &Map<String, Value>,
    annotations: &Map<String, Value>,
    collections: &[Value],
) -> Result<(), sqlx::Error> {
    let remote_id = remote_id.to_string();
    let now = now_secs();

    let tag_rows = tags
        .get(&remote_id)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for tag in tag_rows {
        let Some(tag) = tag.as_str().filter(|tag| !tag.is_empty()) else {
            continue;
        };
        let tag_id = match sqlx::query("SELECT id FROM tags WHERE tag=? AND namespace IS NULL")
            .bind(tag)
            .fetch_optional(&mut *conn)
            .await?
        {
            Some(row) => row.try_get("id")?,
            None => sqlx::query("INSERT INTO tags (tag, first_seen_mtime) VALUES (?, ?)")
                .bind(tag)
                .bind(now)
                .execute(&mut *conn)
                .await?
                .last_insert_rowid(),
        };
        sqlx::query(
            "INSERT OR IGNORE INTO file_tags (file_id,tag_id,weight,source) VALUES (?,?,?,?)",
        )
        .bind(local_id)
        .bind(tag_id)
        .bind(1.0)
        .bind("meta")
        .execute(&mut *conn)
        .await?;
    }

    if let Some(rating) = ratings.get(&remote_id) {
        let mut query = QueryBuilder::<Sqlite>::new(
            "INSERT INTO file_ratings (file_id,rating,rated_at,updated_at) VALUES (",
        );
        query.push_bind(local_id).push(",");
        push_json_bind(&mut query, rating)?;
        query
            .push(",")
            .push_bind(now)
            .push(",")
            .push_bind(now)
            .push(") ON CONFLICT(file_id) DO UPDATE SET rating=excluded.rating,rated_at=excluded.rated_at,updated_at=excluded.updated_at");
        query.build().execute(&mut *conn).await?;
    }

    let annotation_rows = match annotations.get(&remote_id) {
        None => Vec::new(),
        Some(Value::String(value)) => vec![serde_json::json!({
            "source": "remote",
            "key": "note",
            "value": value,
        })],
        Some(Value::Array(rows)) => rows.clone(),
        Some(_) => return Err(invalid_value("invalid annotation rows")),
    };
    for row in annotation_rows {
        let annotation = row
            .as_object()
            .ok_or_else(|| invalid_value("invalid annotation row"))?;
        let value = annotation_value(annotation)?;
        let source = annotation_string(annotation, "source", "remote")?;
        let key = annotation_string(annotation, "key", "note")?;
        let null = Value::Null;
        let created_now = Value::from(now);
        let created_at = annotation
            .get("created_at")
            .filter(|value| json_truthy(value))
            .unwrap_or(&created_now);
        let mut query = QueryBuilder::<Sqlite>::new(
            "INSERT INTO file_annotations (file_id,source,key,value,confidence,created_at) VALUES (",
        );
        query
            .push_bind(local_id)
            .push(",")
            .push_bind(source)
            .push(",")
            .push_bind(key)
            .push(",");
        if annotation.get("value_enc").and_then(Value::as_str) == Some("base64")
            && value.is_string()
        {
            let decoded = STANDARD
                .decode(value.as_str().expect("checked string"))
                .map_err(|_| invalid_value("invalid base64 annotation value"))?;
            query.push_bind(decoded);
        } else {
            push_json_bind(&mut query, value)?;
        }
        query.push(",");
        push_json_bind(&mut query, annotation.get("confidence").unwrap_or(&null))?;
        query.push(",");
        push_json_bind(&mut query, created_at)?;
        query.push(") ON CONFLICT(file_id,source,key) DO UPDATE SET value=excluded.value,confidence=excluded.confidence,created_at=excluded.created_at");
        query.build().execute(&mut *conn).await?;
    }

    let now = now_secs();
    for collection in collections {
        let collection = collection
            .as_object()
            .ok_or_else(|| invalid_value("invalid collection"))?;
        let remote_collection_id = collection
            .get("id")
            .and_then(Value::as_i64)
            .ok_or_else(|| invalid_value("invalid collection id"))?;
        let collection_name = collection
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_value("invalid collection name"))?;
        let collection_id = lan_cowork_import_state::get_or_create_collection(
            &mut *conn,
            session_id,
            peer_id,
            remote_collection_id,
            collection_name,
        )
        .await?;
        if collection_id == 1 {
            continue;
        }
        sqlx::query(
            "INSERT OR IGNORE INTO favorites (file_id,collection_id,added_at) VALUES (?,?,?)",
        )
        .bind(local_id)
        .bind(collection_id)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Persists one file, its import-session mapping, and metadata on one transaction.
// Keep the public persistence signature stable; grouping arguments would break callers.
#[allow(clippy::too_many_arguments)]
pub async fn persist_downloaded_file(
    conn: &mut SqliteConnection,
    session_id: &str,
    peer_id: &str,
    remote_id: i64,
    path: &str,
    file_meta: &Map<String, Value>,
    tags: &Map<String, Value>,
    ratings: &Map<String, Value>,
    annotations: &Map<String, Value>,
    collections: &[Value],
) -> Result<i64, sqlx::Error> {
    let local_id = insert_file(conn, path, peer_id, file_meta).await?;
    lan_cowork_import_state::register_file(
        &mut *conn, session_id, peer_id, remote_id, local_id, "done",
    )
    .await?;
    write_metadata(
        conn,
        session_id,
        peer_id,
        remote_id,
        local_id,
        tags,
        ratings,
        annotations,
        collections,
    )
    .await?;
    Ok(local_id)
}

/// Runs `persist_downloaded_file` in its own immediate transaction.
// Keep the public persistence signature stable; grouping arguments would break callers.
#[allow(clippy::too_many_arguments)]
pub async fn persist_downloaded_file_standalone(
    pool: &SqlitePool,
    session_id: &str,
    peer_id: &str,
    remote_id: i64,
    path: &str,
    file_meta: &Map<String, Value>,
    tags: &Map<String, Value>,
    ratings: &Map<String, Value>,
    annotations: &Map<String, Value>,
    collections: &[Value],
) -> Result<i64, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let result = persist_downloaded_file(
        &mut conn,
        session_id,
        peer_id,
        remote_id,
        path,
        file_meta,
        tags,
        ratings,
        annotations,
        collections,
    )
    .await;
    lan_cowork_import_state::finish_write(&mut conn, result).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    const DDL: &str = r#"
        PRAGMA foreign_keys=ON;
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
          width INTEGER,
          height INTEGER,
          imported_from_peer TEXT
        );
        CREATE TABLE tags (
          id INTEGER PRIMARY KEY,
          tag TEXT NOT NULL,
          namespace TEXT,
          first_seen_mtime INTEGER,
          UNIQUE(tag, namespace)
        );
        CREATE TABLE file_tags (
          file_id INTEGER NOT NULL,
          tag_id INTEGER NOT NULL,
          weight REAL NOT NULL DEFAULT 1.0,
          source TEXT NOT NULL DEFAULT 'meta',
          UNIQUE(file_id, tag_id),
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
          FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE
        );
        CREATE TABLE file_annotations (
          id INTEGER PRIMARY KEY,
          file_id INTEGER NOT NULL,
          source TEXT NOT NULL,
          key TEXT NOT NULL,
          value BLOB NOT NULL,
          confidence REAL,
          created_at INTEGER NOT NULL,
          UNIQUE(file_id, source, key),
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
        );
        CREATE TABLE file_ratings (
          file_id INTEGER PRIMARY KEY,
          rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
          rated_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
        );
        CREATE TABLE collections (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          sort_order INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL,
          query_json TEXT
        );
        INSERT INTO collections (id,name,sort_order,created_at) VALUES (1,'Favorites',0,0);
        CREATE TABLE favorites (
          file_id INTEGER NOT NULL,
          collection_id INTEGER NOT NULL DEFAULT 1,
          added_at INTEGER NOT NULL,
          PRIMARY KEY (file_id, collection_id),
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
          FOREIGN KEY(collection_id) REFERENCES collections(id) ON DELETE CASCADE
        );
        CREATE TABLE import_session (
          id TEXT PRIMARY KEY,
          done_files INTEGER NOT NULL DEFAULT 0,
          updated_at INTEGER NOT NULL
        );
        CREATE TABLE import_file_id_map (
          session_id TEXT NOT NULL,
          remote_peer_id TEXT NOT NULL,
          remote_file_id INTEGER NOT NULL,
          local_file_id INTEGER NOT NULL,
          status TEXT NOT NULL,
          PRIMARY KEY(session_id,remote_peer_id,remote_file_id)
        );
        CREATE TABLE import_collection_id_map (
          session_id TEXT NOT NULL,
          remote_peer_id TEXT NOT NULL,
          remote_collection_id INTEGER NOT NULL,
          local_collection_id INTEGER NOT NULL,
          PRIMARY KEY(session_id,remote_peer_id,remote_collection_id)
        );
        CREATE TABLE file_tag_counts (
          file_id INTEGER PRIMARY KEY,
          tag_count INTEGER NOT NULL DEFAULT 0,
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
        );
        CREATE TABLE search_stats (
          key TEXT PRIMARY KEY,
          value INTEGER NOT NULL DEFAULT 0,
          updated_at INTEGER NOT NULL
        );
        INSERT INTO search_stats(key,value,updated_at) VALUES ('active_files',0,0),('active_tagged_files',0,0);
        CREATE VIRTUAL TABLE files_path_fts USING fts5(path,content='files',content_rowid='id',tokenize='trigram');
        CREATE TRIGGER files_path_fts_ai AFTER INSERT ON files BEGIN
          INSERT INTO files_path_fts(rowid,path) VALUES (new.id,new.path);
        END;
        CREATE TRIGGER trg_files_ai_search_stats AFTER INSERT ON files BEGIN
          UPDATE search_stats SET value=value+CASE WHEN NEW.is_deleted=0 THEN 1 ELSE 0 END,updated_at=strftime('%s','now') WHERE key='active_files';
        END;
        CREATE TRIGGER trg_file_tags_ai_search_stats AFTER INSERT ON file_tags BEGIN
          UPDATE search_stats SET value=value+1,updated_at=strftime('%s','now') WHERE key='active_tagged_files' AND COALESCE((SELECT is_deleted FROM files WHERE id=NEW.file_id),1)=0 AND COALESCE((SELECT tag_count FROM file_tag_counts WHERE file_id=NEW.file_id),0)=0;
          INSERT INTO file_tag_counts(file_id,tag_count) VALUES (NEW.file_id,1) ON CONFLICT(file_id) DO UPDATE SET tag_count=tag_count+1;
        END;
    "#;

    async fn test_db() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::raw_sql(DDL).execute(&pool).await.unwrap();
        pool
    }

    async fn seed_session(pool: &SqlitePool) {
        sqlx::query("INSERT INTO import_session (id,done_files,updated_at) VALUES ('session',0,0)")
            .execute(pool)
            .await
            .unwrap();
    }

    async fn new_file(pool: &SqlitePool, path: &str) -> i64 {
        let mut conn = pool.acquire().await.unwrap();
        insert_file(&mut conn, path, "peer", &Map::new())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn insert_file_uses_path_after_ignore_and_keeps_tombstones() {
        let pool = test_db().await;
        let mut conn = pool.acquire().await.unwrap();
        let first = insert_file(&mut conn, "/first", "peer", &Map::new())
            .await
            .unwrap();
        sqlx::query("INSERT INTO files (path,mtime,size) VALUES ('/other',0,0)")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert_eq!(
            insert_file(&mut conn, "/first", "peer", &Map::new())
                .await
                .unwrap(),
            first
        );
        sqlx::query("INSERT INTO files (path,mtime,size,is_deleted) VALUES ('/tombstone',0,0,1)")
            .execute(&mut *conn)
            .await
            .unwrap();
        let tombstone: i64 = sqlx::query_scalar("SELECT id FROM files WHERE path='/tombstone'")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(
            insert_file(&mut conn, "/tombstone", "peer", &Map::new())
                .await
                .unwrap(),
            tombstone
        );
    }

    #[tokio::test]
    async fn metadata_defaults_only_for_missing_keys() {
        let pool = test_db().await;
        let mut conn = pool.acquire().await.unwrap();
        insert_file(&mut conn, "/missing", "peer", &Map::new())
            .await
            .unwrap();
        assert!(insert_file(
            &mut conn,
            "/null-mtime",
            "peer",
            &serde_json::json!({"mtime": null})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await
        .is_err());
        assert!(insert_file(
            &mut conn,
            "/null-size",
            "peer",
            &serde_json::json!({"size": null})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn write_metadata_reuses_tags_skips_empty_and_overwrites_rating() {
        let pool = test_db().await;
        let file_id = new_file(&pool, "/file").await;
        sqlx::query("INSERT INTO tags (tag,first_seen_mtime) VALUES ('old',0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO file_ratings (file_id,rating,rated_at,updated_at) VALUES (?,2,0,0)",
        )
        .bind(file_id)
        .execute(&pool)
        .await
        .unwrap();
        let tags = serde_json::json!({"7":["old","new",""]})
            .as_object()
            .unwrap()
            .clone();
        let ratings = serde_json::json!({"7":4}).as_object().unwrap().clone();
        let mut conn = pool.acquire().await.unwrap();
        write_metadata(
            &mut conn,
            "session",
            "peer",
            7,
            file_id,
            &tags,
            &ratings,
            &Map::new(),
            &[],
        )
        .await
        .unwrap();
        let rows = sqlx::query("SELECT t.tag,ft.weight,ft.source FROM file_tags ft JOIN tags t ON t.id=ft.tag_id ORDER BY t.tag")
            .fetch_all(&mut *conn)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert_eq!(row.try_get::<f64, _>("weight").unwrap(), 1.0);
            assert_eq!(row.try_get::<String, _>("source").unwrap(), "meta");
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT rating FROM file_ratings WHERE file_id=?")
                .bind(file_id)
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            4
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT value FROM search_stats WHERE key='active_tagged_files'",
            )
            .fetch_one(&mut *conn)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT tag_count FROM file_tag_counts WHERE file_id=?")
                .bind(file_id)
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn annotations_preserve_bytes_strings_and_fallback_rows() {
        let pool = test_db().await;
        let file_id = new_file(&pool, "/file").await;
        let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];
        let annotations = serde_json::json!({"7":[
            {"source":"remote","key":"blob","value":STANDARD.encode(&zstd_magic),"value_enc":"base64"},
            {"source":"remote","key":"text","value":"before"},
            {"source":"remote","key":"missing-created","value":"x"},
            {"source":"remote","key":"null-created","value":"y","created_at":null}
        ]}).as_object().unwrap().clone();
        let mut conn = pool.acquire().await.unwrap();
        write_metadata(
            &mut conn,
            "session",
            "peer",
            7,
            file_id,
            &Map::new(),
            &Map::new(),
            &annotations,
            &[],
        )
        .await
        .unwrap();
        let update = serde_json::json!({"7":[{"source":"remote","key":"text","value":"after"}]})
            .as_object()
            .unwrap()
            .clone();
        write_metadata(
            &mut conn,
            "session",
            "peer",
            7,
            file_id,
            &Map::new(),
            &Map::new(),
            &update,
            &[],
        )
        .await
        .unwrap();
        let fallback = serde_json::json!({"7":"fallback"})
            .as_object()
            .unwrap()
            .clone();
        write_metadata(
            &mut conn,
            "session",
            "peer",
            7,
            file_id,
            &Map::new(),
            &Map::new(),
            &fallback,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT value FROM file_annotations WHERE file_id=? AND key='blob'"
            )
            .bind(file_id)
            .fetch_one(&mut *conn)
            .await
            .unwrap(),
            zstd_magic
        );
        assert_eq!(
            sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT value FROM file_annotations WHERE file_id=? AND key='text'"
            )
            .bind(file_id)
            .fetch_one(&mut *conn)
            .await
            .unwrap(),
            b"after"
        );
        assert_eq!(
            sqlx::query_scalar::<_, Vec<u8>>("SELECT value FROM file_annotations WHERE file_id=? AND source='remote' AND key='note'")
                .bind(file_id).fetch_one(&mut *conn).await.unwrap(),
            b"fallback"
        );
        let created: i64 = sqlx::query_scalar("SELECT MIN(created_at) FROM file_annotations WHERE file_id=? AND key IN ('missing-created','null-created')")
            .bind(file_id).fetch_one(&mut *conn).await.unwrap();
        assert!(created > 0);
    }

    #[tokio::test]
    async fn annotations_bind_scalars_and_rollback_nested_values() {
        let pool = test_db().await;
        seed_session(&pool).await;
        let file_id = new_file(&pool, "/scalars").await;
        let annotations = serde_json::json!({"7":[
            {"key":"number","value":42},
            {"key":"bool","value":true}
        ]})
        .as_object()
        .unwrap()
        .clone();
        let mut conn = pool.acquire().await.unwrap();
        write_metadata(
            &mut conn,
            "session",
            "peer",
            7,
            file_id,
            &Map::new(),
            &Map::new(),
            &annotations,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT value FROM file_annotations WHERE file_id=? AND key='number'",
            )
            .bind(file_id)
            .fetch_one(&mut *conn)
            .await
            .unwrap(),
            42
        );
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT value FROM file_annotations WHERE file_id=? AND key='bool'",
        )
        .bind(file_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap());
        drop(conn);

        let nested_annotations = serde_json::json!({"8":[{"key":"nested","value":[]} ]})
            .as_object()
            .unwrap()
            .clone();
        assert!(persist_downloaded_file_standalone(
            &pool,
            "session",
            "peer",
            8,
            "/nested",
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &nested_annotations,
            &[],
        )
        .await
        .is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM files WHERE path='/nested'")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM import_file_id_map WHERE remote_file_id=8",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT done_files FROM import_session WHERE id='session'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn collections_skip_seeded_favorites_and_add_other_collections() {
        let pool = test_db().await;
        seed_session(&pool).await;
        let file_id = new_file(&pool, "/file").await;
        let collections = vec![
            serde_json::json!({"id":1,"name":"Favorites"}),
            serde_json::json!({"id":2,"name":"Other"}),
        ];
        let mut conn = pool.acquire().await.unwrap();
        write_metadata(
            &mut conn,
            "session",
            "peer",
            7,
            file_id,
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &collections,
        )
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM favorites WHERE file_id=?")
                .bind(file_id)
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT c.name FROM favorites f JOIN collections c ON c.id=f.collection_id WHERE f.file_id=?")
                .bind(file_id).fetch_one(&mut *conn).await.unwrap(),
            "Other"
        );
    }

    #[tokio::test]
    async fn persist_downloaded_file_rolls_back_all_writes_on_metadata_failure() {
        let pool = test_db().await;
        seed_session(&pool).await;
        let ratings = serde_json::json!({"7":6}).as_object().unwrap().clone();
        assert!(persist_downloaded_file_standalone(
            &pool,
            "session",
            "peer",
            7,
            "/file",
            &Map::new(),
            &Map::new(),
            &ratings,
            &Map::new(),
            &[],
        )
        .await
        .is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM files")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM import_file_id_map")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT done_files FROM import_session WHERE id='session'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn file_insert_triggers_update_fts_and_search_stats() {
        let pool = test_db().await;
        new_file(&pool, "/trigger.png").await;
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT path FROM files_path_fts WHERE rowid=1")
                .fetch_one(&pool)
                .await
                .unwrap(),
            "/trigger.png"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT value FROM search_stats WHERE key='active_files'")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
    }
}

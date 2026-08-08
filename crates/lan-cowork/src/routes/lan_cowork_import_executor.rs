//! LAN Cowork import orchestration (Increment L3c).
//!
//! This module is intentionally unwired until the import routes land.

use std::{collections::HashMap, path::Path};

use serde_json::{json, Map, Value};
use sqlx::SqlitePool;

use super::{
    lan_cowork_host::LanCoworkHost,
    lan_cowork_import_persist::persist_downloaded_file_standalone,
    lan_cowork_import_state::{
        claim_execution, is_file_processed, plan, register_file_standalone, update_standalone,
    },
    lan_cowork_import_transfer::{
        download_file, download_zip, SessionDownloadBudget, SESSION_DOWNLOAD_LIMIT,
    },
    lan_cowork_registry::{PeerInfo, PeerRegistry},
};

const BATCH_THRESHOLD: usize = 100;
const REMOTE_FILE_COUNT_LIMIT: usize = 10_000;
// This outbound wire limit only happens to match the receiver SQL IN chunk size; change independently.
const ZIP_IDS_PER_REQUEST: usize = 500;

fn validate_remote_file_count(files: &[Value]) -> Result<(), sqlx::Error> {
    if files.len() > REMOTE_FILE_COUNT_LIMIT {
        return Err(sqlx::Error::Protocol(
            "remote import file count exceeds session limit".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, dead_code)]
pub(crate) async fn run(
    pool: &SqlitePool,
    session_id: &str,
    peer: &PeerInfo,
    meta: &Map<String, Value>,
    import_folder: &Path,
    _options: &Map<String, Value>,
    local_peer_id: Option<&str>,
    seed: &[u8],
    registry: &PeerRegistry,
    host: &dyn LanCoworkHost,
    execution_claimed: bool,
) -> Result<(), sqlx::Error> {
    let files = match meta.get("files") {
        None => &[][..],
        Some(Value::Array(value)) => value.as_slice(),
        Some(_) => return Err(sqlx::Error::Protocol("invalid import files".into())),
    };
    let tags = match meta.get("tags") {
        None => &Map::new(),
        Some(Value::Object(value)) => value,
        Some(_) => return Err(sqlx::Error::Protocol("invalid import tags".into())),
    };
    let collections = match meta.get("collections") {
        None => &[][..],
        Some(Value::Array(value)) => value.as_slice(),
        Some(_) => return Err(sqlx::Error::Protocol("invalid import collections".into())),
    };
    let ratings = match meta.get("file_ratings") {
        None => &Map::new(),
        Some(Value::Object(value)) => value,
        Some(_) => return Err(sqlx::Error::Protocol("invalid import file ratings".into())),
    };
    let annotations = match meta.get("file_annotations") {
        None => &Map::new(),
        Some(Value::Object(value)) => value,
        Some(_) => {
            return Err(sqlx::Error::Protocol(
                "invalid import file annotations".into(),
            ))
        }
    };
    let max_rowid = match meta.get("max_rowid") {
        None => 0,
        Some(value) => value
            .as_i64()
            .ok_or_else(|| sqlx::Error::Protocol("invalid import max rowid".into()))?,
    };
    let peer_id = if peer.peer_id.is_empty() {
        peer.name.as_str()
    } else {
        peer.peer_id.as_str()
    };
    validate_remote_file_count(files)?;
    if !execution_claimed && !claim_execution(pool, session_id, SESSION_DOWNLOAD_LIMIT).await? {
        return Err(sqlx::Error::Protocol(
            "import session was already executed".into(),
        ));
    }
    let download_budget = SessionDownloadBudget::new(pool, session_id);

    update_standalone(
        pool,
        session_id,
        json!({
            "total_files": files.len(),
            "snapshot_max_rowid": max_rowid,
        })
        .as_object()
        .expect("JSON object"),
    )
    .await?;

    let (to_import, to_skip) = plan(pool, files).await?;
    for skip in to_skip {
        let remote_id = skip["remote_id"]
            .as_i64()
            .ok_or_else(|| sqlx::Error::Protocol("invalid planned remote file id".into()))?;
        let local_id = skip["local_id"]
            .as_i64()
            .ok_or_else(|| sqlx::Error::Protocol("invalid planned local file id".into()))?;
        if !is_file_processed(pool, session_id, peer_id, remote_id).await? {
            register_file_standalone(pool, session_id, peer_id, remote_id, local_id, "skipped")
                .await?;
        }
    }

    if uses_batch_zip(to_import.len()) {
        batch_zip(
            pool,
            session_id,
            peer_id,
            peer,
            &to_import,
            import_folder,
            tags,
            ratings,
            annotations,
            collections,
            local_peer_id,
            seed,
            registry,
            host,
            Some(&download_budget),
        )
        .await?;
    } else {
        individual_http(
            pool,
            session_id,
            peer_id,
            peer,
            &to_import,
            import_folder,
            tags,
            ratings,
            annotations,
            collections,
            local_peer_id,
            seed,
            registry,
            host,
            Some(&download_budget),
        )
        .await?;
    }

    let mut unprocessed = to_import.len();
    for file_meta in &to_import {
        let Some(file_meta) = file_meta.as_object() else {
            continue;
        };
        let Some(remote_id) = file_meta.get("id").and_then(Value::as_i64) else {
            continue;
        };
        if is_file_processed(pool, session_id, peer_id, remote_id).await? {
            unprocessed -= 1;
        }
    }
    let completion = if unprocessed == 0 {
        json!({"status": "completed", "last_seen_rowid": max_rowid})
    } else {
        json!({"status": "completed"})
    };
    update_standalone(
        pool,
        session_id,
        completion.as_object().expect("JSON object"),
    )
    .await
}

fn uses_batch_zip(to_import_len: usize) -> bool {
    to_import_len >= BATCH_THRESHOLD
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn individual_http(
    pool: &SqlitePool,
    session_id: &str,
    peer_id: &str,
    peer: &PeerInfo,
    to_import: &[Value],
    import_folder: &Path,
    tags: &Map<String, Value>,
    ratings: &Map<String, Value>,
    annotations: &Map<String, Value>,
    collections: &[Value],
    local_peer_id: Option<&str>,
    seed: &[u8],
    registry: &PeerRegistry,
    host: &dyn LanCoworkHost,
    download_budget: Option<&SessionDownloadBudget>,
) -> Result<(), sqlx::Error> {
    for file_meta in to_import {
        // Intentional asymmetry: `plan` hard-fails malformed skip IDs; malformed import metadata
        // (non-objects or missing/invalid `id` or `path`) fails closed per item.
        let Some(file_meta) = file_meta.as_object() else {
            continue;
        };
        let Some(remote_id) = file_meta.get("id").and_then(Value::as_i64) else {
            continue;
        };
        if is_file_processed(pool, session_id, peer_id, remote_id).await? {
            continue;
        }
        let Some(original_name) = file_meta
            .get("path")
            .and_then(Value::as_str)
            .and_then(|path| Path::new(path).file_name())
            .and_then(|name| name.to_str())
        else {
            continue;
        };
        let Some(dest) = download_file(
            peer,
            remote_id,
            import_folder,
            original_name,
            local_peer_id,
            seed,
            registry,
            host,
            download_budget,
        )
        .await
        else {
            tracing::warn!(
                session_id,
                remote_file_id = remote_id,
                "import download failed"
            );
            continue;
        };
        let path = dest.to_string_lossy();
        persist_downloaded_file_standalone(
            pool,
            session_id,
            peer_id,
            remote_id,
            path.as_ref(),
            file_meta,
            tags,
            ratings,
            annotations,
            collections,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn batch_zip(
    pool: &SqlitePool,
    session_id: &str,
    peer_id: &str,
    peer: &PeerInfo,
    to_import: &[Value],
    import_folder: &Path,
    tags: &Map<String, Value>,
    ratings: &Map<String, Value>,
    annotations: &Map<String, Value>,
    collections: &[Value],
    local_peer_id: Option<&str>,
    seed: &[u8],
    registry: &PeerRegistry,
    host: &dyn LanCoworkHost,
    download_budget: Option<&SessionDownloadBudget>,
) -> Result<(), sqlx::Error> {
    let mut ids_to_dl = Vec::new();
    let mut file_map_by_id = HashMap::new();
    for file_meta in to_import {
        // Intentional asymmetry: `plan` hard-fails malformed skip IDs; malformed import metadata
        // (non-objects or missing/invalid `id` or `path`) fails closed per item.
        let Some(file_meta) = file_meta.as_object() else {
            continue;
        };
        let Some(remote_id) = file_meta.get("id").and_then(Value::as_i64) else {
            continue;
        };
        file_map_by_id.insert(remote_id, file_meta);
        if !is_file_processed(pool, session_id, peer_id, remote_id).await? {
            ids_to_dl.push(remote_id);
        }
    }
    for ids in ids_to_dl.chunks(ZIP_IDS_PER_REQUEST) {
        let Some(downloaded) = download_zip(
            peer,
            ids,
            import_folder,
            local_peer_id,
            seed,
            registry,
            host,
            download_budget,
        )
        .await
        else {
            let chunk_meta: Vec<_> = ids
                .iter()
                .filter_map(|remote_id| {
                    file_map_by_id
                        .get(remote_id)
                        .map(|meta| Value::Object((*meta).clone()))
                })
                .collect();
            individual_http(
                pool,
                session_id,
                peer_id,
                peer,
                &chunk_meta,
                import_folder,
                tags,
                ratings,
                annotations,
                collections,
                local_peer_id,
                seed,
                registry,
                host,
                download_budget,
            )
            .await?;
            continue;
        };
        let mut downloaded: Vec<_> = downloaded.into_iter().collect();
        downloaded.sort_unstable_by_key(|(remote_id, _)| *remote_id);
        for (remote_id, dest) in downloaded {
            let Some(file_meta) = file_map_by_id.get(&remote_id) else {
                continue;
            };
            let path = dest.to_string_lossy();
            persist_downloaded_file_standalone(
                pool,
                session_id,
                peer_id,
                remote_id,
                path.as_ref(),
                file_meta,
                tags,
                ratings,
                annotations,
                collections,
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write, sync::atomic::Ordering, time::Duration};

    use sqlx::sqlite::SqlitePoolOptions;
    use tempfile::tempdir;
    use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

    use super::*;
    use crate::routes::{
        lan_cowork_descriptor::{test_guard, TEST_ALLOW_LOOPBACK},
        lan_cowork_import_transfer::{
            FILE_DOWNLOAD_LIMIT, TEST_FILE_DOWNLOAD_LIMIT, TEST_ZIP_DOWNLOAD_LIMIT,
            ZIP_DOWNLOAD_LIMIT,
        },
    };
    use crate::state::semantic_test_state;

    async fn test_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TABLE files (id INTEGER PRIMARY KEY, path TEXT UNIQUE, mtime INTEGER DEFAULT 0, size INTEGER DEFAULT 0, hash TEXT, phash TEXT, is_deleted INTEGER NOT NULL, meta_source TEXT, not_modified INTEGER DEFAULT 0, parser_version INTEGER DEFAULT 1, width INTEGER, height INTEGER, imported_from_peer TEXT);\
             CREATE TABLE import_session (id TEXT PRIMARY KEY, peer_id TEXT NOT NULL, peer_name TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, last_seen_rowid INTEGER, snapshot_max_rowid INTEGER, total_files INTEGER, done_files INTEGER NOT NULL DEFAULT 0, import_folder TEXT NOT NULL, options TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);\
             CREATE TABLE import_file_id_map (session_id TEXT NOT NULL, remote_peer_id TEXT NOT NULL, remote_file_id INTEGER NOT NULL, local_file_id INTEGER NOT NULL, status TEXT NOT NULL, PRIMARY KEY(session_id, remote_peer_id, remote_file_id));\
             CREATE TABLE status_history (status TEXT NOT NULL, snapshot_max_rowid INTEGER, last_seen_rowid INTEGER);\
             CREATE TRIGGER record_import_status AFTER UPDATE ON import_session BEGIN INSERT INTO status_history VALUES (NEW.status, NEW.snapshot_max_rowid, NEW.last_seen_rowid); END;",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    async fn add_session(pool: &SqlitePool, id: &str) {
        sqlx::query("INSERT INTO import_session(id,peer_id,peer_name,mode,status,import_folder,created_at,updated_at) VALUES (?,'peer','peer','all','pending','.',0,0)")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }

    fn peer(peer_id: &str, name: &str) -> PeerInfo {
        PeerInfo {
            peer_id: peer_id.to_owned(),
            name: name.to_owned(),
            api_host: "127.0.0.1".to_owned(),
            api_port: 1,
            token: None,
            token_expires_at: None,
            token_issued_at: None,
            pubkey: None,
            x25519_pk: None,
            version: String::new(),
            bridges: vec![],
            inference_types: vec![],
            gpu: String::new(),
            generating: false,
            queue_depth: 0,
            status: String::new(),
            last_seen: 0.0,
            session_id: String::new(),
            roles: vec![],
            last_reached_at: None,
            last_attempted_at: None,
        }
    }

    fn remote_peer(port: u16) -> PeerInfo {
        let mut peer = peer("peer", "peer");
        peer.api_port = port;
        peer.token = Some("outbound-token".to_owned());
        peer.token_expires_at = Some(2_000_000_000);
        peer.token_issued_at = Some(1_700_000_000);
        peer
    }

    async fn response_server(response: Vec<u8>) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind is required to verify import transfer execution");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;

            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            stream.write_all(&response).await.unwrap();
            request
        });
        (port, server)
    }

    async fn response_server_many(
        responses: Vec<Vec<u8>>,
    ) -> (u16, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;

            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                stream.write_all(&response).await.unwrap();
                requests.push(request);
            }
            requests
        });
        (port, server)
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt;

        let mut request = Vec::with_capacity(8192);
        let mut buffer = [0; 8192];
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let len = stream.read(&mut buffer).await.unwrap();
            if len == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..len]);
        }
        request
    }

    async fn received_request(server: tokio::task::JoinHandle<Vec<u8>>) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("test server did not receive an HTTP request within 5 seconds")
            .unwrap()
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, content) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn zip_response(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let body = zip_bytes(entries);
        [
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
            body,
        ]
        .concat()
    }

    fn file_metas(count: i64) -> Vec<Value> {
        (1..=count)
            .map(|id| json!({"id": id, "path": format!("{id}.txt")}))
            .collect()
    }

    async fn run_meta(
        pool: &SqlitePool,
        session_id: &str,
        peer: &PeerInfo,
        meta: &Map<String, Value>,
    ) -> Result<(), sqlx::Error> {
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());
        run(
            pool,
            session_id,
            peer,
            meta,
            Path::new("."),
            &Map::new(),
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            false,
        )
        .await
    }

    #[tokio::test]
    async fn malformed_ids_are_asymmetric_and_early_error_leaves_session_running() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TABLE files (id INTEGER PRIMARY KEY, hash TEXT, is_deleted INTEGER NOT NULL);\
             CREATE TABLE import_session (id TEXT PRIMARY KEY, peer_id TEXT NOT NULL, peer_name TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, last_seen_rowid INTEGER, snapshot_max_rowid INTEGER, total_files INTEGER, done_files INTEGER NOT NULL DEFAULT 0, import_folder TEXT NOT NULL, options TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);\
             CREATE TABLE import_file_id_map (session_id TEXT NOT NULL, remote_peer_id TEXT NOT NULL, remote_file_id INTEGER NOT NULL, local_file_id INTEGER NOT NULL, status TEXT NOT NULL, PRIMARY KEY(session_id, remote_peer_id, remote_file_id));\
             INSERT INTO files(id,hash,is_deleted) VALUES (1,'same',0);\
             INSERT INTO import_session(id,peer_id,peer_name,mode,status,import_folder,created_at,updated_at) VALUES ('skip','peer','peer','all','pending','.',0,0),('import','peer','peer','all','pending','.',0,0);",
        )
        .execute(&pool)
        .await
        .unwrap();
        let peer = PeerInfo {
            peer_id: String::new(),
            name: "peer".to_owned(),
            api_host: "127.0.0.1".to_owned(),
            api_port: 1,
            token: None,
            token_expires_at: None,
            token_issued_at: None,
            pubkey: None,
            x25519_pk: None,
            version: String::new(),
            bridges: vec![],
            inference_types: vec![],
            gpu: String::new(),
            generating: false,
            queue_depth: 0,
            status: String::new(),
            last_seen: 0.0,
            session_id: String::new(),
            roles: vec![],
            last_reached_at: None,
            last_attempted_at: None,
        };
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());
        let state = semantic_test_state(true).await;
        let options = Map::new();

        assert!(run(
            &pool,
            "skip",
            &peer,
            json!({"files":[{"id":"bad","hash":"same"}]})
                .as_object()
                .unwrap(),
            Path::new("."),
            &options,
            None,
            &[7; 32],
            &registry,
            &*state,
            false,
        )
        .await
        .is_err());
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT status FROM import_session WHERE id='skip'")
                .fetch_one(&pool)
                .await
                .unwrap(),
            "running"
        );

        run(
            &pool,
            "import",
            &peer,
            json!({"files":[{"id":"bad"}]}).as_object().unwrap(),
            Path::new("."),
            &options,
            None,
            &[7; 32],
            &registry,
            &*state,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT status FROM import_session WHERE id='import'")
                .fetch_one(&pool)
                .await
                .unwrap(),
            "completed"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT total_files FROM import_session WHERE id='import'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM import_file_id_map")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn skipped_files_count_update_lifecycle_and_use_peer_name_fallback() {
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        sqlx::query("INSERT INTO files(id,hash,is_deleted) VALUES (7,'same',0)")
            .execute(&pool)
            .await
            .unwrap();
        let peer = peer("", "peer-name");

        run_meta(
            &pool,
            "session",
            &peer,
            json!({
                "files": [{"id": 42, "hash": "same"}, {"id": "bad"}],
                "max_rowid": 123,
            })
            .as_object()
            .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(
            sqlx::query_as::<_, (String, Option<i64>, Option<i64>, Option<i64>, i64)>(
                "SELECT status,snapshot_max_rowid,last_seen_rowid,total_files,done_files FROM import_session WHERE id='session'"
            ).fetch_one(&pool).await.unwrap(),
            ("completed".to_owned(), Some(123), None, Some(2), 1),
        );
        let history = sqlx::query_as::<_, (String, Option<i64>, Option<i64>)>(
            "SELECT status,snapshot_max_rowid,last_seen_rowid FROM status_history",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(history.first(), Some(&("running".to_owned(), None, None)));
        assert_eq!(
            history.last(),
            Some(&("completed".to_owned(), Some(123), None))
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT remote_peer_id FROM import_file_id_map")
                .fetch_one(&pool)
                .await
                .unwrap(),
            "peer-name",
        );
    }

    #[tokio::test]
    async fn completed_import_advances_rowid_when_all_files_are_processed() {
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        sqlx::query("INSERT INTO import_file_id_map VALUES ('session','peer',1,7,'done')")
            .execute(&pool)
            .await
            .unwrap();

        run_meta(
            &pool,
            "session",
            &peer("peer", "peer"),
            json!({"files": [{"id": 1, "path": "1.txt"}], "max_rowid": 42})
                .as_object()
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(
            sqlx::query_as::<_, (String, Option<i64>)>(
                "SELECT status,last_seen_rowid FROM import_session WHERE id='session'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            ("completed".to_owned(), Some(42))
        );
    }

    #[tokio::test]
    async fn completed_import_keeps_null_rowid_when_a_file_is_unprocessed() {
        let pool = test_pool().await;
        add_session(&pool, "session").await;

        run_meta(
            &pool,
            "session",
            &peer("peer", "peer"),
            json!({"files": [{"id": "bad", "path": "bad.txt"}], "max_rowid": 42})
                .as_object()
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(
            sqlx::query_as::<_, (String, Option<i64>)>(
                "SELECT status,last_seen_rowid FROM import_session WHERE id='session'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            ("completed".to_owned(), None)
        );
    }

    #[tokio::test]
    async fn repeated_execution_is_rejected_without_registering_twice() {
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        sqlx::query("INSERT INTO files(id,hash,is_deleted) VALUES (7,'same',0)")
            .execute(&pool)
            .await
            .unwrap();
        let peer = peer("peer", "name");
        let meta = json!({"files": [{"id": 42, "hash": "same"}]});

        run_meta(&pool, "session", &peer, meta.as_object().unwrap())
            .await
            .unwrap();
        assert!(run_meta(&pool, "session", &peer, meta.as_object().unwrap())
            .await
            .is_err());

        assert_eq!(
            sqlx::query_as::<_, (i64, i64)>("SELECT done_files,(SELECT COUNT(*) FROM import_file_id_map) FROM import_session WHERE id='session'")
                .fetch_one(&pool).await.unwrap(),
            (1, 1),
        );
    }

    #[tokio::test]
    async fn absent_meta_keys_default_but_wrong_types_error() {
        let pool = test_pool().await;
        add_session(&pool, "defaults").await;
        let peer = peer("peer", "name");
        run_meta(&pool, "defaults", &peer, &Map::new())
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_as::<_, (String, Option<i64>, Option<i64>, Option<i64>)>(
                "SELECT status,snapshot_max_rowid,last_seen_rowid,total_files FROM import_session WHERE id='defaults'"
            ).fetch_one(&pool).await.unwrap(),
            ("completed".to_owned(), Some(0), Some(0), Some(0)),
        );
        for (id, meta) in [
            ("files", json!({"files": {}})),
            ("tags", json!({"tags": null})),
        ] {
            add_session(&pool, id).await;
            assert!(run_meta(&pool, id, &peer, meta.as_object().unwrap())
                .await
                .is_err());
            assert_eq!(
                sqlx::query_scalar::<_, String>("SELECT status FROM import_session WHERE id=?")
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .unwrap(),
                "pending",
            );
        }
    }

    #[tokio::test]
    async fn individual_http_downloads_basename_and_persists_file() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        let (port, server) =
            response_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()).await;
        let directory = tempdir().unwrap();
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());

        individual_http(
            &pool,
            "session",
            "peer",
            &remote_peer(port),
            &[json!({"id": 7, "path": "nested/original.txt"})],
            directory.path(),
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &[],
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read(directory.path().join("original.txt")).unwrap(),
            b"ok"
        );
        assert_eq!(sqlx::query_as::<_, (String, i64, String)>("SELECT path,remote_file_id,status FROM files JOIN import_file_id_map ON files.id=local_file_id")
            .fetch_one(&pool).await.unwrap(), (directory.path().join("original.txt").to_string_lossy().into_owned(), 7, "done".to_owned()));
        assert!(String::from_utf8(received_request(server).await)
            .unwrap()
            .starts_with("GET /ext/lan_cowork/api/peer/import/file/7 HTTP/1.1"));
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn individual_http_does_not_register_404_download() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        let (port, server) =
            response_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        let directory = tempdir().unwrap();
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());

        individual_http(
            &pool,
            "session",
            "peer",
            &remote_peer(port),
            &[json!({"id": 8, "path": "missing.txt"})],
            directory.path(),
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &[],
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM import_file_id_map")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert!(String::from_utf8(received_request(server).await)
            .unwrap()
            .starts_with("GET /ext/lan_cowork/api/peer/import/file/8 HTTP/1.1"));
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn individual_http_size_cap_does_not_register_download() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        TEST_FILE_DOWNLOAD_LIMIT.store(2, Ordering::Relaxed);
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        let (port, server) =
            response_server(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nno!".to_vec()).await;
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());
        individual_http(
            &pool,
            "session",
            "peer",
            &remote_peer(port),
            &[json!({"id": 8, "path": "retry.txt"})],
            tempdir().unwrap().path(),
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &[],
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM import_file_id_map")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        received_request(server).await;
        TEST_FILE_DOWNLOAD_LIMIT.store(FILE_DOWNLOAD_LIMIT, Ordering::Relaxed);
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn batch_zip_persists_in_remote_id_order() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        let body = zip_bytes(&[("9/nine.txt", b"nine"), ("2/two.txt", b"two")]);
        let (port, server) = response_server(
            [
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
                body,
            ]
            .concat(),
        )
        .await;
        let directory = tempdir().unwrap();
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());

        batch_zip(
            &pool,
            "session",
            "peer",
            &remote_peer(port),
            &[json!({"id": 9}), json!({"id": 2})],
            directory.path(),
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &[],
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .unwrap();

        assert_eq!(sqlx::query_as::<_, (i64, i64)>("SELECT remote_file_id,local_file_id FROM import_file_id_map ORDER BY local_file_id").fetch_all(&pool).await.unwrap(), vec![(2, 1), (9, 2)]);
        assert!(String::from_utf8(received_request(server).await)
            .unwrap()
            .starts_with("GET /ext/lan_cowork/api/peer/import/zip?ids=9%2C2 HTTP/1.1"));
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn batch_zip_rejects_archive_with_unrequested_remote_id() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        let body = zip_bytes(&[("3/kept.txt", b"kept"), ("999/unrequested.txt", b"skip")]);
        let (port, server) = response_server_many(vec![
            [
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
                body,
            ]
            .concat(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
        ])
        .await;
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());

        batch_zip(
            &pool,
            "session",
            "peer",
            &remote_peer(port),
            &[json!({"id": 3, "path": "kept.txt"})],
            tempdir().unwrap().path(),
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &[],
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM import_file_id_map WHERE remote_file_id = 999"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_as::<_, (i64, String)>(
                "SELECT remote_file_id,status FROM import_file_id_map WHERE remote_file_id = 3"
            )
            .fetch_all(&pool)
            .await
            .unwrap(),
            vec![(3, "done".to_owned())]
        );
        let requests = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("test server did not receive both HTTP requests within 5 seconds")
            .unwrap();
        assert!(String::from_utf8_lossy(&requests[0])
            .starts_with("GET /ext/lan_cowork/api/peer/import/zip?ids=3 HTTP/1.1"));
        assert!(String::from_utf8_lossy(&requests[1])
            .starts_with("GET /ext/lan_cowork/api/peer/import/file/3 HTTP/1.1"));
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn batch_zip_size_cap_falls_back_to_individual_http() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        let zip = zip_bytes(&[("1/a.txt", b"zip")]);
        TEST_ZIP_DOWNLOAD_LIMIT.store((zip.len() - 1) as u64, Ordering::Relaxed);
        let (port, server) = response_server_many(vec![
            [
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", zip.len()).into_bytes(),
                zip,
            ]
            .concat(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
        ])
        .await;
        let directory = tempdir().unwrap();
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());
        batch_zip(
            &pool,
            "session",
            "peer",
            &remote_peer(port),
            &[json!({"id": 1, "path": "a.txt"})],
            directory.path(),
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &[],
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .unwrap();
        assert_eq!(fs::read(directory.path().join("a.txt")).unwrap(), b"ok");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM import_file_id_map")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        let requests = server.await.unwrap();
        assert!(String::from_utf8_lossy(&requests[0])
            .starts_with("GET /ext/lan_cowork/api/peer/import/zip"));
        assert!(String::from_utf8_lossy(&requests[1])
            .starts_with("GET /ext/lan_cowork/api/peer/import/file/1"));
        TEST_ZIP_DOWNLOAD_LIMIT.store(ZIP_DOWNLOAD_LIMIT, Ordering::Relaxed);
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn size_cap_fallback_then_run_completes_and_advances_rowid() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        let zip = zip_bytes(&[("1/a.txt", b"zip")]);
        TEST_ZIP_DOWNLOAD_LIMIT.store((zip.len() - 1) as u64, Ordering::Relaxed);
        let (port, server) = response_server_many(vec![
            [
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", zip.len()).into_bytes(),
                zip,
            ]
            .concat(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
        ])
        .await;
        let directory = tempdir().unwrap();
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());
        batch_zip(
            &pool,
            "session",
            "peer",
            &remote_peer(port),
            &[json!({"id": 1, "path": "a.txt"})],
            directory.path(),
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &[],
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .unwrap();
        assert_eq!(fs::read(directory.path().join("a.txt")).unwrap(), b"ok");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM import_file_id_map")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 2);

        run(
            &pool,
            "session",
            &remote_peer(1),
            json!({"files": [], "max_rowid": 42}).as_object().unwrap(),
            directory.path(),
            &Map::new(),
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_as::<_, (String, Option<i64>)>(
                "SELECT status,last_seen_rowid FROM import_session WHERE id='session'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            ("completed".to_owned(), Some(42))
        );
        TEST_ZIP_DOWNLOAD_LIMIT.store(ZIP_DOWNLOAD_LIMIT, Ordering::Relaxed);
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn batch_zip_chunks_499_501_and_1200_ids() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        for (count, expected) in [(499, 1), (501, 2), (1200, 3)] {
            let pool = test_pool().await;
            add_session(&pool, "session").await;
            let (port, server) = response_server_many(vec![zip_response(&[]); expected]).await;
            let directory = tempdir().unwrap();
            let registry =
                PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());
            batch_zip(
                &pool,
                "session",
                "peer",
                &remote_peer(port),
                &file_metas(count as i64),
                directory.path(),
                &Map::new(),
                &Map::new(),
                &Map::new(),
                &[],
                None,
                &[7; 32],
                &registry,
                &*semantic_test_state(true).await,
                None,
            )
            .await
            .unwrap();
            let requests = server.await.unwrap();
            assert_eq!(requests.len(), expected);
            for (index, request) in requests.iter().enumerate() {
                let first = index * ZIP_IDS_PER_REQUEST + 1;
                let last = (first + ZIP_IDS_PER_REQUEST - 1).min(count);
                let request = String::from_utf8_lossy(request);
                assert!(request.starts_with(&format!(
                    "GET /ext/lan_cowork/api/peer/import/zip?ids={first}"
                )));
                assert!(request.contains(&format!("{last} HTTP/1.1")));
            }
        }
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn batch_zip_persists_before_a_later_non_success_chunk() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        let (port, server) = response_server_many(vec![
            zip_response(&[("1/1.txt", b"one")]),
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ])
        .await;
        let directory = tempdir().unwrap();
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());
        batch_zip(
            &pool,
            "session",
            "peer",
            &remote_peer(port),
            &file_metas(1000),
            directory.path(),
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &[],
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM import_file_id_map")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        assert_eq!(server.await.unwrap().len(), 2);
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn batch_zip_size_cap_falls_back_only_for_its_chunk() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        let oversized_body = zip_bytes(&[("500/500.txt", b"cap")]);
        TEST_ZIP_DOWNLOAD_LIMIT.store((oversized_body.len() - 1) as u64, Ordering::Relaxed);
        let oversized = [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                oversized_body.len()
            )
            .into_bytes(),
            oversized_body,
        ]
        .concat();
        let mut responses = vec![zip_response(&[]), oversized];
        responses.extend(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                .to_vec();
            ZIP_IDS_PER_REQUEST
        ]);
        responses.push(zip_response(&[]));
        let (port, server) = response_server_many(responses).await;
        let directory = tempdir().unwrap();
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());
        batch_zip(
            &pool,
            "session",
            "peer",
            &remote_peer(port),
            &file_metas(1200),
            directory.path(),
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &[],
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .unwrap();
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), ZIP_IDS_PER_REQUEST + 3);
        assert!(!requests.iter().any(|request| {
            String::from_utf8_lossy(request)
                .starts_with("GET /ext/lan_cowork/api/peer/import/file/1001 ")
        }));
        TEST_ZIP_DOWNLOAD_LIMIT.store(ZIP_DOWNLOAD_LIMIT, Ordering::Relaxed);
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn batch_zip_keeps_prior_chunk_after_401() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        let (port, server) = response_server_many(vec![
            zip_response(&[("1/1.txt", b"one")]),
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_vec(),
            zip_response(&[]),
        ])
        .await;
        let directory = tempdir().unwrap();
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());
        batch_zip(
            &pool,
            "session",
            "peer",
            &remote_peer(port),
            &file_metas(1200),
            directory.path(),
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &[],
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM import_file_id_map")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        assert_eq!(server.await.unwrap().len(), 3);
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn batch_zip_with_no_ids_makes_no_request() {
        let pool = test_pool().await;
        add_session(&pool, "session").await;
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "local".to_owned());
        batch_zip(
            &pool,
            "session",
            "peer",
            &remote_peer(1),
            &[],
            tempdir().unwrap().path(),
            &Map::new(),
            &Map::new(),
            &Map::new(),
            &[],
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .unwrap();
    }

    #[test]
    fn batch_selection_uses_the_exact_threshold() {
        assert!(!uses_batch_zip(99));
        assert!(uses_batch_zip(100));
    }

    #[test]
    fn remote_file_count_limit_rejects_zero_byte_metadata() {
        let files = (0..=REMOTE_FILE_COUNT_LIMIT)
            .map(|id| json!({"id": id, "path": format!("{id}.txt"), "size": 0}))
            .collect::<Vec<_>>();
        assert!(validate_remote_file_count(&files).is_err());
        assert!(validate_remote_file_count(&files[..REMOTE_FILE_COUNT_LIMIT]).is_ok());
    }
}

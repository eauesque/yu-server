//! LAN Cowork import transfer helpers (Increment L3b-1).
//!
//! This module is intentionally unwired until the import transfer routes land.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::header::HeaderValue;
use sqlx::SqlitePool;
use tokio::io::AsyncWriteExt;

use crate::path_guard::{path_is_within, resolve_non_strict};
use crate::routes::{
    lan_cowork_client::build_peer_client,
    lan_cowork_host::LanCoworkHost,
    lan_cowork_import_state,
    lan_cowork_registry::{PeerInfo, PeerRegistry},
    lan_cowork_transport::{build_peer_headers_at, invalidate_outbound_token},
};

pub(crate) const FILE_DOWNLOAD_LIMIT: u64 = 8 * 1024 * 1024 * 1024;
pub(crate) const ZIP_DOWNLOAD_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const SESSION_DOWNLOAD_LIMIT: u64 = 8 * 1024 * 1024 * 1024;
const ZIP_MEMBER_LIMIT: u64 = 512 * 1024 * 1024;
const ZIP_ENTRY_COUNT_LIMIT: usize = 10_000;
const ZIP_EXTRACT_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const ZIP_COMPRESSION_RATIO_LIMIT: u64 = 100;

pub(crate) struct SessionDownloadBudget {
    pool: SqlitePool,
    session_id: String,
}

impl SessionDownloadBudget {
    pub(crate) fn new(pool: &SqlitePool, session_id: &str) -> Self {
        Self {
            pool: pool.clone(),
            session_id: session_id.to_owned(),
        }
    }

    async fn consume(&self, size: u64) -> bool {
        lan_cowork_import_state::consume_download_budget(&self.pool, &self.session_id, size)
            .await
            .unwrap_or(false)
    }
}

#[cfg(test)]
pub(crate) static TEST_FILE_DOWNLOAD_LIMIT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(FILE_DOWNLOAD_LIMIT);
#[cfg(test)]
pub(crate) static TEST_ZIP_DOWNLOAD_LIMIT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(ZIP_DOWNLOAD_LIMIT);

fn file_download_limit() -> u64 {
    #[cfg(test)]
    {
        TEST_FILE_DOWNLOAD_LIMIT.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(test))]
    FILE_DOWNLOAD_LIMIT
}

fn zip_download_limit() -> u64 {
    #[cfg(test)]
    {
        TEST_ZIP_DOWNLOAD_LIMIT.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(test))]
    ZIP_DOWNLOAD_LIMIT
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ZipEntryNameError {
    Empty,
    Nul,
    Absolute,
    DriveLetter,
    Unc,
    ParentSegment,
}

pub(crate) fn unique_dest(folder: &Path, name: &str) -> PathBuf {
    let dest = folder.join(name);
    if !dest.exists() {
        return dest;
    }

    let file_name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let (stem, suffix) = python_stem_and_suffix(file_name);
    for index in 1.. {
        let candidate = folder.join(format!("{stem}_{index}{suffix}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}

pub(crate) fn validate_zip_entry_name(name: &str) -> Result<(), ZipEntryNameError> {
    if name.is_empty() {
        return Err(ZipEntryNameError::Empty);
    }
    if name.contains('\0') {
        return Err(ZipEntryNameError::Nul);
    }

    let normalized = name.replace('\\', "/");
    if normalized.starts_with('/') {
        return Err(if normalized.starts_with("//") {
            ZipEntryNameError::Unc
        } else {
            ZipEntryNameError::Absolute
        });
    }
    if normalized.as_bytes().get(1) == Some(&b':') {
        return Err(ZipEntryNameError::DriveLetter);
    }
    if normalized.split('/').any(|part| part == "..") {
        return Err(ZipEntryNameError::ParentSegment);
    }
    Ok(())
}

pub(crate) fn verify_within(child: &Path, parent: &Path) -> bool {
    let Ok(base) = resolve_non_strict(parent) else {
        return false;
    };
    let Ok(resolved) = resolve_non_strict(child) else {
        return false;
    };
    path_is_within(&resolved, &base)
}

fn python_stem_and_suffix(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(index) if index > 0 && !name.ends_with('.') => (&name[..index], &name[index..]),
        _ => (name, ""),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn download_file(
    peer: &PeerInfo,
    remote_file_id: i64,
    dest_folder: &Path,
    original_name: &str,
    local_peer_id: Option<&str>,
    seed: &[u8],
    registry: &PeerRegistry,
    host: &dyn LanCoworkHost,
    download_budget: Option<&SessionDownloadBudget>,
) -> Option<PathBuf> {
    let full_path = format!("/ext/lan_cowork/api/peer/import/file/{remote_file_id}");
    let local_peer_id = local_peer_id
        .filter(|peer_id| !peer_id.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| registry.local_peer_id());
    let mut headers = match build_peer_headers_at(
        now_secs(),
        seed,
        &local_peer_id,
        peer,
        "GET",
        &full_path,
        "",
        b"",
    ) {
        Ok(headers) => headers,
        Err(_) => {
            tracing::warn!(peer_id = %peer.peer_id, remote_file_id, "could not build import file headers");
            return None;
        }
    };
    headers.insert(
        "X-Requested-With",
        HeaderValue::from_static("ImportTransfer"),
    );

    let (client, base) = match build_peer_client(
        &peer.api_host,
        peer.api_port,
        None,
        Some(Duration::from_secs(60)),
    )
    .await
    {
        Ok(client) => client,
        Err(_) => {
            tracing::warn!(peer_id = %peer.peer_id, remote_file_id, "could not build import file client");
            return None;
        }
    };
    let response = match client
        .get(format!("{base}{full_path}"))
        .headers(headers)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            tracing::warn!(peer_id = %peer.peer_id, remote_file_id, "import file request failed");
            return None;
        }
    };
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        invalidate_outbound_token(registry, host, &peer.peer_id).await;
        return None;
    }
    if status != reqwest::StatusCode::OK {
        tracing::warn!(peer_id = %peer.peer_id, remote_file_id, status = status.as_u16(), "import file request returned non-OK status");
        return None;
    }
    if let Err(reason) = validate_zip_entry_name(original_name) {
        tracing::warn!(
            peer_id = %peer.peer_id,
            remote_file_id,
            ?reason,
            original_name_len = original_name.len(),
            "rejected import file name"
        );
        return None;
    }
    let dest = unique_dest(dest_folder, original_name);
    let parent = dest.parent()?;
    if tokio::fs::create_dir_all(parent).await.is_err() {
        tracing::warn!(peer_id = %peer.peer_id, remote_file_id, dest_folder = %dest_folder.display(), "could not create import destination directory");
        return None;
    }
    if !verify_within(&dest, dest_folder) {
        tracing::warn!(peer_id = %peer.peer_id, remote_file_id, dest_folder = %dest_folder.display(), "import destination escaped destination folder");
        return None;
    }

    let mut bytes_written = 0u64;
    let write_result = async {
        let mut file = tokio::fs::File::create(&dest).await.map_err(|_| ())?;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ())?;
            if let Some(download_budget) = download_budget {
                if !download_budget.consume(chunk.len() as u64).await {
                    tracing::warn!(peer_id = %peer.peer_id, "import session download exceeded size limit");
                    return Err(());
                }
            }
            if bytes_written.saturating_add(chunk.len() as u64) > file_download_limit() {
                tracing::warn!(peer_id = %peer.peer_id, bytes_written, limit = file_download_limit(), "import file download exceeded size limit");
                return Err(());
            }
            file.write_all(&chunk).await.map_err(|_| ())?;
            bytes_written = bytes_written.saturating_add(chunk.len() as u64);
        }
        file.flush().await.map_err(|_| ())
    }
    .await;
    if write_result.is_err() {
        let _ = tokio::fs::remove_file(&dest).await;
        tracing::warn!(peer_id = %peer.peer_id, remote_file_id, bytes_written, "import file write failed");
        return None;
    }
    Some(dest)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn download_zip(
    peer: &PeerInfo,
    remote_file_ids: &[i64],
    dest_folder: &Path,
    local_peer_id: Option<&str>,
    seed: &[u8],
    registry: &PeerRegistry,
    host: &dyn LanCoworkHost,
    download_budget: Option<&SessionDownloadBudget>,
) -> Option<HashMap<i64, PathBuf>> {
    let full_path = "/ext/lan_cowork/api/peer/import/zip";
    let query_string = format!(
        "ids={}",
        remote_file_ids
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join("%2C")
    );
    let local_peer_id = local_peer_id
        .filter(|peer_id| !peer_id.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| registry.local_peer_id());
    let mut headers = match build_peer_headers_at(
        now_secs(),
        seed,
        &local_peer_id,
        peer,
        "GET",
        full_path,
        &query_string,
        b"",
    ) {
        Ok(headers) => headers,
        Err(_) => {
            tracing::warn!(peer_id = %peer.peer_id, "could not build import ZIP headers");
            return Some(HashMap::new());
        }
    };
    headers.insert(
        "X-Requested-With",
        HeaderValue::from_static("ImportTransfer"),
    );
    let (client, base) = match build_peer_client(
        &peer.api_host,
        peer.api_port,
        None,
        Some(Duration::from_secs(300)),
    )
    .await
    {
        Ok(client) => client,
        Err(_) => {
            tracing::warn!(peer_id = %peer.peer_id, "could not build import ZIP client");
            return Some(HashMap::new());
        }
    };
    // The exact signed query string must also be the wire query string.
    let response = match client
        .get(format!("{base}{full_path}?{query_string}"))
        .headers(headers)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            tracing::warn!(peer_id = %peer.peer_id, "import ZIP request failed");
            return Some(HashMap::new());
        }
    };
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        invalidate_outbound_token(registry, host, &peer.peer_id).await;
        return Some(HashMap::new());
    }
    if response.status() != reqwest::StatusCode::OK {
        tracing::warn!(peer_id = %peer.peer_id, status = response.status().as_u16(), "import ZIP request returned non-OK status");
        return Some(HashMap::new());
    }

    let mut file = match tempfile::tempfile() {
        Ok(file) => tokio::fs::File::from_std(file),
        Err(_) => {
            tracing::warn!(peer_id = %peer.peer_id, "could not create temporary import ZIP file");
            return Some(HashMap::new());
        }
    };
    let mut bytes_written = 0u64;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            tracing::warn!(peer_id = %peer.peer_id, bytes_written, "import ZIP download failed");
            return Some(HashMap::new());
        };
        if bytes_written.saturating_add(chunk.len() as u64) > zip_download_limit() {
            tracing::warn!(peer_id = %peer.peer_id, bytes_written, limit = zip_download_limit(), "import ZIP download exceeded size limit");
            return None;
        }
        if file.write_all(&chunk).await.is_err() {
            tracing::warn!(peer_id = %peer.peer_id, bytes_written, "import ZIP write failed");
            return Some(HashMap::new());
        }
        bytes_written = bytes_written.saturating_add(chunk.len() as u64);
    }
    if file.flush().await.is_err() {
        tracing::warn!(peer_id = %peer.peer_id, bytes_written, "import ZIP write failed");
        return Some(HashMap::new());
    }
    let file = file.into_std().await;
    let allowed_ids = remote_file_ids.iter().copied().collect::<HashSet<_>>();
    let (file, expanded_size) = tokio::task::spawn_blocking(move || {
        inspect_zip(
            file,
            &allowed_ids,
            ZIP_ENTRY_COUNT_LIMIT,
            ZIP_MEMBER_LIMIT,
            ZIP_EXTRACT_LIMIT,
            ZIP_COMPRESSION_RATIO_LIMIT,
        )
    })
    .await
    .ok()??;
    if let Some(download_budget) = download_budget {
        if !download_budget.consume(expanded_size).await {
            tracing::warn!(peer_id = %peer.peer_id, "import session extraction exceeded size limit");
            return None;
        }
    }
    let dest_folder = dest_folder.to_path_buf();
    Some(
        tokio::task::spawn_blocking(move || extract_zip(file, &dest_folder))
            .await
            .unwrap_or_default(),
    )
}

fn inspect_zip(
    file: fs::File,
    allowed_ids: &HashSet<i64>,
    entry_limit: usize,
    member_limit: u64,
    extract_limit: u64,
    ratio_limit: u64,
) -> Option<(fs::File, u64)> {
    let mut archive = zip::ZipArchive::new(file).ok()?;
    if archive.len() > entry_limit {
        return None;
    }
    let mut expanded = 0u64;
    let mut remote_ids = HashSet::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index).ok()?;
        if entry.is_dir() || entry.size() > member_limit {
            return None;
        }
        expanded = expanded.checked_add(entry.size())?;
        if expanded > extract_limit
            || (entry.size() > 0
                && (entry.compressed_size() == 0
                    || entry.size() > entry.compressed_size().saturating_mul(ratio_limit)))
        {
            return None;
        }
        let (remote_id, name) = entry.name().split_once('/')?;
        let remote_id = remote_id.parse::<i64>().ok()?;
        if !allowed_ids.contains(&remote_id)
            || !remote_ids.insert(remote_id)
            || validate_zip_entry_name(name).is_err()
        {
            return None;
        }
    }
    Some((archive.into_inner(), expanded))
}

fn extract_zip(file: fs::File, dest_folder: &Path) -> HashMap<i64, PathBuf> {
    let mut result = HashMap::new();
    let mut created = Vec::new();
    let mut failed = false;
    let Ok(mut archive) = zip::ZipArchive::new(file) else {
        tracing::warn!(dest_folder = %dest_folder.display(), "could not open import ZIP archive");
        return result;
    };
    let entry_count = archive.len();

    // Keep extraction sequential: unique_dest has a check/create TOCTOU window.
    for index in 0..entry_count {
        let Ok(mut entry) = archive.by_index(index) else {
            tracing::warn!(entry_count, "could not read import ZIP entry");
            failed = true;
            break;
        };
        // zip may apply Info-ZIP Unicode Path extras and retains NULs unlike CPython;
        // validate the crate-reported name instead of reparsing raw directory bytes.
        let name = entry.name().to_owned();
        let Some((rid, fname)) = name.split_once('/') else {
            failed = true;
            break;
        };
        // Rust accepts a narrower integer grammar than Python; failure stays fail-closed.
        let Ok(rid) = rid.parse::<i64>() else {
            failed = true;
            break;
        };
        if let Err(reason) = validate_zip_entry_name(fname) {
            tracing::warn!(
                remote_id = rid,
                ?reason,
                fname_len = fname.len(),
                "rejected import ZIP entry name"
            );
            failed = true;
            break;
        }
        // Do not flatten fname: its nested components are part of the Python contract.
        let dest = unique_dest(dest_folder, fname);
        let Some(parent) = dest.parent() else {
            failed = true;
            break;
        };
        if fs::create_dir_all(parent).is_err() {
            tracing::warn!(remote_id = rid, fname_len = fname.len(), dest_folder = %dest_folder.display(), "could not create import ZIP destination directory");
            failed = true;
            break;
        }
        if !verify_within(&dest, dest_folder) {
            tracing::warn!(remote_id = rid, fname_len = fname.len(), dest_folder = %dest_folder.display(), "import ZIP destination escaped destination folder");
            failed = true;
            break;
        }
        let Ok(mut output) = fs::File::create(&dest) else {
            tracing::warn!(
                remote_id = rid,
                fname_len = fname.len(),
                "could not create import ZIP file"
            );
            failed = true;
            break;
        };
        created.push(dest.clone());
        if std::io::copy(&mut entry, &mut output).is_err() {
            let _ = fs::remove_file(&dest);
            tracing::warn!(
                remote_id = rid,
                fname_len = fname.len(),
                bytes_written = 0,
                "import ZIP write failed"
            );
            failed = true;
            break;
        }
        if result.contains_key(&rid) {
            failed = true;
            break;
        }
        result.insert(rid, dest);
    }
    if failed {
        for path in created {
            let _ = fs::remove_file(path);
        }
        result.clear();
    }
    result
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{
        lan_cowork_descriptor::{test_guard, TEST_ALLOW_LOOPBACK},
        lan_cowork_registry::PeerRegistry,
    };
    use crate::state::semantic_test_state;
    use sqlx::{sqlite::SqlitePoolOptions, Row};
    use std::{io::Write, sync::atomic::Ordering, sync::Arc};
    use tempfile::tempdir;
    use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

    fn peer(port: u16) -> PeerInfo {
        PeerInfo {
            peer_id: "remote".to_owned(),
            name: "remote".to_owned(),
            api_host: "127.0.0.1".to_owned(),
            api_port: port,
            token: Some("outbound-token".to_owned()),
            token_expires_at: Some(2_000_000_000),
            token_issued_at: Some(1_700_000_000),
            pubkey: None,
            x25519_pk: None,
            version: String::new(),
            bridges: vec![],
            inference_types: vec![],
            gpu: String::new(),
            generating: false,
            queue_depth: 0,
            status: "online".to_owned(),
            last_seen: 0.0,
            session_id: String::new(),
            roles: vec![],
            last_reached_at: None,
            last_attempted_at: None,
        }
    }

    async fn registry() -> (Arc<PeerRegistry>, sqlx::SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE peers (peer_id TEXT PRIMARY KEY, name TEXT, api_host TEXT, api_port INTEGER, \
             token TEXT, token_expires_at INTEGER, token_issued_at INTEGER, pubkey BLOB, x25519_pk BLOB, \
             created_at INTEGER, updated_at INTEGER)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("CREATE TABLE peer_tokens (peer_id TEXT PRIMARY KEY, revoked_at INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
        (
            Arc::new(PeerRegistry::new(
                pool.clone(),
                Duration::from_secs(30),
                "local".to_owned(),
            )),
            pool,
        )
    }

    async fn response_server(response: Vec<u8>) -> Option<(u16, tokio::task::JoinHandle<Vec<u8>>)> {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(error) => panic!("could not bind response server: {error}"),
        };
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let len = stream.read(&mut request).await.unwrap();
            request.truncate(len);
            stream.write_all(&response).await.unwrap();
            request
        });
        Some((port, server))
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

    fn zip_file(bytes: &[u8]) -> fs::File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    fn corrupt_entry_crc(mut bytes: Vec<u8>, entry_index: usize) -> Vec<u8> {
        let central = bytes
            .windows(4)
            .enumerate()
            .filter_map(|(index, part)| (part == b"PK\x01\x02").then_some(index))
            .nth(entry_index)
            .unwrap();
        bytes[central + 16..central + 20].fill(0);
        bytes
    }

    #[tokio::test]
    async fn download_file_uses_fallback_id_and_signed_mounted_path() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let (registry, _) = registry().await;
        let seed = [7; 32];

        for local_peer_id in [Some(""), None] {
            let Some((port, server)) =
                response_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()).await
            else {
                return;
            };
            let remote = peer(port);
            let directory = tempdir().unwrap();
            let folder = directory.path().join("folder");
            fs::create_dir(&folder).unwrap();
            let unresolved = folder.join("..").join("folder");
            let path = download_file(
                &remote,
                42,
                &unresolved,
                "a.txt",
                local_peer_id,
                &seed,
                &registry,
                &*semantic_test_state(true).await,
                None,
            )
            .await;
            assert_eq!(path, Some(unresolved.join("a.txt")));
            assert_eq!(fs::read(folder.join("a.txt")).unwrap(), b"ok");

            let request = String::from_utf8_lossy(&server.await.unwrap()).into_owned();
            let request_lower = request.to_ascii_lowercase();
            assert!(
                request_lower.starts_with("get /ext/lan_cowork/api/peer/import/file/42 http/1.1")
            );
            assert!(request_lower.contains("x-peer-id: local"));
            assert!(request_lower.contains("x-requested-with: importtransfer"));
            let timestamp = request
                .lines()
                .find_map(|line| line.strip_prefix("x-peer-ts: "))
                .unwrap()
                .parse()
                .unwrap();
            let expected = build_peer_headers_at(
                timestamp,
                &seed,
                "local",
                &remote,
                "GET",
                "/ext/lan_cowork/api/peer/import/file/42",
                "",
                b"",
            )
            .unwrap();
            assert!(request.contains(&format!(
                "x-peer-sig: {}",
                expected["X-Peer-Sig"].to_str().unwrap()
            )));
        }
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn download_file_rejects_header_failure_and_non_ok_statuses() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let (registry, _) = registry().await;
        let directory = tempdir().unwrap();
        assert!(download_file(
            &peer(1),
            1,
            directory.path(),
            "a.txt",
            None,
            &[],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .is_none());
        for response in [
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".as_slice(),
        ] {
            let Some((port, server)) = response_server(response.to_vec()).await else {
                return;
            };
            assert!(download_file(
                &peer(port),
                1,
                directory.path(),
                "a.txt",
                None,
                &[7; 32],
                &registry,
                &*semantic_test_state(true).await,
                None,
            )
            .await
            .is_none());
            server.await.unwrap();
        }
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn download_file_401_clears_outbound_token_and_emits_only_revocation() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let Some((port, server)) =
            response_server(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_vec())
                .await
        else {
            return;
        };
        let (registry, pool) = registry().await;
        let remote = peer(port);
        registry.upsert(remote.clone()).await.unwrap();
        sqlx::query("INSERT INTO peer_tokens (peer_id, revoked_at) VALUES ('remote', NULL)")
            .execute(&pool)
            .await
            .unwrap();
        let state = semantic_test_state(true).await;
        let mut events = state.sse_hub.subscribe();
        assert!(download_file(
            &remote,
            1,
            tempdir().unwrap().path(),
            "a.txt",
            None,
            &[7; 32],
            &registry,
            &*state,
            None,
        )
        .await
        .is_none());
        let updated = registry.get("remote").unwrap();
        assert_eq!(updated.token, None);
        assert_eq!(updated.token_expires_at, None);
        assert_eq!(updated.token_issued_at, None);
        let row = sqlx::query("SELECT revoked_at FROM peer_tokens WHERE peer_id='remote'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.get::<Option<i64>, _>("revoked_at"), None);
        assert_eq!(
            events.recv().await.unwrap().event_type,
            "peer.token_revoked"
        );
        assert!(events.try_recv().is_err());
        server.await.unwrap();
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn download_file_rejects_unsafe_name_before_creating_file() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let Some((port, server)) =
            response_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()).await
        else {
            return;
        };
        let (registry, _) = registry().await;
        let directory = tempdir().unwrap();
        assert!(download_file(
            &peer(port),
            1,
            directory.path(),
            "../x",
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .is_none());
        assert!(!directory.path().join("x").exists());
        server.await.unwrap();
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn download_file_removes_partial_file_after_stream_failure() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let Some((port, server)) =
            response_server(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\npartial".to_vec()).await
        else {
            return;
        };
        let (registry, _) = registry().await;
        let directory = tempdir().unwrap();
        assert!(download_file(
            &peer(port),
            1,
            directory.path(),
            "a.txt",
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .is_none());
        assert!(!directory.path().join("a.txt").exists());
        server.await.unwrap();
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn download_file_accepts_exact_size_limit() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        TEST_FILE_DOWNLOAD_LIMIT.store(2, Ordering::Relaxed);
        let Some((port, server)) =
            response_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()).await
        else {
            return;
        };
        let (registry, _) = registry().await;
        let directory = tempdir().unwrap();
        assert_eq!(
            download_file(
                &peer(port),
                1,
                directory.path(),
                "a.txt",
                None,
                &[7; 32],
                &registry,
                &*semantic_test_state(true).await,
                None,
            )
            .await,
            Some(directory.path().join("a.txt"))
        );
        assert_eq!(fs::read(directory.path().join("a.txt")).unwrap(), b"ok");
        server.await.unwrap();
        TEST_FILE_DOWNLOAD_LIMIT.store(FILE_DOWNLOAD_LIMIT, Ordering::Relaxed);
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn download_file_rejects_size_limit_plus_one_and_removes_destination() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        TEST_FILE_DOWNLOAD_LIMIT.store(2, Ordering::Relaxed);
        let Some((port, server)) =
            response_server(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nno!".to_vec()).await
        else {
            return;
        };
        let (registry, _) = registry().await;
        let directory = tempdir().unwrap();
        assert!(download_file(
            &peer(port),
            1,
            directory.path(),
            "a.txt",
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .is_none());
        assert!(!directory.path().join("a.txt").exists());
        server.await.unwrap();
        TEST_FILE_DOWNLOAD_LIMIT.store(FILE_DOWNLOAD_LIMIT, Ordering::Relaxed);
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn download_zip_signs_the_exact_percent_encoded_wire_query() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let body = zip_bytes(&[("1/a.txt", b"ok")]);
        let Some((port, server)) = response_server(
            [
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
                body,
            ]
            .concat(),
        )
        .await
        else {
            return;
        };
        let (registry, _) = registry().await;
        let remote = peer(port);
        let directory = tempdir().unwrap();
        let result = download_zip(
            &remote,
            &[1, 2, 3],
            directory.path(),
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await;
        assert_eq!(fs::read(&result.unwrap()[&1]).unwrap(), b"ok");
        let request = String::from_utf8(server.await.unwrap()).unwrap();
        let request_lower = request.to_ascii_lowercase();
        assert!(request_lower
            .starts_with("get /ext/lan_cowork/api/peer/import/zip?ids=1%2c2%2c3 http/1.1"));
        assert!(request_lower.contains("x-requested-with: importtransfer"));
        let timestamp = request
            .lines()
            .find_map(|line| line.strip_prefix("x-peer-ts: "))
            .unwrap()
            .parse()
            .unwrap();
        let expected = build_peer_headers_at(
            timestamp,
            &[7; 32],
            "local",
            &remote,
            "GET",
            "/ext/lan_cowork/api/peer/import/zip",
            "ids=1%2C2%2C3",
            b"",
        )
        .unwrap();
        assert!(request.contains(&format!(
            "x-peer-sig: {}",
            expected["X-Peer-Sig"].to_str().unwrap()
        )));
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn download_zip_401_clears_only_outbound_token() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let Some((port, server)) =
            response_server(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_vec())
                .await
        else {
            return;
        };
        let (registry, pool) = registry().await;
        let remote = peer(port);
        registry.upsert(remote.clone()).await.unwrap();
        sqlx::query("INSERT INTO peer_tokens (peer_id, revoked_at) VALUES ('remote', NULL)")
            .execute(&pool)
            .await
            .unwrap();
        let state = semantic_test_state(true).await;
        let mut events = state.sse_hub.subscribe();
        assert!(download_zip(
            &remote,
            &[1],
            tempdir().unwrap().path(),
            None,
            &[7; 32],
            &registry,
            &*state,
            None,
        )
        .await
        .unwrap()
        .is_empty());
        let updated = registry.get("remote").unwrap();
        assert_eq!(updated.token, None);
        assert_eq!(updated.token_expires_at, None);
        assert_eq!(updated.token_issued_at, None);
        assert_eq!(
            sqlx::query("SELECT revoked_at FROM peer_tokens WHERE peer_id='remote'")
                .fetch_one(&pool)
                .await
                .unwrap()
                .get::<Option<i64>, _>("revoked_at"),
            None
        );
        assert_eq!(
            events.recv().await.unwrap().event_type,
            "peer.token_revoked"
        );
        assert!(events.try_recv().is_err());
        server.await.unwrap();
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn download_zip_accepts_exact_size_limit() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let body = zip_bytes(&[("1/a.txt", b"ok")]);
        TEST_ZIP_DOWNLOAD_LIMIT.store(body.len() as u64, Ordering::Relaxed);
        let Some((port, server)) = response_server(
            [
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
                body,
            ]
            .concat(),
        )
        .await
        else {
            return;
        };
        let (registry, _) = registry().await;
        let directory = tempdir().unwrap();
        assert_eq!(
            fs::read(
                &download_zip(
                    &peer(port),
                    &[1],
                    directory.path(),
                    None,
                    &[7; 32],
                    &registry,
                    &*semantic_test_state(true).await,
                    None,
                )
                .await
                .unwrap()[&1]
            )
            .unwrap(),
            b"ok"
        );
        server.await.unwrap();
        TEST_ZIP_DOWNLOAD_LIMIT.store(ZIP_DOWNLOAD_LIMIT, Ordering::Relaxed);
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn download_zip_returns_none_at_size_limit_plus_one() {
        let _guard = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let body = zip_bytes(&[("1/a.txt", b"ok")]);
        TEST_ZIP_DOWNLOAD_LIMIT.store((body.len() - 1) as u64, Ordering::Relaxed);
        let Some((port, server)) = response_server(
            [
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
                body,
            ]
            .concat(),
        )
        .await
        else {
            return;
        };
        let (registry, _) = registry().await;
        assert!(download_zip(
            &peer(port),
            &[1],
            tempdir().unwrap().path(),
            None,
            &[7; 32],
            &registry,
            &*semantic_test_state(true).await,
            None,
        )
        .await
        .is_none());
        server.await.unwrap();
        TEST_ZIP_DOWNLOAD_LIMIT.store(ZIP_DOWNLOAD_LIMIT, Ordering::Relaxed);
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[test]
    fn size_cap_logs_exclude_peer_derived_strings() {
        let source = include_str!("lan_cowork_import_transfer.rs");
        for message in [
            "import file download exceeded size limit",
            "import ZIP download exceeded size limit",
        ] {
            let log = source.lines().find(|line| line.contains(message)).unwrap();
            assert!(
                log.contains("peer_id") && log.contains("bytes_written") && log.contains("limit")
            );
            assert!(!log.contains("original_name") && !log.contains("chunk"));
        }
    }

    #[test]
    fn extract_zip_fails_closed_on_invalid_entry() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join("keep.txt"), b"keep").unwrap();
        let result = extract_zip(
            zip_file(&zip_bytes(&[
                ("1/created.txt", b"created"),
                ("missing-separator", b"skip"),
                ("3/sub/a.txt", b"nested"),
            ])),
            directory.path(),
        );
        assert!(result.is_empty());
        assert_eq!(
            fs::read(directory.path().join("keep.txt")).unwrap(),
            b"keep"
        );
        assert!(!directory.path().join("created.txt").exists());
        assert!(!directory.path().join("sub/a.txt").exists());
    }

    #[test]
    fn extract_zip_removes_all_created_files_on_read_failure() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join("keep.txt"), b"keep").unwrap();
        let bytes = corrupt_entry_crc(
            zip_bytes(&[
                ("1/good.txt", b"good"),
                ("2/bad.txt", b"bad"),
                ("3/later.txt", b"later"),
            ]),
            1,
        );
        let result = extract_zip(zip_file(&bytes), directory.path());
        assert!(result.is_empty());
        assert_eq!(
            fs::read(directory.path().join("keep.txt")).unwrap(),
            b"keep"
        );
        assert!(!directory.path().join("good.txt").exists());
        assert!(!directory.path().join("bad.txt").exists());
        assert!(!directory.path().join("later.txt").exists());
    }

    #[test]
    fn extract_zip_fails_closed_on_duplicate_remote_id() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join("keep.txt"), b"keep").unwrap();
        let result = extract_zip(
            zip_file(&zip_bytes(&[("12/a.txt", b"a"), ("12/b.txt", b"b")])),
            directory.path(),
        );
        assert!(result.is_empty());
        assert_eq!(
            fs::read(directory.path().join("keep.txt")).unwrap(),
            b"keep"
        );
        assert!(!directory.path().join("a.txt").exists());
        assert!(!directory.path().join("b.txt").exists());
    }

    #[test]
    fn inspect_zip_rejects_member_count_size_total_and_ratio_bombs() {
        let allowed = HashSet::from([1, 2]);
        for (entries, limits) in [
            (
                vec![("1/a.txt", b"a".as_slice()), ("2/b.txt", b"b".as_slice())],
                (1, 10, 20, 100),
            ),
            (vec![("1/a.txt", b"abc".as_slice())], (10, 2, 20, 100)),
            (
                vec![("1/a.txt", b"ab".as_slice()), ("2/b.txt", b"cd".as_slice())],
                (10, 10, 3, 100),
            ),
            (vec![("1/a.txt", &[0; 1024])], (10, 2048, 2048, 2)),
        ] {
            assert!(inspect_zip(
                zip_file(&zip_bytes(&entries)),
                &allowed,
                limits.0,
                limits.1,
                limits.2,
                limits.3,
            )
            .is_none());
        }
    }

    #[test]
    fn extract_zip_returns_empty_map_for_a_broken_archive() {
        assert!(extract_zip(zip_file(b"not a zip"), tempdir().unwrap().path()).is_empty());
    }

    #[test]
    fn validates_zip_entry_names_with_reasons() {
        for name in ["a.txt", "sub/a.txt", "12/a.txt"] {
            assert_eq!(validate_zip_entry_name(name), Ok(()));
        }

        for (name, reason) in [
            ("", ZipEntryNameError::Empty),
            ("a\0b", ZipEntryNameError::Nul),
            ("/abs/x", ZipEntryNameError::Absolute),
            ("C:\\x", ZipEntryNameError::DriveLetter),
            ("//server/share/x", ZipEntryNameError::Unc),
            ("../x", ZipEntryNameError::ParentSegment),
            ("a/../../x", ZipEntryNameError::ParentSegment),
            ("12/..\\..\\x.txt", ZipEntryNameError::ParentSegment),
            ("a/..", ZipEntryNameError::ParentSegment),
        ] {
            assert_eq!(validate_zip_entry_name(name), Err(reason), "{name:?}");
        }
    }

    #[test]
    fn verifies_resolved_containment() {
        let directory = tempdir().unwrap();
        let parent = directory.path().join("parent");
        let parentfoo = directory.path().join("parentfoo");
        let outside = directory.path().join("outside");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&parentfoo).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(parent.join("inside.txt"), b"inside").unwrap();
        fs::create_dir_all(parent.join("missing/sub")).unwrap();

        assert!(verify_within(&parent.join("inside.txt"), &parent));
        assert!(verify_within(&parent.join("missing/sub/file.txt"), &parent));
        assert!(!verify_within(&outside.join("file.txt"), &parent));
        assert!(!verify_within(&parent.join("../outside/file.txt"), &parent));
        assert!(!verify_within(&parentfoo.join("file.txt"), &parent));
    }

    #[cfg(unix)]
    #[test]
    fn verify_within_rejects_external_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let parent = directory.path().join("parent");
        let outside = directory.path().join("outside");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&outside, parent.join("photos")).unwrap();

        assert!(!verify_within(&parent.join("photos/x"), &parent));
    }

    #[test]
    fn chooses_python_style_unique_destinations() {
        let directory = tempdir().unwrap();
        let folder = directory.path().join("folder");
        fs::create_dir(&folder).unwrap();

        assert_eq!(unique_dest(&folder, "a.txt"), folder.join("a.txt"));
        fs::write(folder.join("a.txt"), b"").unwrap();
        assert_eq!(unique_dest(&folder, "a.txt"), folder.join("a_1.txt"));
        fs::write(folder.join("a_1.txt"), b"").unwrap();
        assert_eq!(unique_dest(&folder, "a.txt"), folder.join("a_2.txt"));

        fs::write(folder.join("a.tar.gz"), b"").unwrap();
        assert_eq!(unique_dest(&folder, "a.tar.gz"), folder.join("a.tar_1.gz"));
        fs::write(folder.join("a"), b"").unwrap();
        assert_eq!(unique_dest(&folder, "a"), folder.join("a_1"));
        fs::write(folder.join("a."), b"").unwrap();
        assert_eq!(unique_dest(&folder, "a."), folder.join("a._1"));

        let nested_folder = directory.path().join("nested-folder");
        fs::create_dir_all(nested_folder.join("sub")).unwrap();
        fs::write(nested_folder.join("sub/a.txt"), b"").unwrap();
        assert_eq!(
            unique_dest(&nested_folder, "sub/a.txt"),
            nested_folder.join("a_1.txt")
        );
    }

    #[test]
    fn matches_python_stem_and_suffix() {
        for (name, stem, suffix) in [
            ("a.", "a.", ""),
            ("a.txt", "a", ".txt"),
            ("a.tar.gz", "a.tar", ".gz"),
            ("a", "a", ""),
            (".bashrc", ".bashrc", ""),
            ("a..", "a..", ""),
        ] {
            assert_eq!(python_stem_and_suffix(name), (stem, suffix));
        }
    }
}

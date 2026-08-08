//! LAN Cowork sync manifest and path-validation primitives (Increment S1).
//!
//! Port of `sync_manifest.py` and the pure file helpers in `sync_manager.py`.
//! This module is intentionally unwired until the sync routes land in a later increment.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::path_guard::resolve_non_strict;

#[derive(Clone, Debug, PartialEq)]
pub struct ManifestEntry {
    pub hash: String,
    pub mtime: f64,
    pub size: u64,
}

pub type Manifest = BTreeMap<String, ManifestEntry>;

#[derive(Debug, thiserror::Error)]
pub enum SyncPathError {
    #[error("sync path is invalid")]
    Invalid,
    #[error("sync path escapes its root")]
    EscapesRoot,
    #[error("sync path resolution failed")]
    Io(#[source] io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum SyncWriteError {
    #[error("sync path validation failed")]
    Path(#[from] SyncPathError),
    #[error("sync file write failed")]
    Io(#[from] io::Error),
}

/// Return the SHA-256 hex digest of a file, reading it in Python's 8192-byte chunks.
pub fn file_hash(path: &Path) -> io::Result<String> {
    use std::io::Read;

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut chunk = [0; 8192];
    loop {
        let count = file.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        hasher.update(&chunk[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Scan a root with Python `Path.rglob("*")` semantics, excluding leaves resolving outside root.
pub fn build_manifest(root: &Path) -> io::Result<Manifest> {
    let root = resolve_non_strict(root)?;
    let mut manifest = Manifest::new();
    // No depth limit is needed: this is a heap-backed explicit stack, and directory
    // symlinks are not descended, so each finite directory tree is scanned finitely.
    let mut directories = vec![root.clone()];

    while let Some(directory) = directories.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if directory == root && error.kind() == io::ErrorKind::NotFound => {
                return Ok(manifest);
            }
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                directories.push(path);
                continue;
            }
            // Python rglob does not descend directory symlinks, but is_file follows file symlinks.
            // Therefore symlinks can only be leaf entries here; resolve those before admitting them.
            if file_type.is_symlink() && !resolve_non_strict(&path)?.starts_with(&root) {
                continue;
            }
            let metadata = match fs::metadata(&path) {
                Ok(metadata) if metadata.is_file() => metadata,
                _ => continue,
            };
            let relative = path
                .strip_prefix(&root)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "manifest entry is outside its root",
                    )
                })?
                .components()
                .map(|component| match component {
                    Component::Normal(name) => name.to_str().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "manifest path contains a non-UTF-8 component",
                        )
                    }),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "manifest path contains an invalid component",
                    )),
                })
                .collect::<io::Result<Vec<_>>>()?
                .join("/");
            manifest.insert(
                relative,
                ManifestEntry {
                    hash: file_hash(&path)?,
                    mtime: mtime_f64(metadata.modified()?),
                    size: metadata.len(),
                },
            );
        }
    }
    Ok(manifest)
}

/// Return `(to_fetch, to_push)`, with sorted output from BTreeMap iteration.
pub fn diff_manifests(local: &Manifest, remote: &Manifest) -> (Vec<String>, Vec<String>) {
    let mut to_fetch = Vec::new();
    let mut to_push = Vec::new();
    let keys: BTreeSet<_> = local.keys().chain(remote.keys()).collect();

    for key in keys {
        match (local.get(key), remote.get(key)) {
            (None, Some(_)) => to_fetch.push(key.clone()),
            (Some(_), None) => to_push.push(key.clone()),
            (Some(local_entry), Some(remote_entry)) if local_entry.hash != remote_entry.hash => {
                if remote_entry.mtime > local_entry.mtime {
                    to_fetch.push(key.clone());
                } else {
                    to_push.push(key.clone());
                }
            }
            _ => {}
        }
    }
    (to_fetch, to_push)
}

/// Resolve and validate a relative sync path against a root without lexical-only shortcuts.
pub fn validate_sync_path(root: &Path, rel_path: &str) -> Result<PathBuf, SyncPathError> {
    if rel_path.contains('\0') {
        return Err(SyncPathError::Invalid);
    }
    if Path::new(rel_path).is_absolute() {
        // Python accepts absolute paths resolving inside root; reject them here fail-closed.
        return Err(SyncPathError::Invalid);
    }
    let resolved_root = resolve_non_strict(root).map_err(SyncPathError::Io)?;
    let target = resolve_non_strict(&root.join(rel_path)).map_err(SyncPathError::Io)?;
    target
        .starts_with(&resolved_root)
        .then_some(target)
        .ok_or(SyncPathError::EscapesRoot)
}

/// Create the Python `with_suffix(suffix + ".bak")` backup and preserve its mtime.
pub fn backup_file(path: &Path) -> io::Result<()> {
    let modified = fs::metadata(path)?.modified()?;
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "backup path has no file name")
    })?;
    let mut backup_name = OsString::from(name);
    backup_name.push(".bak");
    let backup = path.with_file_name(backup_name);
    fs::copy(path, &backup)?;
    OpenOptions::new()
        .write(true)
        .open(backup)?
        .set_modified(modified)
}

/// Write a sync payload to its validated resolved path and return whether it replaced a file.
pub fn write_synced_file(
    root: &Path,
    rel_path: &str,
    content: &[u8],
) -> Result<bool, SyncWriteError> {
    let target = validate_sync_path(root, rel_path)?;
    let conflict = target.exists();
    if conflict {
        backup_file(&target)?;
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(target, content)?;
    Ok(conflict)
}

fn mtime_f64(time: SystemTime) -> f64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs_f64(),
        Err(error) => -error.duration().as_secs_f64(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::time::Duration;
    use tempfile::tempdir;

    const VECTORS: &str = include_str!("../../tests/vectors/sync_vectors.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("sync vectors parse")
    }

    fn manifest(value: &Value) -> Manifest {
        value
            .as_object()
            .unwrap()
            .iter()
            .map(|(path, entry)| {
                (
                    path.clone(),
                    ManifestEntry {
                        hash: entry["hash"].as_str().unwrap().into(),
                        mtime: entry["mtime"].as_f64().unwrap(),
                        size: entry["size"].as_u64().unwrap(),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn file_hash_matches_sha256_vector() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("hash.txt");
        fs::write(&path, b"abc").unwrap();
        assert_eq!(
            file_hash(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn diff_matches_vectors() {
        for case in vectors()["diff_cases"].as_array().unwrap() {
            let (fetch, push) =
                diff_manifests(&manifest(&case["local"]), &manifest(&case["remote"]));
            let expected_fetch: Vec<String> =
                serde_json::from_value(case["fetch"].clone()).unwrap();
            let expected_push: Vec<String> = serde_json::from_value(case["push"].clone()).unwrap();
            assert_eq!(
                (fetch, push),
                (expected_fetch, expected_push),
                "{}",
                case["label"]
            );
        }
    }

    #[test]
    fn backup_names_match_vectors() {
        let directory = tempdir().unwrap();
        for case in vectors()["backup_names"].as_array().unwrap() {
            let path = directory.path().join(case["source"].as_str().unwrap());
            fs::write(&path, b"source").unwrap();
            backup_file(&path).unwrap();
            assert!(directory
                .path()
                .join(case["backup"].as_str().unwrap())
                .exists());
        }
    }

    #[test]
    fn simple_path_cases_match_vectors() {
        let directory = tempdir().unwrap();
        let root = directory.path().join("root");
        fs::create_dir(&root).unwrap();
        for case in vectors()["path_cases"].as_array().unwrap() {
            assert_eq!(
                validate_sync_path(&root, case["path"].as_str().unwrap()).is_ok(),
                case["valid"].as_bool().unwrap(),
                "{}",
                case["label"]
            );
        }
    }

    #[test]
    fn validate_rejects_absolute_path_inside_root() {
        let directory = tempdir().unwrap();
        let root = directory.path().join("root");
        fs::create_dir(&root).unwrap();
        let absolute_path = root.join("inside.txt");

        assert!(matches!(
            validate_sync_path(&root, absolute_path.to_str().unwrap()),
            Err(SyncPathError::Invalid)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn validate_resolves_each_component_and_rejects_escapes() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let root = directory.path().join("root");
        let outside = directory.path().join("outside.txt");
        fs::create_dir(&root).unwrap();
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, root.join("link")).unwrap();

        assert!(matches!(
            validate_sync_path(&root, "link"),
            Err(SyncPathError::EscapesRoot)
        ));
        assert!(matches!(
            validate_sync_path(&root, "nope/../link"),
            Err(SyncPathError::EscapesRoot)
        ));
        assert!(matches!(
            validate_sync_path(&root, "a/../../.."),
            Err(SyncPathError::EscapesRoot)
        ));
        assert_eq!(
            validate_sync_path(&root, "nonexistent/../ok.txt").unwrap(),
            root.join("ok.txt")
        );
        assert!(matches!(
            validate_sync_path(&root, "bad\0path"),
            Err(SyncPathError::Invalid)
        ));
    }

    #[test]
    fn write_creates_parents_and_preserves_backup_mtime() {
        let directory = tempdir().unwrap();
        let root = directory.path().join("root");
        assert!(!write_synced_file(&root, "nested/new.txt", b"new").unwrap());
        assert_eq!(fs::read(root.join("nested/new.txt")).unwrap(), b"new");

        let original = root.join("nested/new.txt");
        let mtime = UNIX_EPOCH + Duration::from_secs(1_234_567);
        File::open(&original).unwrap().set_modified(mtime).unwrap();
        assert!(write_synced_file(&root, "nested/new.txt", b"replacement").unwrap());
        let backup = root.join("nested/new.txt.bak");
        assert_eq!(fs::read(&backup).unwrap(), b"new");
        assert_eq!(fs::metadata(&backup).unwrap().modified().unwrap(), mtime);
    }

    #[cfg(unix)]
    #[test]
    fn write_rejects_dangling_external_link() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let root = directory.path().join("root");
        let outside = directory.path().join("outside.txt");
        fs::create_dir(&root).unwrap();
        symlink(&outside, root.join("link")).unwrap();
        assert!(matches!(
            write_synced_file(&root, "link", b"secret"),
            Err(SyncWriteError::Path(SyncPathError::EscapesRoot))
        ));
        assert!(!outside.exists());
    }

    #[test]
    fn writing_a_directory_returns_an_io_error() {
        let directory = tempdir().unwrap();
        let root = directory.path().join("root");
        fs::create_dir(&root).unwrap();
        for path in [".", "./", "a/.."] {
            assert!(matches!(
                write_synced_file(&root, path, b"x"),
                Err(SyncWriteError::Io(_))
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn manifest_skips_directory_links_and_follows_file_links() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let root = directory.path().join("root");
        let external_dir = directory.path().join("external-dir");
        let external_file = directory.path().join("external.txt");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::create_dir(&external_dir).unwrap();
        fs::write(root.join("nested/local.txt"), b"local").unwrap();
        fs::write(external_dir.join("hidden.txt"), b"hidden").unwrap();
        fs::write(&external_file, b"linked").unwrap();
        fs::write(root.join("inside.txt"), b"inside").unwrap();
        symlink(&external_dir, root.join("directory-link")).unwrap();
        symlink(&external_file, root.join("file-link")).unwrap();
        symlink(root.join("inside.txt"), root.join("inside-link")).unwrap();

        let manifest = build_manifest(&root).unwrap();
        assert_eq!(
            manifest["nested/local.txt"].hash,
            file_hash(&root.join("nested/local.txt")).unwrap()
        );
        assert!(!manifest.contains_key("file-link"));
        assert_eq!(
            manifest["inside-link"].hash,
            file_hash(&root.join("inside.txt")).unwrap()
        );
        assert!(!manifest
            .keys()
            .any(|path| path.starts_with("directory-link/")));
    }

    #[cfg(unix)]
    #[test]
    fn manifest_key_preserves_backslashes() {
        let directory = tempdir().unwrap();
        let root = directory.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join(r"a\b.txt"), b"contents").unwrap();

        let manifest = build_manifest(&root).unwrap();
        assert!(manifest.contains_key(r"a\b.txt"));
        assert!(!manifest.contains_key("a/b.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn manifest_rejects_non_utf8_key_components() {
        use std::os::unix::ffi::OsStringExt;

        let directory = tempdir().unwrap();
        let root = directory.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join(OsString::from_vec(b"non-utf8-\xff.txt".to_vec())),
            b"contents",
        )
        .unwrap();

        assert_eq!(
            build_manifest(&root).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn missing_root_has_an_empty_manifest() {
        let directory = tempdir().unwrap();
        assert!(build_manifest(&directory.path().join("missing"))
            .unwrap()
            .is_empty());
    }
}

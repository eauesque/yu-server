use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

const UNIX_SENSITIVE_BASES: &[&str] = &[
    "/etc",
    "/bin",
    "/sbin",
    "/boot",
    "/dev",
    "/proc",
    "/run",
    "/sys",
    "/lib",
    "/lib64",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/bin",
    "/usr/local/lib",
    "/usr/share/applications",
    "/usr/local/share/applications",
];
const WINDOWS_SENSITIVE_BASES: &[&str] = &[
    r"C:\\Windows",
    r"C:\\Program Files",
    r"C:\\Program Files (x86)",
];

pub fn normalize_path(path: &Path) -> PathBuf {
    let path = path.as_os_str().to_string_lossy();
    if let Some(path) = path.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{path}"))
    } else {
        PathBuf::from(path.strip_prefix(r"\\?\").unwrap_or(&path))
    }
}

/// Compare two **already-resolved** paths for containment.
///
/// This is a COMPARISON predicate, not a NORMALIZATION one: it strips the Windows
/// verbatim prefix and compares components (case-insensitively on Windows), but it
/// never calls `canonicalize` and never folds `..`. Callers must resolve both sides
/// first — e.g. with `resolve_non_strict` when the target may not exist yet.
///
/// Passing unresolved paths silently defeats containment checks: an outward symlink
/// or a bare `..` component compares as "inside". See
/// `docs/development/development_docs/WINDOWS_VERBATIM_PATH_PITFALL.md` — the
/// "correct usage" there is two steps (resolve, then compare), and this function is
/// only the second.
pub fn path_is_within(path: &Path, base: &Path) -> bool {
    let path = normalize_path(path);
    let base = normalize_path(base);
    let base = base.as_path();
    #[cfg(windows)]
    {
        let mut path_components = path.components();
        base.components().all(|base_component| {
            path_components.next().is_some_and(|component| {
                component.as_os_str().to_string_lossy().to_lowercase()
                    == base_component.as_os_str().to_string_lossy().to_lowercase()
            })
        })
    }
    #[cfg(not(windows))]
    {
        path.starts_with(base)
    }
}

/// Resolve a path the way Python's `os.path.realpath(strict=False)` does: canonicalize
/// each existing prefix, following symlinks (bounded at 40 hops to avoid infinite
/// symlink cycles), and pass through any trailing components that do not exist yet
/// without requiring them to. This lets containment checks resolve targets that may
/// not have been created yet, unlike `std::fs::canonicalize` which requires the full
/// path to exist.
pub fn resolve_non_strict(path: &Path) -> io::Result<PathBuf> {
    let mut resolved = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir()?
    };
    let mut pending = path_parts(path);
    let mut expansions = 0;

    while let Some(part) = pending.pop_front() {
        match part {
            PathPart::Prefix(prefix) => resolved.push(prefix),
            PathPart::Root => resolved.push(std::path::MAIN_SEPARATOR_STR),
            PathPart::Current => {}
            PathPart::Parent => {
                resolved.pop();
            }
            PathPart::Normal(name) => {
                let candidate = resolved.join(&name);
                match fs::read_link(&candidate) {
                    Ok(link) if expansions < 40 => {
                        expansions += 1;
                        if link.is_absolute() {
                            resolved.clear();
                        }
                        prepend_parts(&mut pending, path_parts(&link));
                    }
                    Ok(_) => resolved.push(name),
                    Err(_) => resolved.push(name),
                }
            }
        }
    }
    Ok(resolved)
}

enum PathPart {
    Prefix(OsString),
    Root,
    Current,
    Parent,
    Normal(OsString),
}

fn path_parts(path: &Path) -> VecDeque<PathPart> {
    path.components()
        .map(|component| match component {
            Component::Prefix(prefix) => PathPart::Prefix(prefix.as_os_str().to_os_string()),
            Component::RootDir => PathPart::Root,
            Component::CurDir => PathPart::Current,
            Component::ParentDir => PathPart::Parent,
            Component::Normal(name) => PathPart::Normal(name.to_os_string()),
        })
        .collect()
}

fn prepend_parts(pending: &mut VecDeque<PathPart>, mut parts: VecDeque<PathPart>) {
    while let Some(part) = parts.pop_back() {
        pending.push_front(part);
    }
}

/// Resolve sensitive bases before comparing them with an already-resolved path.
/// Callers choose the extra bases and home-directory failure policy.
pub fn resolve_sensitive_bases(extra: &[PathBuf], home: &Path) -> Vec<PathBuf> {
    let mut bases = extra.to_vec();
    bases.push(home.join("AppData"));
    if Path::new("/").exists() {
        bases.extend(UNIX_SENSITIVE_BASES.iter().map(PathBuf::from));
    }
    if cfg!(windows) {
        bases.extend(
            ["APPDATA", "LOCALAPPDATA"]
                .into_iter()
                .filter_map(std::env::var_os)
                .map(PathBuf::from),
        );
        bases.extend(WINDOWS_SENSITIVE_BASES.iter().map(PathBuf::from));
    }
    bases
        .into_iter()
        .filter_map(|base| resolve_non_strict(&base).ok())
        .map(|base| normalize_path(&base))
        .filter(|base| !base.as_os_str().is_empty() && base.parent().is_some())
        .collect()
}

pub fn under_home_dot_dir(path: &Path, home: &Path) -> bool {
    path_is_within(path, home)
        && path
            .components()
            .nth(home.components().count())
            .is_some_and(|component| component.as_os_str().to_string_lossy().starts_with('.'))
}

pub fn is_under_any(path: &Path, bases: &[PathBuf]) -> bool {
    bases.iter().any(|base| path_is_within(path, base))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn normalizes_verbatim_and_unc_prefixes() {
        assert_eq!(
            normalize_path(Path::new(r"\\?\C:\root\file.jpg")),
            PathBuf::from(r"C:\root\file.jpg")
        );
        assert_eq!(
            normalize_path(Path::new(r"\\?\UNC\server\share\file.jpg")),
            PathBuf::from(r"\\server\share\file.jpg")
        );
    }

    #[test]
    fn compares_path_components() {
        assert!(path_is_within(
            Path::new("/root/file.jpg"),
            Path::new("/root")
        ));
        assert!(!path_is_within(
            Path::new("/rootfoo/file.jpg"),
            Path::new("/root")
        ));
    }

    #[cfg(windows)]
    #[test]
    fn folds_case_on_windows() {
        assert!(path_is_within(
            Path::new(r"\\?\C:\ROOT\file.jpg"),
            Path::new(r"c:\root"),
        ));
        assert!(path_is_within(
            Path::new(r"\\?\UNC\server\share\file.jpg"),
            Path::new(r"\\server\share"),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_non_strict_keeps_remaining_components_after_symlink_limit() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let root = directory.path().join("root");
        fs::create_dir(&root).unwrap();
        for index in 0..45 {
            symlink(
                format!("link{}", index + 1),
                root.join(format!("link{index}")),
            )
            .unwrap();
        }

        assert_eq!(
            resolve_non_strict(&root.join("link0/tail/file.txt")).unwrap(),
            root.join("link40/tail/file.txt")
        );
    }
}

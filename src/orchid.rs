//! orchid awareness. ast never starts, stops, enables or disables a service; it only detects the
//! service files a package ships and reports their state, so the user can decide.

use crate::db::{FileKind, FileRecord};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// Service names shipped by a package: the files of `etc/orchid/services/`.
pub fn services_in(files: &[FileRecord]) -> Vec<String> {
    let mut v: Vec<String> = files
        .iter()
        .filter(|f| f.kind == FileKind::File)
        .filter_map(|f| f.path.strip_prefix("etc/orchid/services/"))
        .filter_map(|n| n.strip_suffix(".toml"))
        .filter(|n| !n.is_empty() && !n.contains('/'))
        .map(String::from)
        .collect();
    v.sort();
    v
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ServiceState {
    /// Starts at boot: its link is in `etc/orchid/enabled`, or that directory does not exist yet
    /// (then orchid starts every service).
    pub enabled: bool,
    /// PID 1 reports it running.
    pub running: bool,
}

pub fn service_state(root: &Path, svc: &str) -> ServiceState {
    let dir = root.join("etc/orchid/enabled");
    let enabled = !dir.is_dir() || std::fs::symlink_metadata(dir.join(format!("{svc}.toml"))).is_ok();
    ServiceState { enabled, running: running(root, svc) }
}

/// Ask PID 1 (`list`: `NAME  STATE  ...`); a system that is not running answers nothing.
fn running(root: &Path, svc: &str) -> bool {
    let Ok(mut s) = UnixStream::connect(root.join("run/orchid.sock")) else { return false };
    if s.write_all(b"list\n").is_err() {
        return false;
    }
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.lines().any(|l| {
        let mut f = l.split("  ");
        f.next() == Some(svc) && f.next() == Some("up")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, kind: FileKind) -> FileRecord {
        FileRecord { path: path.into(), kind, sha256: None, target: None, mode: 0o644, config: false }
    }

    #[test]
    fn detects_services() {
        let files = vec![
            f("etc/orchid/services/nginx.toml", FileKind::File),
            f("etc/orchid/services/readme.txt", FileKind::File),
            f("etc/orchid/services", FileKind::Dir),
            f("etc/orchid/enabled/nginx.toml", FileKind::Symlink),
            f("usr/bin/nginx", FileKind::File),
        ];
        assert_eq!(services_in(&files), vec!["nginx".to_string()]);
    }

    #[test]
    fn reads_service_state() {
        let d = tempfile::tempdir().unwrap();
        // no enabled directory: everything starts at boot
        assert!(service_state(d.path(), "nginx").enabled);
        std::fs::create_dir_all(d.path().join("etc/orchid/enabled")).unwrap();
        assert!(!service_state(d.path(), "nginx").enabled);
        std::os::unix::fs::symlink("../services/nginx.toml", d.path().join("etc/orchid/enabled/nginx.toml")).unwrap();
        let s = service_state(d.path(), "nginx");
        assert!(s.enabled && !s.running);
    }
}

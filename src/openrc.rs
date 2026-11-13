//! OpenRC awareness. ast never starts, stops, enables or disables a
//! service; it only detects service scripts and reports their state so the
//! user can decide.

use crate::db::{FileKind, FileRecord};
use std::path::Path;

/// Service names shipped by a package: executable files in `etc/init.d/`.
pub fn services_in(files: &[FileRecord]) -> Vec<String> {
    let mut v: Vec<String> = files
        .iter()
        .filter(|f| f.kind == FileKind::File && f.mode & 0o111 != 0)
        .filter_map(|f| f.path.strip_prefix("etc/init.d/"))
        .filter(|n| !n.is_empty() && !n.contains('/'))
        .map(String::from)
        .collect();
    v.sort();
    v
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ServiceState {
    /// Runlevels in which the service is enabled (`/etc/runlevels/<level>/<svc>`).
    pub enabled_in: Vec<String>,
    /// `/run/openrc/started/<svc>` exists.
    pub running: bool,
}

pub fn service_state(root: &Path, svc: &str) -> ServiceState {
    let mut st = ServiceState::default();
    if let Ok(rd) = std::fs::read_dir(root.join("etc/runlevels")) {
        for lvl in rd.flatten() {
            if std::fs::symlink_metadata(lvl.path().join(svc)).is_ok() {
                st.enabled_in.push(lvl.file_name().to_string_lossy().into_owned());
            }
        }
    }
    st.enabled_in.sort();
    st.running = std::fs::symlink_metadata(root.join("run/openrc/started").join(svc)).is_ok();
    st
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, mode: u32, kind: FileKind) -> FileRecord {
        FileRecord { path: path.into(), kind, sha256: None, target: None, mode, config: false }
    }

    #[test]
    fn detects_services() {
        let files = vec![
            f("etc/init.d/nginx", 0o755, FileKind::File),
            f("etc/init.d/readme", 0o644, FileKind::File),
            f("etc/init.d", 0o755, FileKind::Dir),
            f("etc/conf.d/nginx", 0o644, FileKind::File),
            f("usr/bin/nginx", 0o755, FileKind::File),
        ];
        assert_eq!(services_in(&files), vec!["nginx".to_string()]);
    }

    #[test]
    fn reads_service_state() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc/runlevels/default")).unwrap();
        std::fs::create_dir_all(d.path().join("etc/runlevels/boot")).unwrap();
        std::os::unix::fs::symlink("/etc/init.d/nginx", d.path().join("etc/runlevels/default/nginx")).unwrap();
        std::fs::create_dir_all(d.path().join("run/openrc/started")).unwrap();
        std::fs::write(d.path().join("run/openrc/started/nginx"), "").unwrap();
        let s = service_state(d.path(), "nginx");
        assert_eq!(s.enabled_in, vec!["default".to_string()]);
        assert!(s.running);
        assert_eq!(service_state(d.path(), "other"), ServiceState::default());
    }
}

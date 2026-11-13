//! Filesystem layout, locking, logging and small helpers.

use crate::error::{Error, IoCtx, Result};
use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// All paths ast uses, derived from an alternate root (`/` normally, a
/// temporary directory in tests).
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
    pub etc: PathBuf,
    pub keys: PathBuf,
    pub db: PathBuf,
    pub installed: PathBuf,
    pub repo_cache: PathBuf,
    pub journal: PathBuf,
    pub lock: PathBuf,
    pub packages: PathBuf,
    pub build: PathBuf,
    pub log: PathBuf,
}

impl Paths {
    pub fn new(root: &Path) -> Paths {
        let r = |p: &str| root.join(p);
        Paths {
            root: root.to_path_buf(),
            etc: r("etc/ast"),
            keys: r("etc/ast/keys"),
            db: r("var/lib/ast/db"),
            installed: r("var/lib/ast/db/installed"),
            repo_cache: r("var/lib/ast/db/repos"),
            journal: r("var/lib/ast/db/txn"),
            lock: r("var/lib/ast/lock"),
            packages: r("var/cache/ast/packages"),
            build: r("var/cache/ast/build"),
            log: r("var/log/ast.log"),
        }
    }

    pub fn ast_toml(&self) -> PathBuf {
        self.etc.join("ast.toml")
    }
    pub fn repos_toml(&self) -> PathBuf {
        self.etc.join("repos.toml")
    }
}

/// Create a directory (and parents) with the given mode for the leaf.
pub fn mkdir_private(path: &Path, mode: u32) -> Result<()> {
    std::fs::create_dir_all(path).ctx("cannot create directory", path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).ctx("cannot chmod", path)
}

/// Write a file atomically: temp file in the same directory, fsync, rename.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().ok_or_else(|| Error::Other(format!("no parent for {}", path.display())))?;
    std::fs::create_dir_all(dir).ctx("cannot create directory", dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
        std::process::id()
    ));
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, mode);
        let mut f = opts.open(&tmp).ctx("cannot create", &tmp)?;
        f.write_all(data).ctx("cannot write", &tmp)?;
        f.sync_all().ctx("cannot sync", &tmp)?;
    }
    std::fs::rename(&tmp, path).ctx("cannot rename into place", path)?;
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Exclusive process-wide lock; released when dropped.
pub struct LockGuard {
    _file: File,
}

impl LockGuard {
    pub fn acquire(path: &Path) -> Result<LockGuard> {
        if let Some(dir) = path.parent() {
            mkdir_private(dir, 0o755)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .ctx("cannot open lock file", path)?;
        // Retry briefly: a lock can still be held for a few milliseconds by a
        // child process that has forked but not yet exec'd (close-on-exec).
        let contended = fs2::lock_contended_error().raw_os_error();
        for attempt in 0..6 {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(LockGuard { _file: file }),
                Err(e) if e.raw_os_error() == contended => {
                    if attempt < 5 {
                        std::thread::sleep(std::time::Duration::from_millis(40));
                    }
                }
                Err(e) => return Err(Error::io(format!("cannot lock {}", path.display()), e)),
            }
        }
        Err(Error::Locked(path.display().to_string()))
    }
}

/// Append-only operation log.
pub struct Log {
    path: PathBuf,
}

impl Log {
    pub fn new(path: PathBuf) -> Log {
        Log { path }
    }

    pub fn line(&self, msg: &str) {
        // Logging must never make an operation fail.
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(f, "{} {}", iso_time(now()), msg);
        }
    }
}

/// Running as root (the effective uid owns /proc/self).
pub fn is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map(|m| m.uid() == 0).unwrap_or(false)
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// UTC timestamp `YYYY-MM-DDTHH:MM:SSZ` from unix seconds.
pub fn iso_time(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// One line per row: the non-empty cells joined by exactly two spaces.
/// No padding, no alignment: every gap is the same.
pub fn table(rows: &[Vec<String>], indent: &str) -> Vec<String> {
    rows.iter()
        .map(|r| format!("{indent}{}", r.iter().filter(|c| !c.is_empty()).map(String::as_str).collect::<Vec<_>>().join("  ")))
        .collect()
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

pub fn available_space(path: &Path) -> Result<u64> {
    // Walk up to the first existing ancestor.
    let mut p = path;
    while !p.exists() {
        p = p.parent().ok_or_else(|| Error::Other(format!("no existing parent of {}", path.display())))?;
    }
    fs2::available_space(p).map_err(|e| Error::io(format!("cannot query free space of {}", p.display()), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_joins_with_exactly_two_spaces() {
        let row = |c: &[&str]| c.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let rows = vec![row(&["cowsay-lite", "1.0-1", "src", "ast"]), row(&["hello", "1.1-1", "", "ast"])];
        assert_eq!(table(&rows, "  "), vec!["  cowsay-lite  1.0-1  src  ast", "  hello  1.1-1  ast"]);
        assert!(table(&[], "").is_empty());
    }

    #[test]
    fn iso_time_known_values() {
        assert_eq!(iso_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_time(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn lock_is_exclusive() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("lock");
        let g = LockGuard::acquire(&p).unwrap();
        assert!(matches!(LockGuard::acquire(&p), Err(Error::Locked(_))));
        drop(g);
        LockGuard::acquire(&p).unwrap();
    }

    #[test]
    fn atomic_write_replaces() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a/b.txt");
        atomic_write(&p, b"one", 0o644).unwrap();
        atomic_write(&p, b"two", 0o644).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
    }
}

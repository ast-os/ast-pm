//! Transaction journal with rollback.
//!
//! Every filesystem mutation made during an install/remove goes through a
//! `Txn`, which records an undo entry in `<db>/txn/journal` *before* the
//! change. Replaced or removed files are moved into `<db>/txn/backup/`
//! instead of being deleted. `commit` deletes the journal and backups;
//! `rollback` (also run automatically by `recover` after a crash or power
//! cut) replays the journal in reverse.
//!
//! This is as atomic as a general filesystem allows: individual files appear
//! non-atomically during the transaction, but any failure or interruption
//! returns the system to its previous state.

use crate::error::{Error, IoCtx, Result};
use crate::util::{Paths, mkdir_private};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq)]
enum Op {
    /// A new file/symlink was created at `path`.
    Created { path: PathBuf },
    /// The existing `path` was moved to backup file `backup`.
    Backup { path: PathBuf, backup: String },
    /// A new directory was created.
    Mkdir { path: PathBuf },
    /// An (empty) directory was removed.
    Rmdir { path: PathBuf, mode: u32 },
}

impl Op {
    /// One journal line (without the newline): fields separated by tabs, with `\\`, tab and
    /// newline escaped inside paths.
    fn encode(&self) -> String {
        match self {
            Op::Created { path } => format!("created\t{}", esc(path)),
            Op::Backup { path, backup } => format!("backup\t{}\t{backup}", esc(path)),
            Op::Mkdir { path } => format!("mkdir\t{}", esc(path)),
            Op::Rmdir { path, mode } => format!("rmdir\t{mode:o}\t{}", esc(path)),
        }
    }

    fn decode(line: &str) -> Option<Op> {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["created", p] => Some(Op::Created { path: unesc(p) }),
            ["backup", p, b] => Some(Op::Backup { path: unesc(p), backup: b.to_string() }),
            ["mkdir", p] => Some(Op::Mkdir { path: unesc(p) }),
            ["rmdir", m, p] => Some(Op::Rmdir { path: unesc(p), mode: u32::from_str_radix(m, 8).ok()? }),
            _ => None,
        }
    }
}

fn esc(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "\\\\").replace('\t', "\\t").replace('\n', "\\n")
}

fn unesc(s: &str) -> PathBuf {
    let mut out = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some(o) => out.push(o),
            None => {}
        }
    }
    PathBuf::from(out)
}

pub struct Txn {
    dir: PathBuf,
    backups: PathBuf,
    journal: File,
    seq: u64,
    root: PathBuf,
}

impl Txn {
    pub fn begin(paths: &Paths) -> Result<Txn> {
        if paths.journal.join("journal").exists() {
            return Err(Error::Other(format!(
                "an unfinished transaction journal exists in {}; it should have been rolled back automatically",
                paths.journal.display()
            )));
        }
        mkdir_private(&paths.journal, 0o700)?;
        let backups = paths.journal.join("backup");
        mkdir_private(&backups, 0o700)?;
        let jp = paths.journal.join("journal");
        let journal = OpenOptions::new()
            .create_new(true)
            .append(true)
            .mode(0o600)
            .open(&jp)
            .ctx("cannot create journal", &jp)?;
        Ok(Txn { dir: paths.journal.clone(), backups, journal, seq: 0, root: paths.root.clone() })
    }

    /// Roll back a journal left by a crashed run. Returns true if one existed.
    pub fn recover(paths: &Paths) -> Result<bool> {
        let jp = paths.journal.join("journal");
        if !jp.exists() {
            let _ = std::fs::remove_dir_all(&paths.journal); // stray empty dirs
            return Ok(false);
        }
        rollback_dir(&paths.journal)?;
        Ok(true)
    }

    fn record(&mut self, op: &Op, durable: bool) -> Result<()> {
        let mut line = op.encode().into_bytes();
        line.push(b'\n');
        self.journal.write_all(&line).map_err(|e| Error::io("cannot write journal", e))?;
        if durable {
            self.journal.sync_data().map_err(|e| Error::io("cannot sync journal", e))?;
        }
        Ok(())
    }

    fn check(&self, p: &Path) -> Result<()> {
        if !p.starts_with(&self.root) {
            return Err(Error::UnsafeArchive(format!("refusing to touch {} outside the root", p.display())));
        }
        Ok(())
    }

    pub fn path_exists(p: &Path) -> bool {
        std::fs::symlink_metadata(p).is_ok()
    }

    /// Create `path` (and missing parents) as directories; created ones are
    /// journaled so they are removed again on rollback.
    pub fn mkdir_all(&mut self, path: &Path, mode: u32) -> Result<()> {
        self.check(path)?;
        let mut missing = Vec::new();
        let mut cur = path.to_path_buf();
        while !Self::path_exists(&cur) {
            missing.push(cur.clone());
            match cur.parent() {
                Some(p) if p.starts_with(&self.root) => cur = p.to_path_buf(),
                _ => break,
            }
        }
        for d in missing.into_iter().rev() {
            self.record(&Op::Mkdir { path: d.clone() }, false)?;
            std::fs::create_dir(&d).ctx("cannot create directory", &d)?;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).ctx("cannot chmod", &d)?;
        }
        Ok(())
    }

    /// Move an existing file/symlink out of the way (kept until commit).
    pub fn backup_and_remove(&mut self, path: &Path) -> Result<()> {
        self.check(path)?;
        if !Self::path_exists(path) {
            return Ok(());
        }
        self.seq += 1;
        let name = format!("{:08}", self.seq);
        // Journal first (durably): after a crash the entry restores the file.
        self.record(&Op::Backup { path: path.to_path_buf(), backup: name.clone() }, true)?;
        move_path(path, &self.backups.join(&name))
    }

    /// Create a new regular file from `src`; any existing file must have been
    /// moved away with `backup_and_remove` first.
    pub fn create_file(&mut self, path: &Path, mode: u32, src: &mut impl Read) -> Result<()> {
        self.check(path)?;
        self.record(&Op::Created { path: path.to_path_buf() }, false)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .ctx("cannot create", path)?;
        std::io::copy(src, &mut f).ctx("cannot write", path)?;
        f.set_permissions(std::fs::Permissions::from_mode(mode)).ctx("cannot chmod", path)?;
        f.sync_data().ctx("cannot sync", path)?;
        Ok(())
    }

    pub fn create_symlink(&mut self, path: &Path, target: &str) -> Result<()> {
        self.check(path)?;
        self.record(&Op::Created { path: path.to_path_buf() }, false)?;
        std::os::unix::fs::symlink(target, path).ctx("cannot create symlink", path)
    }

    /// Remove an empty directory; silently keeps it if it is not empty.
    pub fn rmdir_if_empty(&mut self, path: &Path) -> Result<bool> {
        self.check(path)?;
        let md = match std::fs::symlink_metadata(path) {
            Ok(m) if m.is_dir() => m,
            _ => return Ok(false),
        };
        let mode = md.permissions().mode() & 0o7777;
        let empty = std::fs::read_dir(path).map(|mut rd| rd.next().is_none()).unwrap_or(false);
        if !empty {
            return Ok(false);
        }
        self.record(&Op::Rmdir { path: path.to_path_buf(), mode }, true)?;
        match std::fs::remove_dir(path) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false), // not empty after all; rollback's mkdir tolerates existing dirs
        }
    }

    pub fn sync(&mut self) -> Result<()> {
        self.journal.sync_data().map_err(|e| Error::io("cannot sync journal", e))
    }

    /// Make the transaction permanent: drop backups and the journal.
    pub fn commit(mut self) -> Result<()> {
        self.sync()?;
        let dir = self.dir.clone();
        drop(self);
        std::fs::remove_dir_all(&dir).ctx("cannot remove journal", &dir)
    }

    /// Undo everything done so far.
    pub fn rollback(self) -> Result<()> {
        let dir = self.dir.clone();
        drop(self);
        rollback_dir(&dir)
    }
}

fn rollback_dir(dir: &Path) -> Result<()> {
    let jp = dir.join("journal");
    let text = std::fs::read_to_string(&jp).ctx("cannot read journal", &jp)?;
    // Only complete lines count. A torn final line (power cut while writing it)
    // means that operation never started; it must not be half-applied.
    let ops: Vec<Op> = text
        .split_inclusive('\n')
        .filter_map(|l| l.strip_suffix('\n'))
        .filter_map(Op::decode)
        .collect();
    let backups = dir.join("backup");
    let mut errors = Vec::new();
    for op in ops.into_iter().rev() {
        let r: Result<()> = match &op {
            Op::Created { path } => match std::fs::symlink_metadata(path) {
                Ok(m) if m.is_dir() => Ok(()),
                Ok(_) => std::fs::remove_file(path).ctx("rollback: cannot remove", path),
                Err(_) => Ok(()),
            },
            Op::Mkdir { path } => {
                let _ = std::fs::remove_dir(path); // leaves non-empty dirs alone
                Ok(())
            }
            Op::Backup { path, backup } => {
                let b = backups.join(backup);
                if std::fs::symlink_metadata(&b).is_ok() {
                    if std::fs::symlink_metadata(path).is_ok() {
                        let _ = std::fs::remove_file(path);
                    }
                    move_path(&b, path)
                } else {
                    Ok(()) // journaled but the move never happened
                }
            }
            Op::Rmdir { path, mode } => {
                if std::fs::symlink_metadata(path).is_err() {
                    std::fs::create_dir(path)
                        .and_then(|_| std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode)))
                        .ctx("rollback: cannot recreate", path)
                } else {
                    Ok(())
                }
            }
        };
        if let Err(e) = r {
            errors.push(e.to_string());
        }
    }
    if !errors.is_empty() {
        // Keep the journal and backups for manual inspection.
        return Err(Error::Other(format!(
            "rollback incomplete, journal kept in {}:\n  {}",
            dir.display(),
            errors.join("\n  ")
        )));
    }
    std::fs::remove_dir_all(dir).ctx("cannot remove journal", dir)
}

/// Rename, falling back to copy+delete across filesystems.
fn move_path(src: &Path, dst: &Path) -> Result<()> {
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            let md = std::fs::symlink_metadata(src).ctx("cannot stat", src)?;
            if md.file_type().is_symlink() {
                let t = std::fs::read_link(src).ctx("cannot read link", src)?;
                std::os::unix::fs::symlink(t, dst).ctx("cannot create symlink", dst)?;
            } else {
                std::fs::copy(src, dst).ctx("cannot copy", src)?;
            }
            std::fs::remove_file(src).ctx("cannot remove", src)
        }
        Err(e) => Err(Error::io(format!("cannot move {} to {}", src.display(), dst.display()), e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Paths) {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::new(d.path());
        std::fs::create_dir_all(d.path().join("var/lib/ast")).unwrap();
        (d, paths)
    }

    #[test]
    fn rollback_restores_everything() {
        let (d, paths) = setup();
        let root = d.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/old.conf"), "original").unwrap();
        std::os::unix::fs::symlink("old.conf", root.join("etc/link")).unwrap();
        std::fs::create_dir_all(root.join("var/gone")).unwrap();

        let mut t = Txn::begin(&paths).unwrap();
        t.backup_and_remove(&root.join("etc/old.conf")).unwrap();
        t.create_file(&root.join("etc/old.conf"), 0o644, &mut &b"new"[..]).unwrap();
        t.backup_and_remove(&root.join("etc/link")).unwrap();
        t.mkdir_all(&root.join("usr/share/x"), 0o755).unwrap();
        t.create_file(&root.join("usr/share/x/f"), 0o644, &mut &b"data"[..]).unwrap();
        t.create_symlink(&root.join("usr/share/x/l"), "f").unwrap();
        assert!(t.rmdir_if_empty(&root.join("var/gone")).unwrap());
        assert_eq!(std::fs::read_to_string(root.join("etc/old.conf")).unwrap(), "new");
        t.rollback().unwrap();

        assert_eq!(std::fs::read_to_string(root.join("etc/old.conf")).unwrap(), "original");
        assert_eq!(std::fs::read_link(root.join("etc/link")).unwrap().to_str(), Some("old.conf"));
        assert!(!root.join("usr").exists());
        assert!(root.join("var/gone").is_dir());
        assert!(!paths.journal.exists());
    }

    #[test]
    fn commit_keeps_changes_and_drops_journal() {
        let (d, paths) = setup();
        let mut t = Txn::begin(&paths).unwrap();
        t.mkdir_all(&d.path().join("usr/bin"), 0o755).unwrap();
        t.create_file(&d.path().join("usr/bin/x"), 0o755, &mut &b"x"[..]).unwrap();
        t.commit().unwrap();
        assert!(d.path().join("usr/bin/x").exists());
        assert!(!paths.journal.exists());
    }

    #[test]
    fn crashed_transaction_is_recovered() {
        let (d, paths) = setup();
        std::fs::write(d.path().join("keep"), "orig").unwrap();
        let mut t = Txn::begin(&paths).unwrap();
        t.backup_and_remove(&d.path().join("keep")).unwrap();
        t.create_file(&d.path().join("keep"), 0o644, &mut &b"half"[..]).unwrap();
        t.create_file(&d.path().join("extra"), 0o644, &mut &b"x"[..]).unwrap();
        std::mem::forget(t); // simulate a crash: no commit, no rollback
        assert!(Txn::begin(&paths).is_err());
        assert!(Txn::recover(&paths).unwrap());
        assert_eq!(std::fs::read_to_string(d.path().join("keep")).unwrap(), "orig");
        assert!(!d.path().join("extra").exists());
        assert!(!Txn::recover(&paths).unwrap());
    }

    #[test]
    fn journal_lines_roundtrip_with_odd_paths() {
        for op in [
            Op::Created { path: PathBuf::from("/a b/c\td\ne\\f") },
            Op::Backup { path: PathBuf::from("/x"), backup: "00000001".into() },
            Op::Mkdir { path: PathBuf::from("/m") },
            Op::Rmdir { path: PathBuf::from("/r"), mode: 0o755 },
        ] {
            let line = op.encode();
            assert!(!line.contains('\n'));
            assert_eq!(Op::decode(&line), Some(op));
        }
        assert_eq!(Op::decode("garbage"), None);
        assert_eq!(Op::decode("rmdir\tzz\t/r"), None);
    }

    #[test]
    fn refuses_paths_outside_root() {
        let (_d, paths) = setup();
        let mut t = Txn::begin(&paths).unwrap();
        assert!(t.create_file(Path::new("/tmp/ast-escape-test"), 0o644, &mut &b"x"[..]).is_err());
        assert!(t.mkdir_all(Path::new("/tmp/ast-escape-dir"), 0o755).is_err());
        t.rollback().unwrap();
    }

    #[test]
    fn torn_journal_line_is_tolerated() {
        let (d, paths) = setup();
        let mut t = Txn::begin(&paths).unwrap();
        t.create_file(&d.path().join("f"), 0o644, &mut &b"x"[..]).unwrap();
        std::mem::forget(t);
        let jp = paths.journal.join("journal");
        // a torn last line names a path that must NOT be touched
        let victim = d.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let mut f = OpenOptions::new().append(true).open(&jp).unwrap();
        write!(f, "created\t{}", victim.display()).unwrap();
        assert!(Txn::recover(&paths).unwrap());
        assert!(!d.path().join("f").exists());
        assert!(victim.exists());
    }
}

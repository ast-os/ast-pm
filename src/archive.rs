//! Safe handling of untrusted tar payloads.
//!
//! Unpacking is split in two passes. `scan` reads the whole stream without
//! touching the disk, rejects anything unsafe and returns a manifest of
//! entries (with SHA-256 for regular files). Only then does the installer
//! write files, using the manifest (never the raw archive paths).
//!
//! Rules: only regular files, directories and symlinks are accepted; paths
//! must be relative and free of `..`; hard links, devices, fifos and the like
//! are refused; setuid/setgid/sticky bits are dropped; no entry may live
//! below a symlink created by the same archive.

use crate::error::{Error, Result};
use crate::security::sha256_reader;
use std::collections::HashSet;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    File { size: u64, sha256: String },
    Symlink { target: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Normalized relative path, no leading slash, no `..`.
    pub path: String,
    pub kind: EntryKind,
    /// Permission bits with setuid/setgid/sticky removed.
    pub mode: u32,
}

/// Normalize a relative path: drop `.` components, reject absolute paths,
/// `..`, empty paths, NUL bytes and non-UTF-8.
pub fn normalize_rel(p: &str) -> Result<String> {
    if p.contains('\0') {
        return Err(Error::UnsafeArchive(format!("path {p:?} contains a NUL byte")));
    }
    let path = Path::new(p);
    let mut parts: Vec<String> = Vec::new();
    for c in path.components() {
        match c {
            Component::Normal(s) => parts.push(
                s.to_str().ok_or_else(|| Error::UnsafeArchive(format!("path {p:?} is not valid UTF-8")))?.to_string(),
            ),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(Error::UnsafeArchive(format!("path {p:?} contains '..' (path traversal)")));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(Error::UnsafeArchive(format!("path {p:?} is absolute")));
            }
        }
    }
    if parts.is_empty() {
        return Err(Error::UnsafeArchive(format!("path {p:?} is empty")));
    }
    Ok(parts.join("/"))
}

/// Read a tar stream and produce a verified manifest without writing anything.
pub fn scan(reader: impl Read, setuid: &HashSet<String>) -> Result<Vec<Entry>> {
    let mut ar = tar::Archive::new(reader);
    let mut out: Vec<Entry> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut symlinks: HashSet<String> = HashSet::new();
    let entries = ar.entries().map_err(|e| Error::UnsafeArchive(format!("cannot read archive: {e}")))?;
    for e in entries {
        let mut e = e.map_err(|err| Error::UnsafeArchive(format!("corrupted archive: {err}")))?;
        let raw = e.path().map_err(|err| Error::UnsafeArchive(format!("bad entry path: {err}")))?;
        let raw = raw.to_str().ok_or_else(|| Error::UnsafeArchive("entry path is not valid UTF-8".into()))?.to_string();
        let t = e.header().entry_type();
        // The tar crate may hand us the root "./" entry; ignore it.
        if raw == "./" || raw == "." {
            continue;
        }
        let path = normalize_rel(&raw)?;
        // Some writers leave the mode field empty for symlinks; modes of
        // symlinks are ignored anyway.
        let raw_mode = e.header().mode().unwrap_or(0o644);
        let mut mode = raw_mode & 0o777;
        // Nothing may live below a symlink from the same archive.
        let mut anc = String::new();
        let comps: Vec<&str> = path.split('/').collect();
        for c in &comps[..comps.len() - 1] {
            if !anc.is_empty() {
                anc.push('/');
            }
            anc.push_str(c);
            if symlinks.contains(&anc) {
                return Err(Error::UnsafeArchive(format!("{path}: lies below symlink {anc} from the same package")));
            }
        }
        if !seen.insert(path.clone()) {
            return Err(Error::UnsafeArchive(format!("duplicate entry {path}")));
        }
        let kind = match t {
            tar::EntryType::Directory => {
                mode |= raw_mode & 0o1000; // sticky directories (/tmp) are safe and needed
                EntryKind::Dir
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                // setuid only for files the package metadata names explicitly
                if raw_mode & 0o4000 != 0 && setuid.contains(&format!("/{path}")) {
                    mode |= 0o4000;
                }
                let size = e.header().size().map_err(|err| Error::UnsafeArchive(format!("{path}: {err}")))?;
                let h = sha256_reader(&mut e).map_err(|err| Error::UnsafeArchive(format!("{path}: {err}")))?;
                EntryKind::File { size, sha256: h }
            }
            tar::EntryType::Symlink => {
                let target = e
                    .link_name()
                    .map_err(|err| Error::UnsafeArchive(format!("{path}: bad link: {err}")))?
                    .ok_or_else(|| Error::UnsafeArchive(format!("{path}: symlink without target")))?;
                let target = target
                    .to_str()
                    .ok_or_else(|| Error::UnsafeArchive(format!("{path}: link target is not valid UTF-8")))?
                    .to_string();
                if target.is_empty() || target.contains('\0') {
                    return Err(Error::UnsafeArchive(format!("{path}: invalid symlink target")));
                }
                symlinks.insert(path.clone());
                EntryKind::Symlink { target }
            }
            tar::EntryType::XGlobalHeader | tar::EntryType::XHeader => continue,
            tar::EntryType::Link => {
                return Err(Error::UnsafeArchive(format!("{path}: hard links are not allowed")));
            }
            other => {
                return Err(Error::UnsafeArchive(format!(
                    "{path}: unsupported entry type {other:?} (devices, fifos and sockets are not allowed)"
                )));
            }
        };
        out.push(Entry { path, kind, mode });
    }
    Ok(out)
}

/// Resolve `rel` below `root`, following existing symlinks as a chroot
/// would (absolute targets are interpreted relative to `root`). Fails if the
/// walk would leave `root` or loop. The final component is not followed, so
/// the returned path names the entry itself.
pub fn resolve_in_root(root: &Path, rel: &str) -> Result<PathBuf> {
    resolve_inner(root, rel, false)
}

/// Like `resolve_in_root`, but also follows a symlink in the final component.
pub fn resolve_following(root: &Path, rel: &str) -> Result<PathBuf> {
    resolve_inner(root, rel, true)
}

/// Is `rel` a directory when symlinks are resolved inside `root`?
pub fn is_dir_in_root(root: &Path, rel: &str) -> bool {
    resolve_following(root, rel)
        .ok()
        .and_then(|p| std::fs::symlink_metadata(p).ok())
        .map(|m| m.is_dir())
        .unwrap_or(false)
}

fn resolve_inner(root: &Path, rel: &str, follow_last: bool) -> Result<PathBuf> {
    let mut stack: Vec<String> = Vec::new(); // components below root
    let mut todo: Vec<String> = rel.split('/').filter(|s| !s.is_empty()).map(String::from).rev().collect();
    let mut hops = 0;
    while let Some(c) = todo.pop() {
        match c.as_str() {
            "." => continue,
            ".." => {
                if stack.pop().is_none() {
                    return Err(Error::UnsafeArchive(format!("{rel}: escapes the target root")));
                }
                continue;
            }
            _ => {}
        }
        let is_last = todo.is_empty();
        let candidate = {
            let mut p = root.to_path_buf();
            p.extend(stack.iter());
            p.push(&c);
            p
        };
        match std::fs::symlink_metadata(&candidate) {
            Ok(md) if md.file_type().is_symlink() && (!is_last || follow_last) => {
                hops += 1;
                if hops > 40 {
                    return Err(Error::UnsafeArchive(format!("{rel}: too many symlink levels")));
                }
                let target = std::fs::read_link(&candidate)
                    .map_err(|e| Error::io(format!("cannot read link {}", candidate.display()), e))?;
                let t = target.to_string_lossy().into_owned();
                if t.starts_with('/') {
                    stack.clear();
                }
                for part in t.split('/').filter(|s| !s.is_empty()).rev() {
                    todo.push(part.to_string());
                }
            }
            _ => stack.push(c),
        }
    }
    let mut p = root.to_path_buf();
    p.extend(stack.iter());
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tar(f: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        f(&mut b);
        b.into_inner().unwrap()
    }

    fn file_entry(b: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        // set_path rejects '..' so write the raw name bytes ourselves
        let name = path.as_bytes();
        h.as_old_mut().name[..name.len()].copy_from_slice(name);
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    #[test]
    fn accepts_normal_archive() {
        let t = build_tar(|b| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Directory);
            h.set_mode(0o755);
            h.set_size(0);
            b.append_data(&mut h, "usr/bin", std::io::empty()).unwrap();
            file_entry(b, "usr/bin/x", b"data");
            let mut l = tar::Header::new_gnu();
            l.set_entry_type(tar::EntryType::Symlink);
            l.set_size(0);
            b.append_link(&mut l, "usr/bin/y", "x").unwrap();
        });
        let m = scan(&t[..], &HashSet::new()).unwrap();
        assert_eq!(m.len(), 3);
        assert!(matches!(&m[1].kind, EntryKind::File { size: 4, .. }));
        assert!(matches!(&m[2].kind, EntryKind::Symlink { target } if target == "x"));
    }

    #[test]
    fn rejects_path_traversal() {
        let t = build_tar(|b| file_entry(b, "../evil", b"x"));
        assert!(matches!(scan(&t[..], &HashSet::new()), Err(Error::UnsafeArchive(_))));
        let t = build_tar(|b| file_entry(b, "usr/../../evil", b"x"));
        assert!(matches!(scan(&t[..], &HashSet::new()), Err(Error::UnsafeArchive(_))));
    }

    #[test]
    fn rejects_absolute_paths() {
        let t = build_tar(|b| file_entry(b, "/etc/passwd", b"x"));
        assert!(matches!(scan(&t[..], &HashSet::new()), Err(Error::UnsafeArchive(_))));
    }

    #[test]
    fn rejects_special_files_and_hardlinks() {
        for et in [tar::EntryType::Char, tar::EntryType::Block, tar::EntryType::Fifo, tar::EntryType::Link] {
            let t = build_tar(|b| {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(et);
                h.set_size(0);
                h.set_mode(0o644);
                if et == tar::EntryType::Link {
                    b.append_link(&mut h, "usr/dev", "usr/other").unwrap();
                } else {
                    b.append_data(&mut h, "usr/dev", std::io::empty()).unwrap();
                }
            });
            assert!(matches!(scan(&t[..], &HashSet::new()), Err(Error::UnsafeArchive(_))), "{et:?}");
        }
    }

    #[test]
    fn rejects_entry_below_archive_symlink() {
        let t = build_tar(|b| {
            let mut l = tar::Header::new_gnu();
            l.set_entry_type(tar::EntryType::Symlink);
            l.set_size(0);
            b.append_link(&mut l, "usr/lib", "/etc").unwrap();
            file_entry(b, "usr/lib/passwd", b"x");
        });
        assert!(matches!(scan(&t[..], &HashSet::new()), Err(Error::UnsafeArchive(_))));
    }

    #[test]
    fn rejects_duplicates_and_strips_special_bits() {
        let t = build_tar(|b| {
            file_entry(b, "a", b"1");
            file_entry(b, "a", b"2");
        });
        assert!(scan(&t[..], &HashSet::new()).is_err());
        let t = build_tar(|b| {
            let mut h = tar::Header::new_gnu();
            h.set_size(1);
            h.set_mode(0o4755);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, "su", &b"x"[..]).unwrap();
        });
        assert_eq!(scan(&t[..], &HashSet::new()).unwrap()[0].mode, 0o755);
        // ...unless the package metadata lists the file
        let listed: HashSet<String> = ["/su".to_string()].into();
        assert_eq!(scan(&t[..], &listed).unwrap()[0].mode, 0o4755);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(scan(&b"this is definitely not a tar archive at all, not even close.."[..], &HashSet::new()).is_err());
    }

    #[test]
    fn normalize_cases() {
        assert_eq!(normalize_rel("./usr//bin/x").unwrap(), "usr/bin/x");
        assert!(normalize_rel("").is_err());
        assert!(normalize_rel("..").is_err());
        assert!(normalize_rel("/x").is_err());
    }

    #[test]
    fn resolve_follows_root_relative_symlinks_and_blocks_escape() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::os::unix::fs::symlink("usr/lib", root.join("lib")).unwrap();
        std::os::unix::fs::symlink("/usr/lib", root.join("lib64")).unwrap();
        assert_eq!(resolve_in_root(root, "lib/x.so").unwrap(), root.join("usr/lib/x.so"));
        assert_eq!(resolve_in_root(root, "lib64/x.so").unwrap(), root.join("usr/lib/x.so"));
        // final component is not followed
        assert_eq!(resolve_in_root(root, "lib").unwrap(), root.join("lib"));
        std::os::unix::fs::symlink("../../../etc", root.join("usr/escape")).unwrap();
        assert!(resolve_in_root(root, "usr/escape/passwd").is_err());
        std::os::unix::fs::symlink("loop", root.join("loop")).unwrap();
        assert!(resolve_in_root(root, "loop/x").is_err());
    }
}

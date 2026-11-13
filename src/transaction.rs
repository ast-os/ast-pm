//! Installing and removing a single package inside a `Txn`.
//!
//! Installation: verify payload hash -> scan the whole archive (no writes) ->
//! check file ownership/conflicts -> write files through the journal ->
//! drop files of the old version that disappeared -> write the db record.
//! Anything that fails makes the caller roll the whole transaction back.

use crate::archive::{self, Entry, EntryKind, resolve_in_root};
use crate::db::{Db, FileKind, FileRecord, InstallOrigin, InstalledPackage, Reason, record_path};
use crate::error::{Error, Result};
use crate::openrc;
use crate::package::PackageFile;
use crate::security::{HashingReader, sha256_file};
use crate::txn::Txn;
use crate::util::{Paths, now, available_space};
use crate::version::PackageName;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct InstallOutcome {
    pub notice: Option<String>,
    pub services: Vec<String>,
    /// Config files kept as the user had them; the new default is `<path>.astnew`.
    pub new_config_files: Vec<String>,
}

#[derive(Debug, Default)]
pub struct RemoveOutcome {
    /// Modified config files that were left in place.
    pub kept_configs: Vec<String>,
    pub services: Vec<String>,
}

fn hash_if_regular(p: &Path) -> Option<String> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_file() => sha256_file(p).ok(),
        _ => None,
    }
}

fn target_path(paths: &Paths, rel: &str) -> Result<PathBuf> {
    resolve_in_root(&paths.root, rel)
}

fn parent_dir(paths: &Paths, rel: &str) -> Result<PathBuf> {
    match rel.rsplit_once('/') {
        Some((parent, _)) => target_path(paths, parent),
        None => Ok(paths.root.clone()),
    }
}

/// Install `pf` (already authenticated by the caller). `removing` lists
/// packages that are being removed earlier in the same transaction.
pub fn install_package(
    txn: &mut Txn,
    paths: &Paths,
    db: &Db,
    pf: &PackageFile,
    origin: InstallOrigin,
    reason: Reason,
    removing: &[PackageName],
    adopt: bool,
) -> Result<(InstalledPackage, InstallOutcome)> {
    let meta = &pf.meta;
    let name = &meta.name;
    pf.verify_payload()?;
    let setuid: HashSet<String> = meta.setuid.iter().cloned().collect();
    let manifest: Vec<Entry> = archive::scan(pf.payload_tar()?, &setuid)?;

    let config_set: HashSet<String> =
        meta.config_files.iter().map(|c| c.trim_start_matches('/').to_string()).collect();
    for c in &config_set {
        let in_payload = manifest.iter().any(|e| &e.path == c && matches!(e.kind, EntryKind::File { .. }));
        if !in_payload {
            return Err(Error::Parse(format!("{name}: config file /{c} is not a regular file in the payload")));
        }
    }

    let old = db.get(name);
    let owners = db.file_owners();
    let mut allowed: Vec<&PackageName> = removing.iter().collect();
    allowed.push(name);

    // ---- pass 1: conflicts, no writes
    let mut need = 0u64;
    for e in &manifest {
        let dest = target_path(paths, &e.path)?;
        let exists = Txn::path_exists(&dest);
        match &e.kind {
            EntryKind::Dir => {
                if exists && !archive::is_dir_in_root(&paths.root, &e.path) {
                    return Err(Error::Conflict(format!(
                        "{name}: cannot create directory /{}: a non-directory exists there",
                        e.path
                    )));
                }
            }
            kind => {
                if let EntryKind::File { size, .. } = kind {
                    need += size;
                }
                if let Some(owner) = owners.get(e.path.as_str()) {
                    if !allowed.contains(owner) {
                        return Err(Error::Conflict(format!(
                            "{name}: file /{} is already owned by package {owner}; add `replaces` to the package or remove {owner} first",
                            e.path
                        )));
                    }
                } else if exists && !adopt && !config_set.contains(&e.path) {
                    return Err(Error::Conflict(format!(
                        "{name}: /{} already exists and belongs to no package; refusing to overwrite it (move it away first)",
                        e.path
                    )));
                }
                if exists && std::fs::symlink_metadata(&dest).map(|m| m.is_dir()).unwrap_or(false) {
                    return Err(Error::Conflict(format!(
                        "{name}: cannot install /{}: a directory exists there",
                        e.path
                    )));
                }
            }
        }
    }
    if need > 0 {
        let free = available_space(&paths.root)?;
        if free < need {
            return Err(Error::Other(format!(
                "not enough disk space to install {name}: need {}, {} free",
                crate::util::human_size(need),
                crate::util::human_size(free)
            )));
        }
    }

    // ---- pass 2: write
    let mut outcome = InstallOutcome::default();
    let mut ar = tar::Archive::new(pf.payload_tar()?);
    let entries = ar.entries().map_err(|e| Error::UnsafeArchive(format!("cannot re-read archive: {e}")))?;
    let mut mi = manifest.iter();
    for ent in entries {
        let mut ent = ent.map_err(|e| Error::UnsafeArchive(format!("corrupted archive: {e}")))?;
        let t = ent.header().entry_type();
        if matches!(t, tar::EntryType::XGlobalHeader | tar::EntryType::XHeader) {
            continue;
        }
        let raw = ent.path().map_err(|e| Error::UnsafeArchive(e.to_string()))?.to_string_lossy().into_owned();
        if raw == "./" || raw == "." {
            continue;
        }
        let m = mi.next().ok_or_else(|| Error::UnsafeArchive("archive changed between verification and install".into()))?;
        if archive::normalize_rel(&raw)? != m.path {
            return Err(Error::UnsafeArchive("archive changed between verification and install".into()));
        }
        let dest = target_path(paths, &m.path)?;
        match &m.kind {
            EntryKind::Dir => {
                if !Txn::path_exists(&dest) {
                    txn.mkdir_all(&dest, m.mode)?;
                }
            }
            EntryKind::Symlink { target } => {
                txn.mkdir_all(&parent_dir(paths, &m.path)?, 0o755)?;
                txn.backup_and_remove(&dest)?;
                txn.create_symlink(&dest, target)?;
            }
            EntryKind::File { sha256, .. } => {
                txn.mkdir_all(&parent_dir(paths, &m.path)?, 0o755)?;
                let mut write_to = dest.clone();
                if config_set.contains(&m.path) && Txn::path_exists(&dest) {
                    let cur = hash_if_regular(&dest);
                    let recorded = old.and_then(|o| o.file(&m.path)).and_then(|f| f.sha256.clone());
                    let pristine = recorded.is_some() && cur == recorded;
                    if !pristine {
                        if cur.as_deref() == Some(sha256.as_str()) {
                            // user already has exactly the new default
                            io_skip(&mut ent)?;
                            continue;
                        }
                        write_to = PathBuf::from(format!("{}.astnew", dest.display()));
                        outcome.new_config_files.push(format!("/{}", m.path));
                    }
                }
                txn.backup_and_remove(&write_to)?;
                let mut hr = HashingReader::new(&mut ent);
                txn.create_file(&write_to, m.mode, &mut hr)?;
                let (h, _) = hr.finish();
                if &h != sha256 {
                    return Err(Error::UnsafeArchive(format!(
                        "/{}: content changed between verification and install",
                        m.path
                    )));
                }
            }
        }
    }
    if mi.next().is_some() {
        return Err(Error::UnsafeArchive("archive changed between verification and install".into()));
    }

    // ---- files of the previous version that are gone now
    let new_paths: HashSet<&str> = manifest.iter().map(|e| e.path.as_str()).collect();
    if let Some(o) = old {
        let mut gone_dirs = Vec::new();
        for f in &o.files {
            if new_paths.contains(f.path.as_str()) {
                continue;
            }
            if f.kind == FileKind::Dir {
                gone_dirs.push(f.path.clone());
                continue;
            }
            if !db.other_owners(&f.path, &allowed).is_empty() {
                continue;
            }
            let p = target_path(paths, &f.path)?;
            if f.config && hash_if_regular(&p) != f.sha256 {
                continue; // user-modified config of the old version stays
            }
            txn.backup_and_remove(&p)?;
        }
        gone_dirs.sort_by_key(|d| std::cmp::Reverse(d.len()));
        for d in gone_dirs {
            if db.other_owners(&d, &allowed).is_empty() {
                txn.rmdir_if_empty(&target_path(paths, &d)?)?;
            }
        }
    }

    // ---- db record
    let files: Vec<FileRecord> = manifest
        .iter()
        .map(|e| match &e.kind {
            EntryKind::Dir => FileRecord { path: e.path.clone(), kind: FileKind::Dir, sha256: None, target: None, mode: e.mode, config: false },
            EntryKind::File { sha256, .. } => FileRecord {
                path: e.path.clone(),
                kind: FileKind::File,
                sha256: Some(sha256.clone()),
                target: None,
                mode: e.mode,
                config: config_set.contains(&e.path),
            },
            EntryKind::Symlink { target } => FileRecord {
                path: e.path.clone(),
                kind: FileKind::Symlink,
                sha256: None,
                target: Some(target.clone()),
                mode: e.mode,
                config: false,
            },
        })
        .collect();
    let services = openrc::services_in(&files);
    let record = InstalledPackage {
        name: meta.name.clone(),
        version: meta.version.clone(),
        revision: meta.revision,
        arch: meta.arch.clone(),
        reason,
        installed_at: now(),
        description: meta.description.clone(),
        license: meta.license.clone(),
        depends: meta.depends.clone(),
        conflicts: meta.conflicts.clone(),
        replaces: meta.replaces.clone(),
        channel: meta.release.channel,
        status: meta.release.status,
        services: services.clone(),
        origin,
        files,
    };
    write_record(txn, paths, &record)?;
    outcome.notice = meta.notice.clone();
    outcome.services = services;
    Ok((record, outcome))
}

fn io_skip(ent: &mut impl std::io::Read) -> Result<()> {
    std::io::copy(ent, &mut std::io::sink()).map_err(|e| Error::io("cannot read archive entry", e))?;
    Ok(())
}

pub fn write_record(txn: &mut Txn, paths: &Paths, rec: &InstalledPackage) -> Result<()> {
    txn.mkdir_all(&paths.installed, 0o755)?;
    let p = record_path(paths, &rec.name);
    txn.backup_and_remove(&p)?;
    txn.create_file(&p, 0o644, &mut rec.to_toml()?.as_bytes())
}

/// Remove an installed package. Files also owned by another installed
/// package, and user-modified config files, are left in place.
pub fn remove_package(
    txn: &mut Txn,
    paths: &Paths,
    db: &Db,
    pkg: &InstalledPackage,
    also_removing: &[PackageName],
) -> Result<RemoveOutcome> {
    let mut except: Vec<&PackageName> = also_removing.iter().collect();
    except.push(&pkg.name);
    let mut out = RemoveOutcome { services: pkg.services.clone(), ..Default::default() };
    let mut dirs = Vec::new();
    for f in &pkg.files {
        if f.kind == FileKind::Dir {
            dirs.push(f.path.clone());
            continue;
        }
        if !db.other_owners(&f.path, &except).is_empty() {
            continue;
        }
        let p = target_path(paths, &f.path)?;
        if f.config && f.kind == FileKind::File {
            let cur = hash_if_regular(&p);
            if cur.is_some() && cur != f.sha256 {
                out.kept_configs.push(format!("/{}", f.path));
                continue;
            }
        }
        txn.backup_and_remove(&p)?;
    }
    dirs.sort_by_key(|d| std::cmp::Reverse(d.len()));
    for d in dirs {
        if db.other_owners(&d, &except).is_empty() {
            txn.rmdir_if_empty(&target_path(paths, &d)?)?;
        }
    }
    txn.backup_and_remove(&record_path(paths, &pkg.name))?;
    Ok(out)
}

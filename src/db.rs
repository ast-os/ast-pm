//! Installed-package database: `/var/lib/ast/db/installed/<name>.toml`.
//!
//! One small TOML file per package. Rationale: each file is replaced
//! atomically (write temp + fsync + rename), so a power cut never leaves a
//! half-written record; a damaged record affects one package only; and the
//! files are readable and repairable with a text editor. The transaction
//! journal (see `txn`) covers record writes together with the file changes
//! they describe. No embedded database engine is needed at this scale.

use crate::config::Channel;
use crate::error::{Error, IoCtx, Result};
use crate::package::Status;
use crate::util::Paths;
use crate::version::{Dependency, PackageName, Version};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reason {
    /// Requested by the user.
    Explicit,
    /// Pulled in as a runtime dependency.
    Dependency,
    /// Installed only to build another package.
    Build,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OriginKind {
    Binary,
    Source,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallOrigin {
    pub kind: OriginKind,
    pub repo: String,
    /// Artifact file name in the repository.
    pub file: String,
    /// SHA-256 of the package file (binary) or recipe (source).
    pub sha256: String,
    /// For source builds: SHA-256 of the upstream source archive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    #[default]
    File,
    Dir,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    /// Relative to the root, no leading slash.
    pub path: String,
    pub kind: FileKind,
    pub sha256: Option<String>,
    pub target: Option<String>,
    pub mode: u32,
    pub config: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPackage {
    pub name: PackageName,
    pub version: Version,
    pub revision: u32,
    pub arch: String,
    pub reason: Reason,
    pub installed_at: u64,
    pub description: String,
    pub license: String,
    pub depends: Vec<Dependency>,
    pub conflicts: Vec<Dependency>,
    pub replaces: Vec<PackageName>,
    pub channel: Option<Channel>,
    pub status: Option<Status>,
    /// orchid service names shipped by the package.
    pub services: Vec<String>,
    pub origin: InstallOrigin,
    pub files: Vec<FileRecord>,
}

/// File layout: `[package]`, `[origin]` and one `[files."PATH"]` table per file.
#[derive(Serialize, Deserialize)]
struct Raw {
    package: RawPackage,
    origin: InstallOrigin,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    files: BTreeMap<String, RawFile>,
}

#[derive(Serialize, Deserialize)]
struct RawPackage {
    name: PackageName,
    version: Version,
    #[serde(default = "one", skip_serializing_if = "is_one")]
    revision: u32,
    arch: String,
    reason: Reason,
    installed: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    license: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    depends: Vec<Dependency>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    conflicts: Vec<Dependency>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    replaces: Vec<PackageName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    channel: Option<Channel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<Status>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    services: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct RawFile {
    #[serde(default, skip_serializing_if = "is_file")]
    kind: FileKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(with = "octal")]
    mode: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    config: bool,
}

fn one() -> u32 {
    1
}
fn is_one(n: &u32) -> bool {
    *n == 1
}
fn is_false(b: &bool) -> bool {
    !*b
}
fn is_file(k: &FileKind) -> bool {
    *k == FileKind::File
}

/// Modes are written the way `ls` and `chmod` show them: `"0755"`.
mod octal {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(m: &u32, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{m:04o}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
        let t = String::deserialize(d)?;
        u32::from_str_radix(&t, 8).map_err(serde::de::Error::custom)
    }
}

impl InstalledPackage {
    pub fn file(&self, path: &str) -> Option<&FileRecord> {
        self.files.iter().find(|f| f.path == path)
    }

    pub fn full_version(&self) -> String {
        format!("{}-{}", self.version, self.revision)
    }

    pub fn parse(text: &str) -> Result<InstalledPackage> {
        let raw: Raw = toml::from_str(text).map_err(|e| Error::Parse(e.to_string()))?;
        let p = raw.package;
        Ok(InstalledPackage {
            name: p.name,
            version: p.version,
            revision: p.revision,
            arch: p.arch,
            reason: p.reason,
            installed_at: p.installed,
            description: p.description,
            license: p.license,
            depends: p.depends,
            conflicts: p.conflicts,
            replaces: p.replaces,
            channel: p.channel,
            status: p.status,
            services: p.services,
            origin: raw.origin,
            files: raw
                .files
                .into_iter()
                .map(|(path, f)| FileRecord { path, kind: f.kind, sha256: f.sha256, target: f.target, mode: f.mode, config: f.config })
                .collect(),
        })
    }

    pub fn to_toml(&self) -> Result<String> {
        let raw = Raw {
            package: RawPackage {
                name: self.name.clone(),
                version: self.version.clone(),
                revision: self.revision,
                arch: self.arch.clone(),
                reason: self.reason,
                installed: self.installed_at,
                description: self.description.clone(),
                license: self.license.clone(),
                depends: self.depends.clone(),
                conflicts: self.conflicts.clone(),
                replaces: self.replaces.clone(),
                channel: self.channel,
                status: self.status,
                services: self.services.clone(),
            },
            origin: self.origin.clone(),
            files: self
                .files
                .iter()
                .map(|f| {
                    (
                        f.path.clone(),
                        RawFile { kind: f.kind, sha256: f.sha256.clone(), target: f.target.clone(), mode: f.mode, config: f.config },
                    )
                })
                .collect(),
        };
        toml::to_string_pretty(&raw).map_err(|e| Error::Other(format!("cannot serialize db record: {e}")))
    }
}

/// In-memory view of the whole database.
#[derive(Debug, Default, Clone)]
pub struct Db {
    pub packages: BTreeMap<PackageName, InstalledPackage>,
}

pub fn record_path(paths: &Paths, name: &PackageName) -> std::path::PathBuf {
    paths.installed.join(format!("{name}.toml"))
}

impl Db {
    pub fn load(paths: &Paths) -> Result<Db> {
        let mut db = Db::default();
        let rd = match std::fs::read_dir(&paths.installed) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(db),
            Err(e) => return Err(Error::io(format!("cannot read {}", paths.installed.display()), e)),
        };
        for ent in rd {
            let ent = ent.ctx("cannot read", &paths.installed)?;
            let p = ent.path();
            let fname = ent.file_name().to_string_lossy().into_owned();
            if fname.starts_with('.') || !fname.ends_with(".toml") {
                continue; // temp files from interrupted atomic writes
            }
            let text = std::fs::read_to_string(&p).ctx("cannot read", &p)?;
            let pkg = InstalledPackage::parse(&text)
                .map_err(|e| Error::Parse(format!("database record {}: {e}", p.display())))?;
            if format!("{}.toml", pkg.name) != fname {
                return Err(Error::Parse(format!("database record {} names package {}", p.display(), pkg.name)));
            }
            db.packages.insert(pkg.name.clone(), pkg);
        }
        Ok(db)
    }

    pub fn get(&self, name: &PackageName) -> Option<&InstalledPackage> {
        self.packages.get(name)
    }

    /// Map of non-directory path -> owning package.
    pub fn file_owners(&self) -> HashMap<&str, &PackageName> {
        let mut m = HashMap::new();
        for p in self.packages.values() {
            for f in &p.files {
                if f.kind != FileKind::Dir {
                    m.insert(f.path.as_str(), &p.name);
                }
            }
        }
        m
    }

    /// Packages (other than `except`) that list `path` of any kind.
    pub fn other_owners<'a>(&'a self, path: &str, except: &[&PackageName]) -> Vec<&'a PackageName> {
        self.packages
            .values()
            .filter(|p| !except.contains(&&p.name) && p.files.iter().any(|f| f.path == path))
            .map(|p| &p.name)
            .collect()
    }

    /// Installed packages whose `depends` mention `name`.
    pub fn dependents_of(&self, name: &PackageName) -> Vec<&InstalledPackage> {
        self.packages.values().filter(|p| p.depends.iter().any(|d| &d.name == name)).collect()
    }

    pub fn insert(&mut self, p: InstalledPackage) {
        self.packages.insert(p.name.clone(), p);
    }

    pub fn remove(&mut self, name: &PackageName) {
        self.packages.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample(name: &str) -> InstalledPackage {
        InstalledPackage {
            name: PackageName::new(name).unwrap(),
            version: Version::new("1.0").unwrap(),
            revision: 1,
            arch: "x86_64".into(),
            reason: Reason::Explicit,
            installed_at: 1,
            description: "d".into(),
            license: "MIT".into(),
            depends: vec![Dependency::parse("zlib >= 1").unwrap()],
            conflicts: vec![],
            replaces: vec![],
            channel: Some(Channel::Stable),
            status: None,
            services: vec![],
            origin: InstallOrigin {
                kind: OriginKind::Binary,
                repo: "ast".into(),
                file: "x.ast".into(),
                sha256: "0".repeat(64),
                source_sha256: None,
            },
            files: vec![
                FileRecord { path: "usr/bin".into(), kind: FileKind::Dir, sha256: None, target: None, mode: 0o755, config: false },
                FileRecord { path: "usr/bin/x".into(), kind: FileKind::File, sha256: Some("a".repeat(64)), target: None, mode: 0o755, config: false },
                FileRecord { path: "usr/bin/y".into(), kind: FileKind::Symlink, sha256: None, target: Some("x".into()), mode: 0o777, config: false },
            ],
        }
    }

    #[test]
    fn record_roundtrip_and_load() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::new(d.path());
        std::fs::create_dir_all(&paths.installed).unwrap();
        let p = sample("foo");
        std::fs::write(record_path(&paths, &p.name), p.to_toml().unwrap()).unwrap();
        std::fs::write(paths.installed.join(".junk.tmp1"), "garbage").unwrap();
        let db = Db::load(&paths).unwrap();
        assert_eq!(db.get(&p.name), Some(&p));
        assert_eq!(db.dependents_of(&PackageName::new("zlib").unwrap()).len(), 1);
        assert_eq!(db.file_owners().get("usr/bin/x").map(|n| n.as_str()), Some("foo"));
        assert!(!db.file_owners().contains_key("usr/bin"));
    }

    #[test]
    fn missing_db_is_empty_and_bad_record_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::new(d.path());
        assert!(Db::load(&paths).unwrap().packages.is_empty());
        std::fs::create_dir_all(&paths.installed).unwrap();
        std::fs::write(paths.installed.join("bad.toml"), "name = ").unwrap();
        assert!(Db::load(&paths).is_err());
        std::fs::write(paths.installed.join("bad.toml"), sample("other").to_toml().unwrap()).unwrap();
        assert!(Db::load(&paths).is_err());
    }
}

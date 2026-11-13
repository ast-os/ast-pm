//! Repository index: `index.toml` and its detached signature `index.toml.sig`.
//!
//! `[metadata]` names the repository; every package version is a table
//! `[NAME."VERSION-REV"]`. The files are found by name:
//! `NAME-VERSION-REL.ast` (binary) and `NAME-VERSION-REL.recipe.toml` (recipe);
//! the index only records their SHA-256. The signature covers the exact bytes served.

use crate::config::Channel;
use crate::error::{Error, Result};
use crate::package::Status;
use crate::security::is_hex_sha256;
use crate::version::{Dependency, PackageName, Version};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;

/// A file of a repository and the checksum the index promises for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub file: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub name: PackageName,
    pub version: Version,
    pub revision: u32,
    pub arch: String,
    pub description: String,
    pub license: String,
    pub depends: Vec<Dependency>,
    /// Only meaningful for entries that have a `recipe`.
    pub build_depends: Vec<Dependency>,
    pub conflicts: Vec<Dependency>,
    pub replaces: Vec<PackageName>,
    /// Absent for ordinary packages.
    pub status: Option<Status>,
    /// SHA-256 of `NAME-VERSION-REV.ast`.
    pub binary: Option<String>,
    /// SHA-256 of `NAME-VERSION-REV.recipe.toml`.
    pub recipe: Option<String>,
}

/// What `index.toml` stores per package version, under `[NAME."VERSION-REV"]`.
#[derive(Serialize, Deserialize)]
struct Body {
    arch: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    license: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    depends: Vec<Dependency>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    build_depends: Vec<Dependency>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    conflicts: Vec<Dependency>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    replaces: Vec<PackageName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<Status>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipe: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    repo: String,
    arch: String,
    channel: Channel,
}

#[derive(Serialize, Deserialize)]
struct File {
    metadata: Metadata,
    #[serde(flatten)]
    packages: BTreeMap<PackageName, BTreeMap<String, Body>>,
}

pub fn binary_file_name(name: &PackageName, version: &Version, revision: u32) -> String {
    format!("{name}-{version}-{revision}.ast")
}

pub fn recipe_file_name(name: &PackageName, version: &Version, revision: u32) -> String {
    format!("{name}-{version}-{revision}.recipe.toml")
}

impl IndexEntry {
    pub fn binary_artifact(&self) -> Option<Artifact> {
        let sha256 = self.binary.clone()?;
        Some(Artifact { file: binary_file_name(&self.name, &self.version, self.revision), sha256 })
    }

    pub fn recipe_artifact(&self) -> Option<Artifact> {
        let sha256 = self.recipe.clone()?;
        Some(Artifact { file: recipe_file_name(&self.name, &self.version, self.revision), sha256 })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub repo: String,
    pub arch: String,
    pub channel: Channel,
    pub packages: Vec<IndexEntry>,
}

impl Index {
    pub fn parse(bytes: &[u8]) -> Result<Index> {
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Parse("index.toml is not UTF-8".into()))?;
        let file: File = toml::from_str(text).map_err(|e| Error::Parse(format!("index.toml: {e}")))?;
        let mut packages = Vec::new();
        for (name, versions) in file.packages {
            for (key, b) in versions {
                let (version, revision) = key
                    .rsplit_once('-')
                    .and_then(|(v, r)| Some((Version::new(v).ok()?, r.parse::<u32>().ok()?)))
                    .ok_or_else(|| Error::Parse(format!("index.toml: [{name}.\"{key}\"] is not VERSION-REVISION")))?;
                if b.binary.is_none() && b.recipe.is_none() {
                    return Err(Error::Parse(format!("index entry {name} {version} has neither binary nor recipe")));
                }
                for sha in [&b.binary, &b.recipe].into_iter().flatten() {
                    if !is_hex_sha256(sha) {
                        return Err(Error::Parse(format!("index entry {name}: {sha:?} is not a SHA-256")));
                    }
                }
                packages.push(IndexEntry {
                    name: name.clone(),
                    version,
                    revision,
                    arch: b.arch,
                    description: b.description,
                    license: b.license,
                    depends: b.depends,
                    build_depends: b.build_depends,
                    conflicts: b.conflicts,
                    replaces: b.replaces,
                    status: b.status,
                    binary: b.binary,
                    recipe: b.recipe,
                });
            }
        }
        Ok(Index { repo: file.metadata.repo, arch: file.metadata.arch, channel: file.metadata.channel, packages })
    }

    pub fn to_toml(&self) -> Result<Vec<u8>> {
        let mut packages: BTreeMap<PackageName, BTreeMap<String, Body>> = BTreeMap::new();
        for e in &self.packages {
            packages.entry(e.name.clone()).or_default().insert(
                format!("{}-{}", e.version, e.revision),
                Body {
                    arch: e.arch.clone(),
                    description: e.description.clone(),
                    license: e.license.clone(),
                    depends: e.depends.clone(),
                    build_depends: e.build_depends.clone(),
                    conflicts: e.conflicts.clone(),
                    replaces: e.replaces.clone(),
                    status: e.status,
                    binary: e.binary.clone(),
                    recipe: e.recipe.clone(),
                },
            );
        }
        let file = File {
            metadata: Metadata { repo: self.repo.clone(), arch: self.arch.clone(), channel: self.channel },
            packages,
        };
        toml::to_string_pretty(&file)
            .map(String::into_bytes)
            .map_err(|e| Error::Other(format!("cannot serialize index: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, ver: &str) -> IndexEntry {
        IndexEntry {
            name: PackageName::new(name).unwrap(),
            version: Version::new(ver).unwrap(),
            revision: 1,
            arch: "x86_64".into(),
            description: String::new(),
            license: String::new(),
            depends: vec![],
            build_depends: vec![],
            conflicts: vec![],
            replaces: vec![],
            status: None,
            binary: Some("0".repeat(64)),
            recipe: None,
        }
    }

    #[test]
    fn roundtrip_validation_and_shape() {
        let idx = Index { repo: "t".into(), arch: "x86_64".into(), channel: Channel::Stable, packages: vec![entry("a", "1")] };
        let bytes = idx.to_toml().unwrap();
        assert_eq!(Index::parse(&bytes).unwrap(), idx);
        // nothing but what is set: no empty lists, no defaults
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("depends") && !text.contains("size"), "{text}");
        assert!(text.starts_with("[metadata]\n") && text.contains("[a.1-1]"), "{text}");
        let mut bad = idx.clone();
        bad.packages[0].binary = None;
        assert!(Index::parse(&bad.to_toml().unwrap()).is_err());
        let mut bad = idx.clone();
        bad.packages[0].binary = Some("xyz".into());
        assert!(Index::parse(&bad.to_toml().unwrap()).is_err());
        assert!(Index::parse(b"not = toml =").is_err());
        assert!(Index::parse(b"[metadata]\nrepo=\"r\"\narch=\"x86_64\"\nchannel=\"stable\"\n[a.\"nonsense\"]\narch=\"x86_64\"\n").is_err());
    }

    #[test]
    fn files_are_found_by_name() {
        let mut e = entry("nginx", "1.28.0");
        e.revision = 2;
        e.recipe = Some("1".repeat(64));
        assert_eq!(e.binary_artifact().unwrap().file, "nginx-1.28.0-2.ast");
        assert_eq!(e.recipe_artifact().unwrap().file, "nginx-1.28.0-2.recipe.toml");
    }
}

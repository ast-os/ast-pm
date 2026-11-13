//! Binary package container (`.ast`) and its metadata.
//!
//! Container layout (all integers little-endian):
//!
//! ```text
//! offset 0   9 bytes   magic "ASTERPKG" + format version byte (0x01)
//! offset 9   u32       length N of the metadata block (<= 1 MiB)
//! offset 13  N bytes   metadata.toml (UTF-8)
//! offset 13+N ...      payload: a Zstandard-compressed tar stream, to EOF
//! ```
//!
//! `metadata.toml` records the SHA-256 and length of the payload bytes, so
//! the payload can be verified (streaming, one pass) before anything is
//! unpacked. The whole file is additionally covered by the checksum in the
//! signed repository index and by a detached `.sig` signature.
//!
//! The container is deliberately *not* itself a zstd stream, which is why the
//! extension is `.ast` rather than `.pkg.zst`: the extension should say what
//! the format is, while zstd is only the payload compression.

use crate::config::Channel;
use crate::error::{Error, IoCtx, Result};
use crate::security::{HashingReader, check_sha256, is_hex_sha256};
use crate::version::{Dependency, PackageName, Version};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const MAGIC: &[u8; 9] = b"ASTERPKG\x01";
pub const MAX_METADATA: u32 = 1024 * 1024;
pub const PACKAGE_EXT: &str = "ast";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Tested,
    Untested,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Tested => "tested",
            Status::Untested => "untested",
        }
    }
}

/// `[release]` table. Both fields are optional; `status` is meaningful only
/// for system components and is never invented for ordinary packages.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<Channel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

impl Release {
    pub fn is_empty(&self) -> bool {
        self.channel.is_none() && self.status.is_none()
    }
}

impl Origin {
    pub fn is_empty(&self) -> bool {
        self == &Origin::default()
    }
}

impl Serialize for Channel {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// `[origin]` table: where the package came from and how it was built.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub built_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub name: PackageName,
    pub version: Version,
    pub revision: u32,
    /// `aarch64`, `x86_64`, or `any` for architecture-independent packages.
    pub arch: String,
    pub description: String,
    pub license: String,
    pub depends: Vec<Dependency>,
    pub conflicts: Vec<Dependency>,
    pub replaces: Vec<PackageName>,
    /// Absolute paths (inside the target root) that are user-editable config.
    pub config_files: Vec<String>,
    /// Absolute paths of files that may keep their setuid bit (sudo, login, ...).
    pub setuid: Vec<String>,
    /// Message shown after installation (kernel/bootloader/DT hints etc.).
    pub notice: Option<String>,
    pub release: Release,
    pub origin: Origin,
    pub payload_sha256: String,
}

fn one() -> u32 {
    1
}

fn is_one(n: &u32) -> bool {
    *n == 1
}

/// How the metadata is written: `[package]`, `[payload]`, `[release]`, `[origin]`.
#[derive(Serialize, Deserialize)]
struct Raw {
    package: RawPackage,
    #[serde(default, skip_serializing_if = "Payload::is_empty")]
    payload: Payload,
    #[serde(default, skip_serializing_if = "Release::is_empty")]
    release: Release,
    #[serde(default, skip_serializing_if = "Origin::is_empty")]
    origin: Origin,
}

#[derive(Serialize, Deserialize)]
struct RawPackage {
    name: PackageName,
    version: Version,
    #[serde(default = "one", skip_serializing_if = "is_one")]
    revision: u32,
    arch: String,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    config_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    setuid: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notice: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Payload {
    #[serde(default)]
    sha256: String,
}

impl Payload {
    fn is_empty(&self) -> bool {
        self.sha256.is_empty()
    }
}

pub fn arch_compatible(pkg_arch: &str, system_arch: &str) -> bool {
    pkg_arch == "any" || pkg_arch == system_arch
}

impl Metadata {
    pub fn parse(text: &str) -> Result<Metadata> {
        let raw: Raw = toml::from_str(text).map_err(|e| Error::Parse(format!("package metadata: {e}")))?;
        let p = raw.package;
        let m = Metadata {
            name: p.name,
            version: p.version,
            revision: p.revision,
            arch: p.arch,
            description: p.description,
            license: p.license,
            depends: p.depends,
            conflicts: p.conflicts,
            replaces: p.replaces,
            config_files: p.config_files,
            setuid: p.setuid,
            notice: p.notice,
            release: raw.release,
            origin: raw.origin,
            payload_sha256: raw.payload.sha256,
        };
        m.validate()?;
        Ok(m)
    }

    pub fn to_toml(&self) -> Result<String> {
        let raw = Raw {
            package: RawPackage {
                name: self.name.clone(),
                version: self.version.clone(),
                revision: self.revision,
                arch: self.arch.clone(),
                description: self.description.clone(),
                license: self.license.clone(),
                depends: self.depends.clone(),
                conflicts: self.conflicts.clone(),
                replaces: self.replaces.clone(),
                config_files: self.config_files.clone(),
                setuid: self.setuid.clone(),
                notice: self.notice.clone(),
            },
            payload: Payload { sha256: self.payload_sha256.clone() },
            release: self.release.clone(),
            origin: self.origin.clone(),
        };
        toml::to_string_pretty(&raw).map_err(|e| Error::Other(format!("cannot serialize metadata: {e}")))
    }

    pub fn validate(&self) -> Result<()> {
        let a = &self.arch;
        if a != "any" && !crate::config::KNOWN_ARCHES.contains(&a.as_str()) {
            return Err(Error::Parse(format!("{}: unknown architecture {a:?}", self.name)));
        }
        for (what, list) in [("config file", &self.config_files), ("setuid file", &self.setuid)] {
            for c in list {
                crate::archive::normalize_rel(c.trim_start_matches('/'))
                    .map_err(|_| Error::Parse(format!("{}: unsafe {what} path {c:?}", self.name)))?;
                if !c.starts_with('/') {
                    return Err(Error::Parse(format!("{}: {what} path {c:?} must be absolute", self.name)));
                }
            }
        }
        if !self.payload_sha256.is_empty() && !is_hex_sha256(&self.payload_sha256) {
            return Err(Error::Parse(format!("{}: payload_sha256 is not a SHA-256 hex digest", self.name)));
        }
        Ok(())
    }

    pub fn full_version(&self) -> String {
        format!("{}-{}", self.version, self.revision)
    }
}

/// An opened package container with parsed metadata. Nothing from the
/// payload has been trusted or unpacked yet.
#[derive(Debug)]
pub struct PackageFile {
    pub path: PathBuf,
    pub meta: Metadata,
    payload_offset: u64,
    payload_len: u64,
}

impl PackageFile {
    pub fn open(path: &Path) -> Result<PackageFile> {
        let mut f = File::open(path).ctx("cannot open package", path)?;
        let total = f.metadata().ctx("cannot stat", path)?.len();
        let mut magic = [0u8; 9];
        f.read_exact(&mut magic)
            .map_err(|_| Error::Parse(format!("{}: file too short to be a package", path.display())))?;
        if &magic != MAGIC {
            return Err(Error::Parse(format!("{}: not a ast package (bad magic)", path.display())));
        }
        let mut len = [0u8; 4];
        f.read_exact(&mut len).map_err(|_| Error::Parse(format!("{}: truncated header", path.display())))?;
        let n = u32::from_le_bytes(len);
        if n == 0 || n > MAX_METADATA || 13 + n as u64 > total {
            return Err(Error::Parse(format!("{}: invalid metadata length {n}", path.display())));
        }
        let mut buf = vec![0u8; n as usize];
        f.read_exact(&mut buf).map_err(|_| Error::Parse(format!("{}: truncated metadata", path.display())))?;
        let text = String::from_utf8(buf).map_err(|_| Error::Parse(format!("{}: metadata is not UTF-8", path.display())))?;
        let meta = Metadata::parse(&text)?;
        let payload_offset = 13 + n as u64;
        let payload_len = total - payload_offset;
        if meta.payload_sha256.is_empty() {
            return Err(Error::Parse(format!("{}: metadata has no payload_sha256", path.display())));
        }
        Ok(PackageFile { path: path.to_path_buf(), meta, payload_offset, payload_len })
    }

    fn raw_payload(&self) -> Result<std::io::Take<File>> {
        let mut f = File::open(&self.path).ctx("cannot open package", &self.path)?;
        f.seek(SeekFrom::Start(self.payload_offset)).ctx("cannot seek in", &self.path)?;
        Ok(f.take(self.payload_len))
    }

    /// Hash the payload bytes and compare with the metadata.
    pub fn verify_payload(&self) -> Result<()> {
        let mut r = HashingReader::new(self.raw_payload()?);
        std::io::copy(&mut r, &mut std::io::sink()).ctx("cannot read", &self.path)?;
        let (h, _) = r.finish();
        check_sha256(&format!("payload of {}", self.meta.name), &self.meta.payload_sha256, &h)
    }

    /// Decompressed tar stream. Call `verify_payload` first.
    pub fn payload_tar(&self) -> Result<impl Read> {
        zstd::Decoder::new(self.raw_payload()?).map_err(|e| Error::io("cannot start zstd decoder", e))
    }
}

/// Build a package from a staging directory. `meta` supplies everything
/// except the payload checksum, which is computed.
/// Returns the final metadata.
pub fn pack_directory(dir: &Path, meta: Metadata, out: &Path) -> Result<Metadata> {
    pack_with(meta, out, 19, |tb| add_dir_entries(tb, dir, Path::new("")))
}

pub type PayloadWriter = tar::Builder<zstd::Encoder<'static, File>>;

/// Build a package whose payload is written by `fill` into a zstd-compressed tar.
pub fn pack_with(mut meta: Metadata, out: &Path, level: i32, fill: impl FnOnce(&mut PayloadWriter) -> Result<()>) -> Result<Metadata> {
    let tmp = out.with_extension("payload.tmp");
    {
        let f = File::create(&tmp).ctx("cannot create", &tmp)?;
        let enc = zstd::Encoder::new(f, level).map_err(|e| Error::io("zstd init", e))?;
        let mut tb = tar::Builder::new(enc);
        tb.mode(tar::HeaderMode::Deterministic);
        fill(&mut tb)?;
        let enc = tb.into_inner().map_err(|e| Error::io("tar finish", e))?;
        let f = enc.finish().map_err(|e| Error::io("zstd finish", e))?;
        f.sync_all().ctx("cannot sync", &tmp)?;
    }
    let mut r = HashingReader::new(File::open(&tmp).ctx("cannot open", &tmp)?);
    std::io::copy(&mut r, &mut std::io::sink()).ctx("cannot read", &tmp)?;
    meta.payload_sha256 = r.finish().0;
    meta.validate()?;
    let text = meta.to_toml()?;
    if text.len() as u32 > MAX_METADATA {
        return Err(Error::Other("metadata too large".into()));
    }
    {
        let mut o = File::create(out).ctx("cannot create", out)?;
        o.write_all(MAGIC).ctx("cannot write", out)?;
        o.write_all(&(text.len() as u32).to_le_bytes()).ctx("cannot write", out)?;
        o.write_all(text.as_bytes()).ctx("cannot write", out)?;
        let mut p = File::open(&tmp).ctx("cannot open", &tmp)?;
        std::io::copy(&mut p, &mut o).ctx("cannot write", out)?;
        o.sync_all().ctx("cannot sync", out)?;
    }
    let _ = std::fs::remove_file(&tmp);
    Ok(meta)
}

fn add_dir_entries<W: Write>(tb: &mut tar::Builder<W>, base: &Path, rel: &Path) -> Result<()> {
    let here = base.join(rel);
    let mut names: Vec<_> = std::fs::read_dir(&here)
        .ctx("cannot read directory", &here)?
        .collect::<std::io::Result<Vec<_>>>()
        .ctx("cannot read directory", &here)?
        .into_iter()
        .map(|e| e.file_name())
        .collect();
    names.sort();
    for name in names {
        let rel_path = rel.join(&name);
        let full = base.join(&rel_path);
        let md = std::fs::symlink_metadata(&full).ctx("cannot stat", &full)?;
        let ft = md.file_type();
        if ft.is_dir() {
            tb.append_dir(&rel_path, &full).ctx("cannot archive", &full)?;
            add_dir_entries(tb, base, &rel_path)?;
        } else if ft.is_file() {
            let mut f = File::open(&full).ctx("cannot open", &full)?;
            tb.append_file(&rel_path, &mut f).ctx("cannot archive", &full)?;
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&full).ctx("cannot read link", &full)?;
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            tb.append_link(&mut h, &rel_path, &target).ctx("cannot archive", &full)?;
        } else {
            return Err(Error::Other(format!(
                "{}: special files (devices, fifos, sockets) cannot be packaged",
                full.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
pub fn test_meta(name: &str, version: &str) -> Metadata {
    Metadata {
        name: PackageName::new(name).unwrap(),
        version: Version::new(version).unwrap(),
        revision: 1,
        arch: "x86_64".into(),
        description: format!("test package {name}"),
        license: "MIT".into(),
        depends: vec![],
        conflicts: vec![],
        replaces: vec![],
        config_files: vec![],
        setuid: vec![],
        notice: None,
        release: Release::default(),
        origin: Origin::default(),
        payload_sha256: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pkg(dir: &Path, out: &Path) -> Metadata {
        std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
        std::fs::write(dir.join("usr/bin/hello"), b"#!/bin/sh\necho hi\n").unwrap();
        std::os::unix::fs::symlink("hello", dir.join("usr/bin/hi")).unwrap();
        pack_directory(dir, test_meta("hello", "1.0"), out).unwrap()
    }

    #[test]
    fn pack_and_open_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let stage = d.path().join("stage");
        let out = d.path().join("hello.ast");
        let m = make_pkg(&stage, &out);
        let p = PackageFile::open(&out).unwrap();
        assert_eq!(p.meta, m);
        p.verify_payload().unwrap();
        let mut names = vec![];
        let mut ar = tar::Archive::new(p.payload_tar().unwrap());
        for e in ar.entries().unwrap() {
            names.push(e.unwrap().path().unwrap().to_string_lossy().into_owned());
        }
        assert!(names.contains(&"usr/bin/hello".to_string()));
        assert!(names.contains(&"usr/bin/hi".to_string()));
    }

    #[test]
    fn packing_is_deterministic() {
        let d = tempfile::tempdir().unwrap();
        let stage = d.path().join("stage");
        let a = d.path().join("a.ast");
        let b = d.path().join("b.ast");
        make_pkg(&stage, &a);
        pack_directory(&stage, test_meta("hello", "1.0"), &b).unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    }

    #[test]
    fn corrupted_payload_is_detected() {
        let d = tempfile::tempdir().unwrap();
        let out = d.path().join("hello.ast");
        make_pkg(&d.path().join("stage"), &out);
        let mut bytes = std::fs::read(&out).unwrap();
        let last = bytes.len() - 5;
        bytes[last] ^= 0xff;
        std::fs::write(&out, &bytes).unwrap();
        let p = PackageFile::open(&out).unwrap();
        assert!(matches!(p.verify_payload(), Err(Error::Verify(_))));
    }

    #[test]
    fn truncated_and_garbage_files_are_rejected() {
        let d = tempfile::tempdir().unwrap();
        let out = d.path().join("hello.ast");
        make_pkg(&d.path().join("stage"), &out);
        let bytes = std::fs::read(&out).unwrap();
        let cut = d.path().join("cut.ast");
        std::fs::write(&cut, &bytes[..bytes.len() - 10]).unwrap();
        // a truncated payload no longer matches its checksum
        assert!(PackageFile::open(&cut).and_then(|p| p.verify_payload()).is_err());
        let junk = d.path().join("junk.ast");
        std::fs::write(&junk, b"hello world, not a package").unwrap();
        assert!(PackageFile::open(&junk).is_err());
        std::fs::write(&junk, b"").unwrap();
        assert!(PackageFile::open(&junk).is_err());
    }

    #[test]
    fn metadata_parsing_and_validation() {
        let text = r#"
[package]
name = "nginx"
version = "1.28.0"
arch = "aarch64"
depends = ["pcre2 >= 10.40", "zlib"]
conflicts = ["nginx-mainline"]
config_files = ["/etc/nginx/nginx.conf"]
[release]
channel = "edge"
status = "untested"
"#;
        let m = Metadata::parse(text).unwrap();
        assert_eq!(m.depends.len(), 2);
        assert_eq!(m.release.status, Some(Status::Untested));
        assert_eq!(m.release.channel, Some(Channel::Edge));
        let again = Metadata::parse(&m.to_toml().unwrap()).unwrap();
        assert_eq!(again, m);
        // no status field => no status invented
        let plain = Metadata::parse("[package]\nname=\"git\"\nversion=\"2\"\narch=\"any\"\n").unwrap();
        assert_eq!(plain.release.status, None);
        assert!(Metadata::parse("[package]\nname=\"../x\"\nversion=\"1\"\narch=\"any\"\n").is_err());
        assert!(Metadata::parse("[package]\nname=\"x\"\nversion=\"1\"\narch=\"sparc\"\n").is_err());
        assert!(Metadata::parse("[package]\nname=\"x\"\nversion=\"1\"\narch=\"any\"\nconfig_files=[\"etc/rel\"]\n").is_err());
        assert!(Metadata::parse("[package]\nname=\"x\"\nversion=\"1\"\narch=\"any\"\nconfig_files=[\"/etc/../x\"]\n").is_err());
        assert!(Metadata::parse("[package]\nname=\"x\"\nversion=\"1\"\narch=\"any\"\n[release]\nstatus=\"maybe\"\n").is_err());
    }
}

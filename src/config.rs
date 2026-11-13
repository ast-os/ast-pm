//! `ast.toml` and `repos.toml`: parsing, validation and in-place edits
//! (edits keep comments via `toml_edit`).

use crate::error::{Error, IoCtx, Result};
use crate::util::{Paths, atomic_write};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

pub const DEFAULT_AST_TOML: &str = include_str!("../examples/ast.toml");
pub const DEFAULT_REPOS_TOML: &str = include_str!("../examples/repos.toml");

pub const KNOWN_ARCHES: &[&str] = &["aarch64", "x86_64"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Stable,
    Edge,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::Edge => "edge",
        }
    }
    pub fn parse(s: &str) -> Result<Channel> {
        match s {
            "stable" => Ok(Channel::Stable),
            "edge" => Ok(Channel::Edge),
            o => Err(Error::Config(format!("unknown channel {o:?} (expected `stable` or `edge`)"))),
        }
    }
}
impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Core {
    pub architecture: String,
    #[serde(default = "default_channel")]
    pub channel: Channel,
}
fn default_channel() -> Channel {
    Channel::Stable
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PackagesCfg {
    pub allow_untested: bool,
    pub prefer_binary: bool,
    pub compression: String,
}
impl Default for PackagesCfg {
    fn default() -> Self {
        PackagesCfg { allow_untested: false, prefer_binary: false, compression: "zstd".into() }
    }
}

/// How build scripts are isolated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxMode {
    /// Run scripts inside bubblewrap; refuse to build if it is unavailable.
    Required,
    /// Use bubblewrap when present, otherwise warn and run unsandboxed.
    Auto,
    /// No isolation (debugging only).
    None,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BuildCfg {
    /// See `SandboxMode`. Default: required.
    pub sandbox: SandboxMode,
    pub enabled: bool,
    pub jobs: u32,
    pub directory: String,
    /// uid/gid the build script runs as when ast itself runs as root.
    pub uid: u32,
    pub gid: u32,
}
impl Default for BuildCfg {
    fn default() -> Self {
        BuildCfg { sandbox: SandboxMode::Required, enabled: true, jobs: 2, directory: "/var/cache/ast/build".into(), uid: 65534, gid: 65534 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityCfg {
    pub verify_signatures: bool,
    pub verify_checksums: bool,
}
impl Default for SecurityCfg {
    fn default() -> Self {
        SecurityCfg { verify_signatures: true, verify_checksums: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub core: Core,
    #[serde(default)]
    pub packages: PackagesCfg,
    #[serde(default)]
    pub build: BuildCfg,
    #[serde(default)]
    pub security: SecurityCfg,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config> {
        let c: Config = toml::from_str(text).map_err(|e| Error::Config(format!("ast.toml: {e}")))?;
        c.validate()?;
        Ok(c)
    }

    pub fn load(paths: &Paths) -> Result<Config> {
        let p = paths.ast_toml();
        let text = std::fs::read_to_string(&p).map_err(|e| {
            Error::Config(format!("cannot read {}: {e}", p.display()))
        })?;
        Config::parse(&text)
    }

    fn validate(&self) -> Result<()> {
        let a = &self.core.architecture;
        if !KNOWN_ARCHES.contains(&a.as_str()) {
            return Err(Error::Config(format!(
                "unsupported architecture {a:?} in [core] (supported: {})",
                KNOWN_ARCHES.join(", ")
            )));
        }
        if self.packages.compression != "zstd" {
            return Err(Error::Config(format!(
                "compression {:?} is not supported (only \"zstd\")",
                self.packages.compression
            )));
        }
        if self.build.jobs == 0 {
            return Err(Error::Config("[build] jobs must be at least 1".into()));
        }
        if !self.build.directory.starts_with('/') {
            return Err(Error::Config("[build] directory must be an absolute path".into()));
        }
        Ok(())
    }

    /// Build jobs: the requested value, never more than the CPU count or
    /// one job per 512 MiB of RAM, and at least 1.
    pub fn effective_jobs(&self, override_jobs: Option<u32>) -> u32 {
        let requested = override_jobs.unwrap_or(self.build.jobs).max(1);
        let cpus = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1);
        let by_mem = mem_total_mib().map(|m| (m / 512).max(1) as u32).unwrap_or(cpus);
        requested.min(cpus).min(by_mem).max(1)
    }

    pub fn build_dir(&self, paths: &Paths) -> PathBuf {
        paths.root.join(self.build.directory.trim_start_matches('/'))
    }
}

fn mem_total_mib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = s.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb / 1024)
}

// ------------------------------------------------------------- repos.toml

#[derive(Debug, Clone)]
pub struct Repo {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub priority: u32,
    /// Key file name inside /etc/ast/keys/.
    pub key: String,
    pub channel: Channel,
}

/// One `[NAME]` table of repos.toml.
#[derive(Debug, Deserialize)]
struct RepoBody {
    url: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_priority")]
    priority: u32,
    key: String,
    #[serde(default = "default_channel")]
    channel: Channel,
}
fn default_priority() -> u32 {
    100
}

#[derive(Debug, Clone)]
pub struct Repos(pub Vec<Repo>);

impl Repos {
    pub fn parse(text: &str) -> Result<Repos> {
        let tables: BTreeMap<String, RepoBody> =
            toml::from_str(text).map_err(|e| Error::Config(format!("repos.toml: {e}")))?;
        let mut repos = Vec::new();
        for (name, b) in tables {
            let name_ok = !name.is_empty()
                && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
            if !name_ok {
                return Err(Error::Config(format!(
                    "repos.toml: invalid repository name {name:?} (lowercase letters, digits, '-', '_')"
                )));
            }
            if b.key.is_empty() || b.key.contains('/') || b.key.contains("..") {
                return Err(Error::Config(format!(
                    "repos.toml: key {:?} of repository {name:?} must be a plain file name inside /etc/ast/keys/",
                    b.key
                )));
            }
            if b.url.is_empty() {
                return Err(Error::Config(format!("repos.toml: repository {name:?} has an empty url")));
            }
            repos.push(Repo { name, url: b.url, enabled: b.enabled, priority: b.priority, key: b.key, channel: b.channel });
        }
        Ok(Repos(repos))
    }

    pub fn load(paths: &Paths) -> Result<Repos> {
        let p = paths.repos_toml();
        let text = std::fs::read_to_string(&p)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", p.display())))?;
        Repos::parse(&text)
    }

    pub fn get(&self, name: &str) -> Option<&Repo> {
        self.0.iter().find(|r| r.name == name)
    }

    /// Repositories that take part in operations under `channel`.
    pub fn active(&self, channel: Channel) -> Vec<&Repo> {
        self.0.iter().filter(|r| r.enabled && r.channel == channel).collect()
    }
}

// ------------------------------------------------------------------ edits

pub fn set_channel(paths: &Paths, channel: Channel) -> Result<()> {
    let p = paths.ast_toml();
    let text = std::fs::read_to_string(&p).ctx("cannot read", &p)?;
    let mut doc: toml_edit::DocumentMut =
        text.parse().map_err(|e| Error::Config(format!("ast.toml: {e}")))?;
    doc["core"]["channel"] = toml_edit::value(channel.as_str());
    atomic_write(&p, doc.to_string().as_bytes(), 0o644)
}

pub fn set_repo_enabled(paths: &Paths, name: &str, enabled: bool) -> Result<()> {
    let p = paths.repos_toml();
    let text = std::fs::read_to_string(&p).ctx("cannot read", &p)?;
    let mut doc: toml_edit::DocumentMut =
        text.parse().map_err(|e| Error::Config(format!("repos.toml: {e}")))?;
    let tbl = doc
        .get_mut(name)
        .and_then(|i| i.as_table_mut())
        .ok_or_else(|| Error::NotFound(format!("repository {name:?} is not defined in repos.toml")))?;
    tbl["enabled"] = toml_edit::value(enabled);
    atomic_write(&p, doc.to_string().as_bytes(), 0o644)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_configs_parse() {
        let c = Config::parse(DEFAULT_AST_TOML).unwrap();
        assert_eq!(c.core.architecture, "aarch64");
        assert_eq!(c.core.channel, Channel::Stable);
        assert!(c.packages.allow_untested && !c.packages.prefer_binary);
        assert!(c.security.verify_signatures);
        let r = Repos::parse(DEFAULT_REPOS_TOML).unwrap();
        assert_eq!(r.0.len(), 4);
        assert!(r.get("ast").unwrap().enabled);
        assert!(!r.get("space-edge").unwrap().enabled);
        assert_eq!(r.active(Channel::Stable).len(), 2);
        assert_eq!(r.active(Channel::Edge).len(), 0);
    }

    #[test]
    fn safe_defaults_when_sections_missing() {
        let c = Config::parse("[core]\narchitecture = \"x86_64\"\n").unwrap();
        assert!(!c.packages.allow_untested);
        assert!(c.security.verify_signatures && c.security.verify_checksums);
        assert_eq!(c.core.channel, Channel::Stable);
    }

    #[test]
    fn invalid_values_are_rejected() {
        assert!(Config::parse("[core]\narchitecture = \"mips\"\n").is_err());
        assert!(Config::parse("[core]\narchitecture = \"x86_64\"\nchannel = \"beta\"\n").is_err());
        assert!(Config::parse("[core]\narchitecture = \"x86_64\"\n[build]\njobs = 0\n").is_err());
        assert!(Config::parse("[core]\narchitecture = \"x86_64\"\n[packages]\ncompression = \"xz\"\n").is_err());
        assert!(Config::parse("not toml at all =").is_err());
        assert!(Repos::parse("[a]\nurl=\"u\"\nkey=\"../x\"\n").is_err());
        assert!(Repos::parse("[a]\nurl=\"u\"\nkey=\"k\"\n[a]\nurl=\"u\"\nkey=\"k\"\n").is_err());
        assert!(Repos::parse("[Bad Name]\nurl=\"u\"\nkey=\"k\"\n").is_err());
    }

    #[test]
    fn jobs_are_capped() {
        let c = Config::parse("[core]\narchitecture = \"x86_64\"\n[build]\njobs = 100000\n").unwrap();
        let cpus = std::thread::available_parallelism().unwrap().get() as u32;
        assert!(c.effective_jobs(None) <= cpus);
        assert!(c.effective_jobs(Some(1)) == 1);
    }

    #[test]
    fn edits_preserve_comments() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::new(d.path());
        std::fs::create_dir_all(&paths.etc).unwrap();
        std::fs::write(paths.repos_toml(), DEFAULT_REPOS_TOML).unwrap();
        std::fs::write(paths.ast_toml(), DEFAULT_AST_TOML).unwrap();
        set_repo_enabled(&paths, "space-edge", true).unwrap();
        let text = std::fs::read_to_string(paths.repos_toml()).unwrap();
        assert!(text.contains("placeholders"));
        assert!(Repos::parse(&text).unwrap().get("space-edge").unwrap().enabled);
        assert!(set_repo_enabled(&paths, "nope", true).is_err());
        set_channel(&paths, Channel::Edge).unwrap();
        assert_eq!(Config::load(&paths).unwrap().core.channel, Channel::Edge);
    }
}

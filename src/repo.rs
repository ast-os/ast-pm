//! Repository access: `ast -u`, the cached-index catalog and artifact
//! downloads.
//!
//! The cached index is re-verified against the repository key every time it
//! is loaded, so tampering with the cache is detected.

use crate::config::{Channel, Config, Repo, Repos};
use crate::download::{download_to, fetch_bytes, join_url};
use crate::error::{Error, IoCtx, Result};
use crate::index::{Artifact, Index, IndexEntry, MAX_INDEX_BYTES};
use crate::package::arch_compatible;
use crate::security::{PublicKey, sha256_file};
use crate::util::{Paths, atomic_write, mkdir_private};
use crate::version::PackageName;
use std::path::PathBuf;

/// Largest file `ast` downloads.
const MAX_PACKAGE_BYTES: u64 = 4 << 30;

/// Message covered by a package/recipe signature: the file's SHA-256, bound
/// to a domain string so it cannot be confused with an index signature.
pub fn package_signature_message(sha256_hex: &str) -> Vec<u8> {
    format!("ast-package-v1:{}", sha256_hex.to_ascii_lowercase()).into_bytes()
}

fn load_key(paths: &Paths, repo: &Repo) -> Result<PublicKey> {
    let p = paths.keys.join(&repo.key);
    PublicKey::load(&p).map_err(|e| match e {
        Error::Io { .. } => Error::Config(format!(
            "repository {:?}: cannot read key {} ({e}); install the key or set verify_signatures = false (not recommended)",
            repo.name,
            p.display()
        )),
        other => other,
    })
}

#[derive(Debug)]
pub struct UpdateResult {
    pub repo: String,
    pub packages: usize,
    pub changed: bool,
}

fn cache_dir(paths: &Paths, repo: &str) -> PathBuf {
    paths.repo_cache.join(repo)
}

/// Download and verify the index of one repository. Only the index and its
/// signature are fetched, never packages.
pub fn update_repo(paths: &Paths, cfg: &Config, repo: &Repo) -> Result<UpdateResult> {
    let bytes = fetch_bytes(&join_url(&repo.url, "index.toml"), MAX_INDEX_BYTES)
        .map_err(|e| ctx_repo(&repo.name, e))?;
    let sig = if cfg.security.verify_signatures {
        let s = fetch_bytes(&join_url(&repo.url, "index.toml.sig"), 4096).map_err(|e| match e {
            Error::NotFound(_) => Error::Verify(format!(
                "repository {:?} has no index.toml.sig; refusing to use an unsigned index",
                repo.name
            )),
            other => ctx_repo(&repo.name, other),
        })?;
        let sig = String::from_utf8(s).map_err(|_| Error::Verify("signature file is not text".into()))?;
        load_key(paths, repo)?.verify(&format!("index of repository {:?}", repo.name), &bytes, &sig)?;
        Some(sig)
    } else {
        None
    };
    let idx = Index::parse(&bytes)?;
    check_index_matches(cfg, repo, &idx)?;

    let dir = cache_dir(paths, &repo.name);
    let old = std::fs::read(dir.join("index.toml")).ok().and_then(|b| Index::parse(&b).ok());
    let changed = old.as_ref() != Some(&idx);
    mkdir_private(&dir, 0o755)?;
    atomic_write(&dir.join("index.toml"), &bytes, 0o644)?;
    match sig {
        Some(s) => atomic_write(&dir.join("index.toml.sig"), s.as_bytes(), 0o644)?,
        None => {
            let _ = std::fs::remove_file(dir.join("index.toml.sig"));
        }
    }
    Ok(UpdateResult { repo: repo.name.clone(), packages: idx.packages.len(), changed })
}

fn ctx_repo(name: &str, e: Error) -> Error {
    match e {
        Error::Network(m) => Error::Network(format!("repository {name:?}: {m}")),
        Error::NotFound(m) => Error::NotFound(format!("repository {name:?}: {m}")),
        other => other,
    }
}

fn check_index_matches(cfg: &Config, repo: &Repo, idx: &Index) -> Result<()> {
    if idx.repo != repo.name {
        return Err(Error::Verify(format!(
            "index served for repository {:?} claims to be {:?}; wrong URL or key in repos.toml?",
            repo.name, idx.repo
        )));
    }
    if idx.arch != cfg.core.architecture {
        return Err(Error::Verify(format!(
            "repository {:?} is for architecture {}, this system is {}",
            repo.name, idx.arch, cfg.core.architecture
        )));
    }
    if idx.channel != repo.channel {
        return Err(Error::Verify(format!(
            "repository {:?} is configured as channel {} but serves channel {}",
            repo.name, repo.channel, idx.channel
        )));
    }
    Ok(())
}

/// One installable choice: an index entry together with where it came from.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub repo: String,
    pub repo_url: String,
    pub priority: u32,
    pub key: String,
    /// Channel the repository belongs to.
    pub channel: Channel,
    /// The repository is outside the system channel and was pulled in by an
    /// explicit `name:repo` request.
    pub foreign: bool,
    pub entry: IndexEntry,
}

#[derive(Debug)]
pub struct Catalog {
    pub arch: String,
    pub channel: Channel,
    pub all: Vec<Candidate>,
    /// Active repositories skipped because they have no cached index yet.
    pub skipped: Vec<String>,
    /// Candidates of repositories outside the system channel, loaded only
    /// when the user names such a repository explicitly.
    pub foreign: Vec<Candidate>,
}

impl Catalog {
    /// Load the cached, re-verified indexes of all active repositories.
    pub fn load(paths: &Paths, cfg: &Config, repos: &Repos) -> Result<Catalog> {
        let active = repos.active(cfg.core.channel);
        if active.is_empty() {
            return Err(Error::Config(format!(
                "no repositories are enabled for channel {}; see `ast repo list` and `ast repo enable <name>`",
                cfg.core.channel
            )));
        }
        let mut all = Vec::new();
        let mut skipped = Vec::new();
        for repo in active {
            match load_repo_candidates(paths, cfg, repo, false)? {
                Some(c) => all.extend(c),
                None => skipped.push(repo.name.clone()),
            }
        }
        if all.is_empty() && !skipped.is_empty() {
            return Err(Error::NotFound(format!(
                "no cached index for repositories: {}; run `ast -u`",
                skipped.join(", ")
            )));
        }
        Ok(Catalog { arch: cfg.core.architecture.clone(), channel: cfg.core.channel, all, skipped, foreign: vec![] })
    }

    /// Make the candidates of an explicitly named repository available.
    /// The repository must be defined and enabled; it may belong to another
    /// channel (that is the point). Nothing is downloaded here.
    pub fn load_extra(&mut self, paths: &Paths, cfg: &Config, repos: &Repos, name: &str) -> Result<()> {
        let repo = repos.get(name).ok_or_else(|| {
            Error::NotFound(format!("repository {name:?} is not defined in repos.toml (see `ast repo list`)"))
        })?;
        if !repo.enabled {
            return Err(Error::Config(format!(
                "repository {name:?} is disabled; enable it with `ast repo enable {name}` and run `ast -u`"
            )));
        }
        if repo.channel == cfg.core.channel {
            return Ok(()); // already part of the active set
        }
        if self.foreign.iter().any(|c| c.repo == name) {
            return Ok(());
        }
        match load_repo_candidates(paths, cfg, repo, true)? {
            Some(c) => {
                self.foreign.extend(c);
                Ok(())
            }
            None => Err(Error::NotFound(format!(
                "repository {name:?} has no cached index; run `ast -u`"
            ))),
        }
    }

    pub fn from_candidates(arch: &str, channel: Channel, all: Vec<Candidate>) -> Catalog {
        Catalog { arch: arch.into(), channel, all, skipped: vec![], foreign: vec![] }
    }

    /// Candidates for `name`, best first: higher repository priority, then
    /// newer version, then newer release.
    /// Candidates from foreign repositories (if any were loaded) come last,
    /// so they are only used when the active repositories cannot satisfy a
    /// requirement.
    pub fn candidates(&self, name: &PackageName) -> Vec<&Candidate> {
        let mut v = sorted(self.all.iter().filter(|c| &c.entry.name == name).collect());
        v.extend(sorted(self.foreign.iter().filter(|c| &c.entry.name == name).collect()));
        v
    }

    /// Candidates of one specific repository (active or foreign).
    pub fn candidates_in(&self, name: &PackageName, repo: &str) -> Vec<&Candidate> {
        sorted(
            self.all
                .iter()
                .chain(self.foreign.iter())
                .filter(|c| &c.entry.name == name && c.repo == repo)
                .collect(),
        )
    }

    pub fn names(&self) -> Vec<&PackageName> {
        let mut n: Vec<&PackageName> = self.all.iter().map(|c| &c.entry.name).collect();
        n.sort();
        n.dedup();
        n
    }
}

fn sorted(mut v: Vec<&Candidate>) -> Vec<&Candidate> {
    v.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| b.entry.version.cmp(&a.entry.version))
            .then_with(|| b.entry.revision.cmp(&a.entry.revision))
            .then_with(|| a.repo.cmp(&b.repo))
    });
    v
}

/// Load, re-verify and filter the cached index of one repository.
/// `None` means there is no cached index yet.
fn load_repo_candidates(paths: &Paths, cfg: &Config, repo: &Repo, foreign: bool) -> Result<Option<Vec<Candidate>>> {
    let dir = cache_dir(paths, &repo.name);
    let Ok(bytes) = std::fs::read(dir.join("index.toml")) else {
        return Ok(None);
    };
    if cfg.security.verify_signatures {
        let sig = std::fs::read_to_string(dir.join("index.toml.sig")).map_err(|_| {
            Error::Verify(format!("cached index of {:?} has no signature; run `ast -u`", repo.name))
        })?;
        load_key(paths, repo)?.verify(&format!("cached index of repository {:?}", repo.name), &bytes, &sig)?;
    }
    let idx = Index::parse(&bytes)?;
    check_index_matches(cfg, repo, &idx).map_err(|e| Error::Verify(format!("{e} (run `ast -u`)")))?;
    Ok(Some(
        idx.packages
            .into_iter()
            .filter(|e| arch_compatible(&e.arch, &cfg.core.architecture))
            .map(|entry| Candidate {
                repo: repo.name.clone(),
                repo_url: repo.url.clone(),
                priority: repo.priority,
                key: repo.key.clone(),
                channel: repo.channel,
                foreign,
                entry,
            })
            .collect(),
    ))
}

/// Download (or reuse from cache) a repository artifact, verifying size and
/// checksum. Returns the cached path.
pub fn fetch_artifact(paths: &Paths, cfg: &Config, cand: &Candidate, art: &Artifact) -> Result<PathBuf> {
    let dest = paths.packages.join(format!("{}-{}", &art.sha256[..16], art.file));
    mkdir_private(&paths.packages, 0o755)?;
    let url = join_url(&cand.repo_url, &art.file);
    let cached_ok = dest.exists()
        && (!cfg.security.verify_checksums || sha256_file(&dest).map(|h| h.eq_ignore_ascii_case(&art.sha256)).unwrap_or(false));
    if !cached_ok {
        let _ = std::fs::remove_file(&dest);
        download_to(&url, &dest, cfg.security.verify_checksums.then_some(art.sha256.as_str()), MAX_PACKAGE_BYTES)
            .map_err(|e| match e {
                Error::Verify(m) => Error::Verify(format!("{} {}: {m}", cand.entry.name, cand.entry.version)),
                Error::NotFound(m) => Error::NotFound(format!("{} {}: {m}", cand.entry.name, cand.entry.version)),
                o => o,
            })?;
    }
    Ok(dest)
}

/// Verify the detached signature of a downloaded package against the key of
/// the repository it came from. The `.sig` is fetched next to the package.
pub fn verify_package_signature(paths: &Paths, cfg: &Config, cand: &Candidate, art: &Artifact, file: &std::path::Path) -> Result<()> {
    if !cfg.security.verify_signatures {
        return Ok(());
    }
    let sig_url = join_url(&cand.repo_url, &format!("{}.sig", art.file));
    let sig = fetch_bytes(&sig_url, 4096).map_err(|e| match e {
        Error::NotFound(_) => Error::Verify(format!(
            "{} {} has no detached signature ({}.sig); refusing to install an unsigned package",
            cand.entry.name, cand.entry.version, art.file
        )),
        other => other,
    })?;
    let sig = String::from_utf8(sig).map_err(|_| Error::Verify("signature file is not text".into()))?;
    let sha = sha256_file(file)?;
    let key = load_key(paths, &Repo {
        name: cand.repo.clone(),
        url: cand.repo_url.clone(),
        enabled: true,
        priority: cand.priority,
        key: cand.key.clone(),
        channel: cand_channel(cfg),
    })?;
    key.verify(&format!("package {} {}", cand.entry.name, cand.entry.version), &package_signature_message(&sha), &sig)
}

fn cand_channel(cfg: &Config) -> Channel {
    cfg.core.channel
}

pub fn ensure_dir(p: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(p).ctx("cannot create", p)
}

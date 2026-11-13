//! High-level commands. Output and confirmation go through the `Ui` trait so
//! the CLI and the tests share exactly the same logic.

use crate::config::{Config, Repo, Repos};
use crate::error::{Error, IoCtx, Result};
use crate::repo::{self, Catalog};
use crate::resolver::Options;
use crate::txn::Txn;
use crate::util::{LockGuard, Log, Paths, mkdir_private, table};
use std::path::{Path, PathBuf};

pub trait Ui {
    fn out(&mut self, line: &str);
    fn warn(&mut self, line: &str);
    /// Ask a yes/no question. Must return `default_yes` semantics only when the
    /// user just presses Enter; with no way to ask, return false.
    fn confirm(&mut self, prompt: &str, default_yes: bool) -> bool;
}

#[derive(Debug, Clone, Default)]
pub struct Flags {
    /// Accept ordinary confirmations (never the `untested` one).
    pub yes: bool,
    /// Explicitly accept installing untested system components.
    pub accept_untested: bool,
    pub dry_run: bool,
    pub jobs: Option<u32>,
    /// Explicitly accept dependencies taken from a repository of another channel.
    pub accept_foreign: bool,
    /// Use ready-made binary packages only (`-b`); the default builds from source.
    pub binary: bool,
    /// Replace files that belong to no package (building the base over the temporary tools).
    pub adopt: bool,
}

pub struct Ast {
    pub paths: Paths,
    pub cfg: Config,
    pub repos: Repos,
    pub flags: Flags,
    pub(crate) log: Log,
}

/// Create the directory layout and default configuration files (never
/// overwrites existing files).
pub fn init(root: &Path) -> Result<Vec<PathBuf>> {
    let paths = Paths::new(root);
    for d in [&paths.etc, &paths.keys, &paths.db, &paths.installed, &paths.repo_cache, &paths.packages, &paths.build] {
        mkdir_private(d, 0o755)?;
    }
    let mut created = vec![];
    let arch = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        _ => "x86_64",
    };
    let ast = crate::config::DEFAULT_AST_TOML.replace("architecture = \"aarch64\"", &format!("architecture = \"{arch}\""));
    let repos = crate::config::DEFAULT_REPOS_TOML.replace("/aarch64/", &format!("/{arch}/"));
    for (p, text) in [(paths.ast_toml(), ast), (paths.repos_toml(), repos)] {
        if !p.exists() {
            std::fs::write(&p, text).ctx("cannot write", &p)?;
            created.push(p);
        }
    }
    Ok(created)
}

impl Ast {
    pub fn open(root: &Path, flags: Flags) -> Result<Ast> {
        let paths = Paths::new(root);
        let cfg = Config::load(&paths)?;
        let repos = Repos::load(&paths)?;
        let log = Log::new(paths.log.clone());
        Ok(Ast { paths, cfg, repos, flags, log })
    }

    /// Open `root`, but read settings, repositories and keys from `etc` instead of the
    /// root's own `/etc/ast`; the database and caches still live inside `root`.
    pub fn open_with_config(root: &Path, etc: &Path, flags: Flags) -> Result<Ast> {
        let mut paths = Paths::new(root);
        paths.etc = etc.to_path_buf();
        paths.keys = etc.join("keys");
        for d in [&paths.db, &paths.installed, &paths.repo_cache, &paths.packages, &paths.build] {
            mkdir_private(d, 0o755)?;
        }
        let cfg = Config::load(&paths)?;
        let repos = Repos::load(&paths)?;
        let log = Log::new(paths.log.clone());
        Ok(Ast { paths, cfg, repos, flags, log })
    }

    /// Configuration warnings the CLI should print on every run.
    pub fn security_warnings(&self) -> Vec<String> {
        let mut v = vec![];
        if !self.cfg.security.verify_signatures {
            v.push("!  signature verification disabled".into());
        }
        if !self.cfg.security.verify_checksums {
            v.push("!  checksum verification disabled".into());
        }
        v
    }

    pub(crate) fn begin_mutation(&self, ui: &mut dyn Ui) -> Result<LockGuard> {
        let lock = LockGuard::acquire(&self.paths.lock)?;
        if Txn::recover(&self.paths)? {
            ui.warn("!  interrupted transaction rolled back");
            self.log.line("recovered interrupted transaction (rolled back)");
        }
        Ok(lock)
    }

    pub(crate) fn catalog(&self, ui: &mut dyn Ui) -> Result<Catalog> {
        let c = Catalog::load(&self.paths, &self.cfg, &self.repos)?;
        for r in &c.skipped {
            ui.warn(&format!("!  {r}  no index, skipped; run `ast -u`"));
        }
        Ok(c)
    }

    pub(crate) fn resolver_opts(&self) -> Options {
        Options { prefer_binary: self.cfg.packages.prefer_binary, build_enabled: self.cfg.build.enabled }
    }

    pub fn update(&self, ui: &mut dyn Ui) -> Result<()> {
        let _lock = self.begin_mutation(ui)?;
        // Every enabled repository is refreshed, including ones of another
        // channel, so that explicit `name:repo` requests can use them.
        let enabled: Vec<&Repo> = self.repos.0.iter().filter(|r| r.enabled).collect();
        if enabled.is_empty() {
            return Err(Error::Config("no repositories are enabled; see `ast repo list`".into()));
        }
        let mut first_err: Option<Error> = None;
        let mut rows: Vec<Vec<String>> = Vec::new();
        for r in enabled {
            match repo::update_repo(&self.paths, &self.cfg, r) {
                Ok(u) => {
                    rows.push(vec![
                        u.repo.clone(),
                        format!("{} packages", u.packages),
                        if u.changed { String::new() } else { "(unchanged)".into() },
                        if r.channel != self.cfg.core.channel { format!("[{} channel: used only via `name:{}`]", r.channel, r.name) } else { String::new() },
                    ]);
                    self.log.line(&format!("update {}: {} packages", u.repo, u.packages));
                }
                Err(e) => {
                    ui.warn(&format!("!  {}  {e}", r.name));
                    self.log.line(&format!("update {} failed: {e}", r.name));
                    first_err.get_or_insert(e);
                }
            }
        }
        for l in table(&rows, "") {
            ui.out(&l);
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

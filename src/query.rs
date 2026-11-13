//! Read-mostly commands: search, info, list, repositories, channel, clean, verify.

use crate::config::{Channel, Repo};
use crate::db::{Db, FileKind, InstalledPackage, OriginKind, Reason};
use crate::error::{Error, Result};
use crate::ops::{Ast, Ui};
use crate::repo::{Candidate, Catalog};
use crate::security::sha256_file;
use crate::util::{human_size, table};
use crate::version::{Dependency, PackageName};
use std::path::Path;

impl Ast {
    // ---------------------------------------------------- query commands

    fn best_per_name<'a>(&self, catalog: &'a Catalog) -> Vec<&'a Candidate> {
        catalog.names().into_iter().filter_map(|n| catalog.candidates(n).into_iter().next()).collect()
    }

    pub fn search(&self, term: &str, ui: &mut dyn Ui) -> Result<usize> {
        let catalog = self.catalog(ui)?;
        let db = Db::load(&self.paths)?;
        let t = term.to_lowercase();
        let mut n = 0;
        let mut rows: Vec<Vec<String>> = Vec::new();
        for c in self.best_per_name(&catalog) {
            let e = &c.entry;
            if e.name.as_str().contains(&t) || e.description.to_lowercase().contains(&t) {
                n += 1;
                let mut flags = vec![];
                if e.binary.is_some() {
                    flags.push("bin");
                }
                if e.recipe.is_some() {
                    flags.push("src");
                }
                let st = e.status.map(|s| format!(" ({})", s.as_str())).unwrap_or_default();
                rows.push(vec![
                    e.name.to_string(),
                    e.version.to_string(),
                    c.repo.clone(),
                    format!("{}{}", flags.join("+"), st),
                    if db.get(&e.name).is_some() { "[installed]".into() } else { String::new() },
                    e.description.clone(),
                ]);
            }
        }
        for l in table(&rows, "") {
            ui.out(&l);
        }
        if n == 0 {
            ui.out("no match");
        }
        Ok(n)
    }

    pub fn info(&self, name: &str, ui: &mut dyn Ui) -> Result<()> {
        let n = PackageName::new(name)?;
        let db = Db::load(&self.paths)?;
        let catalog = self.catalog(ui).ok();
        let cands: Vec<&Candidate> = catalog.as_ref().map(|c| c.candidates(&n)).unwrap_or_default();
        let inst = db.get(&n);
        if cands.is_empty() && inst.is_none() {
            return Err(Error::NotFound(format!(
                "package {name} is neither installed nor available in the enabled repositories"
            )));
        }
        let list = |v: &[Dependency]| v.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ");
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut add = |k: &str, v: String| {
            if !v.is_empty() {
                rows.push(vec![k.into(), v]);
            }
        };
        if let Some(c) = cands.first() {
            let e = &c.entry;
            ui.out(&format!("{n}  {}-{}", e.version, e.revision));
            if !e.description.is_empty() {
                ui.out(&e.description);
            }
            add("repo", c.repo.clone());
            add("license", e.license.clone());
            add("arch", e.arch.clone());
            add("depends", list(&e.depends));
            add("builddeps", list(&e.build_depends));
            add("conflicts", list(&e.conflicts));
            add("replaces", e.replaces.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", "));
            add("status", e.status.map(|s| format!("{} (system component)", s.as_str())).unwrap_or_default());
            let mut from = vec![];
            if e.binary.is_some() {
                from.push("binary");
            }
            if e.recipe.is_some() {
                from.push("recipe");
            }
            add("provides", from.join(", "));
            add(
                "others",
                cands[1..]
                    .iter()
                    .map(|o| format!("{} {}-{}", o.repo, o.entry.version, o.entry.revision))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        } else {
            ui.out(&n.to_string());
        }
        if let Some(i) = inst {
            let how = match i.origin.kind {
                OriginKind::Binary => "binary",
                OriginKind::Source => "built from source",
            };
            let why = if i.reason == Reason::Explicit { "explicit" } else { "dependency" };
            add("installed", format!("{} ({why}, {how}, {})", i.full_version(), i.origin.repo));
            add("files", i.files.iter().filter(|f| f.kind != FileKind::Dir).count().to_string());
            add("services", i.services.join(", "));
        }
        for l in table(&rows, "  ") {
            ui.out(&l);
        }
        Ok(())
    }

    pub fn list(&self, ui: &mut dyn Ui) -> Result<usize> {
        let db = Db::load(&self.paths)?;
        let rows: Vec<Vec<String>> = db
            .packages
            .values()
            .map(|p| {
                vec![
                    p.name.to_string(),
                    p.full_version(),
                    match p.origin.kind {
                        OriginKind::Binary => "bin".to_string(),
                        OriginKind::Source => "src".to_string(),
                    },
                    p.origin.repo.clone(),
                    if p.reason == Reason::Explicit { String::new() } else { "(dependency)".into() },
                ]
            })
            .collect();
        for l in table(&rows, "") {
            ui.out(&l);
        }
        if db.packages.is_empty() {
            ui.out("nothing installed");
        }
        Ok(db.packages.len())
    }

    // ------------------------------------------------- repos and channel

    pub fn repo_list(&self, ui: &mut dyn Ui) {
        ui.out(&format!("channel  {}", self.cfg.core.channel));
        let mut rows: Vec<Vec<String>> = Vec::new();
        for r in &self.repos.0 {
            let active = r.enabled && r.channel == self.cfg.core.channel;
            let state = if active {
                "active"
            } else if r.enabled {
                "enabled, inactive (other channel)"
            } else {
                "disabled"
            };
            let cached = match std::fs::read(self.paths.repo_cache.join(&r.name).join("index.toml"))
                .ok()
                .and_then(|b| crate::index::Index::parse(&b).ok())
            {
                Some(i) => format!("{} packages", i.packages.len()),
                None => "no index (run `ast -u`)".into(),
            };
            rows.push(vec![
                r.name.clone(),
                r.channel.to_string(),
                format!("prio {}", r.priority),
                state.to_string(),
                cached,
                r.key.clone(),
                r.url.clone(),
            ]);
        }
        for l in table(&rows, "") {
            ui.out(&l);
        }
    }

    pub fn repo_set_enabled(&self, name: &str, enabled: bool, ui: &mut dyn Ui) -> Result<()> {
        let _lock = self.begin_mutation(ui)?;
        let r: &Repo = self
            .repos
            .get(name)
            .ok_or_else(|| Error::NotFound(format!("repository {name:?} is not defined in repos.toml")))?;
        crate::config::set_repo_enabled(&self.paths, name, enabled)?;
        self.log.line(&format!("repo {name} {}", if enabled { "enabled" } else { "disabled" }));
        ui.out(&format!(
            "{name}  {}",
            if enabled { "enabled, run `ast -u` to fetch its index" } else { "disabled" }
        ));
        if enabled && r.channel != self.cfg.core.channel {
            ui.warn(&format!(
                "!  {name}  {} channel: usable as NAME:{name} until `ast channel {}`",
                r.channel, r.channel
            ));
        }
        Ok(())
    }

    pub fn channel(&self, new: Option<&str>, ui: &mut dyn Ui) -> Result<()> {
        match new {
            None => {
                ui.out(&self.cfg.core.channel.to_string());
                Ok(())
            }
            Some(c) => {
                let ch = Channel::parse(c)?;
                let _lock = self.begin_mutation(ui)?;
                if ch == self.cfg.core.channel {
                    ui.out(&format!("channel  {ch}  (unchanged)"));
                    return Ok(());
                }
                crate::config::set_channel(&self.paths, ch)?;
                self.log.line(&format!("channel set to {ch}"));
                ui.out(&format!("channel  {ch}"));
                let active: Vec<&str> = self.repos.active(ch).iter().map(|r| r.name.as_str()).collect();
                if active.is_empty() {
                    ui.warn(&format!("!  no repository enabled for {ch}: `ast repo enable NAME`"));
                } else {
                    ui.out(&format!("repos  {}", active.join(", ")));
                }
                Ok(())
            }
        }
    }

    // ------------------------------------------------------ clean/verify

    pub fn clean(&self, ui: &mut dyn Ui) -> Result<()> {
        let _lock = self.begin_mutation(ui)?;
        let mut freed = 0u64;
        for dir in [&self.paths.packages, &self.cfg.build_dir(&self.paths)] {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    freed += tree_size(&p);
                    crate::build::remove_tree(&p)?;
                }
            }
        }
        self.log.line(&format!("clean: freed {freed} bytes"));
        ui.out(&format!("cleaned  {}", human_size(freed)));
        Ok(())
    }

    /// Returns the number of problems found.
    pub fn verify(&self, names: &[String], ui: &mut dyn Ui) -> Result<usize> {
        let db = Db::load(&self.paths)?;
        let selected: Vec<&InstalledPackage> = if names.is_empty() {
            db.packages.values().collect()
        } else {
            names
                .iter()
                .map(|n| {
                    let pn = PackageName::new(n)?;
                    db.get(&pn).ok_or_else(|| Error::NotFound(format!("package {n} is not installed")))
                })
                .collect::<Result<_>>()?
        };
        let mut problems = 0;
        let mut ok_rows: Vec<Vec<String>> = Vec::new();
        for p in &selected {
            let mut bad = 0;
            for f in &p.files {
                let path = match crate::archive::resolve_in_root(&self.paths.root, &f.path) {
                    Ok(x) => x,
                    Err(e) => {
                        ui.warn(&format!("!  {}  /{}  {e}", p.name, f.path));
                        bad += 1;
                        continue;
                    }
                };
                let md = std::fs::symlink_metadata(&path);
                match f.kind {
                    FileKind::Dir => {
                        if !md.map(|m| m.is_dir()).unwrap_or(false) && !crate::archive::is_dir_in_root(&self.paths.root, &f.path) {
                            ui.warn(&format!("!  {}  /{}  directory missing", p.name, f.path));
                            bad += 1;
                        }
                    }
                    FileKind::Symlink => match std::fs::read_link(&path) {
                        Ok(t) if Some(t.to_string_lossy().as_ref()) == f.target.as_deref() => {}
                        Ok(_) => {
                            ui.warn(&format!("!  {}  /{}  wrong link target", p.name, f.path));
                            bad += 1;
                        }
                        Err(_) => {
                            ui.warn(&format!("!  {}  /{}  link missing", p.name, f.path));
                            bad += 1;
                        }
                    },
                    FileKind::File => match md {
                        Err(_) => {
                            ui.warn(&format!("!  {}  /{}  missing", p.name, f.path));
                            bad += 1;
                        }
                        Ok(m) if !m.is_file() => {
                            ui.warn(&format!("!  {}  /{}  not a regular file", p.name, f.path));
                            bad += 1;
                        }
                        Ok(_) => {
                            if let Some(expected) = &f.sha256
                                && &sha256_file(&path)? != expected {
                                    if f.config {
                                        ui.out(&format!("~  {}  /{}  config edited", p.name, f.path));
                                    } else {
                                        ui.warn(&format!("!  {}  /{}  modified", p.name, f.path));
                                        bad += 1;
                                    }
                                }
                        }
                    },
                }
            }
            if bad == 0 {
                ok_rows.push(vec![p.name.to_string(), "ok".into()]);
            }
            problems += bad;
        }
        for l in table(&ok_rows, "") {
            ui.out(&l);
        }
        if problems == 0 {
            ui.out(&format!("verified  {}", selected.len()));
        }
        Ok(problems)
    }
}

fn tree_size(p: &Path) -> u64 {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::read_dir(p)
            .map(|rd| rd.flatten().map(|e| tree_size(&e.path())).sum())
            .unwrap_or(0),
        Ok(m) => m.len(),
        Err(_) => 0,
    }
}

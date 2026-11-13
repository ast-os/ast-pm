//! Running a plan: show it, ask, download and check everything, then install in
//! one journaled transaction.

use crate::build::{BuildJob, Recipe};
use crate::db::{Db, InstallOrigin, OriginKind};
use crate::error::{Error, Result};
use crate::openrc;
use crate::package::{Metadata, PackageFile, Status};
use crate::repo::{self, Candidate};
use crate::resolver::{Method, Plan, PlanItem};
use crate::transaction::{self, InstallOutcome};
use crate::txn::Txn;
use crate::util::table;
use crate::ops::{Ast, Ui};
use crate::version::PackageName;

struct Acquired {
    kind: AcquiredKind,
}

enum AcquiredKind {
    Binary { pf: PackageFile, file: String, sha256: String },
    Source { recipe: Recipe, file: String, sha256: String },
}

impl Ast {
    pub(crate) fn print_plan(&self, plan: &Plan, ui: &mut dyn Ui) {
        let mut rows: Vec<Vec<String>> = Vec::new();
        for i in &plan.install {
            let e = &i.cand.entry;
            let new = format!("{}-{}", e.version, e.revision);
            let mut notes = vec![];
            if i.method == Method::Source {
                notes.push("build".to_string());
            }
            if let Some(st) = e.status {
                notes.push(st.as_str().to_string());
            }
            if i.cand.foreign {
                notes.push(format!("{} channel", i.cand.channel));
            }
            rows.push(match &i.old {
                None => vec!["+".into(), i.name().to_string(), new, i.cand.repo.clone(), notes.join(", ")],
                Some(o) => vec![
                    "~".into(),
                    i.name().to_string(),
                    format!("{} -> {new}", o.full_version()),
                    i.cand.repo.clone(),
                    notes.join(", "),
                ],
            });
        }
        for (n, why) in &plan.remove {
            rows.push(vec!["-".into(), n.to_string(), String::new(), String::new(), why.clone()]);
        }
        for l in table(&rows, "  ") {
            ui.out(&l);
        }
        let count = |f: &dyn Fn(&PlanItem) -> bool| plan.install.iter().filter(|i| f(i)).count();
        let mut parts = vec![];
        for (n, what) in [
            (count(&|i| i.old.is_none()), "to install"),
            (count(&|i| i.old.is_some()), "to upgrade"),
            (plan.remove.len(), "to remove"),
        ] {
            if n > 0 {
                parts.push(format!("{n} {what}"));
            }
        }
        ui.out("");
        ui.out(&parts.join(", "));
        ui.out("");
    }

    fn untested_in(plan: &Plan) -> Vec<&PlanItem> {
        plan.install.iter().filter(|i| i.cand.entry.status == Some(Status::Untested)).collect()
    }

    /// Plan -> confirmations -> download/verify -> transaction.
    pub(crate) fn execute(&self, plan: Plan, db: &Db, pins: &[PackageName], ui: &mut dyn Ui) -> Result<()> {
        self.print_plan(&plan, ui);

        // untested system components: checked for the whole plan, so
        // dependencies cannot smuggle one in.
        let untested = Self::untested_in(&plan);
        if !untested.is_empty() {
            let list: Vec<String> = untested.iter().map(|i| format!("{}  {}", i.name(), i.cand.entry.version)).collect();
            if !self.cfg.packages.allow_untested {
                return Err(Error::Untested(format!(
                    "the transaction contains untested system components and allow_untested = false: {}",
                    list.join(", ")
                )));
            }
            ui.warn("!  untested system components:");
            for l in &list {
                ui.warn(&format!("  {l}"));
            }
        }
        let foreign: Vec<&PlanItem> = plan.install.iter().filter(|i| i.cand.foreign).collect();
        if !foreign.is_empty() {
            ui.warn(&format!("!  outside the current channel ({}):", self.cfg.core.channel));
            for i in &foreign {
                ui.warn(&format!(
                    "  {}  {}  {}  {} channel{}",
                    i.name(),
                    i.cand.entry.version,
                    i.cand.repo,
                    i.cand.channel,
                    if pins.contains(i.name()) { "" } else { "  dependency" }
                ));
            }
        }
        let foreign_deps: Vec<&&PlanItem> = foreign.iter().filter(|i| !pins.contains(i.name())).collect();
        let sources: Vec<&PlanItem> = plan.install.iter().filter(|i| i.method == Method::Source).collect();
        if !sources.is_empty() {
            ui.warn(if self.cfg.build.sandbox == crate::config::SandboxMode::None { "!  runs recipe scripts WITHOUT a sandbox:" } else { "!  runs recipe scripts (sandboxed, no network):" });
            for s in &sources {
                ui.warn(&format!("  {}  {}  {}", s.name(), s.cand.entry.version, s.cand.repo));
            }
        }

        if self.flags.dry_run {
            ui.out("dry run, nothing changed");
            return Ok(());
        }
        if !self.flags.yes && !ui.confirm("proceed?", true) {
            return Err(Error::Aborted);
        }
        if !untested.is_empty() {
            if self.flags.accept_untested {
                ui.warn("!  --accept-untested: not asking about untested components");
            } else if !ui.confirm("install untested components?", false) {
                return Err(Error::Aborted);
            }
        }
        if !foreign_deps.is_empty() {
            // The user consented to the packages they named; dependencies
            // that drag in another channel need their own consent.
            if self.flags.accept_foreign {
                ui.warn("!  --accept-foreign: not asking about other-channel dependencies");
            } else if !ui.confirm("use dependencies from another channel?", false) {
                return Err(Error::Aborted);
            }
        }
        if !sources.is_empty() && !self.flags.yes && !ui.confirm("run build scripts?", false) {
            return Err(Error::Aborted);
        }

        // Download and authenticate everything before touching the system.
        let mut acquired = Vec::new();
        for item in &plan.install {
            acquired.push(self.acquire(item, ui)?);
        }

        // warn about services of packages about to be removed
        for (n, _) in &plan.remove {
            if let Some(p) = db.get(n) {
                self.warn_services_of_removal(p, ui);
            }
        }

        let mut work_db = db.clone();
        let mut txn = Txn::begin(&self.paths)?;
        let res = self.run_txn(&mut txn, &mut work_db, &plan, acquired, ui);
        match res {
            Ok(posts) => {
                txn.commit()?;
                self.log.line(&format!(
                    "transaction committed: {} installed/upgraded, {} removed",
                    plan.install.len(),
                    plan.remove.len()
                ));
                for p in posts {
                    for l in p {
                        ui.out(&l);
                    }
                }
                let changed: Vec<String> = plan
                    .install
                    .iter()
                    .filter_map(|i| work_db.get(i.name()))
                    .flat_map(|p| p.files.iter().map(|f| f.path.clone()))
                    .chain(plan.remove.iter().filter_map(|(n, _)| db.get(n)).flat_map(|p| p.files.iter().map(|f| f.path.clone())))
                    .collect();
                crate::hooks::run(&self.paths, &changed, ui);
                let up = plan.install.iter().filter(|i| i.old.is_some()).count();
                let mut parts = vec![];
                for (n, what) in [(plan.install.len() - up, "installed"), (up, "upgraded"), (plan.remove.len(), "removed")] {
                    if n > 0 {
                        parts.push(format!("{n} {what}"));
                    }
                }
                ui.out(&format!("done  {}", parts.join(", ")));
                Ok(())
            }
            Err(e) => {
                self.log.line(&format!("transaction failed, rolling back: {e}"));
                match txn.rollback() {
                    Ok(()) => ui.warn("!  failed, rolled back"),
                    Err(re) => ui.warn(&format!("!  rollback failed: {re}")),
                }
                Err(e)
            }
        }
    }

    fn acquire(&self, item: &PlanItem, ui: &mut dyn Ui) -> Result<Acquired> {
        let cand = &item.cand;
        match item.method {
            Method::Binary => {
                let art = cand.entry.binary_artifact().ok_or_else(|| {
                    Error::NotFound(format!("{} {} has no binary package", item.name(), cand.entry.version))
                })?;
                ui.out(&format!("  fetch  {}  {}", item.name(), cand.entry.version));
                let path = repo::fetch_artifact(&self.paths, &self.cfg, cand, &art)?;
                repo::verify_package_signature(&self.paths, &self.cfg, cand, &art, &path)?;
                let pf = PackageFile::open(&path)?;
                check_meta_matches(cand, &pf.meta, &self.cfg.core.architecture)?;
                Ok(Acquired { kind: AcquiredKind::Binary { pf, file: art.file.clone(), sha256: art.sha256.clone() } })
            }
            Method::Source => {
                let art = cand.entry.recipe_artifact().ok_or_else(|| {
                    Error::NotFound(format!("{} {} has no source recipe", item.name(), cand.entry.version))
                })?;
                ui.out(&format!("  fetch  {}  {}  recipe", item.name(), cand.entry.version));
                let path = repo::fetch_artifact(&self.paths, &self.cfg, cand, &art)?;
                let recipe = Recipe::load(&path)?;
                if recipe.name != cand.entry.name || recipe.version != cand.entry.version || recipe.revision != cand.entry.revision {
                    return Err(Error::Verify(format!(
                        "recipe {} does not match the index entry for {} {}",
                        art.file, cand.entry.name, cand.entry.version
                    )));
                }
                Ok(Acquired { kind: AcquiredKind::Source { recipe, file: art.file.clone(), sha256: art.sha256.clone() } })
            }
        }
    }

    fn run_txn(
        &self,
        txn: &mut Txn,
        db: &mut Db,
        plan: &Plan,
        acquired: Vec<Acquired>,
        ui: &mut dyn Ui,
    ) -> Result<Vec<Vec<String>>> {
        let removing: Vec<PackageName> = plan.remove.iter().map(|(n, _)| n.clone()).collect();
        let mut posts = Vec::new();
        for (name, why) in &plan.remove {
            let pkg = db.get(name).cloned().ok_or_else(|| Error::NotFound(format!("{name} is not installed")))?;
            ui.out(&format!("  remove  {name}"));
            let out = transaction::remove_package(txn, &self.paths, db, &pkg, &removing)?;
            db.remove(name);
            self.log.line(&format!("remove {} {} ({why})", name, pkg.full_version()));
            let mut lines = vec![];
            for c in out.kept_configs {
                lines.push(format!("!  {c}  edited config kept"));
            }
            posts.push(lines);
        }
        for (item, acq) in plan.install.iter().zip(acquired) {
            let (pf, origin) = match acq.kind {
                AcquiredKind::Binary { pf, file, sha256 } => {
                    let o = InstallOrigin {
                        kind: OriginKind::Binary,
                        repo: item.cand.repo.clone(),
                        file,
                        sha256,
                        source_sha256: pf.meta.origin.source_sha256.clone(),
                    };
                    (pf, o)
                }
                AcquiredKind::Source { recipe, file, sha256 } => {
                    ui.out(&format!("  build  {}  {}", recipe.name, recipe.version));
                    let build_dir = self.cfg.build_dir(&self.paths);
                    let job = BuildJob {
                        recipe: &recipe,
                        repo_url: Some(&item.cand.repo_url),
                        arch: &self.cfg.core.architecture,
                        build_dir: &build_dir,
                        out_dir: &self.paths.packages,
                        jobs: self.cfg.effective_jobs(self.flags.jobs),
                        cfg: &self.cfg.build,
                        verify_checksums: self.cfg.security.verify_checksums,
                    };
                    let built = crate::build::build_package(&job)?;
                    let pf = PackageFile::open(&built)?;
                    if pf.meta.name != recipe.name || pf.meta.version != recipe.version {
                        return Err(Error::Build("built package does not match its recipe".into()));
                    }
                    let o = InstallOrigin {
                        kind: OriginKind::Source,
                        repo: item.cand.repo.clone(),
                        file,
                        sha256,
                        source_sha256: Some(recipe.source.sha256.clone()),
                    };
                    (pf, o)
                }
            };
            ui.out(&format!(
                "  {}  {}  {}",
                if item.old.is_some() { "upgrade" } else { "install" },
                item.name(),
                item.cand.entry.version
            ));
            let (record, outcome) =
                transaction::install_package(txn, &self.paths, db, &pf, origin, item.reason, &removing, self.flags.adopt)?;
            self.log.line(&format!(
                "{} {} {} from {} ({:?})",
                if item.old.is_some() { "upgrade" } else { "install" },
                record.name,
                record.full_version(),
                record.origin.repo,
                record.origin.kind
            ));
            posts.push(self.post_install_lines(item, &outcome));
            db.insert(record);
        }
        Ok(posts)
    }

    fn post_install_lines(&self, item: &PlanItem, o: &InstallOutcome) -> Vec<String> {
        let mut v = vec![];
        let name = item.name();
        if let Some(n) = &o.notice {
            v.push(format!("!  {name}  {n}"));
        }
        if item.cand.entry.status.is_some() {
            v.push(format!("!  {name}  system component: applies after reboot, no service restarted"));
        }
        for c in &o.new_config_files {
            v.push(format!("!  {c}  edited locally, kept; new default in {c}.astnew"));
        }
        for s in &o.services {
            let st = openrc::service_state(&self.paths.root, s);
            if item.old.is_some() && st.running {
                v.push(format!("!  {s}  service runs the old version: rc-service {s} restart"));
            } else if item.old.is_none() {
                v.push(format!("!  {s}  service not enabled: rc-update add {s} default"));
            }
        }
        v
    }
}

/// The package's own metadata must agree with the (signed) index entry.
fn check_meta_matches(c: &Candidate, m: &Metadata, system_arch: &str) -> Result<()> {
    let e = &c.entry;
    let mismatch = |what: &str| {
        Error::Verify(format!(
            "package file for {} {} disagrees with the repository index ({what}); refusing to install",
            e.name, e.version
        ))
    };
    if m.name != e.name {
        return Err(mismatch("name"));
    }
    if m.version != e.version || m.revision != e.revision {
        return Err(mismatch("version"));
    }
    if m.arch != e.arch {
        return Err(mismatch("architecture"));
    }
    if !crate::package::arch_compatible(&m.arch, system_arch) {
        return Err(Error::Verify(format!("{} is built for {}, this system is {system_arch}", m.name, m.arch)));
    }
    if m.depends != e.depends || m.conflicts != e.conflicts || m.replaces != e.replaces {
        return Err(mismatch("dependencies"));
    }
    if m.release.status != e.status {
        return Err(mismatch("release status"));
    }
    Ok(())
}

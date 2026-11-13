//! `ast -i` and `ast -u`: turn the request into a plan and run it.

use crate::db::{Db, InstalledPackage, OriginKind, Reason};
use crate::error::{Error, Result};
use crate::ops::{Ast, Ui};
use crate::repo::Catalog;
use crate::resolver::{Request, Resolver};
use crate::spec::{TargetSpec, parse_spec};
use crate::transaction;
use crate::txn::Txn;
use crate::version::{Dependency, PackageName};

impl Ast {
    pub(crate) fn make_request(&self, spec: &TargetSpec, catalog: &Catalog) -> Result<Request> {
        let has = |n: &PackageName| match &spec.repo {
            Some(r) => !catalog.candidates_in(n, r).is_empty(),
            None => !catalog.candidates(n).is_empty(),
        };
        let mk = |n: PackageName, bin: bool| Request {
            dep: Dependency { name: n, constraint: spec.version.clone() },
            binary_only: bin,
            repo: spec.repo.clone(),
        };
        let t = spec.name.as_str();
        if let Some(n) = PackageName::new(t).ok().filter(|n| has(n)) {
            return Ok(mk(n, self.flags.binary));
        }
        let (name, bin) = match t.strip_suffix("-bin") {
            Some(base) if !base.is_empty() => (base, true),
            _ => (t, false),
        };
        let n = PackageName::new(name)?;
        if !has(&n) {
            return Err(Error::NotFound(format!(
                "package {name} was not found {}{}",
                match &spec.repo {
                    Some(r) => format!("in repository {r}"),
                    None => "in the enabled repositories".to_string(),
                },
                if bin { " (requested as a binary package via the -bin suffix)" } else { "" }
            )));
        }
        Ok(mk(n, bin || self.flags.binary))
    }

    pub fn install(&self, targets: &[String], ui: &mut dyn Ui) -> Result<()> {
        if targets.is_empty() {
            return Err(Error::Other("no packages given".into()));
        }
        let _lock = self.begin_mutation(ui)?;
        let specs: Vec<TargetSpec> = targets.iter().map(|t| parse_spec(t)).collect::<Result<_>>()?;
        let mut catalog = self.catalog(ui)?;
        for r in specs.iter().filter_map(|s| s.repo.as_deref()) {
            catalog.load_extra(&self.paths, &self.cfg, &self.repos, r)?;
        }
        let db = Db::load(&self.paths)?;
        let reqs: Vec<Request> = specs.iter().map(|s| self.make_request(s, &catalog)).collect::<Result<_>>()?;
        let pins: Vec<PackageName> =
            reqs.iter().filter(|r| r.repo.is_some()).map(|r| r.dep.name.clone()).collect();
        let plan = Resolver::new(&catalog, &db, self.resolver_opts()).resolve_install(&reqs)?;
        for r in &reqs {
            if let Some(i) = db.get(&r.dep.name)
                && !plan.install.iter().any(|p| p.name() == &i.name) {
                    let how = match i.origin.kind {
                        OriginKind::Binary => "binary",
                        OriginKind::Source => "source",
                    };
                    ui.out(&format!("  =  {}  {}  installed ({how})", i.name, i.full_version()));
                }
        }
        if plan.is_empty() {
            self.mark_explicit(&reqs, &db, ui)?;
            return Ok(());
        }
        self.execute(plan, &db, &pins, ui)
    }

    pub(crate) fn mark_explicit(&self, reqs: &[Request], db: &Db, ui: &mut dyn Ui) -> Result<()> {
        let todo: Vec<&InstalledPackage> = reqs
            .iter()
            .filter_map(|r| db.get(&r.dep.name))
            .filter(|p| p.reason != Reason::Explicit)
            .collect();
        if todo.is_empty() || self.flags.dry_run {
            return Ok(());
        }
        let mut txn = Txn::begin(&self.paths)?;
        let r: Result<()> = (|| {
            for p in &todo {
                let mut rec = (*p).clone();
                rec.reason = Reason::Explicit;
                transaction::write_record(&mut txn, &self.paths, &rec)?;
            }
            Ok(())
        })();
        match r {
            Ok(()) => txn.commit()?,
            Err(e) => {
                let _ = txn.rollback();
                return Err(e);
            }
        }
        for p in todo {
            ui.out(&format!("  =  {}  marked explicit", p.name));
        }
        Ok(())
    }

    /// Upgrade the named packages, or every installed one when `only` is empty.
    pub fn upgrade(&self, only: &[String], ui: &mut dyn Ui) -> Result<()> {
        let _lock = self.begin_mutation(ui)?;
        let catalog = self.catalog(ui)?;
        let db = Db::load(&self.paths)?;
        let names: Vec<PackageName> = only.iter().map(|n| PackageName::new(n)).collect::<Result<_>>()?;
        for n in &names {
            if db.get(n).is_none() {
                return Err(Error::NotFound(format!("package {n} is not installed")));
            }
        }
        let only = if names.is_empty() { None } else { Some(names.as_slice()) };
        let plan = Resolver::new(&catalog, &db, self.resolver_opts()).resolve_upgrade(only, self.flags.binary)?;
        for (n, why) in &plan.held_back {
            ui.warn(&format!("!  {n}  held back: {why}"));
        }
        if plan.is_empty() {
            ui.out("nothing to upgrade");
            return Ok(());
        }
        self.execute(plan, &db, &[], ui)
    }
}

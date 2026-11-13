//! `ast -r`.

use crate::db::{Db, InstalledPackage, Reason};
use crate::error::{Error, Result};
use crate::ops::{Ast, Ui};
use crate::openrc;
use crate::transaction;
use crate::txn::Txn;
use crate::util::table;
use crate::version::PackageName;

impl Ast {
    pub(crate) fn warn_services_of_removal(&self, p: &InstalledPackage, ui: &mut dyn Ui) {
        for s in &p.services {
            let st = openrc::service_state(&self.paths.root, s);
            if st.running {
                ui.warn(&format!("!  {s}  service running: rc-service {s} stop"));
            }
            if !st.enabled_in.is_empty() {
                ui.warn(&format!("!  {s}  service enabled in {}: rc-update del {s}", st.enabled_in.join(", ")));
            }
        }
    }

    pub fn remove(&self, targets: &[String], ui: &mut dyn Ui) -> Result<()> {
        if targets.is_empty() {
            return Err(Error::Other("no packages given".into()));
        }
        let _lock = self.begin_mutation(ui)?;
        let db = Db::load(&self.paths)?;
        let mut names: Vec<PackageName> = Vec::new();
        for t in targets {
            let n = PackageName::new(t)?;
            if db.get(&n).is_none() {
                return Err(Error::NotFound(format!("package {t} is not installed")));
            }
            if !names.contains(&n) {
                names.push(n);
            }
        }
        for n in &names {
            let blockers: Vec<String> = db
                .dependents_of(n)
                .iter()
                .filter(|p| !names.contains(&p.name))
                .map(|p| p.name.to_string())
                .collect();
            if !blockers.is_empty() {
                return Err(Error::Conflict(format!(
                    "cannot remove {n}: it is required by {}; remove those first",
                    blockers.join(", ")
                )));
            }
        }
        // Orphans: automatically installed packages nothing else needs.
        let mut removing: Vec<PackageName> = names.clone();
        let mut orphans: Vec<PackageName> = Vec::new();
        loop {
            let found: Vec<PackageName> = db
                .packages
                .values()
                .filter(|p| p.reason != Reason::Explicit && !removing.contains(&p.name))
                .filter(|p| {
                    db.dependents_of(&p.name).iter().all(|d| removing.contains(&d.name))
                })
                .map(|p| p.name.clone())
                .collect();
            if found.is_empty() {
                break;
            }
            for n in found {
                orphans.push(n.clone());
                removing.push(n);
            }
        }
        let rows: Vec<Vec<String>> = names
            .iter()
            .map(|n| (n, ""))
            .chain(orphans.iter().map(|n| (n, "unneeded")))
            .map(|(n, note)| {
                vec!["-".into(), n.to_string(), db.get(n).unwrap().full_version(), String::new(), note.to_string()]
            })
            .collect();
        for l in table(&rows, "  ") {
            ui.out(&l);
        }
        ui.out("");
        for n in &removing {
            self.warn_services_of_removal(db.get(n).unwrap(), ui);
        }
        if self.flags.dry_run {
            ui.out("dry run, nothing changed");
            return Ok(());
        }
        if !self.flags.yes && !ui.confirm("proceed?", true) {
            return Err(Error::Aborted);
        }
        let mut work = db.clone();
        let mut txn = Txn::begin(&self.paths)?;
        let r: Result<Vec<String>> = (|| {
            let mut notes = vec![];
            // dependents before their dependencies
            let mut left = removing.clone();
            while !left.is_empty() {
                let pos = left
                    .iter()
                    .position(|n| work.dependents_of(n).iter().all(|d| !left.contains(&d.name) || &d.name == n))
                    .unwrap_or(0);
                let n = left.remove(pos);
                let pkg = work.get(&n).cloned().unwrap();
                let out = transaction::remove_package(&mut txn, &self.paths, &work, &pkg, &left)?;
                work.remove(&n);
                self.log.line(&format!("remove {} {}", n, pkg.full_version()));
                for c in out.kept_configs {
                    notes.push(format!("!  {c}  edited config kept (was {n})"));
                }
            }
            Ok(notes)
        })();
        match r {
            Ok(notes) => {
                txn.commit()?;
                for l in notes {
                    ui.out(&l);
                }
                ui.out(&format!("done  {} removed", removing.len()));
                Ok(())
            }
            Err(e) => {
                self.log.line(&format!("remove failed, rolling back: {e}"));
                match txn.rollback() {
                    Ok(()) => ui.warn("!  failed, rolled back"),
                    Err(re) => ui.warn(&format!("!  rollback failed: {re}")),
                }
                Err(e)
            }
        }
    }
}

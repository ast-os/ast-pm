//! Dependency resolution.
//!
//! A depth-first search with backtracking. For every requirement it considers
//! candidates ordered by repository priority, then version (highest first),
//! and rejects those that violate version constraints, conflicts or the
//! acquisition mode (`-bin` = binary only). Installed packages are kept when
//! they already satisfy a requirement. The result is an ordered plan; nothing
//! is installed here.

use crate::db::{Db, InstalledPackage, Reason};
use crate::error::{Error, Result};
use crate::repo::{Candidate, Catalog};
use crate::version::{Dependency, Op, PackageName, Version};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Binary,
    Source,
}

#[derive(Debug, Clone)]
pub struct PlanItem {
    pub cand: Candidate,
    pub method: Method,
    pub reason: Reason,
    /// The installed version this replaces (upgrade/reinstall).
    pub old: Option<InstalledPackage>,
}

impl PlanItem {
    pub fn name(&self) -> &PackageName {
        &self.cand.entry.name
    }
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    /// Dependencies first.
    pub install: Vec<PlanItem>,
    /// Installed packages removed because something replaces them.
    pub remove: Vec<(PackageName, String)>,
    /// Upgrades that could not be planned: (package, reason).
    pub held_back: Vec<(PackageName, String)>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.install.is_empty() && self.remove.is_empty()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub prefer_binary: bool,
    pub build_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub dep: Dependency,
    /// `name-bin`: only a prebuilt binary is acceptable (for the package and
    /// everything it pulls in); never fall back to building.
    pub binary_only: bool,
    /// `name:repo`: take this package from that repository only (which may
    /// belong to another channel).
    pub repo: Option<String>,
}

#[derive(Debug, Clone)]
struct Pending {
    dep: Dependency,
    binary_only: bool,
    repo: Option<String>,
    reason: Reason,
    by: String,
}

#[derive(Clone, Default)]
struct State {
    sel: BTreeMap<PackageName, PlanItem>,
    removes: BTreeMap<PackageName, String>,
}

pub struct Resolver<'a> {
    pub catalog: &'a Catalog,
    pub db: &'a Db,
    pub opts: Options,
    force: HashSet<PackageName>,
}

/// Dependencies of a plan item, including build dependencies for source builds.
fn item_deps(it: &PlanItem) -> Vec<(Dependency, Reason)> {
    let mut v: Vec<(Dependency, Reason)> =
        it.cand.entry.depends.iter().map(|d| (d.clone(), Reason::Dependency)).collect();
    if it.method == Method::Source {
        v.extend(it.cand.entry.build_depends.iter().map(|d| (d.clone(), Reason::Build)));
    }
    v
}

fn newer_than(c: &Candidate, i: &InstalledPackage) -> bool {
    (&c.entry.version, c.entry.revision) > (&i.version, i.revision)
}

impl<'a> Resolver<'a> {
    pub fn new(catalog: &'a Catalog, db: &'a Db, opts: Options) -> Self {
        Resolver { catalog, db, opts, force: HashSet::new() }
    }

    fn method_for(&self, c: &Candidate, binary_only: bool) -> Option<Method> {
        let bin = c.entry.binary.is_some();
        let src = c.entry.recipe.is_some() && self.opts.build_enabled;
        if binary_only {
            return bin.then_some(Method::Binary);
        }
        let order = if self.opts.prefer_binary {
            [(bin, Method::Binary), (src, Method::Source)]
        } else {
            [(src, Method::Source), (bin, Method::Binary)]
        };
        order.into_iter().find(|(ok, _)| *ok).map(|(_, m)| m)
    }

    /// Facts about a package as it will be after the plan: (version, depends, conflicts).
    fn effective<'s>(
        &'s self,
        st: &'s State,
    ) -> Vec<(&'s PackageName, &'s Version, Vec<Dependency>, &'s [Dependency])> {
        let mut v = Vec::new();
        for (n, it) in &st.sel {
            v.push((n, &it.cand.entry.version, item_deps(it).into_iter().map(|(d, _)| d).collect(), &it.cand.entry.conflicts[..]));
        }
        for (n, p) in &self.db.packages {
            if !st.sel.contains_key(n) && !st.removes.contains_key(n) {
                v.push((n, &p.version, p.depends.clone(), &p.conflicts[..]));
            }
        }
        v
    }

    fn compatible(&self, st: &State, c: &Candidate) -> std::result::Result<(), String> {
        let x = &c.entry;
        for (qn, qv, qdeps, qconf) in self.effective(st) {
            if qn == &x.name {
                continue;
            }
            for d in &qdeps {
                if d.name == x.name && !d.matches(&x.name, &x.version) {
                    return Err(format!("{qn} requires {d}, which conflicts with {} {}", x.name, x.version));
                }
            }
            if !x.replaces.contains(qn) {
                for d in &x.conflicts {
                    if d.matches(qn, qv) {
                        return Err(format!("{} {} conflicts with installed/planned {qn} {qv}", x.name, x.version));
                    }
                }
            }
            for d in qconf {
                if d.matches(&x.name, &x.version) {
                    return Err(format!("{qn} conflicts with {} {}", x.name, x.version));
                }
            }
        }
        for r in &x.replaces {
            if r == &x.name {
                continue;
            }
            for (qn, _, qdeps, _) in self.effective(st) {
                if qn != r && qdeps.iter().any(|d| &d.name == r) {
                    return Err(format!("{} replaces {r}, but {qn} still requires it", x.name));
                }
            }
        }
        Ok(())
    }

    fn solve(&self, mut pending: Vec<Pending>, mut st: State) -> std::result::Result<State, String> {
        let Some(p) = pending.pop() else { return Ok(st) };
        let name = p.dep.name.clone();

        if let Some(sel) = st.sel.get_mut(&name) {
            if p.dep.matches(&name, &sel.cand.entry.version) {
                if p.reason == Reason::Explicit {
                    sel.reason = Reason::Explicit;
                }
                return self.solve(pending, st);
            }
            return Err(format!(
                "{} requires {}, but {} {} is already selected",
                p.by, p.dep, name, sel.cand.entry.version
            ));
        }
        let installed = self.db.get(&name);
        let cands = match &p.repo {
            Some(r) => self.catalog.candidates_in(&name, r),
            None => self.catalog.candidates(&name),
        };
        if p.repo.is_some() {
            // An explicit repository request replaces what is installed,
            // unless the installed copy is exactly what that repo offers.
            if let Some(inst) = installed
                && !st.removes.contains_key(&name)
                    && let Some(best) = cands.iter().find(|c| p.dep.matches(&name, &c.entry.version))
                        && best.entry.version == inst.version && best.entry.revision == inst.revision {
                            return self.solve(pending, st);
                        }
        } else if let Some(inst) = installed
            && !st.removes.contains_key(&name) && !self.force.contains(&name) && p.dep.matches(&name, &inst.version) {
                return self.solve(pending, st);
            }
        if cands.is_empty() {
            return Err(match &p.repo {
                Some(r) => format!("package {name} was not found in repository {r}"),
                None => format!("package {name} (required by {}) was not found in the enabled repositories", p.by),
            });
        }
        let mut last: Option<String> = None;
        let mut matching = 0;
        for c in &cands {
            if !p.dep.matches(&name, &c.entry.version) {
                continue;
            }
            matching += 1;
            if self.force.contains(&name) && p.repo.is_none()
                && let Some(i) = installed
                    && !newer_than(c, i) {
                        continue;
                    }
            let Some(method) = self.method_for(c, p.binary_only) else {
                last = Some(if p.binary_only {
                    format!("no binary package of {name} {} is available (binary-only install requested; not falling back to a source build)", c.entry.version)
                } else if c.entry.recipe.is_some() {
                    format!("{name} {} is only available as a source recipe but building is disabled (build.enabled = false)", c.entry.version)
                } else {
                    format!("{name} {} has no usable artifact", c.entry.version)
                });
                continue;
            };
            if let Err(e) = self.compatible(&st, c) {
                last = Some(e);
                continue;
            }
            let mut st2 = st.clone();
            let item = PlanItem {
                cand: (*c).clone(),
                method,
                reason: match installed {
                    Some(i) if p.reason != Reason::Explicit => i.reason,
                    _ => p.reason,
                },
                old: installed.cloned(),
            };
            for r in &c.entry.replaces {
                if self.db.get(r).is_some() && r != &name {
                    st2.removes.insert(r.clone(), format!("replaced by {name}"));
                }
            }
            let mut pend2 = pending.clone();
            for (d, reason) in item_deps(&item) {
                pend2.push(Pending {
                    dep: d,
                    binary_only: p.binary_only,
                    repo: None,
                    reason,
                    by: format!("{name} {}", c.entry.version),
                });
            }
            st2.sel.insert(name.clone(), item);
            match self.solve(pend2, st2) {
                Ok(s) => return Ok(s),
                Err(e) => last = Some(e),
            }
        }
        if let Some(l) = last {
            return Err(l);
        }
        if matching == 0 {
            let avail: Vec<String> = cands.iter().map(|c| c.entry.version.to_string()).collect();
            return Err(format!(
                "no version of {name} satisfies `{}` (required by {}; available: {})",
                p.dep,
                p.by,
                avail.join(", ")
            ));
        }
        Err(format!("no installable candidate for {name} (required by {})", p.by))
    }

    fn order(&self, st: &State) -> Vec<PlanItem> {
        fn visit(n: &PackageName, st: &State, seen: &mut HashSet<PackageName>, out: &mut Vec<PlanItem>) {
            if !seen.insert(n.clone()) {
                return;
            }
            let it = &st.sel[n];
            for (d, _) in item_deps(it) {
                if st.sel.contains_key(&d.name) {
                    visit(&d.name, st, seen, out);
                }
            }
            out.push(it.clone());
        }
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for n in st.sel.keys() {
            visit(n, st, &mut seen, &mut out);
        }
        out
    }

    fn plan_from(&self, st: State, held: Vec<(PackageName, String)>) -> Plan {
        Plan { install: self.order(&st), remove: st.removes.into_iter().collect(), held_back: held }
    }

    pub fn resolve_install(&self, requests: &[Request]) -> Result<Plan> {
        let mut pending: Vec<Pending> = requests
            .iter()
            .rev()
            .map(|r| Pending {
                dep: r.dep.clone(),
                binary_only: r.binary_only,
                repo: r.repo.clone(),
                reason: Reason::Explicit,
                by: "the request".into(),
            })
            .collect();
        // Process in the order given.
        pending.reverse();
        pending.reverse();
        let st = self.solve(pending, State::default()).map_err(Error::Resolve)?;
        Ok(self.plan_from(st, vec![]))
    }

    /// Plan upgrades of every installed package that has a newer candidate.
    /// Packages whose upgrade cannot be resolved are reported as held back.
    pub fn resolve_upgrade(mut self, only: Option<&[PackageName]>, binary_only: bool) -> Result<Plan> {
        let mut st = State::default();
        let mut held = Vec::new();
        for (name, inst) in &self.db.packages {
            if only.is_some_and(|o| !o.contains(name)) {
                continue;
            }
            let best = self
                .catalog
                .candidates(name)
                .into_iter()
                .find(|c| self.method_for(c, binary_only).is_some());
            let Some(best) = best else { continue };
            if !newer_than(best, inst) {
                continue;
            }
            self.force.insert(name.clone());
            let pend = Pending {
                dep: Dependency { name: name.clone(), constraint: Some((Op::Ge, inst.version.clone())) },
                binary_only,
                repo: None,
                reason: inst.reason,
                by: "upgrade".into(),
            };
            match self.solve(vec![pend], st.clone()) {
                Ok(s) => st = s,
                Err(e) => {
                    self.force.remove(name);
                    held.push((name.clone(), e));
                }
            }
        }
        Ok(self.plan_from(st, held))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Channel;
    use crate::db::{InstallOrigin, OriginKind};
    use crate::index::IndexEntry;

    pub fn entry(name: &str, ver: &str, deps: &[&str]) -> IndexEntry {
        IndexEntry {
            name: PackageName::new(name).unwrap(),
            version: Version::new(ver).unwrap(),
            revision: 1,
            arch: "x86_64".into(),
            description: String::new(),
            license: String::new(),
            depends: deps.iter().map(|d| Dependency::parse(d).unwrap()).collect(),
            build_depends: vec![],
            conflicts: vec![],
            replaces: vec![],
            status: None,
            binary: Some("0".repeat(64)),
            recipe: None,
        }
    }

    fn cand(repo: &str, prio: u32, e: IndexEntry) -> Candidate {
        Candidate { repo: repo.into(), repo_url: "file:///x".into(), priority: prio, key: "k.pub".into(), channel: Channel::Stable, foreign: false, entry: e }
    }

    fn cat(v: Vec<Candidate>) -> Catalog {
        Catalog::from_candidates("x86_64", Channel::Stable, v)
    }

    fn opts() -> Options {
        Options { prefer_binary: true, build_enabled: true }
    }

    fn req(s: &str, bin: bool) -> Request {
        Request { dep: Dependency::parse(s).unwrap(), binary_only: bin, repo: None }
    }

    fn installed(name: &str, ver: &str, deps: &[&str], reason: Reason) -> InstalledPackage {
        InstalledPackage {
            name: PackageName::new(name).unwrap(),
            version: Version::new(ver).unwrap(),
            revision: 1,
            arch: "x86_64".into(),
            reason,
            installed_at: 0,
            description: String::new(),
            license: String::new(),
            depends: deps.iter().map(|d| Dependency::parse(d).unwrap()).collect(),
            conflicts: vec![],
            replaces: vec![],
            channel: None,
            status: None,
            services: vec![],
            origin: InstallOrigin { kind: OriginKind::Binary, repo: "r".into(), file: "f".into(), sha256: "0".repeat(64), source_sha256: None },
            files: vec![],
        }
    }

    fn names(p: &Plan) -> Vec<String> {
        p.install.iter().map(|i| format!("{} {}", i.name(), i.cand.entry.version)).collect()
    }

    #[test]
    fn transitive_dependencies_in_order() {
        let c = cat(vec![
            cand("r", 1, entry("nginx", "1.28.0", &["pcre2 >= 10", "zlib"])),
            cand("r", 1, entry("pcre2", "10.46", &["zlib"])),
            cand("r", 1, entry("zlib", "1.3.1", &[])),
        ]);
        let db = Db::default();
        let plan = Resolver::new(&c, &db, opts()).resolve_install(&[req("nginx", false)]).unwrap();
        assert_eq!(names(&plan), vec!["zlib 1.3.1", "pcre2 10.46", "nginx 1.28.0"]);
        assert_eq!(plan.install[2].reason, Reason::Explicit);
        assert_eq!(plan.install[0].reason, Reason::Dependency);
    }

    #[test]
    fn installed_packages_satisfy_dependencies() {
        let c = cat(vec![cand("r", 1, entry("a", "1", &["b"])), cand("r", 1, entry("b", "2", &[]))]);
        let mut db = Db::default();
        db.insert(installed("b", "1", &[], Reason::Explicit));
        let plan = Resolver::new(&c, &db, opts()).resolve_install(&[req("a", false)]).unwrap();
        assert_eq!(names(&plan), vec!["a 1"]);
    }

    #[test]
    fn version_constraints_and_backtracking() {
        // newest `lib` 2.0 is incompatible with `app` (needs < 2): resolver must fall back to 1.5
        let c = cat(vec![
            cand("r", 1, entry("app", "1", &["lib < 2"])),
            cand("r", 1, entry("lib", "2.0", &[])),
            cand("r", 1, entry("lib", "1.5", &[])),
        ]);
        let db = Db::default();
        let plan = Resolver::new(&c, &db, opts()).resolve_install(&[req("app", false)]).unwrap();
        assert!(names(&plan).contains(&"lib 1.5".to_string()));
        // unsatisfiable constraint gives a readable error
        let e = Resolver::new(&c, &db, opts()).resolve_install(&[req("lib >= 3", false)]).unwrap_err();
        assert!(e.to_string().contains("no version of lib"), "{e}");
        // missing package
        let e = Resolver::new(&c, &db, opts()).resolve_install(&[req("ghost", false)]).unwrap_err();
        assert!(e.to_string().contains("ghost") && e.to_string().contains("not found"), "{e}");
    }

    #[test]
    fn conflicts_are_detected() {
        let mut a = entry("a", "1", &[]);
        a.conflicts = vec![Dependency::parse("b").unwrap()];
        let c = cat(vec![cand("r", 1, a), cand("r", 1, entry("b", "1", &[])), cand("r", 1, entry("both", "1", &["a", "b"]))]);
        let mut db = Db::default();
        // installed b blocks a
        db.insert(installed("b", "1", &[], Reason::Explicit));
        let e = Resolver::new(&c, &db, opts()).resolve_install(&[req("a", false)]).unwrap_err();
        assert!(e.to_string().contains("conflicts"), "{e}");
        // within one transaction
        let e = Resolver::new(&c, &Db::default(), opts()).resolve_install(&[req("both", false)]).unwrap_err();
        assert!(e.to_string().contains("conflict"), "{e}");
        // installed package declaring a conflict blocks the newcomer
        let mut db = Db::default();
        let mut ia = installed("a", "1", &[], Reason::Explicit);
        ia.conflicts = vec![Dependency::parse("b").unwrap()];
        db.insert(ia);
        assert!(Resolver::new(&c, &db, opts()).resolve_install(&[req("b", false)]).is_err());
    }

    #[test]
    fn replaces_schedules_removal() {
        let mut new = entry("busybox-ng", "1", &[]);
        new.replaces = vec![PackageName::new("busybox").unwrap()];
        let c = cat(vec![cand("r", 1, new)]);
        let mut db = Db::default();
        db.insert(installed("busybox", "1", &[], Reason::Explicit));
        let plan = Resolver::new(&c, &db, opts()).resolve_install(&[req("busybox-ng", false)]).unwrap();
        assert_eq!(plan.remove.len(), 1);
        assert_eq!(plan.remove[0].0.as_str(), "busybox");
        // but not when another package still needs it
        db.insert(installed("needs", "1", &["busybox"], Reason::Explicit));
        assert!(Resolver::new(&c, &db, opts()).resolve_install(&[req("busybox-ng", false)]).is_err());
    }

    #[test]
    fn repository_priority_beats_version() {
        let c = cat(vec![
            cand("space", 50, entry("tool", "9.0", &[])),
            cand("ast", 100, entry("tool", "1.0", &[])),
        ]);
        let plan = Resolver::new(&c, &Db::default(), opts()).resolve_install(&[req("tool", false)]).unwrap();
        assert_eq!(plan.install[0].cand.repo, "ast");
        // constraint can still force the lower-priority repo
        let plan = Resolver::new(&c, &Db::default(), opts()).resolve_install(&[req("tool >= 5", false)]).unwrap();
        assert_eq!(plan.install[0].cand.repo, "space");
        // same priority: highest version wins
        let c = cat(vec![cand("a", 10, entry("t", "1", &[])), cand("b", 10, entry("t", "2", &[]))]);
        let plan = Resolver::new(&c, &Db::default(), opts()).resolve_install(&[req("t", false)]).unwrap();
        assert_eq!(plan.install[0].cand.entry.version.as_str(), "2");
    }

    #[test]
    fn binary_only_never_falls_back_to_source() {
        let mut src_only = entry("nginx", "1", &[]);
        src_only.binary = None;
        src_only.recipe = Some("0".repeat(64));
        let c = cat(vec![cand("r", 1, src_only.clone())]);
        let db = Db::default();
        // plain install builds from source
        let plan = Resolver::new(&c, &db, opts()).resolve_install(&[req("nginx", false)]).unwrap();
        assert_eq!(plan.install[0].method, Method::Source);
        // -bin refuses, explaining why
        let e = Resolver::new(&c, &db, opts()).resolve_install(&[req("nginx", true)]).unwrap_err();
        assert!(e.to_string().contains("no binary package"), "{e}");
        // building disabled: plain install fails clearly
        let e = Resolver::new(&c, &db, Options { build_enabled: false, ..opts() }).resolve_install(&[req("nginx", false)]).unwrap_err();
        assert!(e.to_string().contains("building is disabled"), "{e}");
    }

    #[test]
    fn binary_only_propagates_to_dependencies() {
        let mut dep = entry("dep", "1", &[]);
        dep.binary = None;
        dep.recipe = Some("0".repeat(64));
        let c = cat(vec![cand("r", 1, entry("app", "1", &["dep"])), cand("r", 1, dep)]);
        assert!(Resolver::new(&c, &Db::default(), opts()).resolve_install(&[req("app", true)]).is_err());
        assert!(Resolver::new(&c, &Db::default(), opts()).resolve_install(&[req("app", false)]).is_ok());
    }

    #[test]
    fn prefer_binary_setting_and_build_deps() {
        let mut both = entry("pkg", "1", &[]);
        both.recipe = Some("0".repeat(64));
        both.build_depends = vec![Dependency::parse("gcc").unwrap()];
        let c = cat(vec![cand("r", 1, both), cand("r", 1, entry("gcc", "1", &[]))]);
        let p = Resolver::new(&c, &Db::default(), opts()).resolve_install(&[req("pkg", false)]).unwrap();
        assert_eq!(p.install[0].method, Method::Binary);
        assert_eq!(p.install.len(), 1); // build deps not pulled for a binary install
        let p = Resolver::new(&c, &Db::default(), Options { prefer_binary: false, ..opts() }).resolve_install(&[req("pkg", false)]).unwrap();
        assert_eq!(p.install.len(), 2);
        let gcc = p.install.iter().find(|i| i.name().as_str() == "gcc").unwrap();
        assert_eq!(gcc.reason, Reason::Build);
        assert_eq!(p.install[0].name().as_str(), "gcc"); // built first
    }

    #[test]
    fn explicit_repo_request_uses_only_that_repo_and_replaces_installed() {
        let c = cat(vec![
            cand("ast", 100, entry("tg", "1.0", &[])),
            cand("space-edge", 50, entry("tg", "2.0", &["dep"])),
            cand("ast", 100, entry("dep", "1", &[])),
        ]);
        let r = Request { dep: Dependency::parse("tg").unwrap(), binary_only: false, repo: Some("space-edge".into()) };
        let plan = Resolver::new(&c, &Db::default(), opts()).resolve_install(std::slice::from_ref(&r)).unwrap();
        assert_eq!(plan.install.iter().find(|i| i.name().as_str() == "tg").unwrap().cand.repo, "space-edge");
        // dependencies still come from the normal repositories
        assert_eq!(plan.install.iter().find(|i| i.name().as_str() == "dep").unwrap().cand.repo, "ast");
        // installed 1.0 from ast is replaced by 2.0 from space-edge
        let mut db = Db::default();
        db.insert(installed("tg", "1.0", &[], Reason::Explicit));
        let plan = Resolver::new(&c, &db, opts()).resolve_install(std::slice::from_ref(&r)).unwrap();
        assert!(plan.install.iter().any(|i| i.name().as_str() == "tg" && i.old.is_some()));
        // already at what that repo offers: nothing to do
        let mut db = Db::default();
        db.insert(installed("tg", "2.0", &["dep"], Reason::Explicit));
        db.insert(installed("dep", "1", &[], Reason::Dependency));
        assert!(Resolver::new(&c, &db, opts()).resolve_install(&[r]).unwrap().install.is_empty());
        // unknown repo / package absent from the repo
        let r = Request { dep: Dependency::parse("dep").unwrap(), binary_only: false, repo: Some("space-edge".into()) };
        let e = Resolver::new(&c, &Db::default(), opts()).resolve_install(&[r]).unwrap_err();
        assert!(e.to_string().contains("not found in repository space-edge"), "{e}");
    }

    #[test]
    fn foreign_candidates_are_a_last_resort_for_dependencies() {
        let mut foreign = cand("edge", 50, entry("lib", "3.0", &[]));
        foreign.foreign = true;
        let mut c = cat(vec![cand("ast", 100, entry("app", "1", &["lib >= 2"]))]);
        c.foreign.push(foreign);
        let plan = Resolver::new(&c, &Db::default(), opts()).resolve_install(&[req("app", false)]).unwrap();
        let lib = plan.install.iter().find(|i| i.name().as_str() == "lib").unwrap();
        assert!(lib.cand.foreign);
        // when the stable repo can satisfy it, it is preferred
        c.all.push(cand("ast", 100, entry("lib", "2.0", &[])));
        let plan = Resolver::new(&c, &Db::default(), opts()).resolve_install(&[req("app", false)]).unwrap();
        assert!(!plan.install.iter().find(|i| i.name().as_str() == "lib").unwrap().cand.foreign);
    }

    #[test]
    fn dependency_cycles_terminate() {
        let c = cat(vec![cand("r", 1, entry("a", "1", &["b"])), cand("r", 1, entry("b", "1", &["a"]))]);
        let p = Resolver::new(&c, &Db::default(), opts()).resolve_install(&[req("a", false)]).unwrap();
        assert_eq!(p.install.len(), 2);
    }

    #[test]
    fn upgrade_plans_newer_versions_only() {
        let c = cat(vec![
            cand("r", 1, entry("a", "2", &["c"])),
            cand("r", 1, entry("b", "1", &[])),
            cand("r", 1, entry("c", "1", &[])),
        ]);
        let mut db = Db::default();
        db.insert(installed("a", "1", &[], Reason::Explicit));
        db.insert(installed("b", "1", &[], Reason::Explicit));
        let p = Resolver::new(&c, &db, opts()).resolve_upgrade(None, false).unwrap();
        assert_eq!(names(&p), vec!["c 1", "a 2"]);
        assert!(p.install[1].old.is_some());
        assert_eq!(p.install[0].reason, Reason::Dependency);
        assert_eq!(p.install[1].reason, Reason::Explicit);
    }

    #[test]
    fn upgrade_holds_back_blocked_packages() {
        let c = cat(vec![cand("r", 1, entry("lib", "2", &[])), cand("r", 1, entry("app", "1", &["lib < 2"]))]);
        let mut db = Db::default();
        db.insert(installed("lib", "1", &[], Reason::Dependency));
        db.insert(installed("app", "1", &["lib < 2"], Reason::Explicit));
        let p = Resolver::new(&c, &db, opts()).resolve_upgrade(None, false).unwrap();
        assert!(p.install.is_empty());
        assert_eq!(p.held_back.len(), 1);
        assert_eq!(p.held_back[0].0.as_str(), "lib");
    }

    #[test]
    fn upgrade_to_new_release_of_same_version() {
        let mut e = entry("a", "1", &[]);
        e.revision = 2;
        let c = cat(vec![cand("r", 1, e)]);
        let mut db = Db::default();
        db.insert(installed("a", "1", &[], Reason::Explicit));
        let p = Resolver::new(&c, &db, opts()).resolve_upgrade(None, false).unwrap();
        assert_eq!(p.install.len(), 1);
        assert_eq!(p.install[0].cand.entry.revision, 2);
    }
}

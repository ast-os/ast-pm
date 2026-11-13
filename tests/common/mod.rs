#![allow(dead_code)]
//! Test harness: temporary root + local signed repositories. Nothing here
//! touches the real system.

use ast::config::Channel;
use ast::ops::{Flags, Ast, Ui};
use ast::package::{Release, Status, pack_directory};
use ast::repogen::generate_index;
use ast::security::SecretKey;
use ast::version::{Dependency, PackageName, Version};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

pub struct TestUi {
    pub out: Vec<String>,
    pub warns: Vec<String>,
    pub asked: Vec<String>,
    pub answers: VecDeque<bool>,
}

impl TestUi {
    pub fn new() -> Self {
        TestUi { out: vec![], warns: vec![], asked: vec![], answers: VecDeque::new() }
    }
    pub fn answering(a: &[bool]) -> Self {
        let mut u = Self::new();
        u.answers = a.iter().copied().collect();
        u
    }
    pub fn all(&self) -> String {
        self.out.iter().chain(self.warns.iter()).cloned().collect::<Vec<_>>().join("\n")
    }
}

impl Ui for TestUi {
    fn out(&mut self, l: &str) {
        self.out.push(l.to_string());
    }
    fn warn(&mut self, l: &str) {
        self.warns.push(l.to_string());
    }
    fn confirm(&mut self, p: &str, _d: bool) -> bool {
        self.asked.push(p.to_string());
        self.answers.pop_front().unwrap_or(false)
    }
}

pub struct Repo {
    pub name: String,
    pub dir: PathBuf,
    pub key: SecretKey,
    pub channel: Channel,
    pub priority: u32,
}

pub struct Pkg {
    pub name: String,
    pub version: String,
    pub revision: u32,
    pub deps: Vec<String>,
    pub conflicts: Vec<String>,
    pub replaces: Vec<String>,
    pub files: Vec<(String, String, u32)>,
    pub symlinks: Vec<(String, String)>,
    pub configs: Vec<String>,
    pub status: Option<Status>,
    pub notice: Option<String>,
}

pub fn pkg(name: &str, version: &str) -> Pkg {
    Pkg {
        name: name.into(),
        version: version.into(),
        revision: 1,
        deps: vec![],
        conflicts: vec![],
        replaces: vec![],
        files: vec![(format!("usr/bin/{name}"), format!("{name} {version}\n"), 0o755)],
        symlinks: vec![],
        configs: vec![],
        status: None,
        notice: None,
    }
}

impl Pkg {
    pub fn deps(mut self, d: &[&str]) -> Self {
        self.deps = d.iter().map(|s| s.to_string()).collect();
        self
    }
    pub fn file(mut self, path: &str, content: &str) -> Self {
        self.files.push((path.into(), content.into(), 0o644));
        self
    }
    pub fn only_files(mut self, f: &[(&str, &str)]) -> Self {
        self.files = f.iter().map(|(p, c)| (p.to_string(), c.to_string(), 0o644)).collect();
        self
    }
    pub fn config(mut self, path: &str, content: &str) -> Self {
        self.files.push((path.trim_start_matches('/').into(), content.into(), 0o644));
        self.configs.push(path.into());
        self
    }
    pub fn status(mut self, s: Status) -> Self {
        self.status = Some(s);
        self
    }
    pub fn conflicts(mut self, c: &[&str]) -> Self {
        self.conflicts = c.iter().map(|s| s.to_string()).collect();
        self
    }
    pub fn replaces(mut self, c: &[&str]) -> Self {
        self.replaces = c.iter().map(|s| s.to_string()).collect();
        self
    }
    pub fn service(mut self, name: &str) -> Self {
        self.files.push((format!("etc/init.d/{name}"), "#!/sbin/openrc-run\n".into(), 0o755));
        self
    }
    pub fn notice(mut self, n: &str) -> Self {
        self.notice = Some(n.into());
        self
    }
}

pub struct Env {
    pub dir: tempfile::TempDir,
    pub root: PathBuf,
    pub repos: Vec<Repo>,
    pub allow_untested: bool,
    pub prefer_binary: bool,
    pub build_enabled: bool,
    pub system_channel: Channel,
}

impl Env {
    pub fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        Env { dir, root, repos: vec![], allow_untested: true, prefer_binary: true, build_enabled: true, system_channel: Channel::Stable }
    }

    pub fn add_repo(&mut self, name: &str, priority: u32) -> usize {
        self.add_repo_ch(name, priority, Channel::Stable)
    }

    pub fn add_repo_ch(&mut self, name: &str, priority: u32, channel: Channel) -> usize {
        let dir = self.dir.path().join(format!("repo-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        self.repos.push(Repo { name: name.into(), dir, key: SecretKey::generate().unwrap(), channel, priority });
        self.repos.len() - 1
    }

    pub fn add(&self, repo: usize, p: &Pkg) {
        let r = &self.repos[repo];
        let stage = self.dir.path().join(format!("stage-{}-{}-{}", r.name, p.name, p.version));
        let _ = std::fs::remove_dir_all(&stage);
        for (path, content, mode) in &p.files {
            let full = stage.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, content).unwrap();
            std::os::unix::fs::PermissionsExt::set_mode(&mut std::fs::metadata(&full).unwrap().permissions(), *mode);
            std::fs::set_permissions(&full, std::os::unix::fs::PermissionsExt::from_mode(*mode)).unwrap();
        }
        for (path, target) in &p.symlinks {
            let full = stage.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(target, full).unwrap();
        }
        let mut m = ast::package::Metadata::parse(&format!(
            "[package]\nname = \"{}\"\nversion = \"{}\"\narch = \"x86_64\"\n",
            p.name, p.version
        ))
        .unwrap();
        m.revision = p.revision;
        m.description = format!("the {} package", p.name);
        m.license = "MIT".into();
        m.depends = p.deps.iter().map(|d| Dependency::parse(d).unwrap()).collect();
        m.conflicts = p.conflicts.iter().map(|d| Dependency::parse(d).unwrap()).collect();
        m.replaces = p.replaces.iter().map(|d| PackageName::new(d).unwrap()).collect();
        m.config_files = p.configs.clone();
        m.notice = p.notice.clone();
        m.release = Release { channel: Some(r.channel), status: p.status };
        let out = r.dir.join(format!("{}-{}-{}.ast", p.name, p.version, p.revision));
        pack_directory(&stage, m, &out).unwrap();
        let _ = Version::new(&p.version).unwrap();
    }

    /// Add a source-only package: a recipe plus a tarball containing `hello.sh`.
    pub fn add_recipe(&self, repo: usize, name: &str, version: &str, deps: &[&str], build_deps: &[&str], script: &str) {
        let r = &self.repos[repo];
        let tgz = r.dir.join(format!("{name}-{version}.tar.gz"));
        {
            let enc = flate2::write::GzEncoder::new(std::fs::File::create(&tgz).unwrap(), flate2::Compression::fast());
            let mut b = tar::Builder::new(enc);
            let body = format!("#!/bin/sh\necho {name}-{version}\n");
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o755);
            b.append_data(&mut h, format!("{name}-{version}/hello.sh"), body.as_bytes()).unwrap();
            b.into_inner().unwrap().finish().unwrap();
        }
        let sha = ast::security::sha256_file(&tgz).unwrap();
        let q = |v: &[&str]| v.iter().map(|d| format!("\"{d}\"")).collect::<Vec<_>>().join(", ");
        let text = format!(
            "[package]\nname = \"{name}\"\nversion = \"{version}\"\ndescription = \"source {name}\"\nlicense = \"MIT\"\narch = [\"x86_64\"]\ndepends = [{}]\nbuild_depends = [{}]\n[source]\nurl = \"{name}-{version}.tar.gz\"\nsha256 = \"{sha}\"\n[build]\nbuild = '''{script}'''\n",
            q(deps),
            q(build_deps)
        );
        std::fs::write(r.dir.join(format!("{name}-{version}-1.recipe.toml")), text).unwrap();
    }

    /// Sign packages and write the index of a repository.
    pub fn publish(&self, repo: usize) {
        let r = &self.repos[repo];
        generate_index(&r.dir, &r.name, "x86_64", r.channel, &r.key).unwrap();
    }

    /// Write /etc/ast config for the root from the current state.
    pub fn configure(&self) {
        let etc = self.root.join("etc/ast");
        std::fs::create_dir_all(etc.join("keys")).unwrap();
        std::fs::write(
            etc.join("ast.toml"),
            format!(
                "[core]\narchitecture = \"x86_64\"\nchannel = \"{}\"\n[packages]\nallow_untested = {}\nprefer_binary = {}\n[build]\nenabled = {}\njobs = 1\ndirectory = \"/var/cache/ast/build\"\n",
                self.system_channel, self.allow_untested, self.prefer_binary, self.build_enabled
            ),
        )
        .unwrap();
        let mut repos = String::new();
        for r in &self.repos {
            repos.push_str(&format!(
                "[{}]\nurl = \"file://{}\"\nenabled = true\npriority = {}\nkey = \"{}.pub\"\nchannel = \"{}\"\n\n",
                r.name, r.dir.display(), r.priority, r.name, r.channel
            ));
            std::fs::write(etc.join("keys").join(format!("{}.pub", r.name)), format!("{}\n", r.key.public_hex())).unwrap();
        }
        std::fs::write(etc.join("repos.toml"), repos).unwrap();
    }

    pub fn ast(&self) -> Ast {
        self.ast_with(Flags { yes: true, ..Default::default() })
    }

    pub fn ast_with(&self, flags: Flags) -> Ast {
        self.configure();
        Ast::open(&self.root, flags).unwrap()
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
    pub fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.path(rel)).unwrap()
    }
    pub fn exists(&self, rel: &str) -> bool {
        std::fs::symlink_metadata(self.path(rel)).is_ok()
    }
    pub fn installed(&self, name: &str) -> bool {
        self.root.join(format!("var/lib/ast/db/installed/{name}.toml")).exists()
    }
}

/// Every regular file/symlink/dir below `p` as a sorted list (for before/after comparisons).
pub fn snapshot(p: &Path) -> Vec<String> {
    fn walk(base: &Path, p: &Path, out: &mut Vec<String>) {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let path = e.path();
                let rel = path.strip_prefix(base).unwrap().display().to_string();
                let md = std::fs::symlink_metadata(&path).unwrap();
                if md.is_dir() {
                    out.push(format!("{rel}/"));
                    walk(base, &path, out);
                } else if md.file_type().is_symlink() {
                    out.push(format!("{rel} -> {}", std::fs::read_link(&path).unwrap().display()));
                } else {
                    out.push(format!("{rel} {}", ast::security::sha256_file(&path).unwrap()));
                }
            }
        }
    }
    let mut v = vec![];
    walk(p, p, &mut v);
    v.sort();
    v
}

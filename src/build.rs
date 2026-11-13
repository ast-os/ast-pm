//! Source recipes and on-device (or CI) builds.
//!
//! Trust model: a recipe is code. It is only ever obtained from a repository
//! whose signed index contains the recipe's SHA-256, and `ast` asks the user
//! before running any recipe script. The script runs under `sh -e` with a
//! cleared environment inside the build directory, as an unprivileged user
//! when `ast` itself runs as root. There is NO sandbox: a malicious recipe
//! can still read world-readable files and use the network. See
//! docs/security.md.

use crate::archive::normalize_rel;
use crate::config::{BuildCfg, KNOWN_ARCHES, SandboxMode};
use crate::download;
use crate::error::{Error, IoCtx, Result};
use crate::package::{Metadata, Origin, Release, pack_directory};
use crate::security::is_hex_sha256;
use crate::version::{Dependency, PackageName, Version};
use serde::Deserialize;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const SOURCE_DATE_EPOCH: &str = "315532800";
pub const RECIPE_SUFFIX: &str = ".recipe.toml";

#[derive(Debug, Clone, Deserialize)]
pub struct SourceSpec {
    /// Absolute URL, or a path relative to the repository URL.
    pub url: String,
    pub sha256: String,
    /// Leading path components to strip from the tarball (default 1).
    #[serde(default = "one")]
    pub strip: usize,
}

/// How a package is built. A `style` supplies the usual `build` and `install` scripts; a script
/// written in the recipe replaces the one of the style. The phases run in this order, each as
/// `sh -e` in the unpacked source: `prepare`, `build`, `install`, `fixup`. Whatever ends up
/// in `$DESTDIR` is the package.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BuildSpec {
    /// `gnu` (configure, make), `cmake`, `meson` or `cargo`.
    #[serde(default)]
    pub style: Option<Style>,
    /// Extra arguments for configure, cmake, meson or cargo, written as shell words.
    #[serde(default)]
    pub configure: Vec<String>,
    /// Extra arguments for make or ninja.
    #[serde(default)]
    pub make: Vec<String>,
    /// Extra arguments for `make install`.
    #[serde(default)]
    pub install_args: Vec<String>,
    /// Build in a separate `build` directory (gnu style; gcc, binutils and glibc want it).
    #[serde(default)]
    pub out_of_tree: bool,
    /// The programs a cargo package installs into `/usr/bin`.
    #[serde(default)]
    pub bins: Vec<String>,
    /// Runs first: apply patches, generate files, ...
    #[serde(default)]
    pub prepare: Option<String>,
    /// The main build step.
    #[serde(default)]
    pub build: Option<String>,
    /// Copies the results into `$DESTDIR`.
    #[serde(default)]
    pub install: Option<String>,
    /// Runs last, after the install: tidy up inside `$DESTDIR`.
    #[serde(default)]
    pub fixup: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Style {
    Gnu,
    Cmake,
    Meson,
    Cargo,
}

impl BuildSpec {
    /// The scripts to run, in order: `(phase, script)`.
    pub fn phases(&self) -> Vec<(&'static str, String)> {
        let args = |v: &[String]| if v.is_empty() { String::new() } else { format!(" {}", v.join(" ")) };
        let (configure, make, inst) = (args(&self.configure), args(&self.make), args(&self.install_args));
        let (mut build, mut install) = (None, None);
        match self.style {
            Some(Style::Gnu) => {
                let (enter, dots) = if self.out_of_tree { ("mkdir -p build\ncd build\n", "..") } else { ("", ".") };
                build = Some(format!(
                    "{enter}{dots}/configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var{configure}\nmake -j\"$JOBS\"{make}\n"
                ));
                install = Some(format!("{}make DESTDIR=\"$DESTDIR\" install{inst}\n", if self.out_of_tree { "cd build\n" } else { "" }));
            }
            Some(Style::Cmake) => {
                build = Some(format!(
                    "cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release{configure}\ncmake --build build -j\"$JOBS\"{make}\n"
                ));
                install = Some("DESTDIR=\"$DESTDIR\" cmake --install build\n".to_string());
            }
            Some(Style::Meson) => {
                build = Some(format!("meson setup build --prefix=/usr --buildtype=release{configure}\nninja -C build -j\"$JOBS\"{make}\n"));
                install = Some("DESTDIR=\"$DESTDIR\" ninja -C build install\n".to_string());
            }
            Some(Style::Cargo) => {
                build = Some(format!("cargo build --release --locked{configure}\n"));
                install = Some(self.bins.iter().map(|b| format!("install -Dm755 target/release/{b} \"$DESTDIR/usr/bin/{b}\"\n")).collect());
            }
            None => {}
        }
        let pick = |own: &Option<String>, default: Option<String>| own.clone().or(default);
        [
            ("prepare", self.prepare.clone()),
            ("build", pick(&self.build, build)),
            ("install", pick(&self.install, install)),
            ("fixup", self.fixup.clone()),
        ]
        .into_iter()
        .filter_map(|(n, s)| s.filter(|t| !t.trim().is_empty()).map(|t| (n, t)))
        .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Recipe {
    pub name: PackageName,
    pub version: Version,
    pub revision: u32,
    pub description: String,
    pub license: String,
    /// Architectures the package can be built for (`any` allowed).
    pub arch: Vec<String>,
    pub depends: Vec<Dependency>,
    pub build_depends: Vec<Dependency>,
    pub conflicts: Vec<Dependency>,
    pub replaces: Vec<PackageName>,
    pub config_files: Vec<String>,
    pub notice: Option<String>,
    pub release: Release,
    pub source: SourceSpec,
    pub build: BuildSpec,
}

/// File layout: `[package]`, `[source]`, `[build]` and an optional `[release]`.
#[derive(Deserialize)]
struct Raw {
    package: RawPackage,
    source: SourceSpec,
    build: BuildSpec,
    #[serde(default)]
    release: Release,
}

#[derive(Deserialize)]
struct RawPackage {
    name: PackageName,
    version: Version,
    #[serde(default = "one32")]
    revision: u32,
    #[serde(default)]
    description: String,
    #[serde(default)]
    license: String,
    arch: Vec<String>,
    #[serde(default)]
    depends: Vec<Dependency>,
    #[serde(default)]
    build_depends: Vec<Dependency>,
    #[serde(default)]
    conflicts: Vec<Dependency>,
    #[serde(default)]
    replaces: Vec<PackageName>,
    #[serde(default)]
    config_files: Vec<String>,
    #[serde(default)]
    notice: Option<String>,
}

fn one() -> usize {
    1
}
fn one32() -> u32 {
    1
}

impl Recipe {
    pub fn parse(text: &str) -> Result<Recipe> {
        let raw: Raw = toml::from_str(text).map_err(|e| Error::Parse(format!("recipe: {e}")))?;
        let p = raw.package;
        let r = Recipe {
            name: p.name,
            version: p.version,
            revision: p.revision,
            description: p.description,
            license: p.license,
            arch: p.arch,
            depends: p.depends,
            build_depends: p.build_depends,
            conflicts: p.conflicts,
            replaces: p.replaces,
            config_files: p.config_files,
            notice: p.notice,
            release: raw.release,
            source: raw.source,
            build: raw.build,
        };
        r.validate()?;
        Ok(r)
    }

    pub fn load(path: &Path) -> Result<Recipe> {
        let text = std::fs::read_to_string(path).ctx("cannot read recipe", path)?;
        Recipe::parse(&text)
    }

    fn validate(&self) -> Result<()> {
        if self.arch.is_empty() {
            return Err(Error::Parse(format!("recipe {}: `arch` must list at least one architecture", self.name)));
        }
        for a in &self.arch {
            if a != "any" && !KNOWN_ARCHES.contains(&a.as_str()) {
                return Err(Error::Parse(format!("recipe {}: unknown architecture {a:?}", self.name)));
            }
        }
        if !is_hex_sha256(&self.source.sha256) {
            return Err(Error::Parse(format!("recipe {}: source.sha256 must be a SHA-256 hex digest", self.name)));
        }
        if self.build.phases().is_empty() {
            return Err(Error::Parse(format!(
                "recipe {}: [build] needs a `style` or at least one non-empty script (`prepare`, `build`, `install` or `fixup`)",
                self.name
            )));
        }
        Ok(())
    }

    pub fn supports(&self, arch: &str) -> bool {
        self.arch.iter().any(|a| a == "any" || a == arch)
    }

    pub fn source_url(&self, repo_url: Option<&str>) -> Result<String> {
        let u = &self.source.url;
        if u.starts_with("http://") || u.starts_with("https://") || u.starts_with("file://") || u.starts_with('/') {
            Ok(u.clone())
        } else if let Some(base) = repo_url {
            normalize_rel(u).map_err(|_| Error::Parse(format!("recipe {}: unsafe source path {u:?}", self.name)))?;
            Ok(download::join_url(base, u))
        } else {
            Err(Error::Parse(format!(
                "recipe {}: relative source url {u:?} needs a repository to resolve against",
                self.name
            )))
        }
    }
}

/// Everything needed to build one package.
pub struct BuildJob<'a> {
    pub recipe: &'a Recipe,
    pub repo_url: Option<&'a str>,
    pub arch: &'a str,
    pub build_dir: &'a Path,
    pub out_dir: &'a Path,
    pub jobs: u32,
    pub cfg: &'a BuildCfg,
    pub verify_checksums: bool,
}

/// Run the recipe and return the path of the finished `.ast`.
pub fn build_package(job: &BuildJob) -> Result<PathBuf> {
    let r = job.recipe;
    if !r.supports(job.arch) {
        return Err(Error::Build(format!(
            "{} {} does not support architecture {} (supports: {})",
            r.name, r.version, job.arch, r.arch.join(", ")
        )));
    }
    crate::util::mkdir_private(job.build_dir, 0o755)?;
    std::fs::create_dir_all(job.out_dir).ctx("cannot create", job.out_dir)?;
    let work = job.build_dir.join(format!("{}-{}", r.name, r.version));
    remove_tree(&work)?;
    crate::util::mkdir_private(&work, 0o755)?;
    let log_path = job.build_dir.join(format!("{}-{}.log", r.name, r.version));

    let res = build_inner(job, &work, &log_path);
    // Always clean temporary data; keep only the log on failure.
    if let Err(e) = remove_tree(&work) {
        eprintln!("warning: cannot clean {}: {e}", work.display());
    }
    match res {
        Ok(p) => {
            let _ = std::fs::remove_file(&log_path);
            Ok(p)
        }
        Err(Error::Build(m)) => Err(Error::Build(format!("{m}\n  full build log: {}", log_path.display()))),
        Err(e) => Err(e),
    }
}

/// The source archive: from the cache of earlier builds, else from a mirror, else from upstream.
/// A downloaded archive is kept in `sources/` next to the build directory, named by its checksum.
fn fetch_source(job: &BuildJob, url: &str, dest: &Path) -> Result<()> {
    let r = job.recipe;
    let expected = job.verify_checksums.then_some(r.source.sha256.as_str());
    let cache = job.build_dir.parent().map(|p| p.join("sources"));
    let cached = cache.as_ref().map(|c| c.join(&r.source.sha256));
    if let Some(c) = cached.as_ref().filter(|c| c.is_file())
        && crate::security::sha256_file(c).is_ok_and(|h| h == r.source.sha256)
        && std::fs::copy(c, dest).is_ok()
    {
        return Ok(());
    }
    let file_name = url.rsplit('/').next().unwrap_or("source");
    let mirrors = job.cfg.mirrors.iter().map(|m| format!("{}/{file_name}", m.trim_end_matches('/')));
    let mut last = None;
    for u in mirrors.chain(std::iter::once(url.to_string())) {
        match download::download_to(&u, dest, expected, 4 << 30) {
            Ok(()) => {
                if let Some(c) = cached.as_ref().filter(|_| expected.is_some()) {
                    let _ = std::fs::create_dir_all(c.parent().unwrap_or(c));
                    let _ = std::fs::copy(dest, c);
                }
                return Ok(());
            }
            Err(e) => last = Some(e),
        }
    }
    Err(match last {
        Some(Error::Verify(m)) => Error::Verify(format!("source of {}: {m}", r.name)),
        Some(e) => e,
        None => Error::Network(format!("no source for {}", r.name)),
    })
}

fn build_inner(job: &BuildJob, work: &Path, log_path: &Path) -> Result<PathBuf> {
    let r = job.recipe;
    let url = r.source_url(job.repo_url)?;
    let src_file = work.join("source.archive");
    fetch_source(job, &url, &src_file)?;
    let src_dir = work.join("src");
    let dest_dir = work.join("dest");
    for d in [&src_dir, &dest_dir] {
        crate::util::mkdir_private(d, 0o755)?;
    }
    extract_source(&src_file, &src_dir, r.source.strip)?;

    if crate::util::is_root() {
        chown_tree(work, job.cfg.uid, job.cfg.gid)?;
    }
    File::create(log_path).ctx("cannot create build log", log_path)?;
    let sandbox = choose_sandbox(job.cfg.sandbox, find_in_path("bwrap", std::env::var_os("PATH")))?;
    if sandbox.is_none() {
        eprintln!("warning: build scripts of {} run WITHOUT sandbox", r.name);
    }
    for (phase, script) in r.build.phases() {
        let script = script.as_str();
        let mut log = std::fs::OpenOptions::new().append(true).open(log_path).ctx("cannot open build log", log_path)?;
        let _ = writeln!(log, "==> {phase}");
        let mut cmd = match &sandbox {
            Some(bwrap) => {
                let mut c = Command::new(bwrap);
                c.args(sandbox_args(work, &src_dir));
                c.arg("--").arg("/bin/sh").arg("-e").arg("-c").arg(script);
                c
            }
            None => {
                let mut c = Command::new("/bin/sh");
                c.arg("-e").arg("-c").arg(script);
                c
            }
        };
        cmd.env_clear()
            .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .env("HOME", work)
            .env("LC_ALL", "C")
            .env("MSRC", &src_dir)
            .env("DESTDIR", &dest_dir)
            .env("JOBS", job.jobs.to_string())
            .env("MAKEFLAGS", format!("-j{}", job.jobs))
            .env("ARCH", job.arch)
            .env("PKGNAME", r.name.as_str())
            .env("PKGVER", r.version.as_str())
            .env("PHASE", phase)
            .env("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)
            .current_dir(&src_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().ctx("cannot dup log", log_path)?))
            .stderr(Stdio::from(log));
        if crate::util::is_root() {
            std::os::unix::process::CommandExt::uid(&mut cmd, job.cfg.uid);
            std::os::unix::process::CommandExt::gid(&mut cmd, job.cfg.gid);
        }
        let status = cmd
            .status()
            .map_err(|e| Error::Build(format!("cannot start /bin/sh for {}: {e}", r.name)))?;
        if !status.success() {
            return Err(Error::Build(format!(
                "{phase} script of {} {} failed ({status}); last log lines:\n{}",
                r.name,
                r.version,
                tail(log_path, 15)
            )));
        }
    }
    if std::fs::read_dir(&dest_dir).ctx("cannot read", &dest_dir)?.next().is_none() {
        return Err(Error::Build(format!(
            "build of {} installed nothing into $DESTDIR (use `make install DESTDIR=\"$DESTDIR\"`)",
            r.name
        )));
    }
    let meta = Metadata {
        name: r.name.clone(),
        version: r.version.clone(),
        revision: r.revision,
        arch: if r.arch.iter().any(|a| a == "any") { "any".into() } else { job.arch.to_string() },
        description: r.description.clone(),
        license: r.license.clone(),
        depends: r.depends.clone(),
        conflicts: r.conflicts.clone(),
        replaces: r.replaces.clone(),
        config_files: r.config_files.clone(),
        setuid: vec![],
        notice: r.notice.clone(),
        release: r.release.clone(),
        origin: Origin {
            builder: Some(format!("ast-pm {}", env!("CARGO_PKG_VERSION"))),
            built_at: Some(crate::util::now()),
            source_url: Some(url),
            source_sha256: Some(r.source.sha256.clone()),
        },
        payload_sha256: String::new(),
    };
    let out = job.out_dir.join(format!("{}-{}-{}.{}", r.name, r.version, r.revision, crate::package::PACKAGE_EXT));
    pack_directory(&dest_dir, meta, &out)?;
    Ok(out)
}

/// Look up an executable in a PATH-style string (plus the standard dirs).
pub fn find_in_path(name: &str, path: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = path.map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    dirs.extend(["/usr/bin", "/bin", "/usr/local/bin"].map(PathBuf::from));
    dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file())
}

/// Decide whether to sandbox: `Some(bwrap)` = use it.
pub fn choose_sandbox(mode: SandboxMode, bwrap: Option<PathBuf>) -> Result<Option<PathBuf>> {
    match (mode, bwrap) {
        (SandboxMode::None, _) => Ok(None),
        (_, Some(b)) => Ok(Some(b)),
        (SandboxMode::Auto, None) => Ok(None),
        (SandboxMode::Required, None) => Err(Error::Build(
            "build sandbox is required but `bwrap` (bubblewrap) was not found; install bubblewrap, or set \
             [build] sandbox = \"auto\" (or \"none\") in ast.toml if you accept running scripts unisolated"
                .into(),
        )),
    }
}

/// bubblewrap arguments: a fresh, empty-ish world. Read-only system dirs, no
/// network, no other processes, no other users' files, no capabilities;
/// the only writable place is the package's own work directory.
pub fn sandbox_args(work: &Path, cwd: &Path) -> Vec<std::ffi::OsString> {
    let mut a: Vec<std::ffi::OsString> = Vec::new();
    let mut push = |xs: &[&str]| a.extend(xs.iter().map(std::ffi::OsString::from));
    push(&["--die-with-parent", "--new-session", "--unshare-all", "--cap-drop", "ALL"]);
    push(&["--ro-bind", "/usr", "/usr"]);
    for d in ["/bin", "/sbin", "/lib", "/lib64"] {
        push(&["--ro-bind-try", d, d]);
    }
    for f in ["/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives", "/etc/localtime"] {
        push(&["--ro-bind-try", f, f]);
    }
    push(&["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]);
    a.extend(["--bind".into(), work.into(), work.into(), "--chdir".into(), cwd.into()]);
    a
}

fn tail(path: &Path, n: usize) -> String {
    let mut s = String::new();
    if let Ok(mut f) = File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    let lines: Vec<&str> = s.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].iter().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n")
}


fn chown_tree(p: &Path, uid: u32, gid: u32) -> Result<()> {
    std::os::unix::fs::lchown(p, Some(uid), Some(gid)).ctx("cannot chown", p)?;
    if std::fs::symlink_metadata(p).ctx("cannot stat", p)?.is_dir() {
        for e in std::fs::read_dir(p).ctx("cannot read", p)? {
            chown_tree(&e.ctx("cannot read", p)?.path(), uid, gid)?;
        }
    }
    Ok(())
}

/// Remove a directory tree, refusing to follow a top-level symlink.
pub fn remove_tree(p: &Path) -> Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_symlink() || m.is_file() => std::fs::remove_file(p).ctx("cannot remove", p),
        Ok(_) => {
            // Make sure we can delete read-only trees left by builds.
            make_writable(p);
            std::fs::remove_dir_all(p).ctx("cannot remove", p)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(format!("cannot stat {}", p.display()), e)),
    }
}

fn make_writable(p: &Path) {
    if let Ok(m) = std::fs::symlink_metadata(p)
        && m.is_dir() {
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(m.permissions().mode() | 0o700));
            if let Ok(rd) = std::fs::read_dir(p) {
                for e in rd.flatten() {
                    make_writable(&e.path());
                }
            }
        }
}

/// Unpack a source tarball (`.tar`, `.tar.gz`/`.tgz`, `.tar.zst`) into `dest`,
/// stripping `strip` leading components. Only files, dirs and symlinks are
/// accepted and nothing may escape `dest`.
pub fn extract_source(archive: &Path, dest: &Path, strip: usize) -> Result<()> {
    let mut magic = [0u8; 4];
    let mut f = File::open(archive).ctx("cannot open", archive)?;
    let n = f.read(&mut magic).ctx("cannot read", archive)?;
    drop(f);
    let f = File::open(archive).ctx("cannot open", archive)?;
    let reader: Box<dyn Read> = if n >= 2 && magic[..2] == [0x1f, 0x8b] {
        Box::new(flate2::read::GzDecoder::new(f))
    } else if n >= 4 && magic == [0x28, 0xb5, 0x2f, 0xfd] {
        Box::new(zstd::Decoder::new(f).map_err(|e| Error::io("zstd", e))?)
    } else {
        Box::new(f)
    };
    let mut ar = tar::Archive::new(reader);
    let mut symlinks = std::collections::HashSet::<String>::new();
    for e in ar.entries().map_err(|e| Error::Build(format!("cannot read source archive: {e}")))? {
        let mut e = e.map_err(|e| Error::Build(format!("corrupted source archive: {e}")))?;
        let raw = e.path().map_err(|e| Error::Build(format!("bad path in source archive: {e}")))?.into_owned();
        let raw = raw.to_string_lossy().into_owned();
        let comps: Vec<&str> = raw.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
        if comps.len() <= strip {
            continue; // the stripped top directory itself
        }
        let rel = normalize_rel(&comps[strip..].join("/")).map_err(|e| Error::Build(format!("source archive: {e}")))?;
        let parts: Vec<&str> = rel.split('/').collect();
        for i in 1..parts.len() {
            if symlinks.contains(&parts[..i].join("/")) {
                return Err(Error::Build(format!("source archive entry {rel} lies below a symlink")));
            }
        }
        let target = dest.join(&rel);
        if let Some(p) = target.parent() {
            std::fs::create_dir_all(p).ctx("cannot create", p)?;
        }
        let mode = e.header().mode().unwrap_or(0o644) & 0o777;
        match e.header().entry_type() {
            tar::EntryType::Directory => {
                std::fs::create_dir_all(&target).ctx("cannot create", &target)?;
                let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode | 0o700));
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                let mut out = File::create(&target).ctx("cannot create", &target)?;
                std::io::copy(&mut e, &mut out).ctx("cannot write", &target)?;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).ctx("cannot chmod", &target)?;
            }
            tar::EntryType::Symlink => {
                let l = e
                    .link_name()
                    .map_err(|e| Error::Build(format!("bad link in source archive: {e}")))?
                    .ok_or_else(|| Error::Build(format!("symlink {rel} has no target")))?;
                std::os::unix::fs::symlink(&l, &target).ctx("cannot create symlink", &target)?;
                symlinks.insert(rel);
            }
            tar::EntryType::XGlobalHeader | tar::EntryType::XHeader => {}
            other => {
                return Err(Error::Build(format!("source archive entry {rel}: unsupported type {other:?}")));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const RECIPE: &str = r#"
[package]
name = "hello"
version = "1.0"
description = "hello"
license = "MIT"
arch = ["x86_64", "aarch64"]
depends = ["libx >= 1"]
build_depends = ["gcc"]

[source]
url = "hello-1.0.tar.gz"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

[build]
build = "true"
"#;

    #[test]
    fn recipe_parse_and_validate() {
        let r = Recipe::parse(RECIPE).unwrap();
        assert_eq!(r.depends.len(), 1);
        assert_eq!(r.build_depends.len(), 1);
        assert!(r.supports("x86_64") && !r.supports("riscv64"));
        assert_eq!(r.source_url(Some("http://r/x")).unwrap(), "http://r/x/hello-1.0.tar.gz");
        assert!(r.source_url(None).is_err());
        assert!(Recipe::parse(&RECIPE.replace("0000000000000000000000000000000000000000000000000000000000000000", "abc")).is_err());
        assert!(Recipe::parse(&RECIPE.replace("build = \"true\"", "build = \"  \"")).is_err());
        assert!(Recipe::parse(&RECIPE.replace("[\"x86_64\", \"aarch64\"]", "[]")).is_err());
        assert!(Recipe::parse(&RECIPE.replace("hello-1.0.tar.gz", "../x")).unwrap().source_url(Some("http://r")).is_err());
    }

    fn make_source(dir: &Path) -> (PathBuf, String) {
        let tgz = dir.join("hello-1.0.tar.gz");
        let enc = flate2::write::GzEncoder::new(File::create(&tgz).unwrap(), flate2::Compression::fast());
        let mut b = tar::Builder::new(enc);
        let script = b"#!/bin/sh\necho built-ok\n";
        let mut h = tar::Header::new_gnu();
        h.set_size(script.len() as u64);
        h.set_mode(0o755);
        b.append_data(&mut h, "hello-1.0/hello.sh", &script[..]).unwrap();
        b.into_inner().unwrap().finish().unwrap();
        let sha = crate::security::sha256_file(&tgz).unwrap();
        (tgz, sha)
    }

    fn recipe_for(url: &str, sha: &str, script: &str) -> Recipe {
        let text = RECIPE
            .replace("hello-1.0.tar.gz", url)
            .replace(&"0".repeat(64), sha)
            .replace("build = \"true\"", &format!("build = '''{script}'''"));
        Recipe::parse(&text).unwrap()
    }

    #[test]
    fn builds_a_package_from_source() {
        let d = tempfile::tempdir().unwrap();
        let (tgz, sha) = make_source(d.path());
        let r = recipe_for(&format!("file://{}", tgz.display()), &sha,
            "mkdir -p \"$DESTDIR/usr/bin\"\ninstall -m755 hello.sh \"$DESTDIR/usr/bin/hello\"\ntest \"$JOBS\" -ge 1");
        let cfg = BuildCfg::default();
        let job = BuildJob {
            recipe: &r, repo_url: None, arch: "x86_64",
            build_dir: &d.path().join("build"), out_dir: &d.path().join("out"),
            jobs: 1, cfg: &cfg, verify_checksums: true,
        };
        let out = build_package(&job).unwrap();
        let p = crate::package::PackageFile::open(&out).unwrap();
        p.verify_payload().unwrap();
        assert_eq!(p.meta.name.as_str(), "hello");
        assert_eq!(p.meta.origin.source_sha256.as_deref(), Some(sha.as_str()));
        assert!(p.meta.depends.iter().any(|d| d.name.as_str() == "libx"));
        // build_depends do not leak into runtime depends
        assert!(!p.meta.depends.iter().any(|d| d.name.as_str() == "gcc"));
        // work dir cleaned, log removed
        assert!(!d.path().join("build/hello-1.0").exists());
        assert!(!d.path().join("build/hello-1.0.log").exists());
        // the build is reproducible apart from the build timestamp in metadata
        let again = build_package(&job).unwrap();
        let a = crate::package::PackageFile::open(&again).unwrap();
        assert_eq!(a.meta.payload_sha256, p.meta.payload_sha256);
    }

    #[test]
    fn build_phases_run_in_order_with_phase_env() {
        let d = tempfile::tempdir().unwrap();
        let (tgz, sha) = make_source(d.path());
        let text = RECIPE
            .replace("hello-1.0.tar.gz", &format!("file://{}", tgz.display()))
            .replace(&"0".repeat(64), &sha)
            .replace(
                "[build]\nbuild = \"true\"",
                "[build]\nprepare = '''echo $PHASE > order.txt'''\nbuild = '''echo $PHASE >> order.txt'''\ninstall = '''echo $PHASE >> order.txt\nmkdir -p \"$DESTDIR/usr/share\"\ncp order.txt \"$DESTDIR/usr/share/order.txt\"'''",
            );
        let r = Recipe::parse(&text).unwrap();
        assert_eq!(r.build.phases().iter().map(|p| p.0).collect::<Vec<_>>(), vec!["prepare", "build", "install"]);
        let cfg = BuildCfg::default();
        let job = BuildJob {
            recipe: &r, repo_url: None, arch: "x86_64",
            build_dir: &d.path().join("build"), out_dir: &d.path().join("out"),
            jobs: 1, cfg: &cfg, verify_checksums: true,
        };
        let out = build_package(&job).unwrap();
        let p = crate::package::PackageFile::open(&out).unwrap();
        let mut ar = tar::Archive::new(p.payload_tar().unwrap());
        let mut found = String::new();
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            if e.path().unwrap().ends_with("order.txt") {
                e.read_to_string(&mut found).unwrap();
            }
        }
        assert_eq!(found, "prepare\nbuild\ninstall\n");
        // a recipe without any script, or with both `script` and `build`, is rejected
        assert!(Recipe::parse(&RECIPE.replace("build = \"true\"", "")).is_err());
        assert!(Recipe::parse(&RECIPE.replace("build = \"true\"", "build = \"true\"\nbuild = \"true\"")).is_err());
    }

    #[test]
    fn sandbox_selection_policy() {
        let b = Some(PathBuf::from("/usr/bin/bwrap"));
        assert!(choose_sandbox(SandboxMode::Required, b.clone()).unwrap().is_some());
        assert!(matches!(choose_sandbox(SandboxMode::Required, None), Err(Error::Build(m)) if m.contains("bubblewrap")));
        assert!(choose_sandbox(SandboxMode::Auto, None).unwrap().is_none());
        assert!(choose_sandbox(SandboxMode::Auto, b.clone()).unwrap().is_some());
        assert!(choose_sandbox(SandboxMode::None, b).unwrap().is_none());
        assert!(find_in_path("definitely-not-a-real-tool", Some("/nonexistent".into())).is_none());
        assert!(find_in_path("sh", Some("/nonexistent".into())).is_some());
        let args = sandbox_args(Path::new("/w"), Path::new("/w/src"));
        let joined = args.iter().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>().join(" ");
        assert!(joined.contains("--unshare-all") && joined.contains("--cap-drop ALL") && joined.contains("--bind /w /w"));
        assert!(!joined.contains("--share-net"));
    }

    fn run_script(script: &str, d: &Path) -> Result<PathBuf> {
        let (tgz, sha) = make_source(d);
        let r = recipe_for(&format!("file://{}", tgz.display()), &sha, &format!("mkdir -p \"$DESTDIR/usr\"\ntouch \"$DESTDIR/usr/ok\"\n{script}"));
        let cfg = BuildCfg::default();
        let job = BuildJob {
            recipe: &r, repo_url: None, arch: "x86_64",
            build_dir: &d.join("build"), out_dir: &d.join("out"),
            jobs: 1, cfg: &cfg, verify_checksums: true,
        };
        build_package(&job)
    }

    #[test]
    fn sandbox_blocks_writes_outside_the_work_dir() {
        if find_in_path("bwrap", std::env::var_os("PATH")).is_none() {
            eprintln!("bwrap not installed: skipping");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("escape.txt");
        // the work dir is writable...
        run_script("echo fine > \"$HOME/inside.txt\"", d.path()).unwrap();
        // ...but nothing else is: a path outside is not even visible
        let e = run_script(&format!("echo pwned > {}", target.display()), d.path());
        assert!(e.is_err(), "write outside the work dir must fail");
        assert!(!target.exists());
        // system dirs are read-only
        assert!(run_script("echo x > /usr/pwned", d.path()).is_err());
        // /etc is a throw-away in-memory dir inside the sandbox: writing may succeed there,
        // but it must never reach the host
        let _ = run_script("echo x > /etc/pwned", d.path());
        assert!(!Path::new("/etc/pwned").exists() && !Path::new("/usr/pwned").exists());
    }

    #[test]
    fn sandbox_has_no_network_no_host_home_and_is_isolated() {
        if find_in_path("bwrap", std::env::var_os("PATH")).is_none() {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        // only the loopback device exists in the new network namespace
        run_script("test \"$(tail -n +3 /proc/net/dev | wc -l)\" -eq 1", d.path()).unwrap();
        // the user's home directory and /root are not visible
        run_script("test ! -e /home && test ! -e /root", d.path()).unwrap();
        // cannot see other processes: we are PID 1-ish in our own namespace
        run_script("test \"$(ls /proc | grep -c '^[0-9]')\" -le 5", d.path()).unwrap();
        // environment is scrubbed
        run_script("test -z \"${SSH_AUTH_SOCK:-}\" && test -z \"${USER:-}\"", d.path()).unwrap();
    }

    #[test]
    fn failing_build_cleans_up_and_reports_log() {
        let d = tempfile::tempdir().unwrap();
        let (tgz, sha) = make_source(d.path());
        let r = recipe_for(&format!("file://{}", tgz.display()), &sha, "echo about-to-fail\nexit 3");
        let cfg = BuildCfg::default();
        let job = BuildJob {
            recipe: &r, repo_url: None, arch: "x86_64",
            build_dir: &d.path().join("build"), out_dir: &d.path().join("out"),
            jobs: 1, cfg: &cfg, verify_checksums: true,
        };
        let e = build_package(&job).unwrap_err();
        let msg = e.to_string();
        assert!(matches!(e, Error::Build(_)));
        assert!(msg.contains("about-to-fail") && msg.contains("hello-1.0.log"), "{msg}");
        assert!(!d.path().join("build/hello-1.0").exists());
        assert!(d.path().join("build/hello-1.0.log").exists());
    }

    #[test]
    fn bad_source_checksum_and_empty_destdir() {
        let d = tempfile::tempdir().unwrap();
        let (tgz, _sha) = make_source(d.path());
        let cfg = BuildCfg::default();
        let r = recipe_for(&format!("file://{}", tgz.display()), &"1".repeat(64), "true");
        let job = BuildJob {
            recipe: &r, repo_url: None, arch: "x86_64",
            build_dir: &d.path().join("build"), out_dir: &d.path().join("out"),
            jobs: 1, cfg: &cfg, verify_checksums: true,
        };
        assert!(matches!(build_package(&job), Err(Error::Verify(_))));
        let sha = crate::security::sha256_file(&tgz).unwrap();
        let r = recipe_for(&format!("file://{}", tgz.display()), &sha, "true");
        let job = BuildJob { recipe: &r, ..job };
        assert!(matches!(build_package(&job), Err(Error::Build(m)) if m.contains("DESTDIR")));
        let job2 = BuildJob { arch: "aarch64", ..job };
        let mut r2 = r.clone();
        r2.arch = vec!["x86_64".into()];
        let job2 = BuildJob { recipe: &r2, ..job2 };
        assert!(matches!(build_package(&job2), Err(Error::Build(_))));
    }

    fn recipe(build: &str) -> Recipe {
        Recipe::parse(&format!(
            "[package]\nname = \"x\"\nversion = \"1\"\narch = [\"x86_64\"]\n[source]\nurl = \"https://e/x.tar.gz\"\nsha256 = \"{}\"\n[build]\n{build}",
            "0".repeat(64)
        ))
        .unwrap()
    }

    #[test]
    fn styles_supply_the_usual_scripts() {
        let r = recipe("style = \"gnu\"\nconfigure = [\"--disable-static\"]\nmake = [\"V=1\"]\n");
        let p = r.build.phases();
        assert_eq!(p.iter().map(|(n, _)| *n).collect::<Vec<_>>(), ["build", "install"]);
        assert!(p[0].1.contains("./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-static"));
        assert!(p[0].1.contains("make -j\"$JOBS\" V=1") && p[1].1.contains("make DESTDIR=\"$DESTDIR\" install"));
        let m = recipe("style = \"meson\"\nconfigure = [\"-Dfoo=true\"]\n").build.phases();
        assert!(m[0].1.contains("meson setup build --prefix=/usr --buildtype=release -Dfoo=true") && m[1].1.contains("ninja -C build install"));
        let c = recipe("style = \"cargo\"\nbins = [\"tool\"]\n").build.phases();
        assert!(c[1].1.contains("install -Dm755 target/release/tool"));
    }

    #[test]
    fn out_of_tree_builds_enter_the_build_directory_in_both_phases() {
        let p = recipe("style = \"gnu\"\nout_of_tree = true\n").build.phases();
        assert!(p[0].1.starts_with("mkdir -p build\ncd build\n../configure"));
        assert!(p[1].1.starts_with("cd build\nmake"));
    }

    #[test]
    fn own_scripts_replace_the_style_and_a_fixup_runs_last() {
        let p = recipe("style = \"gnu\"\nprepare = \"patch -p1 < x.patch\"\ninstall = \"make install-strip DESTDIR=$DESTDIR\"\nfixup = \"rm -rf $DESTDIR/usr/share/doc\"\n").build.phases();
        assert_eq!(p.iter().map(|(n, _)| *n).collect::<Vec<_>>(), ["prepare", "build", "install", "fixup"]);
        assert!(p[2].1.contains("install-strip") && !p[2].1.contains("make DESTDIR"));
    }
}

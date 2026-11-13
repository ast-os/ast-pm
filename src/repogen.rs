//! Building and signing repositories (used by `astpkg` and the tests).

use crate::build::{RECIPE_SUFFIX, Recipe};
use crate::config::Channel;
use crate::error::{Error, IoCtx, Result};
use crate::index::{Index, IndexEntry, binary_file_name, recipe_file_name};
use crate::package::{PACKAGE_EXT, PackageFile};
use crate::repo::package_signature_message;
use crate::security::{SecretKey, sha256_file};
use std::collections::BTreeMap;
use std::path::Path;

/// Write `<file>.sig`, a signature over the file's SHA-256 digest.
pub fn sign_package(file: &Path, key: &SecretKey) -> Result<()> {
    let sha = sha256_file(file)?;
    let sig = key.sign_hex(&package_signature_message(&sha));
    let sigp = format!("{}.sig", file.display());
    std::fs::write(&sigp, format!("{sig}\n")).ctx("cannot write", Path::new(&sigp))
}

fn expect_name(actual: &str, expected: String) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Other(format!("{actual}: files in a repository are named by convention; rename it to {expected}")))
    }
}

type Entries = BTreeMap<(String, String, u32), IndexEntry>;

/// Scan `dir` for `*.ast` and `*.recipe.toml`, sign the packages and write a
/// signed `index.toml` / `index.toml.sig`.
pub fn generate_index(dir: &Path, repo: &str, arch: &str, channel: Channel, key: &SecretKey) -> Result<Index> {
    let mut entries = Entries::new();
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .ctx("cannot read", dir)?
        .collect::<std::io::Result<Vec<_>>>()
        .ctx("cannot read", dir)?;
    files.sort_by_key(|e| e.file_name());
    for f in &files {
        let name = f.file_name().to_string_lossy().into_owned();
        if name.ends_with(&format!(".{PACKAGE_EXT}")) {
            add_binary(&mut entries, &f.path(), &name, arch, key)?;
        } else if name.ends_with(RECIPE_SUFFIX) {
            add_recipe(&mut entries, &f.path(), &name, arch)?;
        }
    }
    let idx = Index { repo: repo.to_string(), arch: arch.to_string(), channel, packages: entries.into_values().collect() };
    let bytes = idx.to_toml()?;
    let index = dir.join("index.toml");
    std::fs::write(&index, &bytes).ctx("cannot write", &index)?;
    let sig = dir.join("index.toml.sig");
    std::fs::write(&sig, format!("{}\n", key.sign_hex(&bytes))).ctx("cannot write", &sig)?;
    Ok(idx)
}

fn add_binary(entries: &mut Entries, path: &Path, name: &str, arch: &str, key: &SecretKey) -> Result<()> {
    let p = PackageFile::open(path)?;
    p.verify_payload()?;
    let m = &p.meta;
    if m.arch != "any" && m.arch != arch {
        return Err(Error::Other(format!("{name}: architecture {} does not match repository arch {arch}", m.arch)));
    }
    expect_name(name, binary_file_name(&m.name, &m.version, m.revision))?;
    sign_package(path, key)?;
    let e = entries
        .entry((m.name.to_string(), m.version.to_string(), m.revision))
        .or_insert_with(|| blank(m.name.clone(), m.version.clone(), m.revision, m.arch.clone()));
    e.arch = m.arch.clone();
    e.description = m.description.clone();
    e.license = m.license.clone();
    e.depends = m.depends.clone();
    e.conflicts = m.conflicts.clone();
    e.replaces = m.replaces.clone();
    e.status = m.release.status;
    e.binary = Some(sha256_file(path)?);
    Ok(())
}

fn add_recipe(entries: &mut Entries, path: &Path, name: &str, arch: &str) -> Result<()> {
    let r = Recipe::load(path)?;
    if !r.supports(arch) {
        return Ok(());
    }
    expect_name(name, recipe_file_name(&r.name, &r.version, r.revision))?;
    let e = entries.entry((r.name.to_string(), r.version.to_string(), r.revision)).or_insert_with(|| {
        let a = if r.arch.iter().any(|a| a == "any") { "any" } else { arch };
        let mut e = blank(r.name.clone(), r.version.clone(), r.revision, a.to_string());
        e.description = r.description.clone();
        e.license = r.license.clone();
        e.depends = r.depends.clone();
        e.conflicts = r.conflicts.clone();
        e.replaces = r.replaces.clone();
        e.status = r.release.status;
        e
    });
    e.build_depends = r.build_depends.clone();
    e.recipe = Some(sha256_file(path)?);
    Ok(())
}

fn blank(name: crate::version::PackageName, version: crate::version::Version, revision: u32, arch: String) -> IndexEntry {
    IndexEntry {
        name,
        version,
        revision,
        arch,
        description: String::new(),
        license: String::new(),
        depends: vec![],
        build_depends: vec![],
        conflicts: vec![],
        replaces: vec![],
        status: None,
        binary: None,
        recipe: None,
    }
}

//! `astpkg`: tools for repository maintainers and CI (not needed on devices).

use ast::args::Args;
use ast::build::{BuildJob, Recipe, build_package};
use ast::config::{BuildCfg, Channel};
use ast::error::{Error, IoCtx, Result};
use ast::package::{Metadata, pack_directory};
use ast::repogen::{generate_index, sign_package};
use ast::security::SecretKey;
use std::path::{Path, PathBuf};

const HELP: &str = "astpkg  repository and package tools

  keygen NAME [--out DIR]                       key pair NAME.key (secret) and NAME.pub
  pack DIR --meta FILE --out FILE [--key KEY]   pack a staging directory into a .ast
  build RECIPE --out DIR [--arch A] [--jobs N]  build a recipe into a .ast
        [--build-dir DIR] [--repo-url URL] [--key KEY]
  index DIR --name N --arch A --channel C --key KEY
                                                sign packages, write index.toml(.sig)
  publish RECIPES --out DIR --name N --arch A --channel C --key KEY [--build-dir DIR] [--no-build] [--files DIR]
                                                build every RECIPES/*/*.recipe.toml that is not
                                                in DIR yet (--no-build: none), copy the recipes, write the index;
                                                the files of --files DIR (source archives of our own) are served too";

fn sign(file: &Path, key: Option<String>) -> Result<()> {
    match key {
        Some(k) => sign_package(file, &SecretKey::load(Path::new(&k))?),
        None => Ok(()),
    }
}

fn run(mut a: Args) -> Result<()> {
    let cmd = a.command().ok_or_else(|| Error::Usage("no command given".into()))?;
    match cmd.as_str() {
        "keygen" => {
            let out = PathBuf::from(a.value(&["--out"])?.unwrap_or_else(|| ".".into()));
            let [name] = operands::<1>(a)?;
            SecretKey::generate()?.write_pair(&out, &name)?;
            println!("{0}/{1}.key  secret, keep offline\n{0}/{1}.pub", out.display(), name);
        }
        "pack" => {
            let (meta, out, key) = (a.need(&["--meta"])?, PathBuf::from(a.need(&["--out"])?), a.value(&["--key"])?);
            let [dir] = operands::<1>(a)?;
            let text = std::fs::read_to_string(&meta).ctx("cannot read", Path::new(&meta))?;
            let m = pack_directory(Path::new(&dir), Metadata::parse(&text)?, &out)?;
            sign(&out, key)?;
            println!("{}  {}  {}", m.name, m.full_version(), out.display());
        }
        "build" => {
            let out = PathBuf::from(a.need(&["--out"])?);
            let arch = a.value(&["--arch"])?.unwrap_or_else(|| std::env::consts::ARCH.into());
            let jobs = a.value(&["-j", "--jobs"])?.and_then(|j| j.parse().ok()).unwrap_or(2);
            let build_dir = PathBuf::from(a.value(&["--build-dir"])?.unwrap_or_else(|| "/tmp/astpkg-build".into()));
            let (repo_url, key) = (a.value(&["--repo-url"])?, a.value(&["--key"])?);
            let [recipe] = operands::<1>(a)?;
            let recipe = Recipe::load(Path::new(&recipe))?;
            let cfg = BuildCfg::default();
            let job = BuildJob {
                recipe: &recipe,
                repo_url: repo_url.as_deref(),
                arch: &arch,
                build_dir: &build_dir,
                out_dir: &out,
                jobs,
                cfg: &cfg,
                verify_checksums: true,
            };
            let pkg = build_package(&job)?;
            sign(&pkg, key)?;
            println!("{}", pkg.display());
        }
        "index" => {
            let (name, arch, channel, key) =
                (a.need(&["--name"])?, a.need(&["--arch"])?, a.need(&["--channel"])?, a.need(&["--key"])?);
            let [dir] = operands::<1>(a)?;
            let key = SecretKey::load(Path::new(&key))?;
            let idx = generate_index(Path::new(&dir), &name, &arch, Channel::parse(&channel)?, &key)?;
            println!("{name}  {} packages  {dir}/index.toml", idx.packages.len());
        }
        "publish" => {
            let out = PathBuf::from(a.need(&["--out"])?);
            let (name, arch, channel) = (a.need(&["--name"])?, a.need(&["--arch"])?, a.need(&["--channel"])?);
            let key_path = a.need(&["--key"])?;
            let build_dir = PathBuf::from(a.value(&["--build-dir"])?.unwrap_or_else(|| "/tmp/astpkg-build".into()));
            let no_build = a.flag(&["--no-build"]);
            let files = a.value(&["--files"])?;
            let [recipes] = operands::<1>(a)?;
            if let Some(dir) = files {
                std::fs::create_dir_all(&out).ctx("cannot create", &out)?;
                for f in std::fs::read_dir(&dir).ctx("cannot read", Path::new(&dir))? {
                    let f = f.ctx("cannot read", Path::new(&dir))?.path();
                    if f.is_file() {
                        std::fs::copy(&f, out.join(f.file_name().unwrap_or_default())).ctx("cannot copy", &f)?;
                    }
                }
            }
            publish(Path::new(&recipes), &out, &name, &arch, Channel::parse(&channel)?, Path::new(&key_path), &build_dir, !no_build)?;
        }
        _ => return Err(Error::Usage(format!("unknown command {cmd:?}"))),
    }
    Ok(())
}

/// Build the missing packages (unless `build` is off: then only the recipes are published) of `recipes/NAME/NAME.recipe.toml` into `out`, then index them.
#[allow(clippy::too_many_arguments)]
fn publish(recipes: &Path, out: &Path, name: &str, arch: &str, channel: Channel, key_path: &Path, build_dir: &Path, build: bool) -> Result<()> {
    let key = SecretKey::load(key_path)?;
    let cfg = BuildCfg::default();
    std::fs::create_dir_all(out).ctx("cannot create", out)?;
    let mut files = Vec::new();
    for dir in std::fs::read_dir(recipes).ctx("cannot read", recipes)? {
        let dir = dir.ctx("cannot read", recipes)?.path();
        if !dir.is_dir() || dir.file_name().is_some_and(|n| n.to_string_lossy().starts_with('_')) {
            continue;
        }
        for f in std::fs::read_dir(&dir).ctx("cannot read", &dir)? {
            let f = f.ctx("cannot read", &dir)?.path();
            if f.to_string_lossy().ends_with(ast::build::RECIPE_SUFFIX) {
                files.push(f);
            } else if f.is_file() {
                // other files of the recipe (a source archive a recipe names by a relative path) are served with it
                let dest = out.join(f.file_name().unwrap_or_default());
                std::fs::copy(&f, &dest).ctx("cannot copy", &f)?;
            }
        }
    }
    files.sort();
    for file in files {
        let recipe = Recipe::load(&file)?;
        if !recipe.supports(arch) {
            continue;
        }
        let pkg = out.join(format!("{}-{}-{}.ast", recipe.name, recipe.version, recipe.revision));
        if pkg.exists() || !build {
            println!("  skip  {}  {}", recipe.name, recipe.version);
        } else {
            println!("  build  {}  {}", recipe.name, recipe.version);
            let job = BuildJob {
                recipe: &recipe,
                repo_url: None,
                arch,
                build_dir,
                out_dir: out,
                jobs: 2,
                cfg: &cfg,
                verify_checksums: true,
            };
            sign_package(&build_package(&job)?, &key)?;
        }
        let dest = out.join(ast::index::recipe_file_name(&recipe.name, &recipe.version, recipe.revision));
        std::fs::copy(&file, &dest).ctx("cannot copy", &file)?;
    }
    let idx = generate_index(out, name, arch, channel, &key)?;
    println!("{name}  {} packages  {}/index.toml", idx.packages.len(), out.display());
    Ok(())
}

/// Exactly N operands.
fn operands<const N: usize>(a: Args) -> Result<[String; N]> {
    let v = a.operands()?;
    let n = v.len();
    v.try_into().map_err(|_| Error::Usage(format!("expected {N} argument(s), got {n}")))
}

fn main() {
    let mut a = Args::from_env();
    if a.is_empty() || a.flag(&["-h", "--help"]) {
        println!("{HELP}");
        return;
    }
    if let Err(e) = run(a) {
        ast::cli::report(&e);
        std::process::exit(e.exit_code());
    }
}

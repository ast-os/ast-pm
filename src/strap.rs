//! `astrap`: install the base system into an empty directory, like pacstrap.

use crate::args::Args;
use crate::error::{Error, IoCtx, Result};
use crate::ops::{Flags, Ast, Ui};
use std::path::Path;

pub const HELP: &str = "astrap ROOT [PKG...]

install asteros-base and PKG... into ROOT, using this system's repositories and keys

  -y, --yes           skip ordinary questions
  -C, --config DIR    read ast.toml, repos.toml and keys from DIR (default /etc/ast)
  -b, --base NAME     the package group to install instead of asteros-base
  -j, --jobs N        build jobs
  --accept-untested   do not ask about untested system components";

pub fn run(mut a: Args, ui: &mut dyn Ui) -> Result<i32> {
    let jobs = a
        .value(&["-j", "--jobs"])?
        .map(|v| v.parse().map_err(|_| Error::Usage(format!("bad job count {v:?}"))))
        .transpose()?;
    let base = a.value(&["-b", "--base"])?.unwrap_or_else(|| "asteros-base".into());
    let config = a.value(&["-C", "--config"])?.unwrap_or_else(|| "/etc/ast".into());
    let flags = Flags {
        yes: a.flag(&["-y", "--yes"]),
        accept_untested: a.flag(&["--accept-untested"]),
        accept_foreign: false,
        binary: false,
        dry_run: false,
        jobs,
    };
    let operands = a.operands()?;
    let Some((root, extra)) = operands.split_first() else {
        return Err(Error::Usage("astrap needs a target directory".into()));
    };
    let root = Path::new(root);
    if root == Path::new("/") {
        return Err(Error::Usage("refusing to bootstrap into /".into()));
    }
    std::fs::create_dir_all(root).ctx("cannot create", root)?;
    let m = Ast::open_with_config(root, Path::new(&config), flags)?;
    m.update(ui)?;
    let mut targets = vec![base];
    targets.extend(extra.iter().cloned());
    m.install(&targets, ui)?;
    Ok(0)
}

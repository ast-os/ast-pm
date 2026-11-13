//! `astchroot`: enter an installed system with /proc, /sys, /dev and the network config in place.
//! Runs in its own mount namespace, so nothing needs unmounting afterwards.

use crate::error::{Error, Result};
use std::os::unix::process::CommandExt;
use std::process::Command;

pub const HELP: &str = "astchroot ROOT [COMMAND...]

run COMMAND (default: a shell) inside ROOT; /proc, /sys, /dev, /run and resolv.conf are mounted for it";

const SETUP: &str = r#"set -e
r=$1; shift
mount --rbind /dev "$r/dev"; mount --make-rslave "$r/dev"
mount -t proc proc "$r/proc"
mount --rbind /sys "$r/sys"; mount --make-rslave "$r/sys"
mount -t tmpfs tmpfs "$r/run"
if [ -e /etc/resolv.conf ]; then
    [ -e "$r/etc/resolv.conf" ] || : > "$r/etc/resolv.conf"
    mount --bind /etc/resolv.conf "$r/etc/resolv.conf"
fi
[ $# -gt 0 ] || set -- /bin/sh -c 'if [ -x /bin/bash ]; then exec bash -l; else exec sh -l; fi'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH
exec chroot "$r" "$@"
"#;

pub fn run(args: Vec<String>) -> Result<i32> {
    let Some((root, cmd)) = args.split_first() else {
        return Err(Error::Usage("astchroot needs a directory".into()));
    };
    if !std::path::Path::new(root).join("bin").exists() && !std::path::Path::new(root).join("usr/bin").exists() {
        return Err(Error::Other(format!("{root} does not look like an installed system")));
    }
    for d in ["dev", "proc", "sys", "run"] {
        std::fs::create_dir_all(std::path::Path::new(root).join(d)).map_err(|e| Error::io("cannot create", e))?;
    }
    let err = Command::new("unshare")
        .args(["--mount", "--propagation", "private", "--", "sh", "-c", SETUP, "astchroot", root])
        .args(cmd)
        .exec();
    Err(Error::io("cannot run unshare", err))
}

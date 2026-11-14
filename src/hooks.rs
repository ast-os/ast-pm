//! System hooks. Packages carry no scripts; after a transaction `ast` itself refreshes
//! what the changed files make stale: the linker cache, module dependencies, and the
//! account files that `base-passwd` only ships as masters.

use crate::ops::Ui;
use crate::util::{Paths, is_root};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Stdio};

/// Run the hooks the changed paths (relative to the root, no leading slash) call for.
/// A hook that fails is reported, never fatal: the transaction is already committed.
pub fn run(paths: &Paths, changed: &[String], ui: &mut dyn Ui) {
    let root = &paths.root;
    if accounts(root) {
        ui.out("  hook  accounts");
    }
    let libs = changed.iter().any(|p| {
        let in_lib = ["lib/", "usr/lib/", "lib64/", "usr/lib64/"].iter().any(|d| p.starts_with(d));
        (in_lib && p.contains(".so")) || p.starts_with("etc/ld.so.conf")
    });
    if libs && tool(root, "ldconfig") {
        report(ui, "ldconfig", exec(root, "ldconfig", &[]));
    }
    let versions: BTreeSet<&str> = changed
        .iter()
        .filter_map(|p| p.strip_prefix("lib/modules/").or_else(|| p.strip_prefix("usr/lib/modules/")))
        .filter_map(|p| p.split('/').next())
        .collect();
    if tool(root, "depmod") {
        for v in versions {
            report(ui, &format!("depmod {v}"), exec(root, "depmod", &["-a", v]));
        }
    }
    desktop(root, changed, ui);
}

/// The caches of the desktop stack, refreshed when the files they index changed.
fn desktop(root: &Path, changed: &[String], ui: &mut dyn Ui) {
    let touched = |prefix: &str| changed.iter().any(|p| p.starts_with(prefix));
    let jobs: [(&str, &str, &[&str]); 5] = [
        ("usr/share/glib-2.0/schemas/", "glib-compile-schemas", &["/usr/share/glib-2.0/schemas"]),
        ("usr/share/mime/packages/", "update-mime-database", &["/usr/share/mime"]),
        ("usr/share/applications/", "update-desktop-database", &["-q", "/usr/share/applications"]),
        ("usr/share/fonts/", "fc-cache", &["-s"]),
        ("usr/lib/gtk-3.0/", "gtk-query-immodules-3.0", &["--update-cache"]),
    ];
    for (prefix, name, args) in jobs {
        if touched(prefix) && tool(root, name) {
            report(ui, name, exec(root, name, args));
        }
    }
    // an icon theme: its cache is per theme directory
    let themes: BTreeSet<&str> = changed
        .iter()
        .filter_map(|p| p.strip_prefix("usr/share/icons/"))
        .filter_map(|p| p.split('/').next())
        .collect();
    if tool(root, "gtk-update-icon-cache") {
        for t in themes {
            let dir = format!("/usr/share/icons/{t}");
            if root.join(dir.trim_start_matches('/')).join("index.theme").is_file() {
                report(ui, &format!("icon cache {t}"), exec(root, "gtk-update-icon-cache", &["-q", "-t", "-f", &dir]));
            }
        }
    }
}

fn report(ui: &mut dyn Ui, what: &str, ok: bool) {
    if ok {
        ui.out(&format!("  hook  {what}"));
    } else {
        ui.warn(&format!("!  hook {what} failed"));
    }
}

/// Is `name` installed in the target root (so it can run there)?
fn tool(root: &Path, name: &str) -> bool {
    ["sbin", "usr/sbin", "bin", "usr/bin"].iter().any(|d| root.join(d).join(name).symlink_metadata().is_ok())
}

/// Run a tool inside the root: chroot for another root, directly for `/`.
fn exec(root: &Path, name: &str, args: &[&str]) -> bool {
    let path = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    let mut c;
    if root == Path::new("/") {
        c = Command::new("env");
        c.arg(path).arg(name);
    } else {
        if !is_root() {
            return true; // a chroot needs root; astrap and system installs have it
        }
        c = Command::new("chroot");
        c.arg(root).arg("env").arg(path).arg(name);
    }
    c.args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    c.status().map(|s| s.success()).unwrap_or(false)
}

/// What `base-passwd` does when installed: the master files become the first account
/// files. Existing files are never touched. Accounts start locked; set a password later.
fn accounts(root: &Path) -> bool {
    use std::os::unix::fs::{PermissionsExt, chown};
    let master = root.join("usr/share/base-passwd");
    let (passwd, group) = (root.join("etc/passwd"), root.join("etc/group"));
    if passwd.exists() || group.exists() || !master.join("passwd.master").is_file() {
        return false;
    }
    let read = |f: &str| std::fs::read_to_string(master.join(f)).unwrap_or_default();
    // an empty password field would mean "no password"; "x" sends login to the locked shadow entry
    let open = |l: &str| {
        let mut f: Vec<&str> = l.split(':').collect();
        if f.len() > 1 && f[1].is_empty() {
            f[1] = "x";
        }
        f.join(":") + "\n"
    };
    let pw: String = read("passwd.master").lines().map(open).collect();
    let gr = read("group.master");
    let locked = |text: &str, tail: &str| {
        text.lines().filter_map(|l| l.split(':').next()).map(|n| format!("{n}:*:{tail}\n")).collect::<String>()
    };
    let files = [
        ("etc/passwd", pw.clone(), 0o644),
        ("etc/group", gr.clone(), 0o644),
        ("etc/shadow", locked(&pw, "19000:0:99999:7:::"), 0o640),
        ("etc/gshadow", locked(&gr, ":"), 0o640),
    ];
    let shadow_gid = gr.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.first() == Some(&"shadow")).then(|| f.get(2).and_then(|g| g.parse::<u32>().ok())).flatten()
    });
    for (rel, text, mode) in files {
        let p = root.join(rel);
        if std::fs::write(&p, text).is_err() {
            return false;
        }
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode));
        if rel.ends_with("shadow") && is_root() {
            let _ = chown(&p, Some(0), shadow_gid);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Quiet(Vec<String>);
    impl Ui for Quiet {
        fn out(&mut self, l: &str) {
            self.0.push(l.into());
        }
        fn warn(&mut self, l: &str) {
            self.0.push(l.into());
        }
        fn confirm(&mut self, _: &str, _: bool) -> bool {
            false
        }
    }

    #[test]
    fn accounts_come_from_the_masters_once() {
        let d = tempfile::tempdir().unwrap();
        let m = d.path().join("usr/share/base-passwd");
        std::fs::create_dir_all(&m).unwrap();
        std::fs::create_dir_all(d.path().join("etc")).unwrap();
        std::fs::write(m.join("passwd.master"), "root::0:0:root:/root:/bin/sh\n").unwrap();
        std::fs::write(m.join("group.master"), "root:x:0:\nshadow:x:42:\n").unwrap();
        let mut ui = Quiet(vec![]);
        run(&Paths::new(d.path()), &[], &mut ui);
        assert_eq!(ui.0, vec!["  hook  accounts"]);
        let shadow = std::fs::read_to_string(d.path().join("etc/shadow")).unwrap();
        assert_eq!(shadow, "root:*:19000:0:99999:7:::\n");
        assert_eq!(std::fs::read_to_string(d.path().join("etc/passwd")).unwrap(), "root:x:0:0:root:/root:/bin/sh\n");
        std::fs::write(d.path().join("etc/passwd"), "changed\n").unwrap();
        let mut ui = Quiet(vec![]);
        run(&Paths::new(d.path()), &[], &mut ui);
        assert!(ui.0.is_empty());
        assert_eq!(std::fs::read_to_string(d.path().join("etc/passwd")).unwrap(), "changed\n");
    }

    #[test]
    fn tools_missing_from_the_root_are_skipped() {
        let d = tempfile::tempdir().unwrap();
        let mut ui = Quiet(vec![]);
        run(&Paths::new(d.path()), &["usr/lib/libc.so.6".into(), "lib/modules/7.3.4/x.ko".into()], &mut ui);
        assert!(ui.0.is_empty());
    }
}

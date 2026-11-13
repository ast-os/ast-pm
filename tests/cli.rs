//! Drives the real `ast` and `astpkg` binaries against a temporary root.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::io::Write;

fn astpkg() -> Command {
    Command::new(env!("CARGO_BIN_EXE_astpkg"))
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(mut c: Command, stdin: &str) -> Out {
    let mut child = c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let o = child.wait_with_output().unwrap();
    Out {
        code: o.status.code().unwrap(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

struct Sandbox {
    dir: tempfile::TempDir,
    root: PathBuf,
    repo: PathBuf,
}

impl Sandbox {
    fn ast(&self, args: &[&str], stdin: &str) -> Out {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ast"));
        c.arg("--root").arg(&self.root).args(args);
        run(c, stdin)
    }
}

fn pack(dir: &Path, name: &str, version: &str, deps: &str, extra: &str, files: &[(&str, &str)]) {
    let stage = dir.join(format!("stage-{name}-{version}"));
    for (p, c) in files {
        let f = stage.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, c).unwrap();
    }
    let meta = dir.join(format!("{name}.meta.toml"));
    std::fs::write(&meta, format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\narch = \"x86_64\"\ndepends = [{deps}]\n{extra}\n")).unwrap();
    let out = run({
        let mut c = astpkg();
        c.arg("pack").arg(&stage).arg("--meta").arg(&meta).arg("--out").arg(dir.join("repo").join(format!("{name}-{version}-1.ast")));
        c
    }, "");
    assert_eq!(out.code, 0, "{}", out.stderr);
}

fn sandbox() -> Sandbox {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    // 1. keys
    let o = run({ let mut c = astpkg(); c.arg("keygen").arg("ast").arg("--out").arg(dir.path().join("keys")); c }, "");
    assert_eq!(o.code, 0, "{}", o.stderr);
    // packages: app -> libfoo ; kernel is an untested system component
    pack(dir.path(), "libfoo", "1.0", "", "", &[("usr/lib/libfoo.so", "lib\n")]);
    pack(dir.path(), "app", "1.0", "\"libfoo >= 1.0\"", "", &[("usr/bin/app", "#!/bin/sh\n")]);
    pack(dir.path(), "linux", "7.1", "", "[release]\nstatus = \"untested\"\n", &[("boot/vmlinuz", "kernel\n")]);
    // 2. signed index
    let o = run({
        let mut c = astpkg();
        c.arg("index").arg(&repo).args(["--name", "ast", "--arch", "x86_64", "--channel", "stable", "--key"]).arg(dir.path().join("keys/ast.key"));
        c
    }, "");
    assert_eq!(o.code, 0, "{}", o.stderr);
    // 3. ast init + repos.toml + key
    let sb = Sandbox { dir, root, repo };
    let o = sb.ast(&["init"], "");
    assert_eq!(o.code, 0, "{}", o.stderr);
    let etc = sb.root.join("etc/ast");
    std::fs::write(etc.join("ast.toml"), "[core]\narchitecture = \"x86_64\"\n[packages]\nallow_untested = true\n").unwrap();
    std::fs::write(
        etc.join("repos.toml"),
        format!("[ast]\nurl = \"file://{}\"\nenabled = true\npriority = 100\nkey = \"ast.pub\"\n", sb.repo.display()),
    )
    .unwrap();
    std::fs::copy(sb.dir.path().join("keys/ast.pub"), etc.join("keys/ast.pub")).unwrap();
    sb
}

#[test]
fn first_version_acceptance_flow() {
    let sb = sandbox();
    // update + search
    let o = sb.ast(&["-u"], "");
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    let o = sb.ast(&["-s", "app"], "");
    assert_eq!(o.code, 0);
    assert!(o.stdout.contains("app"), "{}", o.stdout);
    assert_eq!(sb.ast(&["-s", "zzz-nothing"], "").code, 1);
    // install a package with its dependency; the prompt is answered on stdin
    let o = sb.ast(&["-i", "app"], "y\n");
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("+  libfoo") && o.stdout.contains("2 to install") && o.stdout.contains("proceed?  [Y/n]"), "{}", o.stdout);
    assert!(sb.root.join("usr/bin/app").exists() && sb.root.join("usr/lib/libfoo.so").exists());
    let o = sb.ast(&["-l"], "");
    assert!(o.stdout.contains("app") && o.stdout.contains("libfoo") && o.stdout.contains("(dependency)"), "{}", o.stdout);
    let o = sb.ast(&["-q", "app"], "");
    assert_eq!(o.code, 0);
    assert!(o.stdout.contains("depends") && o.stdout.contains("libfoo >= 1.0"), "{}", o.stdout);
    // verify ok, then break a file
    assert_eq!(sb.ast(&["verify"], "").code, 0);
    std::fs::write(sb.root.join("usr/lib/libfoo.so"), "changed").unwrap();
    let o = sb.ast(&["verify"], "");
    assert_eq!(o.code, 1);
    assert!(o.stderr.contains("/usr/lib/libfoo.so  modified"), "{}", o.stderr);
    // remove
    let o = sb.ast(&["-r", "app"], "y\n");
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert!(!sb.root.join("usr/bin/app").exists());
    // default answer to the confirmation is taken from the user, EOF means "no"
    let o = sb.ast(&["-i", "app"], "");
    assert_eq!(o.code, 8);
    assert!(!sb.root.join("usr/bin/app").exists());
}

#[test]
fn exit_codes_and_messages() {
    let sb = sandbox();
    sb.ast(&["-u"], "");
    let o = sb.ast(&["-i", "ghost"], "");
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains("error  ") && o.stderr.contains("ghost") && o.stderr.contains("hint  "), "{}", o.stderr);
    let o = sb.ast(&["-ib", "ghost"], "");
    assert_eq!(o.code, 4);
    assert!(sb.ast(&["frobnicate"], "").code == 2);
    let o = sb.ast(&["-r", "app"], "");
    assert_eq!(o.code, 4);
    // missing configuration
    let empty = tempfile::tempdir().unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_ast"));
    c.arg("--root").arg(empty.path()).arg("-l");
    let o = run(c, "");
    assert_eq!(o.code, 3);
    assert!(o.stderr.contains("ast init"), "{}", o.stderr);
}

#[test]
fn untested_warning_default_is_no_and_yes_flag_does_not_bypass_it() {
    let sb = sandbox();
    sb.ast(&["-u"], "");
    // proceed? y, install untested components? <enter> (default No)
    let o = sb.ast(&["-i", "linux"], "y\n\n");
    assert_eq!(o.code, 8, "{}{}", o.stdout, o.stderr);
    assert!(o.stderr.contains("!  untested system components") && o.stderr.contains("linux  7.1"), "{}", o.stderr);
    assert!(o.stdout.contains("install untested components?  [y/N]"), "{}", o.stdout);
    assert!(!sb.root.join("boot/vmlinuz").exists());
    // -y alone: still asks the extra question; EOF => no
    let o = sb.ast(&["-iy", "linux"], "");
    assert_eq!(o.code, 8);
    assert!(!sb.root.join("boot/vmlinuz").exists());
    // explicit answer installs
    let o = sb.ast(&["-iy", "linux"], "y\n");
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert!(sb.root.join("boot/vmlinuz").exists());
}

#[test]
fn untested_blocked_when_not_allowed_has_exit_code_9() {
    let sb = sandbox();
    sb.ast(&["-u"], "");
    std::fs::write(sb.root.join("etc/ast/ast.toml"), "[core]\narchitecture = \"x86_64\"\n[packages]\nallow_untested = false\n").unwrap();
    let o = sb.ast(&["-iy", "--accept-untested", "linux"], "y\n");
    assert_eq!(o.code, 9, "{}{}", o.stdout, o.stderr);
    assert!(!sb.root.join("boot/vmlinuz").exists());
}

#[test]
fn disabled_verification_is_loudly_reported() {
    let sb = sandbox();
    std::fs::write(sb.root.join("etc/ast/ast.toml"), "[core]\narchitecture = \"x86_64\"\n[security]\nverify_signatures = false\n").unwrap();
    let o = sb.ast(&["-l"], "");
    assert!(o.stderr.contains("signature verification disabled"), "{}", o.stderr);
}

#[test]
fn repo_and_channel_commands() {
    let sb = sandbox();
    let o = sb.ast(&["repo", "list"], "");
    assert!(o.stdout.contains("ast") && o.stdout.contains("active"), "{}", o.stdout);
    assert_eq!(sb.ast(&["channel"], "").stdout.trim(), "stable");
    assert_eq!(sb.ast(&["channel", "edge"], "").code, 0);
    assert_eq!(sb.ast(&["channel"], "").stdout.trim(), "edge");
    assert_eq!(sb.ast(&["channel", "bogus"], "").code, 3);
    assert_eq!(sb.ast(&["repo", "disable", "ast"], "").code, 0);
    assert_eq!(sb.ast(&["repo", "enable", "nope"], "").code, 4);
}

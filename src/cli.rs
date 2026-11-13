//! Command-line interface of `ast`: argument handling, help, terminal output.

use crate::args::Args;
use crate::error::{Error, Result};
use crate::ops::{Flags, Ast, Ui};
use crate::util::table;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

const MODES: &[[&str; 2]] = &[
    ["-i PKG...", "install: build from source, or take a binary with -b; PKG[:repo][@ver]"],
    ["-r PKG...", "remove, with the dependencies nothing else needs"],
    ["-u [PKG...]", "refresh the repositories; with names, or -a, upgrade as well"],
    ["-l", "list the installed packages"],
    ["-q PKG", "information about a package"],
    ["-s TEXT", "search; an empty TEXT lists everything"],
];

const WORDS: &[[&str; 2]] = &[
    ["repo [enable|disable NAME]", "list the repositories, or use one or stop using it"],
    ["channel [stable|edge]", "show or set the system channel"],
    ["verify [PKG...]", "check the installed files"],
    ["clean", "drop cached packages and build data"],
    ["init", "create the directories and the default configuration"],
];

const OPTIONS: &[[&str; 2]] = &[
    ["-b", "binary packages only"],
    ["-a", "all installed packages (with -u)"],
    ["-y", "do not ask ordinary questions"],
    ["--dry-run", "show the plan, change nothing"],
    ["-j N", "build jobs"],
    ["--root DIR", "work inside DIR instead of /"],
    ["--accept-untested", "do not ask about untested system components"],
    ["--accept-foreign", "do not ask about other-channel dependencies"],
    ["--adopt", "replace files that belong to no package (bootstrap)"],
];

fn help() -> String {
    let rows = |r: &[[&str; 2]]| table(&r.iter().map(|c| c.iter().map(|s| s.to_string()).collect()).collect::<Vec<_>>(), "  ").join("\n");
    format!("ast {}\n\n{}\n\n{}\n\n{}\n\nletters combine: ast -iby nano, ast -ua, ast -ry nano", env!("CARGO_PKG_VERSION"), rows(MODES), rows(OPTIONS), rows(WORDS))
}

// ------------------------------------------------------------ terminal

/// Light colour, only on a terminal and only if `NO_COLOR` is unset.
struct TermUi {
    color_out: bool,
    color_err: bool,
}

impl TermUi {
    fn new() -> TermUi {
        let ok = std::env::var_os("NO_COLOR").is_none();
        TermUi { color_out: ok && std::io::stdout().is_terminal(), color_err: ok && std::io::stderr().is_terminal() }
    }
}

fn paint(code: &str, text: &str) -> String {
    format!("\x1b[{code}m{text}\x1b[0m")
}

/// Colour a line by its leading marker.
fn style(line: &str) -> String {
    let body = line.trim_start();
    let indent = &line[..line.len() - body.len()];
    let (head, rest) = body.split_once(' ').unwrap_or((body, ""));
    let code = match head {
        "+" => "32",
        "-" => "31",
        "~" | "!" => "33",
        "=" | "fetch" | "build" | "install" | "upgrade" | "remove" | "hook" => "2",
        "done" | "cleaned" => "1;32",
        _ => return line.to_string(),
    };
    format!("{indent}{} {rest}", paint(code, head)).trim_end().to_string()
}

impl Ui for TermUi {
    fn out(&mut self, line: &str) {
        // Errors are ignored on purpose: a closed pipe (`ast -l | head`) must not panic.
        let l = if self.color_out { style(line) } else { line.to_string() };
        let _ = writeln!(std::io::stdout(), "{l}");
    }

    fn warn(&mut self, line: &str) {
        let l = if self.color_err { style(line) } else { line.to_string() };
        let _ = writeln!(std::io::stderr(), "{l}");
    }

    fn confirm(&mut self, prompt: &str, default_yes: bool) -> bool {
        let _ = write!(std::io::stdout(), "{prompt}  {} ", if default_yes { "[Y/n]" } else { "[y/N]" });
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => {
                let _ = writeln!(std::io::stdout());
                false // nobody to ask: never assume consent
            }
            Ok(_) => match line.trim().to_ascii_lowercase().as_str() {
                "" => default_yes,
                "y" | "yes" => true,
                _ => false,
            },
        }
    }
}

pub fn report(e: &Error) {
    if matches!(e, Error::Aborted) {
        let _ = writeln!(std::io::stderr(), "aborted");
        return;
    }
    let color = std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal();
    let (err, hint) = if color { (paint("1;31", "error"), paint("2", "hint")) } else { ("error".into(), "hint".into()) };
    let mut out = std::io::stderr();
    let _ = writeln!(out, "{err}  {e}");
    if let Some(h) = e.hint() {
        let _ = writeln!(out, "{hint}  {h}");
    }
}

// ------------------------------------------------------------- dispatch

/// Commands that change the system. Everything else works as a normal user.
fn needs_root(cmd: &str, ops: &[&str]) -> bool {
    matches!(
        (cmd, ops),
        ("install" | "remove" | "update" | "upgrade" | "clean" | "init", _)
            | ("repo", ["enable" | "disable", _])
            | ("channel", [_])
    )
}

/// Run this very command again through sudo (or doas), like paru does. Only returns on failure.
pub fn escalate() -> Error {
    use std::os::unix::process::CommandExt;
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return Error::io("cannot find ast's own path", e),
    };
    for tool in ["sudo", "doas"] {
        if let Some(path) = crate::build::find_in_path(tool, std::env::var_os("PATH")) {
            let _ = writeln!(std::io::stderr(), "!  needs root, using {tool}");
            let mut c = std::process::Command::new(path);
            if tool == "sudo" {
                c.arg("--");
            }
            return Error::io(format!("cannot run {tool}"), c.arg(&exe).args(std::env::args().skip(1)).exec());
        }
    }
    Error::Other("this needs root: run ast as root, or install sudo or doas".into())
}

/// `astfstab` and `astchroot`: small tools for installing by hand.
pub fn run_tool(name: &str, args: Vec<String>) -> i32 {
    let help = match name {
        "astfstab" => crate::fstab::HELP,
        _ => crate::chroot::HELP,
    };
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{help}");
        return 0;
    }
    let go = || -> Result<i32> {
        if name == "astchroot" && !crate::util::is_root() {
            return Err(escalate());
        }
        match name {
            "astfstab" => crate::fstab::run(args),
            _ => crate::chroot::run(args),
        }
    };
    match go() {
        Ok(code) => code,
        Err(e) => {
            report(&e);
            e.exit_code()
        }
    }
}

/// `astrap`: install the base system into a directory.
pub fn run_strap() -> i32 {
    let go = || -> Result<i32> {
        let mut a = Args::from_env();
        if a.is_empty() || a.flag(&["-h", "--help"]) {
            println!("{}", crate::strap::HELP);
            return Ok(0);
        }
        if !crate::util::is_root() {
            return Err(escalate());
        }
        crate::strap::run(a, &mut TermUi::new())
    };
    match go() {
        Ok(code) => code,
        Err(e) => {
            report(&e);
            e.exit_code()
        }
    }
}

pub fn run() -> i32 {
    match dispatch(Args::from_env()) {
        Ok(code) => code,
        Err(e) => {
            report(&e);
            e.exit_code()
        }
    }
}

/// The one action of a line such as `-iby nano`: the letters pick it, the rest are modifiers.
fn mode(a: &mut Args) -> Result<Option<&'static str>> {
    let mut chosen: Vec<&'static str> = [("install", "-i"), ("remove", "-r"), ("upgrade", "-u"), ("list", "-l"), ("info", "-q"), ("search", "-s")]
        .into_iter()
        .filter_map(|(word, letter)| a.flag(&[letter]).then_some(word))
        .collect();
    // `-li`: the installed ones, which is what -l lists anyway
    if chosen == ["install", "list"] {
        chosen = vec!["list"];
    }
    match chosen.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(one)),
        _ => Err(Error::Usage("give one of -i -r -u -l -q -s".into())),
    }
}

fn dispatch(mut a: Args) -> Result<i32> {
    if a.flag(&["-V", "--version"]) {
        println!("ast {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    if a.is_empty() || a.flag(&["-h", "--help"]) {
        println!("{}", help());
        return Ok(0);
    }
    let root = PathBuf::from(a.value(&["--root"])?.unwrap_or_else(|| "/".into()));
    let jobs = a
        .value(&["-j", "--jobs"])?
        .map(|v| v.parse().map_err(|_| Error::Usage(format!("bad job count {v:?}"))))
        .transpose()?;
    let all = a.flag(&["-a"]);
    let flags = Flags {
        yes: a.flag(&["-y"]),
        binary: a.flag(&["-b"]),
        adopt: a.flag(&["--adopt"]),
        accept_untested: a.flag(&["--accept-untested"]),
        accept_foreign: a.flag(&["--accept-foreign"]),
        dry_run: a.flag(&["--dry-run"]),
        jobs,
    };
    let picked = mode(&mut a)?;
    let cmd = match picked {
        Some(m) => m.to_string(),
        None => match a.command() {
            Some(c) => c,
            None => {
                println!("{}", help());
                return Ok(0);
            }
        },
    };
    let operands = a.operands()?;
    let ops: Vec<&str> = operands.iter().map(String::as_str).collect();

    let mut ui = TermUi::new();
    if root == Path::new("/") && !crate::util::is_root() && needs_root(&cmd, &ops) {
        return Err(escalate());
    }
    if cmd == "init" && ops.is_empty() {
        for p in crate::ops::init(&root)? {
            ui.out(&format!("created  {}", p.display()));
        }
        return Ok(0);
    }
    if cmd == "help" {
        println!("{}", help());
        return Ok(0);
    }
    if picked.is_none() && !["repo", "channel", "verify", "clean"].contains(&cmd.as_str()) {
        return Err(Error::Usage(format!("unknown command {cmd:?}; see ast -h")));
    }

    let m = Ast::open(&root, flags)?;
    for w in m.security_warnings() {
        ui.warn(&w);
    }
    match (cmd.as_str(), ops.as_slice()) {
        ("install", p) if !p.is_empty() => m.install(&operands, &mut ui)?,
        ("remove", p) if !p.is_empty() => m.remove(&operands, &mut ui)?,
        ("upgrade", p) => {
            m.update(&mut ui)?;
            if all || !p.is_empty() {
                m.upgrade(if all { &[] } else { &operands }, &mut ui)?;
            }
        }
        ("search", [term]) => {
            if m.search(term, &mut ui)? == 0 {
                return Ok(1);
            }
        }
        ("info", [pkg]) => m.info(pkg, &mut ui)?,
        ("list", []) => {
            m.list(&mut ui)?;
        }
        ("repo", [] | ["list"]) => m.repo_list(&mut ui),
        ("repo", ["enable", name]) => m.repo_set_enabled(name, true, &mut ui)?,
        ("repo", ["disable", name]) => m.repo_set_enabled(name, false, &mut ui)?,
        ("channel", []) => m.channel(None, &mut ui)?,
        ("channel", [name]) => m.channel(Some(name), &mut ui)?,
        ("clean", []) => m.clean(&mut ui)?,
        ("verify", _) => {
            if m.verify(&operands, &mut ui)? > 0 {
                return Ok(1);
            }
        }
        _ => return Err(Error::Usage(format!("wrong arguments for {cmd}; see ast -h"))),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_is_aligned_and_complete() {
        let h = help();
        for c in MODES.iter().chain(WORDS).chain(OPTIONS) {
            assert!(h.contains(c[0]));
        }
        assert!(h.lines().all(|l| l == l.trim_end()));
        assert!(h.contains("PKG[:repo][@ver]"), "{h}");
    }

    #[test]
    fn only_system_changes_need_root() {
        assert!(needs_root("install", &["pfetch"]) && needs_root("upgrade", &[]) && needs_root("channel", &["edge"]));
        assert!(needs_root("repo", &["enable", "extra"]) && needs_root("clean", &[]));
        for (c, o) in [("list", vec![]), ("search", vec!["x"]), ("info", vec!["x"]), ("verify", vec![]), ("channel", vec![]), ("repo", vec![]), ("repo", vec!["list"])] {
            assert!(!needs_root(c, &o), "{c} {o:?}");
        }
    }

    fn picked(line: &str) -> Result<Option<&'static str>> {
        mode(&mut Args::new(line.split_whitespace().map(String::from)))
    }

    #[test]
    fn letters_pick_one_action_and_combine() {
        assert_eq!(picked("-iby nano").unwrap(), Some("install"));
        assert_eq!(picked("-uay").unwrap(), Some("upgrade"));
        assert_eq!(picked("-ry nano").unwrap(), Some("remove"));
        assert_eq!(picked("-li").unwrap(), Some("list"));
        assert_eq!(picked("-q nano").unwrap(), Some("info"));
        assert_eq!(picked("-s x").unwrap(), Some("search"));
        assert_eq!(picked("repo").unwrap(), None);
        assert!(picked("-ir nano").is_err());
    }

    #[test]
    fn styling_only_touches_the_marker() {
        assert_eq!(style("  +  hello  1.0"), "  \x1b[32m+\x1b[0m  hello  1.0");
        assert_eq!(style("plain line"), "plain line");
        assert!(style("done  2 installed").starts_with("\x1b[1;32mdone"));
    }
}

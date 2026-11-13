mod common;
use common::*;
use ast::config::Channel;
use ast::error::Error;
use ast::ops::Flags;
use ast::package::Status;

/// Repo with nginx -> pcre2, zlib (+ an unrelated package) installed through
/// the full pipeline: update, search, install with dependencies, verify.
fn basic_env() -> (Env, usize) {
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("zlib", "1.3.1"));
    env.add(r, &pkg("pcre2", "10.46").deps(&["zlib >= 1.3"]));
    env.add(r, &pkg("nginx", "1.28.0").deps(&["pcre2", "zlib"]).config("/etc/nginx/nginx.conf", "worker_processes 1;\n").service("nginx"));
    env.add(r, &pkg("other", "1.0"));
    env.publish(r);
    (env, r)
}

#[test]
fn update_search_install_verify_remove() {
    let (env, _) = basic_env();
    let m = env.ast();
    let mut ui = TestUi::new();
    m.update(&mut ui).unwrap();
    assert_eq!(ui.out.iter().filter(|l| l.contains("ast") && l.contains("4 packages")).count(), 1, "{:?}", ui.out);
    // update must not download any package
    assert!(!env.path("var/cache/ast/packages").exists() || std::fs::read_dir(env.path("var/cache/ast/packages")).unwrap().next().is_none());

    let mut ui = TestUi::new();
    assert_eq!(m.search("nginx", &mut ui).unwrap(), 1);
    assert_eq!(m.search("no-such-thing", &mut ui).unwrap(), 0);

    let mut ui = TestUi::new();
    m.install(&["nginx".into()], &mut ui).unwrap();
    let all = ui.all();
    assert!(all.contains("zlib") && all.contains("pcre2") && all.contains("3 to install"), "{all}");
    assert!(all.contains("service not enabled: rc-update add nginx default"), "{all}");
    assert_eq!(env.read("usr/bin/nginx"), "nginx 1.28.0\n");
    assert!(env.exists("usr/bin/zlib") && env.exists("usr/bin/pcre2"));
    assert!(env.exists("etc/nginx/nginx.conf"));
    // services are never enabled automatically
    assert!(!env.exists("etc/runlevels"));
    assert!(env.installed("nginx") && env.installed("zlib"));
    // reasons recorded
    let rec = env.read("var/lib/ast/db/installed/zlib.toml");
    assert!(rec.contains("reason = \"dependency\""), "{rec}");
    // no journal left behind
    assert!(!env.path("var/lib/ast/db/txn").exists());
    // the operation log has entries
    assert!(env.read("var/log/ast.log").contains("install nginx"));

    let mut ui = TestUi::new();
    assert_eq!(m.verify(&[], &mut ui).unwrap(), 0, "{}", ui.all());

    // installing again is a no-op
    let mut ui = TestUi::new();
    m.install(&["nginx".into()], &mut ui).unwrap();
    assert!(ui.all().contains("installed ("));

    // remove: nginx plus orphaned dependencies, but never someone else's files
    let before_other = std::fs::read_to_string(env.path("usr/bin/other")).ok();
    let mut ui = TestUi::new();
    m.install(&["other".into()], &mut ui).unwrap();
    let mut ui = TestUi::new();
    m.remove(&["nginx".into()], &mut ui).unwrap();
    assert!(ui.all().contains("unneeded"), "{}", ui.all());
    assert!(!env.exists("usr/bin/nginx") && !env.exists("usr/bin/zlib") && !env.exists("usr/bin/pcre2"));
    assert!(!env.exists("etc/nginx/nginx.conf"), "unmodified config is removed with the package");
    assert!(!env.exists("etc/nginx"), "empty directories are cleaned");
    assert!(env.exists("usr/bin/other") && env.exists("usr/bin"), "other packages and shared dirs survive");
    assert!(before_other.is_none());
    assert!(!env.installed("nginx") && !env.installed("zlib") && env.installed("other"));
}

#[test]
fn removal_is_blocked_by_dependents_and_keeps_modified_configs() {
    let (env, _) = basic_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["nginx".into()], &mut TestUi::new()).unwrap();
    let e = m.remove(&["zlib".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Conflict(_)) && e.to_string().contains("required by"), "{e}");
    assert!(env.exists("usr/bin/zlib"));

    std::fs::write(env.path("etc/nginx/nginx.conf"), "my edits\n").unwrap();
    let mut ui = TestUi::new();
    m.remove(&["nginx".into()], &mut ui).unwrap();
    assert_eq!(env.read("etc/nginx/nginx.conf"), "my edits\n");
    assert!(ui.all().contains("edited config kept"), "{}", ui.all());
    assert!(!env.exists("usr/bin/nginx"));
    assert!(matches!(m.remove(&["ghost".into()], &mut TestUi::new()), Err(Error::NotFound(_))));
}

#[test]
fn verify_detects_modified_and_missing_files() {
    let (env, _) = basic_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["pcre2".into()], &mut TestUi::new()).unwrap();
    std::fs::write(env.path("usr/bin/zlib"), "tampered").unwrap();
    std::fs::remove_file(env.path("usr/bin/pcre2")).unwrap();
    let mut ui = TestUi::new();
    assert_eq!(m.verify(&[], &mut ui).unwrap(), 2);
    let all = ui.all();
    assert!(all.contains("modified") && all.contains("missing"), "{all}");
    assert_eq!(m.verify(&["zlib".into()], &mut TestUi::new()).unwrap(), 1);
}

#[test]
fn unsigned_and_tampered_indexes_are_rejected() {
    let (env, r) = basic_env();
    let m = env.ast();
    // flipped byte in the index => signature no longer matches
    let idx = env.repos[r].dir.join("index.toml");
    let mut bytes = std::fs::read(&idx).unwrap();
    let pos = bytes.iter().position(|&b| b == b'1').unwrap();
    bytes[pos] = b'2';
    std::fs::write(&idx, bytes).unwrap();
    let e = m.update(&mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Verify(_)), "{e}");
    assert!(!env.path("var/lib/ast/db/repos/ast/index.toml").exists(), "bad index must not be cached");

    // missing signature
    let (env, r) = basic_env();
    std::fs::remove_file(env.repos[r].dir.join("index.toml.sig")).unwrap();
    let e = env.ast().update(&mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Verify(_)) && e.to_string().contains("unsigned"), "{e}");

    // signed by the wrong key
    let (mut env, _) = basic_env();
    env.repos[0].key = ast::security::SecretKey::generate().unwrap();
    env.publish(0);
    // keys in /etc/ast/keys still carry the OLD public key
    env.configure();
    let old_pub = std::fs::read_to_string(env.path("etc/ast/keys/ast.pub")).unwrap();
    std::fs::write(env.path("etc/ast/keys/ast.pub"), old_pub.replace(&old_pub[..4], "0000")).unwrap();
    let e = ast::ops::Ast::open(&env.root, Flags::default()).unwrap().update(&mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Verify(_) | Error::Parse(_) | Error::Config(_)), "{e}");
}

#[test]
fn tampered_cached_index_is_detected_on_use() {
    let (env, _) = basic_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    let cached = env.path("var/lib/ast/db/repos/ast/index.toml");
    let text = std::fs::read_to_string(&cached).unwrap().replace("nginx", "nginy");
    std::fs::write(&cached, text).unwrap();
    let e = m.install(&["nginy".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Verify(_)), "{e}");
}

#[test]
fn tampered_or_unsigned_package_is_rejected_before_unpacking() {
    // artifact modified after indexing: checksum mismatch, nothing installed
    let (env, r) = basic_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    let f = env.repos[r].dir.join("other-1.0-1.ast");
    let mut b = std::fs::read(&f).unwrap();
    let n = b.len() - 3;
    b[n] ^= 0x55;
    std::fs::write(&f, b).unwrap();
    let before = snapshot(&env.root);
    let e = m.install(&["other".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Verify(_)), "{e}");
    assert!(!env.exists("usr/bin/other"));
    // cache holds no corrupted artifact
    let cached: Vec<_> = snapshot(&env.path("var/cache/ast/packages"));
    assert!(cached.iter().all(|c| !c.ends_with(".part") && !c.contains("other")), "{cached:?}");
    let _ = before;

    // detached signature missing
    let (env, r) = basic_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    std::fs::remove_file(env.repos[r].dir.join("other-1.0-1.ast.sig")).unwrap();
    let e = m.install(&["other".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Verify(_)) && e.to_string().contains("signature"), "{e}");
    assert!(!env.exists("usr/bin/other"));

    // signature from a different key
    let (env, r) = basic_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    let evil = ast::security::SecretKey::generate().unwrap();
    ast::repogen::sign_package(&env.repos[r].dir.join("other-1.0-1.ast"), &evil).unwrap();
    let e = m.install(&["other".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Verify(_)), "{e}");
    assert!(!env.exists("usr/bin/other"));
}

#[test]
fn community_repo_key_cannot_sign_for_official_repo() {
    // Package in `ast` signed with the key of `space`: rejected, because each repo has its own key.
    let mut env = Env::new();
    let ast = env.add_repo("ast", 100);
    let space = env.add_repo("space", 50);
    env.add(ast, &pkg("official", "1.0"));
    env.publish(ast);
    env.publish(space);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    ast::repogen::sign_package(&env.repos[ast].dir.join("official-1.0-1.ast"), &env.repos[space].key).unwrap();
    let e = m.install(&["official".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Verify(_)), "{e}");
}

#[test]
fn untested_dependency_blocks_when_not_allowed() {
    let mut env = Env::new();
    env.allow_untested = false;
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("libc", "2.40").status(Status::Untested));
    env.add(r, &pkg("app", "1.0").deps(&["libc"]));
    env.publish(r);
    let m = env.ast_with(Flags { yes: true, accept_untested: true, ..Default::default() });
    m.update(&mut TestUi::new()).unwrap();
    let e = m.install(&["app".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Untested(_)), "{e}");
    assert!(e.to_string().contains("libc  2.40"));
    assert!(!env.exists("usr/bin/app") && !env.exists("usr/bin/libc"));
}

#[test]
fn allow_untested_still_needs_explicit_confirmation() {
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("linux", "7.1").status(Status::Untested));
    env.add(r, &pkg("device-tree", "1.2").status(Status::Untested));
    env.add(r, &pkg("busybox", "1.37").status(Status::Tested));
    env.add(r, &pkg("app", "1.0").deps(&["linux", "device-tree", "busybox"]));
    env.publish(r);
    // `--yes` alone: the ordinary prompt is skipped, the untested one is NOT
    let m = env.ast_with(Flags { yes: true, ..Default::default() });
    m.update(&mut TestUi::new()).unwrap();
    let mut ui = TestUi::new(); // every question answered "no"
    let e = m.install(&["app".into()], &mut ui).unwrap_err();
    assert!(matches!(e, Error::Aborted), "{e}");
    assert_eq!(ui.asked, vec!["install untested components?"]);
    let all = ui.all();
    assert!(all.contains("untested system components") && all.contains("linux  7.1") && all.contains("device-tree  1.2"), "{all}");
    assert!(!all.contains("busybox 1.37\n") || !ui.warns.iter().any(|w| w.contains("busybox")), "tested components are not listed as untested");
    assert!(!env.exists("usr/bin/app") && !env.exists("usr/bin/linux"));
    assert!(!env.installed("app"));

    // explicit "yes" to the extra question installs
    let mut ui = TestUi::answering(&[true]);
    m.install(&["app".into()], &mut ui).unwrap();
    assert!(env.exists("usr/bin/linux") && env.exists("usr/bin/app"));

    // `--accept-untested` is the explicit, named bypass and says so
    let env2 = {
        let mut e = Env::new();
        let r = e.add_repo("ast", 100);
        e.add(r, &pkg("linux", "7.1").status(Status::Untested));
        e.publish(r);
        e
    };
    let m2 = env2.ast_with(Flags { yes: true, accept_untested: true, ..Default::default() });
    m2.update(&mut TestUi::new()).unwrap();
    let mut ui = TestUi::new();
    m2.install(&["linux".into()], &mut ui).unwrap();
    assert!(ui.asked.is_empty());
    assert!(ui.warns.iter().any(|w| w.contains("--accept-untested")));
    assert!(env2.exists("usr/bin/linux"));
}

#[test]
fn ordinary_packages_have_no_status_and_install_without_the_warning() {
    let (env, _) = basic_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    let mut ui = TestUi::new();
    m.install(&["nginx".into()], &mut ui).unwrap();
    assert!(ui.asked.is_empty());
    assert!(!ui.all().contains("untested"));
    assert!(!env.read("var/lib/ast/db/installed/nginx.toml").contains("status"));
}

#[test]
fn multi_package_upgrade_lists_all_untested_components() {
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("linux", "6.1").status(Status::Tested));
    env.add(r, &pkg("device-tree", "1.1").status(Status::Tested));
    env.publish(r);
    let m = env.ast_with(Flags { yes: true, accept_untested: true, ..Default::default() });
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["linux".into(), "device-tree".into()], &mut TestUi::new()).unwrap();
    env.add(r, &pkg("linux", "7.0").status(Status::Untested));
    env.add(r, &pkg("device-tree", "1.2").status(Status::Untested));
    env.publish(r);
    let m = env.ast_with(Flags { yes: true, ..Default::default() });
    m.update(&mut TestUi::new()).unwrap();
    let mut ui = TestUi::new();
    let e = m.upgrade(&[], &mut ui).unwrap_err();
    assert!(matches!(e, Error::Aborted));
    let all = ui.all();
    assert!(all.contains("linux  7.0") && all.contains("device-tree  1.2"), "{all}");
    assert_eq!(env.read("usr/bin/linux"), "linux 6.1\n");
}

#[test]
fn bin_suffix_requires_binary_and_never_falls_back() {
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add_recipe(r, "hello", "1.0", &[], &[], "mkdir -p \"$DESTDIR/usr/bin\"\ninstall -m755 hello.sh \"$DESTDIR/usr/bin/hello\"");
    env.add(r, &pkg("tool", "2.0"));
    env.add_recipe(r, "tool", "2.0", &[], &[], "mkdir -p \"$DESTDIR/usr/bin\"\ninstall -m755 hello.sh \"$DESTDIR/usr/bin/tool\"");
    env.publish(r);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();

    // source-only package: `hello-bin` is refused, nothing is built
    let mut ui = TestUi::new();
    let e = m.install(&["hello-bin".into()], &mut ui).unwrap_err();
    assert!(matches!(e, Error::Resolve(_)) && e.to_string().contains("no binary package"), "{e}");
    assert!(!env.exists("usr/bin/hello"));
    assert!(!env.path("var/cache/ast/build/hello-1.0.log").exists(), "no build was attempted");

    // plain `hello` builds from source (after the recipe warning and confirmation)
    let mut ui = TestUi::new();
    m.install(&["hello".into()], &mut ui).unwrap();
    assert!(ui.warns.iter().any(|w| w.contains("runs recipe scripts")), "{:?}", ui.warns);
    assert!(env.exists("usr/bin/hello"));
    let rec = env.read("var/lib/ast/db/installed/hello.toml");
    assert!(rec.contains("kind = \"source\"") && rec.contains("source_sha256"), "{rec}");

    // `tool` has both: -bin installs the binary, and it is the SAME package as `tool`
    m.install(&["tool-bin".into()], &mut TestUi::new()).unwrap();
    assert_eq!(env.read("usr/bin/tool"), "tool 2.0\n");
    let rec = env.read("var/lib/ast/db/installed/tool.toml");
    assert!(rec.contains("kind = \"binary\""), "{rec}");
    assert!(!env.installed("tool-bin"));
    // asking for `tool` afterwards does not install a second copy
    let mut ui = TestUi::new();
    m.install(&["tool".into()], &mut ui).unwrap();
    assert!(ui.all().contains("installed ("));
    // unknown -bin package
    let e = m.install(&["ghost-bin".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::NotFound(_)), "{e}");
}

#[test]
fn source_build_disabled_is_reported() {
    let mut env = Env::new();
    env.build_enabled = false;
    let r = env.add_repo("ast", 100);
    env.add_recipe(r, "hello", "1.0", &[], &[], "true");
    env.publish(r);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    let e = m.install(&["hello".into()], &mut TestUi::new()).unwrap_err();
    assert!(e.to_string().contains("building is disabled"), "{e}");
}

#[test]
fn failed_build_rolls_back_earlier_packages_of_the_transaction() {
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("lib", "1.0"));
    env.add_recipe(r, "broken", "1.0", &["lib"], &[], "echo compiling >&2\nexit 7");
    env.publish(r);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    let before = snapshot(&env.root.join("usr"));
    let mut ui = TestUi::new();
    let e = m.install(&["broken".into()], &mut ui).unwrap_err();
    assert!(matches!(e, Error::Build(_)) && e.to_string().contains("compiling"), "{e}");
    assert!(ui.all().contains("rolled back"));
    assert!(!env.exists("usr/bin/lib"), "lib (installed earlier in the same transaction) was rolled back");
    assert_eq!(snapshot(&env.root.join("usr")), before);
    assert!(!env.installed("lib") && !env.installed("broken"));
    assert!(!env.path("var/lib/ast/db/txn").exists());
    assert!(!env.path("var/cache/ast/build/broken-1.0").exists(), "temporary build data cleaned");
    assert!(env.path("var/cache/ast/build/broken-1.0.log").exists(), "log kept for the user");
}

#[test]
fn build_dependencies_do_not_become_runtime_dependencies() {
    let mut env = Env::new();
    env.prefer_binary = false;
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("gcc", "14.0"));
    env.add_recipe(r, "prog", "1.0", &[], &["gcc"], "mkdir -p \"$DESTDIR/usr/bin\"\ninstall -m755 hello.sh \"$DESTDIR/usr/bin/prog\"");
    env.publish(r);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["prog".into()], &mut TestUi::new()).unwrap();
    assert!(env.exists("usr/bin/gcc") && env.exists("usr/bin/prog"));
    let rec = env.read("var/lib/ast/db/installed/prog.toml");
    assert!(!rec.contains("gcc"), "{rec}");
    assert!(env.read("var/lib/ast/db/installed/gcc.toml").contains("reason = \"build\""));
    // gcc is an orphan now and goes away with the next removal
    m.remove(&["prog".into()], &mut TestUi::new()).unwrap();
    assert!(!env.exists("usr/bin/gcc"));
}

#[test]
fn file_conflicts_between_packages_are_refused_and_rolled_back() {
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("first", "1.0").only_files(&[("usr/share/shared.txt", "from first\n"), ("usr/bin/first", "x\n")]));
    env.add(r, &pkg("good", "1.0"));
    env.add(r, &pkg("second", "1.0").deps(&["good"]).only_files(&[("usr/share/shared.txt", "from second\n"), ("usr/bin/second", "x\n")]));
    env.publish(r);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["first".into()], &mut TestUi::new()).unwrap();
    let before = snapshot(&env.root);
    let e = m.install(&["second".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Conflict(_)) && e.to_string().contains("owned by package first"), "{e}");
    assert_eq!(env.read("usr/share/shared.txt"), "from first\n");
    // `good` was installed first inside the transaction, then rolled back: system unchanged
    let after = snapshot(&env.root);
    let strip = |v: &Vec<String>| v.iter().filter(|l| !l.contains("ast.log") && !l.contains("var/cache") && !l.contains("var/lib/ast/lock")).cloned().collect::<Vec<_>>();
    assert_eq!(strip(&before), strip(&after));
    assert!(!env.exists("usr/bin/good"));
}

#[test]
fn unowned_existing_files_are_never_overwritten() {
    let (env, _) = basic_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    std::fs::create_dir_all(env.path("usr/bin")).unwrap();
    std::fs::write(env.path("usr/bin/other"), "user's own program\n").unwrap();
    let e = m.install(&["other".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Conflict(_)), "{e}");
    assert_eq!(env.read("usr/bin/other"), "user's own program\n");
}

#[test]
fn replaces_transfers_ownership() {
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("oldname", "1.0").only_files(&[("usr/bin/tool", "old\n")]));
    env.add(r, &pkg("newname", "2.0").replaces(&["oldname"]).only_files(&[("usr/bin/tool", "new\n")]));
    env.publish(r);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["oldname".into()], &mut TestUi::new()).unwrap();
    let mut ui = TestUi::new();
    m.install(&["newname".into()], &mut ui).unwrap();
    assert!(ui.all().contains("replaced by newname"));
    assert_eq!(env.read("usr/bin/tool"), "new\n");
    assert!(!env.installed("oldname") && env.installed("newname"));
}

#[test]
fn conflicting_packages_cannot_both_be_installed() {
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("a", "1.0").conflicts(&["b"]));
    env.add(r, &pkg("b", "1.0"));
    env.publish(r);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["b".into()], &mut TestUi::new()).unwrap();
    let e = m.install(&["a".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Resolve(_)) && e.to_string().contains("conflict"), "{e}");
    assert!(!env.exists("usr/bin/a"));
}

#[test]
fn upgrade_replaces_files_preserves_user_config_and_drops_stale_files() {
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("app", "1.0").config("/etc/app.conf", "default v1\n").file("usr/share/app/old.txt", "old\n").service("app"));
    env.publish(r);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["app".into()], &mut TestUi::new()).unwrap();
    std::fs::write(env.path("etc/app.conf"), "user edited\n").unwrap();
    // pretend the service runs
    std::fs::create_dir_all(env.path("run/openrc/started")).unwrap();
    std::fs::write(env.path("run/openrc/started/app"), "").unwrap();

    env.add(r, &pkg("app", "2.0").config("/etc/app.conf", "default v2\n").file("usr/share/app/new.txt", "new\n").service("app"));
    env.publish(r);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    let mut ui = TestUi::new();
    m.upgrade(&[], &mut ui).unwrap();
    let all = ui.all();
    assert!(all.contains("~  app") && all.contains("1.0-1 -> 2.0-1"), "{all}");
    assert_eq!(env.read("usr/bin/app"), "app 2.0\n");
    assert_eq!(env.read("etc/app.conf"), "user edited\n", "edited config is kept");
    assert_eq!(env.read("etc/app.conf.astnew"), "default v2\n");
    assert!(all.contains("app.conf.astnew"));
    assert!(!env.exists("usr/share/app/old.txt") && env.exists("usr/share/app/new.txt"));
    assert!(all.contains("rc-service app restart"), "running service is reported, not restarted: {all}");
    assert!(env.read("var/lib/ast/db/installed/app.toml").contains("version = \"2.0\""));

    // nothing left to do
    let mut ui = TestUi::new();
    m.upgrade(&[], &mut ui).unwrap();
    assert!(ui.all().contains("nothing to upgrade"));

    // an UNEDITED config is overwritten by the next upgrade
    env.add(r, &pkg("app", "3.0").config("/etc/app.conf", "default v3\n").service("app"));
    std::fs::remove_file(env.path("etc/app.conf")).ok();
    std::fs::write(env.path("etc/app.conf"), "default v2\n").unwrap(); // user "accepted" v2? recorded hash is v2's
    env.publish(r);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.upgrade(&[], &mut TestUi::new()).unwrap();
    assert_eq!(env.read("etc/app.conf"), "default v3\n");
}

#[test]
fn upgrade_failure_leaves_old_version_intact() {
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("app", "1.0"));
    env.publish(r);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["app".into()], &mut TestUi::new()).unwrap();
    // v2 collides with a file owned by nobody and present on disk
    env.add(r, &pkg("app", "2.0").file("usr/share/collide", "x\n"));
    env.publish(r);
    std::fs::create_dir_all(env.path("usr/share")).unwrap();
    std::fs::write(env.path("usr/share/collide"), "pre-existing\n").unwrap();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    let e = m.upgrade(&[], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Conflict(_)), "{e}");
    assert_eq!(env.read("usr/bin/app"), "app 1.0\n");
    assert_eq!(env.read("usr/share/collide"), "pre-existing\n");
    assert!(env.read("var/lib/ast/db/installed/app.toml").contains("version = \"1.0\""));
}

#[test]
fn repository_priority_selects_the_source_repo() {
    let mut env = Env::new();
    let ast = env.add_repo("ast", 100);
    let space = env.add_repo("space", 50);
    env.add(ast, &pkg("tool", "1.0"));
    env.add(space, &pkg("tool", "9.0"));
    env.add(space, &pkg("only-space", "1.0"));
    env.publish(ast);
    env.publish(space);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["tool".into(), "only-space".into()], &mut TestUi::new()).unwrap();
    assert_eq!(env.read("usr/bin/tool"), "tool 1.0\n");
    assert!(env.read("var/lib/ast/db/installed/tool.toml").contains("repo = \"ast\""));
    assert!(env.read("var/lib/ast/db/installed/only-space.toml").contains("repo = \"space\""));
    let mut ui = TestUi::new();
    m.info("tool", &mut ui).unwrap();
    assert!(ui.all().contains("others") && ui.all().contains("space 9.0"), "{}", ui.all());
}

#[test]
fn channels_and_repo_enable_disable() {
    let mut env = Env::new();
    let stable = env.add_repo_ch("ast", 100, Channel::Stable);
    let edge = env.add_repo_ch("ast-edge", 100, Channel::Edge);
    env.add(stable, &pkg("tool", "1.0"));
    env.add(edge, &pkg("tool", "2.0"));
    env.publish(stable);
    env.publish(edge);
    let m = env.ast();
    // edge repo is enabled in repos.toml but inactive on the stable channel
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["tool".into()], &mut TestUi::new()).unwrap();
    assert_eq!(env.read("usr/bin/tool"), "tool 1.0\n");

    let mut ui = TestUi::new();
    m.channel(None, &mut ui).unwrap();
    assert_eq!(ui.out, vec!["stable"]);
    // switching is explicit and never touches installed packages or repos
    let mut ui = TestUi::new();
    m.channel(Some("edge"), &mut ui).unwrap();
    assert_eq!(env.read("usr/bin/tool"), "tool 1.0\n");
    assert!(m.channel(Some("nightly"), &mut TestUi::new()).is_err());
    let toml = std::fs::read_to_string(env.path("etc/ast/ast.toml")).unwrap();
    assert!(toml.contains("channel = \"edge\""));
    let m = ast::ops::Ast::open(&env.root, Flags { yes: true, ..Default::default() }).unwrap();
    let mut ui = TestUi::new();
    m.repo_list(&mut ui);
    let l = ui.all();
    assert!(l.contains("channel  edge") && l.contains("inactive"), "{l}");
    m.update(&mut TestUi::new()).unwrap();
    m.upgrade(&[], &mut TestUi::new()).unwrap();
    assert_eq!(env.read("usr/bin/tool"), "tool 2.0\n");

    // repo enable/disable edit repos.toml
    m.repo_set_enabled("ast-edge", false, &mut TestUi::new()).unwrap();
    let r = std::fs::read_to_string(env.path("etc/ast/repos.toml")).unwrap();
    assert!(r.contains("enabled = false"));
    assert!(matches!(m.repo_set_enabled("nope", true, &mut TestUi::new()), Err(Error::NotFound(_))));
}

#[test]
fn clean_removes_cache_but_keeps_database() {
    let (env, _) = basic_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["other".into()], &mut TestUi::new()).unwrap();
    assert!(std::fs::read_dir(env.path("var/cache/ast/packages")).unwrap().next().is_some());
    m.clean(&mut TestUi::new()).unwrap();
    assert!(std::fs::read_dir(env.path("var/cache/ast/packages")).unwrap().next().is_none());
    assert!(env.installed("other"));
    assert!(env.path("var/lib/ast/db/repos/ast/index.toml").exists());
    assert_eq!(m.list(&mut TestUi::new()).unwrap(), 1);
    // after clean the package can still be verified and removed
    assert_eq!(m.verify(&[], &mut TestUi::new()).unwrap(), 0);
}

#[test]
fn dry_run_changes_nothing() {
    let (env, _) = basic_env();
    let m = env.ast_with(Flags { yes: true, dry_run: true, ..Default::default() });
    m.update(&mut TestUi::new()).unwrap();
    let mut ui = TestUi::new();
    m.install(&["nginx".into()], &mut ui).unwrap();
    assert!(ui.all().contains("dry run"));
    assert!(!env.exists("usr/bin/nginx"));
}

#[test]
fn declining_the_prompt_aborts_without_changes() {
    let (env, _) = basic_env();
    let m = env.ast_with(Flags::default());
    m.update(&mut TestUi::new()).unwrap();
    let mut ui = TestUi::new(); // answers "no"
    assert!(matches!(m.install(&["nginx".into()], &mut ui), Err(Error::Aborted)));
    assert_eq!(ui.asked, vec!["proceed?"]);
    assert!(!env.exists("usr/bin/nginx") && !env.installed("nginx"));
}

#[test]
fn concurrent_operations_are_blocked_by_the_lock() {
    let (env, _) = basic_env();
    let m = env.ast();
    let _held = ast::util::LockGuard::acquire(&env.path("var/lib/ast/lock")).unwrap();
    let e = m.update(&mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Locked(_)));
    assert_eq!(e.exit_code(), 7);
}

#[test]
fn interrupted_transaction_is_rolled_back_by_the_next_run() {
    let (env, _) = basic_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    let paths = ast::util::Paths::new(&env.root);
    // simulate a crash in the middle of an install: journal + a half-written file
    std::fs::create_dir_all(env.path("usr/bin")).unwrap();
    let mut t = ast::txn::Txn::begin(&paths).unwrap();
    t.create_file(&env.path("usr/bin/half"), 0o755, &mut &b"partial"[..]).unwrap();
    std::mem::forget(t);
    assert!(env.exists("usr/bin/half"));
    let mut ui = TestUi::new();
    m.install(&["other".into()], &mut ui).unwrap();
    assert!(!env.exists("usr/bin/half"));
    assert!(ui.warns.iter().any(|w| w.contains("interrupted transaction")));
    assert!(env.exists("usr/bin/other"));
}

#[test]
fn arch_mismatch_is_rejected() {
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("tool", "1.0"));
    env.publish(r);
    env.configure();
    // system says aarch64 but the repository serves x86_64
    let p = env.path("etc/ast/ast.toml");
    let t = std::fs::read_to_string(&p).unwrap().replace("x86_64", "aarch64");
    std::fs::write(&p, t).unwrap();
    let m = ast::ops::Ast::open(&env.root, Flags::default()).unwrap();
    let e = m.update(&mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Verify(_)) && e.to_string().contains("architecture"), "{e}");
}

#[test]
fn install_notice_and_system_component_message() {
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("linux", "6.6").status(Status::Tested).notice("run mkinitfs and reboot"));
    env.publish(r);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    let mut ui = TestUi::new();
    m.install(&["linux".into()], &mut ui).unwrap();
    let all = ui.all();
    assert!(all.contains("run mkinitfs and reboot") && all.contains("applies after reboot"), "{all}");
    assert!(env.read("var/lib/ast/db/installed/linux.toml").contains("status = \"tested\""));
}

#[test]
fn removal_warns_about_enabled_and_running_services() {
    let (env, _) = basic_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["nginx".into()], &mut TestUi::new()).unwrap();
    std::fs::create_dir_all(env.path("etc/runlevels/default")).unwrap();
    std::os::unix::fs::symlink("/etc/init.d/nginx", env.path("etc/runlevels/default/nginx")).unwrap();
    std::fs::create_dir_all(env.path("run/openrc/started")).unwrap();
    std::fs::write(env.path("run/openrc/started/nginx"), "").unwrap();
    let mut ui = TestUi::new();
    m.remove(&["nginx".into()], &mut ui).unwrap();
    let w = ui.warns.join("\n");
    assert!(w.contains("rc-service nginx stop") && w.contains("rc-update del nginx"), "{w}");
    // ast itself did not touch runlevels
    assert!(std::fs::symlink_metadata(env.path("etc/runlevels/default/nginx")).is_ok());
}

#[test]
fn symlink_in_target_root_cannot_redirect_writes_outside() {
    // A pre-existing symlink pointing outside the root must not be followed.
    let mut env = Env::new();
    let r = env.add_repo("ast", 100);
    env.add(r, &pkg("evil", "1.0").only_files(&[("data/payload.txt", "x\n")]));
    env.publish(r);
    let outside = env.dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    std::os::unix::fs::symlink("../../outside", env.path("data")).unwrap();
    let e = m.install(&["evil".into()], &mut TestUi::new());
    assert!(e.is_err(), "writing through a root-escaping symlink must fail");
    assert!(std::fs::read_dir(&outside).unwrap().next().is_none(), "nothing may be written outside the root");

    // An absolute symlink is interpreted relative to the root (chroot semantics), staying inside.
    let _ = std::fs::remove_file(env.path("data"));
    std::fs::create_dir_all(env.path("real")).unwrap();
    std::os::unix::fs::symlink("/real", env.path("data")).unwrap();
    m.install(&["evil".into()], &mut TestUi::new()).unwrap();
    assert!(env.exists("real/payload.txt"));
    assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
}

fn foreign_env() -> Env {
    let mut env = Env::new();
    let ast = env.add_repo_ch("ast", 100, Channel::Stable);
    let edge = env.add_repo_ch("space-edge", 50, Channel::Edge);
    env.add(ast, &pkg("zlib", "1.3.1"));
    env.add(edge, &pkg("zlib", "1.4.0"));
    env.add(edge, &pkg("telegram-desktop", "5.0").deps(&["zlib >= 1.3"]));
    env.add(edge, &pkg("telegram-desktop", "5.1").deps(&["zlib >= 1.3"]));
    env.add(edge, &pkg("tg-new", "1.0").deps(&["zlib >= 1.4"]));
    env.publish(ast);
    env.publish(edge);
    env
}

#[test]
fn install_from_another_channel_with_name_repo_version_syntax() {
    let env = foreign_env();
    let m = env.ast();
    let mut ui = TestUi::new();
    m.update(&mut ui).unwrap();
    assert!(ui.all().contains("space-edge") && ui.all().contains("used only via"), "{}", ui.all());

    // not visible without naming the repository: the system is on stable
    let e = m.install(&["telegram-desktop".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::NotFound(_)), "{e}");
    assert_eq!(m.search("telegram", &mut TestUi::new()).unwrap(), 0);

    // explicit repository, latest version ('@*'); dependency zlib comes from the stable repo
    let mut ui = TestUi::new();
    m.install(&["telegram-desktop:space-edge@*".into()], &mut ui).unwrap();
    assert_eq!(env.read("usr/bin/telegram-desktop"), "telegram-desktop 5.1\n");
    assert_eq!(env.read("usr/bin/zlib"), "zlib 1.3.1\n", "dependencies stay on the current channel when they can");
    assert!(ui.asked.is_empty(), "naming the package is the consent: {:?}", ui.asked);
    let all = ui.all();
    assert!(all.contains("outside the current channel (stable)") && all.contains("edge channel"), "{all}");
    assert!(env.read("var/lib/ast/db/installed/telegram-desktop.toml").contains("repo = \"space-edge\""));
    assert!(env.read("var/lib/ast/db/installed/zlib.toml").contains("repo = \"ast\""));

    // `ast -u` never silently moves anything between channels
    let mut ui = TestUi::new();
    m.upgrade(&[], &mut ui).unwrap();
    assert!(ui.all().contains("nothing to upgrade"), "{}", ui.all());
}

#[test]
fn exact_version_and_omitted_version() {
    let env = foreign_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    m.install(&["telegram-desktop:space-edge@5.0".into()], &mut TestUi::new()).unwrap();
    assert_eq!(env.read("usr/bin/telegram-desktop"), "telegram-desktop 5.0\n");
    // no '@': latest; replaces the installed 5.0 with 5.1 from the same repository
    m.install(&["telegram-desktop:space-edge".into()], &mut TestUi::new()).unwrap();
    assert_eq!(env.read("usr/bin/telegram-desktop"), "telegram-desktop 5.1\n");
    // asking again changes nothing
    let mut ui = TestUi::new();
    m.install(&["telegram-desktop:space-edge@*".into()], &mut ui).unwrap();
    assert!(ui.all().contains("installed ("), "{}", ui.all());
    let e = m.install(&["telegram-desktop:space-edge@9.9".into()], &mut TestUi::new()).unwrap_err();
    assert!(e.to_string().contains("no version of telegram-desktop"), "{e}");
}

#[test]
fn dependencies_from_another_channel_need_their_own_consent() {
    let env = foreign_env();
    let m = env.ast(); // --yes
    m.update(&mut TestUi::new()).unwrap();
    // tg-new needs zlib >= 1.4, which exists only in the edge repository
    let mut ui = TestUi::new();
    let e = m.install(&["tg-new:space-edge".into()], &mut ui).unwrap_err();
    assert!(matches!(e, Error::Aborted), "{e}");
    assert_eq!(ui.asked.len(), 1);
    assert!(ui.asked[0].contains("dependencies"), "{:?}", ui.asked);
    assert!(ui.all().contains("  dependency"));
    assert!(!env.exists("usr/bin/tg-new") && !env.exists("usr/bin/zlib"));

    // a "yes" answer is required; --yes alone is not enough
    let mut ui = TestUi::answering(&[true]);
    m.install(&["tg-new:space-edge".into()], &mut ui).unwrap();
    assert_eq!(env.read("usr/bin/zlib"), "zlib 1.4.0\n");

    // the explicit flag works non-interactively
    let env = foreign_env();
    let m = env.ast_with(Flags { yes: true, accept_foreign: true, ..Default::default() });
    m.update(&mut TestUi::new()).unwrap();
    let mut ui = TestUi::new();
    m.install(&["tg-new:space-edge".into()], &mut ui).unwrap();
    assert!(ui.asked.is_empty());
    assert!(ui.warns.iter().any(|w| w.contains("--accept-foreign")));
    assert!(env.exists("usr/bin/tg-new"));
}

#[test]
fn explicit_repo_must_exist_be_enabled_and_have_the_package() {
    let env = foreign_env();
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    let e = m.install(&["tg-new:nope".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::NotFound(_)) && e.to_string().contains("not defined"), "{e}");
    let e = m.install(&["ghost:space-edge".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::NotFound(_)) && e.to_string().contains("in repository space-edge"), "{e}");
    // disabled repositories are never used implicitly
    m.repo_set_enabled("space-edge", false, &mut TestUi::new()).unwrap();
    let m = ast::ops::Ast::open(&env.root, Flags { yes: true, ..Default::default() }).unwrap();
    let e = m.install(&["tg-new:space-edge".into()], &mut TestUi::new()).unwrap_err();
    assert!(matches!(e, Error::Config(_)) && e.to_string().contains("ast repo enable space-edge"), "{e}");
    assert!(m.install(&["tg-new:".into()], &mut TestUi::new()).is_err());
}

#[test]
fn explicit_repo_inside_the_current_channel_needs_no_special_consent() {
    // `name:space` where space is an ordinary active repository of the same channel
    let mut env = Env::new();
    let ast = env.add_repo("ast", 100);
    let space = env.add_repo("space", 50);
    env.add(ast, &pkg("tool", "1.0"));
    env.add(space, &pkg("tool", "9.0"));
    env.publish(ast);
    env.publish(space);
    let m = env.ast();
    m.update(&mut TestUi::new()).unwrap();
    let mut ui = TestUi::new();
    m.install(&["tool:space".into()], &mut ui).unwrap();
    assert_eq!(env.read("usr/bin/tool"), "tool 9.0\n");
    assert!(!ui.all().contains("outside the current channel"));
}

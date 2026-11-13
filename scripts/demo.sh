#!/usr/bin/env bash
# Builds a demo environment for poking at ast:
#   scripts/demo.sh [setup]   create keys, packages, two signed repositories and a test root
#   scripts/demo.sh update    publish newer versions (hello 1.1, telegram-demo 5.2) to try `update`/`upgrade`
#   scripts/demo.sh serve     serve the repositories over HTTP on 127.0.0.1:8000
# Everything lives in $DEMO (default: ast/demo, git-ignored); the real system is never touched.
#   scripts/demo.sh reset     wipe only the test root (installed packages), keep the repositories
#   scripts/demo.sh build     rebuild ast and copy it to demo/bin
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="${DEMO:-$HERE/demo}"
PORT="${PORT:-8000}"
ARCH="$(uname -m)"
BIN="$HERE/target/release"
WWW="$DEMO/www"
ROOT="$DEMO/root"
export PATH="$BIN:$PATH"

pack() { # pack REPO NAME VERSION META_EXTRA  (files are read from $DEMO/stage/NAME-VERSION)
  local repo=$1 name=$2 ver=$3 extra=${4:-} stage="$DEMO/stage/$2-$3"
  cat > "$DEMO/stage/$name.meta.toml" <<TOML
[package]
name = "$name"
version = "$ver"
arch = "any"
description = "$name (demo package)"
license = "MIT"
$extra
TOML
  astpkg pack "$stage" --meta "$DEMO/stage/$name.meta.toml" --out "$WWW/$repo/$name-$ver-1.ast" >/dev/null
}

file() { # file NAME VERSION PATH MODE  (content on stdin)
  local f="$DEMO/stage/$1-$2/$3"
  mkdir -p "$(dirname "$f")"; cat > "$f"; chmod "$4" "$f"
}

index() { # index REPO CHANNEL KEY
  astpkg index "$WWW/$1" --name "$1" --arch "$ARCH" --channel "$2" --key "$DEMO/keys/$3.key" >/dev/null
}

build_packages() {
  rm -rf "$DEMO/stage"; mkdir -p "$DEMO/stage"

  # --- libgreet: a tiny library
  file libgreet 1.0 usr/lib/libgreet.sh 644 <<'X'
greet() { echo "Hello, $1! (libgreet 1.0)"; }
X
  pack ast libgreet 1.0

  # --- hello: depends on libgreet, has a config file and an orchid service
  file hello 1.0 usr/bin/hello 755 <<'X'
#!/bin/sh
R="$(dirname "$0")/../.."; . "$R/usr/lib/libgreet.sh"
[ -f "$R/etc/hello.conf" ] && . "$R/etc/hello.conf"
greet "${NAME:-world}"
echo "hello 1.0"
X
  file hello 1.0 etc/hello.conf 644 <<'X'
NAME=world
X
  file hello 1.0 etc/orchid/services/hello.toml 644 <<'X'
[service]
exec = ["/usr/bin/hello"]
X
  pack ast hello 1.0 'depends = ["libgreet >= 1.0"]
config_files = ["/etc/hello.conf"]'

  # --- a system component marked untested, and one marked tested
  file linux-demo 7.0 boot/vmlinuz-demo 644 <<'X'
not a real kernel
X
  pack ast linux-demo 7.0 'notice = "run mkinitfs and reboot to use the new kernel"
[release]
channel = "stable"
status = "untested"'
  file busybox-demo 1.37 usr/bin/busybox-demo 755 <<'X'
#!/bin/sh
echo busybox-demo
X
  pack ast busybox-demo 1.37 '[release]
channel = "stable"
status = "tested"'
  # an ordinary app that needs the untested kernel: shows the dependency warning
  file kernel-tool 1.0 usr/bin/kernel-tool 755 <<'X'
#!/bin/sh
echo kernel-tool
X
  pack ast kernel-tool 1.0 'depends = ["linux-demo"]'

  # --- fortune-demo: has BOTH a binary package and a source recipe (try fortune-demo-bin)
  file fortune-demo 1.0 usr/bin/fortune-demo 755 <<'X'
#!/bin/sh
echo "A watched package manager never installs. (prebuilt binary)"
X
  pack ast fortune-demo 1.0

  # --- space-edge (edge channel, its own key): telegram-demo
  file telegram-demo 5.0 usr/bin/telegram-demo 755 <<'X'
#!/bin/sh
R="$(dirname "$0")/../.."; . "$R/usr/lib/libgreet.sh"
greet telegram; echo "telegram-demo 5.0 (edge)"
X
  pack space-edge telegram-demo 5.0 'depends = ["libgreet >= 1.0"]
[release]
channel = "edge"'

  # --- pfetch: built from the official recipe of ast-packages
  astpkg build "$HERE/../ast-packages/recipes/pfetch/pfetch.recipe.toml" --out "$WWW/ast" >/dev/null
  cp "$HERE/../ast-packages/recipes/pfetch/pfetch.recipe.toml" "$WWW/ast/pfetch-0.6.0-1.recipe.toml"

  # --- source-only recipes (built on this machine by `ast install`)
  local src="$DEMO/stage/src/cowsay-lite-1.0"
  mkdir -p "$src"
  cat > "$src/cow.sh.in" <<'X'
#!/bin/sh
msg="${*:-moo}"
echo " < $msg >"
echo "   \\  ^__^"
echo "    \\ (oo)\\_______   built from source by ast, version @VERSION@"
echo "      (__)\\       )\\/\\"
X
  tar -C "$DEMO/stage/src" -czf "$WWW/ast/cowsay-lite-1.0.tar.gz" cowsay-lite-1.0
  local sha; sha=$(sha256sum "$WWW/ast/cowsay-lite-1.0.tar.gz" | cut -d' ' -f1)
  cat > "$WWW/ast/cowsay-lite-1.0-1.recipe.toml" <<TOML
[package]
name = "cowsay-lite"
version = "1.0"
description = "A cow that says things (source package with custom build phases)"
license = "MIT"
arch = ["any"]

[source]
url = "cowsay-lite-1.0.tar.gz"      # relative to the repository URL
sha256 = "$sha"

[build]
prepare = '''
sed "s/@VERSION@/\$PKGVER/" cow.sh.in > cow.sh
'''
build = '''
chmod +x cow.sh
echo "phase=\$PHASE jobs=\$JOBS arch=\$ARCH"
'''
install = '''
install -D -m755 cow.sh "\$DESTDIR/usr/bin/cowsay-lite"
'''
TOML
  # a recipe next to the fortune-demo binary: same package, two ways to get it
  cat > "$WWW/ast/fortune-demo-1.0-1.recipe.toml" <<TOML
[package]
name = "fortune-demo"
version = "1.0"
description = "fortune-demo"
license = "MIT"
arch = ["any"]

[source]
url = "cowsay-lite-1.0.tar.gz"
sha256 = "$sha"
[build]
install = '''
install -D -m755 cow.sh.in "\$DESTDIR/usr/bin/fortune-demo"
'''
TOML
}

build() { # rebuild and copy the binaries into $DEMO/bin (repositories and root are kept)
  (cd "$HERE" && cargo build --release 2>&1 | tail -1)
  mkdir -p "$DEMO/bin"
  cp "$BIN/ast" "$BIN/astpkg" "$DEMO/bin/"
}

setup() {
  rm -rf "$DEMO"; mkdir -p "$DEMO"
  build
  rm -rf "$DEMO/www" "$DEMO/keys"; mkdir -p "$WWW/ast" "$WWW/space-edge" "$DEMO/keys"
  astpkg keygen ast --out "$DEMO/keys" >/dev/null
  astpkg keygen space --out "$DEMO/keys" >/dev/null
  build_packages
  index ast stable ast
  index space-edge edge space
  make_root
}

make_root() {
  rm -rf "$ROOT"
  ast --root "$ROOT" init >/dev/null
  sed -i "s/aarch64/$ARCH/" "$ROOT/etc/ast/ast.toml"
  cp "$DEMO/keys/ast.pub" "$DEMO/keys/space.pub" "$ROOT/etc/ast/keys/"
  cat > "$ROOT/etc/ast/repos.toml" <<TOML
[ast]
url = "http://127.0.0.1:$PORT/ast"
enabled = true
priority = 100
key = "ast.pub"
channel = "stable"

[space-edge]
url = "http://127.0.0.1:$PORT/space-edge"
enabled = false
priority = 50
key = "space.pub"
channel = "edge"
TOML
  # convenience wrapper: ./ast ARGS  ==  ast --root ROOT ARGS
  cat > "$DEMO/ast" <<SH
#!/bin/sh
exec "$DEMO/bin/ast" --root "$ROOT" "\$@"
SH
  chmod +x "$DEMO/ast"
  cat <<MSG

Demo ready in $DEMO
  repositories : $WWW   (serve with: scripts/demo.sh serve)
  test root    : $ROOT
  command      : $DEMO/ast <args>      (same as: ast --root $ROOT <args>)
MSG
}

update() {
  # newer versions appear in the repositories
  file hello 1.1 usr/bin/hello 755 <<'X'
#!/bin/sh
R="$(dirname "$0")/../.."; . "$R/usr/lib/libgreet.sh"
[ -f "$R/etc/hello.conf" ] && . "$R/etc/hello.conf"
greet "${NAME:-world}"
echo "hello 1.1 (upgraded)"
X
  file hello 1.1 etc/hello.conf 644 <<'X'
NAME=world
GREETING=new-default
X
  file hello 1.1 etc/orchid/services/hello.toml 644 <<'X'
[service]
exec = ["/usr/bin/hello"]
X
  pack ast hello 1.1 'depends = ["libgreet >= 1.0"]
config_files = ["/etc/hello.conf"]'
  file telegram-demo 5.2 usr/bin/telegram-demo 755 <<'X'
#!/bin/sh
R="$(dirname "$0")/../.."; . "$R/usr/lib/libgreet.sh"
greet telegram; echo "telegram-demo 5.2 (edge)"
X
  pack space-edge telegram-demo 5.2 'depends = ["libgreet >= 1.0"]
[release]
channel = "edge"'
  index ast stable ast
  index space-edge edge space
  echo "Published hello 1.1 and telegram-demo 5.2. Now run: $DEMO/ast update && $DEMO/ast upgrade"
}

serve() {
  echo "Serving $WWW on http://127.0.0.1:$PORT  (Ctrl-C to stop)"
  cd "$WWW" && exec python3 -m http.server "$PORT" --bind 127.0.0.1
}

case "${1:-setup}" in
  setup) setup ;;
  reset) make_root ;;
  build) build ;;
  update) update ;;
  serve) serve ;;
  *) echo "usage: $0 [setup|update|serve|reset|build]" >&2; exit 2 ;;
esac

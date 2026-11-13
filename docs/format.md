# Formats

Every file of ast is TOML: one table per concern, unset fields left out.

## Package: `.ast`

```
9 bytes   "ASTERPKG" + format version (0x01)
u32 LE    length N of the metadata (1 .. 1 MiB)
N bytes   metadata.toml
rest      payload: tar, compressed with Zstandard
```

Not a zstd stream itself, hence `.ast` and not `.pkg.zst`. The payload checksum in the
metadata is checked in one pass before anything is unpacked. The whole file is covered by the
checksum in the signed index and by `<file>.sig` (Ed25519 over
`ast-package-v1:<sha256 of the file>`). Packing is deterministic.

```toml
[package]
name = "nginx"                  # [a-z0-9][a-z0-9+._-]*
version = "1.28.0"
arch = "aarch64"                # aarch64 | x86_64 | any
description = "HTTP server"
license = "BSD-2-Clause"
depends = ["pcre2 >= 10.40", "zlib"]    # = >= > <= <
config_files = ["/etc/nginx/nginx.conf"]

[payload]
sha256 = "..."

[release]                       # system components only
status = "tested"               # tested | untested

[origin]
builder = "ast-pm 0.1.0"
source_url = "https://..."
source_sha256 = "..."
```

Also optional in `[package]`: `revision` (default 1), `conflicts`, `replaces`, `notice`, and `setuid`:
the absolute paths that may keep their setuid bit. Any other setuid bit is dropped on install.
No `[release] status` means no status; it is never assumed. No install scripts.

## Index: `index.toml` + `index.toml.sig`

```
<url>/index.toml  index.toml.sig
<url>/NAME-VERSION-REV.ast  .ast.sig
<url>/NAME-VERSION-REV.recipe.toml
```

Signed as served (Ed25519 over the raw bytes). Files are found by name, the index only holds
their SHA-256. A package version is the table `[NAME."VERSION-REV"]`.

```toml
[metadata]
repo = "ast"
arch = "x86_64"
channel = "stable"

[nginx."1.28.0-1"]
arch = "x86_64"
description = "HTTP server"
license = "BSD-2-Clause"
depends = ["zlib"]
status = "untested"      # system components only
binary = "9a1f..."       # sha256 of nginx-1.28.0-1.ast
recipe = "d1f6..."       # sha256 of nginx-1.28.0-1.recipe.toml
```

An entry has `binary`, `recipe` or both. `ast -u` checks the signature and that
`repo`, `arch` and `channel` match the configuration.

## Recipe: `*.recipe.toml`

```toml
[package]
name = "hello"
version = "2.12"
arch = ["aarch64", "x86_64"]
build_depends = ["gcc", "make"]

[source]
url = "https://ftp.gnu.org/gnu/hello/hello-2.12.tar.gz"
sha256 = "..."

[build]            # up to three shell scripts, run in this order: prepare, build, install
build = "./configure --prefix=/usr && make -j$JOBS"
install = 'make install DESTDIR="$DESTDIR"'
```

Whatever ends up in `$DESTDIR` is the package. See `examples/hello.recipe.toml`.

## Repositories: `repos.toml`

One table per repository, named like it (see `examples/repos.toml`).

## Database

`/var/lib/ast/db/installed/NAME.toml`, one small file per package: `[package]` (version,
reason, status, dependencies, orchid services), `[origin]` (binary or source, repository,
checksums) and one `[files."PATH"]` table per file with its SHA-256 and mode. Changes go
through the transaction journal, so a power cut leaves either the old or the new state.
Cached indexes live in `db/repos/`, the journal in `db/txn/`.

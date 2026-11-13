# ast

The package manager of asterOS. `ast` installs, upgrades, removes and builds packages: from
source by default, from a binary when asked. Own package format (`.ast`), signed repositories,
transactional installs. Written in Rust.

## Build

```
cargo build --release     # target/release/: ast, astrap, astfstab, astchroot, astpkg
cargo test
```

`ast` runs on the device. `astpkg` is for repository maintainers.

## Use

One action, written as letters that combine with its modifiers:

```
ast -i PKG...        install: build from source (the default)
ast -ib PKG...       install a binary package instead
ast -u               refresh the repositories
ast -ua              refresh and upgrade everything; ast -u PKG... upgrades only those
ast -r PKG...        remove, with the dependencies nothing else needs
ast -l               list the installed packages
ast -q PKG           information about a package
ast -s TEXT          search; "" lists everything
```

`-y` skips the ordinary questions, so `ast -iby nano` and `ast -ry nano` work as written.
`--dry-run` shows the plan only, `--root DIR` works inside DIR, `-j N` sets the build jobs.

Rare actions are words: `ast repo [enable|disable NAME]`, `ast channel [stable|edge]`,
`ast verify [PKG...]`, `ast clean`, `ast init`.

`ast -i toolbox:extra-edge@*` installs from another repository, even of another
channel. The system channel never changes on its own.

Packages marked `untested` (kernel, libc, bootloader...) are installed only after an extra
answer. `-y` does not skip it; `--accept-untested` does.

## Installing by hand

`astrap ROOT` installs the base system into a directory, `astfstab ROOT` prints the fstab
lines for what is mounted under it, `astchroot ROOT` enters it.

## Configuration

```
/etc/ast/ast.toml  repos.toml  keys/*.pub
/var/lib/ast/db        installed packages and cached indexes
/var/cache/ast         downloads and build directories
```

Examples: [examples/ast.toml](examples/ast.toml), [examples/repos.toml](examples/repos.toml).
Each repository has its own key. A repository takes part only if it is enabled and its
channel matches the system channel.

## Make a repository

```
astpkg keygen ast                                    # ast.key (secret), ast.pub
astpkg pack DIR --meta meta.toml --out NAME.ast      # or: astpkg build recipe.toml --out DIR
astpkg index DIR --name ast --arch x86_64 --channel stable --key ast.key
astpkg publish RECIPES --out DIR --name ... --arch ... --channel ... --key ...
```

`publish` builds every recipe that is not in DIR yet, signs it and writes the signed index.
Serve DIR over HTTP or `file://`. Recipes: [examples/hello.recipe.toml](examples/hello.recipe.toml).

## More

[docs/format.md](docs/format.md) package, index and database formats ·
[docs/security.md](docs/security.md) what is verified, the build sandbox, limits.

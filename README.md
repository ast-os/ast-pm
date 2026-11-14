# ast

Package manager of asterOS, in Rust. Builds from source by default; `.ast` packages, signed
repositories, transactional installs.

```
cargo build --release     # ast, astrap, astfstab, astchroot, astpkg
cargo test
```

## Use

```
ast -i PKG...    install (build from source; -b for a binary)
ast -u           refresh repositories
ast -ua          upgrade everything
ast -r PKG...    remove
ast -l           list installed
ast -q PKG       package info
ast -s TEXT      search
```

`-y` skips questions, `--dry-run` shows the plan, `--root DIR` works inside DIR, `-C DIR` reads
another config dir. Config: `/etc/ast/{ast.toml,repos.toml,keys/}`, see [examples/](examples).

`astrap ROOT` installs the base into a directory, `astfstab ROOT` prints fstab lines,
`astchroot ROOT` enters it. `astpkg` is for maintainers (`keygen`, `pack`, `index`, `publish`).

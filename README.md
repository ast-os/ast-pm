# ast

Package manager of asterOS, in Rust. Builds from source by default; `.ast` packages, signed
repositories, transactional installs.

```
cargo build --release     # ast
cargo test
```

## Use

```
ast -i PKG...    install (build from source; -b for a binary)
ast -u           refresh repositories
ast -ua          upgrade everything
ast -r PKG...    remove
ast -l           list installed
ast -n PKG       package info
ast -s TEXT      search
ast -v [PKG...]  check files
ast -c           drop caches
```

`-y` skips questions, `--dry-run` shows the plan, `--root DIR` works inside DIR, `-C DIR` reads
another config dir. Config: `/etc/ast/{ast.toml,repos.toml,keys/}`, see [examples/](examples).

`astpkg` (repository ast-tools) is the maintainer tool.

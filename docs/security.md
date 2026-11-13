# Security

## Verified

| what | how |
|---|---|
| index | Ed25519 signature with the repository's key; `repo`, `arch`, `channel` match |
| cached index | verified again on every use |
| package | checksum from the signed index; its own `.sig` by the same repository's key; payload hash; metadata equals the index entry |
| files | SHA-256 per file while unpacking; `ast verify` later |

Not checked: freshness. The index carries no date, so a validly signed old index could be served again.

Every repository has its own key, so one repository cannot sign for another. Signature and
checksum checks can be switched off in `ast.toml`; every run then prints a warning.

## Unpacking

Two passes: the whole archive is scanned without writing, then written from the manifest.
Refused: `..` or absolute paths, hard links, devices, fifos, duplicates, entries below an
archive symlink. setuid/setgid/sticky bits are dropped. Targets are resolved like a chroot;
nothing can leave the root. Files of other packages and unowned files are not overwritten.

## Transactions

Every change is journaled first; replaced files are moved to a backup, not deleted. Success
removes the journal, failure rolls back, a crash is rolled back on the next run. Not atomic at
the filesystem level: during a transaction the system is partly updated.

## Recipes

A recipe is code. It comes only from a repository whose signed index lists its SHA-256, and
`ast` asks before running it. Sources are downloaded by `ast` and checked by SHA-256.
Scripts run in bubblewrap (`[build] sandbox`, default `required`): no network, read-only
system, no `/home` or `/root`, a cleaned environment, writable only inside their work
directory, all capabilities dropped; as an unprivileged user when `ast` runs as root.
Modes: `required`, `auto` (warn and run unsandboxed without bwrap), `none`.
Limits: the kernel is shared; no CPU, memory or disk limits besides `jobs`.

## OpenRC

`ast` never starts, stops, enables or restarts a service. It reports the commands to run.

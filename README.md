# sanitize

*Deletes even the traces of your data.*

Recursive secure deletion that tells you the truth about what it destroyed.

Named for NIST SP 800-88, *Guidelines for Media Sanitization*, whose Clear / Purge / Destroy
tiers it reports against. It never prints "securely erased" — it prints what actually happened.

```bash
sanitize /Volumes/STICK/folder        # recursive, overwrites, renames, deletes
sanitize --dry-run /Volumes/STICK     # show the scope first — always do this
sanitize --head 1G --tail 1M disk.img # kill an encrypted container's headers
```

## Status

v0.1, early. The traversal, name generation, extent planning, guards and reporting are
implemented and tested. Filesystem/device detection (`--explain`, the `purge` guarantee) and
privilege escalation are not yet — see [doc/TODO.md](doc/TODO.md) for everything outstanding
and `doc/DESIGN.md` §12 for the roadmap.

## Why not `shred` / `wipe` / `srm`

See `doc/COMPARISON.md`. Briefly: `shred` isn't recursive and ignores directories; `wipe` and `srm`
do the job but have been unmaintained since 2016 and 2015, abort the whole run on a single read
error, traverse by `chdir` rather than `openat`, generate replacement names that are unsafe on
FAT/exFAT, never rename directories, and — like everything else in this space — claim success on
filesystems and devices where overwriting provably does nothing.

## Defaults

| | |
|---|---|
| Recursion | on |
| Deletion | on (`-k` to overwrite and keep) |
| Passes | 1, random (`-n` to change) |
| Symlinks | the link is removed; **the target is never touched** |
| Boundary | stays on one filesystem — never crosses a mount point |
| Hard links | skipped: the data is reachable under another name |
| Dangerous paths | `/`, `$HOME`, `/usr`, `/System`… refused without `-F` |

## `-F` / `--force-everything`

One flag that removes every guard at once. It is **required** to name `/` or your home
directory, and it is **sufficient** — no prompt, no countdown.

With `-F`: no path is refused; symlinks are followed and their targets destroyed before the link
is removed; mount-point containment is off; permissions are forced and immutable flags cleared.
Full effect needs root. Symlink cycles are detected, so it terminates.

Understand what that combination means: `sudo sanitize -F /` will destroy every mounted volume
reachable from the tree — external drives, network shares, backup targets — because the symlink
boundary and the mount boundary were the only things scoping it. Use `--dry-run` first.

## Robustness

The program does not crash. This is a hard requirement, not an aspiration: a destructive
recursive tool that aborts partway leaves you with some data destroyed, some not, and no record
of which. Every per-entry error — permission denied, I/O error, unreadable directory, missing
file — is recorded and the walk continues. `EINTR`/`EAGAIN` retry; short writes loop. A file
that could not be fully overwritten is **not** deleted. The summary always prints.

Exit codes: `0` everything destroyed · `1` something was skipped or failed · `2` usage error ·
`3` refused for safety, nothing touched.

## Build

```bash
cargo build --release
```

## What it cannot do

Overwriting a file does not reliably overwrite the file's blocks on APFS, btrfs, ZFS, or any
SSD — copy-on-write allocates new blocks, and the flash translation layer redirects every write.
On those, `sanitize` achieves *clear* (the data is unreachable through the filesystem) and says
so, rather than claiming *purge*. If you need a real guarantee, the answer is cryptographic
erasure or whole-device sanitization, not this tool. `doc/DESIGN.md` §2 explains at length.

## Licence

MIT. See [LICENSE](LICENSE).

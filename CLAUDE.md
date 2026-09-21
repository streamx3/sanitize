# Working agreements for this repository

## 1. Never endanger the Claude Cloud environment — standing instruction

Stated by the repository owner, 2026-09-21, and binding on every session.

> Never do anything harmful to the Linux environment of Claude Cloud, and avoid running any of
> the software this repository builds against the virtualized OS or its data. Even where no harm
> would result, the possibility of an account being suspended is not worth it.

This matters more here than in most projects: `sanitize` is a recursive secure-deletion tool
whose whole purpose is destroying data irreversibly. The blast radius of a mistake is the
container.

**Never, in a cloud session:**

- Point `sanitize` at any path that existed before the session — no `/`, `/etc`, `/usr`, `/root`,
  `$HOME`, `/tmp` itself, the repository checkout, or any system directory.
- Use `-F`, `--no-preserve-root`, `--follow-symlinks`, `--no-one-file-system` or
  `--hard-links=shred` against a real path, for any reason, including "just to see".
- Run `sanitize` against a real block device, a mounted volume that the session did not create,
  or a loop device backed by anything but a scratch image made during the session.
- Format, mount, unmount, `losetup`, `fdisk` or otherwise touch storage the session did not
  create. Detach every loop device and remove every scratch image before finishing.
- Install, remove, or reconfigure anything system-wide beyond what a build or test genuinely
  needs, and never to work around a sandbox restriction.

**Permitted, and the boundary that makes it permitted:** directories and image files the session
creates itself under its own scratchpad or `$TMPDIR`, destroyed by the session, containing only
data the session wrote. The integration suites (`tests/residue.rs`, `tests/interrupt.rs`) work
this way — every one creates its own directory, uses only files it wrote, and removes it on drop.
Nothing pre-existing is ever a target.

If a task seems to require crossing that line, **stop and ask**. The answer is a note in
`doc/HARDWARE-TESTS.md` for the owner to run on their own machine, not a careful attempt here.

> The owner may narrow this further. If self-created scratch directories should also be
> off-limits — which would mean not running `cargo test` in a cloud session at all — say so and
> this section gets tightened.

## 2. Environment facts, measured 2026-09-21

Recorded so no future session has to re-probe. Kernel `6.18.44-fc-v37`, a trimmed Firecracker
microVM.

| | |
|---|---|
| Privileges | root; `/dev/loop*` and `losetup` present |
| `apt-get install` | works (network via the agent proxy) |
| ext4 loopback mount | **yes** — the DESIGN §11 canary test runs here |
| `vfat` / `msdos` / `exfat` in kernel | **no** — and no `/lib/modules`, no `modprobe` |
| exFAT via `losetup` + `exfat-fuse` | **yes** — see `ci/fs-forensics.sh` |
| FAT32 | **not reachable** — needs real hardware or a full kernel |

Anything needing a power cut, a bus analyser, slow USB media, macOS, or Windows is out of reach
by construction. Those live in `doc/HARDWARE-TESTS.md`.

## 3. Project conventions

- `doc/DESIGN.md` §16 holds the locked decisions and supersedes earlier sections.
- `doc/REFERENCE.md` is the flag and config authority model — read §0 before adding any setting.
- `doc/SHORTCOMINGS.md` is the honest inventory; every claim is marked `[code]`, `[design]`,
  `[assumed]` or `[unknown]`. Do not upgrade a mark without evidence.
- The crate denies `unwrap_used`, `expect_used` and `panic`. Integration tests opt out at the
  file level, because assertions panic by design.
- Keep `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean. CI runs both.
- Never print "securely erased". Print what actually happened. (§3)

# sanitize — outstanding work

State as of the v0.1 commit. Everything below was verified against the code, not
remembered. File references are `path:line`.

Priority key: **P0** ships a tool that lies or loses data · **P1** credibility ·
**P2** planned features · **P3** polish.

---

## P0 — broken or dishonest right now

These matter disproportionately because the entire pitch of this tool is that it
does not overclaim. A tool that misreports its own capabilities fails at the one
thing that distinguishes it from `wipe`.

### 1. `--explain` is advertised in output but does not exist — **text removed**

> The misleading clause is gone from `report.rs`; the flag itself still waits on `fsinfo`.


Every run that overwrites anything ends with:

```
sanitize: sanitization level: clear (overwrite UNVERIFIABLE on this filesystem/device — run --explain)
```

`src/report.rs:262`. The flag is not implemented; running it gives
`error: unexpected argument '--explain' found`.

**Fix now:** drop the `— run --explain` clause from that string.
**Fix properly:** implement `--explain` (see P2.1). Until the `fsinfo` detection
exists there is nothing for it to report, so removing the text is the honest
short-term move.

### 2. Cargo.toml license contradicts the repository LICENSE

`Cargo.toml` declared `GPL-3.0-or-later`; the repository ships an MIT LICENSE
(`LICENSE`, © 2026 Andrii Shelestov). Aligned to `MIT` in the move commit.

Note on provenance, since it is a fair question: `wipe` is GPL-2 and its source
was read during design, but no code was copied — the Rust implementation is
original, and the comparisons in `doc/COMPARISON.md` are factual observations
about published behaviour. MIT is therefore unencumbered. If you would rather
the project be GPL, change both the `LICENSE` file and `Cargo.toml` together.

### 3. SIGINT is not handled — Ctrl-C leaves no record — **DONE**

> Implemented in `src/interrupt.rs`. The handler bumps an atomic and nothing
> else; the walker polls between directory entries and the wipe engine between
> passes and between 1 MiB chunks. Exit 1, summary always printed, and a
> partially overwritten file is left in place and reported per §7.5. Covered by
> `tests/interrupt.rs`. The original description follows for the record.


There is no signal handler anywhere in `src/`. Default disposition terminates the
process immediately, so Ctrl-C during a long run over slow media kills it
mid-file with **no summary printed**.

This directly violates DESIGN.md §16.1 item 5, and `src/report.rs:197` carries a
doc comment asserting the opposite ("Always printed, including after SIGINT").

It is also the exact failure state the robustness requirement exists to prevent:
some data destroyed, some not, and no record of which. It is the most likely way
a real user ends a long job on a USB stick.

**Fix:** install a handler that sets an `AtomicBool`; check it between entries in
`Walker::process` and at the top of each pass in `wipe::wipe_fd`; unwind cleanly,
print the summary, exit 1. Do not abandon a file mid-overwrite without recording
it — a partially overwritten file must still be reported as not-deleted per §7.5.

---

## P1 — the tests do not yet prove the tool works

All 42 tests are unit tests of pure functions (size parsing, name invariants,
extent planning). Every destructive behaviour was verified **by hand** during
development and is captured nowhere.

### 4. No integration tests (`tests/` does not exist)

Hand-verified during the v0.1 session, currently unguarded against regression:

- symlinks: link removed, target untouched (default) vs followed and destroyed (`-F`)
- symlink cycles terminate under `-F`
- hard-linked files are skipped and their content left intact
- a directory that cannot be removed keeps its **original name** (the rename
  ladder must be undone) — this was a real bug found and fixed in testing
- a `chmod 000` directory mid-tree is reported and the walk continues past it
- exit codes: 0 clean, 1 skipped-or-failed, 2 usage, 3 refused
- guards refuse `/`, `$HOME`, `/usr`, and textual `..` tricks; `-F` permits them
- `--head`/`--tail` leave the middle of a file bit-for-bit untouched

### 5. The forensic test from DESIGN.md §11 is unwritten

Nothing currently proves an overwrite reaches the media at all. The test that
would:

1. Create a loopback ext4 image, write a file containing a known canary string.
2. `sanitize` it, unmount, `grep` the **raw image** for the canary → assert absent.
3. Repeat on btrfs and assert the canary is **present** — and let that test pass,
   documenting where the guarantee does not hold.

DESIGN.md calls this "the honest core of the project". Needs Linux, so it is CI
work rather than local.

### 6. No differential oracle against `wipe`

Per DESIGN.md §14.7: run `wipe` and `sanitize` over identical trees on a loopback
FAT image, compare surviving bytes and directory entries. A 27-year-old
independent implementation agreeing with ours is worth more than any unit test.

### 7. No CI

No `.github/workflows/`. Wanted: `cargo test`, `cargo clippy -- -D warnings`,
`cargo fmt --check` on macOS and Linux, plus the loopback tests on Linux only.

---

## P2 — planned features not yet built

### 8. Privilege escalation (`--escalate`) — an original requirement, still missing

Explicitly requested at the start of the project: *"an option to escalate
privileges for every or all files in this session if permissions to write/delete
are not granted by default."*

`-F` covers the guard-removal half (chmod, immutable flags, no path refused), but
there is no escalation. A non-root user running `-F` over root-owned files just
collects `EACCES` per entry.

Design is already written — DESIGN.md §8.1: traverse unprivileged first, collect
the `EACCES`/`EPERM` set, show it, then re-exec once under `sudo` operating from
a `0600` manifest rather than the original arguments, so a symlink swap between
phases cannot redirect the privileged run. No setuid, no helper daemon, no
credential caching.

### 9. Filesystem/device detection + `--explain` + the `purge` guarantee

`Guarantee::Purge` exists but is never constructed (`src/report.rs:13-18`), so
every overwrite reports `unverifiable`. Honest, but uninformative: on ext4 over a
spinning disk we *could* legitimately claim purge.

Needs: filesystem type, rotational flag (Linux `queue/rotational`, macOS IOKit
`Solid State`), CoW detection, sparse/cloned/compressed file checks, and APFS
local-snapshot detection (`tmutil listlocalsnapshots`). The last one matters most
in practice — on a stock Mac an hourly Time Machine snapshot is likelier to
defeat a shred than the SSD's FTL is.

### 10. Extended attributes, resource forks, alternate data streams

DESIGN.md §9.2. Untouched today. On macOS that means `com.apple.ResourceFork`
(arbitrary size), `com.apple.metadata:*`, and `com.apple.quarantine` (source URL,
timestamp, downloading app) all survive the file they belonged to.

### 11. v0.3 items

`--scrub-dirents`, `--verify`, raw block device support, `--preset=container`
(head 1G + tail 1M with LUKS/VeraCrypt/GPT header geometry).

---

## P3 — known limitations and polish

### 12. Sparse files are written densely

DESIGN.md §6.3 specifies detecting holes via `SEEK_HOLE`/`SEEK_DATA` and skipping
them. Not implemented: `wipe::wipe_fd` writes through holes, which materialises
them. Irrelevant on FAT/exFAT (no sparse support) but would inflate a sparse
ext4 image and can hit `ENOSPC` — which then blocks the deletion.

### 13. CLI options designed but not implemented

- `--range A:B` (§4.2) — only `--head`/`--tail` exist
- `-j/--jobs` (§4.2) — no concurrency; serial is correct for rotational media, wasteful on NVMe
- `-I` interactive threshold (§7.4) — designed to auto-prompt above ~50 files or on any directory

### 14. No man page

`--help` is complete; there is no `sanitize.1`.

### 15. Directory listings are read fully into memory

`Walker::drain_directory` collects all names before processing, deliberately, to
avoid mutating a directory while its stream is open. A directory with millions of
entries would use proportional memory. Acceptable for now; note it.

---

## Decided 2026-09-21 — metadata, residue and config

Governing principle recorded in DESIGN.md §16.4: **aggression is the default.** The operator is
assumed competent and to have a reason. Guards that ask *"did you mean this path?"* stay; guards
that ask *"are you sure you want it this thoroughly gone?"* are removed.

Ordered by value per line of code.

### 16. Truncate to 0 before unlink — P0

> **DONE.** `walk.rs::wipe_truncate_scrub`. Verified with strace: `pwrite → fdatasync → ftruncate(0) → utimensat → renameat2 ×12 → unlinkat`.

~5 lines. `ftruncate(fd, 0)` after `wipe_fd`'s final `full_sync`, before `close`, gated on
`!cfg.keep`. Today the residual FAT32 dirent keeps `DIR_FileSize` (0x1C) and the first cluster
(0x14/0x1A) — the exact size and a pointer to where the data began. exFAT: `DataLength`,
`ValidDataLength`, `FirstCluster` in the Stream Extension entry. Unlink sets `0xE5` and frees the
chain but does not scrub those fields.

Same mechanism as the §5.2 same-length rename: rewrite the dirent while it is still live, because
once it is slack it is unreachable. Verify with a hex dump of the dirent before/after on a
loopback image — this is P1.5's forensic test and it is what proves the change earns its keep.

### 17. `--scrub-times`, on by default — P0

> **DONE.** `meta::scrub_times`, after truncation per §16.5. Random in `[1980-01-01, now]`; the FAT epoch floor is unit-tested.

Inverse is `--no-scrub-times`. `utimensat` on `atime`/`mtime` before unlink. **Not** the Unix
epoch: FAT's epoch starts 1980-01-01, so `0` clamps and the clamp is itself a signature. Random
value in a plausible window. Create time unsettable from POSIX — macOS `setattrlist(ATTR_CMN_CRTIME)`,
Linux reports it as unfixable residue. DESIGN §9.4 designed this; nothing in `src/` implements it.

### 18. AppleDouble sidecars — P0

> **DONE.** `meta::sidecar_of` + `walk.rs::scrub_sidecar_of`, processed before the principal. The single-file leak is closed and guarded by `sidecar_dies_with_its_principal`.

`._<name>` carries `com.apple.quarantine` (source URL, timestamp, downloading app) on FAT/exFAT,
where macOS has no native xattrs. **The sidecar's own filename contains the principal's name**,
which defeats the entire §5.2 ladder.

Current live bug: `sanitize /Volumes/STICK/foo.7z` (single-file target) leaves `._foo.7z` naming
the file and holding its download URL. Whole-directory runs already destroy it incidentally.
Process the sidecar *before* its principal.

### 19. `--scrub-sidecars`, on by default — P1

> **DONE.** `.DS_Store`, `Thumbs.db`, `ehthumbs.db`, `desktop.ini` via `meta::CACHE_FILES`.

`.DS_Store`, `Thumbs.db`, `ehthumbs.db`, `desktop.ini` in any directory touched. `.DS_Store` is a
buddy-allocated B-tree that does not compact, so it **retains records for files already deleted** —
an on-disk list of names that used to be there. `Thumbs.db` is an OLE compound file holding
*rendered thumbnails*: content recovery, not metadata leakage, and the strongest item on the list.

### 20. `--scrub-volume`, on by default — P1

Inverse `--no-scrub-volume`. `.fseventsd`, `.Spotlight-V100`, `.Trashes`, `._.Trashes`,
`$RECYCLE.BIN`, `System Volume Information`, `.TemporaryItems`, `LOST.DIR`, `FOUND.*`, `*.CHK`.
(`lost+found` is ext-only and not relevant on the priority filesystems.)

`.fseventsd` is the reason this is default-on rather than opt-in: it holds gzip'd records of
**full paths plus event masks** for everything that ever changed on the volume. Plaintext, readable
with `zcat`. The §5.2 ladder protects one name in one 32-byte dirent while `.fseventsd` holds the
same name in the clear — without this, the ladder is theatre on any volume that has touched a Mac.

Must run **last** (our own unlinks generate the records we are removing) and cannot fully win while
mounted — see §16.5.1. Needs volume-root identification, a subset of the `fsinfo` work in P2.9.

### 21. Residue reporting — P1

> **PARTLY DONE.** `scrubbed` and `present, not scrubbed` are implemented and drive exit 1; `not_checked` exists but has no caller until `--scrub-volume` lands.

Three states per residue class: `scrubbed` / `present, not scrubbed` (with reason) / `not checked`.
Unscrubbed residue referencing a destroyed path sets exit 1, by the same argument `main.rs:75`
already makes for skipped entries. DESIGN §16.7.

### 22. Config file — P2

Full specification in [REFERENCE.md](REFERENCE.md) §5, including the scope/thoroughness split
that makes `force_everything` structurally inexpressible in config.

`hardcoded < /etc/sanitize/default.conf < CLI`. Flat `key = value`, parsed in-tree, no TOML
dependency. Every destructive run prints which layers were in effect and where each non-default
setting came from. DESIGN §16.6.

### 23. Expose a library target — P2

`Cargo.toml` declares no `[lib]`, there is no `src/lib.rs`, and every module is private
(`main.rs:7-14`). Nothing in this repo is consumable by another crate, so a GUI front-end or
`blktamper` integration cannot reuse `name.rs`, `size.rs`, `plan_extents`, `guards.rs` or the
`Guarantee` model as things stand. Add `src/lib.rs`, make the modules `pub`, reduce `main.rs` to
argument handling plus a call in. Mechanical, and cheaper before a consumer exists than after.
See [SHORTCOMINGS.md](SHORTCOMINGS.md) §6.

### 24. Settle the FAT dirent assumptions — P1

Eight assumptions the design relies on and cannot verify from userspace
([SHORTCOMINGS.md](SHORTCOMINGS.md) §4). Rows 1-4 are FAT/exFAT-specific and therefore the
highest-value experiments here. Row 3 decides whether the ladder's same-length first step — which
the whole of DESIGN §5.2 rests on — does anything at all. Row 4 (the 8.3 short-name alias) may
show that a mangled form of the original filename survives every rename, in which case the §5
claims need correcting rather than defending.

### Open questions

Mostly resolved 2026-09-21; see [REFERENCE.md](REFERENCE.md) §8 for the table and the reasoning.

- ~~`-f` vs `-F`~~ — both stay, different categories.
- ~~Config trust~~ — `/etc/sanitize/` is read and trusted. A permission check protects nothing:
  anyone who can write it can replace the binary.
- ~~Per-user config layer~~ — no. Hardcoded, `/etc`, command line. Three layers, no more.
- ~~`--allow-dangerous-path`~~ — flag dropped. `/` keeps a hard gate (`--no-preserve-root`);
  every other dangerous path warns and waits. The guard is exact-match and a shell glob walks
  past it, so it was a typo guard all along, and a prompt is what a typo guard should be.
- ~~`--hard-links=shred` as scope~~ — moot on FAT32/exFAT, which have no hard links. Revisit
  with ext4/NTFS/APFS, not before.

Still open:

- **Symlink policy**, deferred by decision until a stable FAT-first release exists. FAT32/exFAT
  have no symlinks, so nothing on the priority path depends on it.
- **The shape of warn-and-wait** (`y/N`, typed confirmation, countdown). The non-TTY rule matters
  more: stdin not a TTY and no `--yes` must refuse (exit 3), never proceed.

---

## Publishing checklist (crates.io)

The name `sanitize` was free on crates.io, Homebrew, Debian's file index and as a
binary name when checked on 2026-07-28. It is still unclaimed.

Before `cargo publish`:

- [x] LICENSE file present (MIT, from the repository)
- [x] `license` field matches it
- [ ] `repository = "https://github.com/streamx3/sanitize"` in `Cargo.toml`
- [ ] `keywords` / `categories` for discoverability
- [ ] fix P0.1 — do not ship a binary that advertises a flag it lacks
- [ ] decide whether v0.1 is publishable or whether to claim the name with a
      placeholder and publish properly at v0.2

---

## Suggested order

1. P0.1 and P0.3 — small, self-contained, and both are honesty defects in a tool
   whose entire pitch is honesty.
2. P1.4 and P1.7 — integration tests and CI, so hand-verified behaviour stops
   being hand-verified.
3. Claim the crates.io name.
4. P1.5 — the forensic loopback test, in CI.
5. P2.8 — escalation, the one original requirement still outstanding.

# sanitize vs. the existing tools

Everything below was verified against upstream man pages and, for `wipe`, against the
source — not from memory. Checked 2026-07-28.

---

## Why `sanitize` exists at all

Short version: the feature set is not new. `wipe` (2009) and `srm` (2015) already did recursive,
delete-by-default, rename-before-unlink. Both are dead. What is new is being *correct*, being
*honest*, and being *alive*.

- **`shred` cannot do the job.** It is not recursive, does not delete by default, and ignores
  directories entirely — so the directory names, which on FAT/exFAT are as recoverable as the
  files, are never touched.
- **The tools that could do the job are abandoned.** `wipe`'s last functional commit was 2016
  (16 commits, ever). `srm` released 1.2.15 in Feb 2015. secure-delete's upstream is from 2003.
  `scrub` last released Aug 2014. None of them have a maintainer.
- **They crash on the errors that actually happen.** `wipe` calls `exit(EXIT_FAILURE)` in the
  middle of its write loop (wipe.c:1047). One bad sector on a worn USB stick and a recursive job
  dies partway through, leaving a half-destroyed tree and no record of which half.
- **They lie about what they achieved.** All of them assume overwriting a file overwrites the
  file's blocks. On APFS, btrfs, ZFS and any SSD that is false — copy-on-write allocates new
  blocks and the FTL redirects every write. `scrub`'s man page at least *documents* the problem;
  none of them *detect* it, and none adjust their claims.
- **They ignore the leaks nobody lists.** Hard links (destroying data still reachable under
  another name), extended attributes and resource forks, APFS local snapshots — untouched by
  every tool in this table.
- **Their traversal is from the pre-`openat` era.** `wipe` descends with `opendir()` then
  `chdir()` by name (wipe.c:1204-1214). Swap a directory for a symlink between those two calls
  and it walks somewhere else. For a program whose job is recursive destruction, running as root,
  that is the bug that matters.
- **They are unsafe on the media people actually use.** `wipe`'s replacement-name charset is
  `0-9a-zA-Z-.` filled at every position (wipe.c:520), so it can emit a leading `-`, a leading or
  trailing `.`, or a reserved DOS device name — all hazards on the exFAT/FAT32 volumes that
  removable drives use. It also mixes case, which halves the usable namespace on a
  case-insensitive volume.
- **Their defaults burn hardware for nothing.** 34 passes (`wipe`) or 38 (secure-delete) over
  20 GB is 680–760 GB of writes: about six hours on a USB 3 stick and ten full drive-writes of
  wear, destroying exactly zero bytes that the first pass missed, because the FTL sends every
  pass to fresh pages.
- **There is nothing on macOS.** Only `scrub` and GNU `shred` are packaged in Homebrew. `wipe`,
  `srm` and secure-delete are not. Apple shipped an `srm` once and removed it, and withdrew
  Secure Empty Trash in OS X 10.11 on the grounds that erasure could not be guaranteed on SSDs.
- **On Darwin they do not even sync correctly.** `fsync(2)` does not flush the drive's write
  cache on macOS; only `fcntl(F_FULLFSYNC)` does. No tool in this table calls it.

`sanitize` is therefore not pitched as "recursive shred". It is pitched as a maintained,
memory-safe, TOCTOU-correct implementation that refuses to claim more than it achieved.

---

## Feature comparison

| | `shred` | `srm` (SF) | `srm` (secure-delete) | `wipe` | `scrub` | `nwipe` | **`sanitize`** |
|---|---|---|---|---|---|---|---|
| Scope | files, devices | files + trees | files + trees | files, trees, devices | files, devices, free space | whole disks | files + trees |
| Recursive | no | `-r` | `-r` | `-r` | no | n/a | **default** |
| Deletes by default | no | yes | yes | yes | no (`-r`) | n/a | **yes** |
| Renames files first | ladder (`-u`) | yes | yes | 1× (`-P` raises) | opt-in `-D` | n/a | **ladder, same-length first** |
| Renames **directories** | n/a | ? | ? | **no** | n/a | n/a | **yes** |
| Portable name charset | digits only | ? | ? | **unsafe on FAT** | ? | n/a | **verified 6 filesystems** |
| Partial byte range | `-s` (head) | no | no | `-o` + `-l` | no | no | **`--head` + `--tail`** |
| Default passes | 3 | 1 × `0x00` | 38 | 34 | 4 (NNSA) | varies | **1 (random)** |
| Survives read/permission errors | per-file | ? | ? | **no — `exit()`** | ? | n/a | **required, never aborts** |
| Symlinks | follows | — | — | not followed | `-L` | n/a | **link only; `-F` follows** |
| Mount containment | no | `-x` | no | no | no | n/a | **default** |
| TOCTOU-safe traversal | n/a | no | no | **no (`chdir`)** | n/a | n/a | **`openat` throughout** |
| Hard-link detection | no | no | no | no | no | n/a | **skips by default** |
| Dry run | no | no | no | no | `-n` | n/a | **yes** |
| `F_FULLFSYNC` on macOS | no | no | no | no | no | n/a | **yes** |
| Reports achieved guarantee | no | no | no | no | no | certificate | **NIST clear/purge** |
| Machine-readable output | no | no | no | no | no | PDF | **`--json`** |
| Memory-safe language | no | no | no | no | no | no | **yes** |
| Last upstream release | active | Feb 2015 | 2003 | 2016 | Aug 2014 | active | — |

---

## What each tool is still best at

- **`shred`** — a single file or raw device, on a system where it is already installed. Its
  `-s`/`--size` and rename ladder are better than its reputation, and its size-suffix parser is
  the one `sanitize` copies.
- **`srm` (SourceForge)** — closest in spirit to "`rm` but secure", and the only prior tool with
  `--one-file-system`. Note its default is a single pass of `0x00`: zeros, which is the entropy
  edge you usually want to avoid.
- **secure-delete** — the siblings are the real value: `sfill` (free space), `sswap`, `sdmem`.
  Out of scope for `sanitize` and staying that way.
- **`scrub`** — a pattern library with block-device and free-space modes, plus a `--dry-run` and
  an honest caveats section. Use it for free-space filling.
- **`nwipe`** — whole-device sanitization with erasure certificates. Not a competitor: it is what
  you should use *instead of* `sanitize` when the whole drive is the unit of destruction, and
  `--explain` should say so.

## What `sanitize` does not do

- It does not fill free space (`sfill`, `scrub -X`).
- It does not sanitize whole drives (`nwipe`, `blkdiscard`, ATA secure erase).
- It does not claim `purge` yet — the filesystem/device detection that would justify it is v0.2.
  Until then it reports `unverifiable` after every overwrite, which is the honest answer.
- It cannot defeat CoW filesystems, SSD FTLs, or APFS snapshots. Nothing in userspace can. The
  design goal is to *say so* rather than to pretend.

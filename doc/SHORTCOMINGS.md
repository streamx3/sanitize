# sanitize — shortcomings, implicit targets, and known residue

> The honest inventory. Three questions, answered without hedging:
>
> 1. **What do we destroy that the user did not name?** (§1)
> 2. **What should be destroyed, but will not be?** (§2, §3)
> 3. **What are we assuming that we cannot check?** (§4)
>
> This exists because the project's only differentiator is not overclaiming. A tool that
> silently exceeds its stated scope, or silently falls short of it, has the same defect in two
> directions. Downstream tools (`blktamper`, a GUI front-end) should be able to read this file
> and know exactly where this repo's guarantees stop — see §6.

---

## 0. Verification status — read this before trusting anything below

**Most of this document is still unproven.** As of the residue work there are 47 unit tests of
pure functions (size parsing, name invariants, extent planning, timestamp bounds) plus 8
integration tests in `tests/residue.rs` that drive the real binary against real directories and
cover the §16.5 chain. Everything *else* destructive — symlink policy, hard links, the rename
ladder's effect on disk, exit codes — was verified by hand once during the v0.1 session and is
captured nowhere. The forensic loopback test (DESIGN §11, TODO P1.5) now exists as `ci/fs-forensics.sh` and runs
in CI on vfat, exfat and ext4 — see §4.1 for what it has established. Claims about *devices*
below remain untested and mostly untestable in software.

So each claim below is one of:

| Mark | Meaning |
|---|---|
| **[code]** | read directly out of `src/` — this is what the program does today |
| **[design]** | specified in DESIGN.md, not implemented |
| **[assumed]** | believed true of the filesystem or device, **not verified from userspace** |
| **[unknown]** | genuinely do not know; needs an experiment |

---

## 1. Implicit targets — destroyed without being named

### 1.1 Always, once implemented — bounded and enumerable

These are the complete out-of-tree residue set (REFERENCE.md §0.3). The list is exhaustive by
design: if something is not here, we do not touch it.

| Path | Where | Why it is residue | Status |
|---|---|---|---|
| `._<name>` | beside each destroyed file | AppleDouble sidecar: holds `com.apple.quarantine` (source URL, timestamp, downloading app) and the resource fork on FAT/exFAT. **Its own filename contains the principal's name**, defeating the §5.2 ladder. | **[design]** |
| `.DS_Store` | every directory touched | Buddy-allocated B-tree that does not compact; retains records for files already deleted. An on-disk list of names that used to be there. | **[design]** |
| `Thumbs.db`, `ehthumbs.db` | every directory touched | OLE compound file holding *rendered thumbnails*. Content recovery, not metadata leakage. | **[design]** |
| `desktop.ini` | every directory touched | Folder customisation; can name files. | **[design]** |
| `.fseventsd/` | volume root | gzip'd records of **full paths plus event masks** for everything that ever changed on the volume. Plaintext under `zcat`. | **[design]** |
| `.Spotlight-V100/` | volume root | Spotlight index: filenames and indexed file *content*. | **[design]** |
| `.Trashes/`, `._.Trashes` | volume root | Real user files. See the warning below. | **[design]** |
| `$RECYCLE.BIN/` | volume root | Real user files. See the warning below. | **[design]** |
| `System Volume Information/` | volume root | `IndexerVolumeGuid`, `WPSettings.dat`, restore metadata. | **[design]** |
| `.TemporaryItems/` | volume root | macOS scratch. | **[design]** |
| `LOST.DIR/` | volume root | Android recovery. (`lost+found` is ext-only; not relevant on the priority filesystems.) | **[design]** |
| `FOUND.*/`, `*.CHK` | volume root | Windows `chkdsk` salvage — **recovered fragments of previously deleted files**, which is precisely what we are trying to eliminate. | **[design]** |

> **Warning, repeated from REFERENCE.md §0.3.** `$RECYCLE.BIN` and `.Trashes` contain arbitrary
> user files of unbounded size, possibly written by a different person on a different machine.
> Their *location* is enumerable; their *contents* are not. They are destroyed by default under the
> DESIGN §16.4 threat model — a trashed file is a recoverable copy of exactly what you asked to
> destroy — but this is the single most surprising thing the tool does. It must be reported as its
> own class, never folded into the file count.

Note that even a sidecar escapes the named path when the target is a single file:
`sanitize ~/notes/a.txt` must reach the sibling `~/notes/._a.txt`.

### 1.2 Only under an explicit scope flag — unbounded

Command-line-only, never config (REFERENCE.md §1). Each has a blast radius set by filesystem
contents rather than by the flag.

| Flag | What else dies | Status |
|---|---|---|
| `--follow-symlinks` (today: only via `-F`) | Whatever the links point at, anywhere on the system. A link planted inside a tree you were going to destroy redirects destruction arbitrarily. | **[code]** |
| `--no-one-file-system` | Every mounted filesystem reachable by descent — external drives, network shares, backup targets. | **[code]** |
| `--hard-links=shred` | The content behind every other name for the same inode, including names outside the tree. | **[code]** |
| `-F` | All of the above at once, plus every path guard. | **[code]** |

### 1.3 Collateral within a named target

| What | Why | Status |
|---|---|---|
| Slack past EOF in the final block | `plan_extents` rounds the file size up to `st_blksize` unless `-x`. Writes land past the logical end of file, inside its last allocated block. Intentional (it wipes the file's own tail slack) but it is a write the user did not ask for. | **[code]** |
| Other files' name slack in a directory | `--scrub-dirents` (DESIGN §5.4) churns a directory's data blocks by creating and deleting many files. Those blocks hold the deleted-name slack of *siblings*, including files that were never targets. | **[design]** |
| Sparse file holes | `wipe_fd` writes through holes rather than skipping them, materialising them. Inflates a sparse image and can hit `ENOSPC` — which then blocks the deletion. | **[code]**, TODO P3.12 |

---

## 2. Known residue — should die, will not

### 2.1 On the target volume

| Residue | Why it survives | Status |
|---|---|---|
| Directory-entry slack | Renaming does not overwrite the old name. On ext4 the old entry is absorbed into the previous record's `rec_len` and its bytes survive in slack. The §5.2 ladder is a best-effort in-place rewrite, not a guarantee. | **[assumed]**, DESIGN §5.3 |
| **FAT32 8.3 short-name alias** | Every LFN entry has a companion 8.3 alias derived from the original name (`GAY_NO~1.7Z`). Whether the rename ladder regenerates or orphans it, and whether a mangled form of the original name survives, is **not established**. Directly relevant to the FAT-first priority. | **[unknown]** — see §5 |
| The second FAT | FAT32 keeps two copies of the allocation table. We rely on the driver mirroring writes to both. | **[assumed]** |
| exFAT allocation bitmap / upcase table | Never touched; may retain allocation history. | **[assumed]** |
| Create time on Linux | No POSIX API sets birth time on vfat/exfat. `--scrub-times` reaches `atime`/`mtime` only. macOS can use `setattrlist(ATTR_CMN_CRTIME)`. | **[design]** |
| `.fseventsd` records written *after* our scrub | The daemon logs our own unlinks and buffers before flushing. Scrubbing last narrows the window; mounting keeps it open. Cannot be closed from userspace. | **[design]**, DESIGN §16.5.1 |
| ext4 journal | May hold copies of both old and new directory entries. | **[assumed]** |
| NTFS `$LogFile` / `$UsnJrnl` | USN journal logs rename events with **both** old and new names. Name obfuscation is close to useless on NTFS. | **[assumed]** |
| APFS / btrfs / ZFS snapshots | The old dirent and the old extents live in the snapshot. On a stock Mac an hourly Time Machine local snapshot is likelier to defeat a shred than the SSD's FTL is. | **[assumed]**, TODO P2.9 |
| CoW old extents | Overwriting allocates new blocks; the originals stay until reclaimed. | **[assumed]**, DESIGN §2 |
| Free space that previously held the file | Any prior move, defrag, CoW copy or compaction left a full copy elsewhere. We only overwrite the *current* extents. | **[assumed]** |
| Volume label / serial | Identifies the medium and often the machine that formatted it. Not content, but a clue about provenance. | **[code]** — never touched |

### 2.2 On the host, not the volume — entirely out of scope today

Destroying a file on a USB stick does nothing about any of this. For the stated goal ("leave no
clues as to what might have been in the files or how they were created"), several of these leak
more than the file's own name did.

- **Spotlight index** on the host for the mounted volume's paths.
- **Windows Search index** (`Windows.edb`).
- **QuickLook thumbnail cache** — macOS `com.apple.QuickLook.thumbnailcache`: rendered previews of
  files that no longer exist.
- **Explorer thumbnail cache** — `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db`.
- **Temp extraction directories.** Opening a `.7z` extracted it somewhere — `/tmp`, `/var/folders`,
  `%TEMP%`. Those copies are unrelated to the archive you destroyed.
- **Shell history**, `~/.recently-used.xbel`, GTK/Qt recent-file lists, application MRU.
- **macOS `.DS_Store` on the host** for the volume's mount path.
- **Time Machine / Volume Shadow Copy** snapshots holding earlier states.
- **Swap and hibernation files** — plaintext of anything that was in memory.

### 2.3 Below the filesystem

Nothing a userspace tool writes through a filesystem can reach these. This is §2 of DESIGN.md and
the reason the tool reports `clear` rather than `purge`.

- **FTL over-provisioning and wear levelling** — a rewrite lands on a fresh physical page; the old
  page is retained until garbage collection, and is readable by anyone who can address the flash
  directly.
- **Bad-block remapping** — a sector retired by the drive still holds its data and is no longer
  addressable.
- **SLC write cache / internal buffers.**
- **Drive write cache not flushed to platters** even after `fsync`.
- **HPA / DCO regions.**
- **Controller-level compression or dedup** — one logical overwrite may not touch the stored copy.

---

## 3. Things we deliberately do not do

| Not done | Why | What to do instead |
|---|---|---|
| Follow symlinks by default | The target is a file the user did not name. | `--follow-symlinks`, deliberately |
| Cross mount points by default | Silent destruction of a backup drive. | `--no-one-file-system`, deliberately |
| Shred hard-linked files by default | The data is reachable under another name; destroying it is invisible from the target tree. | `--hard-links=shred` |
| Verify overwrites by reading back | Proves the page cache lies to you, not that the media changed. `--verify` is designed but is honest only on raw devices. | read the raw device — §6 |
| Claim `purge` on a filesystem | `Guarantee::Purge` is never constructed; every overwrite reports `unverifiable`. Honest, uninformative, and blocked on filesystem/device detection. | TODO P2.9 |
| Prompt by default | Warn-and-wait is designed, unbuilt. Today dangerous paths refuse outright (exit 3). | REFERENCE.md §3.1 |

---

## 4. Implementation-dependent assumptions — the `blktamper` handoff

Each line is something the design **relies on** and which **cannot be confirmed from userspace**,
because every check goes through the same filesystem driver whose behaviour is in question. The
only way to settle any of them is to read the raw block device and compare. That is the boundary
between this repo and a block-level tool.

### 4.1 Measured 2026-09-21

`ci/fs-forensics.sh` writes a canary to a scratch image, destroys it with `sanitize`, unmounts,
and reads the **raw image**. Results so far:

| Filesystem | Canary in raw image | Original filename in raw image |
|---|---|---|
| **exFAT** (loop + `exfat-fuse`) | **0** — the overwrite reached the image | **0** — the §5.2 ladder left no trace |
| **ext4** (loop) | **0** | **17** — survives, exactly as DESIGN §5.3 predicts |

The ext4 result is the more useful of the two: it is a documented limitation demonstrated rather
than asserted. Renaming does not overwrite the old directory entry, and the name lives on in
slack. The script therefore *reports* the filename count and only fails on the canary — failing
on the name would be claiming a guarantee the design does not make.

Two caveats on the exFAT row. `exfat-fuse` is a userspace reimplementation, so it answers "what
does exfat-fuse do", not "what does every exFAT driver do" — one leg of the matrix, not the
matrix. And a clean result on a freshly-made 64 MiB image says nothing about a stick that has
been written and rewritten for years.

**FAT32 is not reachable in a Claude Cloud session at all**: the kernel (`6.18.44-fc-v37`,
Firecracker) has no `vfat`, `msdos` or `exfat`, there is no `/lib/modules`, and there is no
`modprobe`. `mkfs.vfat` works because it is userspace; `mount -t vfat` cannot. GitHub Actions
runners *do* have kernel vfat, so CI covers FAT32 even though the development environment cannot.
See `CLAUDE.md` §2.

### 4.2 Still assumed

| # | Assumption | If false |
|---|---|---|
| 1 | Unlink on FAT marks `0xE5` but does **not** scrub `DIR_FileSize` / first-cluster | the truncate-to-0 step is redundant — harmless, but a line of justification evaporates |
| 2 | `ftruncate(0)` rewrites the dirent **in place** rather than reallocating it | the size and first-cluster leak survives anyway |
| 3 | A same-length rename reuses the existing LFN slot chain in place | step 1 of the ladder overwrites nothing, and the original name survives in full |
| 4 | The 8.3 alias is regenerated rather than orphaned on rename | a mangled form of the original name survives every ladder step |
| 5 | `fsync` / `F_FULLFSYNC` reaches the media, not just the drive's cache | multi-pass mode is theatre; `-n > 1` writes nothing extra to the platter |
| 6 | The drive honours FLUSH CACHE / FUA | same as 5 |
| 7 | `F_NOCACHE` / `posix_fadvise(DONTNEED)` actually bypasses the page cache | passes coalesce and only the last one lands |
| 8 | Writes to the same LBA reach the same physical location | false on **all** flash — this is §2 of DESIGN.md and why `purge` is never claimed |

**Which of these are testable, and how.** The split matters, because half of them are ordinary
automated tests and half cannot be settled in software at all.

| Rows | Testable? | How |
|---|---|---|
| 1–3 | **Automated.** | Loopback FAT32/exFAT image, `xxd` the directory region, run the operation, `xxd` again, assert on the bytes. Pure CI work; belongs in the same job as TODO P1.5. |
| 4 (8.3 alias) | **Automated per OS, but needs a manual cross-OS matrix.** | Alias generation on rename is driver behaviour: Linux `vfat`, macOS `msdos`, Windows FASTFAT may each differ. The Linux leg automates like 1–3. macOS and Windows need a real volume written by that OS and inspected by hand, then the result recorded here. Until all three legs exist, the answer is per-driver, not general. |
| 5–6 (`fsync` reaches media; drive honours FLUSH/FUA) | **Not testable in software.** | Proving a write reached the platter rather than the drive's cache needs a power cut mid-write, or a bus analyser. No host-side test can distinguish them. |
| 7 (`F_NOCACHE` bypasses page cache) | **Measurable, not provable.** | Timing and `/proc` accounting give strong evidence; neither is proof. |
| 8 (same LBA → same physical page) | **Not testable without vendor tooling**, and already known false on flash. This is DESIGN §2 and the reason `purge` is never claimed. |

That 5–8 cannot be tested is not a gap to close. It is the boundary of what a userspace tool can
honestly assert, and the reason `Guarantee::Unverifiable` exists.

---

## 5. Out of scope by design — and what should cover it

This repo destroys **files through a filesystem**. It does not touch block devices. Everything here
is a legitimate need that deliberately lives elsewhere.

| Need | Belongs to |
|---|---|
| Verify what actually landed on the medium | `blktamper` — read raw, diff against expectation. Settles every row of §4. |
| Nuke the filesystem table / superblock / partition table | `blktamper` |
| Overwrite an entire block device with white noise | `blktamper`, or `blkdiscard -z`, or `dd` |
| ATA Secure Erase, NVMe Format / Sanitize | drive firmware; the only real *purge* on flash |
| Cryptographic erasure | the correct answer whenever purge is impossible — destroy the key, not the data |
| Host-side artefact cleanup (§2.2) | a separate tool; different privilege model, different threat model |
| Physical destruction | NIST 800-88 *Destroy*; explicitly out of scope, and `--explain` should say so |

---

## 6. Reuse: what a downstream tool can take

### 6.1 The blocker

**`sanitize` is a binary-only crate.** `Cargo.toml` declares no `[lib]`, there is no `src/lib.rs`,
and every module is private (`mod cli;` … `mod wipe;` in `main.rs:7-14`). **Nothing in this repo is
consumable by another crate today.** A GUI front-end or `blktamper` integration needs, first, a
`src/lib.rs` exposing the modules and `main.rs` reduced to argument handling plus a call into it.
That is a mechanical change and should happen before any consumer is written, not after.

### 6.2 Reusable as-is once exposed — pure, no I/O

| Module | What it gives | Notes |
|---|---|---|
| `name.rs` | Portable random name generation and the rename ladder | Charset is the intersection of APFS/HFS+/NTFS/exFAT/FAT32/ext4 constraints, single-case, no reserved DOS names, rejection-sampled. Reusable by anything that renames files on removable media. |
| `size.rs` | `1G`, `1MiB`, `10%` parsing with overflow handling | Fully general. |
| `wipe::plan_extents` | Head/tail/whole-file extent planning with block rounding | Pure function of `(size, blksize, cfg)`; directly reusable for block-device ranges. |
| `guards.rs` | Dangerous-path refusal and non-canonicalising normalisation | Deliberately does not resolve symlinks — resolution happens per-component under `openat`. |
| `report.rs` | The `Guarantee` model and the reporting vocabulary | The NIST clear/purge/unverifiable ladder, which a block-level tool can *strengthen* (it can legitimately claim purge where this cannot). |

### 6.3 Not portable — filesystem-bound

`walk.rs` (`openat` traversal, `st_dev` containment, symlink policy), `wipe::wipe_fd` (fd-based
overwrite), `sysx.rs` (platform sync/cache primitives). A block-device tool addresses an LBA range,
not a tree; only `plan_extents` carries over.

### 6.4 Reusable decisions, independent of code

Worth more than the code for a sibling tool:

- **DESIGN §16.4** — aggression is the default; the operator is competent.
- **REFERENCE.md §0** — scope / out-of-tree residue / thoroughness / ceremony, and the rule that
  the destruction set must be determined by the command line.
- **DESIGN §16.7** — residue reporting in three states (`scrubbed` / `present, not scrubbed` /
  `not checked`); silence is indistinguishable from success.
- **DESIGN §3** — never print "securely erased"; print what happened.
- **This document** — a tool that claims more than §4 can support has the same defect as `wipe`.

---

## 7. Needs an experiment

Ordered by how much the answer would change the design.

1. **§4 rows 1–4**, on loopback FAT32 and exFAT images, with hex dumps of the directory region
   before and after each step. Row 3 in particular decides whether the ladder's first step — the
   one the whole §5.2 design rests on — does anything at all.
2. **The 8.3 alias question** (§2.1) — **manual, cross-OS**. If a mangled original name survives
   every rename, name obfuscation on FAT32 is substantially weaker than DESIGN §5 claims, and the
   claim must be corrected rather than the design defended. Automate the Linux `vfat` leg; the
   macOS `msdos` and Windows FASTFAT legs need a volume written and inspected by hand on that OS,
   because alias generation is driver behaviour and the three may disagree. Record each driver's
   result in §2.1 as it is established — a per-driver answer is the only honest one until all three
   are in.
3. **The forensic canary test** (DESIGN §11, TODO P1.5): known string, sanitize, grep the raw
   image. Then the same on btrfs, asserting the canary **is** present, documenting where the
   guarantee does not hold.
4. **Differential oracle against `wipe`** (DESIGN §14.7, TODO P1.6).
5. **Whether `.fseventsd` records our own deletions**, and how long the flush window is. Determines
   whether §16.5.1's warning is a footnote or the headline.

---

## 8. Concerns not tracked anywhere else

Recorded 2026-09-21 at the point where implementation starts. Nothing here is a blocker for the
FAT-first work; several are traps that would otherwise be discovered by stepping in them.

### 8.1 A symlinked target argument bypasses the dangerous-path guard entirely

`guards::check()` runs on the textual path and deliberately does not canonicalise
(`guards.rs:63`). `sanitize /tmp/l` where `l -> /` is therefore **allowed**: the guard sees
`/tmp/l`, which is not in the refused list.

Not exploitable today — `follow_symlinks` is reachable only through `-F`, and `-F` permits `/`
anyway, so nothing is gained. **But it becomes a real hole the moment `--follow-symlinks` exists
as a standalone flag**, which is precisely the deferred work: `sanitize --follow-symlinks /tmp/l`
would destroy `/` without `--no-preserve-root` ever firing.

The guard's safety currently rests on the symlink *policy*, not on the guard. Whoever implements
`--follow-symlinks` must re-check the resolved target against `guards::check()` after resolution,
not only before. This is the single most important note in this section.

### 8.2 Timestamp scrub must run *after* truncation, not before

`ftruncate` updates `mtime`. Scrubbing timestamps and then truncating puts the real current time
straight back into the dirent, silently undoing the scrub. The correct order is:

```
overwrite → full_sync → ftruncate(0) → scrub times → rename ladder → unlink
```

DESIGN §16.5's ordering constraints do not say this. They should.

### 8.3 The parent directory's mtime dates the run

`rename` and `unlink` update the *parent directory's* mtime, not the file's. When the parent
survives — deleting selected files from a directory that stays — its mtime says "something happened
here, at this second". Unavoidable while the directory exists and we are writing into it; worth
stating rather than discovering. Scrubbing the parent's mtime afterwards is possible but would lie
about a directory the user did not ask us to touch.

### 8.4 Block rounding is a large write amplifier on FAT

`plan_extents` rounds up to `st_blksize`, which on FAT is the **cluster size** — commonly 4 KiB but
legitimately up to 64 KiB on large volumes. A 1-byte file therefore costs a full-cluster write. Ten
thousand small files on a 32 KiB-cluster volume is ~320 MiB of writes instead of ~10 KiB, which on
USB 2.0 flash is minutes rather than seconds, plus the wear.

This is deliberate — it wipes the file's own tail slack — and `-x/--exact` disables it. But it is
not documented as a cost anywhere, and on the priority filesystems it is the difference between a
fast run and a slow one.

A consequence found by writing the integration test: `pwrite` past EOF **extends the file**, since
that is how the tail of the last block is reached. For a deleted file this is invisible, but under
`-k` it meant a kept 30-byte file came back as a 4 KiB one. The file is now truncated back to its
original length after the slack wipe — the overwritten bytes stay on the media, they simply stop
being part of the file — and `keep_neither_truncates_nor_scrubs_times` guards it.

### 8.5 Mount-point roots are not guarded, contrary to DESIGN §7.4

§7.4 lists "any mount point root" among the paths to guard. `guards.rs` does not implement it:
the refused set is a fixed list of exact paths plus `$HOME`. `sanitize /Volumes/STICK` runs with no
warning at all.

For the primary use case that is almost certainly correct — wiping a removable volume is the point
of the tool. But spec and code disagree, and one of them should move. Recommendation: leave the
code, correct §7.4, and let warn-and-wait cover it once that exists.

### 8.6 `--scrub-volume` needs to read above the named target

Finding the volume root from a subdirectory means walking up until `st_dev` changes — i.e.
`stat`ing directories the user did not name, possibly without permission to do so. That is benign
(a read, not a write) but it is the first time the tool looks outside its target, and it can fail
in ways that must report `not checked` rather than silently scrubbing nothing. Part of why this
item is deferred; the rest is that it cannot be done correctly on a mounted volume at all (§16.5.1).

### 8.7 `-z` is largely defeated by the rest of the pipeline

`-z` exists to "hide shredding" by leaving zeros rather than noise. But a zero-filled,
zero-length, randomly-named dirent in a directory of other randomly-named dirents is not
inconspicuous — the *pattern* is the signature, not the byte values. `-z` still has a legitimate
use (some media compress zeros, and a zero pass is cheaper to verify) but its stated purpose is not
achieved and the help text should not imply it is.

### 8.8 Ladder tuning is hardcoded and unreachable

`same_length_rounds: 2` and `max_rename_steps: 16` are set literally in `Config::from_cli`
(`cli.rs:207-208`). They are thoroughness settings by REFERENCE.md §0 and should be config keys,
but no flag or key reaches them today. Low priority; noted so it is not mistaken for a deliberate
omission.

### 8.9b The second-Ctrl-C escalation is unverified

`interrupt::escalates` is unit-tested and the graceful path has four integration tests, but the
re-raise itself was never reached in testing: on this hardware the graceful stop completes in well
under a millisecond, so the process is gone before a second signal can be delivered after the first
handler returns. Four hundred signals at 1 ms intervals did not reach it.

That is a good sign about responsiveness and a bad one about coverage. The path exists for slow
removable flash, where a single chunk write or `fsync` can take long enough that a user wants out
before the next checkpoint — which is exactly the hardware CI does not have. Treat it as
**[unknown]** until someone runs it against a real USB 2.0 stick.

### 8.9a Residue accounting depends on readdir order

In a whole-directory run a sidecar may be reached either by its principal (counted as residue) or
by the listing (counted as an ordinary file), depending on the order `readdir` happens to return
them. Everything is destroyed either way and the totals are correct; only the attribution between
the two counters moves. Cosmetic, but it means "residue: 0 scrubbed" does not imply there were no
sidecars.

### 8.9 The tree is not green

~~`cargo clippy -- -D warnings` fails (dead code, `sysx.rs:101`) and `cargo fmt --check` fails (36
diffs across 6 files).~~ **Fixed.** Both are clean as of the residue work, so TODO P1.7's CI has
something that can pass on its first run. The workflow itself still does not exist.

### 8.10 Documentation has outrun the code

At the point this was written: ~2,000 lines of design documentation against 2,386 lines of Rust,
zero integration tests, and every destructive behaviour verified by hand exactly once. Every
decision recorded in DESIGN §16.4-16.7, REFERENCE.md and this file is specified against code with
no regression protection. The FAT-first goal is achievable; "perfect for FAT32 and exFAT" is not
claimable until §4 rows 1-4 are settled and TODO P1.4's integration tests exist.

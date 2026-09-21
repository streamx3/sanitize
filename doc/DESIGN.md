# sanitize — design document

Status: draft for discussion. Nothing implemented yet.

---

## 0. Verdict up front

Build it, in Rust, but build it as a **deletion tool with an overwrite stage**, not as an
"overwrite tool that also deletes". That reframing changes almost every default.

Two of your three complaints about `shred` are factually wrong (verified against GNU coreutils
9.11, §1). The third is right and is the whole reason this tool should exist. And the feature
you actually care about most — `--head 1G` on an encrypted container — is the one most likely
to silently do **nothing** on your Mac (§2). That is the part worth arguing about.

Also: the feature set below was already shipped, twice, by `wipe` (2009) and `srm` (2015), and
both projects are dead. The differentiator is not capability — it is maintenance, traversal
safety, and refusing to claim success it cannot deliver. See §14 before writing any code.

---

## 1. Correcting the premise: what `shred` already does

I ran these, not from memory.

**`-s/--size` already exists.** `shred -n1 -s 1K file` overwrites exactly the first 1 KiB and
leaves the rest and the file length alone. Your partial-overwrite feature is a rename of an
existing flag. GNU's suffix parser is already the one you want: `K`/`M`/`G`/`T` = 1024ⁿ,
`KB`/`MB`/`GB` = 1000ⁿ, `KiB`/`MiB` = 1024ⁿ. You are not fighting newspeak; coreutils agrees
with you. We inherit that parser verbatim.

**Renaming already happens.** `--remove=wipesync` (the default for `-u`) renames before
unlinking, in a ladder from the original length down to one character, `fsync`ing the parent
directory between steps:

```
shred: sample_file_name.bin: renamed to 00000000000000000000
shred: 00000000000000000000: renamed to 0000000000000000000
...
shred: 00: renamed to 0
shred: sample_file_name.bin: removed
```

Note it renames to `000…`, not gibberish. That is not a weakness. Randomising those bytes buys
nothing: the recoverable artefact is not the *new* name, it is the *old* name sitting in
directory-entry slack, and no choice of replacement name reliably overwrites it (§5.3). If we
ship gibberish names it is for collision-avoidance and shoulder-surfing, not forensics, and the
docs must say so.

**What's genuinely broken, and is our reason to exist:**

| Real gap | Fix |
|---|---|
| Not recursive at all | Recursive by default, TOCTOU-safe descent (§7) |
| Doesn't delete by default | Deletes by default; `-k/--keep` to opt out |
| Ignores directories entirely — dir names are never obfuscated, empty dirs are left behind | Rename ladder + `rmdir`, optional dirent scrub (§5.4) |
| Silently destroys data still reachable via another hard link | Detect `nlink>1`, skip and report (§9.1) |
| Ignores xattrs / resource forks / ADS — real user data lives there | Wipe them (§9.2) |
| Cheerfully pretends to work on CoW filesystems and SSDs | Detect and *refuse to claim success* (§2, §3) |
| Default `-n 3` is 1990s cargo cult | Default `-n 1`, cite NIST SP 800-88r1 |

That is a solid tool. "shred but with a flag it already has" is not.

---

## 2. The uncomfortable part — please read this before designing around `--head`

Your stated use case: a disk image of an encrypted volume, wipe the first ~1 GiB with white
noise so there is no entropy edge and no identifiable header. The reasoning is sound *as
cryptography*. It is likely wrong *as storage*.

### 2.1 On APFS, overwriting a file does not overwrite the file's blocks

APFS is copy-on-write and write-anywhere by design. When you write 1 GiB over the first 1 GiB
of an existing file, the filesystem is free to — and generally does — allocate **new** physical
blocks for those writes and re-point the extent map. The original 1 GiB, including the LUKS /
VeraCrypt / BitLocker header you meant to destroy, stays on the media until those blocks are
reused. Your `--head 1G` then *added* a gigabyte of noise instead of removing a gigabyte of
header.

The same applies to btrfs, ZFS, bcachefs, and to NTFS files that are compressed, sparse, or
inside a VSS-shadowed volume.

### 2.2 Underneath that, the SSD does it again

Every NAND SSD has a flash translation layer that never overwrites a page in place. Logical
block 12345 gets a new physical page on every write; the old page sits in the pool until GC
erases it. Over-provisioning means there are physically more pages than the drive admits to,
and no host-side write can address them. This is not a filesystem you can outsmart from
userspace.

### 2.3 The inversion, which is good news

On an SSD, `unlink` + TRIM is usually **more** effective than overwriting. After discard, most
drives return zeros for the trimmed LBAs deterministically, and the FTL marks the pages for
erase. Deleting is the erase primitive; overwriting is the placebo. This is a strong argument
for your instinct that `-n 1` is enough, and a strong argument for the tool's real posture:
*the delete is the product; the overwrite is a legacy-media courtesy.*

### 2.4 Where `--head` genuinely works

- Raw block devices: `/dev/sdX`, `/dev/rdiskN`. No filesystem indirection. **This is the LUKS-header kill and it is real.**
- ext4/xfs/HFS+ on rotational media, non-sparse, non-compressed, no snapshot pinning the extents.
- Any filesystem where you have separately confirmed in-place overwrite semantics.

### 2.5 Consequence for the design

`sanitize` must know the difference and say so. Concretely:

- At startup, per target, probe: filesystem type, `rotational` (Linux `queue/rotational`, macOS
  `IOKit` `Solid State`), whether the file is sparse/compressed/cloned, whether snapshots exist
  on the volume.
- If the physical-overwrite guarantee is void, emit a **warning that is not suppressible except
  by an explicit flag**, and mark the run's summary `overwrite: unverifiable` rather than `ok`.
- `sanitize --explain PATH` — no destruction, prints exactly what would and would not be
  recoverable, and what to do instead. I consider this the single most valuable feature in the
  tool, because the honest answer for a Mac user with an encrypted image on APFS is usually
  *"delete it and destroy the passphrase; the overwrite is decoration"*.

### 2.6 And the backup header

If you `--head 1G` a VeraCrypt volume you have destroyed the primary header and left the
**backup header in the last 128 KiB of the volume**, which by itself restores full access given
the password. Likewise a GPT backup header lives in the final LBA, and LUKS2 keeps a secondary
JSON metadata area (both within the first ~16 MiB, so head-wiping does cover LUKS2).

Therefore `--head` alone is a footgun and the tool ships `--tail` next to it, plus:

```
--preset=container    # == --head 1G --tail 1M, random fill, no zero pass
```

`-z` (final zero pass) must be **incompatible with the entropy-edge rationale** and should warn
if combined with `--head`: zeros are exactly the distinguishable edge you are trying to avoid.

---

## 3. Modes / threat model

The tool declares which of three it is achieving, per file, in its output:

1. **Logical erasure** — the data is unreachable through the filesystem. Always achieved on
   success. Defeats: another user on the box, an undelete utility, casual carving.
2. **Physical overwrite** — the previous bytes on the media are gone. Achieved only where §2.4
   holds. Defeats: forensic imaging of the media.
3. **Cryptographic erasure** — the key is gone. Not something `sanitize` does, but what
   `--explain` should recommend when (2) is impossible.

Never print "securely erased". Print what actually happened.

---

## 4. CLI surface

### 4.1 `shred` compatibility

All of them except `-u`, with two intentional divergences:

| Flag | Behaviour in `sanitize` |
|---|---|
| `-f, --force` | as `shred` — chmod to gain write; also `chflags nouchg` / `chattr -i` under §8.3 |
| `-n, --iterations=N` | **default 1** (shred: 3). `-n 0` = no overwrite, rename+delete only |
| `--random-source=FILE` | as `shred` |
| `-s, --size=N` | as `shred`; alias for `--head N`. Clamped to file size unless `--grow` |
| `-u`, `--remove[=HOW]` | accepted, no-op for `-u` (it's the default); `--remove=unlink\|wipe\|wipesync` still selects the rename strategy, default `wipesync` |
| `-v, --verbose` | as `shred`; `-vv` for syscall-level |
| `-x, --exact` | as `shred` — don't round up to block size |
| `-z, --zero` | as `shred`, warns under `--head` (§2.6) |

Divergence 1: `-n` default. Gutmann's 35 passes targeted MFM/RLL encoding on pre-1995 drives;
Gutmann himself has said so in the paper's epilogue. NIST SP 800-88r1 accepts a single overwrite
for magnetic media. Three passes is triple the wall-clock for zero additional security.

Divergence 2: deletion is the default, which is the point of the tool. Guarded by §7.4.

### 4.2 New flags

```
Deletion
  -k, --keep                  overwrite but do not delete (i.e. classic shred)
  -r, -R, --recursive         default ON for directories; --no-recursive to error instead
      --keep-dirs             don't remove directories, only their contents
      --rmdir-only            (with -k) remove empty dirs but keep files

Extent selection
      --head SIZE             overwrite only the first SIZE bytes  (alias: -s)
      --tail SIZE             overwrite only the last SIZE bytes
      --range A:B             overwrite [A,B); repeatable; composes with head/tail
      --preset container      == --head 1G --tail 1M
      --grow                  if SIZE > file size, extend the file (default: clamp)
   SIZE: 1024-based K/M/G/T/P, 1000-based KB/MB/GB/TB, explicit KiB/MiB/GiB,
         bare = bytes, trailing % = fraction of file size (e.g. --head 5%)

Naming
      --rename MODE           none | once | ladder     (default: ladder)
      --rename-charset SET    portable | posix | ascii (default: portable, §5.1)
      --scrub-dirents         after emptying a dir, churn its dirent blocks (§5.4)

Privileges
      --escalate MODE         never | ask | always     (default: ask, §8)

Safety
      --dry-run               plan only; prints the exact operation list
      --one-file-system       don't cross mount points (default: ON)
      --dereference           follow symlinks (default: OFF — the link is removed, not
                              its target; this differs from shred, deliberately)
      --hard-links MODE       skip | warn | shred      (default: skip, §9.1)
      --xattrs MODE           wipe | keep              (default: wipe, §9.2)
      --allow-dangerous-root  permit /, $HOME, /Users, /System, ... (§7.4)
  -I                          prompt once when >N files or recursing (like rm -I)
      --yes                   assume yes

Reporting
      --explain PATH          assess recoverability, destroy nothing (§2.5)
      --json                  machine-readable per-file results on stdout
      --progress              progress bars (default when stderr is a tty)
  -j, --jobs N                concurrent files; default 1 on rotational, 4 on SSD
```

### 4.3 Exit codes

`0` all targets fully succeeded · `1` one or more failed · `2` usage error · `3` refused for
safety (guard tripped, no `--allow-dangerous-root`) · `4` data overwritten but deletion failed
(the dangerous halfway state — must be loud and distinguishable).

---

## 5. Name obfuscation

### 5.1 Character set

Intersection of the constraints across APFS, HFS+, NTFS, exFAT, FAT32(LFN), ext3/4:

| FS | Forbidden | Case | Other |
|---|---|---|---|
| ext3/4 | `NUL` `/` | sensitive | 255 **bytes** |
| APFS | `NUL` `/` | **insensitive** by default | 255 UTF-8 chars |
| HFS+ | `NUL` `/` (`:` at Carbon layer) | insensitive | NFD-normalises Unicode |
| NTFS | `NUL`–`\x1F` `\ / : * ? " < > \|` | insensitive | reserved DOS names, no trailing `.`/space |
| exFAT | same as NTFS | insensitive | 255 chars |
| FAT32 | same as NTFS, plus `+ , ; = [ ]` unsafe (8.3 alias mangling) | insensitive | reserved DOS names |

The binding constraints are **case-insensitivity** (mixed-case names can collide) and **HFS+
Unicode normalisation** (any non-ASCII name may come back different). So:

```
charset "portable" = [a-z0-9]          36 symbols, first char must be a letter
charset "posix"    = [a-zA-Z0-9._-]    first char a letter, no trailing . or space
charset "ascii"    = printable ASCII minus the NTFS set
```

Additional invariants enforced by the generator, for `portable`:

- first character is `[a-z]` — avoids all-digit names, leading `-` being read as a flag by other
  tools, and leading `.` hiding the file
- never one of the reserved DOS device names (`con prn aux nul com0-9 lpt0-9 clock$`), checked
  case-folded, with and without a hypothetical extension
- no trailing `.` or space
- length in bytes ≤ min(255, original length) — see below
- generated from the CSPRNG, rejection-sampled to avoid modulo bias
- on `EEXIST`, regenerate (never increment — that leaks ordering)

36¹⁰ ≈ 3.6 × 10¹⁵, so collisions are a non-issue at any realistic directory size.

### 5.2 The ladder

Per file, after the data passes and before `unlink`:

1. rename to a random name of **exactly the original length** (clamped to 255)
2. `fsync` the parent directory (this is what `wipesync` means)
3. rename to length−1, `fsync`, … down to length 1
4. `unlinkat`, `fsync` parent

Step 1 at equal length matters more than the rest: it is the only step that has any chance of
landing in the same directory-entry record. Everything after it obscures the *length* of the
original name, which is itself metadata.

`--rename=once` collapses this to a single equal-length rename plus unlink — much faster on
large trees, and honestly nearly as good; `--rename=none` matches `--remove=unlink`.

Cost note: the `fsync` per step is why `wipesync` is slow. On a tree of 100k files that is
~2M directory fsyncs. `--rename=once` and `--remove=wipe` (no sync) exist for that reason, and
`-j` helps only if the fsyncs are on different devices.

### 5.3 Honest limits (this must be in the man page, not just here)

Renaming does **not** overwrite the old name. On ext4, `rename()` creates a new directory entry
and marks the old one deleted by extending the previous entry's `rec_len`; the old name's bytes
survive in that record's slack until the block is reused. `debugfs` and any competent undelete
tool will read them. htree-indexed directories make it messier, not better. The journal may hold
copies of both. On NTFS the old filename attribute persists in the MFT record and in `$LogFile`.

So: name obfuscation is a cheap best-effort that defeats casual recovery and nothing more. We do
it because it costs microseconds, not because it is a guarantee. Any documentation that implies
otherwise is a bug.

### 5.4 `--scrub-dirents`

The one thing that *does* plausibly overwrite name slack: after a directory is emptied, create
and delete many files with random names sized to churn the directory's data blocks, then `rmdir`.
Filesystem-dependent, unbounded in cost, and unverifiable — hence off by default and documented
as a heuristic. Directories on APFS (B-tree records, CoW) will not benefit at all.

### 5.5 Directories

Same ladder, then `rmdir`, then `fsync` the grandparent. Directories are processed depth-first,
post-order.

---

## 6. Wipe engine

### 6.1 Per-file sequence

```
1.  fstatat(AT_SYMLINK_NOFOLLOW)      type, size, nlink, flags, device
2.  guards                            nlink>1? immutable? mount boundary? (§7,§9)
3.  openat(O_WRONLY|O_NOFOLLOW|O_NOCTTY)
    macOS: fcntl(F_NOCACHE, 1)
    Linux: O_DIRECT if alignable, else posix_fadvise(DONTNEED) after each pass
4.  compute extents                   full | head | tail | ranges
                                      round up to st_blksize unless -x
5.  for pass in 1..=n:
        fill buffer from ChaCha20 CSPRNG (or --random-source)
        pwrite the extents
        Linux: fdatasync    macOS: fcntl(F_FULLFSYNC)   ← plain fsync is NOT enough on macOS
6.  if -z: one zero pass, same sync
7.  wipe xattrs / resource forks / ADS  (§9.2)
8.  close
9.  rename ladder                     (§5.2)
10. unlinkat + fsync parent
```

Steps 5's sync is not optional even for `-n 1`: without it the write may sit in page cache and a
crash leaves the original on disk. Without it for `-n > 1`, the page cache coalesces the passes
and only the last one ever reaches the media, making multi-pass literally meaningless.

`F_FULLFSYNC` on macOS is the one that flushes the drive's own write cache; `fsync(2)` on Darwin
explicitly does not. Getting this wrong makes the whole tool a no-op on a Mac under power loss.

### 6.2 Patterns

`shred`'s pattern schedule (the Gutmann-derived sequence of `0x55`, `0xAA`, 3-byte cycles…)
targets MFM/RLL encoding that no drive built since ~1995 uses. We do not reproduce it. Every
pass is CSPRNG output. Rationale: for modern media random is strictly at least as good, and
random is the only choice compatible with the entropy-edge use case in §2. `-z` remains
available for the "hide that shredding happened" case, with the §2.6 warning.

Use ChaCha20 seeded from `getrandom(2)`, not `/dev/urandom` reads — a `read()` per buffer is a
syscall bottleneck at multi-GB/s. `--random-source=FILE` switches to reading the file, matching
`shred`, and is the deterministic-testing hook.

### 6.3 Sparse files

Writing random data into holes materialises them and can `ENOSPC` mid-run — leaving a file both
partially wiped and undeleted. Default: detect holes via `SEEK_HOLE`/`SEEK_DATA`, skip them
(they contain no data to destroy), warn under `-v`. `--dense` forces writing through holes.

### 6.4 Small files

A file below ~700 bytes on NTFS is resident in the MFT record; ext4 with `inline_data` stores
small files in the inode. Overwriting through the file API may write to a completely different
place, or to the same inode with the old copy surviving in the journal. Under ~1 block,
`sanitize` should say `overwrite: unverifiable` rather than claim success.

### 6.5 `--verify`

Optional read-back of a sample of the written extents. Honest framing: this verifies the write
reached *the filesystem's current mapping of the file*, not that it reached the previous physical
blocks. It catches silently-failing hardware and lying network filesystems; it proves nothing
about forensic recovery. Worth having, worth labelling precisely.

---

## 7. Traversal and safety

This is where the actual risk in the project lives. Rust prevents buffer overflows; nothing
prevents `sanitize ~/Projects` from being typed at 2am. The traversal design is the security
feature.

### 7.1 Descend by file descriptor, never by path string

Every step uses `openat(dirfd, name, O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` and every operation uses
`*at()` relative to that fd. Paths are never re-resolved from strings after the initial open.
This closes the classic race where an attacker swaps a directory for a symlink to `/` between
your `stat` and your `unlink`. `rm -rf` gets this right; a naive implementation will not.

In Rust: use `cap-std` (capability-oriented, `openat`-based throughout) rather than `walkdir` or
`std::fs`, both of which are path-string based.

### 7.2 Symlinks

Default: never follow. A symlink target is a *different file* that the user did not name.
Encountering a symlink means: overwrite nothing, wipe the link itself (the link body is stored in
the inode / inline for short targets, so the target path leaks — rename ladder + unlink is all we
can do), report it. `--dereference` opts into shred's behaviour of following.

This is a deliberate divergence from `shred`, which follows.

### 7.3 Mount boundaries

`--one-file-system` defaults **on** for recursive runs. Compare `st_dev` on every descent. A
network mount or an external drive inside the tree is not what the user meant, and shredding
across an NFS mount is both slow and guarantee-free.

### 7.4 Root guards

> **Superseded — see REFERENCE.md §1.1 and §3.1.** `--allow-dangerous-root` was never built and
> no longer exists as a proposal. `/` alone refuses outright, gated by `--no-preserve-root`; every
> other path below warns and waits instead of refusing. The list itself is unchanged.

Guard the following: `/`, `/Users`, `/home`, `$HOME` itself, `/System`,
`/Applications`, `/usr`, `/etc`, `/var`, `/private`, any mount point root, and any path
whose subtree exceeds a configurable file count without `-I` confirmation. Also refuse if the
target resolves to a path containing `..` after canonicalisation at open time.

`--dry-run` should be the documented first step for anything recursive, and `-I` (rm-style
single prompt) should trigger automatically above ~50 files or on any directory.

### 7.5 Failure semantics

If the overwrite of a file fails partway, **do not delete it**. A partially-wiped, still-present
file is recoverable and obvious; a partially-wiped, deleted file is data loss with no security
benefit. Report, set exit code 1 (or 4 if wipe succeeded and delete failed), continue with the
rest of the tree unless `--fail-fast`.

---

## 8. Privilege escalation

You asked for per-file or per-session escalation. Per-file is the wrong shape: it produces a
password prompt storm, and each prompt is a moment where the user stops reading and types.

### 8.1 Design: plan, then elevate once

`--escalate=ask` (default):

1. Full traversal in **dry-run** first, unprivileged. Collect every path that returns `EACCES`
   or `EPERM` on the access check.
2. If the set is empty, proceed normally. Never escalate speculatively.
3. If non-empty, stop and print: the count, the paths (or a summary above a threshold), the
   reason for each, and exactly what will be destroyed.
4. Write that path list to a manifest file, `0600`, in a private temp dir.
5. Re-exec via `sudo` (or `doas`), passing `--manifest <path> --already-elevated` and *not* the
   original target arguments. The privileged process operates **only** on the manifest, so a
   symlink swap or a `$PWD` change between the two phases cannot redirect it.
6. Verify in the elevated process: manifest is owned by the invoking uid, mode 0600, on a
   non-world-writable directory.

`--escalate=never` fails on the first `EACCES` with a clear message. `--escalate=always` skips
the confirmation but still uses the manifest flow.

### 8.2 What we will not do

- **No setuid binary.** A setuid tool whose entire purpose is recursive deletion is a local root
  exploit waiting for its first argument-parsing bug.
- **No persistent privileged helper or daemon.** Nothing survives the process.
- **No credential caching of our own.** Delegate entirely to `sudo`/`doas`/polkit; the system
  policy decides, we never see a password.
- **No `sudo` per file.**

(v2 could do better: a single `sudo sanitize --helper` child that receives open requests over a
`socketpair` and returns file descriptors via `SCM_RIGHTS`, so the unprivileged parent does the
I/O on root-opened fds and the privileged surface is one `openat` call. Worth doing eventually;
not worth blocking v0.1.)

### 8.3 Escalation is not the only permission problem

- **Unlink needs write permission on the *directory*, not the file.** This is the most common
  `shred -u` failure and the error message should say it outright.
- **Immutable flags:** macOS `uchg`/`schg` (`chflags`), Linux `chattr +i`/`+a`. `-f` clears
  `uchg`/`+i`; `schg` requires root *and* a boot into single-user or SIP considerations.
- **macOS SIP** cannot be escalated past at all. Detect `SF_RESTRICTED` and fail with an
  explanation rather than an opaque `EPERM`.
- **Sticky-bit directories** (`/tmp`): you may not unlink another user's file even as the
  directory is world-writable. Root can; explain the situation rather than just escalating.

---

## 9. The leaks `shred` ignores

### 9.1 Hard links

`shred` on one link of a multiply-linked file destroys the data while the other name still
resolves — the other user sees a file full of noise. `sanitize` default `--hard-links=skip`:
detect `st_nlink > 1`, skip, report the count, exit 1. `warn` proceeds noisily; `shred`
proceeds silently (opt-in only). Where the whole tree is being destroyed and all links are
inside it, we can detect that via an inode set and proceed safely — worth implementing, since it
is the common case.

### 9.2 Data outside the data fork

- **macOS:** extended attributes, including `com.apple.ResourceFork` (arbitrary size),
  `com.apple.metadata:*` (Spotlight comments, download URLs), `com.apple.quarantine` (source
  URL, timestamp, downloading app). Enumerate with `listxattr`, overwrite each value with random
  bytes of equal length, then `removexattr`.
- **NTFS:** alternate data streams (`file:stream:$DATA`). Enumerate and wipe.
- **Linux:** `user.*`, `security.*`, POSIX ACLs.

`--xattrs=wipe` default. Overwriting the value before removal is best-effort for the same reason
as names (§5.3), but the *removal* is what stops the metadata from being trivially read.

### 9.3 Copies you cannot reach

Must be surfaced by `--explain` and warned about at runtime when detectable:

- **APFS local snapshots** (Time Machine takes them hourly, on by default). If a snapshot
  predates the shred, the file's blocks are pinned and fully readable via the snapshot. Check
  `tmutil listlocalsnapshots /`. **On a stock Mac this is the single most likely reason a shred
  achieves nothing.**
- **APFS clones / btrfs reflinks:** `clonefile()` copies share blocks; overwriting your copy
  breaks the sharing and leaves the other copy's blocks intact.
- **Journals:** ext3/4 with `data=journal` writes file *data* through the journal.
- Spotlight/Tracker indexes, thumbnail caches, `.DS_Store`, editor swap/backup files, shell
  history, Time Machine backups, Dropbox/iCloud/Git remotes.

`sanitize` cannot fix any of these. It can refuse to let the user believe otherwise.

### 9.4 Timestamps

`--scrub-times` sets `atime`/`mtime` to a fixed epoch before unlink. `ctime` cannot be set from
userspace. Marginal value; cheap; off by default.

---

## 10. Rust: yes, with one caveat

**Yes.** Reasons that actually apply here, not generic Rust advocacy:

- The tool runs as root over attacker-influenced directory trees. Memory safety in the path- and
  name-handling code is directly load-bearing.
- `rustix` gives clean, allocation-free access to `openat`/`unlinkat`/`renameat`/`fdatasync`/
  `fadvise`/`statx` without libc-shaped ergonomics; `cap-std` gives TOCTOU-safe traversal for
  free (§7.1). That combination does not exist as cleanly in Go or C++.
- Single static binary, cross-compiles to macOS/Linux/Windows, no runtime.
- `OsStr`/`OsString` model filenames as bytes-that-may-not-be-UTF-8, which is exactly right —
  ext4 names are arbitrary byte strings and a tool that assumes UTF-8 will fail on the very
  files most worth shredding. Go's `string` and C's `char*` both let you get this wrong quietly.

The caveat: **Rust does not protect against the failure mode that will actually hurt you**,
which is deleting the wrong subtree. That is a design problem (§7), and it deserves more of the
budget than the wipe engine does.

Alternatives considered: **C** — smaller, but this is a root-privileged recursive deleter and
the string/path handling is the entire risk surface; no. **Go** — perfectly viable, worse
`openat`-relative ergonomics, GC pauses irrelevant here, but you lose `cap-std` and you fight
`string` over non-UTF-8 names. **Zig** — attractive for the syscall layer, ecosystem too thin
for `clap`-grade CLI and the FS-detection matrix.

### 10.1 Crates

```
clap (derive)        CLI, shred-compatible short flags
rustix               openat/unlinkat/renameat/fdatasync/fadvise/statx/getrandom
cap-std              capability-based, openat-rooted directory traversal
rand + rand_chacha   ChaCha20 CSPRNG for pattern generation
libc                 F_FULLFSYNC, F_NOCACHE, chflags, listxattr (macOS specifics)
thiserror + anyhow   error types at the boundary, context in main
indicatif            progress, tty-gated
serde + serde_json   --json output
tempfile             the escalation manifest (0600, private dir)
```

Test-only: `assert_cmd`, `predicates`, `proptest`, `rusty-fork`.

### 10.2 Module layout

```
src/
  main.rs          arg parsing, dispatch, exit codes
  cli.rs           clap definitions + shred-compat aliases
  size.rs          the 1024/1000 suffix parser  ← unit-test this hard, it's the flag people misread
  plan.rs          dry-run traversal, produces an explicit operation list
  walk.rs          cap-std descent, one-file-system, symlink/hardlink policy
  wipe/
    mod.rs         per-file orchestration
    extents.rs     head/tail/range → block-aligned write list, hole detection
    pattern.rs     CSPRNG buffer fill, --random-source
    sync.rs        fdatasync / F_FULLFSYNC / O_DIRECT / F_NOCACHE per platform
  name.rs          charset, invariants, ladder, collision retry
  meta.rs          xattrs / ADS / resource forks / timestamps
  fsinfo.rs        fs type, rotational, CoW, snapshots, sparse → the §2 assessment
  elevate.rs       manifest + re-exec, verification on the privileged side
  report.rs        human + --json output, per-file guarantee level
```

`plan.rs` producing a materialised operation list before anything is destroyed is what makes
`--dry-run` trustworthy and what makes the escalation manifest possible. Build that first.

---

## 11. Testing

The bit that makes this credible rather than aspirational:

- **Forensic end-to-end.** On Linux CI: create a loopback ext4 image, write a file containing a
  known magic string, `sanitize` it, unmount, then `grep` the raw loop file for the magic. Assert
  absent. Run the same test on a btrfs loop image and assert it is **present** — and have the
  test *pass*, documenting where the guarantee does not hold. That test is the honest core of
  the project.
- **Name-generation property tests** (`proptest`): every generated name satisfies all six
  filesystem predicates, is not a reserved DOS name, is ≤ the source length, is lowercase-stable
  under case folding.
- **Cross-FS matrix**: loopback images of ext4, vfat, exfat, ntfs3 on Linux; `hdiutil` sparse
  images of APFS (case-sensitive and -insensitive) and HFS+ on macOS. Round-trip a generated
  name through each.
- **Traversal safety**: symlink-swap race harness, hard-link fixture, mount-boundary fixture,
  sticky-bit directory, immutable-flag file, sparse file, `nlink>1` inside and outside the tree.
- **Determinism**: `--random-source=/dev/zero` makes runs byte-reproducible for assertions.
- **Never test against real paths.** All destructive tests inside a `tempfile::TempDir` inside a
  loopback image, and the test harness should itself refuse to run if `$PWD` is under `$HOME`.

---

## 12. Scope for v0.1

Cut aggressively; the value is in getting the core right.

**In:** recursive `openat` traversal, delete-by-default, `-n/-f/-v/-x/-z/-s/--random-source`
compat, `--head`/`--tail`, rename ladder + portable charset, correct per-platform sync,
`--dry-run`, root guards, hard-link detection, `--json`, exit codes.

**v0.2:** `--escalate` (manifest + re-exec), xattr/ADS wiping, `fsinfo` detection and the
"unverifiable" warning, `--explain`.

**v0.3:** `--scrub-dirents`, `SCM_RIGHTS` privileged helper, `--verify`, block-device support and
a `--preset=container` that knows LUKS/VeraCrypt/GPT header geometry by name.

**Explicitly never:** Gutmann's 35-pass schedule, any claim of "military-grade" or "unrecoverable",
free-space filling (that is a different tool with a different risk profile — `sfill`).

---

## 13. Summary of where I'm pushing back

1. `shred -s` already does partial overwrite, with the 1024-based suffixes you want. Reuse the
   flag and the parser; don't reinvent them.
2. `shred -u` already renames, in a ladder, with directory `fsync`s. Gibberish instead of `000…`
   changes nothing forensically. The real limitation is dirent slack, which no rename fixes.
3. `--head 1G` on a disk image sitting on APFS very likely overwrites *nothing* — CoW allocates
   new blocks, and the SSD's FTL would defeat it anyway. It works on raw block devices. The tool
   must detect the difference and refuse to claim success.
4. If you head-wipe a VeraCrypt container you leave the backup header in the last 128 KiB, which
   is a complete recovery path. `--tail` ships alongside `--head`, and the container preset uses
   both.
5. `-z` (zero) is directly contrary to your no-entropy-edge goal. It should warn when combined
   with `--head`.
6. Per-file privilege escalation is the wrong shape — prompt storms train users to stop reading.
   Plan unprivileged, elevate once, operate from a verified manifest, never setuid.
7. `shred`'s real bugs are the ones nobody lists: hard links, xattrs/resource forks, and APFS
   local snapshots. On a stock Mac the snapshot is more likely to defeat you than the FTL is.
8. Rust: agreed. But budget the effort toward traversal safety, not the wipe loop. The wipe loop
   is two hundred lines; the thing that will ruin someone's day is a recursive delete that
   followed a symlink.

---

## 14. Prior art

Verified against upstream man pages, not memory. Checked 2026-07-28.

| | `shred` | `srm` (SF) | `srm` (secure-delete) | `wipe` | `scrub` | `nwipe` |
|---|---|---|---|---|---|---|
| Scope | files, devices | files + trees | files + trees | files, trees, devices | files, devices, free space | whole disks |
| Recursive | no | `-r` | `-r` | `-r` | no | n/a |
| Deletes by default | no | **yes** | **yes** | **yes** | no (`-r`) | n/a |
| Renames files before unlink | ladder, `-u` | yes | yes | 1× (`-P` raises) | opt-in `-D` | n/a |
| Renames **directories** | n/a | ? | ? | **no** | n/a | n/a |
| Partial byte range | `-s` (head) | no | no | **`-o` + `-l`** | no | no |
| Default passes | 3 | 1 × `0x00` | 38 | 34 | 4 (NNSA) | varies |
| One-file-system | no | `-x` | no | no | no | n/a |
| Symlinks | follows | — | — | not followed | `-L` | n/a |
| Dry run | no | no | no | no | **`-n`** | n/a |
| Last upstream release | active | Feb 2015 | 2003 (3.1) | ~2016 (16 commits) | Aug 2014 | active |

### 14.1 `wipe` (Berke Durak) — this is essentially §4 of this document

Recursive (`-r`), deletes by default (`-k` to keep), and `-o offset` + `-l length` provides both
`--head` and `--tail`. `-c` chmods like `-f`, symlinks are not followed by default (matching
§7.2), `-e` is exact-size, `-F` disables name wiping. The man page states the journaling caveat
plainly.

Source: `github.com/berke/wipe`, one 1750-line C file, last functional commit 2016 (the 2022
commits are man-page spelling fixes). Read rather than trusted, because the man page overstates
it:

- **The default is one rename, not ten.** `#define NAME_MAX_PASSES 1` (wipe.c:49); the ten in
  the man page is `NAME_MAX_TRIES`, the collision-retry limit. `-P n` raises it.
- **It never shortens the name.** Target length is fixed at the original basename length and
  only ever *increases*, on collision (wipe.c:552, 583). The original name's length leaks.
  shred's descending ladder is strictly better here, and my earlier note in this document
  claiming otherwise was wrong.
- **It calls global `sync()` after every rename** (wipe.c:579), not a directory `fsync`. The
  author documents this as the reason wipe is slow (wipe.c:525–531). On a large tree on
  removable media this is the dominant cost by far. §5.2's per-directory `fsync` is the right
  call.
- **It does not rename directories at all** — recurse, then `rmdir(fn)` on the original name
  (wipe.c:1238). Directory names are never obfuscated. This is exactly the gap that motivates
  §5.5, and on FAT/exFAT it is a real leak (§15).
- **Its charset is unsafe for removable media**: `0-9a-zA-Z-.` (wipe.c:520), filled at every
  position, so it can emit a leading `-`, a leading `.`, a trailing `.`, or a reserved DOS name
  — all hazards on exFAT/FAT32/NTFS. Mixed case also halves the effective alphabet on a
  case-insensitive volume. §5.1 exists because of this.
- **Traversal is `opendir(fn)` then `chdir(fn)`** (wipe.c:1204–1214), name-based and race-prone,
  with `chdir` back by saved absolute path. §7.1 exists because of this.

Missing: privilege escalation (only `-c` chmod), hard links, xattrs, CoW/SSD detection,
`openat` traversal, dry-run, directory-name wiping, and any maintainer since 2016.

### 14.2 `srm` (Matt Gauthier, SourceForge 1.2.15)

`rm`-shaped: `-r/-R`, `-i`, `-f`, and `-x/--one-file-system` (§7.3 — the only prior tool with
it). Sequence is overwrite → rename → truncate → unlink. Modes: `-s` simple (default),
`-P` OpenBSD 3-pass, `-E` DoE 3, `-C` RCMP 3, `-D` DoD 7, `-G` Gutmann 35.

Note the default is a **single pass of `0x00`** — zeros, not random. That is the entropy edge
§2.6 warns about, shipped as the default.

Missing: byte ranges, hard links, xattrs, CoW/SSD detection.

### 14.3 `srm` / secure-delete (THC, 3.1, 2003)

Distinct project from 14.2, same binary name. `-r` recursive, deletes by default, renames to
random values then truncates. **38 passes by default**; `-l` reduces to two, `-ll` to one,
`-z` zeroes the final pass, `-f` skips `/dev/urandom` and sync. Debian's `3.1-12` is packaging
activity, not upstream life.

Its lasting value is the siblings — `sfill` (free space), `sswap` (swap), `sdmem` (RAM) — which
are outside `sanitize`'s scope and should stay there (§12).

### 14.4 `scrub` (LLNL / chaos, 2.6.1)

Not a tree walker: a pattern library plus block-device and free-space (`-X`) modes. Patterns:
nnsa (default, 4-pass), dod, bsi, gutmann, schneier, pfitzner7/33, usarmy, fillzero, fillff,
random, random2, old, fastold, custom. `-r` removes after scrubbing, `-D newname` scrubs the
directory entry and renames, `-L` avoids following a symlink to its target, `-n` is a dry run,
and it writes a detectable "scrub signature" so a re-scrub can be skipped or forced.

Its man page names the real enemy outright — "journaled, log structured, copy-on-write,
versioned, and network file systems" — which is §2 of this document, written in 2014. It
documents the limitation; it does not detect it. That gap is our opening.

### 14.5 `nwipe`

Whole-device sanitization (DBAN's `dwipe` fork): ncurses UI, DoD 5220.22-M / Gutmann / RCMP
OPS-II / PRNG / zero methods, `--rounds`, `--verify`, PDF erasure certificates. Different
problem — the drive, not the file. Actively maintained. Not a competitor; it is what you should
use *instead of* `sanitize` when the whole disk is the unit of destruction, and `--explain`
should say so.

### 14.6 Consequences for positioning

1. "Recursive shred that renames things" is `wipe`, and has been for ~17 years. That cannot be
   the pitch.
2. The unoccupied slot is **detection and honest reporting** (§2.5, §3, `--explain`). `scrub`
   documents the CoW/SSD problem in prose; nothing checks the filesystem type, the rotational
   flag, or whether an APFS snapshot is pinning the extents. Build that first — it is the only
   part with no prior art.
3. Secondary, still real: hard links (§9.1), xattrs/resource forks/ADS (§9.2), `openat`-based
   traversal (§7.1), privilege escalation (§8), and memory safety in a root-privileged
   recursive deleter. Zero of the five tools above have any of these.
4. Platform gap: on macOS only `scrub` and GNU `shred` are packaged in Homebrew; `wipe`, `srm`,
   and secure-delete are not. Apple shipped an `srm` binary once and has since removed it, and
   withdrew Secure Empty Trash in OS X 10.11 on the grounds that erasure could not be guaranteed
   on SSDs — the vendor making §2's argument.
5. Reviving `wipe` instead of writing `sanitize` was considered: 16 commits total, C from the
   path-string era, and the changes needed (openat traversal, xattrs, fs detection, escalation)
   touch every file and still leave it in C. Rewriting is defensible; claiming novelty is not.

---

## 15. The primary use case: subtrees on removable flash (FAT32 / exFAT)

Added after the encrypted-image case turned out to be secondary. The main job is: destroy some
tens of GB across a convoluted directory tree on a USB stick or SD card, rooted at a given
subfolder, without destroying the rest of the drive and without burning the drive's endurance.

This changes priorities more than §2 did.

### 15.1 The filesystem is on our side here

FAT32 and exFAT have **no journal, no copy-on-write, no snapshots, no compression, and no
sparse-file games**. A write to offset N of a file goes to the same logical blocks it went to
before. Everything in §2.1 evaporates: the filesystem layer is fully cooperative, and the only
adversary left is the FTL.

That is a much better position than APFS, and it means the overwrite stage is worth doing here
in a way it is not on the user's boot volume.

### 15.2 Names matter far more on FAT/exFAT than anywhere else

Deleting a file on FAT32/exFAT sets `0xE5` on the first byte of the directory entry and does
nothing else. The long-filename entry chain, the starting cluster, and the file size all survive
intact until the slot is reused — which is why every consumer undelete tool works so well on
memory cards. A same-length rename rewrites that same LFN entry chain in place.

So the "the FS table keeps the filename" intuition that motivated this whole project is
**literally correct on FAT and exFAT**, materially weaker on ext4 (§5.3), and close to
irrelevant on APFS. And directory names live in the parent's entry table exactly like file
names — which is precisely what `wipe` does not touch (§14.1).

Consequence: the rename ladder is not a cheap gesture on this media, it is a primary feature,
and §5.5's directory handling is the differentiator against every existing tool.

### 15.3 The FTL is still there, and TRIM probably is not

USB Mass Storage generally does not pass TRIM through to the device; UASP sometimes does, SD
card readers essentially never. So §2.3's consolation — that `unlink` + discard does the real
work on an SSD — does **not** apply to a USB stick. Removable flash controllers also have far
less over-provisioning and cruder wear levelling than a real SSD, which cuts both ways: less
hidden spare area to hide stale copies in, but also less predictable relocation.

### 15.4 Multi-pass on flash is pure cost

The FTL redirects every write to a fresh page, so passes 2..N land on *different physical pages*
than pass 1. They do not overwrite anything the first pass missed. What they do cost, for 20 GB
of files:

| passes | bytes written | time @ 30 MB/s | wear on a 64 GB stick |
|---|---|---|---|
| 1 | 20 GB | ~11 min | 0.3 drive-writes |
| 4 (`wipe -q`) | 80 GB | ~45 min | 1.3 |
| 34 (`wipe` default) | 680 GB | **~6.3 h** | 10.6 |
| 38 (secure-delete default) | 760 GB | ~7 h | 11.9 |

Six hours and ten drive-writes of wear, for zero additional bytes destroyed. `-n 1` is not a
compromise on this media; anything above it is a defect. `sanitize` should **warn** when `-n > 1`
is requested on non-rotational media, naming the wear and the time.

### 15.5 What actually pressures the FTL: one free-space fill

If the concern is stale pages holding old copies, the operation that helps is filling the
volume's free space once — a single drive-write that forces the controller to consume and garbage
-collect its spare pool. One full-volume fill is roughly 3× the wear of a 1-pass shred of a 20 GB
subtree and does considerably more real work than 34 per-file passes.

Important for this use case: free-space filling touches only unallocated space, so it is
compatible with "only this subfolder" — it does not endanger the other files on the drive. It is
out of scope for `sanitize` v1 (§12) and already exists as `sfill` and `scrub -X`, but `--explain`
should recommend it by name on removable media.

### 15.6 Revised priorities

| Feature | Was | Now |
|---|---|---|
| `--dry-run` (§4.2) | nice to have | **v0.1 blocker** — convoluted trees, hand-typed subfolder root |
| `--one-file-system` (§7.3) | insurance | **v0.1** — stops a slip from walking off the stick onto the internal disk |
| Portable name charset (§5.1) | theoretical | **v0.1 core** — exFAT/FAT32 is the target, DOS reserved names and trailing dots actually bite |
| Directory-name wiping (§5.5) | completeness | **the differentiator** — no existing tool does it, and on FAT it leaks |
| Rename ladder quality (§5.2) | best-effort gesture | **primary feature** — same-length renames first (rewrite the LFN chain in place), then descend |
| `fsync` strategy (§6.1) | correctness detail | **performance-critical** — per-directory `fsync`, never `wipe`'s global `sync()` |
| `-n 1` default | defensible | **enforced** with a warning above it (§15.4) |
| Privilege escalation (§8) | headline feature | **deprioritise to v0.2+** — FAT/exFAT carry no permissions; this need comes from other contexts |
| `--head`/`--tail` (§4.2) | headline feature | keep, but it is the *secondary* use case |
| CoW/snapshot detection (§2.5) | headline feature | keep — it is what stops the tool lying on APFS — but it reports "clear" on this media |

### 15.7 Concrete recommendation for the current task

Today, with existing tools, on a stick full of large files:

```bash
wipe -r -q -Q 1 -i /Volumes/STICK/subfolder     # 1 random pass, recursive, delete
```

`-q -Q 1` overrides the 34-pass default. Expect the global `sync()` per rename (§14.1) to
dominate wall-clock on a tree with many small files, and note that directory names are left
un-obfuscated. Preview the tree first with `find` — `wipe` has no dry run.

### 14.7 Code audit of `wipe` (decision: improve vs rewrite)

Read the full source (2692 lines: wipe.c 1750, plus bundled md5/arcfour/rc6/misc), built it on
macOS 26 (`make generic` — compiles with warnings only, and a smoke test correctly wiped and
removed a test tree), and read the write loop, RNG, and traversal in detail.

**Genuine defects found in reading, beyond §14.1:**

- **`-c` chmod fallback drops `O_SYNC`.** On `EACCES` it does `chmod(fn, 0700)` (clobbering the
  original mode) and reopens with plain `O_WRONLY` (wipe.c:831–834) — exactly the files that
  needed permission fixing get the weaker sync path.
- **Block-size roundup off-by-one-block.** `len += blksize - (len % blksize)` (wipe.c:892) adds
  a full block when the size is already aligned, growing every aligned file by one block —
  on FAT, allocating a fresh cluster to wipe nothing.
- **Any write error aborts the entire run.** `exit(EXIT_FAILURE)` mid-loop (wipe.c:1047). On a
  flash drive with one failing sector — the §15 use case — the whole recursive job dies partway,
  contra §7.5.
- **macOS sync is inadequate.** `HAVE_OSYNC` is not defined in the generic target, so it relies
  on per-buffer `fsync` — and Darwin `fsync` does not flush the drive cache; there is no
  `F_FULLFSYNC` anywhere (§6.1).
- **The generic build also lacks `BLKGETSIZE`**, falling back to `lseek` for device sizes, and
  the Makefile's platform matrix is SunOS 5.5.1 / AIX 4.1 / FreeBSD 2.2.6 / Digital Alpha —
  no macOS target exists.
- **`-D` symlink dereference is a documented race**: `readlink` into a `NAME_MAX` buffer, then
  `remove()` by the read path; the comment above it says "of course, we have a race condition
  here" (wipe.c:1108).
- Unaligned `u32` stores in the PRNG fill loops (random.c:231) — UB that happens to work on
  x86/ARM64. RNG is RC4 seeded with 128 bits of MD5; with no entropy source it falls back to
  hashing `environ`+pid+time. Bundles its own MD5/RC4/RC6 (RC6 gated on "if RC6 is accepted as
  the AES", which answers how old this is).

**Architecture:** options and per-file state share one pool of `o_*` globals — `o_wipe_length`
is both the `-l` flag and a per-file computed value (wipe.c:890); `o_skip_passes`/`o_pass_order`
are mutated mid-run "only meant for first file" (wipe.c:1078). Traversal is `opendir`+`chdir`
with a global CWD. There are **zero tests** and no CI.

**Verdict:** the program is coherent, honest for its era, and still works — but every planned
feature (openat traversal §7.1, dir renames §5.5, charset §5.1, sync strategy §6.1, dry-run,
per-file error recovery §7.5) lands in the ~600 lines of core, whose global-state structure
resists incremental change, with no test net under it. "Improving wipe" is a rewrite-in-place
in C, inheriting the architecture, minus the type system, on GPL-2. Rewrite fresh; keep `wipe`
as the **differential-testing oracle** (§11): same tree, wipe vs sanitize, compare surviving
bytes on a loopback image.

---

## 16. Locked decisions for v1 (supersedes earlier sections where they differ)

Name is **`sanitize`**: binary = crate = repo. Chosen over `shredr`, `efface`, `autoclave`,
`incinerate` and a dozen others because it is free in every namespace checked (macOS, Homebrew,
Debian sid file index, crates.io, no Windows builtin), is universally understood, and is the
literal term of art — NIST SP 800-88 is titled *Guidelines for Media Sanitization*, and its
Clear / Purge / Destroy tiers map onto §3's guarantee model:

| NIST 800-88 tier | §3 mode | when `sanitize` can claim it |
|---|---|---|
| Clear | logical erasure | always, on success |
| Purge | physical overwrite | only where §2.4 holds (raw devices, non-CoW on rotational) |
| Destroy | physical destruction | never — out of scope, and `--explain` says so |

### 16.1 Robustness: the program does not crash. Ever.

This is a hard requirement, not a quality goal. A destructive recursive tool that aborts
part-way through a tree leaves the user in the worst possible state: some data destroyed, some
not, and no record of which. Concretely:

1. **No panics by construction.** The crate denies `clippy::unwrap_used`, `expect_used`,
   `panic`, `indexing_slicing`, `integer_arithmetic` outside of audited modules. Every fallible
   operation returns `Result`. `Cargo.toml` sets `panic = "abort"` for release so that a bug
   cannot unwind through a half-written file — and a `panic::set_hook` prints the path being
   processed before aborting, so even the impossible case is diagnosable.
2. **Every per-path error is recorded and the walk continues.** `EACCES`, `EPERM`, `ENOENT`,
   `ENOTDIR`, `ELOOP`, `EIO`, `ENOSPC`, `EROFS`, `EBUSY`, `ETXTBSY`, `ENAMETOOLONG`, `EISDIR`
   are all *per-entry outcomes*, never run-enders. This is the single biggest defect in `wipe`
   (§14.7: `exit(EXIT_FAILURE)` mid-write) and we fix it by design.
3. **Retry the retryable.** `EINTR` and `EAGAIN` retry; short reads and short writes loop until
   complete or a hard error. `EMFILE`/`ENFILE` trigger a descent-depth fallback rather than a
   failure (§16.2).
4. **A read error is not a write error.** Failing to *read* metadata never aborts anything;
   failing to *write* aborts only that file, and per §7.5 an unwiped file is then **not**
   deleted.
5. **Exit code reflects the worst outcome, and the summary always prints** — including on
   `SIGINT`, where the current file is finished or abandoned cleanly and the report is emitted.
6. Fatal conditions are exactly two: a usage error (exit 2) and a safety refusal *before any
   destruction has occurred* (exit 3).

### 16.2 Defaults

| Behaviour | Default | Rationale |
|---|---|---|
| Recursion | **on** | §1; directories are the point of the tool |
| Deletion | **on** | §1; `-k/--keep` to opt out |
| Symlinks | **remove the link, never touch the target** | the target is a file the user did not name (§7.2) |
| Boundary containment | **stop at the narrowest of drive / partition / mount point** | that is `st_dev`, compared on every descent |
| Passes | 1 | §15.4 |
| Dangerous roots | refused | requires `-F` (§16.3) |

Descent holds one directory fd per level. On `EMFILE`/`ENFILE` the walker drops to a
re-open-by-name fallback for the deepest level rather than failing, and raises `RLIMIT_NOFILE`
to its hard limit at startup.

### 16.3 `-F` / `--force-everything`

A single flag that removes every guard at once. Distinct from `shred`'s `-f` (which only
chmods; we keep that spelling and meaning for compatibility).

`-F` does all of the following:

- **No path is refused.** `/`, `$HOME`, `/System`, `/usr` — all permitted. `-F` is *required*
  to name any of these, and it is *sufficient*: no prompt, no countdown, nothing stops it.
- **Symlinks are followed**: the target's contents are wiped and removed first, then the link
  itself is removed. Cycle detection via a visited `(st_dev, st_ino)` set, so a symlink loop
  terminates instead of recursing forever.
- **Boundary containment is off**: descent crosses mount points, partitions, and drives.
- Implies `-f` (chmod to gain write) and clears immutable flags (`uchg`/`schg`, `chattr -i`)
  where permitted.

Full effect requires `root`/`sudo`; without it `-F` still applies the above semantics and
simply records `EACCES` per entry and continues (§16.1) rather than failing the run.

**Consequence the user has accepted, recorded here for the record**: `-F` plus followed
symlinks plus no mount boundary, run as root against `/`, will destroy every mounted volume
reachable from the tree — external drives, network shares, Time Machine targets — because the
symlink and the mount boundary were the only things scoping it. This is the documented purpose
of the flag. `--dry-run` composes with `-F` and is the recommended way to confirm scope first.

### 16.4 Operator assumption: aggression is the default

Decided 2026-09-21. Supersedes any reading of §5.4, §7.4 or §9 that leaves recoverable residue
in place for the user's protection.

`sanitize` assumes a competent operator who has a reason. It does not assume a casual user who
will regret the run. Someone relying on a file in `$RECYCLE.BIN` or `.Trashes` surviving a
hard-cleaning tool — so that it can be carried to another system — does not have a workflow
worth protecting; they have an OpSec failure. A tool that leaves recoverable copies of the data
it was told to destroy has failed at its only job.

The distinction that governs every default below:

> Refusing a **target** protects the user from a mistake. Refusing to scrub the **residue of a
> target they named** protects them from their own stated intent. Only the first is our business.

So the guards that stay are the ones answering *"did you mean this path?"* — dangerous-root
refusal, mount containment, the symlink boundary, hard-link skipping. The guards that go are the
ones answering *"are you sure you want it this thoroughly gone?"* There is no such question;
that is what the user asked for.

Warn-and-wait remains for dangerous targets and is the only interactive gate. A force flag skips
it, and the config file may set it skipped by default. Once the target is accepted, nothing
further is withheld.

### 16.5 Metadata and residue: defaults

All **on** by default, each with a `--no-` inverse. None of this is gated behind `-F`: it is not
extra destruction, it is the destruction the user already asked for, finished properly.

| Behaviour | Disable with | What it removes |
|---|---|---|
| Timestamp scrub | `--no-scrub-times` | `atime`/`mtime` before unlink, so the residual dirent carries no real time |
| Truncate before unlink | `--no-truncate` | rewrites size and first-cluster in the *live* dirent; without it both survive in dirent slack |
| Sidecar scrub | `--no-scrub-sidecars` | AppleDouble `._<name>`, `.DS_Store`, `Thumbs.db`, `ehthumbs.db`, `desktop.ini` |
| Volume residue scrub | `--no-scrub-volume` | `.fseventsd`, `.Spotlight-V100`, `.Trashes`, `._.Trashes`, `$RECYCLE.BIN`, `System Volume Information`, `.TemporaryItems`, `LOST.DIR`, `FOUND.*`, `*.CHK` |

Ordering constraints, all load-bearing:

* `ftruncate(0)` goes **after** `wipe_fd`'s final `full_sync` and **before** `close`. Earlier than
  the sync and the random writes become dead stores the kernel may legally discard; earlier than
  the overwrite and the clusters are freed before there is anything to overwrite.
* Truncation is gated on `!cfg.keep`. `-k` means overwrite *and keep*; truncating there would
  destroy the file the user explicitly preserved.
* The AppleDouble sidecar is processed **before** its principal, so a run that dies part-way never
  leaves `._foo.7z` naming a `foo.7z` that is already gone. Note the sidecar's own filename
  embeds the principal's name, which otherwise defeats the entire §5.2 ladder.
* Volume residue is scrubbed **last**, after every target — it has to be, because our own unlinks
  generate the event records we are trying to remove. See §16.5.1.
* Timestamp scrub cannot use the Unix epoch. FAT's epoch begins 1980-01-01, so `0` is
  unrepresentable and clamps, which is itself a signature. Use a random value in a plausible
  window. Create time is not settable from POSIX; on macOS use `setattrlist(ATTR_CMN_CRTIME)`,
  and on Linux record it as an unfixable residue (FAT has no ctime field at all, so §9.4's
  ctime caveat is moot on the priority filesystems).

#### 16.5.1 The residue window is real, and is reported rather than hidden

`.fseventsd` is written by the OS while the volume is mounted, including in response to our own
unlinks. Scrubbing it last narrows the window; it does not close it, because the daemon buffers
and may flush after we finish. We therefore cannot claim a *mounted* volume is clean of event
residue, and must not. The report states that the window exists and recommends unmounting
immediately. Pretending otherwise is precisely the overclaim this project exists to avoid.

### 16.6 Configuration precedence

The complete flag and config-key reference, with the authority rules, lives in
[REFERENCE.md](REFERENCE.md). Scope settings — those that change *which* bytes are destroyed —
have no config keys at all; see REFERENCE.md §0.

```
hardcoded defaults  <  /etc/sanitize/default.conf  <  user input (CLI)
```

Later overrides earlier; the CLI always wins. A config file may set any default in §16.5,
including turning warn-and-wait off.

Every run that destroys anything prints which layers were in effect and which non-default
settings came from where, so a surprising outcome is always traceable to the line that caused it.
A destructive tool that can be silently reconfigured is a destructive tool that can silently lie
about what it did — the same defect class as printing "securely erased".

Format is flat `key = value`, parsed in-tree. No TOML dependency: the crate denies `unwrap`,
`expect` and `panic`, and a config parser does not justify a new supply-chain edge.

### 16.7 Residue reporting: three states, never two

Every residue class is reported as exactly one of:

| State | Meaning |
|---|---|
| `scrubbed` | found and destroyed |
| `present, not scrubbed` | found, deliberately left, **with the reason** (flag off, `EACCES`, unsupported) |
| `not checked` | we did not look — e.g. the volume root could not be identified |

Collapsing these into silence is the failure this rule exists to prevent. Silence is
indistinguishable from success, so a user cannot tell "there was no residue" from "we never
looked". Unscrubbed residue that references a destroyed path counts as an incomplete run and
sets exit 1, by the same reasoning `main.rs` already applies to skipped entries: exit 0 must mean
the job is done.

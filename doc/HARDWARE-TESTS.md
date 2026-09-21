# Tests that need real hardware

Everything here is out of reach of CI and of a Claude Cloud session, for reasons of physics or
kernel configuration rather than effort. Each entry says what to run, what result would confirm
the design, and what result would mean a documented claim has to change.

> **Use a scratch USB stick with nothing on it.** Every procedure below destroys data, and
> several are run as root against a real block device. Check `lsblk` twice before typing a
> device node: `/dev/sdb` on one boot is not `/dev/sdb` on the next.

Status of the environments involved:

| Environment | Can do | Cannot do |
|---|---|---|
| Claude Cloud session | ext4 and exFAT loopback (`ci/fs-forensics.sh`) | FAT32 — no `vfat` in the kernel, no modules |
| GitHub Actions | FAT32, exFAT, ext4 loopback; macOS build and test | real devices, power loss, slow media |
| Your hardware | everything below | — |

---

## 1. FAT32 8.3 short-name aliases — the highest-value unknown

`SHORTCOMINGS.md` §2.1 and §4 row 4, marked **[unknown]**.

Every FAT32 long filename has a companion 8.3 alias derived from it — `gay_novel.7z` becomes
something like `GAY_NO~1.7Z`. The §5.2 rename ladder rewrites the long-name entry chain. It is
not established whether the alias is regenerated, orphaned, or left carrying a mangled form of
the original name.

**If a mangled original survives every rename, name obfuscation on FAT32 is substantially weaker
than DESIGN §5 claims, and the claim must be corrected rather than the design defended.**

Alias generation is driver behaviour, so this needs all three:

```bash
# Linux (kernel vfat)
sudo ./ci/fs-forensics.sh vfat          # the automated part
# then, by hand, on a scratch image:
mkfs.vfat -F 32 scratch.img
sudo mount -o loop scratch.img /mnt/x
echo secret > /mnt/x/a_long_distinctive_filename.7z
sudo umount /mnt/x
xxd scratch.img | grep -i -A2 -B2 'A_LONG\|~1'   # record the alias bytes
# run sanitize against the mounted image, unmount, xxd again, diff the dirent region
```

On **macOS**, create the volume with Disk Utility or `diskutil eraseVolume MS-DOS`, write the
file from Finder (so the OS generates the alias, not a tool), then read the raw device with
`sudo dd if=/dev/rdiskN` and search. On **Windows**, format with `format /FS:FAT32`, write the
file from Explorer, and read the raw volume with a hex editor running as Administrator.

Record each driver's answer separately in `SHORTCOMINGS.md` §2.1. A per-driver answer is the
only honest one until all three are in; do not generalise from Linux.

## 2. Directory-entry assumptions 1–3

`SHORTCOMINGS.md` §4 rows 1–3, marked **[assumed]**. These are automatable in CI for exFAT and
FAT32, and `ci/fs-forensics.sh` covers the data guarantee — but the *dirent-level* checks below
need a hex dump per operation, which is still manual:

1. Does unlink on FAT scrub `DIR_FileSize` (offset `0x1C`) and the first cluster
   (`0x14`/`0x1A`), or only stamp `0xE5`? If it already scrubs them, the truncate-to-0 step is
   redundant — harmless, but a line of justification evaporates.
2. Does `ftruncate(0)` rewrite the dirent **in place**, or reallocate it? If it reallocates, the
   size and first-cluster leak survives anyway and the step buys nothing.
3. Does a same-length rename reuse the existing long-filename slot chain in place? **This one
   matters most**: if it does not, step 1 of the ladder — which the whole of DESIGN §5.2 rests
   on — overwrites nothing.

Procedure for each: loopback image, `xxd` the directory region, perform the single operation,
`xxd` again, diff. Compare against a run with `--no-truncate` to isolate the effect.

## 3. Does `fsync` reach the platter — assumptions 5–6

`SHORTCOMINGS.md` §4 rows 5–6, **not testable in software at all**. Proving a write reached the
medium rather than the drive's cache needs one of:

- **Power interruption mid-write.** Write a known pattern, `fsync`, cut power at the wall (not a
  clean shutdown), reconnect, read the raw device and check the pattern is there.
- **A bus analyser** or a drive that reports FLUSH CACHE handling honestly.

If `fsync`/`F_FULLFSYNC` does not reach the media, `-n > 1` is theatre: every pass lands in the
same cache and only the last reaches the platter. The `-n > 1` warning text already says extra
passes are near-useless on flash; this would extend that to rotational media too.

## 4. The second Ctrl-C escalation

`SHORTCOMINGS.md` §8.9b, **[unknown]**. `interrupt::escalates` is unit-tested and the graceful
path has four integration tests, but the re-raise itself has never been reached: on fast storage
the graceful stop completes in under a millisecond, so the process is gone before a second signal
can be delivered. Four hundred signals at 1 ms intervals did not reach it.

It exists for slow removable flash, where a single 1 MiB chunk write or an `fsync` can take long
enough that the next checkpoint is far away:

```bash
# scratch USB 2.0 stick, several GB of small files
sanitize /media/you/SCRATCH/tree
# Ctrl-C once  -> expect: stops at a safe point, summary prints, exit 1
# Ctrl-C twice -> expect: dies immediately, no summary (documented cost)
```

Confirm the first Ctrl-C takes a visible moment to stop — that is the window the escalation
exists for. If it is instant even on slow media, the escalation is dead code and should go.

## 5. `.fseventsd` on a real Mac

`DESIGN.md` §16.5.1 asserts a residue window that cannot be closed while the volume is mounted,
because macOS logs our own unlinks and flushes on its own schedule. That is reasoning, not
measurement.

```bash
# scratch exFAT/FAT32 stick on macOS
zcat /Volumes/SCRATCH/.fseventsd/* | strings | grep -c mytestfile   # before
sanitize /Volumes/SCRATCH/mytestfile
zcat /Volumes/SCRATCH/.fseventsd/* | strings | grep -c mytestfile   # after
# then: diskutil unmount, remount, check again — did records land post-scrub?
```

The number that matters is how long after the run new records keep appearing. If it is zero,
§16.5.1's warning is a footnote. If records keep arriving for seconds, it is the headline, and
volume residue scrubbing on a mounted volume is close to pointless — which would strengthen the
case for handing this to `blktamper` entirely.

## 6. AppleDouble sidecars as macOS actually writes them

`tests/residue.rs` synthesises `._foo.7z` by writing a file with that name. Real ones are written
by macOS with AppleDouble structure and a real `com.apple.quarantine` value.

```bash
# on macOS, with a FAT/exFAT scratch volume
curl -o /Volumes/SCRATCH/thing.7z https://example.com/thing.7z   # sets quarantine
ls -la /Volumes/SCRATCH/._thing.7z
xattr -l /Volumes/SCRATCH/thing.7z
sanitize /Volumes/SCRATCH/thing.7z
ls -la /Volumes/SCRATCH/         # sidecar must be gone
```

Also worth measuring: whether macOS recreates the sidecar after we remove it while the volume is
still mounted, which would be the same class of race as §16.5.1.

## 7. Create-time scrubbing on macOS

`--scrub-times` reaches `atime` and `mtime` only. Create time is unsettable from POSIX, but macOS
has `setattrlist(ATTR_CMN_CRTIME)`. Confirm with `GetFileInfo` or `mdls` that a FAT create time
can actually be set that way before implementing it — and confirm what Linux leaves behind, since
there it is simply unreachable.

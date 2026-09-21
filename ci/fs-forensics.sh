#!/usr/bin/env bash
# Loopback forensic test — DESIGN §11, TODO P1.5, SHORTCOMINGS §4.
#
# Creates a scratch filesystem image, writes a file with a known canary string,
# destroys it with sanitize, unmounts, then reads the *raw image* to see what
# actually survived. This is the only way to check a claim about the media
# rather than a claim about the page cache.
#
#   ./ci/fs-forensics.sh exfat     # loop + exfat-fuse; works without kernel exFAT
#   ./ci/fs-forensics.sh vfat      # needs a kernel with vfat (not Claude Cloud)
#   ./ci/fs-forensics.sh ext4      # expected to FAIL the filename check, by design
#
# Safety: every path this touches is created by this script under its own
# mktemp directory and removed on exit, including on failure. It never mounts,
# formats or deletes anything that existed beforehand. See CLAUDE.md §1.

set -euo pipefail

FSTYPE="${1:-exfat}"
SIZE_MB="${SIZE_MB:-64}"
CANARY='CANARY-a7f3e9d1-DO-NOT-RECOVER-ME'
SECRET_NAME='secret_payload.7z'

BIN="${SANITIZE_BIN:-$(dirname "$0")/../target/release/sanitize}"
if [ ! -x "$BIN" ]; then
    echo "error: sanitize binary not found at $BIN (cargo build --release first)" >&2
    exit 2
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="$(mktemp -d)"
IMG="$WORK/fs.img"
MNT="$WORK/mnt"
LOOP=""

cleanup() {
    set +e
    mountpoint -q "$MNT" 2>/dev/null && umount "$MNT"
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$MNT"
dd if=/dev/zero of="$IMG" bs=1M count="$SIZE_MB" status=none

echo "== $FSTYPE: create and mount a ${SIZE_MB} MiB scratch image =="
case "$FSTYPE" in
    exfat)
        mkfs.exfat "$IMG" >/dev/null 2>&1
        # exfat-fuse needs a block device, not a plain file.
        LOOP="$(losetup -f --show "$IMG")"
        mount.exfat-fuse "$LOOP" "$MNT"
        ;;
    vfat)
        mkfs.vfat -F 32 "$IMG" >/dev/null 2>&1
        mount -o loop -t vfat "$IMG" "$MNT"
        ;;
    ext4)
        mkfs.ext4 -q "$IMG"
        mount -o loop "$IMG" "$MNT"
        ;;
    *)
        echo "error: unsupported filesystem '$FSTYPE'" >&2
        exit 2
        ;;
esac
mountpoint -q "$MNT" || { echo "error: mount failed" >&2; exit 1; }

echo "== write the canary, plus an AppleDouble sidecar naming it =="
printf '%s\n' "$CANARY" > "$MNT/$SECRET_NAME"
printf 'https://example.invalid/%s\n' "$SECRET_NAME" > "$MNT/._$SECRET_NAME"
sync

echo "== sanitize =="
"$BIN" "$MNT/$SECRET_NAME"

# Check the two files we created, not directory emptiness: ext4 ships a
# lost+found that has nothing to do with us.
for leftover in "$SECRET_NAME" "._$SECRET_NAME"; do
    if [ -e "$MNT/$leftover" ]; then
        echo "FAIL: '$leftover' survived in the filesystem" >&2
        ls -A "$MNT" >&2
        exit 1
    fi
done
echo "   both the file and its sidecar are gone from the filesystem"

sync
umount "$MNT"
[ -n "$LOOP" ] && { losetup -d "$LOOP"; LOOP=""; }

echo "== read the RAW IMAGE — this is the part that is not a page-cache claim =="
python3 - "$IMG" "$CANARY" "$SECRET_NAME" "$FSTYPE" <<'PY'
import sys

img, canary, name, fstype = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(img, 'rb') as f:
    blob = f.read()

canary_hits = blob.count(canary.encode())
# Long filenames are UTF-16LE on FAT/exFAT and plain bytes on ext4; count both.
name_hits = blob.count(name.encode()) + blob.count(name.encode('utf-16-le'))

print(f"   canary occurrences in raw image : {canary_hits}")
print(f"   original filename occurrences   : {name_hits}")

failed = False

# The data guarantee. If the canary survives, the overwrite did not reach the
# image at all and everything else is moot.
if canary_hits:
    print(f"FAIL: the canary survived {canary_hits} time(s) — the overwrite did "
          f"not reach the media", file=sys.stderr)
    failed = True
else:
    print("   PASS: no trace of the file's contents in the raw image")

# The name is reported, never asserted. DESIGN §5.3 is explicit that renaming
# does not overwrite the old directory entry, and on ext4 it demonstrably does
# not. Printing what happened is the point; failing here would be claiming a
# guarantee the design does not make.
if name_hits:
    print(f"   NOTE: the original filename survives in the raw image "
          f"({fstype}). DESIGN §5.3 predicts exactly this — the rename ladder "
          f"is best effort against directory-entry slack, not a guarantee.")
else:
    print(f"   NOTE: no trace of the original filename on {fstype}.")

sys.exit(1 if failed else 0)
PY

echo "== $FSTYPE: OK =="

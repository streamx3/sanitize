//! Metadata scrubbing: timestamps and the sidecar/cache files that name their
//! neighbours. §9.4, §16.5.
//!
//! Everything here is FAT/exFAT-first, because that is where it matters most:
//!
//!   * macOS has no native xattrs on FAT, so `com.apple.quarantine` — the
//!     download URL, timestamp and downloading app — lives in an AppleDouble
//!     sidecar named `._<principal>`. That filename *contains the principal's
//!     name*, which undoes the entire §5.2 rename ladder.
//!   * `.DS_Store` is a buddy-allocated B-tree that never compacts, so it keeps
//!     records for files that were deleted long ago.
//!   * `Thumbs.db` holds rendered thumbnails: content, not just names.

use crate::wipe::RandomSource;
use rand::Rng;
use rustix::fd::BorrowedFd;
use rustix::fs::AtFlags;
use std::ffi::{CStr, CString};

/// 1980-01-01T00:00:00Z. FAT cannot represent anything earlier, so the Unix
/// epoch is not merely a bad choice of scrub value — it is unrepresentable,
/// and the driver clamping it is itself a signature. §16.5.
pub const FAT_EPOCH: i64 = 315_532_800;

/// Directory-level caches that record the names (and sometimes the contents)
/// of their neighbours. Destroyed in any directory we touch. §16.5.
pub const CACHE_FILES: &[&str] = &[".DS_Store", "Thumbs.db", "ehthumbs.db", "desktop.ini"];

/// Longest name any filesystem we target accepts.
const MAX_NAME: usize = 255;

/// Is this name itself an AppleDouble sidecar?
pub fn is_sidecar(name: &[u8]) -> bool {
    name.starts_with(b"._")
}

/// The AppleDouble sidecar name for `name`.
///
/// `None` when `name` is already a sidecar (we do not want `.__.foo`), or when
/// the result would exceed the filesystem's name limit, in which case no such
/// sidecar can exist to begin with.
pub fn sidecar_of(name: &[u8]) -> Option<CString> {
    if is_sidecar(name) || name.is_empty() || name == b"." || name == b".." {
        return None;
    }
    if name.len().saturating_add(2) > MAX_NAME {
        return None;
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    out.extend_from_slice(b"._");
    out.extend_from_slice(name);
    CString::new(out).ok()
}

/// A timestamp that reveals nothing and does not look like a tool marker.
///
/// Uniform in `[1980-01-01, now]`. Not a constant: a tree where every entry
/// carries the same instant is as distinctive as one carrying the truth. Not
/// the Unix epoch, for the reason in `FAT_EPOCH`.
pub fn plausible_time(rng: &mut RandomSource) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(FAT_EPOCH);
    if now <= FAT_EPOCH {
        return FAT_EPOCH;
    }
    let span = now.saturating_sub(FAT_EPOCH).max(1) as u64;
    FAT_EPOCH.saturating_add((rng.next_u64() % span) as i64)
}

/// Overwrite `atime`/`mtime` on one entry, without following symlinks.
///
/// Must run **after** any truncation: `ftruncate` updates `mtime`, so scrubbing
/// first would put the real time straight back into the directory entry.
/// §16.5.
///
/// `ctime` cannot be set from POSIX, and create time cannot be set on Linux at
/// all — but FAT has no `ctime` field, so on the priority filesystems the only
/// unreachable field is the create time. `SHORTCOMINGS.md` §2.1 records that.
pub fn scrub_times(
    dirfd: BorrowedFd<'_>,
    name: &CStr,
    rng: &mut RandomSource,
) -> Result<(), rustix::io::Errno> {
    let t = plausible_time(rng);
    let ts = rustix::fs::Timestamps {
        last_access: rustix::fs::Timespec {
            tv_sec: t,
            tv_nsec: 0,
        },
        last_modification: rustix::fs::Timespec {
            tv_sec: t,
            tv_nsec: 0,
        },
    };
    rustix::fs::utimensat(dirfd, name, &ts, AtFlags::SYMLINK_NOFOLLOW)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn rng() -> RandomSource {
        RandomSource::new(None).unwrap()
    }

    #[test]
    fn sidecar_names_prefix_the_principal() {
        assert_eq!(sidecar_of(b"foo.7z").unwrap().to_bytes(), b"._foo.7z");
        assert_eq!(sidecar_of(b"a").unwrap().to_bytes(), b"._a");
    }

    #[test]
    fn sidecars_do_not_nest_or_overflow() {
        assert!(sidecar_of(b"._foo").is_none(), "already a sidecar");
        assert!(sidecar_of(b"").is_none());
        assert!(sidecar_of(b".").is_none());
        assert!(sidecar_of(b"..").is_none());
        let long = vec![b'x'; MAX_NAME];
        assert!(
            sidecar_of(&long).is_none(),
            "no room for the prefix, so no such sidecar can exist"
        );
        let fits = vec![b'x'; MAX_NAME - 2];
        assert!(sidecar_of(&fits).is_some());
    }

    #[test]
    fn is_sidecar_matches_the_appledouble_prefix() {
        assert!(is_sidecar(b"._foo"));
        assert!(!is_sidecar(b".foo"));
        assert!(!is_sidecar(b"foo"));
        assert!(!is_sidecar(b"_foo"));
    }

    #[test]
    fn scrub_times_never_predate_the_fat_epoch() {
        // FAT cannot store anything earlier; a clamped value is a signature.
        let mut r = rng();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(FAT_EPOCH);
        for _ in 0..2000 {
            let t = plausible_time(&mut r);
            assert!(t >= FAT_EPOCH, "{t} predates 1980-01-01");
            assert!(t <= now, "{t} is in the future");
        }
    }

    #[test]
    fn scrub_times_are_not_all_the_same_instant() {
        // A tree where every entry carries one instant is as distinctive as
        // one carrying the truth.
        let mut r = rng();
        let first = plausible_time(&mut r);
        assert!(
            (0..100).any(|_| plausible_time(&mut r) != first),
            "timestamps are constant"
        );
    }
}

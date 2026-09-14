//! Portable random name generation and the rename ladder. §5.1, §5.2, §15.2.
//!
//! The charset is the intersection of what APFS, HFS+, NTFS, exFAT, FAT32 and
//! ext3/4 all accept, with two extra constraints that bite in practice:
//!
//!   * case-insensitive volumes (APFS, HFS+, NTFS, exFAT, FAT32) mean mixed-case
//!     names collide, so we use one case only;
//!   * HFS+ normalises Unicode, so we stay strictly ASCII.
//!
//! `wipe` gets this wrong: its charset includes `-` and `.` at every position and
//! mixes case (wipe.c:520), so it can emit leading dashes, leading/trailing dots,
//! and reserved DOS device names — all hazards on removable media (§14.1).

use rand::Rng;

const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Names Windows refuses regardless of extension.
const RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
    "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Longest name we will ever generate. 255 is the limit on every target
/// filesystem (bytes on ext4, UTF-16 units elsewhere — identical for ASCII).
pub const MAX_LEN: usize = 255;

/// Draw a uniform byte from `set` without modulo bias.
fn pick(rng: &mut dyn Rng, set: &[u8]) -> u8 {
    let n = set.len() as u32;
    if n == 0 {
        return b'x';
    }
    // Rejection-sample to the largest multiple of n that fits in u32.
    let limit = u32::MAX - (u32::MAX % n) - 1;
    loop {
        let v = rng.next_u32();
        if v <= limit {
            let idx = (v % n) as usize;
            return set.get(idx).copied().unwrap_or(b'x');
        }
    }
}

/// Generate one portable name of exactly `len` bytes.
///
/// Guarantees, all covered by tests: ASCII lowercase alphanumeric only, first
/// character is a letter, never a reserved DOS device name, no leading `-` or
/// `.`, no trailing `.` or space, length in `1..=MAX_LEN`.
pub fn generate(len: usize, rng: &mut dyn Rng) -> Vec<u8> {
    let len = len.clamp(1, MAX_LEN);
    loop {
        let mut out = Vec::with_capacity(len);
        out.push(pick(rng, ALPHA));
        for _ in 1..len {
            out.push(pick(rng, ALNUM));
        }
        if !is_reserved(&out) {
            return out;
        }
        // Reserved names are 3-4 chars; regenerating terminates with
        // overwhelming probability on the very next draw.
    }
}

fn is_reserved(name: &[u8]) -> bool {
    if name.len() > 5 {
        return false;
    }
    match core::str::from_utf8(name) {
        Ok(s) => RESERVED.contains(&s),
        Err(_) => false,
    }
}

/// The sequence of name lengths to rename through, in order. §5.2, §15.6.
///
/// Same-length renames first: on FAT/exFAT a same-length rename rewrites the
/// existing long-filename entry chain in place, which is the only step with a
/// real chance of overwriting the old name rather than orphaning it. Then we
/// descend so the *length* of the original name stops leaking too — which is
/// what `wipe` never does (it holds length constant forever, wipe.c:552).
///
/// Capped so a 255-character name does not cost 255 renames plus 255 directory
/// fsyncs.
pub fn ladder(original_len: usize, same_length_rounds: usize, max_steps: usize) -> Vec<usize> {
    let orig = original_len.clamp(1, MAX_LEN);
    let mut steps = Vec::new();

    for _ in 0..same_length_rounds.max(1) {
        steps.push(orig);
    }

    let budget = max_steps.saturating_sub(steps.len());
    if budget > 0 && orig > 1 {
        let descent_from = orig.saturating_sub(1).min(12);
        if descent_from > 0 {
            let mut n = descent_from;
            while n >= 1 && steps.len() < max_steps {
                steps.push(n);
                if n == 1 {
                    break;
                }
                n -= 1;
            }
        }
    }
    steps.truncate(max_steps.max(1));
    steps
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([7u8; 32])
    }

    /// The invariants that make a name safe on all six target filesystems.
    fn assert_portable(name: &[u8]) {
        assert!(!name.is_empty(), "empty name");
        assert!(name.len() <= MAX_LEN, "too long: {}", name.len());
        for &b in name {
            assert!(
                b.is_ascii_lowercase() || b.is_ascii_digit(),
                "non-portable byte {b:?} in {:?}",
                String::from_utf8_lossy(name)
            );
        }
        let first = name.first().copied().unwrap_or(b'0');
        assert!(first.is_ascii_lowercase(), "must start with a letter");
        let last = name.last().copied().unwrap_or(b'0');
        assert_ne!(last, b'.', "no trailing dot");
        assert_ne!(last, b' ', "no trailing space");
        assert!(!is_reserved(name), "reserved DOS name");
    }

    #[test]
    fn generated_names_are_portable_at_every_length() {
        let mut r = rng();
        for len in 1..=64 {
            for _ in 0..200 {
                assert_portable(&generate(len, &mut r));
            }
        }
    }

    #[test]
    fn length_is_exact_and_clamped() {
        let mut r = rng();
        for len in 1..=40 {
            assert_eq!(generate(len, &mut r).len(), len);
        }
        assert_eq!(generate(0, &mut r).len(), 1);
        assert_eq!(generate(usize::MAX, &mut r).len(), MAX_LEN);
    }

    #[test]
    fn never_emits_reserved_dos_names() {
        let mut r = rng();
        for _ in 0..20_000 {
            for len in [3usize, 4] {
                let n = generate(len, &mut r);
                assert!(!is_reserved(&n), "{:?}", String::from_utf8_lossy(&n));
            }
        }
    }

    #[test]
    fn case_insensitive_volumes_see_distinct_names() {
        // Two names differing only by case would collide on FAT/exFAT/NTFS/APFS.
        // Single-case output makes that structurally impossible.
        let mut r = rng();
        for _ in 0..1000 {
            let n = generate(16, &mut r);
            let folded = n.to_ascii_lowercase();
            assert_eq!(n, folded);
        }
    }

    #[test]
    fn ladder_starts_at_original_length_then_descends() {
        let l = ladder(20, 2, 16);
        assert_eq!(l.first().copied(), Some(20));
        assert_eq!(l.get(1).copied(), Some(20));
        assert_eq!(l.get(2).copied(), Some(12));
        assert!(l.windows(2).skip(2).all(|w| w[0] > w[1]), "must descend");
        assert_eq!(l.last().copied(), Some(1));
    }

    #[test]
    fn ladder_is_bounded_for_pathological_names() {
        assert!(ladder(255, 2, 16).len() <= 16);
        assert!(!ladder(1, 1, 16).is_empty());
        assert!(!ladder(1, 0, 0).is_empty(), "always at least one step");
    }

    #[test]
    fn ladder_never_yields_zero_length() {
        for orig in 1..=255 {
            for step in ladder(orig, 2, 16) {
                assert!(step >= 1, "zero-length name requested");
            }
        }
    }
}

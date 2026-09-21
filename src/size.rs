//! Size suffix parsing. §4.2.
//!
//! Deliberately GNU-compatible, because coreutils already got this right:
//!   K/M/G/T/P  = 1024^n     (the traditional meaning)
//!   KB/MB/GB   = 1000^n
//!   KiB/MiB    = 1024^n     (explicit, for people who like it spelled out)
//!   bare       = bytes
//!   N%         = fraction of the file's size

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SizeSpec {
    Bytes(u64),
    Percent(u32),
}

impl SizeSpec {
    /// Resolve against a concrete file size. Never panics, never overflows.
    pub fn resolve(self, file_size: u64) -> u64 {
        match self {
            SizeSpec::Bytes(b) => b,
            SizeSpec::Percent(p) => {
                let p = u64::from(p.min(100));
                file_size / 100 * p + (file_size % 100) * p / 100
            }
        }
    }
}

pub fn parse(s: &str) -> Result<SizeSpec, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty size".into());
    }

    if let Some(num) = t.strip_suffix('%') {
        let v: u32 = num
            .trim()
            .parse()
            .map_err(|_| format!("invalid percentage: {s}"))?;
        if v > 100 {
            return Err(format!("percentage above 100: {s}"));
        }
        return Ok(SizeSpec::Percent(v));
    }

    let digits_end = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (num, suffix) = t.split_at(digits_end);
    if num.is_empty() {
        return Err(format!("size must start with a digit: {s}"));
    }
    let base: u64 = num.parse().map_err(|_| format!("size too large: {s}"))?;

    let mult =
        multiplier(suffix).ok_or_else(|| format!("unknown size suffix {suffix:?} in {s}"))?;

    base.checked_mul(mult)
        .map(SizeSpec::Bytes)
        .ok_or_else(|| format!("size overflows 64 bits: {s}"))
}

fn multiplier(suffix: &str) -> Option<u64> {
    let s = suffix.trim();
    if s.is_empty() {
        return Some(1);
    }
    let lower = s.to_ascii_lowercase();
    // (exponent, is_decimal)
    let (letter, rest) = lower.split_at(1);
    let exp: u32 = match letter {
        "b" if rest.is_empty() => return Some(1),
        "k" => 1,
        "m" => 2,
        "g" => 3,
        "t" => 4,
        "p" => 5,
        "e" => 6,
        _ => return None,
    };
    let radix: u64 = match rest {
        "" | "ib" | "i" => 1024,
        "b" => 1000,
        _ => return None,
    };
    radix.checked_pow(exp)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn traditional_suffixes_are_1024_based() {
        assert_eq!(parse("1K").unwrap(), SizeSpec::Bytes(1024));
        assert_eq!(parse("1M").unwrap(), SizeSpec::Bytes(1024 * 1024));
        assert_eq!(parse("1G").unwrap(), SizeSpec::Bytes(1024 * 1024 * 1024));
        assert_eq!(parse("2T").unwrap(), SizeSpec::Bytes(2 * 1024u64.pow(4)));
    }

    #[test]
    fn si_suffixes_are_1000_based() {
        assert_eq!(parse("1KB").unwrap(), SizeSpec::Bytes(1000));
        assert_eq!(parse("1MB").unwrap(), SizeSpec::Bytes(1_000_000));
        assert_eq!(parse("1GB").unwrap(), SizeSpec::Bytes(1_000_000_000));
    }

    #[test]
    fn iec_suffixes_are_1024_based() {
        assert_eq!(parse("1KiB").unwrap(), SizeSpec::Bytes(1024));
        assert_eq!(parse("1MiB").unwrap(), SizeSpec::Bytes(1024 * 1024));
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(parse("1k").unwrap(), parse("1K").unwrap());
        assert_eq!(parse("1gib").unwrap(), parse("1GiB").unwrap());
    }

    #[test]
    fn bare_numbers_are_bytes() {
        assert_eq!(parse("4096").unwrap(), SizeSpec::Bytes(4096));
        assert_eq!(parse("0").unwrap(), SizeSpec::Bytes(0));
        assert_eq!(parse("512b").unwrap(), SizeSpec::Bytes(512));
    }

    #[test]
    fn percentages() {
        assert_eq!(parse("5%").unwrap(), SizeSpec::Percent(5));
        assert_eq!(SizeSpec::Percent(50).resolve(1000), 500);
        // The split-then-recombine form must be exact at the top of the range,
        // not merely close: 100% of anything is that thing.
        assert_eq!(SizeSpec::Percent(100).resolve(u64::MAX), u64::MAX);
        assert_eq!(SizeSpec::Percent(0).resolve(u64::MAX), 0);
        assert!(parse("101%").is_err());
    }

    #[test]
    fn rejects_garbage_without_panicking() {
        for bad in [
            "",
            "K",
            "1X",
            "1KBB",
            "-5",
            "abc",
            "1 2",
            "99999999999999999999999",
        ] {
            assert!(parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn overflow_is_an_error_not_a_wrap() {
        assert!(parse("18446744073709551615E").is_err());
    }
}

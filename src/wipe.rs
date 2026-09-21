//! The overwrite engine. §6.
//!
//! Every pass is CSPRNG output. We do not reproduce shred's Gutmann-derived
//! pattern schedule: it targeted MFM/RLL encoding that no drive built since
//! ~1995 uses, and random is the only choice compatible with the entropy-edge
//! use case in §2.

use crate::cli::Config;
use crate::interrupt;
use crate::report::Guarantee;
use crate::sysx;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::rand_core::TryRng;
use std::convert::Infallible;
use std::io::{self, Read};
use std::os::fd::BorrowedFd;

const BUF_SIZE: usize = 1 << 20; // 1 MiB

/// Random bytes for overwrite patterns and for name generation.
///
/// Always backed by ChaCha20 seeded from the OS; `--random-source` layers a
/// file on top and silently falls back to the CSPRNG if the file runs dry,
/// so a short random file can never abort a run (§16.1).
pub struct RandomSource {
    csprng: ChaCha20Rng,
    file: Option<std::fs::File>,
}

impl RandomSource {
    pub fn new(path: Option<&str>) -> io::Result<Self> {
        let mut seed = [0u8; 32];
        let mut dev = std::fs::File::open("/dev/urandom")?;
        dev.read_exact(&mut seed)?;
        let file = match path {
            Some(p) => Some(std::fs::File::open(p)?),
            None => None,
        };
        Ok(Self {
            csprng: ChaCha20Rng::from_seed(seed),
            file,
        })
    }

    fn fill(&mut self, buf: &mut [u8]) {
        if let Some(f) = self.file.as_mut() {
            match f.read_exact(buf) {
                Ok(()) => return,
                Err(_) => {
                    // Exhausted or unreadable: fall through to the CSPRNG
                    // rather than failing the run.
                    self.file = None;
                }
            }
        }
        self.csprng.fill_bytes(buf);
    }
}

impl TryRng for RandomSource {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.fill(dst);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub offset: u64,
    pub len: u64,
}

fn round_up(v: u64, to: u64) -> u64 {
    if to == 0 {
        return v;
    }
    match v % to {
        0 => v,
        r => v.saturating_add(to - r),
    }
}

/// Work out which byte ranges to overwrite. §4.2, §6.1.
///
/// Note the `-x` semantics inherited from shred: without it we round the end up
/// to a full block so file slack gets covered too. `wipe` has an off-by-one
/// here that grows every already-aligned file by a whole block (§14.7); the
/// `round_up` above returns `v` unchanged when it is already a multiple.
pub fn plan_extents(size: u64, blksize: u64, cfg: &Config) -> Vec<Extent> {
    let blk = if blksize == 0 { 512 } else { blksize };
    let full_end = if cfg.exact { size } else { round_up(size, blk) };

    if !cfg.partial() {
        if full_end == 0 {
            return Vec::new();
        }
        return vec![Extent {
            offset: 0,
            len: full_end,
        }];
    }

    let mut spans: Vec<(u64, u64)> = Vec::new();

    if let Some(h) = cfg.head {
        let want = h.resolve(size).min(size);
        if want > 0 {
            let end = if cfg.exact {
                want
            } else {
                round_up(want, blk).min(full_end)
            };
            spans.push((0, end));
        }
    }
    if let Some(t) = cfg.tail {
        let want = t.resolve(size).min(size);
        if want > 0 {
            let start = size.saturating_sub(want);
            let start = if cfg.exact { start } else { start / blk * blk };
            spans.push((start, full_end));
        }
    }

    spans.sort_unstable();
    let mut merged: Vec<Extent> = Vec::new();
    for (start, end) in spans {
        if end <= start {
            continue;
        }
        match merged.last_mut() {
            Some(prev) if start <= prev.offset.saturating_add(prev.len) => {
                let prev_end = prev.offset.saturating_add(prev.len).max(end);
                prev.len = prev_end.saturating_sub(prev.offset);
            }
            _ => merged.push(Extent {
                offset: start,
                len: end.saturating_sub(start),
            }),
        }
    }
    merged
}

pub struct WipeResult {
    pub bytes_written: u64,
    pub guarantee: Guarantee,
}

/// Overwrite the planned extents. Returns an error only for failures that
/// affect real file data; writes past the original EOF (block-slack rounding)
/// are best-effort and never fail the file.
pub fn wipe_fd(
    fd: BorrowedFd<'_>,
    size: u64,
    blksize: u64,
    cfg: &Config,
    rng: &mut RandomSource,
) -> io::Result<WipeResult> {
    let extents = plan_extents(size, blksize, cfg);
    if extents.is_empty() || cfg.iterations == 0 && !cfg.zero {
        return Ok(WipeResult {
            bytes_written: 0,
            guarantee: Guarantee::Clear,
        });
    }

    sysx::advise_nocache(fd);

    let mut buf = vec![0u8; BUF_SIZE];
    let mut total: u64 = 0;

    let zero_pass = if cfg.zero { 1 } else { 0 };
    for pass in 0..(cfg.iterations + zero_pass) {
        // §16.1 item 5 — between passes is a safe point: the file is either
        // fully overwritten by the previous pass or not started at all.
        if interrupt::requested() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "interrupted between passes",
            ));
        }
        let is_zero_pass = cfg.zero && pass == cfg.iterations;
        if is_zero_pass {
            buf.iter_mut().for_each(|b| *b = 0);
        }

        for ext in &extents {
            let mut written: u64 = 0;
            while written < ext.len {
                // Mid-file, so *not* a safe point: the caller must leave this
                // file in place and say so (§7.5). Checked per chunk rather
                // than per byte — a 1 MiB write is the granularity at which
                // Ctrl-C feels responsive on slow media.
                if interrupt::requested() {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "interrupted part-way through an overwrite",
                    ));
                }
                let remaining = ext.len - written;
                let chunk = remaining.min(BUF_SIZE as u64) as usize;
                let slice = match buf.get_mut(..chunk) {
                    Some(s) => s,
                    None => break,
                };
                if !is_zero_pass {
                    rng.fill_bytes(slice);
                }
                let offset = ext.offset.saturating_add(written);
                match pwrite_all(fd, slice, offset) {
                    Ok(n) => {
                        total = total.saturating_add(n);
                        written = written.saturating_add(n);
                    }
                    Err(e) => {
                        // Past the original EOF this is slack-wiping, which is
                        // a bonus, not a requirement. Below EOF it is real.
                        if offset >= size {
                            break;
                        }
                        return Err(e);
                    }
                }
            }
        }

        // Without this the page cache coalesces the passes and only the last
        // one reaches the media, making -n > 1 literally meaningless. §6.1
        sysx::full_sync(fd)?;
    }

    Ok(WipeResult {
        bytes_written: total,
        guarantee: Guarantee::Unverifiable,
    })
}

/// Write the whole buffer at `offset`, looping over short writes and retrying
/// EINTR/EAGAIN. §16.1 item 3.
fn pwrite_all(fd: BorrowedFd<'_>, buf: &[u8], offset: u64) -> io::Result<u64> {
    let mut done: usize = 0;
    while done < buf.len() {
        let slice = match buf.get(done..) {
            Some(s) => s,
            None => break,
        };
        match rustix::io::pwrite(fd, slice, offset.saturating_add(done as u64)) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "device accepted zero bytes",
                ));
            }
            Ok(n) => done = done.saturating_add(n),
            Err(e) if e == rustix::io::Errno::INTR || e == rustix::io::Errno::AGAIN => continue,
            Err(e) => return Err(io::Error::from_raw_os_error(e.raw_os_error())),
        }
    }
    Ok(done as u64)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cli::Config;

    fn cfg(args: &[&str]) -> Config {
        Config::from_args(args).unwrap()
    }

    #[test]
    fn whole_file_by_default_rounded_to_block() {
        let c = cfg(&["sanitize", "x"]);
        let e = plan_extents(5000, 4096, &c);
        assert_eq!(
            e,
            vec![Extent {
                offset: 0,
                len: 8192
            }]
        );
    }

    #[test]
    fn aligned_sizes_are_not_grown_by_a_whole_block() {
        // This is the wipe.c:892 bug, explicitly tested against.
        let c = cfg(&["sanitize", "x"]);
        let e = plan_extents(8192, 4096, &c);
        assert_eq!(
            e,
            vec![Extent {
                offset: 0,
                len: 8192
            }],
            "must not add a block"
        );
    }

    #[test]
    fn exact_disables_rounding() {
        let c = cfg(&["sanitize", "-x", "x"]);
        assert_eq!(
            plan_extents(5000, 4096, &c),
            vec![Extent {
                offset: 0,
                len: 5000
            }]
        );
    }

    #[test]
    fn head_limits_to_the_front() {
        let c = cfg(&["sanitize", "-x", "--head", "1K", "x"]);
        assert_eq!(
            plan_extents(1 << 20, 4096, &c),
            vec![Extent {
                offset: 0,
                len: 1024
            }]
        );
    }

    #[test]
    fn head_is_clamped_to_file_size() {
        let c = cfg(&["sanitize", "-x", "--head", "1G", "x"]);
        assert_eq!(
            plan_extents(100, 4096, &c),
            vec![Extent {
                offset: 0,
                len: 100
            }]
        );
    }

    #[test]
    fn tail_covers_the_backup_header_region() {
        // §2.6 — the VeraCrypt backup header lives in the last 128 KiB.
        let c = cfg(&["sanitize", "-x", "--tail", "128K", "x"]);
        let size = 10 * 1024 * 1024;
        let e = plan_extents(size, 4096, &c);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].offset, size - 128 * 1024);
        assert_eq!(e[0].offset + e[0].len, size);
    }

    #[test]
    fn head_and_tail_together_stay_disjoint_on_large_files() {
        let c = cfg(&["sanitize", "-x", "--head", "1M", "--tail", "1M", "x"]);
        let e = plan_extents(100 * 1024 * 1024, 4096, &c);
        assert_eq!(e.len(), 2, "must not merge on a large file");
        assert_eq!(e[0].offset, 0);
        assert!(e[1].offset > e[0].len);
    }

    #[test]
    fn head_and_tail_merge_when_they_overlap() {
        let c = cfg(&["sanitize", "-x", "--head", "1M", "--tail", "1M", "x"]);
        let e = plan_extents(1024 * 1024, 4096, &c);
        assert_eq!(
            e,
            vec![Extent {
                offset: 0,
                len: 1024 * 1024
            }],
            "one span, not two"
        );
    }

    #[test]
    fn empty_files_plan_no_writes() {
        let c = cfg(&["sanitize", "x"]);
        assert!(plan_extents(0, 4096, &c).is_empty());
    }

    #[test]
    fn percent_head_resolves_against_size() {
        let c = cfg(&["sanitize", "-x", "--head", "10%", "x"]);
        assert_eq!(
            plan_extents(1000, 4096, &c),
            vec![Extent {
                offset: 0,
                len: 100
            }]
        );
    }

    #[test]
    fn random_source_falls_back_instead_of_failing() {
        // An empty random file must not abort anything. §16.1
        let dir = std::env::temp_dir().join("sanitize-rs-test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("empty.bin");
        let _ = std::fs::write(&p, b"");
        let mut rs = RandomSource::new(p.to_str()).unwrap();
        let mut buf = [0u8; 64];
        rs.fill_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0), "must produce entropy anyway");
        let _ = std::fs::remove_file(&p);
    }
}

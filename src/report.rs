//! Outcome accounting and output. §3, §16.1.
//!
//! Rule from §3: never print "securely erased". Print what actually happened,
//! using the NIST SP 800-88 vocabulary the tool is named after.

use std::io::Write;

/// What we can honestly claim for one file. §16 table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guarantee {
    /// Data is unreachable through the filesystem. Always true on success.
    Clear,
    /// Previous bytes on the media are gone. Only where §2.4 holds — raw block
    /// devices, or non-CoW filesystems on rotational media. Nothing constructs
    /// this yet: the detection that would justify it is `fsinfo`, scheduled for
    /// v0.2 (§12). Until then we never claim purge, which is the point.
    #[allow(dead_code)]
    Purge,
    /// We wrote, but the filesystem or device may have redirected it.
    Unverifiable,
}

impl Guarantee {
    pub fn as_str(self) -> &'static str {
        match self {
            Guarantee::Clear => "clear",
            Guarantee::Purge => "purge",
            Guarantee::Unverifiable => "unverifiable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Special,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Dir => "dir",
            Kind::Symlink => "symlink",
            Kind::Special => "special",
        }
    }
}

#[derive(Debug, Clone)]
pub enum Outcome {
    /// Overwritten (if applicable), renamed, unlinked.
    Removed { kind: Kind, guarantee: Guarantee },
    /// Overwritten but deliberately kept (`-k`).
    Wiped { guarantee: Guarantee },
    /// Would have acted, but `--dry-run`.
    Planned { kind: Kind },
    /// Intentionally not touched, with the reason.
    Skipped { reason: String },
    /// Tried and failed. Never fatal to the run. §16.1
    Failed { stage: &'static str, error: String },
}

pub struct Report {
    pub removed_files: u64,
    pub removed_dirs: u64,
    pub removed_symlinks: u64,
    pub wiped_only: u64,
    pub planned: u64,
    pub skipped: u64,
    pub failed: u64,
    pub bytes_written: u64,
    /// Worst guarantee observed, so the summary cannot overclaim.
    pub weakest: Option<Guarantee>,
    pub json: bool,
    pub verbose: u8,
    problems: Vec<(String, String)>,
}

impl Report {
    pub fn new(json: bool, verbose: u8) -> Self {
        Self {
            removed_files: 0,
            removed_dirs: 0,
            removed_symlinks: 0,
            wiped_only: 0,
            planned: 0,
            skipped: 0,
            failed: 0,
            bytes_written: 0,
            weakest: None,
            json,
            verbose,
            problems: Vec::new(),
        }
    }

    fn note_guarantee(&mut self, g: Guarantee) {
        // Ordering: Purge is strongest, then Clear, then Unverifiable.
        let rank = |g: Guarantee| match g {
            Guarantee::Purge => 2,
            Guarantee::Clear => 1,
            Guarantee::Unverifiable => 0,
        };
        self.weakest = Some(match self.weakest {
            Some(cur) if rank(cur) <= rank(g) => cur,
            _ => g,
        });
    }

    pub fn record(&mut self, path: &str, outcome: &Outcome) {
        match outcome {
            Outcome::Removed { kind, guarantee } => {
                match kind {
                    Kind::Dir => self.removed_dirs += 1,
                    Kind::Symlink => self.removed_symlinks += 1,
                    _ => self.removed_files += 1,
                }
                self.note_guarantee(*guarantee);
            }
            Outcome::Wiped { guarantee } => {
                self.wiped_only += 1;
                self.note_guarantee(*guarantee);
            }
            Outcome::Planned { .. } => self.planned += 1,
            Outcome::Skipped { reason } => {
                self.skipped += 1;
                if self.verbose > 0 {
                    self.problems
                        .push((path.to_string(), format!("skipped: {reason}")));
                }
            }
            Outcome::Failed { stage, error } => {
                self.failed += 1;
                self.problems
                    .push((path.to_string(), format!("{stage}: {error}")));
            }
        }
        self.emit(path, outcome);
    }

    fn emit(&self, path: &str, outcome: &Outcome) {
        if self.json {
            let (status, detail) = match outcome {
                Outcome::Removed { kind, guarantee } => (
                    "removed",
                    format!(
                        "\"kind\":\"{}\",\"guarantee\":\"{}\"",
                        kind.as_str(),
                        guarantee.as_str()
                    ),
                ),
                Outcome::Wiped { guarantee } => {
                    ("wiped", format!("\"guarantee\":\"{}\"", guarantee.as_str()))
                }
                Outcome::Planned { kind } => ("planned", format!("\"kind\":\"{}\"", kind.as_str())),
                Outcome::Skipped { reason } => {
                    ("skipped", format!("\"reason\":{}", json_str(reason)))
                }
                Outcome::Failed { stage, error } => (
                    "failed",
                    format!("\"stage\":\"{stage}\",\"error\":{}", json_str(error)),
                ),
            };
            let line = format!(
                "{{\"path\":{},\"status\":\"{status}\",{detail}}}",
                json_str(path)
            );
            let _ = writeln!(std::io::stdout(), "{line}");
            return;
        }

        match outcome {
            Outcome::Failed { stage, error } => {
                let _ = writeln!(std::io::stderr(), "sanitize: {path}: {stage}: {error}");
            }
            Outcome::Skipped { reason } if self.verbose > 0 => {
                let _ = writeln!(std::io::stderr(), "sanitize: {path}: skipped ({reason})");
            }
            Outcome::Planned { kind } => {
                let _ = writeln!(std::io::stdout(), "would remove {} {path}", kind.as_str());
            }
            Outcome::Removed { kind, guarantee } if self.verbose > 0 => {
                let _ = writeln!(
                    std::io::stderr(),
                    "sanitize: {path}: removed {} ({})",
                    kind.as_str(),
                    guarantee.as_str()
                );
            }
            Outcome::Wiped { guarantee } if self.verbose > 0 => {
                let _ = writeln!(
                    std::io::stderr(),
                    "sanitize: {path}: wiped ({})",
                    guarantee.as_str()
                );
            }
            _ => {}
        }
    }

    /// True if anything the user asked to destroy is still there. Drives the
    /// exit code: 0 means the job is done, not merely that nothing crashed.
    pub fn incomplete(&self) -> bool {
        self.failed > 0 || self.skipped > 0
    }

    /// Always printed, including after SIGINT. §16.1 item 5.
    pub fn summary(&self, dry_run: bool) {
        if self.json {
            let line = format!(
                "{{\"summary\":true,\"files\":{},\"dirs\":{},\"symlinks\":{},\"wiped_only\":{},\"planned\":{},\"skipped\":{},\"failed\":{},\"bytes_written\":{},\"guarantee\":\"{}\"}}",
                self.removed_files,
                self.removed_dirs,
                self.removed_symlinks,
                self.wiped_only,
                self.planned,
                self.skipped,
                self.failed,
                self.bytes_written,
                self.weakest.map(Guarantee::as_str).unwrap_or("none")
            );
            let _ = writeln!(std::io::stdout(), "{line}");
            return;
        }

        let mut err = std::io::stderr();
        if !self.problems.is_empty() && self.verbose == 0 {
            let _ = writeln!(err);
        }

        if dry_run {
            let _ = writeln!(
                err,
                "sanitize: dry run — {} item(s) would be removed, {} skipped, {} unreadable",
                self.planned, self.skipped, self.failed
            );
            return;
        }

        if self.wiped_only > 0 {
            let _ = writeln!(
                err,
                "sanitize: {} file(s) overwritten and kept (-k); {} skipped; {} failed",
                self.wiped_only, self.skipped, self.failed
            );
        } else {
            let _ = writeln!(
                err,
                "sanitize: {} file(s), {} dir(s), {} symlink(s) removed; {} skipped; {} failed",
                self.removed_files,
                self.removed_dirs,
                self.removed_symlinks,
                self.skipped,
                self.failed
            );
        }

        // The honesty clause. §3: never claim more than was achieved.
        match self.weakest {
            Some(Guarantee::Purge) => {
                let _ = writeln!(
                    err,
                    "sanitize: sanitization level: purge (overwrite reached the media)"
                );
            }
            Some(Guarantee::Clear) => {
                let _ = writeln!(
                    err,
                    "sanitize: sanitization level: clear (logical erasure; no physical overwrite claimed)"
                );
            }
            Some(Guarantee::Unverifiable) => {
                let _ = writeln!(
                    err,
                    "sanitize: sanitization level: clear (overwrite UNVERIFIABLE on this filesystem/device)"
                );
            }
            None => {}
        }
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn weakest_guarantee_wins() {
        let mut r = Report::new(true, 0);
        r.note_guarantee(Guarantee::Purge);
        assert_eq!(r.weakest, Some(Guarantee::Purge));
        r.note_guarantee(Guarantee::Clear);
        assert_eq!(
            r.weakest,
            Some(Guarantee::Clear),
            "must degrade, never upgrade"
        );
        r.note_guarantee(Guarantee::Purge);
        assert_eq!(
            r.weakest,
            Some(Guarantee::Clear),
            "must not be upgraded back"
        );
        r.note_guarantee(Guarantee::Unverifiable);
        assert_eq!(r.weakest, Some(Guarantee::Unverifiable));
    }

    #[test]
    fn json_escaping_survives_hostile_filenames() {
        assert_eq!(json_str("a\"b"), "\"a\\\"b\"");
        assert_eq!(json_str("a\\b"), "\"a\\\\b\"");
        assert_eq!(json_str("a\nb"), "\"a\\nb\"");
        assert_eq!(json_str("a\u{1}b"), "\"a\\u0001b\"");
    }
}

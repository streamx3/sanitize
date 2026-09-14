//! Command line surface. §4.
//!
//! All of `shred`'s options are accepted with their `shred` meanings, except
//! `-u` which is our default. Two deliberate divergences, both documented in
//! §4.1: `-n` defaults to 1 rather than 3, and deletion is the default.

use crate::size::{self, SizeSpec};
use clap::{ArgAction, Parser, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RemoveMode {
    /// Plain unlink, no name obfuscation.
    Unlink,
    /// Rename before unlinking.
    Wipe,
    /// Rename before unlinking, fsync the directory between steps.
    Wipesync,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HardLinkMode {
    /// Refuse: the data is reachable under another name. Default.
    Skip,
    /// Warn but proceed.
    Warn,
    /// Proceed silently (this is what `shred` does).
    Shred,
}

#[derive(Parser, Debug)]
#[command(
    name = "sanitize",
    version,
    about = "Recursive secure deletion that tells you the truth about what it destroyed",
    long_about = None,
    after_help = "\
GUARANTEES (NIST SP 800-88):
  clear         data unreachable through the filesystem — always, on success
  purge         previous bytes on the media are gone — only on non-CoW
                filesystems over rotational media, or raw block devices
  unverifiable  we wrote, but the filesystem or SSD may have redirected it

sanitize never prints \"securely erased\". It prints what actually happened."
)]
pub struct Cli {
    /// Files and directories to destroy.
    #[arg(value_name = "PATH", required = true)]
    pub paths: Vec<String>,

    // ---- shred compatibility -------------------------------------------
    /// Overwrite N times (shred defaults to 3; 1 is sufficient on modern media)
    #[arg(short = 'n', long = "iterations", value_name = "N", default_value_t = 1)]
    pub iterations: u32,

    /// Change permissions to allow writing if necessary
    #[arg(short = 'f', long = "force")]
    pub force_perms: bool,

    /// Overwrite only this many bytes (alias for --head)
    #[arg(short = 's', long = "size", value_name = "N", value_parser = size::parse)]
    pub size: Option<SizeSpec>,

    /// Get random bytes from FILE
    #[arg(long = "random-source", value_name = "FILE")]
    pub random_source: Option<String>,

    /// Show details of operations performed (repeat for more)
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub verbose: u8,

    /// Do not round file sizes up to the next full block
    #[arg(short = 'x', long = "exact")]
    pub exact: bool,

    /// Add a final overwrite with zeros to hide shredding
    #[arg(short = 'z', long = "zero")]
    pub zero: bool,

    /// Accepted for shred compatibility; removal is already the default
    #[arg(short = 'u', hide = true)]
    pub compat_u: bool,

    /// How to remove the directory entry
    #[arg(long = "remove", value_name = "HOW", value_enum, default_value = "wipesync")]
    pub remove: RemoveMode,

    // ---- deletion ------------------------------------------------------
    /// Overwrite but do not delete (this is shred's default behaviour)
    #[arg(short = 'k', long = "keep")]
    pub keep: bool,

    /// Error on directories instead of recursing (recursion is the default)
    #[arg(long = "no-recursive")]
    pub no_recursive: bool,

    /// Accepted for rm/shred muscle memory; recursion is already the default
    #[arg(short = 'r', short_alias = 'R', long = "recursive", hide = true)]
    pub compat_r: bool,

    // ---- extent selection ----------------------------------------------
    /// Overwrite only the first SIZE bytes
    #[arg(long = "head", value_name = "SIZE", value_parser = size::parse)]
    pub head: Option<SizeSpec>,

    /// Overwrite only the last SIZE bytes (catches VeraCrypt/GPT backup headers)
    #[arg(long = "tail", value_name = "SIZE", value_parser = size::parse)]
    pub tail: Option<SizeSpec>,

    // ---- safety --------------------------------------------------------
    /// Show what would be destroyed and exit without touching anything
    #[arg(long = "dry-run", short = 'N')]
    pub dry_run: bool,

    /// Remove every guard: permits /, follows symlinks and destroys their
    /// targets, crosses mount points. Required to name / or your home
    /// directory. Full effect requires root.
    #[arg(short = 'F', long = "force-everything")]
    pub force_everything: bool,

    /// Cross mount points (implied by -F)
    #[arg(long = "no-one-file-system")]
    pub no_one_file_system: bool,

    /// What to do about files with more than one hard link
    #[arg(long = "hard-links", value_name = "MODE", value_enum, default_value = "skip")]
    pub hard_links: HardLinkMode,

    // ---- reporting -----------------------------------------------------
    /// Emit one JSON object per path plus a summary
    #[arg(long = "json")]
    pub json: bool,
}

/// Resolved, validated configuration. Built once; never mutated during a run.
#[derive(Debug, Clone)]
pub struct Config {
    pub iterations: u32,
    pub force_perms: bool,
    pub random_source: Option<String>,
    pub verbose: u8,
    pub exact: bool,
    pub zero: bool,
    pub remove: RemoveMode,
    pub keep: bool,
    pub recursive: bool,
    pub head: Option<SizeSpec>,
    pub tail: Option<SizeSpec>,
    pub dry_run: bool,
    pub force_everything: bool,
    pub one_file_system: bool,
    pub follow_symlinks: bool,
    pub hard_links: HardLinkMode,
    pub json: bool,
    pub same_length_rounds: usize,
    pub max_rename_steps: usize,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Result<Self, String> {
        // -s is shred's spelling of --head. If both are given they must agree.
        let head = match (cli.head, cli.size) {
            (Some(h), Some(s)) if h != s => {
                return Err("--head and -s/--size disagree; they are the same option".into());
            }
            (Some(h), _) => Some(h),
            (None, s) => s,
        };

        if cli.zero && head.is_some() {
            // §2.6 — zeros are exactly the entropy edge --head exists to avoid.
            eprintln!(
                "sanitize: warning: -z writes a zero pass over a partial overwrite, creating the \
                 distinguishable boundary that --head is meant to prevent"
            );
        }

        if cli.iterations > 1 {
            // §15.4 — on flash the FTL redirects every pass to fresh pages.
            eprintln!(
                "sanitize: warning: -n {} multiplies wear and time; extra passes land on different \
                 physical pages on any flash device and destroy nothing the first pass missed",
                cli.iterations
            );
        }

        Ok(Config {
            iterations: cli.iterations,
            force_perms: cli.force_perms || cli.force_everything,
            random_source: cli.random_source.clone(),
            verbose: cli.verbose,
            exact: cli.exact,
            zero: cli.zero,
            remove: cli.remove,
            keep: cli.keep,
            recursive: !cli.no_recursive,
            head,
            tail: cli.tail,
            dry_run: cli.dry_run,
            force_everything: cli.force_everything,
            // §16.2: contained by default; -F removes the boundary.
            one_file_system: !cli.no_one_file_system && !cli.force_everything,
            // §16.2/§16.3: never follow by default; -F follows and destroys targets.
            follow_symlinks: cli.force_everything,
            hard_links: cli.hard_links,
            json: cli.json,
            same_length_rounds: 2,
            max_rename_steps: 16,
        })
    }

    pub fn partial(&self) -> bool {
        self.head.is_some() || self.tail.is_some()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Config {
        let cli = Cli::try_parse_from(args).unwrap();
        Config::from_cli(&cli).unwrap()
    }

    #[test]
    fn defaults_match_the_design() {
        let c = parse(&["sanitize", "x"]);
        assert_eq!(c.iterations, 1, "§4.1 divergence from shred");
        assert!(c.recursive, "§16.2 recursive by default");
        assert!(!c.keep, "§16.2 deletes by default");
        assert!(c.one_file_system, "§16.2 contained by default");
        assert!(!c.follow_symlinks, "§16.2 never follow by default");
        assert_eq!(c.hard_links, HardLinkMode::Skip);
        assert_eq!(c.remove, RemoveMode::Wipesync);
    }

    #[test]
    fn force_everything_removes_every_guard() {
        let c = parse(&["sanitize", "-F", "x"]);
        assert!(c.force_everything);
        assert!(c.follow_symlinks, "§16.3 -F follows symlinks");
        assert!(!c.one_file_system, "§16.3 -F crosses mounts");
        assert!(c.force_perms, "§16.3 -F implies -f");
    }

    #[test]
    fn size_is_an_alias_for_head() {
        let c = parse(&["sanitize", "-s", "1K", "x"]);
        assert_eq!(c.head, Some(SizeSpec::Bytes(1024)));
        let c = parse(&["sanitize", "--head", "1M", "x"]);
        assert_eq!(c.head, Some(SizeSpec::Bytes(1024 * 1024)));
    }

    #[test]
    fn contradictory_head_and_size_is_rejected() {
        let cli = Cli::try_parse_from(["sanitize", "-s", "1K", "--head", "2K", "x"]).unwrap();
        assert!(Config::from_cli(&cli).is_err());
    }

    #[test]
    fn shred_compat_flags_parse() {
        let c = parse(&["sanitize", "-u", "-n", "3", "-f", "-v", "-x", "-z", "x"]);
        assert_eq!(c.iterations, 3);
        assert!(c.force_perms && c.exact && c.zero);
        assert_eq!(c.verbose, 1);
    }

    #[test]
    fn paths_are_required() {
        assert!(Cli::try_parse_from(["sanitize"]).is_err());
    }
}

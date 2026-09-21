//! Command line surface. §4.
//!
//! All of `shred`'s options are accepted with their `shred` meanings, except
//! `-u` which is our default. Two deliberate divergences, both documented in
//! §4.1: `-n` defaults to 1 rather than 3, and deletion is the default.

use crate::config_file::ConfigFile;
use crate::size::{self, SizeSpec};
use clap::parser::ValueSource;
use clap::{ArgAction, ArgMatches, Parser, ValueEnum};
#[cfg(test)]
use clap::{CommandFactory, FromArgMatches};

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
    #[arg(
        short = 'n',
        long = "iterations",
        value_name = "N",
        default_value_t = 1
    )]
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
    #[arg(
        long = "remove",
        value_name = "HOW",
        value_enum,
        default_value = "wipesync"
    )]
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
    #[arg(
        long = "hard-links",
        value_name = "MODE",
        value_enum,
        default_value = "skip"
    )]
    pub hard_links: HardLinkMode,

    // ---- metadata and residue (§16.5) ----------------------------------
    /// Keep the real atime/mtime instead of scrubbing them before unlinking
    #[arg(long = "no-scrub-times")]
    pub no_scrub_times: bool,

    /// Scrub atime/mtime (the default; use this to override a config file)
    #[arg(long = "scrub-times", conflicts_with = "no_scrub_times")]
    pub scrub_times: bool,

    /// Do not truncate to zero before unlinking (leaves size and first
    /// cluster recoverable in the directory entry on FAT/exFAT)
    #[arg(long = "no-truncate")]
    pub no_truncate: bool,

    /// Truncate to zero before unlinking (the default; overrides a config file)
    #[arg(long = "truncate", conflicts_with = "no_truncate")]
    pub truncate: bool,

    /// Keep sidecar and cache files: ._* AppleDouble, .DS_Store, Thumbs.db
    #[arg(long = "no-scrub-sidecars")]
    pub no_scrub_sidecars: bool,

    /// Scrub sidecar and cache files (the default; overrides a config file)
    #[arg(long = "scrub-sidecars", conflicts_with = "no_scrub_sidecars")]
    pub scrub_sidecars: bool,

    // ---- configuration (REFERENCE §5) -----------------------------------
    /// Read this file instead of /etc/sanitize/default.conf
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<String>,

    /// Ignore the system configuration file entirely
    #[arg(long = "no-config")]
    pub no_config: bool,

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
    pub scrub_times: bool,
    pub truncate_before_unlink: bool,
    pub scrub_sidecars: bool,
    pub json: bool,
    pub same_length_rounds: usize,
    pub max_rename_steps: usize,
}

/// Where each non-default setting came from, so a surprising run is always
/// traceable to the line that caused it. REFERENCE §5.4.
#[derive(Debug, Clone, Default)]
pub struct Provenance {
    /// Keys the file actually supplied. The file's own path is carried by the
    /// `ConfigFile`, so it is not duplicated here.
    pub from_config: Vec<String>,
    pub from_cli: Vec<String>,
}

/// True when this argument was actually typed, rather than left at its default.
/// The derive alone cannot tell the two apart, and precedence depends on it.
fn given(m: &ArgMatches, id: &str) -> bool {
    matches!(m.value_source(id), Some(ValueSource::CommandLine))
}

/// Resolve a `--x` / `--no-x` pair into an explicit choice; off wins a tie.
fn pair(m: &ArgMatches, on: &str, off: &str) -> Option<bool> {
    if given(m, off) {
        Some(false)
    } else if given(m, on) {
        Some(true)
    } else {
        None
    }
}

/// Resolve a single-direction flag: present means the flag's own value.
fn flag(m: &ArgMatches, id: &str, value: bool) -> Option<bool> {
    given(m, id).then_some(value)
}

/// An explicit flag wins, then the file, then the hardcoded default.
///
/// `explicit` is `None` when the user said nothing either way. A setting that
/// is on by default needs *both* spellings — `--no-x` to turn it off and `--x`
/// to turn it back on over a config file that did — because a command line
/// that can only move a setting one way cannot win, and REFERENCE §5.1 says it
/// always wins.
fn pick_bool(
    explicit: Option<bool>,
    conf: Option<&ConfigFile>,
    key: &str,
    default: bool,
    prov: &mut Provenance,
) -> bool {
    if let Some(v) = explicit {
        return v;
    }
    if let Some(v) = conf.and_then(|c| c.bool(key)) {
        prov.from_config.push(key.to_string());
        return v;
    }
    default
}

impl Config {
    /// Resolve hardcoded defaults < config file < command line. REFERENCE §5.1.
    ///
    /// Scope settings — `-F`, symlink following, mount crossing, hard links —
    /// are read from `cli` only and never consulted in `conf`, because there is
    /// no config key for them to come from (REFERENCE §0).
    pub fn resolve(
        cli: &Cli,
        m: &ArgMatches,
        conf: Option<&ConfigFile>,
    ) -> Result<(Self, Provenance), String> {
        let mut prov = Provenance::default();
        for id in [
            "iterations",
            "force_perms",
            "exact",
            "zero",
            "keep",
            "remove",
            "head",
            "tail",
            "size",
            "random_source",
            "no_recursive",
            "no_scrub_times",
            "scrub_times",
            "no_truncate",
            "truncate",
            "no_scrub_sidecars",
            "scrub_sidecars",
            "dry_run",
            "verbose",
            "json",
            "force_everything",
            "no_one_file_system",
            "hard_links",
        ] {
            if given(m, id) {
                prov.from_cli.push(id.to_string());
            }
        }

        // -s is shred's spelling of --head. If both are given they must agree.
        let cli_head = match (cli.head, cli.size) {
            (Some(h), Some(s)) if h != s => {
                return Err("--head and -s/--size disagree; they are the same option".into());
            }
            (Some(h), _) => Some(h),
            (None, s) => s,
        };
        let head = match cli_head {
            Some(h) => Some(h),
            None => match conf.and_then(|c| c.text("head")) {
                Some(v) => {
                    prov.from_config.push("head".into());
                    Some(size::parse(v)?)
                }
                None => None,
            },
        };
        let tail = match cli.tail {
            Some(t) => Some(t),
            None => match conf.and_then(|c| c.text("tail")) {
                Some(v) => {
                    prov.from_config.push("tail".into());
                    Some(size::parse(v)?)
                }
                None => None,
            },
        };

        let iterations = if given(m, "iterations") {
            cli.iterations
        } else if let Some(v) = conf.and_then(|c| c.u32("iterations")) {
            prov.from_config.push("iterations".into());
            v
        } else {
            cli.iterations
        };

        let verbose = if given(m, "verbose") {
            cli.verbose
        } else if let Some(v) = conf.and_then(|c| c.u8("verbose")) {
            prov.from_config.push("verbose".into());
            v
        } else {
            cli.verbose
        };

        let remove = if given(m, "remove") {
            cli.remove
        } else if let Some(v) = conf.and_then(|c| c.text("remove")) {
            prov.from_config.push("remove".into());
            match v {
                "unlink" => RemoveMode::Unlink,
                "wipe" => RemoveMode::Wipe,
                _ => RemoveMode::Wipesync,
            }
        } else {
            cli.remove
        };

        let random_source = match &cli.random_source {
            Some(s) => Some(s.clone()),
            None => conf.and_then(|c| c.text("random_source")).map(|s| {
                prov.from_config.push("random_source".into());
                s.to_string()
            }),
        };

        let keep = pick_bool(flag(m, "keep", cli.keep), conf, "keep", false, &mut prov);
        let exact = pick_bool(flag(m, "exact", cli.exact), conf, "exact", false, &mut prov);
        let zero = pick_bool(flag(m, "zero", cli.zero), conf, "zero", false, &mut prov);
        let dry_run = pick_bool(
            flag(m, "dry_run", cli.dry_run),
            conf,
            "dry_run",
            false,
            &mut prov,
        );
        let json = pick_bool(flag(m, "json", cli.json), conf, "json", false, &mut prov);
        let force_perms = pick_bool(
            flag(m, "force_perms", cli.force_perms),
            conf,
            "force_perms",
            false,
            &mut prov,
        ) || cli.force_everything;
        let recursive = pick_bool(
            pair(m, "compat_r", "no_recursive"),
            conf,
            "recursive",
            true,
            &mut prov,
        );
        // §16.5 — on by default. Each carries both spellings so the command
        // line can move it either way over a config file that set it.
        let scrub_times = pick_bool(
            pair(m, "scrub_times", "no_scrub_times"),
            conf,
            "scrub_times",
            true,
            &mut prov,
        );
        let truncate_before_unlink = pick_bool(
            pair(m, "truncate", "no_truncate"),
            conf,
            "truncate_before_unlink",
            true,
            &mut prov,
        );
        let scrub_sidecars = pick_bool(
            pair(m, "scrub_sidecars", "no_scrub_sidecars"),
            conf,
            "scrub_sidecars",
            true,
            &mut prov,
        );

        let same_length_rounds = conf
            .and_then(|c| c.usize("same_length_rounds"))
            .inspect(|_| prov.from_config.push("same_length_rounds".into()))
            .unwrap_or(2);
        let max_rename_steps = conf
            .and_then(|c| c.usize("max_rename_steps"))
            .inspect(|_| prov.from_config.push("max_rename_steps".into()))
            .unwrap_or(16);

        if zero && head.is_some() {
            // §2.6 — zeros are exactly the entropy edge --head exists to avoid.
            eprintln!(
                "sanitize: warning: -z writes a zero pass over a partial overwrite, creating the \
                 distinguishable boundary that --head is meant to prevent"
            );
        }
        if iterations > 1 {
            // §15.4 — on flash the FTL redirects every pass to fresh pages.
            eprintln!(
                "sanitize: warning: -n {iterations} multiplies wear and time; extra passes land on \
                 different physical pages on any flash device and destroy nothing the first pass \
                 missed"
            );
        }

        let cfg = Config {
            iterations,
            force_perms,
            random_source,
            verbose,
            exact,
            zero,
            remove,
            keep,
            recursive,
            head,
            tail,
            dry_run,
            // ---- scope: command line only, never read from `conf` ----------
            force_everything: cli.force_everything,
            one_file_system: !cli.no_one_file_system && !cli.force_everything,
            follow_symlinks: cli.force_everything,
            hard_links: cli.hard_links,
            // ----------------------------------------------------------------
            scrub_times,
            truncate_before_unlink,
            scrub_sidecars,
            json,
            same_length_rounds,
            max_rename_steps,
        };
        Ok((cfg, prov))
    }

    /// Test helper: resolve argv with no configuration file in play.
    #[cfg(test)]
    pub fn from_args(args: &[&str]) -> Result<Self, String> {
        let m = Cli::command()
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;
        let cli = Cli::from_arg_matches(&m).map_err(|e| e.to_string())?;
        Self::resolve(&cli, &m, None).map(|(c, _)| c)
    }

    /// Test helper: resolve argv against a configuration file.
    #[cfg(test)]
    pub fn from_args_with(args: &[&str], conf: &ConfigFile) -> Result<(Self, Provenance), String> {
        let m = Cli::command()
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;
        let cli = Cli::from_arg_matches(&m).map_err(|e| e.to_string())?;
        Self::resolve(&cli, &m, Some(conf))
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
        Config::from_args(args).unwrap()
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

    fn conf(text: &str) -> ConfigFile {
        ConfigFile::parse(text, "test.conf").unwrap()
    }

    /// hardcoded < file < command line. The middle layer is the whole point:
    /// without it the file may as well not exist, and if it wins over the
    /// command line the call site stops meaning what it says.
    #[test]
    fn precedence_runs_hardcoded_then_file_then_command_line() {
        let c = conf("iterations = 7\nscrub_times = false\nremove = wipe");

        // Nothing on the command line: the file wins over the defaults.
        let (cfg, prov) = Config::from_args_with(&["sanitize", "x"], &c).unwrap();
        assert_eq!(cfg.iterations, 7);
        assert!(!cfg.scrub_times);
        assert_eq!(cfg.remove, RemoveMode::Wipe);
        assert!(prov.from_config.contains(&"iterations".to_string()));

        // Explicit flags beat the file, every time.
        let (cfg, _) = Config::from_args_with(&["sanitize", "-n", "2", "x"], &c).unwrap();
        assert_eq!(cfg.iterations, 2, "the command line must win");
        assert!(!cfg.scrub_times, "untouched keys still come from the file");
    }

    /// A default-valued flag is not an explicit one. `-n 1` typed by hand must
    /// beat a file saying 7, even though 1 is also the hardcoded default —
    /// this is what the ArgMatches plumbing exists for.
    #[test]
    fn a_flag_typed_at_its_default_value_still_wins() {
        let c = conf("iterations = 7");
        let (cfg, _) = Config::from_args_with(&["sanitize", "-n", "1", "x"], &c).unwrap();
        assert_eq!(
            cfg.iterations, 1,
            "an explicit -n 1 is not the same as no -n"
        );
    }

    /// REFERENCE §0: config may change how thoroughly the chosen bytes die,
    /// never which bytes are chosen. There is no key for any of these, so a
    /// file cannot reach them even by accident.
    #[test]
    fn a_config_file_can_never_widen_scope() {
        let c = conf("iterations = 3\nkeep = true");
        let (cfg, _) = Config::from_args_with(&["sanitize", "x"], &c).unwrap();
        assert!(!cfg.force_everything);
        assert!(cfg.one_file_system, "mount containment stays on");
        assert!(!cfg.follow_symlinks, "symlinks stay unfollowed");
        assert_eq!(cfg.hard_links, HardLinkMode::Skip);
    }

    /// The residue defaults are §16.5's, and the file can turn each one off
    /// individually without touching the others.
    #[test]
    fn residue_settings_come_through_the_file_one_at_a_time() {
        let (cfg, _) =
            Config::from_args_with(&["sanitize", "x"], &conf("scrub_sidecars = false")).unwrap();
        assert!(!cfg.scrub_sidecars);
        assert!(cfg.scrub_times, "unrelated defaults must not move");
        assert!(cfg.truncate_before_unlink);
    }

    /// SHORTCOMINGS §8.8 — these were hardcoded and unreachable.
    #[test]
    fn ladder_tuning_is_reachable_from_the_file() {
        let (cfg, _) = Config::from_args_with(
            &["sanitize", "x"],
            &conf("same_length_rounds = 4\nmax_rename_steps = 8"),
        )
        .unwrap();
        assert_eq!(cfg.same_length_rounds, 4);
        assert_eq!(cfg.max_rename_steps, 8);
    }

    #[test]
    fn contradictory_head_and_size_is_rejected() {
        assert!(Config::from_args(&["sanitize", "-s", "1K", "--head", "2K", "x"]).is_err());
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

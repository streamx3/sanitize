//! sanitize — recursive secure deletion that tells you the truth.
//!
//! See DESIGN.md. The two rules that govern everything here:
//!   §16.1  the program does not crash; per-entry errors never end the run
//!   §3     never print "securely erased"; print what actually happened

mod cli;
mod config_file;
mod guards;
mod interrupt;
mod meta;
mod name;
mod report;
mod size;
mod sysx;
mod walk;
mod wipe;

use clap::{CommandFactory, FromArgMatches};
use report::Report;
use std::process::ExitCode;

/// §4.3 — 0 ok · 1 some failed · 2 usage · 3 refused for safety
const EXIT_OK: u8 = 0;
const EXIT_FAILURES: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_REFUSED: u8 = 3;

fn main() -> ExitCode {
    install_panic_hook();
    // §16.1 item 5 — before anything can be destroyed, so there is no window
    // in which Ctrl-C kills the process without a summary.
    interrupt::install();

    // The derive alone cannot tell a typed `-n 1` from the default `-n 1`, and
    // config precedence depends on knowing which it was. REFERENCE §5.1.
    let matches = cli::Cli::command().get_matches();
    let cli = match cli::Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };

    // hardcoded defaults < /etc/sanitize/default.conf < command line.
    // The file is read and trusted: a permission check would protect nothing,
    // since anyone who can write it can replace this binary. REFERENCE §5.5.
    let conf = if cli.no_config {
        None
    } else {
        let explicit = cli.config.is_some();
        let path = cli.config.as_deref().unwrap_or(config_file::SYSTEM_PATH);
        match config_file::ConfigFile::load(path) {
            Ok(Some(c)) => Some(c),
            // A missing /etc file is the normal case. A missing file the user
            // named by hand is a typo they need to hear about.
            Ok(None) if explicit => {
                eprintln!("sanitize: {path}: no such configuration file");
                return ExitCode::from(EXIT_USAGE);
            }
            Ok(None) => None,
            Err(e) => {
                eprintln!("sanitize: {e}");
                return ExitCode::from(EXIT_USAGE);
            }
        }
    };

    let (cfg, provenance) = match cli::Config::resolve(&cli, &matches, conf.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sanitize: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    disclose(conf.as_ref(), &provenance);

    // §7.4 — refuse dangerous targets before anything is destroyed, so a
    // refusal is always exit 3 with nothing touched.
    let mut refused = false;
    for path in &cli.paths {
        if let guards::Verdict::Refuse(msg) = guards::check(path, cfg.force_everything) {
            eprintln!("sanitize: {msg}");
            refused = true;
        }
    }
    if refused {
        return ExitCode::from(EXIT_REFUSED);
    }

    if cfg.force_everything && !sysx::is_root() {
        eprintln!(
            "sanitize: note: -F given without root; guards are off but entries you cannot \
             write will be recorded and skipped, not retried"
        );
    }

    sysx::raise_nofile();

    let mut rng = match wipe::RandomSource::new(cfg.random_source.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sanitize: cannot obtain randomness: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let mut rep = Report::new(cfg.json, cfg.verbose);
    {
        let mut walker = walk::Walker::new(&cfg, &mut rng, &mut rep);
        for path in &cli.paths {
            // Between targets is the coarsest safe point; the walker and the
            // wipe engine hold the finer ones.
            if interrupt::requested() {
                break;
            }
            walker.run(path);
        }
    }
    rep.interrupted = interrupt::requested();
    rep.summary(cfg.dry_run);

    // Exit 0 must mean "the job is done". A skipped entry is deliberate, but
    // it still leaves data in place, and a script that treats that as success
    // will delete the wrong thing next.
    if rep.incomplete() {
        ExitCode::from(EXIT_FAILURES)
    } else {
        ExitCode::from(EXIT_OK)
    }
}

/// §5.4 — say which layers were in effect and where each non-default setting
/// came from, so a surprising run is traceable to the line that caused it.
///
/// Only when a config file actually contributed something: with no config in
/// play the command line is already in front of the user, and repeating it back
/// is noise rather than disclosure.
fn disclose(conf: Option<&config_file::ConfigFile>, p: &cli::Provenance) {
    let Some(conf) = conf else {
        // No file in play, so the command line is the whole story and is
        // already in front of the user. Repeating it back is noise.
        return;
    };
    if conf.is_empty() {
        return;
    }

    let applied = &p.from_config;
    let overridden: Vec<&str> = conf
        .keys()
        .into_iter()
        .filter(|k| !applied.iter().any(|a| a == k))
        .collect();

    eprintln!(
        "sanitize: config: {} ({})",
        conf.path,
        if applied.is_empty() {
            "nothing applied".to_string()
        } else {
            applied.join(", ")
        }
    );
    if !overridden.is_empty() {
        // Say it explicitly. A setting that is in the file but not in effect is
        // exactly the thing an operator misreads as active.
        eprintln!(
            "sanitize: config: overridden on the command line ({})",
            overridden.join(", ")
        );
    }
}

/// §16.1 item 1 — a panic is a bug, but if one ever happens it must say what it
/// was working on rather than vanishing with a bare backtrace.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        eprintln!(
            "sanitize: INTERNAL ERROR — this is a bug, please report it.\n\
             sanitize: nothing further will be destroyed in this run."
        );
        previous(info);
    }));
}

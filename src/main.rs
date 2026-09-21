//! sanitize — recursive secure deletion that tells you the truth.
//!
//! See DESIGN.md. The two rules that govern everything here:
//!   §16.1  the program does not crash; per-entry errors never end the run
//!   §3     never print "securely erased"; print what actually happened

mod cli;
mod guards;
mod meta;
mod name;
mod report;
mod size;
mod sysx;
mod walk;
mod wipe;

use clap::Parser;
use report::Report;
use std::process::ExitCode;

/// §4.3 — 0 ok · 1 some failed · 2 usage · 3 refused for safety
const EXIT_OK: u8 = 0;
const EXIT_FAILURES: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_REFUSED: u8 = 3;

fn main() -> ExitCode {
    install_panic_hook();

    let cli = cli::Cli::parse();
    let cfg = match cli::Config::from_cli(&cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sanitize: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

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
            walker.run(path);
        }
    }
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

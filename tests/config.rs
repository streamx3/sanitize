//! The configuration file end to end. REFERENCE.md §5.
//!
//! Precedence is `hardcoded < /etc/sanitize/default.conf < command line`, and
//! the property that matters most is the one in §0: a config file can change
//! how thoroughly the chosen bytes die, never *which* bytes are chosen.

// Tests assert by panicking; the crate-wide denials exist for the binary.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_sanitize");
static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("sanitize-cfg-{pid}-{tag}-{n}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
    fn file(&self, name: &str, body: &str) -> PathBuf {
        let p = self.0.join(name);
        fs::write(&p, body).unwrap();
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> (String, i32) {
    let out = Command::new(BIN).args(args).output().unwrap();
    (
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        out.status.code().unwrap_or(-1),
    )
}

/// The middle layer does something, and says that it did.
#[test]
fn a_config_file_changes_behaviour_and_is_disclosed() {
    let s = Scratch::new("applies");
    let conf = s.file("sanitize.conf", "scrub_sidecars = false\n");
    let target = s.file("foo.7z", "payload");
    let sidecar = s.file("._foo.7z", "quarantine");

    let (out, code) = run(&["--config", conf.to_str().unwrap(), target.to_str().unwrap()]);

    assert_eq!(code, 0, "{out}");
    assert!(!target.exists(), "{out}");
    assert!(
        sidecar.exists(),
        "the file's setting was not applied\n{out}"
    );
    assert!(
        out.contains("config:") && out.contains("scrub_sidecars"),
        "a setting that came from a file must be disclosed\n{out}"
    );
}

/// The command line always wins — including in the direction that turns a
/// setting back *on*, which needs the positive spelling to exist at all.
#[test]
fn the_command_line_overrides_the_file_in_both_directions() {
    let s = Scratch::new("override");
    let conf = s.file("sanitize.conf", "scrub_sidecars = false\n");
    let target = s.file("foo.7z", "payload");
    let sidecar = s.file("._foo.7z", "quarantine");

    let (out, code) = run(&[
        "--config",
        conf.to_str().unwrap(),
        "--scrub-sidecars",
        target.to_str().unwrap(),
    ]);

    assert_eq!(code, 0, "{out}");
    assert!(
        !sidecar.exists(),
        "--scrub-sidecars must beat the file\n{out}"
    );
    assert!(
        out.contains("overridden on the command line"),
        "a setting present in the file but not in effect must be named — that \
         is exactly what an operator misreads as active\n{out}"
    );
}

/// REFERENCE §0: there is no config key for scope, so naming one is an error
/// rather than a silent ignore. Nothing may be destroyed on the way to finding
/// that out.
#[test]
fn scope_settings_in_a_config_file_are_refused_before_anything_is_touched() {
    for key in [
        "force_everything = true",
        "follow_symlinks = true",
        "no_one_file_system = true",
        "hard_links = shred",
    ] {
        let s = Scratch::new("scope");
        let conf = s.file("sanitize.conf", &format!("{key}\n"));
        let target = s.file("foo.7z", "payload");

        let (out, code) = run(&["--config", conf.to_str().unwrap(), target.to_str().unwrap()]);

        assert_eq!(code, 2, "`{key}` must be a usage error\n{out}");
        assert!(
            target.exists(),
            "`{key}`: nothing may be destroyed before the config is rejected\n{out}"
        );
        assert!(
            out.contains("command line"),
            "`{key}`: the error must say where the setting belongs\n{out}"
        );
    }
}

/// A typo must not read as "off". This is the difference between a config that
/// failed loudly and a safety setting that silently is not active.
#[test]
fn an_unknown_key_is_refused_with_its_line_number() {
    let s = Scratch::new("typo");
    let conf = s.file("sanitize.conf", "# a comment\nscrub_time = false\n");
    let target = s.file("foo.7z", "payload");

    let (out, code) = run(&["--config", conf.to_str().unwrap(), target.to_str().unwrap()]);

    assert_eq!(code, 2, "{out}");
    assert!(target.exists(), "nothing destroyed\n{out}");
    assert!(out.contains("unknown setting"), "{out}");
    assert!(out.contains(":2"), "must name the line\n{out}");
}

/// `--no-config` skips the layer entirely.
#[test]
fn no_config_ignores_the_file() {
    let s = Scratch::new("noconfig");
    let conf = s.file("sanitize.conf", "scrub_sidecars = false\n");
    let target = s.file("foo.7z", "payload");
    let sidecar = s.file("._foo.7z", "quarantine");

    // --config is still parsed, but --no-config wins and the default applies.
    let (out, code) = run(&[
        "--no-config",
        "--config",
        conf.to_str().unwrap(),
        target.to_str().unwrap(),
    ]);

    assert_eq!(code, 0, "{out}");
    assert!(
        !sidecar.exists(),
        "--no-config must restore the default\n{out}"
    );
    assert!(!out.contains("config:"), "nothing to disclose\n{out}");
}

/// A missing `/etc` file is the normal case. A missing file the user named by
/// hand is a typo they need to hear about.
#[test]
fn a_config_path_that_does_not_exist_is_an_error() {
    let s = Scratch::new("missing");
    let target = s.file("foo.7z", "payload");

    let (out, code) = run(&[
        "--config",
        "/nonexistent/sanitize/default.conf",
        target.to_str().unwrap(),
    ]);

    assert_eq!(code, 2, "{out}");
    assert!(target.exists(), "nothing destroyed\n{out}");
}

/// An ordinary run with no file in play says nothing about configuration: the
/// command line is already in front of the user.
#[test]
fn no_file_means_no_disclosure() {
    let s = Scratch::new("silent");
    let target = s.file("foo.7z", "payload");

    let (out, code) = run(&["--no-config", target.to_str().unwrap()]);

    assert_eq!(code, 0, "{out}");
    assert!(!out.contains("config:"), "{out}");
}

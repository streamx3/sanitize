//! Interrupt behaviour. §16.1 item 5, §7.5.
//!
//! The rule under test: a signal stops the run at a safe point and the summary
//! still prints. The default disposition kills the process silently, which
//! leaves exactly the state the robustness requirement exists to prevent —
//! some data destroyed, some not, and no record of which.
//!
//! These are timing-dependent by nature: you cannot test an interrupt without
//! interrupting something. Each workload is sized so the run lasts several
//! times longer than the delay before the signal, on hardware several times
//! faster than the machine they were written on (~580 MiB/s of overwrite,
//! ~3.8 ms per small file under `--remove=wipesync`). If one ever fails with
//! "finished before it could be interrupted", the fix is a bigger workload,
//! not a longer sleep.

// Tests assert by panicking; the crate-wide denials exist for the binary.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::sleep;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_sanitize");

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("sanitize-int-{pid}-{tag}-{n}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Signal the child by name rather than through `libc`, so the test needs no
/// unsafe and no direct dependency of its own.
fn signal(child: &Child, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &child.id().to_string()])
        .status()
        .unwrap()
        .success();
    assert!(ok, "could not deliver {sig}");
}

fn assert_still_running(child: &mut Child, what: &str) {
    assert!(
        child.try_wait().unwrap().is_none(),
        "{what} finished before it could be interrupted — enlarge the \
         workload rather than lengthening the sleep"
    );
}

/// A signal arriving mid-overwrite. The file is part random and part original,
/// so deleting it would destroy the record of which — §7.5 says it stays, and
/// says so loudly.
#[test]
fn interrupt_mid_overwrite_leaves_the_file_whole_and_reports_it() {
    let s = Scratch::new("midwipe");
    let target = s.path().join("big.img");
    const SIZE: usize = 64 * 1024 * 1024;
    fs::write(&target, vec![0u8; SIZE]).unwrap();

    // 64 MiB x 20 passes = 1.28 GiB of overwrite: seconds, not milliseconds.
    let mut child = Command::new(BIN)
        .args(["-n", "20", target.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    sleep(Duration::from_millis(400));
    assert_still_running(&mut child, "the overwrite");
    signal(&child, "-INT");

    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr).to_string();

    assert_eq!(
        out.status.code(),
        Some(1),
        "an interrupted run exits 1\n{err}"
    );
    assert!(
        err.contains("INTERRUPTED"),
        "the summary must say its counts are a partial account\n{err}"
    );
    assert!(
        err.contains("file left in place"),
        "a half-overwritten file must be reported, not silently left\n{err}"
    );
    assert!(
        target.exists(),
        "§7.5: a partially overwritten file is never deleted\n{err}"
    );
    assert_eq!(
        fs::metadata(&target).unwrap().len(),
        SIZE as u64,
        "left in place means left at its original length\n{err}"
    );
}

/// A signal arriving between directory entries. Everything already destroyed
/// stays destroyed, the rest is untouched, and the directory survives because
/// the emptiness re-check in `process_dir` finds it non-empty.
#[test]
fn interrupt_between_entries_stops_the_walk_and_still_summarises() {
    let s = Scratch::new("tree");
    const FILES: usize = 800;
    for i in 0..FILES {
        fs::write(s.path().join(format!("f{i:04}.bin")), "x".repeat(200)).unwrap();
    }

    let mut child = Command::new(BIN)
        .arg(s.path().to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    sleep(Duration::from_millis(300));
    assert_still_running(&mut child, "the walk");
    signal(&child, "-INT");

    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr).to_string();

    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("INTERRUPTED"), "{err}");
    assert!(
        err.contains("file(s)") && err.contains("removed"),
        "the summary must still print its counts\n{err}"
    );
    assert!(
        s.path().exists(),
        "a directory with entries left in it must not be removed\n{err}"
    );
    let left = fs::read_dir(s.path()).unwrap().count();
    assert!(
        left > 0 && left < FILES,
        "expected a partial run, found {left} of {FILES} remaining\n{err}"
    );
}

/// A closing terminal can deliver SIGHUP *and* SIGTERM. That is the system
/// saying one thing twice, not a user insisting, so it must not escalate past
/// the graceful stop — this is the case where the summary is most wanted.
#[test]
fn hangup_followed_by_terminate_still_prints_the_summary() {
    let s = Scratch::new("hup");
    let target = s.path().join("big.img");
    fs::write(&target, vec![0u8; 64 * 1024 * 1024]).unwrap();

    let mut child = Command::new(BIN)
        .args(["-n", "20", target.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    sleep(Duration::from_millis(400));
    assert_still_running(&mut child, "the overwrite");
    signal(&child, "-HUP");
    signal(&child, "-TERM");

    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr).to_string();

    assert_eq!(
        out.status.code(),
        Some(1),
        "two different signals must still stop gracefully\n{err}"
    );
    assert!(
        err.contains("INTERRUPTED"),
        "the summary must survive SIGHUP followed by SIGTERM\n{err}"
    );
    assert!(target.exists(), "§7.5 still applies\n{err}");
}

/// Nothing above should fire during an ordinary run.
#[test]
fn an_uninterrupted_run_says_nothing_about_interruption() {
    let s = Scratch::new("clean");
    fs::write(s.path().join("a.txt"), "payload").unwrap();

    let out = Command::new(BIN)
        .arg(s.path().to_str().unwrap())
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr).to_string();

    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(!err.contains("INTERRUPTED"), "{err}");
}

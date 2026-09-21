//! Integration tests for the metadata and residue chain. §16.5, §16.7.
//!
//! These cover the behaviours that were previously verified by hand exactly
//! once (TODO P1.4). They drive the real binary against real directories,
//! because the whole point is what ends up on the filesystem.

// Tests assert by panicking; the crate-wide denials exist for the binary.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_sanitize");

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A scratch directory that cleans up after itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("sanitize-it-{pid}-{tag}-{n}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn file(&self, name: &str, body: &str) -> PathBuf {
        let p = self.0.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
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
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (text, out.status.code().unwrap_or(-1))
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn mtime_secs(p: &Path) -> i64 {
    let md = fs::metadata(p).unwrap();
    let m = md.modified().unwrap();
    m.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap() as i64
}

/// The AppleDouble sidecar carries `com.apple.quarantine` on FAT, and its own
/// filename contains the principal's — so leaving it behind undoes the §5.2
/// ladder entirely. This is the single-file case, which is the one the walk
/// does not reach on its own.
#[test]
fn sidecar_dies_with_its_principal() {
    let s = Scratch::new("sidecar");
    let target = s.file("foo.7z", "payload");
    let sidecar = s.file("._foo.7z", "https://example.invalid/foo.7z");

    let (out, code) = run(&[target.to_str().unwrap()]);

    assert!(!target.exists(), "principal survived\n{out}");
    assert!(
        !sidecar.exists(),
        "sidecar survived — it names the principal\n{out}"
    );
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("residue:") && out.contains("scrubbed"),
        "residue was not reported\n{out}"
    );
}

/// `.DS_Store` keeps records for files already deleted; `Thumbs.db` keeps
/// rendered thumbnails of them. Both name the file we just destroyed.
#[test]
fn directory_caches_die_with_a_named_file() {
    let s = Scratch::new("caches");
    let target = s.file("a.txt", "payload");
    let ds = s.file(".DS_Store", "record naming a.txt");
    let thumbs = s.file("Thumbs.db", "thumbnail of a.txt");
    let unrelated = s.file("keep.txt", "not a target");

    let (out, code) = run(&[target.to_str().unwrap()]);

    assert!(!target.exists(), "{out}");
    assert!(!ds.exists(), ".DS_Store survived\n{out}");
    assert!(!thumbs.exists(), "Thumbs.db survived\n{out}");
    assert!(
        unrelated.exists(),
        "an unrelated neighbour was destroyed — residue scrubbing must be a \
         bounded, enumerable set\n{out}"
    );
    assert_eq!(code, 0, "{out}");
}

/// The escape hatch has to work, or the default is not a default but a law.
#[test]
fn no_scrub_sidecars_leaves_residue_alone() {
    let s = Scratch::new("optout");
    let target = s.file("foo.7z", "payload");
    let sidecar = s.file("._foo.7z", "quarantine");
    let ds = s.file(".DS_Store", "record");

    let (out, code) = run(&["--no-scrub-sidecars", target.to_str().unwrap()]);

    assert!(!target.exists(), "{out}");
    assert!(sidecar.exists(), "--no-scrub-sidecars was ignored\n{out}");
    assert!(ds.exists(), "--no-scrub-sidecars was ignored\n{out}");
    assert_eq!(code, 0, "{out}");
}

/// A whole-directory run reaches sidecars through the ordinary listing. The
/// risk is the walk racing itself: the principal removes the sidecar, then the
/// listing reaches a name that is already gone. That must not be an error.
#[test]
fn whole_directory_run_destroys_sidecars_without_spurious_failures() {
    let s = Scratch::new("wholedir");
    s.file("a.txt", "a");
    s.file("._a.txt", "quarantine a");
    s.file(".DS_Store", "records");
    s.file("sub/b.txt", "b");
    s.file("sub/._b.txt", "quarantine b");

    let (out, code) = run(&[s.path().to_str().unwrap()]);

    assert!(!s.path().exists(), "tree survived\n{out}");
    assert_eq!(
        code, 0,
        "a vanished sidecar must not count as a failure\n{out}"
    );
    assert!(
        out.contains("0 skipped; 0 failed"),
        "expected a clean run\n{out}"
    );
}

/// `-k` means overwrite *and keep*. Truncating there would destroy exactly
/// what the user asked to preserve, and scrubbing timestamps would rewrite
/// metadata on a file that survives the run. §16.5.
#[test]
fn keep_neither_truncates_nor_scrubs_times() {
    let s = Scratch::new("keep");
    let body = "payload that is a known length";
    let target = s.file("keep.bin", body);
    let started = now_secs();

    let (out, code) = run(&["-k", target.to_str().unwrap()]);

    assert_eq!(code, 0, "{out}");
    assert!(target.exists(), "-k must keep the file\n{out}");
    // Two things at once: not truncated to zero (the -k gate), and not grown
    // to a block boundary either. The slack wipe writes past EOF to reach the
    // tail of the last block, which extends the file; a kept file must come
    // back at its original length.
    assert_eq!(
        fs::metadata(&target).unwrap().len(),
        body.len() as u64,
        "-k must preserve the original length — neither truncated to 0 nor \
         grown to a block boundary by the slack wipe\n{out}"
    );
    assert!(
        fs::read(&target).unwrap() != body.as_bytes(),
        "-k must still overwrite the contents\n{out}"
    );
    // A scrubbed timestamp is uniform over 1980..now, so a value inside the
    // test window means it was not scrubbed.
    assert!(
        mtime_secs(&target) >= started - 5,
        "-k must not scrub timestamps on a file that survives\n{out}"
    );
}

/// Residue is reported in its own channel, never folded into the file count.
/// §16.7 — the surprising part of the run has to be visible.
#[test]
fn residue_is_counted_separately_from_named_files() {
    let s = Scratch::new("json");
    let target = s.file("foo.7z", "payload");
    s.file("._foo.7z", "quarantine");
    s.file(".DS_Store", "records");

    let (out, code) = run(&["--json", target.to_str().unwrap()]);

    assert_eq!(code, 0, "{out}");
    let summary = out
        .lines()
        .find(|l| l.contains("\"summary\":true"))
        .unwrap_or_else(|| panic!("no summary line\n{out}"));
    assert!(
        summary.contains("\"files\":1"),
        "the named file must be counted once, not three times\n{summary}"
    );
    assert!(
        summary.contains("\"residue_scrubbed\":2"),
        "both residue files must be reported\n{summary}"
    );
    assert!(
        summary.contains("\"residue_unscrubbed\":0"),
        "nothing should have been left behind\n{summary}"
    );
}

/// Dry run must not destroy anything, residue included.
#[test]
fn dry_run_touches_no_residue() {
    let s = Scratch::new("dryrun");
    let target = s.file("foo.7z", "payload");
    let sidecar = s.file("._foo.7z", "quarantine");

    let (out, _) = run(&["--dry-run", target.to_str().unwrap()]);

    assert!(target.exists(), "--dry-run destroyed the target\n{out}");
    assert!(sidecar.exists(), "--dry-run destroyed residue\n{out}");
}

/// A sidecar with no principal in the directory still has to die: nothing
/// else will reach it.
#[test]
fn orphan_sidecars_are_destroyed_by_a_directory_run() {
    let s = Scratch::new("orphan");
    s.file(
        "._vanished.7z",
        "quarantine for a file that is already gone",
    );

    let (out, code) = run(&[s.path().to_str().unwrap()]);

    assert!(!s.path().exists(), "orphan sidecar survived\n{out}");
    assert_eq!(code, 0, "{out}");
}

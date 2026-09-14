//! TOCTOU-safe recursive traversal. §7, §16.
//!
//! Every descent is `openat(dirfd, name, O_DIRECTORY|O_NOFOLLOW)` and every
//! operation is `*at()` relative to a held directory fd. Paths are never
//! re-resolved from strings after the initial open, which closes the race where
//! a directory is swapped for a symlink between the check and the unlink.
//! `wipe` uses `opendir()` + `chdir()` by name (wipe.c:1204-1214) and is racy.
//!
//! §16.1 governs this whole file: no operation on any single entry may end the
//! run. Every error becomes an `Outcome::Failed` and the walk continues.

use crate::cli::{Config, HardLinkMode, RemoveMode};
use crate::name;
use crate::report::{Guarantee, Kind, Outcome, Report};
use crate::sysx;
use crate::wipe::{self, RandomSource};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

/// Bounded so a pathological tree cannot overflow the stack. §16.1
const MAX_DEPTH: usize = 512;

pub struct Walker<'a> {
    cfg: &'a Config,
    rng: &'a mut RandomSource,
    report: &'a mut Report,
    /// The `st_dev` the run is confined to, unless -F. §16.2
    boundary_dev: Option<u64>,
    /// Followed symlink targets, so -F cannot loop forever. §16.3
    visited: HashSet<(u64, u64)>,
}

impl<'a> Walker<'a> {
    pub fn new(cfg: &'a Config, rng: &'a mut RandomSource, report: &'a mut Report) -> Self {
        Self {
            cfg,
            rng,
            report,
            boundary_dev: None,
            visited: HashSet::new(),
        }
    }

    /// Handle one command-line target.
    pub fn run(&mut self, target: &str) {
        let norm = crate::guards::normalize(target);
        let display = norm.display().to_string();

        // The filesystem root has no parent to hold; operate on its contents.
        let (parent, base) = match (norm.parent(), norm.file_name()) {
            (Some(p), Some(b)) => (p.to_path_buf(), b.to_os_string()),
            _ => {
                self.run_root_directory(&norm);
                return;
            }
        };

        let parent_fd = match open_dir_path(&parent) {
            Ok(fd) => fd,
            Err(e) => {
                self.report.record(
                    &display,
                    &Outcome::Failed {
                        stage: "open parent",
                        error: e.to_string(),
                    },
                );
                return;
            }
        };

        let name = match to_cstring(&base) {
            Some(n) => n,
            None => {
                self.report.record(
                    &display,
                    &Outcome::Failed {
                        stage: "name",
                        error: "path contains an interior NUL".into(),
                    },
                );
                return;
            }
        };

        // Confine the run to the filesystem the target lives on. §16.2
        if self.cfg.one_file_system
            && self.boundary_dev.is_none()
            && let Ok(st) =
                rustix::fs::statat(parent_fd.as_fd(), name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
        {
            self.boundary_dev = Some(st.st_dev as _);
        }

        self.process(parent_fd.as_fd(), name.as_c_str(), &display, 0);
    }

    /// `sanitize -F /` — empty the root without trying to unlink it.
    fn run_root_directory(&mut self, path: &Path) {
        let display = path.display().to_string();
        let fd = match open_dir_path(path) {
            Ok(fd) => fd,
            Err(e) => {
                self.report.record(
                    &display,
                    &Outcome::Failed {
                        stage: "open",
                        error: e.to_string(),
                    },
                );
                return;
            }
        };
        if self.cfg.one_file_system
            && self.boundary_dev.is_none()
            && let Ok(st) = rustix::fs::fstat(fd.as_fd())
        {
            self.boundary_dev = Some(st.st_dev as _);
        }
        self.drain_directory(fd.as_fd(), &display, 0);
        self.report.record(
            &display,
            &Outcome::Skipped {
                reason: "filesystem root itself cannot be unlinked; contents processed".into(),
            },
        );
    }

    /// Dispatch one entry by type. Never returns an error: everything is
    /// recorded and the walk continues. §16.1
    fn process(&mut self, dirfd: BorrowedFd<'_>, name: &CStr, display: &str, depth: usize) {
        if depth > MAX_DEPTH {
            self.report.record(
                display,
                &Outcome::Skipped {
                    reason: format!("nesting deeper than {MAX_DEPTH} levels"),
                },
            );
            return;
        }

        let st = match rustix::fs::statat(dirfd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(e) => {
                self.report.record(
                    display,
                    &Outcome::Failed {
                        stage: "stat",
                        error: errno_str(e),
                    },
                );
                return;
            }
        };

        let ftype = FileType::from_raw_mode(st.st_mode as _);
        match ftype {
            FileType::Directory => self.process_dir(dirfd, name, display, depth, st.st_dev as _),
            FileType::Symlink => self.process_symlink(dirfd, name, display, depth),
            FileType::RegularFile => self.process_file(dirfd, name, display, &st),
            _ => {
                // Devices, FIFOs, sockets. Removing them is meaningful;
                // overwriting them through the tree is not.
                if self.cfg.dry_run {
                    self.report.record(display, &Outcome::Planned { kind: Kind::Special });
                    return;
                }
                match self.obfuscate_and_remove(dirfd, name, false) {
                    Ok(()) => self.report.record(
                        display,
                        &Outcome::Removed {
                            kind: Kind::Special,
                            guarantee: Guarantee::Clear,
                        },
                    ),
                    Err((stage, err)) => {
                        self.report.record(display, &Outcome::Failed { stage, error: err })
                    }
                }
            }
        }
    }

    fn process_dir(
        &mut self,
        dirfd: BorrowedFd<'_>,
        name: &CStr,
        display: &str,
        depth: usize,
        dev: u64,
    ) {
        if !self.cfg.recursive {
            self.report.record(
                display,
                &Outcome::Skipped {
                    reason: "is a directory and --no-recursive was given".into(),
                },
            );
            return;
        }

        // §16.2: stop at the narrowest of drive / partition / mount point,
        // which is exactly what st_dev identifies.
        if let Some(boundary) = self.boundary_dev
            && dev != boundary
        {
            {
                self.report.record(
                    display,
                    &Outcome::Skipped {
                        reason: "crosses a mount point (use -F or --no-one-file-system)".into(),
                    },
                );
                return;
            }
        }

        let fd = match rustix::fs::openat(
            dirfd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(e) if e == rustix::io::Errno::ACCESS && self.cfg.force_perms => {
                // -f/-F: try to grant ourselves search+write on the directory.
                let _ = rustix::fs::chmodat(dirfd, name, Mode::RWXU, AtFlags::empty());
                match rustix::fs::openat(
                    dirfd,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(fd) => fd,
                    Err(e) => {
                        self.report.record(
                            display,
                            &Outcome::Failed {
                                stage: "open dir",
                                error: errno_str(e),
                            },
                        );
                        return;
                    }
                }
            }
            Err(e) => {
                self.report.record(
                    display,
                    &Outcome::Failed {
                        stage: "open dir",
                        error: errno_str(e),
                    },
                );
                return;
            }
        };

        let survivors = self.drain_directory(fd.as_fd(), display, depth);

        if self.cfg.keep {
            drop(fd);
            return;
        }

        if self.cfg.dry_run {
            drop(fd);
            if survivors == 0 {
                self.report.record(display, &Outcome::Planned { kind: Kind::Dir });
            } else {
                self.report.record(
                    display,
                    &Outcome::Skipped {
                        reason: format!("{survivors} entr(y/ies) would remain; directory would stay"),
                    },
                );
            }
            return;
        }

        // Confirm emptiness from the filesystem, not from our own bookkeeping,
        // before touching the name. Renaming a directory we then cannot remove
        // would leave the user with a scrambled name and their data still there.
        let remaining = count_entries(fd.as_fd());
        drop(fd);
        if remaining != Some(0) {
            let reason = match remaining {
                Some(n) => format!("{n} entr(y/ies) remain (skipped or failed); directory left in place"),
                None => "could not confirm the directory is empty; left in place".to_string(),
            };
            self.report.record(display, &Outcome::Skipped { reason });
            return;
        }

        // §5.5 / §15.2: directory names live in the parent's entry table
        // exactly like file names. `wipe` never renames directories at all
        // (wipe.c:1238) — on FAT/exFAT that is a real leak.
        match self.obfuscate_and_remove(dirfd, name, true) {
            Ok(()) => self.report.record(
                display,
                &Outcome::Removed {
                    kind: Kind::Dir,
                    guarantee: Guarantee::Clear,
                },
            ),
            Err((stage, err)) => self.report.record(display, &Outcome::Failed { stage, error: err }),
        }
    }

    /// Process every entry in an open directory. Returns how many entries we
    /// believe survived (skipped or failed). Reads the whole listing first:
    /// mutating a directory while its stream is open is asking for trouble.
    fn drain_directory(&mut self, fd: BorrowedFd<'_>, display: &str, depth: usize) -> u64 {
        let mut names: Vec<CString> = Vec::new();
        match Dir::read_from(fd) {
            Ok(dir) => {
                for entry in dir {
                    match entry {
                        Ok(e) => {
                            let n = e.file_name();
                            if n == c"." || n == c".." {
                                continue;
                            }
                            names.push(n.to_owned());
                        }
                        Err(e) => {
                            // A single unreadable entry must not end the run.
                            self.report.record(
                                display,
                                &Outcome::Failed {
                                    stage: "readdir",
                                    error: errno_str(e),
                                },
                            );
                        }
                    }
                }
            }
            Err(e) => {
                self.report.record(
                    display,
                    &Outcome::Failed {
                        stage: "readdir",
                        error: errno_str(e),
                    },
                );
                // Cannot list it, so we cannot claim it is empty.
                return u64::MAX;
            }
        }

        let before_failed = self.report.failed;
        let before_skipped = self.report.skipped;
        for n in &names {
            let child = format!("{display}/{}", n.to_string_lossy());
            self.process(fd, n.as_c_str(), &child, depth.saturating_add(1));
        }
        self.report
            .failed
            .saturating_sub(before_failed)
            .saturating_add(self.report.skipped.saturating_sub(before_skipped))
    }

    fn process_symlink(&mut self, dirfd: BorrowedFd<'_>, name: &CStr, display: &str, depth: usize) {
        if self.cfg.follow_symlinks {
            // §16.3: -F follows the link, destroys the target's contents, then
            // removes the link itself.
            match rustix::fs::readlinkat(dirfd, name, Vec::new()) {
                Ok(target) => {
                    let target = target.to_string_lossy().to_string();
                    let resolved = resolve_relative(display, &target);
                    let key = rustix::fs::statat(dirfd, name, AtFlags::empty())
                        .ok()
                        .map(|st| (st.st_dev as _, st.st_ino as _));
                    let looped = match key {
                        Some(k) => !self.visited.insert(k),
                        None => false,
                    };
                    if looped {
                        self.report.record(
                            display,
                            &Outcome::Skipped {
                                reason: "symlink target already visited (cycle)".into(),
                            },
                        );
                    } else if depth <= MAX_DEPTH {
                        self.run(&resolved);
                    }
                }
                Err(e) => {
                    self.report.record(
                        display,
                        &Outcome::Failed {
                            stage: "readlink",
                            error: errno_str(e),
                        },
                    );
                }
            }
        }

        if self.cfg.keep {
            return;
        }
        if self.cfg.dry_run {
            self.report.record(display, &Outcome::Planned { kind: Kind::Symlink });
            return;
        }

        // Default (§16.2): the link goes, the target is never touched.
        match self.obfuscate_and_remove(dirfd, name, false) {
            Ok(()) => self.report.record(
                display,
                &Outcome::Removed {
                    kind: Kind::Symlink,
                    guarantee: Guarantee::Clear,
                },
            ),
            Err((stage, err)) => self.report.record(display, &Outcome::Failed { stage, error: err }),
        }
    }

    fn process_file(
        &mut self,
        dirfd: BorrowedFd<'_>,
        name: &CStr,
        display: &str,
        st: &rustix::fs::Stat,
    ) {
        // §9.1 — shred silently destroys data reachable under another name.
        if st.st_nlink > 1 {
            match self.cfg.hard_links {
                HardLinkMode::Skip => {
                    self.report.record(
                        display,
                        &Outcome::Skipped {
                            reason: format!(
                                "{} hard links; data is reachable elsewhere (--hard-links=shred to override)",
                                st.st_nlink
                            ),
                        },
                    );
                    return;
                }
                HardLinkMode::Warn => {
                    self.report.record(
                        display,
                        &Outcome::Skipped {
                            reason: format!("{} hard links; proceeding anyway", st.st_nlink),
                        },
                    );
                }
                HardLinkMode::Shred => {}
            }
        }

        if self.cfg.dry_run {
            self.report.record(display, &Outcome::Planned { kind: Kind::File });
            return;
        }

        let size = st.st_size as u64;
        let blksize = st.st_blksize as u64;

        let mut guarantee = Guarantee::Clear;
        if self.cfg.iterations > 0 || self.cfg.zero {
            let fd = match self.open_writable(dirfd, name) {
                Ok(fd) => fd,
                Err(e) => {
                    self.report.record(
                        display,
                        &Outcome::Failed {
                            stage: "open",
                            error: errno_str(e),
                        },
                    );
                    return;
                }
            };

            match wipe::wipe_fd(fd.as_fd(), size, blksize, self.cfg, self.rng) {
                Ok(res) => {
                    self.report.bytes_written = self.report.bytes_written.saturating_add(res.bytes_written);
                    guarantee = res.guarantee;
                }
                Err(e) => {
                    // §7.5 — an unwiped file is NOT deleted. A partially wiped
                    // file that is still present is recoverable and obvious; a
                    // partially wiped file that is gone is data loss with no
                    // security benefit.
                    self.report.record(
                        display,
                        &Outcome::Failed {
                            stage: "overwrite",
                            error: format!("{e}; file left in place"),
                        },
                    );
                    return;
                }
            }
        }

        if self.cfg.keep {
            self.report.record(display, &Outcome::Wiped { guarantee });
            return;
        }

        match self.obfuscate_and_remove(dirfd, name, false) {
            Ok(()) => self.report.record(
                display,
                &Outcome::Removed {
                    kind: Kind::File,
                    guarantee,
                },
            ),
            Err((stage, err)) => self.report.record(display, &Outcome::Failed { stage, error: err }),
        }
    }

    fn open_writable(
        &self,
        dirfd: BorrowedFd<'_>,
        name: &CStr,
    ) -> Result<OwnedFd, rustix::io::Errno> {
        let flags = OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        match rustix::fs::openat(dirfd, name, flags, Mode::empty()) {
            Ok(fd) => Ok(fd),
            Err(e)
                if self.cfg.force_perms
                    && (e == rustix::io::Errno::ACCESS || e == rustix::io::Errno::PERM) =>
            {
                let _ = rustix::fs::chmodat(dirfd, name, Mode::RUSR | Mode::WUSR, AtFlags::empty());
                match rustix::fs::openat(dirfd, name, flags, Mode::empty()) {
                    Ok(fd) => {
                        // Immutable flags survive chmod; clear them too. §8.3
                        if sysx::clear_immutable(fd.as_fd()) {
                            // no-op: already open
                        }
                        Ok(fd)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Rename through the ladder, then unlink. §5.2
    fn obfuscate_and_remove(
        &mut self,
        dirfd: BorrowedFd<'_>,
        name: &CStr,
        is_dir: bool,
    ) -> Result<(), (&'static str, String)> {
        let mut current = name.to_owned();

        if self.cfg.remove != RemoveMode::Unlink {
            let orig_len = name.to_bytes().len();
            let steps = name::ladder(orig_len, self.cfg.same_length_rounds, self.cfg.max_rename_steps);
            let sync_each = self.cfg.remove == RemoveMode::Wipesync;

            for len in steps {
                let mut renamed = false;
                for _ in 0..10 {
                    let candidate = name::generate(len, self.rng);
                    let cname = match CString::new(candidate) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    match rename_noreplace(dirfd, current.as_c_str(), cname.as_c_str()) {
                        Ok(()) => {
                            current = cname;
                            renamed = true;
                            break;
                        }
                        // Collision: at length 1 there are only 26 names, so
                        // this is expected, not exceptional.
                        Err(e) if e == rustix::io::Errno::EXIST => continue,
                        Err(_) => break,
                    }
                }
                if renamed && sync_each {
                    let _ = sysx::sync_dir(dirfd);
                }
            }
        }

        let flags = if is_dir {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        match rustix::fs::unlinkat(dirfd, current.as_c_str(), flags) {
            Ok(()) => {
                let _ = sysx::sync_dir(dirfd);
                Ok(())
            }
            Err(e) => {
                // We renamed it and then could not remove it. Put the name back:
                // leaving the user with a randomly-named directory full of their
                // data is worse than leaving it untouched.
                let restored = current.as_c_str() == name
                    || rename_noreplace(dirfd, current.as_c_str(), name).is_ok();
                let _ = sysx::sync_dir(dirfd);
                let note = if restored {
                    String::new()
                } else {
                    format!(
                        " (WARNING: could not restore the original name; it is now {})",
                        current.to_string_lossy()
                    )
                };
                Err(("unlink", format!("{}{note}", errno_str(e))))
            }
        }
    }
}

/// Count entries in an open directory, ignoring `.` and `..`.
/// `None` means we could not tell — which is never treated as "empty".
fn count_entries(fd: BorrowedFd<'_>) -> Option<u64> {
    let dir = Dir::read_from(fd).ok()?;
    let mut n: u64 = 0;
    for entry in dir {
        let e = entry.ok()?;
        let name = e.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        n = n.saturating_add(1);
    }
    Some(n)
}

/// `renameat` that refuses to clobber an existing entry.
///
/// Plain `rename(2)` silently replaces the destination. With a ladder that
/// descends to one-character names in a directory we are actively emptying,
/// a collision would destroy an unrelated file. RENAME_NOREPLACE (Linux) /
/// RENAME_EXCL (macOS) makes that impossible; where the kernel lacks it we
/// fall back to a check-then-rename, which is racy but strictly better than
/// an unconditional clobber.
fn rename_noreplace(dirfd: BorrowedFd<'_>, from: &CStr, to: &CStr) -> Result<(), rustix::io::Errno> {
    match rustix::fs::renameat_with(dirfd, from, dirfd, to, rustix::fs::RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(e)
            if e == rustix::io::Errno::NOSYS
                || e == rustix::io::Errno::INVAL
                || e == rustix::io::Errno::NOTSUP =>
        {
            match rustix::fs::statat(dirfd, to, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => Err(rustix::io::Errno::EXIST),
                Err(_) => rustix::fs::renameat(dirfd, from, dirfd, to),
            }
        }
        Err(e) => Err(e),
    }
}

fn open_dir_path(path: &Path) -> std::io::Result<OwnedFd> {
    let c = to_cstring(path.as_os_str())
        .ok_or_else(|| std::io::Error::other("path contains an interior NUL"))?;
    rustix::fs::open(
        c.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))
}

fn to_cstring(s: &std::ffi::OsStr) -> Option<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(s.as_bytes()).ok()
}

fn resolve_relative(link_display: &str, target: &str) -> String {
    if target.starts_with('/') {
        return target.to_string();
    }
    let base = Path::new(link_display).parent().unwrap_or(Path::new("/"));
    base.join(target).display().to_string()
}

fn errno_str(e: rustix::io::Errno) -> String {
    std::io::Error::from_raw_os_error(e.raw_os_error()).to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn relative_symlink_targets_resolve_against_the_link() {
        assert_eq!(resolve_relative("/a/b/link", "target"), "/a/b/target");
        assert_eq!(resolve_relative("/a/b/link", "../t"), "/a/b/../t");
        assert_eq!(resolve_relative("/a/b/link", "/abs"), "/abs");
    }

    #[test]
    fn interior_nul_is_rejected_not_panicked_on() {
        use std::os::unix::ffi::OsStrExt;
        let bad = std::ffi::OsStr::from_bytes(b"a\0b");
        assert!(to_cstring(bad).is_none());
    }
}

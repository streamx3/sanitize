//! Platform syscalls that differ where it matters. §6.1.
//!
//! The important one: on Darwin, `fsync(2)` does **not** flush the drive's own
//! write cache. Only `fcntl(F_FULLFSYNC)` does. Getting this wrong makes the
//! whole tool a no-op on a Mac under power loss — and `wipe` gets it wrong
//! (§14.7), because it was written for Linux 2.0.

use std::io;
use std::os::fd::BorrowedFd;

/// Flush this file's data all the way to the media, as far as the OS allows.
pub fn full_sync(fd: BorrowedFd<'_>) -> io::Result<()> {
    #[cfg(target_vendor = "apple")]
    {
        // F_FULLFSYNC: the only Darwin call that flushes the device cache.
        match rustix::fs::fcntl_fullfsync(fd) {
            Ok(()) => return Ok(()),
            Err(e) if e == rustix::io::Errno::NOTSUP || e == rustix::io::Errno::INVAL => {
                // Some filesystems (network mounts) refuse it; fall through.
            }
            Err(e) => return Err(io::Error::from_raw_os_error(e.raw_os_error())),
        }
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        if let Ok(()) = rustix::fs::fdatasync(fd) {
            return Ok(());
        }
    }
    rustix::fs::fsync(fd).map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
}

/// Ask the kernel not to keep our overwrite buffers in the page cache.
/// Best-effort: failure here is never an error worth reporting.
pub fn advise_nocache(fd: BorrowedFd<'_>) {
    #[cfg(target_vendor = "apple")]
    {
        let _ = rustix::fs::fcntl_nocache(fd, true);
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let _ = fd;
    }
}

/// fsync a directory so a rename/unlink is durable. This is what `wipesync`
/// means, and it is what we use instead of `wipe`'s global `sync()` — which
/// flushes every filesystem on the machine after *every* rename (wipe.c:579)
/// and is the reason `wipe` is unusable on large trees over USB.
pub fn sync_dir(fd: BorrowedFd<'_>) -> io::Result<()> {
    rustix::fs::fsync(fd).map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
}

pub fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// Raise the open-file limit so deep trees do not hit EMFILE. §16.2.
/// Silent on failure — this is an optimisation, not a requirement.
pub fn raise_nofile() {
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 && lim.rlim_cur < lim.rlim_max {
            lim.rlim_cur = lim.rlim_max;
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
    }
}

/// Clear immutable/append-only flags that block unlinking. `-f` and `-F`.
/// Returns true if something was actually cleared.
pub fn clear_immutable(fd: BorrowedFd<'_>) -> bool {
    #[cfg(target_vendor = "apple")]
    {
        // UF_IMMUTABLE (uchg) is clearable by the owner; SF_IMMUTABLE (schg)
        // needs root and an appropriate securelevel. Try to clear both.
        unsafe {
            let raw = fd.as_raw_fd_compat();
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(raw, &mut st) != 0 {
                return false;
            }
            let keep = st.st_flags
                & !(libc::UF_IMMUTABLE | libc::UF_APPEND | libc::SF_IMMUTABLE | libc::SF_APPEND);
            if keep == st.st_flags {
                return false;
            }
            libc::fchflags(raw, keep) == 0
        }
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let _ = fd;
        false
    }
}

/// Local helper so the raw fd extraction stays in one place.
/// Only the Apple path needs a raw fd; elsewhere it would be dead code.
#[cfg(target_vendor = "apple")]
trait AsRawFdCompat {
    fn as_raw_fd_compat(&self) -> i32;
}
#[cfg(target_vendor = "apple")]
impl AsRawFdCompat for BorrowedFd<'_> {
    fn as_raw_fd_compat(&self) -> i32 {
        use std::os::fd::{AsFd, AsRawFd};
        self.as_fd().as_raw_fd()
    }
}

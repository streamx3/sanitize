//! Interrupt handling. §16.1 item 5.
//!
//! The requirement it serves: **the summary always prints**. A destructive
//! recursive tool that dies part-way leaves the user with some data destroyed,
//! some not, and no record of which — the exact state the robustness rule
//! exists to prevent. Ctrl-C during a long run over slow media is much the
//! likeliest way to reach it, so the default disposition (immediate death, no
//! output) is not acceptable here.
//!
//! The handler does one async-signal-safe thing: bump an atomic. Everything
//! else happens at the checkpoints the walker and the wipe engine poll —
//! between directory entries, and between overwrite passes and chunks.

use std::sync::atomic::{AtomicU32, Ordering};

/// Any termination signal. Drives the graceful stop.
static HITS: AtomicU32 = AtomicU32::new(0);

/// `SIGINT` only. Drives the escalation, and must be counted separately: a
/// closing terminal can deliver `SIGHUP` *and* `SIGTERM`, which is the system
/// saying one thing twice, not the user insisting. Counting those together
/// would kill the summary in exactly the case it is most wanted.
static INT_HITS: AtomicU32 = AtomicU32::new(0);

/// True once a termination signal has been seen. Polled at every checkpoint;
/// cheap enough for the inner write loop.
pub fn requested() -> bool {
    HITS.load(Ordering::SeqCst) > 0
}

/// Should this `SIGINT` stop being polite?
///
/// Split out so the policy is testable without raising a signal at the test
/// process. The second Ctrl-C means the user is done negotiating: restore the
/// default disposition and let it through, forfeiting the summary. That is no
/// worse than the `kill -9` they would otherwise reach for, and it is only
/// reachable while a checkpoint is still out of reach — on slow removable
/// flash, where a single chunk write or `fsync` can take a long time.
fn escalates(int_hits: u32) -> bool {
    int_hits >= 2
}

extern "C" fn handler(sig: libc::c_int) {
    // Async-signal-safe only: atomics, and — on the second SIGINT — signal(2)
    // and raise(2), both of which POSIX lists as safe. No allocation, no
    // formatting, no locks, no I/O.
    HITS.fetch_add(1, Ordering::SeqCst);

    if sig == libc::SIGINT {
        let n = INT_HITS.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        if escalates(n) {
            unsafe {
                libc::signal(sig, libc::SIG_DFL);
                libc::raise(sig);
            }
        }
    }
}

/// Install handlers for the signals a user actually sends. Called before any
/// destructive work begins, so there is no window in which Ctrl-C kills the
/// process without a summary.
pub fn install() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: `sa` is zeroed before use, `handler` is an `extern "C"` fn
        // with the signature sigaction(2) expects, and mask and flags are set
        // before the struct is handed over.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handler as extern "C" fn(libc::c_int) as libc::sighandler_t;
            // SA_RESTART: resume interrupted syscalls rather than scattering
            // EINTR through the write path. We stop at explicit checkpoints,
            // not by breaking syscalls out from under themselves.
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flag starts clear, or every run would abort before doing anything.
    #[test]
    fn nothing_is_requested_before_a_signal_arrives() {
        assert!(!requested());
    }

    /// `main` calls this once, but the §8.1 escalation re-exec would call it
    /// again in the child.
    #[test]
    fn install_is_idempotent_and_does_not_set_the_flag() {
        install();
        install();
        assert!(!requested());
    }

    /// One Ctrl-C is a request; two is an instruction. The boundary is the
    /// whole policy, and getting it wrong either kills the summary on the
    /// first signal or never honours the second.
    #[test]
    fn only_the_second_interrupt_escalates() {
        assert!(!escalates(0), "no signal must not escalate");
        assert!(!escalates(1), "the first Ctrl-C stops gracefully");
        assert!(escalates(2), "the second Ctrl-C is the user insisting");
        assert!(escalates(3));
    }
}

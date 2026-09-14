//! Refusals that happen before anything is destroyed. §7.4, §16.3.
//!
//! This is the part that matters most. Rust prevents buffer overflows; nothing
//! prevents `sanitize ~/Projects` at 2am except this file.

use std::path::{Component, Path, PathBuf};

/// Absolute paths we refuse to touch without `-F`.
fn always_dangerous() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = [
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/opt",
        "/private",
        "/proc",
        "/root",
        "/sbin",
        "/srv",
        "/sys",
        "/usr",
        "/var",
        "/Applications",
        "/Library",
        "/System",
        "/Users",
        "/Volumes",
        "/nix",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();

    // The user's own home, by both name and environment. §16.3 names this
    // explicitly: -F is required for /home/$USER.
    if let Some(home) = std::env::var_os("HOME") {
        let h = PathBuf::from(home);
        if !h.as_os_str().is_empty() {
            v.push(h);
        }
    }
    if let Some(user) = std::env::var_os("USER").and_then(|u| u.into_string().ok()) {
        v.push(PathBuf::from(format!("/home/{user}")));
        v.push(PathBuf::from(format!("/Users/{user}")));
    }
    v
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Refuse until -F is given. Carries the message shown to the user.
    Refuse(String),
}

/// Normalise without touching the filesystem: absolutise against CWD and fold
/// away `.` and `..` textually. We deliberately do *not* canonicalise through
/// symlinks here — resolution happens later, per-component, under `openat`.
pub fn normalize(path: &str) -> PathBuf {
    let p = Path::new(path);
    let mut base = if p.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
    };
    for c in p.components() {
        match c {
            Component::RootDir => {
                base = PathBuf::from("/");
            }
            Component::CurDir => {}
            Component::ParentDir => {
                base.pop();
            }
            Component::Normal(seg) => base.push(seg),
            Component::Prefix(_) => {}
        }
    }
    if base.as_os_str().is_empty() {
        base.push("/");
    }
    base
}

/// Decide whether this target may be destroyed. Called once per command-line
/// argument, before any traversal.
pub fn check(target: &str, force_everything: bool) -> Verdict {
    let norm = normalize(target);

    if force_everything {
        // §16.3: -F is required *and sufficient*. No prompt, no countdown.
        return Verdict::Allow;
    }

    for danger in always_dangerous() {
        if norm == danger {
            let what = if norm == Path::new("/") {
                "the filesystem root".to_string()
            } else {
                format!("{}", norm.display())
            };
            return Verdict::Refuse(format!(
                "refusing to destroy {what} without -F\n\
                 sanitize: this is a system or home directory; if you truly mean it, re-run with -F\n\
                 sanitize: consider --dry-run first to see the scope"
            ));
        }
    }

    Verdict::Allow
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn refused(p: &str) -> bool {
        matches!(check(p, false), Verdict::Refuse(_))
    }

    #[test]
    fn root_is_refused_without_force() {
        assert!(refused("/"));
        assert!(refused("/usr"));
        assert!(refused("/System"));
        assert!(refused("/etc"));
    }

    #[test]
    fn force_everything_permits_root() {
        // §16.3 — -F is required and sufficient.
        assert_eq!(check("/", true), Verdict::Allow);
        assert_eq!(check("/System", true), Verdict::Allow);
    }

    #[test]
    fn home_is_refused_without_force() {
        // SAFETY: single-threaded test process.
        unsafe { std::env::set_var("HOME", "/Users/testuser") };
        assert!(refused("/Users/testuser"));
        assert!(!refused("/Users/testuser/scratch"));
    }

    #[test]
    fn traversal_tricks_do_not_bypass_the_guard() {
        assert!(refused("/usr/lib/.."), "textual .. must fold to /usr");
        assert!(refused("/./usr"));
        assert!(refused("/usr/"));
        assert!(refused("/tmp/../"));
    }

    #[test]
    fn ordinary_paths_are_allowed() {
        assert_eq!(check("/tmp/scratch", false), Verdict::Allow);
        assert_eq!(check("/Volumes/STICK/folder", false), Verdict::Allow);
    }

    #[test]
    fn normalize_folds_without_touching_the_filesystem() {
        assert_eq!(normalize("/a/b/../c"), PathBuf::from("/a/c"));
        assert_eq!(normalize("/a/./b"), PathBuf::from("/a/b"));
        assert_eq!(normalize("/.."), PathBuf::from("/"));
        assert_eq!(normalize("/"), PathBuf::from("/"));
    }
}

//! The configuration file. REFERENCE.md §5.
//!
//! ```text
//! hardcoded defaults  <  /etc/sanitize/default.conf  <  command line
//! ```
//!
//! Flat `key = value`, parsed in-tree. No TOML dependency: the crate denies
//! `unwrap`, `expect` and `panic`, and a config parser does not justify a new
//! supply-chain edge.
//!
//! The rule that shapes this module (REFERENCE.md §0): **the set of bytes to be
//! destroyed must be determined entirely by the command line.** A config file is
//! invisible at the call site, so a setting that can silently redirect *what
//! dies* must not live here. That is structural rather than a blocklist —
//! there is no config key for scope, so there is nothing to forget to block —
//! and naming one is a hard error rather than a silent ignore, because an
//! operator who believes a safety-relevant setting is active when it is not is
//! worse off than one whose config was rejected.
//!
//! The file itself is read and trusted. A permission check would protect
//! nothing: anyone who can write `/etc/sanitize/default.conf` can replace the
//! binary. REFERENCE.md §5.5.

use std::collections::BTreeMap;

/// The system configuration file. `--config PATH` replaces this layer;
/// `--no-config` skips it.
pub const SYSTEM_PATH: &str = "/etc/sanitize/default.conf";

/// Settings that decide *which bytes die*. Command line only, forever.
/// Listed here solely so naming one produces a useful error.
const SCOPE_KEYS: &[&str] = &[
    "force_everything",
    "follow_symlinks",
    "no_one_file_system",
    "one_file_system",
    "no_preserve_root",
    "preserve_root",
    "allow_dangerous_path",
    "hard_links",
];

/// Everything a config file may set, with the type each value must parse as.
/// Anything not in this table is an error naming the key and line.
const KNOWN_KEYS: &[(&str, Kind)] = &[
    // thoroughness
    ("iterations", Kind::U32),
    ("force_perms", Kind::Bool),
    ("exact", Kind::Bool),
    ("zero", Kind::Bool),
    ("keep", Kind::Bool),
    ("recursive", Kind::Bool),
    ("remove", Kind::RemoveMode),
    ("head", Kind::Size),
    ("tail", Kind::Size),
    ("random_source", Kind::Text),
    ("same_length_rounds", Kind::Usize),
    ("max_rename_steps", Kind::Usize),
    // out-of-tree residue (REFERENCE §0.3 — bounded, enumerable, disclosed)
    ("scrub_times", Kind::Bool),
    ("truncate_before_unlink", Kind::Bool),
    ("scrub_sidecars", Kind::Bool),
    // ceremony
    ("dry_run", Kind::Bool),
    ("verbose", Kind::U8),
    ("json", Kind::Bool),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bool,
    U8,
    U32,
    Usize,
    Size,
    Text,
    RemoveMode,
}

/// One parsed configuration file.
#[derive(Debug, Clone, Default)]
pub struct ConfigFile {
    /// Where it came from, for the disclosure line (§5.4).
    pub path: String,
    values: BTreeMap<String, String>,
}

impl ConfigFile {
    /// Read and parse `path`. `Ok(None)` means the file simply is not there,
    /// which is the normal case and not a problem.
    pub fn load(path: &str) -> Result<Option<Self>, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(Self::parse(&text, path)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{path}: {e}")),
        }
    }

    pub fn parse(text: &str, path: &str) -> Result<Self, String> {
        let mut values = BTreeMap::new();

        for (idx, raw) in text.lines().enumerate() {
            let lineno = idx + 1;
            // `#` starts a comment anywhere on the line.
            let line = match raw.split_once('#') {
                Some((before, _)) => before,
                None => raw,
            }
            .trim();
            if line.is_empty() {
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                return Err(format!(
                    "{path}:{lineno}: expected `key = value`, found `{line}`"
                ));
            };
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_string();

            if key.is_empty() {
                return Err(format!("{path}:{lineno}: empty key"));
            }
            if SCOPE_KEYS.contains(&key.as_str()) {
                return Err(format!(
                    "{path}:{lineno}: `{key}` decides which bytes are destroyed and can only be \
                     given on the command line.\n\
                     sanitize: a config file is invisible at the call site; what dies must be \
                     readable from the command that asked for it."
                ));
            }
            let Some((_, kind)) = KNOWN_KEYS.iter().find(|(k, _)| *k == key) else {
                return Err(format!(
                    "{path}:{lineno}: unknown setting `{key}`.\n\
                     sanitize: refusing to continue rather than silently ignore it — a typo here \
                     would read as \"off\"."
                ));
            };

            validate(&key, &value, *kind).map_err(|e| format!("{path}:{lineno}: {e}"))?;

            if values.insert(key.clone(), value).is_some() {
                return Err(format!("{path}:{lineno}: `{key}` set twice"));
            }
        }

        Ok(Self {
            path: path.to_string(),
            values,
        })
    }

    pub fn bool(&self, key: &str) -> Option<bool> {
        self.values.get(key).map(|v| matches!(v.as_str(), "true"))
    }

    pub fn text(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    pub fn u32(&self, key: &str) -> Option<u32> {
        self.values.get(key).and_then(|v| v.parse().ok())
    }

    pub fn u8(&self, key: &str) -> Option<u8> {
        self.values.get(key).and_then(|v| v.parse().ok())
    }

    pub fn usize(&self, key: &str) -> Option<usize> {
        self.values.get(key).and_then(|v| v.parse().ok())
    }

    /// The keys this file actually set, for the disclosure line. §5.4.
    pub fn keys(&self) -> Vec<&str> {
        self.values.keys().map(String::as_str).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

fn validate(key: &str, value: &str, kind: Kind) -> Result<(), String> {
    match kind {
        Kind::Bool => match value {
            "true" | "false" => Ok(()),
            _ => Err(format!("`{key}` must be true or false, found `{value}`")),
        },
        Kind::U8 => value
            .parse::<u8>()
            .map(|_| ())
            .map_err(|_| format!("`{key}` must be a number 0-255, found `{value}`")),
        Kind::U32 => value
            .parse::<u32>()
            .map(|_| ())
            .map_err(|_| format!("`{key}` must be a whole number, found `{value}`")),
        Kind::Usize => value
            .parse::<usize>()
            .map(|_| ())
            .map_err(|_| format!("`{key}` must be a whole number, found `{value}`")),
        Kind::Size => crate::size::parse(value)
            .map(|_| ())
            .map_err(|e| format!("`{key}`: {e}")),
        Kind::Text => Ok(()),
        Kind::RemoveMode => match value {
            "unlink" | "wipe" | "wipesync" => Ok(()),
            _ => Err(format!(
                "`{key}` must be unlink, wipe or wipesync, found `{value}`"
            )),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<ConfigFile, String> {
        ConfigFile::parse(text, "test.conf")
    }

    #[test]
    fn parses_the_shapes_a_human_writes() {
        let c = parse(
            "# leading comment\n\
             iterations = 3\n\
             \n\
             scrub_times=false   # trailing comment\n\
             	remove = wipe\n",
        )
        .unwrap();
        assert_eq!(c.u32("iterations"), Some(3));
        assert_eq!(c.bool("scrub_times"), Some(false));
        assert_eq!(c.text("remove"), Some("wipe"));
        assert_eq!(c.bool("missing"), None);
    }

    /// The whole point of §0: there is no config key for scope, so a file that
    /// names one is rejected rather than quietly ignored.
    #[test]
    fn scope_settings_are_refused_by_name() {
        for key in [
            "force_everything",
            "follow_symlinks",
            "no_one_file_system",
            "no_preserve_root",
            "hard_links",
        ] {
            let err = parse(&format!("{key} = true")).unwrap_err();
            assert!(
                err.contains("command line"),
                "{key} must be refused with an explanation, got: {err}"
            );
        }
    }

    /// A typo must not read as "off". This is the difference between a config
    /// that failed and a safety setting that silently is not active.
    #[test]
    fn unknown_keys_are_an_error_not_an_ignore() {
        let err = parse("scrub_time = false").unwrap_err();
        assert!(err.contains("unknown setting"), "{err}");
        assert!(err.contains("test.conf:1"), "must name the line: {err}");
    }

    #[test]
    fn type_errors_name_the_key_and_line() {
        assert!(
            parse("iterations = lots")
                .unwrap_err()
                .contains("whole number")
        );
        assert!(
            parse("scrub_times = yes")
                .unwrap_err()
                .contains("true or false")
        );
        assert!(
            parse("remove = obliterate")
                .unwrap_err()
                .contains("wipesync")
        );
        assert!(parse("head = 12 parsecs").unwrap_err().contains("head"));
        assert!(parse("iterations 3").unwrap_err().contains("key = value"));
        assert!(parse("\niterations = x").unwrap_err().contains(":2"));
    }

    #[test]
    fn sizes_and_duplicate_keys() {
        assert!(parse("head = 1G\ntail = 1M").is_ok());
        assert!(
            parse("keep = true\nkeep = false")
                .unwrap_err()
                .contains("twice")
        );
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        // The normal case: most systems have no /etc/sanitize/default.conf.
        assert!(
            ConfigFile::load("/nonexistent/sanitize/default.conf")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn keys_are_reported_for_disclosure() {
        let c = parse("iterations = 2\nzero = true").unwrap();
        assert_eq!(c.keys(), vec!["iterations", "zero"]);
        assert!(parse("# nothing here").unwrap().is_empty());
    }
}

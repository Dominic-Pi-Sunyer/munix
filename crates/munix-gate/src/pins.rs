//! Pins: destinations the user approved at the Console, remembered so the same value from the same source binds
//! next time without asking (trust on first use, like SSH's `known_hosts`).
//!
//! A pin is a pair `(source, value)`. The source is the host of the web page the value was read from, or the name
//! of the tool whose third-party content supplied it; the value is the destination exactly as it was sent. A pin
//! only affects domain binding (`Traced::binds`): it never rescues a value that fails the plan's `from` or
//! `min_trust` rule, and a different value from the same source, or the same value from another source, is not
//! pinned. These strings are real attacker-influenced text: they stay inside the Gate and are never written to the
//! ledger, a reason, the review view or a model's context (invariant 3). The ledger gets only [`Pins::digest`].
//!
//! The file is JSON, `{"version":1,"pins":[{"source":"..","value":".."}]}`. A missing file means no pins. A file
//! that cannot be read or parsed means no pins as well (fail closed; the Gate logs `pins_ignored`). The file must
//! live outside the Integrity Seal's roots, since adding a pin while a task runs would otherwise trip the seal
//! ([`path_in_roots`] lets the CLI refuse such a path at startup).

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::seal::Root;

/// The most pins a file may hold; adding past it is refused.
pub const MAX_PINS: usize = 10_000;

/// The longest source or value, in bytes.
pub const MAX_STRING_BYTES: usize = 512;

const VERSION: u32 = 1;

/// Why a pin could not be loaded or added.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinsError {
    /// The file exists but cannot be read.
    #[error("the pins file cannot be read")]
    Unreadable,
    /// The file is not the expected JSON, has an unknown version, or holds a bad pin.
    #[error("the pins file is malformed")]
    Malformed,
    /// The store already holds [`MAX_PINS`] pins.
    #[error("the pin store is full")]
    Full,
    /// A source or value is empty or longer than [`MAX_STRING_BYTES`].
    #[error("the pin is empty or too long")]
    BadPin,
    /// The file could not be written.
    #[error("the pins file cannot be written")]
    WriteFailed,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinWire {
    source: String,
    value: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileWire {
    version: u32,
    pins: Vec<PinWire>,
}

/// The remembered `(source, value)` pairs, optionally backed by a file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pins {
    set: BTreeSet<(String, String)>,
    path: Option<PathBuf>,
}

fn valid(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_STRING_BYTES
}

impl Pins {
    /// An empty store that is never written to disk (tests, and `Gate::set_pins` callers who persist elsewhere).
    pub fn in_memory() -> Pins {
        Pins::default()
    }

    /// Loads the store at `path`; later [`Pins::add`] calls write back to it. A missing file is an empty store. Any
    /// other problem is an error, and the caller must then run without pins (see `Gate::enable_pins`).
    pub fn load(path: &Path) -> Result<Pins, PinsError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Pins {
                    set: BTreeSet::new(),
                    path: Some(path.to_path_buf()),
                });
            }
            Err(_) => return Err(PinsError::Unreadable),
        };
        let file: FileWire = serde_json::from_str(&text).map_err(|_| PinsError::Malformed)?;
        if file.version != VERSION || file.pins.len() > MAX_PINS {
            return Err(PinsError::Malformed);
        }
        let mut set = BTreeSet::new();
        for pin in file.pins {
            if !valid(&pin.source) || !valid(&pin.value) {
                return Err(PinsError::Malformed);
            }
            set.insert((pin.source, pin.value));
        }
        Ok(Pins {
            set,
            path: Some(path.to_path_buf()),
        })
    }

    /// The file this store writes to, if any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// An empty store backed by `path` (what the Gate uses after an ignored, malformed file).
    pub fn empty_at(path: &Path) -> Pins {
        Pins {
            set: BTreeSet::new(),
            path: Some(path.to_path_buf()),
        }
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// True when this exact `(source, value)` was pinned.
    pub fn is_pinned(&self, source: &str, value: &str) -> bool {
        // Built per lookup; the store is small and lookups are rare.
        self.set.contains(&(source.to_owned(), value.to_owned()))
    }

    /// Pins `(source, value)` and, when the store has a file, writes it atomically (a temp file in the same
    /// directory, then a rename). `Ok(true)` when the pin is new, `Ok(false)` when it was already there. Refused
    /// when either string is empty or over [`MAX_STRING_BYTES`], or the store holds [`MAX_PINS`] pins. If the
    /// write fails the pin is not kept.
    pub fn add(&mut self, source: &str, value: &str) -> Result<bool, PinsError> {
        if !valid(source) || !valid(value) {
            return Err(PinsError::BadPin);
        }
        let key = (source.to_owned(), value.to_owned());
        if self.set.contains(&key) {
            return Ok(false);
        }
        if self.set.len() >= MAX_PINS {
            return Err(PinsError::Full);
        }
        self.set.insert(key.clone());
        if let Err(e) = self.persist() {
            self.set.remove(&key);
            return Err(e);
        }
        Ok(true)
    }

    fn persist(&self) -> Result<(), PinsError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = FileWire {
            version: VERSION,
            pins: self
                .set
                .iter()
                .map(|(source, value)| PinWire {
                    source: source.clone(),
                    value: value.clone(),
                })
                .collect(),
        };
        let text = serde_json::to_string(&file).map_err(|_| PinsError::WriteFailed)?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let write = || -> std::io::Result<()> {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        };
        write().map_err(|_| {
            let _ = std::fs::remove_file(&tmp);
            PinsError::WriteFailed
        })
    }

    /// The only form of a pin the ledger may hold: `sha256:` and the lowercase hex SHA-256 of
    /// `source + "\n" + value`.
    pub fn digest(source: &str, value: &str) -> String {
        let mut h = Sha256::new();
        h.update(source.as_bytes());
        h.update(b"\n");
        h.update(value.as_bytes());
        let mut out = String::from("sha256:");
        for b in h.finalize() {
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}

/// True when `path` is one of the sealed `roots` or lies under a sealed tree. Both sides are made absolute (the
/// current directory for a relative path) and the deepest existing ancestor is canonicalised, so symlinks and
/// `..` cannot hide a path inside a root. The pins file is rewritten while a task runs, so such a path would trip
/// the Integrity Seal; `munix run` refuses it at startup.
pub fn path_in_roots(path: &Path, roots: &[Root]) -> bool {
    let target = resolve(path);
    roots.iter().any(|root| match root {
        Root::File(f) => resolve(f) == target,
        Root::Tree(t) => target.starts_with(resolve(t)),
    })
}

/// An absolute path with `.`/`..` folded and symlinks resolved on the part that exists.
fn resolve(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut folded = PathBuf::new();
    for c in abs.components() {
        match c {
            std::path::Component::ParentDir => {
                folded.pop();
            }
            std::path::Component::CurDir => {}
            other => folded.push(other.as_os_str()),
        }
    }
    // Canonicalise the longest existing prefix, then re-attach the rest.
    let mut rest = Vec::new();
    let mut head = folded.clone();
    loop {
        if let Ok(real) = head.canonicalize() {
            let mut out = real;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (head.file_name().map(|n| n.to_os_string()), head.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                head = parent.to_path_buf();
            }
            _ => return folded,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("munix-pins-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("pins.json")
    }

    #[test]
    fn round_trip_and_atomic_write() {
        let path = temp("rt");
        let mut pins = Pins::load(&path).unwrap();
        assert!(pins.is_empty());
        assert!(pins.add("store.test", "a@store.test").unwrap());
        assert!(!pins.add("store.test", "a@store.test").unwrap());
        let back = Pins::load(&path).unwrap();
        assert!(back.is_pinned("store.test", "a@store.test"));
        assert!(!back.is_pinned("other.test", "a@store.test"));
        assert!(!back.is_pinned("store.test", "b@store.test"));
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn malformed_or_unknown_fields_fail() {
        let path = temp("bad");
        for text in [
            "not json",
            r#"{"version":2,"pins":[]}"#,
            r#"{"version":1,"pins":[],"extra":1}"#,
            r#"{"version":1,"pins":[{"source":"a","value":"b","x":1}]}"#,
            r#"{"version":1,"pins":[{"source":"","value":"b"}]}"#,
        ] {
            std::fs::write(&path, text).unwrap();
            assert_eq!(Pins::load(&path), Err(PinsError::Malformed), "{text}");
        }
    }

    #[test]
    fn size_limits() {
        let mut pins = Pins::in_memory();
        assert_eq!(pins.add("", "v"), Err(PinsError::BadPin));
        assert_eq!(pins.add("s", &"x".repeat(513)), Err(PinsError::BadPin));
        assert!(pins.add("s", &"x".repeat(512)).unwrap());
        for i in 0..MAX_PINS - 1 {
            pins.add("s", &format!("v{i}")).unwrap();
        }
        assert_eq!(pins.len(), MAX_PINS);
        assert_eq!(pins.add("s", "one-too-many"), Err(PinsError::Full));
        assert!(!pins.add("s", "v0").unwrap());
    }

    #[test]
    fn digest_is_stable_and_hides_the_strings() {
        let d = Pins::digest("store.test", "a@store.test");
        assert!(d.starts_with("sha256:") && d.len() == 7 + 64);
        assert!(!d.contains("store"));
        assert_ne!(d, Pins::digest("store.test", "b@store.test"));
    }

    #[test]
    fn paths_inside_roots_are_found() {
        let base = temp("roots");
        let dir = base.parent().unwrap().to_path_buf();
        let roots = [
            Root::Tree(dir.join("sealed")),
            Root::File(dir.join("f.txt")),
        ];
        assert!(path_in_roots(&dir.join("sealed/pins.json"), &roots));
        assert!(path_in_roots(&dir.join("sealed/a/../pins.json"), &roots));
        assert!(path_in_roots(&dir.join("f.txt"), &roots));
        assert!(!path_in_roots(&dir.join("sealed2/pins.json"), &roots));
        assert!(!path_in_roots(&dir.join("pins.json"), &roots));
    }
}

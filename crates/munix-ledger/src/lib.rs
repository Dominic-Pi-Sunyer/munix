//! munix-ledger: append-only, hash-chained audit log.
//!
//! The ledger is a JSON Lines file. Each line is one [`Entry`] whose `hash` is the SHA-256 of the canonical JSON of
//! `{seq, ts_ms, prev, event}`, and whose `prev` is the previous entry's hash (or the genesis value for the first).
//! Opening or verifying a file is strict: every line must be byte-for-byte what [`Ledger::append`] would have written,
//! so duplicate keys, extra whitespace, padding and partial trailing lines all fail closed.
//!
//! One writer per file is enforced with an exclusive advisory lock held for the life of the [`Ledger`].
//!
//! Known limit: a hash chain cannot detect truncation of the newest entries, nor a wholesale rewrite by someone who
//! recomputes every hash. Anchoring the head off-host (checkpoints) is future work.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const HASH_PREFIX: &str = "sha256:";

/// The `prev` of the first entry: `sha256:` followed by 64 zeros.
pub const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Everything that can go wrong reading or writing a ledger.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// An underlying I/O failure (including "file already exists" on create).
    #[error("ledger I/O error: {0}")]
    Io(#[from] io::Error),
    /// A line (1-based) that is not exactly what `append` writes, or a partial trailing line.
    #[error("malformed ledger line {line}: {reason}")]
    Malformed { line: usize, reason: String },
    /// The entry at `seq` has the wrong sequence number or does not link to the previous hash.
    #[error("ledger chain broken at seq {seq}")]
    BrokenChain { seq: u64 },
    /// The stored hash of the entry at `seq` does not match its contents.
    #[error("ledger hash mismatch at seq {seq}")]
    HashMismatch { seq: u64 },
    /// Events must be JSON objects.
    #[error("ledger events must be JSON objects")]
    NotObject,
    /// Another writer holds the exclusive lock on this file.
    #[error("ledger file is locked by another writer")]
    Locked,
}

/// One ledger line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub seq: u64,
    pub ts_ms: u64,
    pub prev: String,
    pub event: Value,
    pub hash: String,
}

fn compute_hash(seq: u64, ts_ms: u64, prev: &str, event: &Value) -> Result<String, LedgerError> {
    let canonical = json!({ "seq": seq, "ts_ms": ts_ms, "prev": prev, "event": event });
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(format!(
        "{HASH_PREFIX}{}",
        hex::encode(Sha256::digest(bytes))
    ))
}

fn to_line(entry: &Entry) -> Result<String, LedgerError> {
    let mut line =
        serde_json::to_string(entry).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    Ok(line)
}

fn malformed(line: usize, reason: &str) -> LedgerError {
    LedgerError::Malformed {
        line,
        reason: reason.to_string(),
    }
}

/// Verify a whole file's bytes and return its entries.
fn verify_bytes(bytes: &[u8]) -> Result<Vec<Entry>, LedgerError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| malformed(1, "not valid UTF-8"))?;
    if !text.ends_with('\n') {
        let line = text.split('\n').count();
        return Err(malformed(line, "partial trailing line"));
    }
    let mut entries = Vec::new();
    let mut prev = GENESIS.to_string();
    for (idx, raw) in text.split_terminator('\n').enumerate() {
        let line_no = idx + 1;
        let seq = idx as u64;
        let entry: Entry = serde_json::from_str(raw).map_err(|e| LedgerError::Malformed {
            line: line_no,
            reason: e.to_string(),
        })?;
        if to_line(&entry)?.strip_suffix('\n') != Some(raw) {
            return Err(malformed(line_no, "line is not in canonical form"));
        }
        if entry.seq != seq || entry.prev != prev {
            return Err(LedgerError::BrokenChain { seq });
        }
        if compute_hash(entry.seq, entry.ts_ms, &entry.prev, &entry.event)? != entry.hash {
            return Err(LedgerError::HashMismatch { seq });
        }
        prev = entry.hash.clone();
        entries.push(entry);
    }
    Ok(entries)
}

/// Verify a ledger file without opening it for append. Returns the number of entries.
pub fn verify_file(path: impl AsRef<Path>) -> Result<usize, LedgerError> {
    let bytes = std::fs::read(path)?;
    Ok(verify_bytes(&bytes)?.len())
}

fn lock(file: &File) -> Result<(), LedgerError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(LedgerError::Locked),
        Err(TryLockError::Error(e)) => Err(LedgerError::Io(e)),
    }
}

/// An open, locked, append-only ledger.
#[derive(Debug)]
pub struct Ledger {
    file: File,
    entries: Vec<Entry>,
    head: String,
    /// Length in bytes of the verified content, used to roll back a failed write.
    len_bytes: u64,
}

impl Ledger {
    /// Create a new, empty ledger. Fails if the file already exists.
    pub fn create(path: impl AsRef<Path>) -> Result<Ledger, LedgerError> {
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(path)?;
        lock(&file)?;
        Ok(Ledger {
            file,
            entries: Vec::new(),
            head: GENESIS.to_string(),
            len_bytes: 0,
        })
    }

    /// Open an existing ledger for appending, after verifying the whole chain.
    pub fn open(path: impl AsRef<Path>) -> Result<Ledger, LedgerError> {
        let mut file = OpenOptions::new().read(true).append(true).open(path)?;
        lock(&file)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let entries = verify_bytes(&bytes)?;
        let head = entries
            .last()
            .map_or_else(|| GENESIS.to_string(), |e| e.hash.clone());
        Ok(Ledger {
            file,
            entries,
            head,
            len_bytes: bytes.len() as u64,
        })
    }

    /// Append one event (a JSON object) and sync it to disk before returning.
    pub fn append(&mut self, event: Value) -> Result<Entry, LedgerError> {
        if !event.is_object() {
            return Err(LedgerError::NotObject);
        }
        let seq = self.entries.len() as u64;
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let hash = compute_hash(seq, ts_ms, &self.head, &event)?;
        let entry = Entry {
            seq,
            ts_ms,
            prev: self.head.clone(),
            event,
            hash,
        };
        let line = to_line(&entry)?;
        let written = self
            .file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.sync_data());
        if let Err(e) = written {
            // Best effort: do not leave a partial line that would poison the next append.
            let _ = self.file.set_len(self.len_bytes);
            return Err(LedgerError::Io(e));
        }
        self.len_bytes += line.len() as u64;
        self.head = entry.hash.clone();
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// All entries, oldest first.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Hash of the last entry, or the genesis value for an empty ledger.
    pub fn head(&self) -> &str {
        &self.head
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no entries have been appended.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

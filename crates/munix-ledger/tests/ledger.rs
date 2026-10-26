#![allow(clippy::unwrap_used, clippy::expect_used)] // test helpers outside #[test] fns
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use munix_ledger::{Entry, GENESIS, Ledger, LedgerError, verify_file};
use serde_json::json;
use sha2::Digest;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique temp directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "munix-ledger-test-{}-{n}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    fn file(&self) -> PathBuf {
        self.0.join("ledger.jsonl")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Write a ledger with `n` entries, close it, and return its lines.
fn make(path: &Path, n: usize) -> Vec<String> {
    let mut l = Ledger::create(path).unwrap();
    for i in 0..n {
        l.append(json!({"kind": "test", "i": i})).unwrap();
    }
    drop(l);
    lines(path)
}

fn lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

fn write_lines(path: &Path, ls: &[String]) {
    let mut s = ls.join("\n");
    s.push('\n');
    fs::write(path, s).unwrap();
}

fn parse(line: &str) -> Entry {
    serde_json::from_str(line).unwrap()
}

#[test]
fn append_and_reopen_round_trip() {
    let d = TempDir::new();
    let mut l = Ledger::create(d.file()).unwrap();
    assert!(l.is_empty());
    assert_eq!(l.head(), GENESIS);
    let e0 = l.append(json!({"a": 1, "z": [1.5, null]})).unwrap();
    let e1 = l.append(json!({"b": "two"})).unwrap();
    assert_eq!((e0.seq, e1.seq), (0, 1));
    assert_eq!(l.len(), 2);
    assert_eq!(l.head(), e1.hash);
    drop(l);

    let mut l = Ledger::open(d.file()).unwrap();
    assert_eq!(l.entries(), &[e0, e1.clone()]);
    assert_eq!(l.head(), e1.hash);
    let e2 = l.append(json!({"c": true})).unwrap();
    assert_eq!(e2.seq, 2);
    assert_eq!(e2.prev, e1.hash);
    drop(l);
    assert_eq!(verify_file(d.file()).unwrap(), 3);
}

#[test]
fn create_fails_if_file_exists() {
    let d = TempDir::new();
    make(&d.file(), 1);
    assert!(matches!(Ledger::create(d.file()), Err(LedgerError::Io(_))));
}

#[test]
fn hashes_chain() {
    let d = TempDir::new();
    make(&d.file(), 5);
    let l = Ledger::open(d.file()).unwrap();
    assert_eq!(l.entries()[0].prev, GENESIS);
    for w in l.entries().windows(2) {
        assert_eq!(w[1].prev, w[0].hash);
        assert_eq!(w[1].seq, w[0].seq + 1);
    }
    for e in l.entries() {
        assert!(e.hash.starts_with("sha256:"));
        let hex = &e.hash["sha256:".len()..];
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }
}

#[test]
fn empty_file_is_valid() {
    let d = TempDir::new();
    drop(Ledger::create(d.file()).unwrap());
    assert_eq!(verify_file(d.file()).unwrap(), 0);
    let l = Ledger::open(d.file()).unwrap();
    assert_eq!(l.len(), 0);
    assert_eq!(l.head(), GENESIS);
}

#[test]
fn edited_event_detected() {
    let d = TempDir::new();
    let mut ls = make(&d.file(), 4);
    ls[2] = ls[2].replace("\"i\":2", "\"i\":99");
    write_lines(&d.file(), &ls);
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::HashMismatch { seq: 2 })
    ));
    assert!(matches!(
        Ledger::open(d.file()),
        Err(LedgerError::HashMismatch { seq: 2 })
    ));
}

#[test]
fn changed_hash_detected() {
    let d = TempDir::new();
    let mut ls = make(&d.file(), 3);
    let mut e = parse(&ls[1]);
    e.hash = format!("sha256:{}", "ab".repeat(32));
    ls[1] = serde_json::to_string(&e).unwrap();
    write_lines(&d.file(), &ls);
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::HashMismatch { seq: 1 })
    ));
}

#[test]
fn deleted_line_detected() {
    let d = TempDir::new();
    let mut ls = make(&d.file(), 4);
    ls.remove(1);
    write_lines(&d.file(), &ls);
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::BrokenChain { seq: 1 })
    ));

    let mut ls = make_again(&d, 3);
    ls.remove(0);
    write_lines(&d.file(), &ls);
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::BrokenChain { seq: 0 })
    ));
}

fn make_again(d: &TempDir, n: usize) -> Vec<String> {
    fs::remove_file(d.file()).unwrap();
    make(&d.file(), n)
}

#[test]
fn swapped_lines_detected() {
    let d = TempDir::new();
    let mut ls = make(&d.file(), 4);
    ls.swap(1, 2);
    write_lines(&d.file(), &ls);
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::BrokenChain { seq: 1 })
    ));
}

#[test]
fn duplicated_line_detected() {
    let d = TempDir::new();
    let mut ls = make(&d.file(), 3);
    let dup = ls[1].clone();
    ls.insert(2, dup);
    write_lines(&d.file(), &ls);
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::BrokenChain { seq: 2 })
    ));
}

#[test]
fn wrong_genesis_detected() {
    let d = TempDir::new();
    let mut ls = make(&d.file(), 2);
    let mut e = parse(&ls[0]);
    e.prev = format!("sha256:{}", "1".repeat(64));
    ls[0] = serde_json::to_string(&e).unwrap();
    write_lines(&d.file(), &ls);
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::BrokenChain { seq: 0 })
    ));
}

#[test]
fn inserted_forged_line_detected() {
    let d = TempDir::new();
    let mut ls = make(&d.file(), 3);
    let mut forged = parse(&ls[0]);
    forged.seq = 1;
    forged.event = json!({"kind": "forged"});
    ls.insert(1, serde_json::to_string(&forged).unwrap());
    write_lines(&d.file(), &ls);
    // Right seq and prev, wrong hash.
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::BrokenChain { seq: 1 })
    ));
}

#[test]
fn rehashed_edit_breaks_next_link() {
    // An attacker who edits entry 1 and recomputes its hash still breaks entry 2's `prev`.
    let d = TempDir::new();
    let mut ls = make(&d.file(), 3);
    let mut e = parse(&ls[1]);
    e.event = json!({"kind": "forged"});
    let canonical = json!({"seq": e.seq, "ts_ms": e.ts_ms, "prev": e.prev, "event": e.event});
    let digest = sha2::Sha256::digest(serde_json::to_vec(&canonical).unwrap());
    e.hash = format!("sha256:{}", hex::encode(digest));
    ls[1] = serde_json::to_string(&e).unwrap();
    write_lines(&d.file(), &ls);
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::BrokenChain { seq: 2 })
    ));
}

#[test]
fn trailing_partial_line_rejected() {
    let d = TempDir::new();
    make(&d.file(), 2);
    let mut bytes = fs::read(d.file()).unwrap();
    bytes.extend_from_slice(b"{\"seq\":2,\"ts_ms\":1");
    fs::write(d.file(), &bytes).unwrap();
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::Malformed { line: 3, .. })
    ));
    assert!(matches!(
        Ledger::open(d.file()),
        Err(LedgerError::Malformed { .. })
    ));

    // A valid last line missing only its newline is also a partial write: fail closed.
    let d2 = TempDir::new();
    make(&d2.file(), 2);
    let mut bytes = fs::read(d2.file()).unwrap();
    bytes.pop();
    fs::write(d2.file(), &bytes).unwrap();
    assert!(matches!(
        verify_file(d2.file()),
        Err(LedgerError::Malformed { .. })
    ));
}

#[test]
fn non_canonical_lines_rejected() {
    let d = TempDir::new();
    let ls = make(&d.file(), 2);

    // Extra whitespace.
    let mut v = ls.clone();
    v[0] = v[0].replacen("{", "{ ", 1);
    write_lines(&d.file(), &v);
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::Malformed { line: 1, .. })
    ));

    // Duplicate key.
    let mut v = ls.clone();
    v[1] = v[1].replacen("{", "{\"seq\":1,", 1);
    write_lines(&d.file(), &v);
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::Malformed { line: 2, .. })
    ));

    // Unknown field.
    let mut v = ls.clone();
    v[1] = v[1].replacen("{", "{\"extra\":1,", 1);
    write_lines(&d.file(), &v);
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::Malformed { line: 2, .. })
    ));

    // Blank line.
    let mut v = ls.clone();
    v.insert(1, String::new());
    write_lines(&d.file(), &v);
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::Malformed { line: 2, .. })
    ));

    // CRLF endings.
    let crlf = format!("{}\r\n{}\r\n", ls[0], ls[1]);
    fs::write(d.file(), crlf).unwrap();
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::Malformed { .. })
    ));

    // Garbage.
    fs::write(d.file(), "not json\n").unwrap();
    assert!(matches!(
        verify_file(d.file()),
        Err(LedgerError::Malformed { line: 1, .. })
    ));
}

#[test]
fn non_object_event_rejected() {
    let d = TempDir::new();
    let mut l = Ledger::create(d.file()).unwrap();
    for bad in [json!(1), json!("s"), json!([1]), json!(null), json!(true)] {
        assert!(matches!(l.append(bad), Err(LedgerError::NotObject)));
    }
    assert_eq!(l.len(), 0);
    drop(l);
    assert_eq!(verify_file(d.file()).unwrap(), 0);
}

#[test]
fn second_writer_is_locked_out_until_first_drops() {
    let d = TempDir::new();
    let mut first = Ledger::create(d.file()).unwrap();
    first.append(json!({"x": 1})).unwrap();
    assert!(matches!(Ledger::open(d.file()), Err(LedgerError::Locked)));
    first.append(json!({"x": 2})).unwrap();
    drop(first);
    let mut second = Ledger::open(d.file()).unwrap();
    assert_eq!(second.len(), 2);
    assert!(matches!(Ledger::open(d.file()), Err(LedgerError::Locked)));
    second.append(json!({"x": 3})).unwrap();
}

#[test]
fn verify_file_counts_entries() {
    let d = TempDir::new();
    make(&d.file(), 7);
    assert_eq!(verify_file(d.file()).unwrap(), 7);
    assert!(matches!(
        verify_file(d.0.join("missing")),
        Err(LedgerError::Io(_))
    ));
}

#[test]
fn floats_survive_reopen() {
    let d = TempDir::new();
    let mut l = Ledger::create(d.file()).unwrap();
    l.append(json!({"f": 0.1, "g": 1e300, "h": -2.5e-7}))
        .unwrap();
    drop(l);
    assert_eq!(Ledger::open(d.file()).unwrap().len(), 1);
}

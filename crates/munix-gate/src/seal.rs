//! The Integrity Seal (invariant 11): Munix's own code is sealed while a task runs.
//!
//! At task start [`Seal::take`] records every sealed file: its SHA-256, size, mtime and, on Unix, its ctime and
//! inode. [`Seal::verify`] compares only the `stat` fields, so it is cheap enough to run before every `execute` and
//! from a watcher thread twice a second. Any write moves mtime and ctime even when the content is put back, so an
//! edit-and-revert between two checks still trips; a rename-over changes the inode. The digest is hashed only to
//! report what changed. A file that can't be read fails closed.
//!
//! The seal detects tampering; preventing it is OS isolation (design spec section 9).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use sha2::{Digest as _, Sha256};

/// Directory names a [`Root::Tree`] never descends into: build output, VCS data and caches written at run time.
pub const SKIP_DIRS: &[&str] = &[
    "target",
    ".git",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "venv",
    ".venv",
    "cache",
];

/// What to seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Root {
    /// One file. A missing file is sealed as absent: creating it later trips the seal.
    File(PathBuf),
    /// Every regular file under a directory, recursively, skipping [`SKIP_DIRS`]. Symlinked directories are not
    /// followed; symlinked files are sealed by what they point to. A missing directory is sealed as empty.
    Tree(PathBuf),
}

/// One sealed file, as `take` saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    /// Lowercase hex SHA-256 of the content.
    sha256: String,
    len: u64,
    modified: Option<SystemTime>,
    /// Unix only (`MetadataExt::ctime`, `ctime_nsec`, `ino`); `None` elsewhere.
    ctime: Option<(i64, i64)>,
    ino: Option<u64>,
}

/// What changed. Digests are lowercase hex SHA-256; `None` means absent or unreadable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tamper {
    pub path: String,
    pub old: Option<String>,
    pub new: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("cannot read {path}: {source}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// The sealed set.
#[derive(Debug, Clone)]
pub struct Seal {
    roots: Vec<Root>,
    files: BTreeMap<PathBuf, Stamp>,
    digest: String,
}

impl Seal {
    /// Walks `roots` and stamps every file. Paths are kept as given (joined under a tree's root), and a file reached
    /// through two roots is stamped once. Any file that exists but can't be read or hashed is an error (fail
    /// closed).
    pub fn take(roots: Vec<Root>) -> Result<Seal, SealError> {
        let mut paths = BTreeSet::new();
        for root in &roots {
            match root {
                Root::File(path) => match fs::metadata(path) {
                    Ok(_) => {
                        paths.insert(path.clone());
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(SealError::Unreadable {
                            path: path.clone(),
                            source,
                        });
                    }
                },
                Root::Tree(dir) => {
                    walk_tree_take(dir, &mut paths)?;
                }
            }
        }
        let mut files = BTreeMap::new();
        for path in paths {
            let stamp = stamp_file(&path)?;
            files.insert(path, stamp);
        }
        let digest = compute_digest(&files);
        Ok(Seal {
            roots,
            files,
            digest,
        })
    }

    /// The seal digest for the ledger: lowercase hex SHA-256 over one line per file, sorted by path,
    /// `"<path>\t<sha256>\t<len>\n"`. Content only, never times, so the same files give the same digest.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// How many files are sealed.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Re-walks the roots and compares `stat` fields (size, mtime, ctime, inode) with the stamps. The first
    /// difference in path order is returned:
    /// - a sealed file whose fields differ: `old` is its stamp's digest, `new` the file's digest now (`None` if it
    ///   can no longer be read);
    /// - a sealed file that is gone: `new: None`;
    /// - a new file under a tree, or a sealed-absent `File` that now exists: `old: None`;
    /// - a file that can't be stat'ed: `new: None`.
    pub fn verify(&self) -> Result<(), Tamper> {
        let mut current = BTreeSet::new();
        for root in &self.roots {
            match root {
                Root::File(path) => match fs::metadata(path) {
                    Ok(_) => {
                        current.insert(path.clone());
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => {
                        current.insert(path.clone());
                    }
                },
                Root::Tree(dir) => {
                    walk_tree_verify(dir, &mut current);
                }
            }
        }
        let mut all_paths: BTreeSet<&PathBuf> = self.files.keys().collect();
        all_paths.extend(current.iter());

        for path in all_paths {
            match (self.files.get(path), current.contains(path)) {
                (Some(stamp), true) => {
                    let same = fs::metadata(path).is_ok_and(|meta| stat_matches(&meta, stamp));
                    if !same {
                        return Err(Tamper {
                            path: path.to_string_lossy().into_owned(),
                            old: Some(stamp.sha256.clone()),
                            new: hash_file(path).ok(),
                        });
                    }
                }
                (Some(stamp), false) => {
                    return Err(Tamper {
                        path: path.to_string_lossy().into_owned(),
                        old: Some(stamp.sha256.clone()),
                        new: None,
                    });
                }
                (None, true) => {
                    return Err(Tamper {
                        path: path.to_string_lossy().into_owned(),
                        old: None,
                        new: hash_file(path).ok(),
                    });
                }
                (None, false) => {}
            }
        }
        Ok(())
    }
}

fn walk_tree_take(dir: &Path, paths: &mut BTreeSet<PathBuf>) -> Result<(), SealError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(SealError::Unreadable {
                path: dir.to_path_buf(),
                source,
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| SealError::Unreadable {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let sym_meta = fs::symlink_metadata(&path).map_err(|source| SealError::Unreadable {
            path: path.clone(),
            source,
        })?;
        let ft = sym_meta.file_type();
        if ft.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && SKIP_DIRS.contains(&name)
            {
                continue;
            }
            walk_tree_take(&path, paths)?;
        } else if ft.is_file() {
            paths.insert(path);
        } else if ft.is_symlink() {
            let target_meta = fs::metadata(&path).map_err(|source| SealError::Unreadable {
                path: path.clone(),
                source,
            })?;
            if target_meta.is_file() {
                paths.insert(path);
            }
        }
    }
    Ok(())
}

fn walk_tree_verify(dir: &Path, paths: &mut BTreeSet<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return,
        Err(_) => {
            paths.insert(dir.to_path_buf());
            return;
        }
    };
    for entry in entries {
        let Ok(entry) = entry else {
            paths.insert(dir.to_path_buf());
            continue;
        };
        let path = entry.path();
        let Ok(sym_meta) = fs::symlink_metadata(&path) else {
            paths.insert(path);
            continue;
        };
        let ft = sym_meta.file_type();
        if ft.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && SKIP_DIRS.contains(&name)
            {
                continue;
            }
            walk_tree_verify(&path, paths);
        } else if ft.is_file() {
            paths.insert(path);
        } else if ft.is_symlink() {
            match fs::metadata(&path) {
                Ok(target_meta) => {
                    if target_meta.is_file() {
                        paths.insert(path);
                    }
                }
                Err(_) => {
                    paths.insert(path);
                }
            }
        }
    }
}

fn stamp_file(path: &Path) -> Result<Stamp, SealError> {
    let meta = fs::metadata(path).map_err(|source| SealError::Unreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let sha256 = hash_file(path).map_err(|source| SealError::Unreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let (ctime, ino) = unix_stat(&meta);
    Ok(Stamp {
        sha256,
        len: meta.len(),
        modified: meta.modified().ok(),
        ctime,
        ino,
    })
}

fn hash_file(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

#[cfg(unix)]
fn unix_stat(meta: &fs::Metadata) -> (Option<(i64, i64)>, Option<u64>) {
    use std::os::unix::fs::MetadataExt;
    (Some((meta.ctime(), meta.ctime_nsec())), Some(meta.ino()))
}

#[cfg(not(unix))]
fn unix_stat(_meta: &fs::Metadata) -> (Option<(i64, i64)>, Option<u64>) {
    (None, None)
}

fn stat_matches(meta: &fs::Metadata, stamp: &Stamp) -> bool {
    let (ctime, ino) = unix_stat(meta);
    meta.len() == stamp.len
        && meta.modified().ok() == stamp.modified
        && ctime == stamp.ctime
        && ino == stamp.ino
}

fn compute_digest(files: &BTreeMap<PathBuf, Stamp>) -> String {
    let mut hasher = Sha256::new();
    for (path, stamp) in files {
        let line = format!(
            "{}\t{}\t{}\n",
            path.to_string_lossy(),
            stamp.sha256,
            stamp.len
        );
        hasher.update(line.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// The check the Gate runs before every `execute`. A trait so tests can supply their own.
pub trait SealCheck: Send + Sync {
    /// The seal digest, recorded in `task_started`.
    fn digest(&self) -> String;
    /// `Err` once anything sealed has changed.
    fn verify(&self) -> Result<(), Tamper>;
}

/// A [`Seal`] shared by the Gate and the watcher. Once a check fails it stays failed: every later `verify` returns
/// the first [`Tamper`], even if the file is put back.
pub struct SealGuard {
    seal: Seal,
    tripped: Mutex<Option<Tamper>>,
}

impl SealGuard {
    pub fn new(seal: Seal) -> SealGuard {
        SealGuard {
            seal,
            tripped: Mutex::new(None),
        }
    }
}

impl SealCheck for SealGuard {
    fn digest(&self) -> String {
        self.seal.digest().to_owned()
    }
    fn verify(&self) -> Result<(), Tamper> {
        let mut guard = match self.tripped.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(tamper) = &*guard {
            return Err(tamper.clone());
        }
        if let Err(tamper) = self.seal.verify() {
            *guard = Some(tamper.clone());
            return Err(tamper);
        }
        Ok(())
    }
}

/// The watcher: a thread that runs `check.verify()` every `poll` and, on the first failure, calls `on_tamper` once
/// and exits. Dropping it (or `stop`) stops it without calling `on_tamper`. Same shape as the runtime's watchdog.
pub struct SealWatch {
    stopped: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl SealWatch {
    pub fn start(
        check: Arc<dyn SealCheck>,
        poll: Duration,
        on_tamper: Box<dyn FnOnce(Tamper) + Send>,
    ) -> SealWatch {
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_stopped = Arc::clone(&stopped);
        let handle = thread::spawn(move || {
            while !thread_stopped.load(Ordering::Acquire) {
                thread::sleep(poll);
                if thread_stopped.load(Ordering::Acquire) {
                    break;
                }
                if let Err(tamper) = check.verify() {
                    if !thread_stopped.load(Ordering::Acquire) {
                        on_tamper(tamper);
                    }
                    break;
                }
            }
        });
        SealWatch {
            stopped,
            handle: Some(handle),
        }
    }

    /// Stops the thread and waits for it.
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for SealWatch {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::time::{Instant, UNIX_EPOCH};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "munix-seal-test-{}-{n}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn unchanged_tree_verifies_ok_and_digest_is_stable() {
        let tmp = TempDir::new();
        let a = tmp.path().join("a.txt");
        let sub = tmp.path().join("sub");
        fs::create_dir_all(&sub).unwrap();
        let b = sub.join("b.txt");
        fs::write(&a, b"alpha").unwrap();
        fs::write(&b, b"beta").unwrap();

        let seal1 = Seal::take(vec![
            Root::Tree(tmp.path().to_path_buf()),
            Root::File(a.clone()),
        ])
        .unwrap();
        let seal2 = Seal::take(vec![Root::Tree(tmp.path().to_path_buf())]).unwrap();

        assert_eq!(seal1.file_count(), 2);
        assert_eq!(seal1.digest(), seal2.digest());
        assert_eq!(seal1.verify(), Ok(()));
    }

    #[test]
    fn editing_a_file_trips_with_old_and_new_digests() {
        let tmp = TempDir::new();
        let f = tmp.path().join("code.rs");
        fs::write(&f, b"fn main() {}").unwrap();

        let seal = Seal::take(vec![Root::File(f.clone())]).unwrap();
        fs::write(&f, b"fn main() { panic!(); }").unwrap();

        let err = seal.verify().unwrap_err();
        assert_eq!(err.path, f.to_string_lossy());
        assert!(err.old.is_some());
        assert!(err.new.is_some());
        assert_ne!(err.old, err.new);
        assert_eq!(
            err.old.unwrap(),
            hex::encode(Sha256::digest(b"fn main() {}"))
        );
        assert_eq!(
            err.new.unwrap(),
            hex::encode(Sha256::digest(b"fn main() { panic!(); }"))
        );
    }

    #[test]
    fn editing_and_writing_back_original_bytes_still_trips() {
        let tmp = TempDir::new();
        let f = tmp.path().join("config.yaml");
        fs::write(&f, b"tier: 3\n").unwrap();

        let seal = Seal::take(vec![Root::File(f.clone())]).unwrap();
        thread::sleep(Duration::from_millis(20));
        fs::write(&f, b"tier: 0\n").unwrap();
        fs::write(&f, b"tier: 3\n").unwrap();

        let err = seal.verify().unwrap_err();
        assert_eq!(err.path, f.to_string_lossy());
        let expected = hex::encode(Sha256::digest(b"tier: 3\n"));
        assert_eq!(err.old.as_deref(), Some(expected.as_str()));
        assert_eq!(err.new.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn deleting_a_file_trips_with_new_none() {
        let tmp = TempDir::new();
        let f = tmp.path().join("manifest.yaml");
        fs::write(&f, b"tool: web.open\n").unwrap();

        let seal = Seal::take(vec![Root::Tree(tmp.path().to_path_buf())]).unwrap();
        fs::remove_file(&f).unwrap();

        let err = seal.verify().unwrap_err();
        assert_eq!(err.path, f.to_string_lossy());
        assert_eq!(
            err.old,
            Some(hex::encode(Sha256::digest(b"tool: web.open\n")))
        );
        assert_eq!(err.new, None);
    }

    #[test]
    fn adding_a_file_to_a_tree_trips_with_old_none() {
        let tmp = TempDir::new();
        let f1 = tmp.path().join("one.txt");
        fs::write(&f1, b"1").unwrap();

        let seal = Seal::take(vec![Root::Tree(tmp.path().to_path_buf())]).unwrap();
        let f2 = tmp.path().join("two.txt");
        fs::write(&f2, b"2").unwrap();

        let err = seal.verify().unwrap_err();
        assert_eq!(err.path, f2.to_string_lossy());
        assert_eq!(err.old, None);
        assert_eq!(err.new, Some(hex::encode(Sha256::digest(b"2"))));
    }

    #[test]
    fn absent_file_root_created_later_trips_with_old_none() {
        let tmp = TempDir::new();
        let absent = tmp.path().join("absent.yaml");

        let seal = Seal::take(vec![Root::File(absent.clone())]).unwrap();
        assert_eq!(seal.file_count(), 0);
        assert_eq!(seal.verify(), Ok(()));

        fs::write(&absent, b"created").unwrap();
        let err = seal.verify().unwrap_err();
        assert_eq!(err.path, absent.to_string_lossy());
        assert_eq!(err.old, None);
        assert_eq!(err.new, Some(hex::encode(Sha256::digest(b"created"))));
    }

    #[test]
    fn skipped_dirs_are_not_sealed() {
        let tmp = TempDir::new();
        let src = tmp.path().join("src");
        let target = tmp.path().join("target");
        let pycache = tmp.path().join("__pycache__");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&pycache).unwrap();

        fs::write(src.join("lib.rs"), b"pub fn ok() {}").unwrap();
        fs::write(target.join("artifact.o"), b"bin").unwrap();
        fs::write(pycache.join("mod.pyc"), b"pyc").unwrap();

        let seal = Seal::take(vec![Root::Tree(tmp.path().to_path_buf())]).unwrap();
        assert_eq!(seal.file_count(), 1);

        // Modifying or adding inside skipped dirs does not trip the seal.
        fs::write(target.join("artifact.o"), b"changed").unwrap();
        fs::write(pycache.join("new.pyc"), b"new").unwrap();
        assert_eq!(seal.verify(), Ok(()));
    }

    #[test]
    fn seal_guard_stays_tripped_after_file_is_restored() {
        let tmp = TempDir::new();
        let f = tmp.path().join("guard.txt");
        fs::write(&f, b"original").unwrap();

        let seal = Seal::take(vec![Root::File(f.clone())]).unwrap();
        let guard = SealGuard::new(seal);
        assert_eq!(guard.verify(), Ok(()));

        fs::remove_file(&f).unwrap();
        let first_err = guard.verify().unwrap_err();
        assert_eq!(first_err.new, None);

        // Even if we write a new file with different content, SealGuard returns the cached first Tamper.
        fs::write(&f, b"original").unwrap();
        let second_err = guard.verify().unwrap_err();
        assert_eq!(second_err, first_err);
    }

    #[test]
    fn seal_watch_calls_on_tamper_once_and_never_if_stopped_first() {
        let tmp = TempDir::new();
        let f = tmp.path().join("watched.txt");
        fs::write(&f, b"clean").unwrap();

        let seal = Seal::take(vec![Root::File(f.clone())]).unwrap();
        let guard: Arc<dyn SealCheck> = Arc::new(SealGuard::new(seal));

        let calls = Arc::new(AtomicU32::new(0));
        let recorded = Arc::new(Mutex::new(None));
        let calls_clone = Arc::clone(&calls);
        let recorded_clone = Arc::clone(&recorded);

        let watch = SealWatch::start(
            Arc::clone(&guard),
            Duration::from_millis(20),
            Box::new(move |t| {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                *recorded_clone.lock().unwrap() = Some(t);
            }),
        );

        fs::write(&f, b"tampered").unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        while calls.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            recorded.lock().unwrap().as_ref().unwrap().path,
            f.to_string_lossy()
        );
        watch.stop();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Second watcher: stopped before any change happens -> never calls on_tamper.
        let f2 = tmp.path().join("watched2.txt");
        fs::write(&f2, b"clean2").unwrap();
        let seal2 = Seal::take(vec![Root::File(f2.clone())]).unwrap();
        let guard2: Arc<dyn SealCheck> = Arc::new(SealGuard::new(seal2));
        let calls2 = Arc::new(AtomicU32::new(0));
        let calls2_clone = Arc::clone(&calls2);

        let watch2 = SealWatch::start(
            guard2,
            Duration::from_millis(20),
            Box::new(move |_| {
                calls2_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );
        watch2.stop();
        fs::write(&f2, b"tampered2").unwrap();
        thread::sleep(Duration::from_millis(50));
        assert_eq!(calls2.load(Ordering::SeqCst), 0);
    }
}

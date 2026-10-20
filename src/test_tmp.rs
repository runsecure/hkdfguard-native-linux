//! Test-only: where the test suites make their temp directories.
//!
//! Not the system temp dir. `/tmp` (and `/var/tmp`, `/dev/shm`) is sticky
//! and world-writable, and the library refuses every file it reads -- key
//! files, policies, secrets, PINs -- anywhere beneath such a directory
//! (`secure_file::check_dir_chain`), so tests that use them -- and the
//! CLI's `wrap` and `--dek-file`, which refuse them there too -- need a
//! root nobody else can write into, all the way up to `/`.
//!
//! The root is, in order:
//!
//! 1. `HKDFGUARD_TEST_TMPDIR`, if set (created `0700` if missing);
//! 2. for integration tests, `CARGO_TARGET_TMPDIR` (`<target>/tmp`);
//! 3. for unit tests, which cargo gives no such directory, `tmp` beside
//!    the test executable's profile directory (`<target>/tmp` again, or
//!    `<target>/<triple>/tmp` for a cross build);
//!
//! and in cases 2 and 3 a private `hkdfguard-tests` directory inside it.
//! Directories this process owns between the target directory and that
//! root are made not group/other-writable (a `002` umask would otherwise
//! leave them `0775`); nothing outside the target directory is changed. If
//! a directory above is still writable by group or others (a checkout in a
//! shared directory, say), the first call panics naming it, rather than
//! letting every key-file test fail with a bare `FILE_UNTRUSTED`.
//!
//! Shared, by `#[path]`, between the library's unit tests, the CLI's, and
//! the integration tests under `tests/`; each uses only part of it.
#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// A fresh `0700` directory under [`root`], removed when dropped.
pub fn private_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(root())
        .unwrap()
}

/// The trusted root every test temp directory goes in; see the module docs.
pub fn root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = match std::env::var_os("HKDFGUARD_TEST_TMPDIR") {
            Some(dir) => {
                let dir = PathBuf::from(dir);
                make_private_dir(&dir);
                dir
            }
            None => {
                let (anchor, tmp) = default_tmp();
                let root = tmp.join("hkdfguard-tests");
                make_private_dir(&root);
                tighten_owned_dirs(&anchor, &root);
                root
            }
        };
        let root = fs::canonicalize(&root).unwrap_or_else(|e| panic!("test temp root {}: {e}", root.display()));
        check_chain(&root);
        root
    })
}

// (the target directory, the temp dir in it).
fn default_tmp() -> (PathBuf, PathBuf) {
    if let Some(tmp) = option_env!("CARGO_TARGET_TMPDIR") {
        let tmp = PathBuf::from(tmp);
        let anchor = tmp.parent().map(Path::to_path_buf).unwrap_or_else(|| tmp.clone());
        return (anchor, tmp);
    }
    // <target>[/<triple>]/<profile>/deps/<test executable>
    let exe = std::env::current_exe().expect("the test executable's path");
    let Some(anchor) = exe.ancestors().nth(3) else {
        panic!("{} is not in a cargo target directory; set HKDFGUARD_TEST_TMPDIR", exe.display());
    };
    let anchor = anchor.to_path_buf();
    let tmp = anchor.join("tmp");
    (anchor, tmp)
}

fn make_private_dir(dir: &Path) {
    if !dir.is_dir() {
        if let Some(parent) = dir.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|e| panic!("creating {}: {e}", parent.display()));
        }
        match fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("creating test temp root {}: {e}", dir.display()),
        }
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let meta = fs::metadata(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    if meta.uid() == euid && meta.mode() & 0o7777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("chmod 0700 {}: {e}", dir.display()));
    }
}

// Clears group/other write on every directory from `anchor` (the target
// directory) down to `root` that this process owns -- build output only.
fn tighten_owned_dirs(anchor: &Path, root: &Path) {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    for d in root.ancestors() {
        if let Ok(meta) = fs::metadata(d) {
            if meta.uid() == euid && meta.mode() & 0o022 != 0 {
                let _ = fs::set_permissions(d, fs::Permissions::from_mode(meta.mode() & 0o7755));
            }
        }
        if d == anchor {
            break;
        }
    }
}

// The library's directory rule, applied up front so a bad root is
// reported once, plainly.
fn check_chain(root: &Path) {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    for d in root.ancestors() {
        let meta = fs::metadata(d).unwrap_or_else(|e| panic!("{}: {e}", d.display()));
        let (uid, mode) = (meta.uid(), meta.mode() & 0o7777);
        let problem = if uid != 0 && uid != euid {
            Some(format!("is owned by uid {uid}, neither root nor this user"))
        } else if mode & 0o022 != 0 {
            Some(format!("is writable by group or others (mode {mode:o})"))
        } else {
            None
        };
        if let Some(problem) = problem {
            panic!(
                "test temp root {}: {} {problem}, so the library would refuse key files, policies and \
                 secrets under it. Run `chmod go-w` on it, or set HKDFGUARD_TEST_TMPDIR to a directory \
                 whose every ancestor is owned by root or you and writable by nobody else.",
                root.display(),
                d.display()
            );
        }
    }
}

//! `secure_file::resolve_trusted` -- the path walk behind
//! `hkdfguard_open_file`, the policy, PIN and TPM files, and external
//! secrets -- on random trees of directories, files and symbolic links,
//! with random modes, and random paths through them.
//!
//! Two oracles, both independent of the walker's code:
//! - **The kernel** says where a path leads: `canonicalize(2)` (realpath).
//!   Wherever the walker resolves a path and trusts everything on the way,
//!   it must land exactly where the kernel does; where the kernel finds
//!   nothing, neither may the walker.
//! - **A reference walk** in this harness, written recursively, records
//!   every directory a lookup happens in -- the ones the path passes
//!   through and the ones each symlink on the way lives in. If any of them
//!   is writable by group or others, the walker must refuse (a trust
//!   refusal: no `raw_os_error`). If none is, it must not.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "common.rs"]
mod common;
use hkdfguard::fuzz_support::resolve_trusted;

const NAMES: [&str; 4] = ["a", "b", "c", "d"];

#[derive(Arbitrary, Debug, Clone, Copy)]
enum DirMode {
    Private, // 0700
    Shared,  // 0755
    Group,   // 0775: refused
    World,   // 0777: refused
    Sticky,  // 1777: refused, sticky or not
}

impl DirMode {
    fn bits(self) -> u32 {
        match self {
            DirMode::Private => 0o700,
            DirMode::Shared => 0o755,
            DirMode::Group => 0o775,
            DirMode::World => 0o777,
            DirMode::Sticky => 0o1777,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Step {
    Name(u8),
    Dot,
    DotDot,
    /// An empty segment: a doubled or trailing `/`.
    Empty,
}

#[derive(Arbitrary, Debug)]
enum Entry {
    Dir { parent: u8, name: u8, mode: DirMode },
    File { parent: u8, name: u8 },
    /// A link to `steps`, relative, or absolute from the tree's root.
    Link { parent: u8, name: u8, absolute: bool, steps: Vec<Step> },
}

#[derive(Arbitrary, Debug)]
struct Case {
    entries: Vec<Entry>,
    path: Vec<Step>,
}

// Built as text, not with `PathBuf::push`, so `.` and empty segments
// survive into the path exactly as written.
fn steps_to_path(steps: &[Step]) -> PathBuf {
    let parts: Vec<&str> = steps
        .iter()
        .take(8)
        .map(|s| match s {
            Step::Name(n) => NAMES[*n as usize % NAMES.len()],
            Step::Dot => ".",
            Step::DotDot => "..",
            Step::Empty => "",
        })
        .collect();
    PathBuf::from(parts.join("/"))
}

// Builds the tree under `root`; directories are created 0700 and given
// their modes afterwards, so building never trips over its own modes.
fn build(root: &Path, entries: &[Entry]) -> Vec<(PathBuf, u32)> {
    let mut dirs = vec![root.to_path_buf()];
    let mut modes = Vec::new();
    for entry in entries.iter().take(24) {
        let (parent, name) = match entry {
            Entry::Dir { parent, name, .. } | Entry::File { parent, name } | Entry::Link { parent, name, .. } => (parent, name),
        };
        let at = dirs[*parent as usize % dirs.len()].join(NAMES[*name as usize % NAMES.len()]);
        if fs::symlink_metadata(&at).is_ok() {
            continue;
        }
        match entry {
            Entry::Dir { mode, .. } => {
                if fs::create_dir(&at).is_ok() {
                    modes.push((at.clone(), mode.bits()));
                    dirs.push(at);
                }
            }
            Entry::File { .. } => {
                let _ = fs::write(&at, b"x");
            }
            Entry::Link { absolute, steps, .. } => {
                let target = steps_to_path(steps);
                let target = if *absolute { PathBuf::from(format!("{}/{}", root.display(), target.display())) } else { target };
                let _ = std::os::unix::fs::symlink(&target, &at);
            }
        }
    }
    modes
}

/// What the reference walk saw.
enum Seen {
    /// Resolved: the directories looked up in, in order.
    Resolved(Vec<PathBuf>),
    /// A component was missing, or an OS error: the directories looked up in.
    Stopped(Vec<PathBuf>),
}

// The reference walk: resolve `rest` from directory `at`, following links
// recursively, recording every directory a lookup happens in.
fn reference(at: PathBuf, rest: &[std::ffi::OsString], looked_in: &mut Vec<PathBuf>, depth: &mut usize) -> Result<PathBuf, ()> {
    let mut at = at;
    for (i, part) in rest.iter().enumerate() {
        if part == "." {
            continue;
        }
        if part == ".." {
            at.pop();
            continue;
        }
        looked_in.push(at.clone());
        let candidate = at.join(part);
        let meta = fs::symlink_metadata(&candidate).map_err(|_| ())?;
        if meta.file_type().is_symlink() {
            *depth += 1;
            if *depth > 40 {
                return Err(());
            }
            let target = fs::read_link(&candidate).map_err(|_| ())?;
            let start = if target.is_absolute() { PathBuf::from("/") } else { at.clone() };
            let mut parts = components(&target);
            parts.extend_from_slice(&rest[i + 1..]);
            return reference(start, &parts, looked_in, depth);
        }
        if i + 1 < rest.len() {
            if !meta.is_dir() {
                return Err(());
            }
            at = candidate;
        } else {
            return Ok(candidate);
        }
    }
    Ok(at)
}

// Split on `/` as the kernel does: `.` and an empty segment (a trailing or
// doubled `/`) are kept as `.`, so the component before them must be a
// directory.
fn components(p: &Path) -> Vec<std::ffi::OsString> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    p.as_os_str()
        .as_bytes()
        .split(|b| *b == b'/')
        .enumerate()
        .filter_map(|(i, s)| match s {
            b"" if i == 0 => None,
            b"" => Some(".".into()),
            other => Some(std::ffi::OsString::from_vec(other.to_vec())),
        })
        .collect()
}

fn writable_by_others(dir: &Path) -> bool {
    dir.ancestors().any(|d| fs::metadata(d).map(|m| m.mode() & 0o022 != 0).unwrap_or(false))
}

fuzz_target!(|case: Case| {
    static N: AtomicU64 = AtomicU64::new(0);
    let root = common::dir().join(format!("walk-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    fs::create_dir(&root).unwrap();
    let root = fs::canonicalize(&root).unwrap();
    let modes = build(&root, &case.entries);
    for (dir, mode) in &modes {
        fs::set_permissions(dir, fs::Permissions::from_mode(*mode)).unwrap();
    }

    let path = PathBuf::from(format!("{}/{}", root.display(), steps_to_path(&case.path).display()));
    let walked = resolve_trusted(&path);
    let kernel = fs::canonicalize(&path);
    let mut looked_in = Vec::new();
    let seen = match reference(PathBuf::from("/"), &components(&path), &mut looked_in, &mut 0) {
        Ok(_) => Seen::Resolved(looked_in),
        Err(()) => Seen::Stopped(looked_in),
    };
    let (Seen::Resolved(dirs) | Seen::Stopped(dirs)) = &seen;
    let untrusted_on_the_way = dirs.iter().any(|d| writable_by_others(d));

    match &walked {
        Err(e) if e.raw_os_error().is_none() => {
            assert!(untrusted_on_the_way, "refused as untrusted with nothing untrusted on the way: {e}\n{case:?}");
        }
        // Both walks check a directory before looking anything up in it,
        // in the same order, so an OS error later on can't come first.
        _ if untrusted_on_the_way => {
            panic!("a lookup in a directory others can write was not refused: {walked:?}\nlooked in {dirs:?}\n{case:?}");
        }
        Ok(Some(real)) => {
            let kernel = kernel.as_ref().unwrap_or_else(|e| panic!("walker resolved {real:?}, kernel says {e}\n{case:?}"));
            assert_eq!(real, kernel, "walker and kernel disagree on where the path leads\n{case:?}");
            assert!(matches!(seen, Seen::Resolved(_)), "reference walk failed where the walker resolved\n{case:?}");
        }
        Ok(None) => {
            assert!(
                matches!(&kernel, Err(e) if e.kind() == std::io::ErrorKind::NotFound),
                "walker found nothing, kernel says {kernel:?}\n{case:?}"
            );
        }
        Err(e) => {
            assert!(kernel.is_err(), "walker failed with {e}, kernel resolved {kernel:?}\n{case:?}");
        }
    }

    // Leave nothing behind: make everything writable again, then remove it.
    for (dir, _) in &modes {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let _ = fs::remove_dir_all(&root);
});

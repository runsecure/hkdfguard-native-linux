//! Hardened reads of security-sensitive files (the administrative policy,
//! the PKCS#11 PIN, externally provisioned KEK material) and a buffer type
//! that guarantees what was read is wiped once it's no longer needed.
//!
//! Two properties every caller relies on:
//!
//! - **Checks are made on the opened descriptor, not the path.** Ownership,
//!   permission bits, and "is this a regular file" come from `fstat` on the
//!   file that was actually opened, so nothing can swap the path between a
//!   check and the read.
//! - **Secret bytes are never left behind in freed memory.** [`SecretBuffer`]
//!   reads into a single, fixed-size allocation made up front -- it never
//!   grows, so there are no intermediate buffers freed un-wiped the way
//!   `Read::read_to_end` leaves them -- and zeroes that whole allocation
//!   (including unused capacity) on [`SecretBuffer::wipe`] and on drop.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Who a checked file must be owned by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// uid 0 only.
    Root,
    /// uid 0, or this process's effective uid.
    RootOrCurrentUser,
}

/// Whose files and directories are trusted: who may own one, and which
/// groups, if any, may hold write access to one. [`Owner`] is the rule for
/// configuration (no group ever); `security_model::Trust` the one for key
/// files, which under the production model also trusts deployers.
pub trait PrincipalTrust {
    fn trusts_owner(&self, uid: u32) -> bool;
    /// Whether write access through the file's group, `gid`, is acceptable.
    fn trusts_group_writer(&self, gid: u32) -> bool;
}

impl PrincipalTrust for Owner {
    fn trusts_owner(&self, uid: u32) -> bool {
        // SAFETY: geteuid takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        match self {
            Owner::Root => uid == 0,
            Owner::RootOrCurrentUser => uid == 0 || uid == euid,
        }
    }

    fn trusts_group_writer(&self, _gid: u32) -> bool {
        false
    }
}

/// Who must own configuration this process reads but must not be able to
/// change: the policy file, the PKCS#11 PIN file, the TPM owner password,
/// and the directories they live in.
///
/// Every build that ships requires root. Accepting the service's own uid would let
/// any process running as that uid rewrite them -- and under Yama
/// `ptrace_scope >= 1` or in a container without `CAP_SYS_PTRACE`, such a
/// process can rewrite the service's files without being able to read its
/// memory. Rewriting the policy redirects every future wrap to a KEK the
/// writer controls; rewriting the PIN locks the HSM user out. Test builds (`cfg(test)`, or
/// the harnesses' `--cfg hkdfguard_test_paths`) also accept this process's
/// own uid, so tests can use temp files; no ordinary build setting --
/// debug profile included -- relaxes it.
pub const fn config_owner() -> Owner {
    if cfg!(any(test, hkdfguard_test_paths)) {
        Owner::RootOrCurrentUser
    } else {
        Owner::Root
    }
}

/// Permission bits that must be clear: nobody but the owner may write.
pub const FORBID_GROUP_OTHER_WRITE: u32 = 0o022;
/// Permission bits that must be clear: nobody but the owner may read, write, or execute.
/// Used by the secret-reading providers; a build with none of them leaves it unused.
#[cfg_attr(not(any(feature = "tpm2", feature = "pkcs11", feature = "external-secret")), allow(dead_code))]
pub const FORBID_GROUP_OTHER_ACCESS: u32 = 0o077;

const GROUP_READ: u32 = 0o040;
const GROUP_WRITE: u32 = 0o020;
const STICKY: u32 = 0o1000;

/// What a file must satisfy before its contents are trusted.
#[derive(Debug, Clone, Copy)]
pub struct FileRequirements {
    /// `None` skips the ownership check.
    pub owner: Option<Owner>,
    /// Any of these mode bits being set rejects the file.
    pub forbidden_mode_bits: u32,
    /// `false` opens with `O_NOFOLLOW`: a symlink as the final path
    /// component fails the open (ELOOP) instead of being followed.
    pub follow_symlinks: bool,
    /// Exempts group read from `forbidden_mode_bits` when the file is owned
    /// by root. `root:<service-group> 0440` is how a root-owned secret is
    /// made readable by a non-root service; on a file the service owns
    /// itself, group read would only leak it to other group members.
    pub allow_group_read_if_root_owned: bool,
}

/// Opens `path` read-only and validates it against `req` using the opened
/// descriptor's own metadata. Only ever returns `ErrorKind::NotFound` when
/// the file genuinely doesn't exist; a file that exists but fails a check
/// is reported as `PermissionDenied` or `InvalidData`, so callers can tell
/// "absent" apart from "present but untrustworthy". A refusal by one of
/// these checks never carries a `raw_os_error`, while the kernel refusing
/// the open itself (`EACCES`, `ELOOP`, ...) always does, so callers can
/// also tell "the OS said no" apart from "the file failed a trust check"
/// (`key_file` reports them as different status codes).
pub fn open_checked(path: &Path, req: &FileRequirements) -> io::Result<File> {
    // O_NONBLOCK: opening a FIFO with no writer would otherwise block in
    // open(2) itself -- before the descriptor could be checked -- hanging
    // the caller (and, for a setup call, everything queued behind it). With
    // it, the open returns at once and the regular-file check below refuses
    // it. It has no effect on reading a regular file. O_NOCTTY: a terminal
    // device must not become this process's controlling terminal.
    // Miri, which runs the tests to check `unsafe` code, can't open with
    // these two flags; neither changes what a regular file's open does.
    let mut flags = if cfg!(miri) { 0 } else { libc::O_NONBLOCK | libc::O_NOCTTY };
    if !req.follow_symlinks {
        flags |= libc::O_NOFOLLOW;
    }
    let mut opts = OpenOptions::new();
    opts.read(true).custom_flags(flags);
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    let mut forbidden = req.forbidden_mode_bits;
    if req.allow_group_read_if_root_owned && meta.uid() == 0 {
        forbidden &= !GROUP_READ;
    }
    check_metadata(&meta, req.owner, forbidden)?;
    Ok(file)
}

/// Checks that nobody `owner` doesn't cover can rename, replace, or delete
/// anything beneath `dir`: `dir` and every ancestor up to `/` must be a
/// directory owned per `owner` and not writable by group or others --
/// **sticky or not**. So nothing under `/tmp`, `/var/tmp`, `/dev/shm` or any
/// other shared, world-writable directory passes, at any depth, however
/// private the directories beneath it: anything this crate trusts belongs
/// in a directory only its owner (or root) can write to, all the way up.
/// (The sticky bit would stop other users renaming or deleting entries they
/// don't own, but they could still create entries there, and its protection
/// would rest on the owner checks of everything beneath -- one mistake there
/// is enough.)
///
/// The one exception: write bits are ignored on a read-only mount. A
/// Kubernetes Secret or ConfigMap volume is `1777` but mounted read-only,
/// so nobody can write to it.
///
/// Applied, through [`check_location`] or directly, to every file this
/// crate reads: key files (`key_file::read`, behind `hkdfguard_open_file`),
/// the policy file, external-secret mounts, the PKCS#11 module and PIN
/// file, and the TPM key files and owner-authorization file. With
/// the target file's own ownership also checked, nobody untrusted can swap
/// the path between this check and a later open or `dlopen` of it by path.
///
/// `dir` must be canonical (no symlinks). Every failure, including one
/// from a directory vanishing mid-walk, is `PermissionDenied` -- never
/// `NotFound`, which callers reserve for "the file isn't there".
#[cfg_attr(not(any(feature = "tpm2", feature = "pkcs11", feature = "external-secret")), allow(dead_code))]
pub fn check_dir_chain(dir: &Path, owner: Owner) -> io::Result<()> {
    check_dir_chain_trusting(dir, &owner)
}

/// [`check_dir_chain`] under any [`PrincipalTrust`]: each directory's owner
/// must be one `trust` accepts, and a directory writable through its group
/// passes only if `trust` accepts that group as a writer (a deployer group,
/// for a key file under the production model). Writable by others never
/// passes, sticky or not -- the read-only-mount exception aside.
pub fn check_dir_chain_trusting(dir: &Path, trust: &dyn PrincipalTrust) -> io::Result<()> {
    match first_untrusted_dir(dir, trust) {
        None => Ok(()),
        Some((d, problem)) => {
            let what = match problem {
                DirProblem::Unexaminable(e) => e,
                DirProblem::NotADirectory => "not a directory".to_string(),
                DirProblem::Owner(uid) => format!("owned by uid {uid}, which is not an allowed owner"),
                DirProblem::Writable { mode } => {
                    let sticky = if mode & STICKY != 0 { "; sticky, like /tmp, which is not enough" } else { "" };
                    format!("writable by group or others (mode {mode:o}{sticky}), so entries could be created or replaced in it")
                }
            };
            Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("directory {}: {what}", d.display())))
        }
    }
}

/// Why a directory isn't one `trust` accepts, as [`judge_dir`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirProblem {
    /// It couldn't be examined (it vanished, or can't be searched).
    Unexaminable(String),
    /// It isn't a directory.
    NotADirectory,
    /// Its owner, this uid, isn't one `trust` accepts.
    Owner(u32),
    /// Someone `trust` doesn't accept can write to it: these are its
    /// permission bits (`0o7777`), sticky bit included. Never reported for
    /// a read-only mount, which nobody can write to.
    Writable { mode: u32 },
}

/// Whether one directory is trustworthy under `trust`: a directory, owned
/// by someone `trust` accepts, and writable by nobody else -- through its
/// group only if `trust` accepts that group, by others never, sticky or
/// not, unless it is on a read-only mount. The one rule every directory
/// check in this crate, and the CLI's, applies.
pub fn judge_dir(dir: &Path, trust: &dyn PrincipalTrust) -> Result<(), DirProblem> {
    let meta = std::fs::metadata(dir).map_err(|e| DirProblem::Unexaminable(e.to_string()))?;
    if !meta.is_dir() {
        return Err(DirProblem::NotADirectory);
    }
    if !trust.trusts_owner(meta.uid()) {
        return Err(DirProblem::Owner(meta.uid()));
    }
    if untrusted_write_bits(&meta, trust) != 0 && !on_read_only_mount(dir) {
        return Err(DirProblem::Writable { mode: meta.mode() & 0o7777 });
    }
    Ok(())
}

/// The first of `dir` and its ancestors, up to `/`, that [`judge_dir`]
/// refuses, and why; `None` if every one passes. `dir` must be canonical.
pub fn first_untrusted_dir(dir: &Path, trust: &dyn PrincipalTrust) -> Option<(std::path::PathBuf, DirProblem)> {
    dir.ancestors().find_map(|d| judge_dir(d, trust).err().map(|problem| (d.to_path_buf(), problem)))
}

/// Most symbolic links [`resolve_trusted`] follows in one path: Linux's
/// own limit (`MAXSYMLINKS`), past which `open(2)` fails with `ELOOP`.
const MAX_SYMLINKS: usize = 40;

/// Resolves `path` the way the kernel does -- one component at a time,
/// following each symbolic link where it is met, applying `..` to the
/// directory actually reached -- and checks every directory a lookup
/// happens in, with all of its ancestors ([`check_dir_chain_trusting`]).
///
/// Those are exactly the directories that decide what `path` names: the
/// ones it passes through, *and* the ones any symbolic link along the way
/// lives in. Whoever can write to any of them can rename an entry, or
/// retarget a link, so that `path` names a file of their choosing. Checking
/// only where `path` is named and where it ends up misses a link in the
/// middle: `/home/app/conf/keys/k`, with `keys -> /etc/keys`, names a file
/// in a trusted directory, but the account owning `/home/app/conf` can
/// point `keys` anywhere.
///
/// Returns `Ok(Some(real))`, `real` the canonical path of what `path`
/// names, once it resolves completely; `Ok(None)` when some component
/// doesn't exist -- after checking the directory the missing name was
/// looked up in, so whoever could create it there is trusted too. A
/// directory refused is `PermissionDenied` with no `raw_os_error`, as
/// every trust refusal here is; anything the OS refuses carries its error
/// (`EACCES`, `ENOTDIR`, `ELOOP` past [`MAX_SYMLINKS`] links).
pub fn resolve_trusted(path: &Path, trust: &dyn PrincipalTrust) -> io::Result<Option<std::path::PathBuf>> {
    use std::collections::{HashSet, VecDeque};
    use std::ffi::OsString;
    use std::path::PathBuf;

    // Components still to resolve, split on `/` as the kernel splits them.
    // Not `Path::components`, which drops `.` and a trailing `/`: the
    // kernel doesn't, and both mean the component before them must be a
    // directory (`file/.` and `file/` are ENOTDIR). So each `.`, and each
    // empty segment after the leading `/` (`a//b`, a trailing `/`), is kept
    // as `.`: a step that does nothing itself, but that makes whatever
    // precedes it a component with more to come.
    let components = |p: &Path| -> VecDeque<OsString> {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        p.as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .enumerate()
            .filter_map(|(i, segment)| match segment {
                b"" if i == 0 => None, // before the leading `/` of an absolute path
                b"" => Some(OsString::from(".")),
                other => Some(OsString::from_vec(other.to_vec())),
            })
            .collect()
    };
    let mut current = if path.is_absolute() { PathBuf::from("/") } else { std::fs::canonicalize(".")? };
    let mut pending = components(path);
    let mut checked: HashSet<PathBuf> = HashSet::new();
    let mut links = 0;

    while let Some(name) = pending.pop_front() {
        if name == "." {
            continue; // `current` is a directory already
        }
        if name == ".." {
            current.pop(); // physical: the parent of the directory actually reached; `/` stays `/`
            continue;
        }
        // A lookup is about to happen in `current`.
        if checked.insert(current.clone()) {
            check_dir_chain_trusting(&current, trust)?;
        }
        let candidate = current.join(&name);
        let meta = match std::fs::symlink_metadata(&candidate) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if meta.file_type().is_symlink() {
            links += 1;
            if links > MAX_SYMLINKS {
                return Err(io::Error::from_raw_os_error(libc::ELOOP));
            }
            let target = std::fs::read_link(&candidate)?;
            if target.is_absolute() {
                current = PathBuf::from("/");
            }
            let mut rest = components(&target);
            rest.extend(pending);
            pending = rest;
        } else if pending.is_empty() {
            return Ok(Some(candidate));
        } else if meta.is_dir() {
            current = candidate;
        } else {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
    }
    // The path ended in `..` or named `/`: a directory, which the caller's
    // open refuses as not a regular file.
    Ok(Some(current))
}

// The write bits `meta` grants to someone `trust` doesn't accept: others'
// always, and the group's unless that group is a trusted writer.
fn untrusted_write_bits(meta: &Metadata, trust: &dyn PrincipalTrust) -> u32 {
    let mut bits = meta.mode() & FORBID_GROUP_OTHER_WRITE;
    if bits & GROUP_WRITE != 0 && trust.trusts_group_writer(meta.gid()) {
        bits &= !GROUP_WRITE;
    }
    bits
}

/// Checks an opened file's metadata under `trust`: a regular file, owned by
/// someone `trust` accepts, writable by nobody else -- through its group
/// only if `trust` accepts that group as a writer. Every refusal is
/// `PermissionDenied` (or `InvalidData` for "not a regular file") with no
/// `raw_os_error`, as [`open_checked`]'s own checks are.
pub fn check_metadata_trusting(meta: &Metadata, trust: &dyn PrincipalTrust) -> io::Result<()> {
    if !meta.file_type().is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a regular file"));
    }
    if !trust.trusts_owner(meta.uid()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("owned by uid {}, which is not an allowed owner", meta.uid()),
        ));
    }
    let offending = untrusted_write_bits(meta, trust);
    if offending != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("permissions too broad (mode {:o}; bits {offending:o} must be clear)", meta.mode() & 0o7777),
        ));
    }
    Ok(())
}

/// Confirms the descriptor `open` returned is the file that was resolved
/// and checked, two ways: on Linux, by reading its path back from
/// `<proc>/self/fd/<n>` and checking it is `within` (pass the resolved file
/// itself to require exactly that file), where `/proc` is mounted; and, in
/// every case, by comparing the descriptor's device and inode with what
/// `target_real` names now. Without `/proc` (masked, as in some minimal
/// containers and sandboxes, or a non-Linux build) the second alone is
/// just as conclusive. The CLI's own opens use the same check.
/// Every failure is `PermissionDenied` -- never `NotFound`, which callers
/// reserve for "the file isn't there".
pub fn verify_opened(file: &File, target_real: &Path, within: &Path, proc_root: &Path) -> io::Result<()> {
    let denied = |what: String| io::Error::new(io::ErrorKind::PermissionDenied, what);

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        if let Ok(opened) = std::fs::read_link(proc_root.join(format!("self/fd/{}", file.as_raw_fd()))) {
            if !opened.starts_with(within) {
                return Err(denied(format!(
                    "opened descriptor refers to {}, outside {}",
                    opened.display(),
                    within.display()
                )));
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (within, proc_root);

    let opened = file.metadata().map_err(|e| denied(format!("could not stat the opened file: {e}")))?;
    let resolved = std::fs::symlink_metadata(target_real)
        .map_err(|e| denied(format!("{} changed after it was opened: {e}", target_real.display())))?;
    if (opened.dev(), opened.ino()) != (resolved.dev(), resolved.ino()) {
        return Err(denied(format!("{} was replaced between resolution and open", target_real.display())));
    }
    Ok(())
}

fn on_read_only_mount(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: an all-zero `statvfs` is a valid out-parameter (plain integers).
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c_path is a valid NUL-terminated string; `st` is a properly
    // sized out-parameter that statvfs fully initializes on success, and
    // is read only then.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut st) } != 0 {
        return false;
    }
    st.f_flag & libc::ST_RDONLY != 0
}

/// Checks that nobody `owner` doesn't cover can delete, rename, or replace
/// `path` or make it resolve elsewhere: every directory that decides what
/// it names -- the ones it passes through and the ones any symbolic link
/// on the way lives in -- must pass [`check_dir_chain`] (see
/// [`resolve_trusted`]). That holds whether or not `path` exists: when it
/// doesn't, up to the directory its missing component would be created in.
///
/// Checking where a file *would* be, not just where it is, matters for
/// files whose absence is meaningful: a missing policy means "no policy",
/// so if an untrusted user could delete it, they could switch policy off.
/// Every failure is `PermissionDenied`; a component the OS won't let this
/// process look up is reported with its error.
pub fn check_location(path: &Path, owner: Owner) -> io::Result<()> {
    match resolve_trusted(path, &owner) {
        Ok(_) => Ok(()), // present, or absent: the open reports which
        Err(e) if e.raw_os_error().is_none() => Err(e),
        Err(e) => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{}: {e}", path.display()))),
    }
}

/// Validates already-obtained metadata: must be a regular file (never a
/// directory, FIFO, device, or socket), owned per `owner`, with none of
/// `forbidden_mode_bits` set.
pub fn check_metadata(meta: &Metadata, owner: Option<Owner>, forbidden_mode_bits: u32) -> io::Result<()> {
    if !meta.file_type().is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a regular file"));
    }
    check_owner_and_mode(meta, owner, forbidden_mode_bits)
}

/// Ownership + permission-bit check alone, for callers validating
/// something other than a regular file (e.g. a directory).
pub fn check_owner_and_mode(meta: &Metadata, owner: Option<Owner>, forbidden_mode_bits: u32) -> io::Result<()> {
    if let Some(owner) = owner {
        let uid = meta.uid();
        if !owner.trusts_owner(uid) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("owned by uid {uid}, which is not an allowed owner"),
            ));
        }
    }
    let offending = meta.mode() & forbidden_mode_bits;
    if offending != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("permissions too broad (mode {:o}; bits {offending:o} must be clear)", meta.mode() & 0o7777),
        ));
    }
    Ok(())
}

/// What identifies one version of a credential file (the PKCS#11 PIN, the
/// TPM owner password). A change to any of these means an operator touched
/// the file, which clears a latched authentication failure: see
/// `pkcs11::PIN_LATCHES` and `tpm2::OWNER_AUTH`.
#[cfg_attr(not(any(feature = "tpm2", feature = "pkcs11")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) len: u64,
    pub(crate) mtime: (i64, i64),
}

#[cfg_attr(not(any(feature = "tpm2", feature = "pkcs11")), allow(dead_code))]
impl FileIdentity {
    /// The identity of the file `path` resolves to, symlinks followed: for
    /// a credential file, where a Kubernetes-style link swap is a change.
    pub(crate) fn of(path: &Path) -> Option<Self> {
        Some(Self::from_meta(&std::fs::metadata(path).ok()?))
    }

    /// The identity of the directory entry `path` itself, a symlink not
    /// followed: for checking a file read with `O_NOFOLLOW` is still the
    /// one at that name before it is deleted.
    #[cfg_attr(not(any(feature = "tpm2", test)), allow(dead_code))]
    pub(crate) fn of_entry(path: &Path) -> Option<Self> {
        Some(Self::from_meta(&std::fs::symlink_metadata(path).ok()?))
    }

    fn from_meta(m: &Metadata) -> Self {
        FileIdentity { dev: m.dev(), ino: m.ino(), len: m.len(), mtime: (m.mtime(), m.mtime_nsec()) }
    }
}

/// A byte buffer for secret file contents that is guaranteed to be zeroed
/// once it's no longer needed: explicitly via [`SecretBuffer::wipe`] as
/// soon as the caller is done with it, and unconditionally on drop -- so
/// every early-return or error path clears it too.
pub struct SecretBuffer {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretBuffer {
    /// Reads all of `file` into one allocation of exactly `max_len + 1`
    /// bytes made before the first read. The allocation never grows, so no
    /// partially-filled intermediate buffer is ever freed with secret bytes
    /// still in it. A file longer than `max_len` is rejected (and the
    /// partial read wiped) rather than truncated.
    pub fn read_from(file: &mut File, max_len: usize) -> io::Result<Self> {
        let mut bytes = Zeroizing::new(vec![0u8; max_len + 1]);
        let mut filled = 0;
        while filled < bytes.len() {
            match file.read(&mut bytes[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e), // `bytes` is zeroed as it drops here
            }
        }
        if filled > max_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("file exceeds the {max_len}-byte limit"),
            ));
        }
        bytes.truncate(filled); // shrinks the length only; the allocation (and its zeroing on drop) is unchanged
        Ok(SecretBuffer { bytes })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Zeroes the entire underlying allocation -- contents and spare
    /// capacity -- immediately, rather than waiting for drop. Afterward the
    /// buffer is empty. Safe to call more than once.
    pub fn wipe(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.wipe(); // belt and braces: `Zeroizing` would also do this, but make the guarantee explicit here
    }
}

/// Test-only: writes `contents` to `path` and pins its mode to `0o644`,
/// rather than trusting the umask to leave it non-group/other-writable.
/// A permissive umask (some distros default to `002`) would otherwise
/// produce a `664` file that `check_owner_and_mode`'s
/// `FORBID_GROUP_OTHER_WRITE` correctly refuses -- breaking every fixture
/// that writes a policy/config file it expects to load successfully.
#[cfg(test)]
pub(crate) fn write_world_readable_for_tests(path: &std::path::Path, contents: impl AsRef<[u8]>) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o644)).unwrap();
}

/// Test-only: a temp directory nobody but this user can write to, whatever
/// the umask, under the trusted test temp root (see `src/test_tmp.rs`), not
/// the system temp dir. `tempfile::tempdir()` creates `0777 & !umask` under
/// `/tmp`: under a `002` umask that is group-writable, and `/tmp` itself is
/// sticky and world-writable -- both of which [`check_dir_chain`] refuses,
/// at any depth, for every file this crate reads.
#[cfg(test)]
pub(crate) fn private_tempdir() -> tempfile::TempDir {
    crate::test_tmp::private_tempdir()
}

/// Test-only: whether a test that can only run as a non-root user should
/// skip, because this process is root (every file it creates is
/// root-owned, and root reads mode-000 files, so there is nothing to
/// refuse). Set `HKDFGUARD_TESTS_MUST_NOT_RUN_AS_ROOT=1` where the suite is
/// meant to run unprivileged -- the Docker image does -- and a root run
/// fails here instead of passing these tests without running them.
#[cfg(test)]
pub(crate) fn skip_as_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return false;
    }
    assert!(
        std::env::var_os("HKDFGUARD_TESTS_MUST_NOT_RUN_AS_ROOT").is_none(),
        "running as root, but HKDFGUARD_TESTS_MUST_NOT_RUN_AS_ROOT is set: \
         this test only proves anything as a non-root user"
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn temp_file_with(contents: &[u8], mode: u32) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new_in(crate::test_tmp::root()).unwrap();
        f.write_all(contents).unwrap();
        f.flush().unwrap();
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        f
    }

    const OWNER_ONLY: FileRequirements = FileRequirements {
        owner: Some(Owner::RootOrCurrentUser),
        forbidden_mode_bits: FORBID_GROUP_OTHER_ACCESS,
        follow_symlinks: true,
        allow_group_read_if_root_owned: false,
    };

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn is_root() -> bool {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn group_read_is_allowed_only_on_a_root_owned_file_when_requested() {
        let f = temp_file_with(b"x", 0o640);
        let req = FileRequirements { allow_group_read_if_root_owned: true, ..OWNER_ONLY };
        let result = open_checked(f.path(), &req);
        if is_root() {
            result.unwrap(); // root:<group> 0640 is the supported layout for a non-root service
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied, "a self-owned secret must stay owner-only");
        }
        // Never group write, and never anything for others, root-owned or not.
        for mode in [0o660, 0o644] {
            chmod(f.path(), mode);
            assert_eq!(open_checked(f.path(), &req).unwrap_err().kind(), io::ErrorKind::PermissionDenied, "mode {mode:o}");
        }
    }

    #[test]
    fn dir_chain_accepts_a_private_dir_and_refuses_a_shared_writable_one() {
        let base = crate::secure_file::private_tempdir();
        let dir = std::fs::canonicalize(base.path()).unwrap();
        check_dir_chain(&dir, Owner::RootOrCurrentUser).unwrap();

        for mode in [0o770, 0o707, 0o1777] {
            chmod(&dir, mode);
            let err = check_dir_chain(&dir, Owner::RootOrCurrentUser).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "mode {mode:o}");
        }
        chmod(&dir, 0o700);
    }

    #[test]
    fn dir_chain_refuses_a_sticky_ancestor_as_well_as_a_plain_writable_one() {
        // A private 0700 directory inside a /tmp-style one: the layout of
        // `mktemp -d` under /tmp. Refused, however private the directory.
        let base = crate::secure_file::private_tempdir();
        let outer = std::fs::canonicalize(base.path()).unwrap();
        let inner = outer.join("inner");
        std::fs::create_dir(&inner).unwrap();
        chmod(&inner, 0o700);
        check_dir_chain(&inner, Owner::RootOrCurrentUser).expect("a private chain passes");

        for (mode, sticky) in [(0o1777, true), (0o1770, true), (0o1733, true), (0o777, false), (0o770, false)] {
            chmod(&outer, mode);
            let err = check_dir_chain(&inner, Owner::RootOrCurrentUser).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "mode {mode:o}");
            let msg = err.to_string();
            assert!(msg.contains(&outer.display().to_string()), "names the directory: {msg}");
            assert_eq!(msg.contains("sticky, like /tmp, which is not enough"), sticky, "says why: {msg}");
        }
        chmod(&outer, 0o700);
        check_dir_chain(&inner, Owner::RootOrCurrentUser).unwrap();
    }

    #[test]
    fn a_file_identity_by_entry_does_not_follow_a_symlink() {
        let dir = private_tempdir();
        let file = dir.path().join("key");
        std::fs::write(&file, b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(FileIdentity::of(&link), FileIdentity::of(&file), "followed: the same file");
        assert_ne!(FileIdentity::of_entry(&link), FileIdentity::of_entry(&file), "by entry: a link is not the file");
        assert_eq!(FileIdentity::of_entry(&file), FileIdentity::of(&file));
    }

    #[test]
    fn resolve_trusted_follows_paths_as_the_kernel_does() {
        let dir = private_tempdir();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let me = Owner::RootOrCurrentUser;
        std::fs::create_dir(base.join("real")).unwrap();
        std::fs::write(base.join("real/file"), b"x").unwrap();
        std::os::unix::fs::symlink("real", base.join("rel")).unwrap(); // relative target
        std::os::unix::fs::symlink(base.join("real/file"), base.join("abs")).unwrap(); // absolute target

        assert_eq!(resolve_trusted(&base.join("real/./file"), &me).unwrap(), Some(base.join("real/file")));
        assert_eq!(resolve_trusted(&base.join("rel/file"), &me).unwrap(), Some(base.join("real/file")));
        assert_eq!(resolve_trusted(&base.join("abs"), &me).unwrap(), Some(base.join("real/file")));
        assert_eq!(resolve_trusted(&base.join("rel/../real/file"), &me).unwrap(), Some(base.join("real/file")));

        // Missing: `None`, at any depth, never an error.
        assert_eq!(resolve_trusted(&base.join("real/absent"), &me).unwrap(), None);
        assert_eq!(resolve_trusted(&base.join("absent/deeper/file"), &me).unwrap(), None);
        // A file used as a directory, and a loop: the OS's own errors.
        assert_eq!(resolve_trusted(&base.join("real/file/x"), &me).unwrap_err().raw_os_error(), Some(libc::ENOTDIR));
        // `file/.` and `file/` name a directory too, as the kernel reads
        // them (found by fuzzing: `Path::components` drops both).
        for spelled in ["real/file/.", "real/file/", "real/file//", "abs/."] {
            let path = std::path::PathBuf::from(format!("{}/{spelled}", base.display()));
            assert_eq!(std::fs::canonicalize(&path).unwrap_err().raw_os_error(), Some(libc::ENOTDIR), "kernel: {spelled}");
            assert_eq!(resolve_trusted(&path, &me).unwrap_err().raw_os_error(), Some(libc::ENOTDIR), "walker: {spelled}");
        }
        // While a directory followed by them is just that directory.
        let real_dot = std::path::PathBuf::from(format!("{}/real/./", base.display()));
        assert_eq!(resolve_trusted(&real_dot, &me).unwrap(), Some(base.join("real")));
        assert_eq!(resolve_trusted(Path::new("/"), &me).unwrap(), Some(std::path::PathBuf::from("/")));
        std::os::unix::fs::symlink(base.join("loop"), base.join("loop")).unwrap();
        assert_eq!(resolve_trusted(&base.join("loop"), &me).unwrap_err().raw_os_error(), Some(libc::ELOOP));
    }

    #[test]
    fn resolve_trusted_checks_where_a_missing_name_would_be_created() {
        // Absent, in a directory others can write: someone could create it
        // there, so that is refused like a present file would be.
        let dir = private_tempdir();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let open = base.join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = resolve_trusted(&open.join("absent"), &Owner::RootOrCurrentUser).unwrap_err();
        assert!(err.raw_os_error().is_none() && err.to_string().contains("writable by group or others"), "{err}");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn check_location_covers_the_directory_a_symlink_in_the_middle_lives_in() {
        // The policy file, the PIN file and the TPM key files go through
        // check_location: a link above them, in a directory others can
        // write, is refused, though both ends of the path are trusted.
        let trusted = private_tempdir();
        let untrusted = private_tempdir();
        std::fs::write(trusted.path().join("policy.toml"), b"").unwrap();
        let link = untrusted.path().join("conf");
        std::os::unix::fs::symlink(trusted.path(), &link).unwrap();
        check_location(&link.join("policy.toml"), Owner::RootOrCurrentUser).unwrap();
        check_location(&link.join("absent.toml"), Owner::RootOrCurrentUser).unwrap();
        std::fs::set_permissions(untrusted.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        for name in ["policy.toml", "absent.toml"] {
            let err = check_location(&link.join(name), Owner::RootOrCurrentUser).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{name}: {err}");
        }
        std::fs::set_permissions(untrusted.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn verify_opened_with_the_file_as_its_own_boundary_requires_that_exact_file() {
        // How hkdfguard_open_file uses it: `within` is the resolved file
        // itself, so even a sibling in the same directory is a mismatch --
        // through /proc and, where /proc is missing, by device and inode.
        let dir = private_tempdir();
        let d = std::fs::canonicalize(dir.path()).unwrap();
        let (a, b) = (d.join("a.key"), d.join("b.key"));
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let file_a = File::open(&a).unwrap();
        for proc_root in [Path::new("/proc"), Path::new("/nonexistent-hkdfguard-proc")] {
            verify_opened(&file_a, &a, &a, proc_root).unwrap_or_else(|e| panic!("{}: {e}", proc_root.display()));
            let err = verify_opened(&file_a, &b, &b, proc_root).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{}", proc_root.display());
        }
    }

    #[test]
    fn dir_chain_refuses_a_sticky_dir_itself() {
        let base = crate::secure_file::private_tempdir();
        let dir = std::fs::canonicalize(base.path()).unwrap();
        for mode in [0o1777, 0o1770, 0o1707] {
            chmod(&dir, mode);
            let err = check_dir_chain(&dir, Owner::RootOrCurrentUser).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "mode {mode:o}");
            assert!(err.to_string().contains("sticky"), "says why: {err}");
        }
        chmod(&dir, 0o700);
    }

    #[test]
    fn dir_chain_refuses_the_system_temp_dir() {
        // Wherever the system temp dir is (/tmp, normally 1777), a private
        // directory under it is still refused -- unless TMPDIR
        // points somewhere private, in which case there is nothing to show.
        let dir = tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
        let dir = std::fs::canonicalize(dir.path()).unwrap();
        let shared = dir.ancestors().skip(1).any(|d| {
            std::fs::metadata(d).map(|m| m.mode() & FORBID_GROUP_OTHER_WRITE != 0).unwrap_or(false)
                && !on_read_only_mount(d)
        });
        if !shared {
            eprintln!("skipping: {} has no group/other-writable ancestor", dir.display());
            return;
        }
        assert!(check_dir_chain(&dir, Owner::RootOrCurrentUser).is_err());
    }

    #[test]
    fn dir_chain_with_root_owner_refuses_a_user_owned_dir() {
        if crate::secure_file::skip_as_root() {
            return;
        }
        let base = crate::secure_file::private_tempdir();
        let err = check_dir_chain(&std::fs::canonicalize(base.path()).unwrap(), Owner::Root).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn location_is_checked_even_when_the_file_is_absent() {
        let base = crate::secure_file::private_tempdir();
        let missing = base.path().join("not-yet").join("policy.toml");
        check_location(&missing, Owner::RootOrCurrentUser).unwrap();

        chmod(base.path(), 0o777);
        let err = check_location(&missing, Owner::RootOrCurrentUser).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "its absence must not be trusted either");
        chmod(base.path(), 0o700);
    }

    #[test]
    fn location_checks_where_a_symlink_points_too() {
        let trusted = crate::secure_file::private_tempdir();
        let shared = crate::secure_file::private_tempdir();
        let target = shared.path().join("policy.toml");
        std::fs::write(&target, b"x").unwrap();
        let link = trusted.path().join("policy.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        check_location(&link, Owner::RootOrCurrentUser).unwrap();

        chmod(shared.path(), 0o777);
        assert!(check_location(&link, Owner::RootOrCurrentUser).is_err(), "the target's directory is writable by others");
        chmod(shared.path(), 0o700);
    }

    #[test]
    fn location_under_a_sticky_ancestor_is_refused_present_or_absent() {
        // The policy, PIN, TPM key files and owner password all go
        // through check_location: a private directory under a /tmp-style
        // one is no place for any of them, whether or not the file exists.
        let base = crate::secure_file::private_tempdir();
        let inner = base.path().join("private");
        std::fs::create_dir(&inner).unwrap();
        chmod(&inner, 0o700);
        let present = inner.join("policy.toml");
        std::fs::write(&present, b"x").unwrap();
        let absent = inner.join("not-yet").join("policy.toml");
        check_location(&present, Owner::RootOrCurrentUser).unwrap();
        check_location(&absent, Owner::RootOrCurrentUser).unwrap();

        chmod(base.path(), 0o1777);
        for path in [&present, &absent] {
            let err = check_location(path, Owner::RootOrCurrentUser).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{}", path.display());
            assert!(err.to_string().contains("sticky"), "says why: {err}");
        }
        chmod(base.path(), 0o700);
    }

    #[test]
    fn reads_contents_within_limit() {
        let f = temp_file_with(b"hello", 0o600);
        let mut file = open_checked(f.path(), &OWNER_ONLY).unwrap();
        let buf = SecretBuffer::read_from(&mut file, 16).unwrap();
        assert_eq!(buf.as_slice(), b"hello");
        assert_eq!(buf.as_slice().len(), 5);
    }

    #[test]
    fn exact_limit_is_accepted_and_one_over_is_rejected() {
        let f = temp_file_with(&[7u8; 8], 0o600);
        let mut file = File::open(f.path()).unwrap();
        assert_eq!(SecretBuffer::read_from(&mut file, 8).unwrap().as_slice().len(), 8);

        let mut file = File::open(f.path()).unwrap();
        let err = SecretBuffer::read_from(&mut file, 7).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn wipe_empties_the_buffer_and_is_idempotent() {
        let f = temp_file_with(b"secret-material", 0o600);
        let mut file = File::open(f.path()).unwrap();
        let mut buf = SecretBuffer::read_from(&mut file, 64).unwrap();
        buf.wipe();
        assert!(buf.as_slice().is_empty());
        assert_eq!(buf.as_slice(), b"");
        buf.wipe(); // second wipe must be harmless
        assert!(buf.as_slice().is_empty());
    }

    #[test]
    fn rejects_group_or_world_accessible_file() {
        let f = temp_file_with(b"x", 0o640);
        let err = open_checked(f.path(), &OWNER_ONLY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn write_only_restriction_allows_world_readable() {
        let f = temp_file_with(b"x", 0o644);
        let req = FileRequirements { forbidden_mode_bits: FORBID_GROUP_OTHER_WRITE, ..OWNER_ONLY };
        open_checked(f.path(), &req).unwrap();

        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(open_checked(f.path(), &req).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn root_only_owner_rejects_non_root_file() {
        if crate::secure_file::skip_as_root() {
            return; // running as root, so any temp file is root-owned; nothing to reject
        }
        let f = temp_file_with(b"x", 0o600);
        let req = FileRequirements { owner: Some(Owner::Root), ..OWNER_ONLY };
        assert_eq!(open_checked(f.path(), &req).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_directories() {
        let dir = crate::secure_file::private_tempdir();
        let req = FileRequirements { owner: None, forbidden_mode_bits: 0, ..OWNER_ONLY };
        assert_eq!(open_checked(dir.path(), &req).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_fifo_is_refused_without_blocking_the_open() {
        let dir = private_tempdir();
        let fifo = dir.path().join("policy.toml");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: c is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(open_checked(&fifo, &OWNER_ONLY).map(|_| ())).unwrap());
        let result = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("open_checked blocked on a FIFO");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn missing_file_is_reported_as_not_found() {
        let err = open_checked(Path::new("/nonexistent-hkdfguard-secure-file-test"), &OWNER_ONLY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn no_follow_rejects_symlink_but_follow_accepts_it() {
        let target = temp_file_with(b"x", 0o600);
        let dir = crate::secure_file::private_tempdir();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(target.path(), &link).unwrap();

        open_checked(&link, &OWNER_ONLY).unwrap(); // follow_symlinks: true

        let no_follow = FileRequirements { follow_symlinks: false, ..OWNER_ONLY };
        let err = open_checked(&link, &no_follow).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    }
}

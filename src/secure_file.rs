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
    // A caller naming no owner judges the file under its own rule, this
    // included (`key_file` does, under the security model's).
    if let Some(owner) = req.owner {
        check_filesystem(&file, &owner, Path::new("/proc"))?;
    }
    let mut forbidden = req.forbidden_mode_bits;
    if req.allow_group_read_if_root_owned && meta.uid() == 0 {
        forbidden &= !GROUP_READ;
    }
    check_metadata(&meta, req.owner, forbidden)?;
    // The same rules for anyone a POSIX ACL names: write only for an owner
    // `req` accepts (root alone when it names none), and read for nobody
    // but root where group read is forbidden. The root-owned group-read
    // allowance is for the file's own group, not for named entries.
    let forbid_write = req.forbidden_mode_bits & GROUP_WRITE != 0;
    let forbid_read = req.forbidden_mode_bits & GROUP_READ != 0;
    if forbid_write || forbid_read {
        let writers = req.owner.unwrap_or(Owner::Root);
        if let Some(problem) = acl_problem(&acl_grants_of_file(&file)?, &writers, forbid_write, forbid_read) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, problem));
        }
    }
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
/// The one exception: write bits are ignored on a **sticky** directory on a
/// read-only mount. A Kubernetes Secret or projected volume's root is
/// `1777` but mounted read-only, so nothing in this container can write to
/// it, and the sticky bit stops anyone writing the volume elsewhere from
/// renaming or deleting entries they don't own. A directory that isn't
/// sticky -- a ConfigMap or `emptyDir` volume's `0777` root -- is refused
/// even read-only: a ConfigMap belongs in a `projected:` volume instead.
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
/// passes, sticky or not -- the sticky-and-read-only exception aside -- and
/// neither does a POSIX ACL entry giving write to anyone else.
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
                DirProblem::Acl(problem) => format!("{problem}, so entries could be created or replaced in it"),
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
    /// a sticky directory on a read-only mount, which nobody here can write
    /// to.
    Writable { mode: u32 },
    /// A POSIX ACL entry gives write access to someone `trust` doesn't
    /// accept; says whom.
    Acl(String),
}

/// Whether one directory is trustworthy under `trust`: a directory, owned
/// by someone `trust` accepts, and writable by nobody else -- through its
/// group only if `trust` accepts that group, by others never, sticky or
/// not, nor through a POSIX ACL entry -- unless it is sticky and on a
/// read-only mount.
/// The one rule every directory check in this crate, and the CLI's, applies.
pub fn judge_dir(dir: &Path, trust: &dyn PrincipalTrust) -> Result<(), DirProblem> {
    let meta = std::fs::metadata(dir).map_err(|e| DirProblem::Unexaminable(e.to_string()))?;
    if !meta.is_dir() {
        return Err(DirProblem::NotADirectory);
    }
    if !trust.trusts_owner(meta.uid()) {
        return Err(DirProblem::Owner(meta.uid()));
    }
    // Sticky as well as read-only: a read-only mount says nothing about who
    // writes the volume elsewhere (a sidecar's read-write mount, the node),
    // and in a directory that isn't sticky any of them could rename or
    // delete what is in it. A Kubernetes Secret or projected volume's root
    // is sticky; a ConfigMap or emptyDir volume's is not.
    let exempt = || meta.mode() & STICKY != 0 && on_read_only_mount(dir);
    if untrusted_write_bits(&meta, trust) != 0 && !exempt() {
        return Err(DirProblem::Writable { mode: meta.mode() & 0o7777 });
    }
    let grants = acl_grants_of_path(dir).map_err(|e| DirProblem::Unexaminable(e.to_string()))?;
    if let Some(problem) = acl_problem(&grants, trust, true, false) {
        if !exempt() {
            return Err(DirProblem::Acl(problem));
        }
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
/// every case, by comparing the descriptor's device and inode with the file
/// `target_real` names now, reached without following a single symlink
/// ([`stat_without_links`]).
///
/// `target_real` is a resolved path, so it had no symlinks in it when it
/// was resolved. One put in place of a directory on the way since then
/// would be followed by the open and by a plain `stat` alike, and the two
/// would agree; walking the path a component at a time, refusing every
/// link, is what makes the comparison conclusive without `/proc` (masked,
/// as in some minimal containers and sandboxes, or a non-Linux build). The
/// CLI's own opens use the same check.
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
    let resolved = stat_without_links(target_real)
        .map_err(|e| denied(format!("{} changed after it was opened: {e}", target_real.display())))?;
    if (opened.dev(), opened.ino()) != (resolved.dev(), resolved.ino()) {
        return Err(denied(format!("{} was replaced between resolution and open", target_real.display())));
    }
    Ok(())
}

/// The metadata of what the absolute path `path` names, reached from `/`
/// one component at a time through directory descriptors, each opened with
/// `O_NOFOLLOW`: a symlink anywhere in the path -- the last component
/// included -- is an error, never followed. `.` and `..` are refused too:
/// a resolved path has neither.
#[cfg(all(target_os = "linux", not(miri)))]
fn stat_without_links(path: &Path) -> io::Result<Metadata> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::path::Component;

    let refused = |what: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("{what} in {}", path.display()));
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(refused("not an absolute path"));
    }
    // O_PATH: a handle on the entry itself, needing no read permission and
    // never blocking (a FIFO, a device) -- only search permission on each
    // directory, as the open being verified needed too.
    let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut here = std::fs::OpenOptions::new().read(true).custom_flags(flags).open("/")?;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(refused("a `.` or `..` component"));
        };
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| refused("a NUL byte"))?;
        // SAFETY: `here` is an open descriptor and `name` a valid
        // NUL-terminated string, both alive for the call.
        let fd = unsafe { libc::openat(here.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by openat and is owned by nothing else.
        here = unsafe { File::from_raw_fd(fd) };
        // With O_PATH | O_NOFOLLOW a symlink is opened as itself, not
        // refused: it is refused here.
        if here.metadata()?.file_type().is_symlink() {
            return Err(refused("a symbolic link"));
        }
    }
    here.metadata()
}

/// Elsewhere (and under Miri, which has no `openat`): what the path names
/// now, its last component not followed.
#[cfg(not(all(target_os = "linux", not(miri))))]
fn stat_without_links(path: &Path) -> io::Result<Metadata> {
    std::fs::symlink_metadata(path)
}

/// `statfs`'s `f_type` for every FUSE filesystem: `fuse`, `fuseblk`, and
/// virtiofs, which is FUSE with the host as its server.
#[cfg(target_os = "linux")]
const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;

/// Refuses a file on a filesystem whose server -- the process that answers
/// every `stat` and `read` of it -- is someone `trust` doesn't accept as an
/// owner.
///
/// Every other check here reads what the filesystem reports: owner, mode,
/// ACL, contents. On a FUSE mount all of that is whatever its server
/// chooses to say, and `fusermount` lets any user be one: a file there can
/// be "owned by root, mode 0600" and hold bytes its mounter picked. (The
/// kernel hides such a mount from other users unless it was mounted with
/// `allow_other`, which `/etc/fuse.conf` can permit; root sees it either
/// way.) So the server is held to the rule an owner is: `user_id=` in the
/// mount's options is the uid `/dev/fuse` was opened by, and it must be one
/// `trust` accepts -- root for configuration and, under the production
/// model, for key files. A root-mounted FUSE filesystem (a CSI driver's, an
/// NTFS volume's) passes, and so does virtiofs, whose server is the
/// hypervisor: only root can mount one.
///
/// The mount is found in `<proc>/self/mountinfo` by the file's device
/// number, and only for a file `fstatfs` says is on FUSE: every other file
/// passes without `/proc` being read. A FUSE file whose mount can't be
/// found there -- no `/proc`, or a descriptor from a mount this process
/// can't see -- is refused.
///
/// What this does not cover: a disk image someone crafted and had mounted
/// (a removable drive, a loop device). Its filesystem is an ordinary one,
/// served by the kernel, and it says what its author wrote into it. Such a
/// mount is root's doing, and where key files are looked for is too.
///
/// Every refusal is `PermissionDenied` with no `raw_os_error`, as
/// [`open_checked`]'s own checks are.
pub fn check_filesystem(file: &File, trust: &dyn PrincipalTrust, proc_root: &Path) -> io::Result<()> {
    #[cfg(all(target_os = "linux", not(miri)))]
    {
        use std::os::unix::io::AsRawFd;
        let denied = |what: String| io::Error::new(io::ErrorKind::PermissionDenied, what);
        // SAFETY: an all-zero `statfs` is a valid out-parameter (plain integers).
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: `file` is an open descriptor for the length of the call;
        // `st` is a properly sized out-parameter that fstatfs fully
        // initializes on success, and is read only then.
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut st) } != 0 {
            return Err(denied(format!("could not tell which filesystem it is on: {}", io::Error::last_os_error())));
        }
        #[allow(clippy::unnecessary_cast)] // `f_type`'s width and sign differ by target
        if st.f_type as u64 != FUSE_SUPER_MAGIC {
            return Ok(());
        }
        let dev = file.metadata().map_err(|e| denied(format!("could not stat the opened file: {e}")))?.dev();
        let mounts = std::fs::read_to_string(proc_root.join("self/mountinfo")).map_err(|e| {
            denied(format!(
                "it is on a FUSE filesystem, and who serves it could not be read from {}/self/mountinfo: {e}",
                proc_root.display()
            ))
        })?;
        match fuse_server(&mounts, dev) {
            Some(FuseServer::Hypervisor) => Ok(()),
            Some(FuseServer::Uid(uid)) if trust.trusts_owner(uid) => Ok(()),
            Some(FuseServer::Uid(uid)) => Err(denied(format!(
                "it is on a FUSE filesystem served by uid {uid}, which is not an allowed owner: its contents and its \
                 reported owner and mode are whatever that user's process says they are"
            ))),
            None => Err(denied("it is on a FUSE filesystem whose mount, and so whose server, could not be identified".into())),
        }
    }
    #[cfg(not(all(target_os = "linux", not(miri))))]
    {
        // Elsewhere there is no FUSE to ask about; and Miri, which runs
        // the tests to check `unsafe` code, can't call fstatfs.
        let _ = (file, trust, proc_root);
        Ok(())
    }
}

/// Who answers for a FUSE filesystem.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum FuseServer {
    /// virtiofs: the virtual machine's host.
    Hypervisor,
    /// The user whose process opened `/dev/fuse` for the mount.
    Uid(u32),
}

/// The server of the FUSE filesystem with device number `dev`, from the
/// text of a `mountinfo` file; `None` if no mount of that device is listed,
/// or the one listed is no FUSE mount or names no server.
///
/// A line is `id parent major:minor root mountpoint options [tags...] -
/// fstype source superoptions`. The kernel writes spaces inside a field as
/// `\040`, so fields split on spaces, and the lone `-` is found after the
/// six fixed fields, where no path can be mistaken for it. Every mount of
/// one filesystem shares its device number, type and super options, so the
/// first line that matches is as good as any.
#[cfg(target_os = "linux")]
fn fuse_server(mountinfo: &str, dev: u64) -> Option<FuseServer> {
    // The kernel's encoding of a device number, as glibc's major()/minor().
    let major = ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0xfff);
    let minor = ((dev >> 12) & 0xffff_ff00) | (dev & 0xff);
    let wanted = format!("{major}:{minor}");
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.get(2) != Some(&wanted.as_str()) {
            continue;
        }
        let separator = fields.iter().skip(6).position(|f| *f == "-")? + 6;
        let fstype = *fields.get(separator + 1)?;
        if fstype == "virtiofs" {
            return Some(FuseServer::Hypervisor);
        }
        let kind = fstype.split('.').next()?; // "fuse.sshfs": the subtype is the server's to choose
        if kind != "fuse" && kind != "fuseblk" {
            return None;
        }
        let options = fields.get(separator + 3)?;
        let uid = options.split(',').find_map(|o| o.strip_prefix("user_id="))?;
        return uid.parse().ok().map(FuseServer::Uid);
    }
    None
}

fn on_read_only_mount(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    // Miri, which runs the tests to check `unsafe` code, can't call
    // statvfs: under it nothing is a read-only mount, as no test directory is.
    if cfg!(miri) {
        return false;
    }
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

// ---------------------------------------------------------------------
// POSIX ACLs.
//
// Owner and mode bits are not the whole story: a POSIX access ACL can name
// further users and groups, each with its own permissions. With such an
// entry the mode's group bits are the ACL's *mask*, an upper bound on every
// named entry -- so `root:svc 0440` can carry `user:mallory:r--` and still
// look like a file only `svc` reads. Every check here that judges who may
// read or write a file or directory also judges its named ACL entries.
// ---------------------------------------------------------------------

/// Whom a named POSIX ACL entry is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclWho {
    User(u32),
    Group(u32),
}

/// A named entry of a POSIX access ACL: someone the owner, group and other
/// bits don't describe. `perm` is what the entry can actually do -- its
/// permission bits (read 4, write 2, execute 1) masked by the ACL's mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclGrant {
    pub who: AclWho,
    pub perm: u32,
}

const ACL_ACCESS_XATTR: &std::ffi::CStr = c"system.posix_acl_access";
const ACL_XATTR_VERSION: u32 = 2;
const ACL_USER: u16 = 0x02;
const ACL_GROUP: u16 = 0x08;
const ACL_MASK: u16 = 0x10;
const ACL_READ: u32 = 4;
const ACL_WRITE: u32 = 2;

/// The named entries of the POSIX access ACL in `xattr` (the kernel's
/// `system.posix_acl_access` format: a version, then 8-byte entries).
/// Anything malformed is an error: an ACL that can't be read can't be
/// judged, so it is refused rather than ignored.
fn parse_acl(xattr: &[u8]) -> io::Result<Vec<AclGrant>> {
    let bad = |why: &str| io::Error::new(io::ErrorKind::PermissionDenied, format!("unreadable POSIX ACL: {why}"));
    let (header, entries) = xattr.split_at_checked(4).ok_or_else(|| bad("too short"))?;
    if u32::from_le_bytes(header.try_into().unwrap()) != ACL_XATTR_VERSION {
        return Err(bad("unknown version"));
    }
    let (entries, rest) = entries.as_chunks::<8>();
    if !rest.is_empty() {
        return Err(bad("truncated entry"));
    }
    let entries: Vec<(u16, u32, u32)> = entries
        .iter()
        .map(|e| {
            let tag = u16::from_le_bytes([e[0], e[1]]);
            let perm = u32::from(u16::from_le_bytes([e[2], e[3]]));
            let id = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
            (tag, perm, id)
        })
        .collect();
    // No mask entry with named entries present isn't a valid ACL; judge
    // their own permissions, unmasked, rather than guess.
    let mask = entries.iter().find(|(tag, _, _)| *tag == ACL_MASK).map_or(0o7, |(_, perm, _)| *perm);
    Ok(entries
        .iter()
        .filter_map(|&(tag, perm, id)| match tag {
            ACL_USER => Some(AclGrant { who: AclWho::User(id), perm: perm & mask }),
            ACL_GROUP => Some(AclGrant { who: AclWho::Group(id), perm: perm & mask }),
            _ => None,
        })
        .collect())
}

/// Reads an extended attribute through `get` (`getxattr` or `fgetxattr`,
/// given the buffer and its size). `None` when there is none, or the
/// filesystem has no extended attributes at all.
fn read_xattr(get: impl Fn(*mut libc::c_void, usize) -> isize) -> io::Result<Option<Vec<u8>>> {
    loop {
        let size = get(std::ptr::null_mut(), 0);
        if size < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(None),
                _ => Err(e),
            };
        }
        let mut buf = vec![0u8; size as usize];
        let got = get(buf.as_mut_ptr().cast(), buf.len());
        if got >= 0 {
            buf.truncate(got as usize);
            return Ok(Some(buf));
        }
        match io::Error::last_os_error().raw_os_error() {
            Some(libc::ERANGE) => continue, // it grew between the two calls
            Some(libc::ENODATA) | Some(libc::ENOTSUP) => return Ok(None),
            _ => return Err(io::Error::last_os_error()),
        }
    }
}

/// The named entries of the open file's access ACL; none when it has no
/// ACL beyond its mode bits. Every failure is `PermissionDenied`: an ACL
/// that couldn't be read couldn't be judged.
pub fn acl_grants_of_file(file: &File) -> io::Result<Vec<AclGrant>> {
    use std::os::unix::io::AsRawFd;
    // Miri can't call fgetxattr: under it no file has an ACL, as no test file does.
    if cfg!(miri) {
        return Ok(Vec::new());
    }
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is open for the life of `file`; the buffer pointer and
    // size come from `read_xattr`, which passes a live buffer of that size.
    let raw = read_xattr(|buf, size| unsafe { libc::fgetxattr(fd, ACL_ACCESS_XATTR.as_ptr(), buf, size) })
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("could not read its POSIX ACL: {e}")))?;
    raw.map_or(Ok(Vec::new()), |raw| parse_acl(&raw))
}

/// [`acl_grants_of_file`] for what `path` names, symlinks followed.
pub fn acl_grants_of_path(path: &Path) -> io::Result<Vec<AclGrant>> {
    use std::os::unix::ffi::OsStrExt;
    if cfg!(miri) {
        return Ok(Vec::new());
    }
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "path contains a NUL byte"))?;
    // SAFETY: `c_path` is NUL-terminated and outlives the call; the buffer
    // pointer and size come from `read_xattr`.
    let raw = read_xattr(|buf, size| unsafe { libc::getxattr(c_path.as_ptr(), ACL_ACCESS_XATTR.as_ptr(), buf, size) })
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("could not read its POSIX ACL: {e}")))?;
    raw.map_or(Ok(Vec::new()), |raw| parse_acl(&raw))
}

/// Why `grants` give access `trust` doesn't allow, if they do: with
/// `forbid_write`, write to a named user it doesn't trust as an owner, or a
/// named group it doesn't trust as a writer -- the same rule the mode's
/// group and other write bits are held to -- and with `forbid_read`, read
/// to anyone but root.
pub fn acl_problem(grants: &[AclGrant], trust: &dyn PrincipalTrust, forbid_write: bool, forbid_read: bool) -> Option<String> {
    grants.iter().find_map(|g| {
        let (kind, id, trusted_writer) = match g.who {
            AclWho::User(uid) => ("user", uid, trust.trusts_owner(uid)),
            AclWho::Group(gid) => ("group", gid, trust.trusts_group_writer(gid)),
        };
        if forbid_write && g.perm & ACL_WRITE != 0 && !trusted_writer {
            return Some(format!("a POSIX ACL entry gives {kind} {id} write access"));
        }
        if forbid_read && g.perm & ACL_READ != 0 && g.who != AclWho::User(0) {
            return Some(format!("a POSIX ACL entry gives {kind} {id} read access"));
        }
        None
    })
}

/// Refuses an open file whose ACL gives write access to someone `trust`
/// doesn't accept -- see [`acl_problem`]. `PermissionDenied`, with no
/// `raw_os_error`, like every other trust refusal here.
pub fn check_acl_trusting(file: &File, trust: &dyn PrincipalTrust) -> io::Result<()> {
    match acl_problem(&acl_grants_of_file(file)?, trust, true, false) {
        Some(problem) => Err(io::Error::new(io::ErrorKind::PermissionDenied, problem)),
        None => Ok(()),
    }
}

/// Removes any access ACL from a file this process just created, so it has
/// exactly the owner, group and mode it is then given. A directory's
/// default ACL is copied onto every file created in it; a key directory
/// carrying one would otherwise make each new key or authValue file
/// readable by whoever it names. No ACL, or no ACL support, is success.
pub fn strip_acl(file: &File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    if cfg!(miri) {
        return Ok(());
    }
    // SAFETY: a valid open descriptor and a NUL-terminated name.
    if unsafe { libc::fremovexattr(file.as_raw_fd(), ACL_ACCESS_XATTR.as_ptr()) } == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(()),
        _ => Err(e),
    }
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
    #[cfg_attr(not(any(feature = "tpm2", test)), allow(dead_code))]
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

    /// The identity of the open file `file`: exactly the one read through
    /// it, whatever has happened at its path since.
    #[cfg_attr(not(any(feature = "tpm2", feature = "pkcs11")), allow(dead_code))]
    pub(crate) fn of_file(file: &std::fs::File) -> Option<Self> {
        Some(Self::from_meta(&file.metadata().ok()?))
    }

    fn from_meta(m: &Metadata) -> Self {
        FileIdentity { dev: m.dev(), ino: m.ino(), len: m.len(), mtime: (m.mtime(), m.mtime_nsec()) }
    }
}

/// Overwrites the regular file at `path` with zeros, in place and synced,
/// before it is deleted: for a secret this library wrote and is now
/// retiring. Every name the file has (a hard link left by an interrupted
/// write, say) then holds zeros too.
///
/// Best effort against what the storage does underneath: a journal, a
/// snapshot, a copy-on-write filesystem or a flash translation layer may
/// keep the old blocks, and no call here can reach those. It does mean the
/// value is no longer in the file's own blocks on a filesystem that writes
/// in place, nor readable through a link or an open descriptor.
///
/// `path` is not followed if it is a symlink, and only a regular file is
/// written to. The file is made owner-writable first (these files are
/// created read-only), which its owner and root may do.
#[cfg_attr(not(any(feature = "tpm2", test)), allow(dead_code))]
pub(crate) fn zero_regular_file(path: &Path) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let no_follow = if cfg!(miri) { libc::O_NOFOLLOW } else { libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY };
    let not_regular = || io::Error::new(io::ErrorKind::InvalidData, "not a regular file");
    // Read-only first: a descriptor to check, and to change the mode
    // through, so nothing is done to whatever a name is swapped for.
    let handle = OpenOptions::new().read(true).custom_flags(no_follow).open(path)?;
    let meta = handle.metadata()?;
    if !meta.file_type().is_file() {
        return Err(not_regular());
    }
    handle.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let mut file = OpenOptions::new().write(true).custom_flags(no_follow).open(path)?;
    let opened = file.metadata()?;
    if (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the file was replaced while it was being overwritten"));
    }
    let zeros = [0u8; 4096];
    let mut left = opened.len();
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..n])?;
        left -= n as u64;
    }
    file.sync_all()
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
        // 0700 whatever the umask: a 002 umask would leave `real` group-writable, and refused.
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(base.join("real")).unwrap();
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
    #[cfg(not(miri))]
    fn verify_opened_without_proc_refuses_a_directory_swapped_for_a_link() {
        // The resolved path had no links in it. One put in place of a
        // directory afterwards is followed by the open, and would be by a
        // plain stat of the path too: the two would agree on the wrong
        // file. With no /proc to say where the descriptor really is, the
        // path is walked link-free instead, and the link is refused.
        let dir = private_tempdir();
        let d = std::fs::canonicalize(dir.path()).unwrap();
        let (real, elsewhere) = (d.join("keys"), d.join("elsewhere"));
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(real.join("a.key"), b"real").unwrap();
        std::fs::write(elsewhere.join("a.key"), b"planted").unwrap();
        let target = real.join("a.key");
        let no_proc = d.join("no-proc-here");

        verify_opened(&File::open(&target).unwrap(), &target, &target, &no_proc).expect("the real file, by a real path");

        std::fs::rename(&real, d.join("keys.moved")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &real).unwrap();
        let planted = File::open(&target).unwrap(); // follows the link, as the library's open would
        let err = verify_opened(&planted, &target, &target, &no_proc).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("symbolic link"), "says why: {err}");
        // A link as the last component is no better.
        let link = d.join("link.key");
        std::os::unix::fs::symlink(elsewhere.join("a.key"), &link).unwrap();
        assert!(verify_opened(&planted, &link, &link, &no_proc).is_err());
        // Nor a path that isn't a resolved one at all.
        assert!(verify_opened(&planted, &elsewhere.join("../elsewhere/a.key"), &d, &no_proc).is_err());
        verify_opened(&planted, &elsewhere.join("a.key"), &d, &no_proc).expect("where it really is");
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
            std::fs::metadata(d)
                .map(|m| m.mode() & FORBID_GROUP_OTHER_WRITE != 0 && !(m.mode() & STICKY != 0 && on_read_only_mount(d)))
                .unwrap_or(false)
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

    // Device numbers as the kernel encodes them: major 0 for every
    // anonymous (FUSE, tmpfs) device.
    fn dev(major: u64, minor: u64) -> u64 {
        ((major & 0xffff_f000) << 32) | ((major & 0xfff) << 8) | ((minor & 0xffff_ff00) << 12) | (minor & 0xff)
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn the_server_of_a_fuse_mount_is_read_from_its_own_mountinfo_line() {
        let mounts = "\
36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
1012 866 0:60 /by-app/x /run/flatpak/doc rw,nosuid,nodev,relatime master:677 - fuse.portal portal rw,user_id=1000,group_id=1000
1154 1153 8:33 / /media/u/My\\040Passport rw,nosuid,nodev,relatime master:941 - fuseblk /dev/sdc1 rw,user_id=0,group_id=0,allow_other
77 60 0:71 / /run/kata/shared rw,relatime - virtiofs kataShared rw
78 60 0:72 / /home/u/remote rw,nosuid,nodev,relatime shared:9 master:3 - fuse.sshfs host:/ rw,user_id=1001,group_id=1001
79 60 0:300 / /mnt/big rw - fuse src rw,user_id=7,group_id=7
80 60 0:73 / /mnt/-\\040- rw - fuse - rw,user_id=8,group_id=8
81 60 0:74 / /mnt/odd rw - fuse src rw,group_id=9
82 60 0:75 / /mnt/odd2 rw - fuse src rw,user_id=root
";
        assert_eq!(fuse_server(mounts, dev(0, 60)), Some(FuseServer::Uid(1000)));
        assert_eq!(fuse_server(mounts, dev(8, 33)), Some(FuseServer::Uid(0)), "an escaped space in the mount point");
        assert_eq!(fuse_server(mounts, dev(0, 71)), Some(FuseServer::Hypervisor));
        assert_eq!(fuse_server(mounts, dev(0, 72)), Some(FuseServer::Uid(1001)), "two optional fields before the separator");
        assert_eq!(fuse_server(mounts, dev(0, 300)), Some(FuseServer::Uid(7)), "a minor above 255");
        assert_eq!(fuse_server(mounts, dev(0, 73)), Some(FuseServer::Uid(8)), "a source that is itself `-`");
        // Nothing that isn't plainly a FUSE mount naming its server.
        assert_eq!(fuse_server(mounts, dev(98, 0)), None, "not a FUSE filesystem");
        assert_eq!(fuse_server(mounts, dev(0, 74)), None, "no user_id");
        assert_eq!(fuse_server(mounts, dev(0, 75)), None, "a user_id that is no number");
        assert_eq!(fuse_server(mounts, dev(0, 99)), None, "no such mount");
        assert_eq!(fuse_server("", dev(0, 60)), None);
        // A mount point can't pose as another mount's line: the device is
        // matched in its own field only.
        assert_eq!(fuse_server("5 4 0:1 / /mnt/0:60 rw - fuse x rw,user_id=0\n", dev(0, 60)), None);
    }

    #[test]
    fn a_file_on_an_ordinary_filesystem_passes_without_proc() {
        // Not FUSE, so nobody's word but the kernel's: `/proc` isn't
        // consulted, and needn't exist.
        let f = temp_file_with(b"contents", 0o600);
        let file = File::open(f.path()).unwrap();
        check_filesystem(&file, &Owner::Root, Path::new("/nonexistent-hkdfguard-proc")).unwrap();
    }

    #[test]
    #[cfg(all(target_os = "linux", not(miri)))]
    fn a_file_on_a_fuse_mount_is_judged_by_who_serves_it() {
        // Whatever FUSE mount this host has that this user can read a
        // file on (a desktop's document portal, an sshfs or NTFS mount);
        // none on a build machine, and then there is nothing to check.
        let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let mount_points = mounts.lines().filter_map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            let separator = fields.iter().skip(6).position(|f| *f == "-")? + 6;
            fields.get(separator + 1)?.starts_with("fuse").then(|| fields[4].replace("\\040", " "))
        });
        for mount_point in mount_points {
            let Some(file) = std::fs::read_dir(&mount_point)
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                .find_map(|e| File::open(e.path()).ok())
            else {
                continue;
            };
            let server = fuse_server(&mounts, file.metadata().unwrap().dev()).expect("a FUSE mount names its server");
            let FuseServer::Uid(uid) = server else { continue };
            struct Only(u32);
            impl PrincipalTrust for Only {
                fn trusts_owner(&self, uid: u32) -> bool {
                    uid == self.0
                }
                fn trusts_group_writer(&self, _gid: u32) -> bool {
                    false
                }
            }
            check_filesystem(&file, &Only(uid), Path::new("/proc")).expect("served by a trusted user");
            let err = check_filesystem(&file, &Only(uid.wrapping_add(1)), Path::new("/proc")).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert!(err.raw_os_error().is_none() && err.to_string().contains("FUSE"), "{err}");
            let err = check_filesystem(&file, &Only(uid), Path::new("/nonexistent-hkdfguard-proc")).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "without /proc nobody can be shown to serve it");
            return;
        }
        eprintln!("skipping: no readable file on a FUSE mount on this host");
    }

    #[test]
    fn zeroing_a_file_overwrites_every_link_to_it_and_nothing_else() {
        let dir = private_tempdir();
        let secret = dir.path().join("svc.tpmauth");
        std::fs::write(&secret, [0xA5u8; 32]).unwrap();
        chmod(&secret, 0o400); // as these files are created
        let link = dir.path().join(".svc.tpmauth.0123456789abcdef");
        std::fs::hard_link(&secret, &link).unwrap();

        zero_regular_file(&secret).unwrap();
        assert_eq!(std::fs::read(&secret).unwrap(), [0u8; 32], "same length, all zeros");
        assert_eq!(std::fs::read(&link).unwrap(), [0u8; 32], "a second name for the file holds zeros too");

        // Longer than one buffer, and an empty file.
        let long = dir.path().join("long");
        std::fs::write(&long, vec![0x5Au8; 10_000]).unwrap();
        zero_regular_file(&long).unwrap();
        assert_eq!(std::fs::read(&long).unwrap(), vec![0u8; 10_000]);
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        zero_regular_file(&empty).unwrap();

        // Never through a symlink, never a directory, and a missing file says so.
        let other = dir.path().join("other");
        std::fs::write(&other, b"keep me").unwrap();
        let symlink = dir.path().join("link");
        std::os::unix::fs::symlink(&other, &symlink).unwrap();
        assert!(zero_regular_file(&symlink).is_err());
        assert_eq!(std::fs::read(&other).unwrap(), b"keep me");
        assert!(zero_regular_file(dir.path()).is_err());
        assert_eq!(zero_regular_file(&dir.path().join("absent")).unwrap_err().kind(), io::ErrorKind::NotFound);
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
    #[cfg_attr(miri, ignore = "makes a FIFO, which Miri can't")]
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

    // ---- POSIX ACLs ----

    // An access ACL in the kernel's xattr format, from (tag, perm, id).
    fn acl_xattr(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut out = ACL_XATTR_VERSION.to_le_bytes().to_vec();
        for &(tag, perm, id) in entries {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&perm.to_le_bytes());
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }
    const USER_OBJ: u16 = 0x01;
    const GROUP_OBJ: u16 = 0x04;
    const OTHER: u16 = 0x20;
    const UNDEF: u32 = u32::MAX;

    // Owner rw, a named user and a named group each rw, the given mask.
    fn acl_with_mask(mask: u16) -> Vec<u8> {
        acl_xattr(&[
            (USER_OBJ, 6, UNDEF),
            (ACL_USER, 6, 54321),
            (GROUP_OBJ, 4, UNDEF),
            (ACL_GROUP, 6, 54322),
            (ACL_MASK, mask, UNDEF),
            (OTHER, 0, UNDEF),
        ])
    }

    #[test]
    fn named_acl_entries_are_masked_and_malformed_acls_refused() {
        let grants = parse_acl(&acl_with_mask(4)).unwrap();
        assert_eq!(
            grants,
            vec![AclGrant { who: AclWho::User(54321), perm: 4 }, AclGrant { who: AclWho::Group(54322), perm: 4 }],
            "the mask caps each named entry"
        );
        assert!(parse_acl(&acl_with_mask(0)).unwrap().iter().all(|g| g.perm == 0), "a zero mask leaves them nothing");
        let base_only = acl_xattr(&[(USER_OBJ, 6, UNDEF), (GROUP_OBJ, 4, UNDEF), (OTHER, 0, UNDEF)]);
        assert!(parse_acl(&base_only).unwrap().is_empty(), "no named entries");
        for bad in [vec![2u8, 0], vec![3, 0, 0, 0], { let mut v = acl_with_mask(6); v.pop(); v }] {
            assert_eq!(parse_acl(&bad).unwrap_err().kind(), io::ErrorKind::PermissionDenied, "{bad:?}");
        }
    }

    // A trust rule for the tests: these owners and these writer groups.
    struct Trusting {
        owners: Vec<u32>,
        writer_groups: Vec<u32>,
    }
    impl PrincipalTrust for Trusting {
        fn trusts_owner(&self, uid: u32) -> bool {
            self.owners.contains(&uid)
        }
        fn trusts_group_writer(&self, gid: u32) -> bool {
            self.writer_groups.contains(&gid)
        }
    }

    #[test]
    fn acl_entries_are_judged_as_owners_and_group_writers_are() {
        let rw = |who| AclGrant { who, perm: 6 };
        let r = |who| AclGrant { who, perm: 4 };
        let trust = Trusting { owners: vec![0, 54321], writer_groups: vec![54322] };
        assert_eq!(acl_problem(&[rw(AclWho::User(54321)), rw(AclWho::Group(54322))], &trust, true, false), None, "both trusted");
        let problem = acl_problem(&[rw(AclWho::User(1002))], &trust, true, false).unwrap();
        assert!(problem.contains("user 1002 write access"), "{problem}");
        let problem = acl_problem(&[rw(AclWho::Group(2003))], &trust, true, false).unwrap();
        assert!(problem.contains("group 2003 write access"), "{problem}");
        assert_eq!(acl_problem(&[rw(AclWho::User(1002))], &trust, false, false), None, "write not forbidden");

        // Read, where it is forbidden: nobody but root, trusted writer or not.
        assert_eq!(acl_problem(&[r(AclWho::User(54321))], &trust, true, false), None);
        let problem = acl_problem(&[r(AclWho::User(54321))], &trust, true, true).unwrap();
        assert!(problem.contains("user 54321 read access"), "{problem}");
        assert!(acl_problem(&[r(AclWho::Group(54322))], &trust, true, true).is_some());
        assert_eq!(acl_problem(&[r(AclWho::User(0))], &trust, true, true), None, "root reads anything anyway");
    }

    // Sets `xattr` as `path`'s access ACL; false where the filesystem has
    // no ACL support, so the test can say it skipped.
    fn set_acl(path: &Path, xattr: &[u8]) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path and name, and a live buffer of that length.
        let rc = unsafe { libc::setxattr(c.as_ptr(), ACL_ACCESS_XATTR.as_ptr(), xattr.as_ptr().cast(), xattr.len(), 0) };
        if rc == 0 {
            return true;
        }
        let e = io::Error::last_os_error();
        assert_eq!(e.raw_os_error(), Some(libc::ENOTSUP), "setting an ACL failed: {e}");
        false
    }

    #[test]
    #[cfg_attr(miri, ignore = "sets an extended attribute, which Miri can't")]
    fn a_real_acl_is_read_back_and_strip_acl_removes_it() {
        let f = temp_file_with(b"x", 0o600);
        if !set_acl(f.path(), &acl_with_mask(6)) {
            eprintln!("skipping: this filesystem has no POSIX ACLs");
            return;
        }
        let file = File::open(f.path()).unwrap();
        assert_eq!(
            acl_grants_of_file(&file).unwrap(),
            vec![AclGrant { who: AclWho::User(54321), perm: 6 }, AclGrant { who: AclWho::Group(54322), perm: 6 }]
        );
        assert_eq!(acl_grants_of_path(f.path()).unwrap(), acl_grants_of_file(&file).unwrap(), "by path, the same");

        // With an ACL the mode's group bits are its mask: rw here.
        assert_eq!(std::fs::metadata(f.path()).unwrap().mode() & 0o070, 0o060);
        let me = Owner::RootOrCurrentUser;
        let problem = check_acl_trusting(&file, &me).unwrap_err().to_string();
        assert!(problem.contains("user 54321 write access"), "{problem}");

        let writable = OpenOptions::new().write(true).open(f.path()).unwrap();
        strip_acl(&writable).unwrap();
        assert!(acl_grants_of_file(&file).unwrap().is_empty(), "removed");
        strip_acl(&writable).unwrap(); // and removing none is fine
        check_acl_trusting(&file, &me).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "sets an extended attribute, which Miri can't")]
    fn a_directory_writable_through_a_trusted_group_but_also_a_named_user_is_refused() {
        // The case the mode bits can't show: group write is accepted for a
        // trusted (deployer) group, and with an ACL that same group-class
        // write is the mask -- which lets a named user write too.
        let dir = private_tempdir();
        let d = std::fs::canonicalize(dir.path()).unwrap();
        // SAFETY: getuid/getgid take no arguments and cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let trust = Trusting { owners: vec![0, uid], writer_groups: vec![gid] };
        chmod(&d, 0o770);
        judge_dir(&d, &trust).expect("group write through a trusted group is fine");

        let acl = acl_xattr(&[(USER_OBJ, 7, UNDEF), (ACL_USER, 7, 65534), (GROUP_OBJ, 7, UNDEF), (ACL_MASK, 7, UNDEF), (OTHER, 0, UNDEF)]);
        if !set_acl(&d, &acl) {
            eprintln!("skipping: this filesystem has no POSIX ACLs");
            return;
        }
        assert_eq!(std::fs::metadata(&d).unwrap().mode() & 0o777, 0o770, "the mode alone looks the same");
        match judge_dir(&d, &trust) {
            Err(DirProblem::Acl(problem)) => assert!(problem.contains("user 65534 write access"), "{problem}"),
            other => panic!("expected the ACL to be refused, got {other:?}"),
        }
        let err = check_dir_chain_trusting(&d, &trust).unwrap_err().to_string();
        assert!(err.contains("POSIX ACL entry gives user 65534 write access"), "{err}");
        chmod(&d, 0o700);
    }
}

//! The security model (`security_model` in the policy file): who may create
//! and retire KEKs, and whose key files `hkdfguard_open_file` trusts. The
//! Windows build's `SecurityModel` policy value, setting for setting.
//!
//! - **Production** -- the default: no policy file, or one that doesn't set
//!   it. Creating a KEK and retiring one take root (an application may still
//!   call `hkdfguard_create_kek` for a KEK that already exists, as at
//!   startup). A key file, and every directory deciding what its path names,
//!   must be owned by root or by a *deployer* -- a direct member of the
//!   `hkdfguard-deployers` group (the packages create it) or of a group the
//!   policy lists in `deployer_groups` -- and may be writable through its
//!   group only when that group is itself a deployer group. The calling
//!   account is trusted only if it is a deployer, so an application that
//!   unwraps (and wraps in memory) cannot persist a key file its own service
//!   would accept.
//! - **Developer**: anyone who can reach the provider may create a KEK, and
//!   key files owned by root or by the calling user are trusted -- the rule
//!   every build applied before the security model existed. Reading a key
//!   file under it is audited (event 1005), once per process.
//!
//! Wrapping and unwrapping are the same in both: the provider's own access
//! control (the `tss` group and derivation secret, the PIN file, the secret
//! file's mode) decides who may use a KEK at all. Wrap and unwrap are the
//! same ECDH operation on the KEK, so no setting can grant one without the
//! other; what the model decides is whose key files are believed.
//!
//! "Direct member" means what `getgrnam(3)` and `getpwuid(3)` say: the
//! group's member list names the user, or the group is the user's primary
//! group. Through NSS a directory (LDAP, sssd) group counts like a local
//! one. Membership is looked up on every call, so removing a deployer makes
//! the key files they own untrusted at once: redeploy those first.

use crate::error::{Error, Result};
use crate::policy;
use crate::secure_file::PrincipalTrust;
use serde::Deserialize;
use std::ffi::{CStr, CString};

/// The security model in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityModel {
    #[default]
    Production,
    Developer,
}

impl SecurityModel {
    /// The `HKDFGUARD_SECURITY_MODEL_*` value: the Windows build's numbers.
    pub fn c_value(self) -> i32 {
        match self {
            SecurityModel::Production => 0,
            SecurityModel::Developer => 1,
        }
    }
}

/// The deployer group the packages create, trusted under the production
/// model whenever it exists. The Windows MSI's `HkdfGuardDeployers`.
pub const DEPLOYERS_GROUP: &str = "hkdfguard-deployers";

/// Groups that may never be deployer groups, nor be given a key file by the
/// CLI's `--group`: each covers essentially every account on a typical
/// host, or the host's administrators or log readers. Matched by resolved
/// gid as well as by name; gid 0 and the overflow gid 65534 are refused
/// whatever their names. The Windows build refuses its own equivalents
/// (Everyone, Users, Authenticated Users, ...).
pub const OVER_BROAD_GROUPS: &[&str] = &["root", "users", "nogroup", "nobody", "wheel", "sudo", "adm", "staff"];

/// The model the policy sets: Production with no policy file, the policy's
/// error if it can't be used.
pub(crate) fn current() -> Result<SecurityModel> {
    match policy::load() {
        None => Ok(SecurityModel::Production),
        Some(Ok(p)) => Ok(p.security_model()),
        Some(Err(e)) => Err(e),
    }
}

/// Whether this process may create a KEK that doesn't exist yet, or retire
/// one: under Developer anyone may; under Production only root.
pub(crate) fn may_administer_keks(model: SecurityModel) -> bool {
    // SAFETY: geteuid takes no arguments and cannot fail.
    model == SecurityModel::Developer || unsafe { libc::geteuid() } == 0
}

/// One deployer group: its gid, and the names its member list holds, as
/// the raw bytes NSS returned (never lossily decoded, so two different
/// names can't compare equal).
#[derive(Debug, Clone)]
struct DeployerGroup {
    gid: libc::gid_t,
    members: Vec<Vec<u8>>,
}

/// Whose key files, and key-file directories, this process trusts under
/// the model in force: the answer [`crate::key_file::read`] checks every
/// owner and group-writable directory against.
#[derive(Debug, Clone)]
pub(crate) struct Trust {
    model: SecurityModel,
    euid: libc::uid_t,
    deployers: Vec<DeployerGroup>,
}

impl Trust {
    /// The trust in force now: the policy's model, and under Production its
    /// deployer groups, resolved. Fails with the policy's error if the
    /// policy can't be used, or with [`Error::GroupInvalid`] if a
    /// `deployer_groups` entry doesn't name a group, names an over-broad
    /// one, or can't be looked up (nor can `hkdfguard-deployers`).
    pub(crate) fn current() -> Result<Trust> {
        let (model, extra) = match policy::load() {
            None => (SecurityModel::Production, Vec::new()),
            Some(Ok(p)) => (p.security_model(), p.deployer_groups().to_vec()),
            Some(Err(e)) => return Err(e),
        };
        // SAFETY: geteuid takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let mut deployers = Vec::new();
        if model == SecurityModel::Production {
            // The packages' own group is optional: without it, only root
            // and the policy's groups deploy.
            if let Some(group) = lookup_group(DEPLOYERS_GROUP).map_err(|e| {
                Error::GroupInvalid(format!("could not look up group \"{DEPLOYERS_GROUP}\": {e}"))
            })? {
                deployers.push(vetted(DEPLOYERS_GROUP, group)?);
            }
            for name in &extra {
                let group = lookup_group(name)
                    .map_err(|e| Error::GroupInvalid(format!("deployer_groups: could not look up group \"{name}\": {e}")))?
                    .ok_or_else(|| Error::GroupInvalid(format!("deployer_groups: \"{name}\" does not name a group on this host")))?;
                deployers.push(vetted(name, group)?);
            }
        }
        Ok(Trust { model, euid, deployers })
    }

    pub(crate) fn model(&self) -> SecurityModel {
        self.model
    }

    /// Whether a key file this process writes -- owned by its effective
    /// uid -- would be trusted.
    pub(crate) fn may_write_key_files(&self) -> bool {
        self.trusts_owner(self.euid)
    }

    // Whether `uid` is a direct member of a deployer group. A uid with no
    // passwd entry, or one that can't be looked up, is not.
    fn is_deployer(&self, uid: libc::uid_t) -> bool {
        if self.deployers.is_empty() {
            return false;
        }
        let Ok(Some((name, primary_gid))) = lookup_user(uid) else {
            return false;
        };
        is_deployer_by(&self.deployers, uid, &name, primary_gid, |n| lookup_uid(n).ok().flatten())
    }

    /// Test-only: this process's euid, its user name, and its primary gid.
    #[cfg(test)]
    pub(crate) fn this_user_for_tests() -> (libc::uid_t, String, libc::gid_t) {
        // SAFETY: geteuid takes no arguments and cannot fail.
        let uid = unsafe { libc::geteuid() };
        let (name, gid) = lookup_user(uid).unwrap().expect("this test's user has a passwd entry");
        (uid, String::from_utf8(name).expect("this test's user name is UTF-8"), gid)
    }

    /// Test-only: whether this process's euid is a deployer through the
    /// packages' own group ([`DEPLOYERS_GROUP`]), by its member list or as
    /// its primary group -- the deployers production trusts with no policy
    /// file. True for `ci` in docker/Dockerfile's image, which adds it.
    #[cfg(test)]
    pub(crate) fn this_user_is_packaged_deployer_for_tests() -> bool {
        let (_, name, primary_gid) = Self::this_user_for_tests();
        match lookup_group(DEPLOYERS_GROUP).unwrap() {
            Some(group) => group.gid == primary_gid || group.members.contains(&name.into_bytes()),
            None => false,
        }
    }

    /// Test-only: a production trust with these deployer groups (gid, member
    /// names), unvetted, for this process's euid.
    #[cfg(test)]
    pub(crate) fn production_for_tests(deployers: &[(libc::gid_t, &[&str])]) -> Trust {
        Trust {
            model: SecurityModel::Production,
            // SAFETY: geteuid takes no arguments and cannot fail.
            euid: unsafe { libc::geteuid() },
            deployers: deployers
                .iter()
                .map(|(gid, members)| DeployerGroup { gid: *gid, members: members.iter().map(|m| m.as_bytes().to_vec()).collect() })
                .collect(),
        }
    }
}

impl PrincipalTrust for Trust {
    fn trusts_owner(&self, uid: u32) -> bool {
        uid == 0
            || match self.model {
                SecurityModel::Developer => uid == self.euid,
                SecurityModel::Production => self.is_deployer(uid),
            }
    }

    fn trusts_group_writer(&self, gid: u32) -> bool {
        self.model == SecurityModel::Production && self.deployers.iter().any(|g| g.gid == gid)
    }
}

// A deployer group must not be one that covers essentially everyone: that
// would trust every account's key files. Fails closed: if a listed group
// can't be looked up, whether it is this gid can't be ruled out.
fn vetted(name: &str, group: Group) -> Result<DeployerGroup> {
    let refuse = |why: String| Err(Error::GroupInvalid(format!("deployer group \"{name}\" (gid {}): {why}", group.gid)));
    if group.gid == 0 || group.gid == 65534 || OVER_BROAD_GROUPS.contains(&group.name.as_str()) {
        return refuse("an over-broad group can't be a deployer group".to_string());
    }
    for broad in OVER_BROAD_GROUPS {
        match lookup_group(broad) {
            Ok(Some(g)) if g.gid == group.gid => return refuse(format!("it is the over-broad group \"{broad}\"")),
            Ok(_) => {}
            Err(e) => return refuse(format!("can't confirm it isn't the over-broad group \"{broad}\" ({e})")),
        }
    }
    Ok(DeployerGroup { gid: group.gid, members: group.members })
}

struct Group {
    gid: libc::gid_t,
    name: String,
    members: Vec<Vec<u8>>,
}

// Whether `uid` -- whose passwd entry gives it `name` and `primary_gid` --
// is a direct member of one of `deployers`. A primary group is matched by
// gid. A member list holds user *names*, though, and two uids can share a
// name (a local account and a directory one, or an image's /etc/passwd
// shadowing a directory entry); so a name on the list counts for `uid` only
// if `resolve` -- getpwnam(3) -- maps it back to `uid`. That is the same
// resolution the OS uses when it grants supplementary groups at login, and
// an ambiguous name fails closed for every uid but the one it resolves to.
fn is_deployer_by(
    deployers: &[DeployerGroup],
    uid: libc::uid_t,
    name: &[u8],
    primary_gid: libc::gid_t,
    resolve: impl Fn(&[u8]) -> Option<libc::uid_t>,
) -> bool {
    if deployers.iter().any(|g| g.gid == primary_gid) {
        return true;
    }
    deployers.iter().any(|g| g.members.iter().any(|m| m.as_slice() == name)) && resolve(name) == Some(uid)
}

// getgr*_r / getpw*_r need room for the whole entry, a group's member list
// included, and report ERANGE when it doesn't fit -- routine for a large
// directory group. Start here and double on ERANGE, up to LOOKUP_MAX_BUF.
const LOOKUP_INITIAL_BUF: usize = 16 * 1024;
const LOOKUP_MAX_BUF: usize = 1024 * 1024;

// The group named `name`, with its member list; `None` if there is none.
fn lookup_group(name: &str) -> std::io::Result<Option<Group>> {
    let c_name = CString::new(name).map_err(|_| std::io::Error::other("a group name must not contain a NUL byte"))?;
    let mut size = LOOKUP_INITIAL_BUF;
    loop {
        // SAFETY: an all-zero `group` is a valid out-parameter; getgrnam_r fills it.
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        let mut buf = vec![0u8; size];
        // SAFETY: every pointer is to a live, correctly sized local; `c_name` is NUL-terminated.
        let rc = unsafe { libc::getgrnam_r(c_name.as_ptr(), &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
        if rc == libc::ERANGE && size < LOOKUP_MAX_BUF {
            size = (size * 2).min(LOOKUP_MAX_BUF);
            continue;
        }
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc));
        }
        if result.is_null() {
            return Ok(None);
        }
        let mut members = Vec::new();
        // SAFETY: getgrnam_r set gr_name to a NUL-terminated string, and
        // gr_mem to a NULL-terminated array of them, all inside `buf`. The
        // array is read unaligned: `buf` is a byte buffer, and not every libc
        // aligns the pointers it places in it (macOS's doesn't; glibc does).
        unsafe {
            let mut member = grp.gr_mem;
            while !member.is_null() && !member.read_unaligned().is_null() {
                members.push(CStr::from_ptr(member.read_unaligned()).to_bytes().to_vec());
                member = member.add(1);
            }
            let name = CStr::from_ptr(grp.gr_name).to_string_lossy().into_owned();
            return Ok(Some(Group { gid: grp.gr_gid, name, members }));
        }
    }
}

// The user name (raw bytes) and primary gid of `uid`; `None` if it has no
// passwd entry.
fn lookup_user(uid: libc::uid_t) -> std::io::Result<Option<(Vec<u8>, libc::gid_t)>> {
    let mut size = LOOKUP_INITIAL_BUF;
    loop {
        // SAFETY: an all-zero `passwd` is a valid out-parameter; getpwuid_r fills it.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0u8; size];
        // SAFETY: every pointer is to a live, correctly sized local.
        let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
        if rc == libc::ERANGE && size < LOOKUP_MAX_BUF {
            size = (size * 2).min(LOOKUP_MAX_BUF);
            continue;
        }
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc));
        }
        if result.is_null() {
            return Ok(None);
        }
        // SAFETY: getpwuid_r set pw_name to a NUL-terminated string inside `buf`.
        let name = unsafe { CStr::from_ptr(pwd.pw_name) }.to_bytes().to_vec();
        return Ok(Some((name, pwd.pw_gid)));
    }
}

// The uid the user name `name` resolves to; `None` if no passwd entry has it.
fn lookup_uid(name: &[u8]) -> std::io::Result<Option<libc::uid_t>> {
    let Ok(name) = std::ffi::CString::new(name) else {
        return Ok(None); // an interior NUL names nobody
    };
    let mut size = LOOKUP_INITIAL_BUF;
    loop {
        // SAFETY: an all-zero `passwd` is a valid out-parameter; getpwnam_r fills it.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0u8; size];
        // SAFETY: every pointer is to a live, correctly sized local, and `name` is NUL-terminated.
        let rc = unsafe { libc::getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
        if rc == libc::ERANGE && size < LOOKUP_MAX_BUF {
            size = (size * 2).min(LOOKUP_MAX_BUF);
            continue;
        }
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc));
        }
        return Ok(if result.is_null() { None } else { Some(pwd.pw_uid) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::test_support::TestPolicy;
    use serial_test::serial;

    fn me() -> (libc::uid_t, String, libc::gid_t) {
        Trust::this_user_for_tests()
    }

    #[test]
    fn the_c_values_are_the_windows_build_s() {
        assert_eq!(SecurityModel::Production.c_value(), 0);
        assert_eq!(SecurityModel::Developer.c_value(), 1);
        assert_eq!(SecurityModel::default(), SecurityModel::Production);
    }

    #[test]
    #[serial]
    fn production_is_the_default_with_no_policy_file_or_none_set() {
        let _none = TestPolicy::absent();
        assert_eq!(current().unwrap(), SecurityModel::Production);
        drop(_none);
        let _unset = TestPolicy::exact("[selection]\nmode = \"prefer\"\n");
        assert_eq!(current().unwrap(), SecurityModel::Production);
        assert_eq!(Trust::current().unwrap().model(), SecurityModel::Production);
    }

    #[test]
    #[serial]
    fn an_unusable_policy_fails_closed() {
        let _bad = TestPolicy::exact("security_model = \"lenient\"\n[selection]\nmode = \"prefer\"\n");
        assert!(matches!(current(), Err(Error::Policy(_))));
        assert!(matches!(Trust::current(), Err(Error::Policy(_))));
    }

    #[test]
    #[serial]
    fn developer_trusts_root_and_this_user_and_no_group() {
        let _dev = TestPolicy::write("security_model = \"developer\"\n");
        let trust = Trust::current().unwrap();
        let (uid, _, gid) = me();
        assert_eq!(trust.model(), SecurityModel::Developer);
        assert!(trust.trusts_owner(0));
        assert!(trust.trusts_owner(uid));
        assert!(!trust.trusts_owner(uid.wrapping_add(4242)));
        assert!(!trust.trusts_group_writer(gid));
        assert!(trust.may_write_key_files());
        assert!(may_administer_keks(SecurityModel::Developer));
    }

    #[test]
    fn production_trusts_root_and_deployers_only() {
        let (uid, name, gid) = me();
        if uid == 0 {
            return; // root is trusted whatever the groups say: nothing to show
        }
        let none = Trust::production_for_tests(&[]);
        assert!(none.trusts_owner(0));
        assert!(!none.trusts_owner(uid), "the calling account is not trusted for being the caller");
        assert!(!none.may_write_key_files());
        assert!(!may_administer_keks(SecurityModel::Production));

        // A member by the group's member list...
        let listed = Trust::production_for_tests(&[(gid.wrapping_add(777), &[name.as_str()])]);
        assert!(listed.trusts_owner(uid));
        assert!(listed.may_write_key_files());
        assert!(listed.trusts_group_writer(gid.wrapping_add(777)));
        assert!(!listed.trusts_group_writer(gid));
        // ...or by its primary group.
        let primary = Trust::production_for_tests(&[(gid, &[])]);
        assert!(primary.trusts_owner(uid));
        assert!(primary.trusts_group_writer(gid));
        // Not a member of any deployer group.
        let other = Trust::production_for_tests(&[(gid.wrapping_add(777), &["someone-else"])]);
        assert!(!other.trusts_owner(uid));
        // A uid with no passwd entry is never a deployer.
        assert!(!primary.trusts_owner(0x7fff_fff0));
    }

    #[test]
    #[serial]
    fn a_deployer_group_that_does_not_exist_is_refused() {
        let _p = TestPolicy::write("security_model = \"production\"\ndeployer_groups = [\"hkdfguard-no-such-group-xyz\"]\n");
        match Trust::current() {
            Err(Error::GroupInvalid(msg)) => assert!(msg.contains("does not name a group"), "{msg}"),
            other => panic!("expected GroupInvalid, got {other:?}"),
        }
        // Developer ignores deployer groups altogether.
        let _d = TestPolicy::write("security_model = \"developer\"\n");
        assert!(Trust::current().is_ok());
    }

    #[test]
    #[serial]
    fn an_over_broad_deployer_group_is_refused() {
        let existing: Vec<&str> = OVER_BROAD_GROUPS.iter().copied().filter(|g| matches!(lookup_group(g), Ok(Some(_)))).collect();
        if existing.is_empty() {
            eprintln!("skipping: none of the over-broad groups exists on this host");
            return;
        }
        for broad in existing {
            let _p = TestPolicy::write(&format!("security_model = \"production\"\ndeployer_groups = [\"{broad}\"]\n"));
            match Trust::current() {
                Err(Error::GroupInvalid(msg)) => assert!(msg.contains("over-broad"), "{broad}: {msg}"),
                other => panic!("{broad}: expected GroupInvalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn this_user_and_its_primary_group_resolve() {
        let (_, name, _) = me();
        assert!(!name.is_empty());
        assert!(lookup_group("hkdfguard-no-such-group-xyz").unwrap().is_none());
        assert!(lookup_user(0x7fff_fff0).unwrap().is_none());
    }

    fn group(gid: libc::gid_t, members: &[&str]) -> DeployerGroup {
        DeployerGroup { gid, members: members.iter().map(|m| m.as_bytes().to_vec()).collect() }
    }

    #[test]
    fn a_listed_name_counts_only_for_the_uid_it_resolves_to() {
        let deployers = [group(5000, &["alice"])];
        // "alice" resolves to 1001: uid 1001 is a deployer...
        assert!(is_deployer_by(&deployers, 1001, b"alice", 100, |_| Some(1001)));
        // ...but uid 50001, whose passwd entry also says "alice", is not.
        assert!(!is_deployer_by(&deployers, 50001, b"alice", 100, |_| Some(1001)));
        // A name that resolves to nobody counts for nobody.
        assert!(!is_deployer_by(&deployers, 1001, b"alice", 100, |_| None));
    }

    #[test]
    fn a_primary_group_counts_by_gid_whatever_the_name() {
        let deployers = [group(5000, &[])];
        assert!(is_deployer_by(&deployers, 1001, b"anyone", 5000, |_| None));
        assert!(!is_deployer_by(&deployers, 1001, b"anyone", 100, |_| Some(1001)));
    }

    #[test]
    fn member_names_compare_as_raw_bytes() {
        // Two different non-UTF-8 names that a lossy decode would both turn
        // into the same replacement character.
        let deployers = [DeployerGroup { gid: 5000, members: vec![vec![0xff, b'x']] }];
        assert!(is_deployer_by(&deployers, 1001, &[0xff, b'x'], 100, |_| Some(1001)));
        assert!(!is_deployer_by(&deployers, 1001, &[0xfe, b'x'], 100, |_| Some(1001)));
    }
}

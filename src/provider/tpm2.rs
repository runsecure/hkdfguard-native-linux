//! Provider 1: TPM2 (preferred provider).
//!
//! ```text
//!  ______________________________________________________________________
//! | HARDWARE-DEPENDENT CODE                                                |
//! |                                                                        |
//! | Verified: built and linked against real `libtss2-esys` 4.0.1 on       |
//! | Ubuntu 24.04, with the `#[ignore]`d conformance suite passing against |
//! | swtpm (docker/run-tests.sh), a real firmware TPM -- Intel PTT         |
//! | (scripts/native-tpm-test.sh) -- a discrete STMicroelectronics chip,   |
//! | and Hyper-V's vTPM (scripts/hardware-tests/). Not yet exercised       |
//! | against other discrete chips (e.g. Infineon, Nuvoton). Re-run both    |
//! | after any change here.                                                |
//! |______________________________________________________________________|
//! ```
//!
//! ## Design
//!
//! Each service's KEK is an ordinary TPM key: a 256-bit HMAC-SHA-256
//! keyed-hash object created by `TPM2_Create` under the Owner hierarchy's
//! storage root key (SRK), and stored as a **key file**,
//! `<tpm.key_dir>/<service>.tpmkey` (default `/var/lib/hkdfguard/tpm`).
//! The key has a random 256-bit **authValue**, kept beside it in
//! `<service>.tpmauth`. Every PRF call re-derives the SRK with
//! `TPM2_CreatePrimary` from the standard TCG template, loads the key file
//! under it with `TPM2_Load`, runs one `TPM2_HMAC` per input in a session
//! keyed by the authValue, and flushes everything: nothing stays resident
//! in the TPM, and no persistent handle has to be allocated, authorized,
//! mapped to a service or kept from colliding.
//!
//! Only the one-shot `TPM2_HMAC` command is used, never the
//! `TPM2_HMAC_Start` / `TPM2_SequenceUpdate` sequence: between commands
//! the kernel's resource manager has to save and reload a sequence object,
//! and on at least one Intel PTT firmware that put the TPM into failure
//! mode until the next reboot. Every PRF input fits one command (see
//! [`crate::crypto::MAX_PRF_INPUT_LEN`]).
//!
//! What the TPM itself guarantees about a key file:
//!
//! - **Its key never leaves this TPM.** The file's private area is
//!   encrypted and integrity-protected under the SRK, whose seed is
//!   generated inside the TPM and never exported. The file is useless on
//!   any other TPM, and `TPM2_Load` refuses a file whose two halves don't
//!   belong together.
//! - **The TPM generated it.** Every key file is checked to carry
//!   `fixedTPM`, `fixedParent` and `sensitiveDataOrigin` (see
//!   [`verify_matches_template`]). The TPM refuses to import an object with
//!   `fixedTPM` set, so such a key can only have been created inside this
//!   TPM and never duplicated out: a key file can't hold a key
//!   anyone knows.
//!
//! What the authValue adds:
//!
//! - **Bus protection that needs no trusted public key.** Every session
//!   that uses the key derives its parameter encryption and its response
//!   HMAC from the authValue, so someone on a discrete TPM's bus can
//!   neither read a wrapping key nor replace one without it. It is a
//!   symmetric secret, so this holds against a quantum computer too. See
//!   the "Session parameter encryption" section below.
//! - **Access control per service.** Using the key takes the key file, the
//!   authValue file and the TPM. Root writes the key file
//!   `root:<key-users> 0440`, the key directory's group, and the authValue
//!   file `root:<group> 0440` for the group `tpm.auth_groups` names for the
//!   service, else `root:root 0400` (see [`auth_file_readers`]). So every
//!   service in `<key-users>` can read every key file, but only a
//!   service's own group its authValue: no other service can use its key.
//!
//! What it does not guarantee: anyone who can read both files *and* open
//! the TPM can use the key, as the PKCS#11 PIN is for that provider. And a
//! `TPM2_Clear` replaces the Owner hierarchy's seed: the SRK changes, and
//! every key file becomes permanently unloadable.
//!
//! Provisioning is real: `load_kek(service, true)` creates the authValue
//! file -- always a new value -- and then the key file if there is none,
//! holding the key directory's lock (see [`KeyDirLock`]) throughout, and
//! only under a storage root key whose Name policy pins, unless policy
//! allows otherwise (see [`check_provisioning_pin`]). A service with no key
//! file has no KEK here ([`Error::KeyNotProvisioned`]), so the provider
//! chain moves on. A key file without its authValue file is an error.
//! `retire_kek` deletes both.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::tpm_key_file::{self, KeyBlob}; // the key file's on-disk format
use crate::provider::{Backend, KekHandle, KekProvider, PrfOutput, ProviderType, KEK_LEN}; // traits/types this module implements
use crate::secure_file::{FileIdentity, Owner};
use sha2::{Digest as ShaDigest, Sha256}; // the payload's key_id tag and TPM Names (aliased to avoid clashing with tss-esapi's own `Digest`)
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd; // the key directory lock file's descriptor, for flock
use std::path::{Path, PathBuf}; // the key directory and key files
use std::str::FromStr; // brings `TctiNameConf::from_str` into scope
use std::sync::{Arc, Mutex, OnceLock}; // shared, lock-protected TPM context; `OnceLock` for the per-process conformance verdict

use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder}; // TPM object-attribute and session-attribute bitfields
use tss_esapi::constants::SessionType; // the HMAC session type
use tss_esapi::handles::{KeyHandle, ObjectHandle, SessionHandle}; // opaque TPM-side handles to a loaded key / a started session
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm}; // enum constants for "SHA-256", "ECC" and "keyed hash"
use tss_esapi::interface_types::ecc::EccCurve; // enum constant for "NIST P-256"
use tss_esapi::interface_types::resource_handles::Hierarchy; // selects the Owner hierarchy for CreatePrimary
use tss_esapi::interface_types::session_handles::AuthSession; // a started session, as passed to execute_with_session
use tss_esapi::structures::{
    Auth, Digest, EccParameter, EccPoint, EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme, MaxBuffer, Name, Private,
    Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData, SymmetricDefinition,
    SymmetricDefinitionObject,
}; // the TPM public-template types this module builds, the TPM Name value, the key file's private area, HMAC input and the session cipher
use tss_esapi::traits::{Marshall, UnMarshall}; // TPMT_PUBLIC to and from its wire bytes
use tss_esapi::{Context, TctiNameConf}; // the ESAPI connection handle and its configuration type

// ---------------------------------------------------------------------
// Key files.
// ---------------------------------------------------------------------

/// Where key files live when the policy names no `tpm.key_dir`.
const DEFAULT_KEY_DIR: &str = "/var/lib/hkdfguard/tpm";

/// A key file's name is the service name plus this. Service names never
/// start with '.', so the hidden temporary files [`write_key_dir_file`] makes
/// can never be mistaken for one.
const KEY_FILE_SUFFIX: &str = ".tpmkey";

/// A service's authValue file sits beside its key file, named with this.
const AUTH_FILE_SUFFIX: &str = ".tpmauth";

use tpm_key_file::AUTH_VALUE_LEN; // every service key's authValue length

/// `tpm.key_dir` from policy, else [`DEFAULT_KEY_DIR`]. `Err` on a policy
/// that exists but can't be trusted.
fn key_dir() -> Result<PathBuf> {
    Ok(crate::policy::tpm_key_dir()?.unwrap_or_else(|| PathBuf::from(DEFAULT_KEY_DIR)))
}

fn key_file_path(dir: &Path, service: &str) -> PathBuf {
    dir.join(format!("{service}{KEY_FILE_SUFFIX}"))
}

fn auth_file_path(dir: &Path, service: &str) -> PathBuf {
    dir.join(format!("{service}{AUTH_FILE_SUFFIX}"))
}

/// Who may own key files, and the directories above them: whoever may
/// create KEKs. Root under the production model; root or this process's
/// user under the developer model (and in test builds -- see
/// [`crate::secure_file::config_owner`]). A key file anyone else could have
/// written could hold a key they also hold a copy of.
fn key_owner() -> Result<Owner> {
    if crate::secure_file::config_owner() == Owner::RootOrCurrentUser {
        return Ok(Owner::RootOrCurrentUser);
    }
    Ok(match crate::security_model::current()? {
        crate::security_model::SecurityModel::Developer => Owner::RootOrCurrentUser,
        crate::security_model::SecurityModel::Production => Owner::Root,
    })
}

/// One service's key file, as read: its public area, its encrypted private
/// area, and which version of the file they came from.
struct KeyFile {
    public: Public,
    private: Private,
    identity: FileIdentity,
}

/// Reads and checks `service`'s key file. `Ok(None)` only when there is
/// none (the key directory missing included): the service isn't
/// provisioned on this TPM. A file that is there but fails any check is an
/// error, never "not provisioned", so a damaged or planted key file can't
/// quietly hand the service to a weaker provider.
///
/// The file must be owned by [`key_owner`], readable by nobody else except
/// the group of a root-owned file (`root:<key-users> 0440`), not a symlink,
/// and in a directory chain nobody else can write to. Its contents must be
/// a key file of exactly the shape this library writes, holding a key with
/// exactly this library's service-key attributes.
fn read_key_file(service: &str) -> Result<Option<KeyFile>> {
    use crate::secure_file::{check_location, open_checked};
    use std::io::Read;

    let path = key_file_path(&key_dir()?, service);
    let owner = key_owner()?;
    let requirements = key_dir_file_requirements()?;
    let fail = |what: String| Error::Provider(format!("TPM key file {} {what}", path.display()));
    let file = match check_location(&path, owner).and_then(|()| open_checked(&path, &requirements)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(fail(format!("is present but can't be trusted: {e}"))),
    };
    let meta = file.metadata().map_err(|e| fail(format!("could not be examined: {e}")))?;
    let identity =
        FileIdentity { dev: meta.dev(), ino: meta.ino(), len: meta.len(), mtime: (meta.mtime(), meta.mtime_nsec()) };

    let mut bytes = Vec::new();
    file.take(tpm_key_file::MAX_KEY_FILE_LEN as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| fail(format!("could not be read: {e}")))?;
    if bytes.len() > tpm_key_file::MAX_KEY_FILE_LEN {
        return Err(fail(format!("is over the {}-byte limit", tpm_key_file::MAX_KEY_FILE_LEN)));
    }
    let blob = tpm_key_file::decode(&bytes).map_err(fail)?;

    // Unmarshalled, then marshalled back and compared: a public area with
    // trailing bytes, or any encoding tss-esapi wouldn't itself produce,
    // is refused rather than normalized.
    let public = Public::unmarshall(&blob.public).map_err(|e| fail(format!("holds an unreadable public area: {e}")))?;
    if public.marshall().ok().as_deref() != Some(blob.public.as_slice()) {
        return Err(fail("holds a public area that is not in canonical form".to_string()));
    }
    if matches!(public, Public::Ecc { .. }) {
        return Err(fail(
            "holds an ECC key, from the ECDH format hkdfguard used before its first release; delete the file and \
             provision the service again"
                .to_string(),
        ));
    }
    verify_matches_template(&service_key_template()?, &public)
        .map_err(|e| fail(format!("is not a key this library creates: {e}")))?;
    let private = Private::try_from(blob.private).map_err(|e| fail(format!("holds an unreadable private area: {e}")))?;
    Ok(Some(KeyFile { public, private, identity }))
}

/// What every file in the key directory must satisfy: owned by
/// [`key_owner`], readable by nobody else except the group of a root-owned
/// file (`root:<group> 0440`), and not a symlink.
fn key_dir_file_requirements() -> Result<crate::secure_file::FileRequirements> {
    Ok(crate::secure_file::FileRequirements {
        owner: Some(key_owner()?),
        forbidden_mode_bits: crate::secure_file::FORBID_GROUP_OTHER_ACCESS,
        follow_symlinks: false,
        allow_group_read_if_root_owned: true, // root:<group> 0440, for a service that doesn't run as root
    })
}

/// Reads `service`'s authValue file: exactly [`AUTH_VALUE_LEN`] bytes, held
/// to the same rules as its key file -- and, where a group can read it, to
/// that group being the one policy names for the service (see
/// [`auth_file_group_problem`]). `Ok(None)` only when there is none.
///
/// Its last byte is never zero: the TPM drops trailing zero bytes from an
/// authValue before using it, and refusing them here keeps both ends
/// agreeing without relying on every layer in between doing the same.
fn read_auth_file(service: &str) -> Result<Option<Auth>> {
    use crate::secure_file::{check_location, open_checked, SecretBuffer};

    let path = auth_file_path(&key_dir()?, service);
    let owner = key_owner()?;
    let requirements = key_dir_file_requirements()?;
    let fail = |what: String| Error::Provider(format!("TPM authValue file {} {what}", path.display()));
    let mut file = match check_location(&path, owner).and_then(|()| open_checked(&path, &requirements)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // The OS refused the open: a trust refusal carries no OS error.
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => {
            return Err(fail(format!(
                "can't be read by this process ({e}). Only root, and the group policy names for this service in \
                 tpm.auth_groups, may read it: add the service's own group there (\"<service>\" = \"<group>\") and \
                 give the file that group (chgrp <group> {})",
                path.display()
            )))
        }
        Err(e) => return Err(fail(format!("is present but can't be trusted: {e}"))),
    };
    let meta = file.metadata().map_err(|e| fail(format!("could not be examined: {e}")))?;
    if meta.uid() == 0 && meta.mode() & 0o040 != 0 {
        // Looked up only for a file a group can read: `root:root 0400`
        // needs no policy, and no NSS lookup.
        let named = match crate::policy::tpm_auth_group(service)? {
            Some(name) => {
                let gid = crate::security_model::service_group_gid(&name)?;
                Some((name, gid))
            }
            None => None,
        };
        if let Some(problem) = auth_file_group_problem(meta.gid(), named.as_ref().map(|(name, gid)| (name.as_str(), *gid))) {
            return Err(fail(problem));
        }
    }
    let mut raw = SecretBuffer::read_from(&mut file, AUTH_VALUE_LEN).map_err(|e| fail(format!("could not be read: {e}")))?;
    let checked = tpm_key_file::check_auth_value(raw.as_slice())
        .map_err(fail)
        .and_then(|()| Auth::try_from(raw.as_slice().to_vec()).map_err(|e| fail(format!("was rejected: {e}")))); // `Auth` wipes itself on drop
    raw.wipe();
    checked.map(Some)
}

/// What is wrong with a root-owned authValue file that the group `gid` can
/// read, given the group policy names for its service in `tpm.auth_groups`
/// (name and gid), if any; `None` if nothing is.
///
/// The file's mode and owner say only that root set it up. Which group may
/// read it is the policy's to say: whoever reads a service's authValue (and
/// can open the TPM) can use its key, so a file left with another group --
/// the key directory's, which every TPM-using service is in, after a
/// `chgrp` or a restore that didn't keep groups -- would hand the key to
/// accounts the administrator never named, with every call still
/// succeeding. Refused instead, saying how to put it right.
fn auth_file_group_problem(gid: libc::gid_t, named: Option<(&str, libc::gid_t)>) -> Option<String> {
    match named {
        Some((_, want)) if want == gid => None,
        Some((name, want)) => Some(format!(
            "can be read by the group with gid {gid}, not the one policy names for this service in tpm.auth_groups \
             (\"{name}\", gid {want}). Give the file that group (chgrp {name}), or name the group that should read \
             it in tpm.auth_groups"
        )),
        None => Some(format!(
            "can be read by the group with gid {gid}, but policy names no group for this service in tpm.auth_groups, \
             so only root may read it. Name the service's own group there (\"<service>\" = \"<group>\"), or make \
             the file root's alone (chown root:root, chmod 0400)"
        )),
    }
}

/// A fresh authValue: [`AUTH_VALUE_LEN`] random bytes, the last non-zero
/// (see [`read_auth_file`]).
fn generate_auth_value() -> Result<zeroize::Zeroizing<[u8; AUTH_VALUE_LEN]>> {
    let mut value = zeroize::Zeroizing::new([0u8; AUTH_VALUE_LEN]);
    loop {
        getrandom::fill(&mut value[..]).map_err(|_| Error::Crypto("the OS random number generator failed"))?;
        if value[AUTH_VALUE_LEN - 1] != 0 {
            return Ok(value);
        }
    }
}

/// Writes `value`, the authValue of a key just created on the TPM, to
/// `service`'s authValue file. Called only under [`KeyDirLock`], for a
/// service with no key file, after [`refuse_orphaned_auth_file`]. It never
/// replaces a file: one that appeared since is refused the same way.
///
/// Who may read the file is [`auth_file_readers`].
///
/// Returns the authValue as read back, and the identity of the file
/// written, for [`remove_new_auth_file`].
fn provision_auth_file(service: &str, value: &[u8; AUTH_VALUE_LEN]) -> Result<(Auth, FileIdentity)> {
    let readers = auth_file_readers(service)?;
    let written = write_key_dir_file(service, AUTH_FILE_SUFFIX, "TPM authValue", value, readers, Publish::New)?;
    let auth = read_auth_file(service)?
        .ok_or_else(|| Error::Provider("the TPM authValue file vanished right after it was written".into()))?;
    Ok((auth, written))
}

/// Refuses to provision `service` while it has an authValue file and no key
/// file. That file may be all that is left of a retired key (a retire that
/// couldn't delete it, a key file deleted by hand) -- or half of a key
/// whose key file is only missing for now: a restore in progress, a
/// directory not fully mounted. The two can't be told apart from here, and
/// in the second case the authValue is the one thing that can't be made
/// again: without it the key file, once back, opens nothing. So it is never
/// overwritten and never deleted for a new key; an administrator says
/// which case it is by restoring the key file or deleting the authValue
/// file. Nor is it reused for the new key: a value that has sat in the
/// directory may have been read by whoever could read it then.
fn refuse_orphaned_auth_file(service: &str) -> Result<()> {
    let dir = key_dir()?;
    let auth = auth_file_path(&dir, service);
    // Whatever is at the name, readable or not: nothing is written over it.
    if std::fs::symlink_metadata(&auth).is_err() {
        return Ok(());
    }
    Err(orphaned_auth_file(&auth, &key_file_path(&dir, service)))
}

fn orphaned_auth_file(auth: &Path, key: &Path) -> Error {
    Error::Provider(format!(
        "refusing to provision a TPM key: this service has an authValue file ({}) but no key file ({}), and          provisioning never replaces an authValue file. If the key file is missing by mistake (a restore in          progress, a directory not mounted), put it back: the key then works as before. If the key is gone for          good, delete the authValue file by hand and provision again",
        auth.display(),
        key.display()
    ))
}

/// Deletes the authValue file this process just wrote for `service`
/// (`written`), after the key file that was to go with it couldn't be
/// written. Best effort: what is left behind only blocks provisioning, with
/// a message saying so.
///
/// Only the very file written is deleted. Anything else at the name now was
/// put there by someone working outside the lock -- a restore, most likely,
/// bringing back the authValue of the key file that got in the way -- and
/// is theirs to keep.
fn remove_new_auth_file(service: &str, written: FileIdentity) {
    let Ok(dir) = key_dir() else { return };
    let path = auth_file_path(&dir, service);
    if FileIdentity::of_entry(&path) != Some(written) {
        log::warn!(
            "hkdfguard: the TPM key file could not be written, and the authValue file at {} is no longer the one \
             made for it; left as it is",
            path.display()
        );
        return;
    }
    match std::fs::remove_file(&path) {
        Ok(()) => {
            let _ = sync_dir(&dir);
        }
        Err(e) => log::warn!(
            "hkdfguard: the TPM key file could not be written, and the authValue file made for it ({}) could not be              deleted: {e}. Delete it by hand before provisioning again",
            path.display()
        ),
    }
}

/// Who may read `service`'s authValue file when root writes it: the group
/// `tpm.auth_groups` names for the service, else root alone. Never the key
/// directory's group: every service using TPM keys is in it, and whoever
/// reads a service's authValue (and can open the TPM) can use its key.
/// Irrelevant when anyone else writes it: the file is then `0400`, its
/// writer's own.
fn auth_file_readers(service: &str) -> Result<Readers> {
    if !running_as_root() {
        return Ok(Readers::OwnerOnly);
    }
    match crate::policy::tpm_auth_group(service)? {
        Some(group) => Ok(Readers::Group(crate::security_model::service_group_gid(&group)?)),
        None => Ok(Readers::OwnerOnly),
    }
}

fn running_as_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// `service`'s authValue, for a key file that exists. A key file whose
/// authValue file is missing can't be used, and is an error rather than
/// "not provisioned". Nor can it be retired: retiring confirms the key's
/// fingerprint on the TPM, which takes the authValue.
fn required_auth_file(service: &str) -> Result<Auth> {
    read_auth_file(service)?.ok_or_else(|| {
        let (key, auth) = key_dir()
            .map(|dir| (key_file_path(&dir, service).display().to_string(), auth_file_path(&dir, service).display().to_string()))
            .unwrap_or_default();
        Error::Provider(format!(
            "this service's TPM key file has no authValue file ({auth}), so its key can't be used, or retired (which \
             confirms the key's fingerprint on the TPM). Restore the file from the backup taken with the key file. \
             If there is none, the key can never be used again: delete {key} by hand and provision the service \
             again; every DEK wrapped under the old key is lost"
        ))
    })
}

/// Writes `service`'s key file.
fn write_key_file(service: &str, blob: &KeyBlob) -> Result<()> {
    let pem = tpm_key_file::encode(blob).map_err(|e| Error::Provider(format!("could not encode the TPM key file: {e}")))?;
    write_key_dir_file(service, KEY_FILE_SUFFIX, "TPM key", pem.as_bytes(), Readers::DirGroup, Publish::NewKey).map(|_| ())
}

/// Who besides its owner may read a file root writes into the key
/// directory. A file anyone else writes is always `0400`: a group-readable
/// file its own (non-root) user owns is refused (see [`read_key_file`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Readers {
    /// The key directory's group (`root:<key-users> 0440`): for key files,
    /// useless without their authValue.
    DirGroup,
    /// One named group (`root:<group> 0440`).
    Group(libc::gid_t),
    /// Nobody (`root:root 0400`).
    OwnerOnly,
}

/// What [`write_key_dir_file`] does when the file already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Publish {
    /// A key file: fail, leaving it as it is, and discard what was to be
    /// written. A key file is never replaced; and the one there is not this
    /// call's key, so the authValue file just written for this call's
    /// doesn't go with it (see [`key_file_appeared`]).
    NewKey,
    /// An authValue file: fail, leaving it as it is. It is never replaced
    /// either, nor used for a new key (see [`refuse_orphaned_auth_file`]).
    New,
}

/// The key directory, resolved and checked: it must already exist, set up
/// by an administrator, and nobody but [`key_owner`] may be able to change
/// it or anything above it.
fn checked_key_dir() -> Result<PathBuf> {
    let configured = key_dir()?;
    let dir = match std::fs::canonicalize(&configured) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Provider(format!(
                "TPM key directory {dir} does not exist. Create it as root, with the group of the services \
                 that may use TPM keys: install -d -m 0750 -o root -g <key-users> {dir}",
                dir = configured.display()
            )));
        }
        Err(e) => return Err(Error::Provider(format!("TPM key directory {}: {e}", configured.display()))),
    };
    crate::secure_file::check_dir_chain(&dir, key_owner()?)
        .map_err(|e| Error::Provider(format!("TPM key directory {} can't be trusted: {e}", dir.display())))?;
    Ok(dir)
}

/// The lock file's name in the key directory. Hidden, like the temporary
/// files [`write_key_dir_file`] makes: a service name never starts with '.'.
const LOCK_FILE_NAME: &str = ".lock";

/// How long [`KeyDirLock::acquire`] waits for another provisioner or
/// retirer to finish before giving up. Each holds the lock for a handful of
/// TPM commands, so this is far longer than any honest wait.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// An exclusive `flock`, held while a service's files are created or
/// deleted, so provisioning and retiring are one step each as far as every
/// other process doing either is concerned: a provisioner that finds no key
/// file can be sure no one else is half-way through writing one, and so
/// that any authValue file there belongs to no key. Readers don't take it;
/// the files they read only ever appear whole. Released when dropped (the
/// descriptor closes).
///
/// The lock is on a file of its own in the key directory, `.lock`, which
/// only [`key_owner`] can open (mode `0600`) -- not on the directory.
/// `flock` needs no more than a descriptor opened for reading, and every
/// service that uses TPM keys can open the directory (`root:<key-users>
/// 0750`): any one of them could hold a lock on it for as long as it liked,
/// and root could then neither provision nor retire a key. Nor does the
/// wait go on for ever: after [`LOCK_WAIT`] it fails, saying so.
struct KeyDirLock {
    _file: std::fs::File,
}

impl KeyDirLock {
    fn acquire() -> Result<KeyDirLock> {
        Self::acquire_within(LOCK_WAIT)
    }

    fn acquire_within(wait: std::time::Duration) -> Result<KeyDirLock> {
        let dir = checked_key_dir()?;
        let path = dir.join(LOCK_FILE_NAME);
        let file = open_lock_file(&path)?;
        let deadline = std::time::Instant::now() + wait;
        loop {
            // SAFETY: `file` is an open descriptor for the life of this call.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(KeyDirLock { _file: file });
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::EWOULDBLOCK) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Some(libc::EWOULDBLOCK) => {
                    return Err(Error::Provider(format!(
                        "the TPM key directory's lock ({}) is still held after {} seconds, by another process                          provisioning or retiring a key; nothing was changed. Run this again once that process has                          finished",
                        path.display(),
                        wait.as_secs()
                    )));
                }
                _ => return Err(Error::Provider(format!("could not lock {}: {e}", path.display()))),
            }
        }
    }
}

/// Opens the key directory's lock file, creating it if this is the first
/// lock taken there. The directory is already known to be writable by
/// nobody but [`key_owner`] (see [`checked_key_dir`]), so whatever is at
/// the name was put there by them; it is checked all the same, on the
/// opened descriptor, and given mode `0600` with no ACL -- a default ACL on
/// the directory would otherwise let whoever it names open the file, and
/// so hold the lock.
fn open_lock_file(path: &Path) -> Result<std::fs::File> {
    use crate::secure_file::PrincipalTrust;

    let fail = |why: String| Error::Provider(format!("TPM key directory lock file {}: {why}", path.display()));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true) // `create` needs it; nothing is ever written
        .create(true)
        .mode(0o600)
        // O_NOFOLLOW: never through a symlink. O_NONBLOCK: a FIFO at the
        // name can't hang the open; the regular-file check then refuses it.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            fail(format!(
                "could not be opened ({e}). Only the account that may create TPM keys here can take the lock: root,                  under the production security model"
            ))
        })?;
    let meta = file.metadata().map_err(|e| fail(e.to_string()))?;
    if !meta.file_type().is_file() {
        return Err(fail("is not a regular file".into()));
    }
    if !key_owner()?.trusts_owner(meta.uid()) {
        return Err(fail(format!("is owned by uid {}, which may not create TPM keys here", meta.uid())));
    }
    crate::secure_file::strip_acl(&file).map_err(|e| fail(format!("could not remove its ACL: {e}")))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| fail(format!("could not set its mode to 0600: {e}")))?;
    Ok(file)
}

/// Writes `<service><suffix>` into the key directory. `what` names the file
/// in messages; `readers` says who besides its owner may read it, when root
/// writes it.
///
/// The file is written to a hidden temporary name and synced, then given
/// its real name by a hard link, which fails if the name exists: nothing in
/// the key directory is ever replaced, and what was to be written is
/// discarded (`publish` chooses the error). A crash never leaves a partial
/// file under the real name. Returns the identity of the file written.
fn write_key_dir_file(
    service: &str,
    suffix: &str,
    what: &str,
    contents: &[u8],
    readers: Readers,
    publish: Publish,
) -> Result<FileIdentity> {
    use std::io::Write;

    let dir = checked_key_dir()?;
    let dir_gid = std::fs::metadata(&dir)
        .map_err(|e| Error::Provider(format!("TPM key directory {}: {e}", dir.display())))?
        .gid();

    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|_| Error::Crypto("the OS random number generator failed"))?;
    let temp = dir.join(format!(".{service}{suffix}.{:016x}", u64::from_ne_bytes(nonce)));
    let target = dir.join(format!("{service}{suffix}"));
    let fail = |doing: &str, e: std::io::Error| Error::Provider(format!("could not {doing} {what} file {}: {e}", target.display()));

    let written = (|| -> std::io::Result<FileIdentity> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL: never through an existing file or symlink
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        // A default ACL on the key directory is copied onto every file made
        // in it: removed before a byte is written, so the file is readable
        // by exactly its owner and group below, never by someone that ACL
        // names. Its mode is then set explicitly, since the ACL also decides
        // the mode a new file is created with.
        crate::secure_file::strip_acl(&file)?;
        let mode = if running_as_root() {
            // Explicitly, whatever group a setgid directory or root's own
            // primary group would have given the file.
            let (gid, mode) = match readers {
                Readers::DirGroup => (dir_gid, 0o440),
                Readers::Group(gid) => (gid, 0o440),
                Readers::OwnerOnly => (0, 0o400),
            };
            std::os::unix::fs::fchown(&file, None, Some(gid))?;
            mode
        } else {
            0o400
        };
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(contents)?;
        file.sync_all()?;
        // Read once everything that changes it is done: linking the file
        // under its real name, below, changes none of what an identity holds.
        FileIdentity::of_file(&file).ok_or_else(|| std::io::Error::other("the file just written can't be examined"))
    })();
    let identity = match written {
        Ok(identity) => identity,
        Err(e) => {
            let _ = std::fs::remove_file(&temp);
            return Err(fail("write", e));
        }
    };
    let linked = std::fs::hard_link(&temp, &target);
    let _ = std::fs::remove_file(&temp);
    match linked {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(match publish {
                Publish::NewKey => key_file_appeared(&target),
                Publish::New => orphaned_auth_file(&target, &dir.join(format!("{service}{KEY_FILE_SUFFIX}"))),
            });
        }
        Err(e) => return Err(fail("create", e)),
    }
    sync_dir(&dir).map_err(|e| fail("persist", e))?;
    Ok(identity)
}

/// A key file turned up at `key` while its service was being provisioned:
/// after the look, under [`KeyDirLock`], that found none. Every provisioner
/// holds that lock, so this one was put there by something else -- a
/// restore from backup, a copy by hand. It is left alone, and so is this
/// call's key, which is discarded: the authValue file this call wrote
/// belongs to that discarded key, not to the file found, and the caller
/// takes it back.
fn key_file_appeared(key: &Path) -> Error {
    Error::Provider(format!(
        "a TPM key file appeared at {} while this service was being provisioned, put there by something other than \
         provisioning (a restore from backup?). It was left as it is, and the key made for this call was discarded. \
         If it is being restored, restore its authValue file with it, then run this again",
        key.display()
    ))
}

/// Flushes `dir`'s entries to disk, so a created or deleted key file
/// survives a crash.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Whether policy lets `service` use the key whose public area is `public`.
/// `Err` when policy pins a different Name for the service: that is the
/// wrong key, not a missing one. `Ok(false)` when `tpm.require_pinned_names`
/// is set and nothing is pinned for it.
fn pin_allows(service: &str, public: &Public) -> Result<bool> {
    let name = computed_name(public)?;
    match crate::policy::pinned_tpm_name(service)? {
        Some(pinned) if pinned != name => Err(Error::Provider(format!(
            "the TPM key file for this service holds a key with Name {}, not the Name pinned in policy ({})",
            hex(&name),
            hex(&pinned)
        ))),
        Some(_) => Ok(true),
        None => Ok(!crate::policy::require_tpm_pinned_names()),
    }
}

// ---------------------------------------------------------------------
// Which TPM.
// ---------------------------------------------------------------------

/// The TCTI used when the policy names none: the kernel's TPM resource
/// manager.
const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

/// The device node [`DEFAULT_TCTI`] opens. Its presence is what tells "no
/// TPM here" apart from "a TPM this process can't open".
const DEFAULT_DEVICE: &str = "/dev/tpmrm0";

/// Whether the policy names a TCTI, rather than leaving [`DEFAULT_TCTI`] --
/// i.e. whether someone pointed this process at a particular TPM on purpose.
fn tcti_is_explicit() -> bool {
    matches!(crate::policy::tpm_tcti(), Ok(Some(_)))
}

/// Which TPM to open: `tpm.tcti` from the root-owned policy, else
/// [`DEFAULT_TCTI`]. Never the environment: whoever chooses the TPM
/// chooses which TPM the key files are loaded into.
///
/// A policy TCTI that can't be parsed, or a policy file that can't be
/// trusted, is an error -- the TPM is then unavailable rather than opened
/// at a default the administrator may have meant to avoid.
fn resolve_tcti() -> Result<TctiNameConf> {
    if let Some(tcti) = crate::policy::tpm_tcti()? {
        return TctiNameConf::from_str(&tcti)
            .map_err(|e| Error::Provider(format!("tpm.tcti \"{tcti}\" in policy is not a usable TCTI: {e}")));
    }
    TctiNameConf::from_str(DEFAULT_TCTI).map_err(|e| Error::Provider(format!("default TCTI: {e}")))
}

// ---------------------------------------------------------------------
// The Owner hierarchy's authorization.
// ---------------------------------------------------------------------

/// Longest Owner-hierarchy authorization value accepted: the size of
/// `TPM2B_AUTH` (a digest of the largest hash the TPM supports).
const MAX_OWNER_AUTH_LEN: usize = 64;

/// Shortest Owner-hierarchy authorization value accepted from
/// `tpm.owner_auth_file`.
///
/// The password never crosses the bus, but what does is enough to test a
/// guess against: the Owner-authorized `TPM2_CreatePrimary` runs in an
/// unsalted, unbound HMAC session (the storage root key that would salt
/// one is the key being created), whose HMAC key is the password alone.
/// Whoever records one such command -- its bytes, both nonces and its HMAC
/// are all in the clear -- can try passwords against it offline, as fast as
/// they can hash and with no dictionary-attack counter in the way. So the
/// value has to be one that can't be guessed: random bytes, not a
/// passphrase. Length is the only part of that this code can check, and
/// 16 random bytes is already out of reach; the documented setup writes 32.
const MIN_OWNER_AUTH_LEN: usize = 16;

/// Reads the Owner-hierarchy authorization value from `path`
/// (`tpm.owner_auth_file`). Held to the same standard as the policy file's
/// other secrets -- root-owned, `0400` or `root:<service-group> 0440`, not
/// a symlink, in a root-controlled directory -- and used verbatim: no
/// trimming, so it matches exactly what `tpm2_changeauth -c o file:<path>`
/// set. Every failure, a missing file included, is an error: the policy
/// says the owner has this password, so trying with none would fail anyway
/// and hide why. A value shorter than [`MIN_OWNER_AUTH_LEN`] is refused
/// before it is ever used to authorize a command.
fn read_owner_auth(path: &std::path::Path) -> Result<tss_esapi::structures::Auth> {
    use crate::secure_file::{
        check_location, config_owner, open_checked, FileRequirements, SecretBuffer, FORBID_GROUP_OTHER_ACCESS,
    };
    let requirements = FileRequirements {
        owner: Some(config_owner()),
        forbidden_mode_bits: FORBID_GROUP_OTHER_ACCESS,
        follow_symlinks: false,
        allow_group_read_if_root_owned: true,
    };
    let mut file = check_location(path, config_owner())
        .and_then(|()| open_checked(path, &requirements))
        .map_err(|e| Error::Provider(format!("TPM owner authorization file {}: {e}", path.display())))?;
    let mut raw = SecretBuffer::read_from(&mut file, MAX_OWNER_AUTH_LEN)
        .map_err(|e| Error::Provider(format!("TPM owner authorization file {}: {e}", path.display())))?;
    if raw.as_slice().is_empty() {
        return Err(Error::Provider(format!("TPM owner authorization file {} is empty", path.display())));
    }
    if raw.as_slice().len() < MIN_OWNER_AUTH_LEN {
        let len = raw.as_slice().len();
        raw.wipe();
        return Err(Error::Provider(format!(
            "TPM owner authorization file {} holds {len} bytes; at least {MIN_OWNER_AUTH_LEN} are required. Each use of \
             the Owner password puts an HMAC keyed by it alone on the TPM's bus, which anyone recording the bus can \
             test guesses against offline, so it must be random bytes, not a passphrase. Write 32 random bytes to \
             the file and set them as the Owner password (tpm2_changeauth -c o -p <current> file:<path>)",
            path.display()
        )));
    }
    // `Auth` keeps its bytes in a `Zeroizing<Vec<u8>>`; `raw` wipes itself on drop.
    let auth = tss_esapi::structures::Auth::try_from(raw.as_slice().to_vec())
        .map_err(|e| Error::Provider(format!("TPM owner authorization value rejected: {e}")));
    raw.wipe();
    auth
}

/// The Owner-hierarchy authorization this process has confirmed, and the
/// one it has latched as rejected -- each keyed by the configured
/// `tpm.owner_auth_file` (`None` when policy names none) and that file's
/// identity.
///
/// Every Owner-authorized command with a wrong password counts toward the
/// TPM's dictionary-attack limit, and that limit is TPM-wide: a Hyper-V
/// vTPM allows 3 failures per 1000 s, after which every DA-protected object
/// on the TPM is refused, for every tenant. `hkdfguard_wrap_dek` is not
/// rate-limited, so a service retrying after an owner-password rotation
/// would otherwise put the whole TPM into lockout within seconds. So: the
/// first call confirms the authorization once, under this lock, so
/// concurrent first calls wait for its verdict rather than each spending an
/// attempt; a rejection latches, and no Owner-authorized command is sent
/// again until the file -- or the policy setting -- changes.
static OWNER_AUTH: Mutex<OwnerAuthState> = Mutex::new(OwnerAuthState { confirmed: None, rejected: None });

type OwnerAuthKey = (Option<PathBuf>, Option<crate::secure_file::FileIdentity>);

struct OwnerAuthState {
    confirmed: Option<OwnerAuthKey>,
    rejected: Option<(OwnerAuthKey, String)>,
}

fn owner_auth_key(file: Option<&std::path::Path>) -> OwnerAuthKey {
    (file.map(std::path::Path::to_path_buf), file.and_then(crate::secure_file::FileIdentity::of))
}

/// Whether the TPM rejected the authorization itself (`TPM_RC_AUTH_FAIL`,
/// which counts toward the DA limit, or `TPM_RC_BAD_AUTH`), as opposed to
/// failing for some other reason.
fn is_auth_rejection(e: &tss_esapi::Error) -> bool {
    use tss_esapi::constants::Tss2ResponseCodeKind;
    matches!(e, tss_esapi::Error::Tss2Error(rc) if matches!(rc.kind(), Some(Tss2ResponseCodeKind::AuthFail | Tss2ResponseCodeKind::BadAuth)))
}

fn rejection_reason(file: Option<&std::path::Path>) -> String {
    let configured = match file {
        Some(path) => format!("tpm.owner_auth_file {}", path.display()),
        None => "the empty Owner password (policy names no tpm.owner_auth_file)".to_string(),
    };
    format!(
        "the TPM rejected the Owner-hierarchy authorization from {configured}; no further Owner-authorized command \
         will be sent by this process until that changes, so the TPM's dictionary-attack counter is not spent"
    )
}

/// Confirms the Owner authorization set on `ctx` before any key is
/// created, once per configured file version -- see [`OWNER_AUTH`].
/// `probe` runs one Owner-authorized command and is called at most once
/// per verdict.
fn confirm_owner_auth(
    file: Option<&std::path::Path>,
    probe: impl FnOnce() -> std::result::Result<(), tss_esapi::Error>,
) -> std::result::Result<(), String> {
    let key = owner_auth_key(file);
    let mut state = OWNER_AUTH.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((rejected, reason)) = &state.rejected {
        if *rejected == key {
            return Err(reason.clone());
        }
        state.rejected = None; // changed since: one attempt may find out whether the correction worked
    }
    if state.confirmed.as_ref() == Some(&key) {
        return Ok(());
    }
    match probe() {
        Ok(()) => {
            state.confirmed = Some(key);
            Ok(())
        }
        Err(e) if is_auth_rejection(&e) => {
            let reason = rejection_reason(file);
            state.confirmed = None;
            state.rejected = Some((key, reason.clone()));
            Err(reason)
        }
        Err(e) => Err(format!("could not confirm the TPM Owner authorization: {e}")), // not a verdict: retried next call
    }
}

/// Records an Owner-authorization rejection seen after confirmation -- the
/// password rotated underneath a running process -- so later calls stop at
/// [`confirm_owner_auth`] instead of spending more attempts.
fn note_owner_auth_failure(e: &tss_esapi::Error) {
    if !is_auth_rejection(e) {
        return;
    }
    let file = crate::policy::tpm_owner_auth_file().ok().flatten();
    let mut state = OWNER_AUTH.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    state.confirmed = None;
    state.rejected = Some((owner_auth_key(file.as_deref()), rejection_reason(file.as_deref())));
}

// ---------------------------------------------------------------------
// The provider and its connection.
// ---------------------------------------------------------------------

// Holds the shared, lazily-usable connection to the TPM. `None` means no
// TPM was reachable at construction time: then either there is no TPM
// (the provider is simply unavailable), or `unreachable` says why the one
// there couldn't be opened.
pub struct Tpm2Provider {
    // A TPM ESYS context is not safe to drive concurrently; serialize
    // access to the (typically low-throughput, one DEK-wrap-at-a-time) TPM
    // channel behind a mutex. Shared (via Arc) with every handle so the
    // actual Load+HMAC round trip can happen lazily in `KekHandle::prf`,
    // once the payload's PRF inputs are known.
    context: Arc<Mutex<Option<Context>>>,
    // Set when a TPM is there but can't be trusted or used (see
    // `crate::provider::Backend::Refused`); every call then fails with it.
    refused: Option<String>,
    // Set when the default device exists but this process couldn't open
    // it: the TPM is there, but whether it is this service's provider
    // depends on the service (see `unreachable_for`).
    unreachable: Option<String>,
    // Set when the default device doesn't exist at all. The provider is
    // then not present (`probe()` is false) -- except for a service that
    // has a TPM key file, whose TPM has gone missing (see `unreachable_for`).
    no_device: Option<String>,
}

impl Tpm2Provider {
    pub fn new() -> Self {
        // try to connect once, at construction time
        let (context, refused, unreachable, no_device) = match open_context() {
            Backend::Ready(ctx) => (Some(ctx), None, None, None),
            Backend::Absent => {
                let device = Path::new(DEFAULT_DEVICE);
                let unreachable = unreachable_default_device(device);
                let no_device = unreachable.is_none().then(|| missing_default_device(device));
                (None, None, unreachable, no_device)
            }
            Backend::Refused(reason) => {
                crate::provider::log_once(log::Level::Error, format!("hkdfguard: TPM refused: {reason}"));
                (None, Some(reason), None, None)
            }
        };
        Tpm2Provider { context: Arc::new(Mutex::new(context)), refused, unreachable, no_device }
    }

    /// For a provider whose TPM couldn't be opened -- the device exists but
    /// this process can't open it, or there is no device at all: the
    /// error a call for `service` must fail with -- because the service has
    /// a TPM key file, so the TPM is its provider and the chain must not
    /// move past it -- or `None` when it has none and the TPM was never
    /// its provider. `None` too for a provider that connected.
    ///
    /// A device that has gone is held to this as much as one that can't be
    /// opened: a TPM driver that didn't load, a vTPM detached from the VM,
    /// or a container started without the device would otherwise turn a
    /// TPM-backed service into one wrapping under whatever comes next in
    /// the policy order, with no call failing.
    fn unreachable_for(&self, service: &str) -> Result<Option<Error>> {
        let (reason, remedy) = match (&self.unreachable, &self.no_device) {
            (Some(reason), _) => (reason, "restore this process's access to the TPM"),
            (None, Some(reason)) => (
                reason,
                "restore the TPM; or, if this service no longer keeps its KEK on one, remove that key file (and its \
                 .tpmauth file)",
            ),
            (None, None) => return Ok(None),
        };
        let path = key_file_path(&key_dir()?, service);
        let present = match std::fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            // ENOTDIR (a path component is a file) names nothing either.
            Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => false,
            // A process that may not even look in the key directory was
            // never given TPM keys, and can't be told apart from one that
            // has lost the access: neither can use the TPM here.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                log::debug!("hkdfguard: TPM key directory not readable by this process ({e}); treating the TPM as not this service's");
                false
            }
            Err(e) => return Err(Error::Provider(format!("could not check for TPM key file {}: {e}", path.display()))),
        };
        Ok(present.then(|| {
            Error::Provider(format!(
                "this service has a TPM key file ({}), but {reason}. Refusing rather than using a weaker provider: \
                 {remedy}",
                path.display()
            ))
        }))
    }

    fn connected(&self) -> bool {
        self.context.lock().map(|guard| guard.is_some()).unwrap_or(false) // a poisoned lock counts as not connected
    }

    fn check_not_refused(&self) -> Result<()> {
        match &self.refused {
            Some(reason) => Err(Error::Provider(format!("TPM refused: {reason}"))),
            None => Ok(()),
        }
    }
}

/// Why the default TPM device, if it exists, couldn't be opened: `None`
/// when there is no such device (no TPM on this host). Its open already
/// failed; this only words the reason, without the device error itself,
/// which tss-esapi reports as an unspecific TCTI failure.
fn unreachable_default_device(device: &Path) -> Option<String> {
    device.exists().then(|| {
        format!(
            "this process could not open the TPM at {} (is it in the device's group, usually tss? is the \
             tpm2-tss device TCTI installed?)",
            device.display()
        )
    })
}

/// What to say of a default TPM device that doesn't exist.
fn missing_default_device(device: &Path) -> String {
    format!(
        "there is no TPM device at {} (the kernel's TPM driver isn't loaded, the TPM or vTPM was removed or \
         disabled, or the device isn't passed into this container)",
        device.display()
    )
}

impl Default for Tpm2Provider {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs `f` against the provider's TPM connection, holding its lock.
fn with_context<T>(context: &Mutex<Option<Context>>, f: impl FnOnce(&mut Context) -> Result<T>) -> Result<T> {
    let mut guard = context.lock().map_err(|_| Error::Provider("TPM context lock poisoned".into()))?; // only one caller may talk to the TPM at a time
    let ctx = guard.as_mut().ok_or(Error::Provider("TPM context not available".into()))?; // connection failed at construction time
    f(ctx)
}

// Attempts to open a connection to the TPM named by `tpm.tcti` in policy,
// else the default Linux TPM resource-manager device node (see
// `resolve_tcti`). Refuses to hand back a connection to a TPM that fails
// `validate_tpm_compatibility` -- see that function's doc comment --
// returning `Backend::Refused` instead, so every call fails with the
// reason rather than creating key files no later call could load.
fn open_context() -> Backend<Context> {
    // Checked before the TCTI is even opened: tpm2-tss starts logging from
    // the first command.
    if let Some(level) = std::env::var_os("TSS2_LOG") {
        if tss2_log_exposes_secrets(&level.to_string_lossy()) {
            return Backend::Refused(
                "TSS2_LOG enables debug/trace logging in tpm2-tss, which writes raw TPM commands and \
                 responses (including HMAC outputs, i.e. wrapping keys), session keys and plaintext \
                 parameters to its log; unset TSS2_LOG or lower it to info or below"
                    .to_string(),
            );
        }
    }

    let tcti = match resolve_tcti() {
        Ok(tcti) => tcti,
        Err(e) => return Backend::Refused(e.to_string()),
    };
    // Which TPM this is, for the conformance verdict below: the TCTI as
    // policy names it (resolve_tcti has just accepted it), or the default.
    let tcti_key = crate::policy::tpm_tcti().ok().flatten().unwrap_or_else(|| DEFAULT_TCTI.to_string());
    let mut ctx = match Context::new(tcti) {
        Ok(ctx) => ctx,
        // The default device failing to open is the normal state of a host
        // with no TPM, or of a service that isn't meant to use it (not in
        // the `tss` group). Which it is gets decided per service, from the
        // key directory: see `Tpm2Provider::unreachable_for`. A TCTI
        // someone configured on purpose is different: its TPM is meant to
        // be used, so failing to reach it is an outage for every service.
        Err(e) if tcti_is_explicit() => return Backend::Refused(format!("could not open the configured TCTI: {e}")),
        Err(e) => {
            log::debug!("hkdfguard: no usable TPM at {DEFAULT_TCTI} ({e})");
            return Backend::Absent;
        }
    };

    // The Owner hierarchy's password, when policy says it has one. Set on
    // the context once, before the self-test: every CreatePrimary here
    // (self-test and SRK) is under the Owner hierarchy and authorizes
    // through `execute_with_nullauth_session`, an HMAC session that keys
    // its HMAC with whatever authValue the context holds for the handle --
    // so the password authorizes without ever crossing the bus. That HMAC
    // is keyed by the password alone, though, so a recorded command lets
    // guesses be tested offline: see `MIN_OWNER_AUTH_LEN`. It is not an
    // input to the SRK's derivation, so setting it changes no KEK.
    let owner_auth_file = match crate::policy::tpm_owner_auth_file() {
        Ok(file) => file,
        Err(e) => return Backend::Refused(e.to_string()),
    };
    if let Some(path) = &owner_auth_file {
        let auth = match read_owner_auth(path) {
            Ok(auth) => auth,
            Err(e) => return Backend::Refused(e.to_string()),
        };
        if let Err(e) = ctx.tr_set_auth(ObjectHandle::from(Hierarchy::Owner), auth) {
            return Backend::Refused(format!("could not set the TPM owner authorization: {e}"));
        }
    }
    // Before any key is created: a wrong Owner password spends one of the
    // TPM's dictionary-attack attempts per command (see `OWNER_AUTH`).
    let probe = |ctx: &mut Context| {
        let template = srk_template().map_err(|_| tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam))?;
        let handle = ctx
            .execute_with_nullauth_session(|ctx| ctx.create_primary(Hierarchy::Owner, template, None, None, None, None))?
            .key_handle;
        let _ = ctx.flush_context(handle.into());
        Ok(())
    };
    if let Err(reason) = confirm_owner_auth(owner_auth_file.as_deref(), || probe(&mut ctx)) {
        return Backend::Refused(reason);
    }

    // The conformance verdict is a fact about the TPM's *behavior*, not a
    // credential, so it's established once per process for each TPM rather
    // than on every connection -- providers are constructed (and this runs)
    // per call. Keyed by the TCTI that reached it: the policy is re-read on
    // every call, and one pointed at another TPM gets that TPM's own
    // verdict. Only a definitive verdict is cached; a self-test that
    // couldn't run at all (TPM busy, command error) refuses the TPM for
    // *this* call only and is retried next time.
    let compatible = match cached_verdict(&tcti_key) {
        Some(verdict) => verdict,
        None => match validate_tpm_compatibility(&mut ctx) {
            Ok(verdict) => record_verdict(tcti_key, verdict), // first definitive verdict wins; a concurrent one agrees
            Err(e) => return Backend::Refused(format!("conformance self-test could not run ({e})")),
        },
    };
    if !compatible {
        return Backend::Refused("failed its conformance self-test".to_string());
    }

    Backend::Ready(ctx)
}

/// Whether a `TSS2_LOG` value turns on tpm2-tss logging at `debug` or
/// `trace` for any module. At those levels its TCTI layer logs raw command
/// and response bytes -- `TPM2_HMAC`'s response is a payload's wrapping key
/// -- and its ESAPI layer logs session keys and parameters before
/// encryption. `TSS2_LOGFILE` can send all of that to any path.
///
/// Mirrors tpm2-tss's own parser (src/util/log.c, `getLogLevel`): every `+`
/// introduces a level, matched case-insensitively by prefix. The module
/// before the `+` is deliberately ignored: any module at these levels
/// leaks.
fn tss2_log_exposes_secrets(value: &str) -> bool {
    value.split('+').skip(1).any(|after_plus| {
        let lower = after_plus.to_ascii_lowercase();
        lower.starts_with("debug") || lower.starts_with("trace")
    })
}

/// Results of `validate_tpm_compatibility`, once per process for each TPM,
/// by the TCTI that reaches it: `true` if that TPM behaves as hkdfguard
/// requires, `false` if it definitively doesn't. A TPM is absent until a
/// self-test on it has actually completed. Bounded by the TCTIs a policy
/// has named during the process's life.
static TPM_CONFORMANCE_VERDICTS: Mutex<Vec<(String, bool)>> = Mutex::new(Vec::new());

fn cached_verdict(tcti: &str) -> Option<bool> {
    let verdicts = TPM_CONFORMANCE_VERDICTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    verdicts.iter().find(|(t, _)| t == tcti).map(|(_, v)| *v)
}

/// Records `verdict` for `tcti`, unless a concurrent self-test recorded one
/// first; returns the verdict in force.
fn record_verdict(tcti: String, verdict: bool) -> bool {
    let mut verdicts = TPM_CONFORMANCE_VERDICTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, existing)) = verdicts.iter().find(|(t, _)| *t == tcti) {
        return *existing;
    }
    verdicts.push((tcti, verdict));
    verdict
}

/// Empirically validates, against the real TPM this process just
/// connected to, the two behaviors the key files depend on. Called once,
/// at connection time (see `open_context`) -- refusing a TPM that can't
/// honor them up front beats creating key files that turn out to be
/// unloadable, or wrapping DEKs under a PRF that isn't the one specified.
///
/// 1. **The SRK must be reproducible.** `TPM2_CreatePrimary` from the same
///    template must return the same key every time, or a key file created
///    under one SRK could never be loaded under the next.
/// 2. **`TPM2_HMAC` must be HMAC-SHA-256.** A known-answer test: a
///    keyed-hash key with a known value, created for this test only, must
///    give the same HMAC as this crate's software implementation over an
///    input of the longest length a PRF call ever sends. That also proves
///    the TPM supports the command and accepts that input length.
///
/// Returns `Ok(true)` if the TPM is compatible, `Ok(false)` if it
/// definitively is not (a verdict `open_context` caches for the process),
/// and `Err` only if the self-test itself couldn't be carried out -- a
/// command failure, which says nothing about the TPM's behavior and so
/// must not be cached as a verdict.
fn validate_tpm_compatibility(ctx: &mut Context) -> Result<bool> {
    let mut publics = Vec::new();
    for _ in 0..2 {
        let (handle, public, _name) = create_srk_unpinned(ctx)?;
        let _ = ctx.flush_context(handle.into());
        publics.push(public.marshall().map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))?);
    }
    if publics[0] != publics[1] {
        log::warn!("hkdfguard: TPM behavior incompatible with hkdfguard requirements: the storage root key is not reproducible");
        return Ok(false);
    }

    let input = vec![0x5a; crate::crypto::MAX_PRF_INPUT_LEN];
    let on_tpm = hmac_known_answer(ctx, &input)?;
    if on_tpm != *crate::provider::software_prf(&KNOWN_ANSWER_KEY, &[&input])[0] {
        log::warn!("hkdfguard: TPM behavior incompatible with hkdfguard requirements: TPM2_HMAC does not compute HMAC-SHA-256");
        return Ok(false);
    }
    Ok(true)
}

/// The key of the conformance self-test's known-answer HMAC. Public by
/// design: it protects nothing, and is never a service's key.
const KNOWN_ANSWER_KEY: [u8; KEK_LEN] = *b"hkdfguard-tpm-hmac-known-answer!";

/// `TPM2_HMAC` of `input` under [`KNOWN_ANSWER_KEY`], created under the
/// SRK with its value supplied (so not `sensitiveDataOrigin`, which no
/// service key lacks -- see [`verify_matches_template`]) and flushed
/// afterwards.
fn hmac_known_answer(ctx: &mut Context, input: &[u8]) -> Result<[u8; 32]> {
    let template = hmac_key_template(false)?;
    let srk = create_srk(ctx)?;
    let value = SensitiveData::try_from(KNOWN_ANSWER_KEY.to_vec())
        .map_err(|e| Error::Provider(format!("failed to build the self-test key: {e}")))?;
    let created = ctx.execute_with_nullauth_session(|ctx| ctx.create(srk, template, None, Some(value), None, None));
    let loaded = created
        .map_err(|e| Error::Provider(format!("TPM2_Create (self-test HMAC key) failed: {e}")))
        .and_then(|created| {
            ctx.execute_with_nullauth_session(|ctx| ctx.load(srk, created.out_private, created.out_public))
                .map_err(|e| Error::Provider(format!("TPM2_Load (self-test HMAC key) failed: {e}")))
        });
    let _ = ctx.flush_context(srk.into());
    let key = loaded?;
    let mac = tpm_hmac(ctx, None, key, input);
    let _ = ctx.flush_context(key.into());
    Ok(*mac?)
}

// ---------------------------------------------------------------------
// Name verification.
// ---------------------------------------------------------------------

/// `TPM_ALG_SHA256`, as it appears in the two-byte algorithm prefix of a
/// TPM Name.
const TPM_ALG_SHA256: [u8; 2] = [0x00, 0x0B];

/// Recomputes an object's TPM Name from its public area:
/// `nameAlg || H_nameAlg(marshalled TPMT_PUBLIC)`.
fn computed_name(public: &Public) -> Result<Vec<u8>> {
    let (Public::Ecc { name_hashing_algorithm, .. } | Public::KeyedHash { name_hashing_algorithm, .. }) = public else {
        return Err(Error::Provider(
            "TPM object is neither an ECC nor a keyed-hash object".into(), // defensive: our own templates request only these
        ));
    };
    if *name_hashing_algorithm != HashingAlgorithm::Sha256 {
        return Err(Error::Provider(
            "TPM object uses an unexpected Name hash algorithm".into(), // our templates always request SHA-256
        ));
    }

    let marshalled = public
        .marshall()
        .map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))?;
    let digest = Sha256::digest(&marshalled);

    let mut out = Vec::with_capacity(TPM_ALG_SHA256.len() + digest.len());
    out.extend_from_slice(&TPM_ALG_SHA256);
    out.extend_from_slice(&digest);
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Two independent checks on the identity of a key the TPM just loaded,
/// in increasing order of strength:
///
/// 1. **Self-consistency.** The Name the TPM reported must equal the Name
///    recomputed from the public area in the key file. That proves the TPM
///    loaded exactly that public area -- and `TPM2_Load` itself refuses a
///    private area that doesn't belong to it.
///
///    This depends on `tss-esapi`'s marshalling reproducing, byte for
///    byte, the `TPMT_PUBLIC` the TPM itself hashed. That equivalence is
///    not assumed: `tpm_reported_name_matches_the_client_recomputed_name`
///    asserts it against a live TPM.
///
/// 2. **Administrative pinning.** If policy records an expected Name for
///    this service (`tpm.pinned_names`), the reported Name must match it.
///    This one *is* anti-substitution: the expected value comes from the
///    root-owned policy file rather than from the key file or the TPM
///    being questioned.
fn verify_name(service: &str, public: &Public, name: &Name) -> Result<()> {
    let expected = computed_name(public)?;
    if name.value() != expected.as_slice() {
        return Err(Error::Provider(format!(
            "TPM Name mismatch: the TPM reported Name {} for a key file whose public area's Name is {}",
            hex(name.value()),
            hex(&expected)
        )));
    }

    if let Some(pinned) = crate::policy::pinned_tpm_name(service)? {
        if name.value() != pinned.as_slice() {
            return Err(Error::Provider(format!(
                "TPM Name for this service does not match the Name pinned in policy (pinned {}, got {})",
                hex(&pinned),
                hex(name.value())
            )));
        }
    }

    Ok(())
}

/// Checks that a public area is the key that was asked for: the same type,
/// attributes, name algorithm, auth policy, and parameters (curve, scheme,
/// KDF, symmetric; or the HMAC scheme) as `template`. Only `unique` -- the
/// public point, or a keyed-hash object's seed digest -- may differ.
///
/// For a service key this is what proves a key file holds a key the TPM
/// generated and will never export (`fixedTPM`, `fixedParent`,
/// `sensitiveDataOrigin`; see the module doc), that it is usable only for
/// HMAC, and that it has no auth policy that could let it be used some
/// other way. For the SRK it proves the TPM returned the standard storage
/// key, not some other object.
fn verify_matches_template(template: &Public, returned: &Public) -> Result<()> {
    let mut differs = Vec::new();
    let mut compare = |same: bool, what: &'static str| {
        if !same {
            differs.push(what);
        }
    };
    match (template, returned) {
        (
            Public::Ecc { object_attributes: ta, name_hashing_algorithm: tn, auth_policy: tp, parameters: tparams, .. },
            Public::Ecc { object_attributes: ra, name_hashing_algorithm: rn, auth_policy: rp, parameters: rparams, .. },
        ) => {
            compare(ta == ra, "object attributes");
            compare(tn == rn, "name algorithm");
            compare(tp == rp, "auth policy");
            compare(tparams == rparams, "ECC parameters");
        }
        (
            Public::KeyedHash { object_attributes: ta, name_hashing_algorithm: tn, auth_policy: tp, parameters: tparams, .. },
            Public::KeyedHash { object_attributes: ra, name_hashing_algorithm: rn, auth_policy: rp, parameters: rparams, .. },
        ) => {
            compare(ta == ra, "object attributes");
            compare(tn == rn, "name algorithm");
            compare(tp == rp, "auth policy");
            compare(tparams == rparams, "keyed-hash parameters");
        }
        (Public::Ecc { .. }, _) => return Err(Error::Provider("the key is not an ECC key".into())),
        _ => return Err(Error::Provider("the key is not a keyed-hash (HMAC) key".into())),
    }
    if differs.is_empty() {
        Ok(())
    } else {
        Err(Error::Provider(format!("the key does not match the expected template ({} differ)", differs.join(", "))))
    }
}

// ---------------------------------------------------------------------
// Templates.
// ---------------------------------------------------------------------

/// The storage root key's template: the TCG's standard ECC P-256 storage
/// key (TCG TPM v2.0 Provisioning Guidance) -- a restricted decryption
/// key, AES-128-CFB, no scheme, and a `unique` of two 32-byte zero
/// coordinates. The same template always yields the same key while the
/// Owner hierarchy's seed is unchanged, which is what lets every key file
/// name its parent as `0x40000001` instead of a persistent handle.
///
/// Restricted, so the TPM uses its private half only to protect its
/// children and, as a session's `tpmKey`, to unwrap a session salt: it
/// refuses `TPM2_ECDH_ZGen` and `TPM2_ECC_Decrypt` with it. That matters
/// because anyone who can send the TPM commands can recreate it from this
/// public template. The SRK is the one ECC key hkdfguard uses: it protects
/// key files at rest inside the TPM and salts sessions, and never takes
/// part in wrapping a DEK.
fn srk_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM object attributes: {e}")))?;
    let ecc_params = PublicEccParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB) // a restricted decrypt key must name its symmetric algorithm
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_is_decryption_key(true)
        .with_is_signing_key(false)
        .with_restricted(true)
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM ECC parameters: {e}")))?;
    let zero = || EccParameter::try_from(vec![0u8; 32]).map_err(|e| Error::Provider(format!("failed to build TPM unique: {e}")));
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::new(zero()?, zero()?))
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM public template: {e}")))
}

/// A service key's template: an HMAC-SHA-256 keyed-hash object, usable
/// only for HMAC (`sign`, not `decrypt` or `restricted`), generated by the
/// TPM (`sensitiveDataOrigin`) and fixed to this TPM and this parent, so
/// never duplicable or exportable. No auth policy; its authValue is given
/// to `TPM2_Create` and is not part of the public area, so the template
/// and the key's Name don't depend on it. `noDA`, since a 256-bit random
/// authValue can't be guessed and a wrong one must never count toward the
/// TPM's dictionary-attack lockout. A keyed-hash key the TPM generates is
/// the size of its hash's digest: 256 bits.
fn service_key_template() -> Result<Public> {
    hmac_key_template(true)
}

/// The service key's template, or -- `generated` false -- the same key
/// with its value supplied by the caller, for the conformance self-test's
/// known-answer key alone.
fn hmac_key_template(generated: bool) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true) // key can never be moved to a different TPM
        .with_fixed_parent(true) // key can never be re-parented/duplicated
        .with_sensitive_data_origin(generated) // the key is generated by the TPM itself
        .with_user_with_auth(true) // USER role: the authValue (none for the self-test key) authorizes use
        .with_no_da(true)
        .with_sign_encrypt(true) // required: TPM2_HMAC needs a signing key
        .with_decrypt(false) // and nothing else: not usable to derive or unseal
        .with_restricted(false) // TPM2_HMAC refuses a restricted key
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM object attributes: {e}")))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::HMAC_SHA_256)) // fixed to HMAC with SHA-256
        .with_keyed_hash_unique_identifier(Digest::default()) // ignored by TPM2_Create: the TPM fills in the seed's digest
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM public template: {e}")))
}

// ---------------------------------------------------------------------
// The storage root key, and the keys under it.
// ---------------------------------------------------------------------

/// Re-derives the SRK and checks the TPM returned the standard storage key
/// with a self-consistent Name, without consulting any pin. Returns the
/// still-loaded handle; the caller flushes it. Every failure path flushes
/// before returning.
///
/// Everything is checked against `TPM2_CreatePrimary`'s own response, not
/// a later `TPM2_ReadPublic`: ESAPI keeps the public area that response
/// carried, and that cached copy is what `TPM2_StartAuthSession` encrypts
/// a session's salt to. A check made on a second response would let an
/// interposer answer `TPM2_CreatePrimary` with its own key and pass
/// `TPM2_ReadPublic` through untouched, so the pin would match while every
/// salt went to the interposer. The Name is ESAPI's too, which it has
/// already compared with that public area.
fn create_srk_unpinned(ctx: &mut Context) -> Result<(KeyHandle, Public, Name)> {
    let template = srk_template()?;
    let created = ctx
        .execute_with_nullauth_session(|ctx| ctx.create_primary(Hierarchy::Owner, template.clone(), None, None, None, None))
        .map_err(|e| {
            note_owner_auth_failure(&e);
            Error::Provider(format!("TPM2_CreatePrimary (storage root key) failed: {e}"))
        })?;
    let handle = created.key_handle;
    let public = created.out_public;
    let checked = ctx
        .tr_get_name(handle.into())
        .map_err(|e| Error::Provider(format!("could not read the storage root key's Name: {e}")))
        .and_then(|name| {
            verify_matches_template(&template, &public)?;
            let expected = computed_name(&public)?;
            if name.value() == expected.as_slice() {
                Ok(name)
            } else {
                Err(Error::Provider(format!(
                    "storage root key Name mismatch: TPM reported {} for a public area whose Name is {}",
                    hex(name.value()),
                    hex(&expected)
                )))
            }
        });
    match checked {
        Ok(name) => Ok((handle, public, name)),
        Err(e) => {
            let _ = ctx.flush_context(handle.into());
            Err(e)
        }
    }
}

/// [`create_srk_unpinned`], plus the policy pin
/// (`tpm.pinned_session_salt_key_name`) when one is set: an SRK whose Name
/// doesn't match is a different TPM or a reset Owner hierarchy -- or, on a
/// bus, an interposer's key -- and nothing is loaded under it.
fn create_srk(ctx: &mut Context) -> Result<KeyHandle> {
    let (handle, _public, name) = create_srk_unpinned(ctx)?;
    match crate::policy::pinned_session_salt_key_name() {
        Ok(Some(pinned)) if name.value() != pinned.as_slice() => {
            let _ = ctx.flush_context(handle.into());
            Err(Error::Provider(format!(
                "storage root key Name {} does not match the Name pinned in policy ({})",
                hex(name.value()),
                hex(&pinned)
            )))
        }
        Ok(_) => Ok(handle),
        Err(e) => {
            let _ = ctx.flush_context(handle.into());
            Err(e)
        }
    }
}

/// Logged once: a key was provisioned under an unpinned SRK.
static UNPINNED_SALT_KEY_WARNED: OnceLock<()> = OnceLock::new();

/// Whether policy pins the SRK's Name (`tpm.pinned_session_salt_key_name`).
/// `Err` on a policy that exists but can't be trusted.
fn srk_is_pinned() -> Result<bool> {
    Ok(crate::policy::pinned_session_salt_key_name()?.is_some())
}

/// Refuses to provision a service key while policy pins no SRK Name,
/// unless it says to go ahead (`tpm.allow_unpinned_provisioning`).
///
/// `TPM2_Create` is the one command whose session has no secret but its
/// salt, and the salt is encrypted to the SRK `TPM2_CreatePrimary` returned
/// (see [`create_service_key`]). Unpinned, that SRK is whatever answered:
/// someone rewriting a discrete TPM's bus traffic could answer with a key
/// of their own, read the new key's authValue, and from then on read and
/// replace every wrapping key `TPM2_HMAC` returns for the service. Nothing
/// read over the bus can show that a TPM has none, so this isn't left to a
/// warning. The refusal carries the SRK's Name, as reported now, in the
/// form to paste into policy.
///
/// Called before anything is written for the service, and again by
/// [`create_service_key`] itself, so no caller can skip it.
fn check_provisioning_pin(ctx: &mut Context) -> Result<()> {
    if srk_is_pinned()? || crate::policy::tpm_allow_unpinned_provisioning() {
        return Ok(());
    }
    let (handle, _public, name) = create_srk_unpinned(ctx)?;
    let _ = ctx.flush_context(handle.into());
    Err(Error::Provider(unpinned_srk_instructions(name.value())))
}

/// The message `provision` gets when policy pins no SRK Name: why it was
/// refused, and the Name this TPM reports, ready to pin. A Name is public.
fn unpinned_srk_instructions(name: &[u8]) -> String {
    let name = hex(name);
    format!(
        "refusing to provision a TPM key: policy pins no storage root key (tpm.pinned_session_salt_key_name). A new \
         key's authValue is sent to the TPM encrypted to that key, so on a TPM reached over a bus, someone able to \
         rewrite bus traffic during provisioning could put their own key in its place and learn the authValue. \
         Nothing was created. This TPM reports its storage root key's Name as {name}. Add this to the [tpm] table \
         of the policy file and provision again:\n  pinned_session_salt_key_name = \"{name}\"\nThe Name stays the \
         same until the TPM is cleared; if it was recorded when the host was set up, check it against that. For a \
         TPM with no bus to tamper with (a firmware or virtual TPM), allow_unpinned_provisioning = true in the same \
         table provisions without a pin instead"
    )
}

/// Creates a new service key under the SRK, with `auth` as its authValue.
/// Returns it as a key file's contents; nothing stays loaded.
///
/// `TPM2_Create` sends `auth` to the TPM, so it always runs in a salted,
/// encrypting session, whatever `tpm.session_encryption` says: this is the
/// one time the authValue crosses the bus, and it never does in cleartext.
/// The salt is the session's only secret here, so this command is as safe
/// as the SRK it is salted to: with no Name pinned for that
/// (`tpm.pinned_session_salt_key_name`), nothing is created unless policy
/// allows it -- see [`check_provisioning_pin`].
fn create_service_key(ctx: &mut Context, auth: &Auth) -> Result<KeyBlob> {
    check_provisioning_pin(ctx)?;
    if !srk_is_pinned()? {
        UNPINNED_SALT_KEY_WARNED.get_or_init(|| {
            log::warn!(
                "hkdfguard: provisioning a TPM key under an unpinned storage root key, as \
                 tpm.allow_unpinned_provisioning allows; on a discrete TPM, someone able to rewrite bus traffic now \
                 could learn the key's authValue. Set tpm.pinned_session_salt_key_name to rule that out"
            );
        });
    }
    let template = service_key_template()?;
    let srk = create_srk(ctx)?;
    let created = start_encrypted_session(ctx, srk).and_then(|session| {
        let created = ctx
            .execute_with_session(Some(session), |ctx| ctx.create(srk, template.clone(), Some(auth.clone()), None, None, None))
            .map_err(|e| Error::Provider(format!("TPM2_Create (service key) failed: {e}")));
        let _ = ctx.flush_context(SessionHandle::from(session).into());
        created
    });
    let _ = ctx.flush_context(srk.into());
    let created = created?;
    verify_matches_template(&template, &created.out_public)?;
    Ok(KeyBlob {
        public: created
            .out_public
            .marshall()
            .map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))?,
        private: created.out_private.value().to_vec(),
    })
}

/// Loads a key file's key under `srk`, verifies the Name the TPM reports
/// for it (see [`verify_name`]), and gives ESAPI its authValue, so every
/// session that uses the key is keyed by it. Returns the loaded handle;
/// the caller flushes it.
fn load_service_key(
    ctx: &mut Context,
    srk: KeyHandle,
    service: &str,
    public: &Public,
    private: &Private,
    auth: &Auth,
) -> Result<KeyHandle> {
    let handle = ctx
        .execute_with_nullauth_session(|ctx| ctx.load(srk, private.clone(), public.clone()))
        .map_err(|e| {
            Error::Provider(format!(
                "TPM2_Load of this service's key file failed ({e}): the file was not created by this TPM, its two \
                 halves don't belong together, or the TPM's Owner hierarchy has been cleared since"
            ))
        })?;
    let checked = ctx
        .tr_get_name(handle.into())
        .map_err(|e| Error::Provider(format!("could not read the loaded key's Name: {e}")))
        .and_then(|name| verify_name(service, public, &name))
        .and_then(|()| {
            ctx.tr_set_auth(handle.into(), auth.clone())
                .map_err(|e| Error::Provider(format!("could not set the TPM key's authValue: {e}")))
        });
    if let Err(e) = checked {
        let _ = ctx.flush_context(handle.into());
        return Err(e);
    }
    Ok(handle)
}

// ---------------------------------------------------------------------
// Session parameter encryption.
// ---------------------------------------------------------------------
//
// A discrete TPM sits on an LPC or SPI bus that an interposer can read and
// rewrite. `TPM2_HMAC`'s response is one payload's wrapping key (or the
// KEK fingerprint, which is public). Read, it opens that payload; replaced
// while a DEK is wrapped, it seals the payload under a key the interposer
// chose. A firmware or virtual TPM has no such bus, but nothing read over
// the bus can prove that, so every TPM is treated alike.
//
// What protects the response is the service key's authValue: 32 random
// bytes in the service's `.tpmauth` file, set on the key when it was
// created and never sent again. ESAPI and the TPM both key a session's
// parameter encryption with `sessionKey || authValue` and its response
// HMAC with the same value (TPM 2.0 Part 1 §19.6 and §21; tpm2-tss's
// `iesys_compute_session_value`), for the entity the session authorizes --
// here the service key. So an interposer who doesn't hold the authValue
// can neither read `outHMAC` nor forge it. That is a symmetric secret: a
// quantum computer gains nothing against it, and no public key has to be
// trusted for it to hold.
//
// The session is also salted, to the SRK, as a second layer: the salt
// enters `sessionKey`, so someone who has read the `.tpmauth` file but
// can't man-in-the-middle the SRK still sees nothing. The salt is the
// specification's one-pass ECDH, and the one classical step left. It
// stands alone only at `TPM2_Create`, which sends a new key's authValue
// and so can't be protected by it; `tpm.pinned_session_salt_key_name`
// closes that against an interposer active at provisioning -- and without
// it provisioning is refused, unless policy opts out (see
// `check_provisioning_pin`) -- and the ECDH
// is the residual against one who records provisioning and later breaks
// P-256.
//
// The session is never bound: binding to the service key would drop its
// authValue from the response HMAC key (tpm2-tss: "bound to the object").
//
// The SRK is *restricted*: the TPM uses its private half only for its
// children and inside `TPM2_StartAuthSession`, so nobody can run ECDH with
// it to recover a session's salt.

/// Whether `TPM2_HMAC` runs in an encrypting session, per
/// `tpm.session_encryption`.
fn session_encryption_enabled() -> bool {
    crate::policy::tpm_session_encryption() == crate::policy::SessionEncryption::On
}

/// Set once this process's TPM has refused AES-256 as a session cipher, so
/// later sessions ask for AES-128 straight away instead of paying for a
/// refusal each time. One TPM per process: policy names it.
static AES_256_SESSIONS_REFUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether the TPM refused `TPM2_StartAuthSession`'s symmetric parameter
/// itself -- the algorithm (`TPM_RC_SYMMETRIC`), its key size
/// (`TPM_RC_KEY_SIZE`) or its mode (`TPM_RC_MODE`) -- as opposed to failing
/// for some other reason, which a smaller key would not cure.
fn is_cipher_refusal(e: &tss_esapi::Error) -> bool {
    use tss_esapi::constants::Tss2ResponseCodeKind;
    matches!(
        e,
        tss_esapi::Error::Tss2Error(rc)
            if matches!(rc.kind(), Some(Tss2ResponseCodeKind::Symmetric | Tss2ResponseCodeKind::KeySize | Tss2ResponseCodeKind::Mode))
    )
}

/// Starts a salted HMAC session, salted to `srk`, with response and
/// command parameter encryption. The caller flushes it.
///
/// The cipher is AES-256-CFB where the TPM has it, and AES-128-CFB where
/// it doesn't: AES-128 is the only size the PC Client profile requires,
/// and some TPMs implement no other. The session key behind either is 256
/// bits of KDFa output, keyed by the service key's authValue and the salt
/// (see the section comment), so the larger cipher uses what is already
/// there. An interposer on the bus can answer the AES-256 request with a
/// refusal and so bring the session down to AES-128 -- which is where
/// every session was before this -- but no lower: there is no fallback to
/// an unencrypted session.
fn start_encrypted_session(ctx: &mut Context, srk: KeyHandle) -> Result<AuthSession> {
    use std::sync::atomic::Ordering;
    let mut start = |cipher: SymmetricDefinition| {
        ctx.start_auth_session(
            Some(srk), // salted: the session key depends on a secret only this TPM can unwrap
            None,      // never bound: see the section comment
            None,
            SessionType::Hmac,
            cipher,
            HashingAlgorithm::Sha256,
        )
    };
    let started = if AES_256_SESSIONS_REFUSED.load(Ordering::Relaxed) {
        start(SymmetricDefinition::AES_128_CFB)
    } else {
        match start(SymmetricDefinition::AES_256_CFB) {
            Err(e) if is_cipher_refusal(&e) => {
                AES_256_SESSIONS_REFUSED.store(true, Ordering::Relaxed);
                crate::provider::log_once(
                    log::Level::Warn,
                    format!("hkdfguard: the TPM refused AES-256 for session encryption ({e}); using AES-128, the size every TPM has"),
                );
                start(SymmetricDefinition::AES_128_CFB)
            }
            other => other,
        }
    };
    let session = started
        .map_err(|e| Error::Provider(format!("TPM2_StartAuthSession failed: {e}")))?
        .ok_or_else(|| Error::Provider("TPM2_StartAuthSession returned no session".into()))?;

    let (attributes, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true) // encrypt the command's first parameter (TPM2_HMAC's buffer; TPM2_Create's inSensitive, which holds the authValue)
        .with_encrypt(true) // encrypt the response's first parameter (outHMAC, i.e. the wrapping key)
        .with_continue_session(true)
        .build();
    if let Err(e) = ctx.tr_sess_set_attributes(session, attributes, mask) {
        let _ = ctx.flush_context(SessionHandle::from(session).into());
        return Err(Error::Provider(format!("failed to set TPM session attributes: {e}")));
    }
    // Read the attributes back and refuse a session that won't encrypt.
    // Encryption is invisible to the caller -- an unencrypted session
    // returns the very same HMAC -- so nothing downstream would notice a
    // stack that accepted the attributes and then dropped them, and the
    // wrapping key would cross the bus in the clear. A local ESAPI call: no TPM round
    // trip.
    let encrypts = ctx.tr_sess_get_attributes(session).map(|a| a.decrypt() && a.encrypt());
    match encrypts {
        Ok(true) => Ok(session),
        Ok(false) => {
            let _ = ctx.flush_context(SessionHandle::from(session).into());
            Err(Error::Provider(
                "the TPM session did not keep its decrypt/encrypt attributes; refusing to send HMAC outputs through it unencrypted"
                    .into(),
            ))
        }
        Err(e) => {
            let _ = ctx.flush_context(SessionHandle::from(session).into());
            Err(Error::Provider(format!("failed to read back TPM session attributes: {e}")))
        }
    }
}

/// Starts an unsalted HMAC session with no parameter encryption, for
/// `tpm.session_encryption = "off"`. Its responses are still authenticated
/// by the key's authValue. The caller flushes it.
fn start_plain_session(ctx: &mut Context) -> Result<AuthSession> {
    let session = ctx
        .start_auth_session(None, None, None, SessionType::Hmac, SymmetricDefinition::AES_128_CFB, HashingAlgorithm::Sha256)
        .map_err(|e| Error::Provider(format!("TPM2_StartAuthSession failed: {e}")))?
        .ok_or_else(|| Error::Provider("TPM2_StartAuthSession returned no session".into()))?;
    let (attributes, mask) = SessionAttributesBuilder::new().with_continue_session(true).build();
    if let Err(e) = ctx.tr_sess_set_attributes(session, attributes, mask) {
        let _ = ctx.flush_context(SessionHandle::from(session).into());
        return Err(Error::Provider(format!("failed to set TPM session attributes: {e}")));
    }
    Ok(session)
}

/// One `TPM2_HMAC` of `input` with `key`, authorized by `session`, or --
/// for the self-test's known-answer key, which has no authValue -- by a
/// throwaway null-auth session. One-shot, never a sequence (see the module
/// doc).
fn tpm_hmac(ctx: &mut Context, session: Option<AuthSession>, key: KeyHandle, input: &[u8]) -> Result<PrfOutput> {
    let buffer = MaxBuffer::try_from(input.to_vec())
        .map_err(|e| Error::Provider(format!("a {}-byte PRF input does not fit one TPM2_HMAC: {e}", input.len())))?;
    let mac = match session {
        Some(session) => ctx.execute_with_session(Some(session), |ctx| ctx.hmac(key.into(), buffer, HashingAlgorithm::Sha256)),
        None => ctx.execute_with_nullauth_session(|ctx| ctx.hmac(key.into(), buffer, HashingAlgorithm::Sha256)),
    }
    .map_err(|e| Error::Provider(format!("TPM2_HMAC failed: {e}")))?; // this `Digest` wipes itself on drop; the copies tss-esapi and libtss2 made on the way to it are theirs, and aren't wiped
    if mac.value().len() != 32 {
        return Err(Error::Provider(format!("TPM2_HMAC returned {} bytes, not an HMAC-SHA-256", mac.value().len())));
    }
    // Self-wiping from here on. Returning it moves it, though, and a move
    // may leave a copy in the stack frame it came from.
    let mut out = PrfOutput::new([0u8; 32]);
    out.copy_from_slice(mac.value());
    Ok(out)
}

/// The PRF on the TPM: re-derives the SRK, loads the key file's key under
/// it -- verifying its Name, and any policy-pinned Name, *before* it is
/// used, so a key that isn't the one policy expects never computes
/// anything -- runs one `TPM2_HMAC` per input in one session keyed by the
/// key's authValue, and flushes everything on every path, so no transient
/// object or session slot (TPMs have very few) can leak.
fn tpm_prf(
    ctx: &mut Context,
    service: &str,
    public: &Public,
    private: &Private,
    auth: &Auth,
    inputs: &[&[u8]],
) -> Result<Vec<PrfOutput>> {
    let srk = create_srk(ctx)?;
    let key = match load_service_key(ctx, srk, service, public, private, auth) {
        Ok(key) => key,
        Err(e) => {
            let _ = ctx.flush_context(srk.into());
            return Err(e);
        }
    };
    let session = if session_encryption_enabled() { start_encrypted_session(ctx, srk) } else { start_plain_session(ctx) };
    let outputs = session.and_then(|session| {
        let outputs = crate::provider::collect_outputs(inputs, |input| tpm_hmac(ctx, Some(session), key, input));
        let _ = ctx.flush_context(SessionHandle::from(session).into());
        outputs
    });
    let _ = ctx.flush_context(key.into());
    let _ = ctx.flush_context(srk.into());
    outputs
}

// ---------------------------------------------------------------------
// Handles.
// ---------------------------------------------------------------------

// Handle type returned from `load_kek`. Holds the key file and its
// authValue as they were read once in `load_kek`, so every PRF call within
// one wrap/unwrap uses the same key even if the files are replaced in
// between; the key is loaded into the TPM only inside `prf`, and flushed
// before it returns.
struct Tpm2Handle {
    key_id: Vec<u8>,                      // diagnostic-only tag embedded in the wrapped payload
    service: String,                      // the service name, for its policy pin
    public: Public,                       // the key file's public area
    private: Private,                     // the key file's private area, encrypted under the SRK
    auth: Auth,                           // the key's authValue (wiped on drop)
    context: Arc<Mutex<Option<Context>>>, // shared handle back to the TPM connection
}

impl KekHandle for Tpm2Handle {
    fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    fn prf(&self, inputs: &[&[u8]]) -> Result<Vec<PrfOutput>> {
        with_context(&self.context, |ctx| tpm_prf(ctx, &self.service, &self.public, &self.private, &self.auth, inputs))
    }
}

impl KekProvider for Tpm2Provider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Tpm2
    }

    fn probe(&self) -> bool {
        // A TPM this process can't open is still present: whether it is
        // this service's provider is answered per service, below.
        self.refused.is_some() || self.connected() || self.unreachable.is_some()
    }

    // No device at all: not present, unless this service has a key file.
    fn claims_while_absent(&self, service: &str) -> Result<()> {
        match self.unreachable_for(service)? {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    // A service has a KEK here when it has a usable key file and authValue
    // file -- and, under `tpm.require_pinned_names`, a pinned Name. Side-
    // effect free: nothing is sent to the TPM. A key file without its
    // authValue file is an error, not "no KEK"; so is a key file this
    // process can't use because it can't open the TPM.
    fn kek_exists(&self, service: &str) -> Result<bool> {
        self.check_not_refused()?;
        if let Some(e) = self.unreachable_for(service)? {
            return Err(e);
        }
        if !self.connected() {
            return Ok(false);
        }
        match read_key_file(service)? {
            Some(file) => {
                required_auth_file(service)?;
                pin_allows(service, &file.public)
            }
            None => Ok(false),
        }
    }

    fn load_kek(&self, service: &str, create_if_missing: bool) -> Result<Box<dyn KekHandle>> {
        self.check_not_refused()?;
        if let Some(e) = self.unreachable_for(service)? {
            return Err(e);
        }
        if self.unreachable.is_some() {
            // No key file: the TPM isn't this service's provider, and a key
            // can't be created on a TPM this process can't open.
            return Err(Error::KeyNotProvisioned("this process can't open the TPM, and the service has no TPM key file"));
        }
        if !self.connected() {
            return Err(Error::Provider("TPM context not available".into()));
        }
        let (file, auth) = match read_key_file(service)? {
            Some(file) => (file, required_auth_file(service)?),
            None if !create_if_missing => return Err(Error::KeyNotProvisioned("no TPM key file for this service")),
            None => {
                // One provisioner at a time (see `KeyDirLock`). Whoever held
                // the lock before may have provisioned the service: look
                // again under it.
                let _lock = KeyDirLock::acquire()?;
                match read_key_file(service)? {
                    Some(file) => (file, required_auth_file(service)?),
                    None => {
                        // Before anything is written: no key is created
                        // under an unpinned SRK unless policy allows it.
                        with_context(&self.context, check_provisioning_pin)?;
                        // Nor while an authValue file with no key file is
                        // there: it is never replaced.
                        refuse_orphaned_auth_file(service)?;
                        // The key is made on the TPM before either file is
                        // written, so a TPM that refuses leaves the
                        // directory as it was.
                        let value = generate_auth_value()?;
                        let fresh = Auth::try_from(value.to_vec())
                            .map_err(|e| Error::Provider(format!("the TPM authValue was rejected: {e}")))?;
                        let blob = with_context(&self.context, |ctx| create_service_key(ctx, &fresh))?;
                        // The authValue file first, so the key file never
                        // exists without one.
                        let (auth, auth_written) = provision_auth_file(service, &value)?;
                        if let Err(e) = write_key_file(service, &blob) {
                            // No key file was written, so the authValue file
                            // just created belongs to no key -- not even to
                            // one that turned up at the key file's name
                            // meanwhile: taken back, or it would block the
                            // next attempt, or sit beside a key it can't
                            // authorize.
                            remove_new_auth_file(service, auth_written);
                            return Err(e);
                        }
                        if !srk_is_pinned()? {
                            // Only reachable under the opt-out; the `log`
                            // warning goes nowhere in a host with no logger.
                            crate::audit::tpm_key_provisioned_unpinned(service);
                        }
                        // Re-read rather than trusting `blob`: the file on
                        // disk is the key every later call uses.
                        let file = read_key_file(service)?
                            .ok_or_else(|| Error::Provider("the TPM key file vanished right after it was written".into()))?;
                        (file, auth)
                    }
                }
            }
        };
        if !pin_allows(service, &file.public)? {
            if create_if_missing {
                // Pinning is a root-owned policy edit, which this process
                // can't (and mustn't) make itself. Do the part it can:
                // report the exact Name to pin.
                return Err(Error::Provider(unpinned_service_instructions(service, &file.public)));
            }
            return Err(Error::KeyNotProvisioned(
                "tpm.require_pinned_names is set and policy pins no TPM Name for this service",
            ));
        }
        if create_if_missing {
            // Provisioning reports the KEK as ready, so prove the key file
            // loads on *this* TPM and its authValue authorizes it first.
            with_context(&self.context, |ctx| tpm_prf(ctx, service, &file.public, &file.private, &auth, &[b"provisioned"]))?;
        }
        Ok(Box::new(Tpm2Handle {
            key_id: service_fingerprint(service),
            service: service.to_string(),
            public: file.public,
            private: file.private,
            auth,
            context: Arc::clone(&self.context), // clone the Arc (cheap: just bumps a refcount), not the underlying context
        }))
    }

    // Deletes the key file, once its key is confirmed (on the TPM) to have
    // `expected_fingerprint` and the file is confirmed to be the one read,
    // then its authValue file. The TPM keeps no copy, so every DEK wrapped
    // under it is then unrecoverable -- unless copies of both files survive
    // (a backup), which still load on this TPM.
    fn retire_kek(&self, service: &str, expected_fingerprint: &[u8; crate::payload::FINGERPRINT_LEN]) -> Result<()> {
        self.check_not_refused()?;
        if let Some(e) = self.unreachable_for(service)? {
            return Err(e);
        }
        if !self.connected() {
            return Err(Error::Provider("TPM context not available".into()));
        }
        let Some(file) = read_key_file(service)? else {
            return Err(Error::KekNotFound);
        };
        // No provisioning of this service can interleave with the deletes.
        // A key file replaced between the read above and here is caught by
        // the identity check before the delete.
        let _lock = KeyDirLock::acquire()?;
        let handle = Tpm2Handle {
            key_id: Vec::new(),
            service: service.to_string(),
            public: file.public,
            private: file.private,
            auth: required_auth_file(service)?,
            context: Arc::clone(&self.context),
        };
        if crate::crypto::kek_fingerprint(&handle)? != *expected_fingerprint {
            return Err(Error::KekFingerprintMismatch);
        }
        let dir = key_dir()?;
        let path = key_file_path(&dir, service);
        // Not following a symlink, as the read didn't: a link put at the
        // name pointing back at the same file is a change, and the unlink
        // below would remove the link, not the key file.
        if FileIdentity::of_entry(&path) != Some(file.identity) {
            return Err(Error::Provider("the TPM key file changed while it was being retired; nothing was deleted".into()));
        }
        std::fs::remove_file(&path)
            .map_err(|e| Error::Provider(format!("could not delete TPM key file {}: {e}", path.display())))?;
        // The key file is gone, so the key is retired: an authValue file
        // left behind by a failure here authorizes nothing. Provisioning
        // the service again is refused until it is deleted (see
        // `refuse_orphaned_auth_file`), so say so.
        let auth_path = auth_file_path(&dir, service);
        if let Err(e) = std::fs::remove_file(&auth_path) {
            log::warn!(
                "hkdfguard: retired the TPM key, but could not delete its authValue file {}: {e}. Delete it by hand:                  this service can't be provisioned again while it is there",
                auth_path.display()
            );
        }
        sync_dir(&dir).map_err(|e| Error::Provider(format!("could not persist deleting TPM key file {}: {e}", path.display())))
    }
}

/// The message `provision` gets for an unpinned service under
/// `tpm.require_pinned_names`: the Name of the key in its key file, in the
/// form to paste into policy.
fn unpinned_service_instructions(service: &str, public: &Public) -> String {
    // Paste-ready: the entry names the (normalized) service itself. Service
    // names are public identifiers, so the message carries it as-is.
    match computed_name(public) {
        Ok(name) => format!(
            "tpm.require_pinned_names is set and service \"{service}\" has no pinned TPM Name. Its key file is \
             created; to provision it, add this to the policy file and run provision again:\n  [tpm.pinned_names]\n  \
             \"{service}\" = \"{}\"",
            hex(&name)
        ),
        Err(e) => format!(
            "tpm.require_pinned_names is set and this service has no pinned TPM Name; computing its key's Name to \
             report it failed: {e}"
        ),
    }
}

// Non-secret diagnostic tag for the wrapped payload: just a hash of the
// service name, carrying no key material.
fn service_fingerprint(service: &str) -> Vec<u8> {
    Sha256::digest(service.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*; // bring `Tpm2Provider` etc. into scope
    use crate::policy::test_support::TestPolicy;
    use serial_test::serial; // the tests below set process-wide env vars

    // ---------------------------------------------------------------
    // Owner-authorization latch (no TPM needed: the probe is a closure).
    // ---------------------------------------------------------------

    fn reset_owner_auth() {
        *OWNER_AUTH.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            OwnerAuthState { confirmed: None, rejected: None };
    }

    // TPM_RC_AUTH_FAIL (format one, session 1), and TPM_RC_LOCKOUT (a warning).
    fn auth_fail() -> tss_esapi::Error {
        tss_esapi::Error::Tss2Error(tss_esapi::constants::Tss2ResponseCode::from(0x98E))
    }
    fn lockout() -> tss_esapi::Error {
        tss_esapi::Error::Tss2Error(tss_esapi::constants::Tss2ResponseCode::from(0x921))
    }

    #[test]
    fn only_a_refusal_of_the_cipher_itself_brings_a_session_down_to_aes_128() {
        let rc = |code: u32| tss_esapi::Error::Tss2Error(tss_esapi::constants::Tss2ResponseCode::from(code));
        // Format one, parameter 4 (StartAuthSession's `symmetric`):
        // TPM_RC_SYMMETRIC, TPM_RC_KEY_SIZE, TPM_RC_MODE.
        for refusal in [0x4D6, 0x4C7, 0x4C9] {
            assert!(is_cipher_refusal(&rc(refusal)), "{refusal:#x}");
        }
        // Anything else is the session failing, at any key size: a bad
        // salt key handle (TPM_RC_VALUE, handle 1), no session slots
        // (TPM_RC_SESSION_MEMORY), a wrong password, a locked-out TPM.
        for other in [0x184, 0x903] {
            assert!(!is_cipher_refusal(&rc(other)), "{other:#x}");
        }
        assert!(!is_cipher_refusal(&auth_fail()));
        assert!(!is_cipher_refusal(&lockout()));
        assert!(!is_cipher_refusal(&tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)));
    }

    #[test]
    #[serial]
    fn a_rejected_owner_password_is_never_tried_again_until_the_file_changes() {
        reset_owner_auth();
        let dir = crate::secure_file::private_tempdir();
        let file = dir.path().join("owner.auth");
        std::fs::write(&file, b"wrong").unwrap();
        assert!(is_auth_rejection(&auth_fail()) && !is_auth_rejection(&lockout()));

        let err = confirm_owner_auth(Some(&file), || Err(auth_fail())).unwrap_err();
        assert!(err.contains("rejected the Owner-hierarchy authorization"), "{err}");
        for _ in 0..5 {
            let again = confirm_owner_auth(Some(&file), || panic!("a latched password must not reach the TPM"));
            assert_eq!(again.unwrap_err(), err);
        }

        // An operator corrects the file: exactly one attempt finds out.
        std::fs::write(&file, b"corrected password").unwrap();
        let mut probes = 0;
        confirm_owner_auth(Some(&file), || {
            probes += 1;
            Ok(())
        })
        .unwrap();
        confirm_owner_auth(Some(&file), || panic!("a confirmed password is not probed again")).unwrap();
        assert_eq!(probes, 1);
        reset_owner_auth();
    }

    #[test]
    #[serial]
    fn a_failure_that_is_not_an_auth_rejection_is_not_latched() {
        reset_owner_auth();
        // In lockout the TPM refuses without counting: nothing to protect,
        // and no verdict about the password, so the next call tries again.
        assert!(confirm_owner_auth(None, || Err(lockout())).unwrap_err().contains("could not confirm"));
        let mut probed = false;
        confirm_owner_auth(None, || {
            probed = true;
            Ok(())
        })
        .unwrap();
        assert!(probed);
        reset_owner_auth();
    }

    #[test]
    #[serial]
    fn a_rotation_after_confirmation_latches_at_the_failing_command() {
        reset_owner_auth();
        let _no_policy = TestPolicy::minimal(); // so `note_owner_auth_failure` reads "no owner_auth_file"
        confirm_owner_auth(None, || Ok(())).unwrap();
        note_owner_auth_failure(&lockout()); // not an auth rejection: ignored
        confirm_owner_auth(None, || panic!("still confirmed")).unwrap();
        note_owner_auth_failure(&auth_fail()); // the password changed underneath the process
        let err = confirm_owner_auth(None, || panic!("latched: must not reach the TPM")).unwrap_err();
        assert!(err.contains("empty Owner password"), "{err}");
        reset_owner_auth();
    }

    #[test]
    #[serial]
    fn concurrent_first_calls_spend_one_attempt_between_them() {
        reset_owner_auth();
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let attempts = attempts.clone();
                std::thread::spawn(move || {
                    confirm_owner_auth(None, || {
                        attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        Err(auth_fail())
                    })
                })
            })
            .collect();
        for t in threads {
            assert!(t.join().unwrap().is_err());
        }
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1, "a burst of first calls must spend one attempt, not one each");
        reset_owner_auth();
    }

    #[test]
    #[serial]
    fn an_owner_password_short_enough_to_guess_offline_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::secure_file::private_tempdir();
        let owner_auth = dir.path().join("owner.auth");
        let write = |bytes: &[u8]| {
            std::fs::write(&owner_auth, bytes).unwrap();
            std::fs::set_permissions(&owner_auth, std::fs::Permissions::from_mode(0o600)).unwrap();
        };

        write(b"correct horse"); // 13 bytes: a passphrase, not a random value
        match read_owner_auth(&owner_auth) {
            Err(Error::Provider(msg)) => {
                assert!(msg.contains("at least 16"), "says what is required: {msg}");
                assert!(!msg.contains("correct horse"), "and never the value: {msg}");
            }
            Err(other) => panic!("expected a Provider error, got {other:?}"),
            Ok(_) => panic!("a 13-byte owner password must be refused"),
        }

        write(&[0x5a; MIN_OWNER_AUTH_LEN]);
        assert!(read_owner_auth(&owner_auth).is_ok(), "the shortest accepted length");
        write(&[0x5a; MAX_OWNER_AUTH_LEN]);
        assert!(read_owner_auth(&owner_auth).is_ok(), "the longest");
    }

    #[test]
    #[serial]
    fn an_owner_password_under_a_sticky_ancestor_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let chmod = |p: &std::path::Path, mode: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();

        // A private 0700 directory inside a /tmp-style (1777) one: the
        // layout of `mktemp -d` under /tmp.
        let base = crate::secure_file::private_tempdir();
        let private = base.path().join("private");
        std::fs::create_dir(&private).unwrap();
        chmod(&private, 0o700);
        let owner_auth = private.join("owner.auth");
        std::fs::write(&owner_auth, [0x5a; 32]).unwrap();
        chmod(&owner_auth, 0o600);
        assert!(read_owner_auth(&owner_auth).is_ok(), "a private chain is fine");

        chmod(base.path(), 0o1777);
        match read_owner_auth(&owner_auth) {
            Err(Error::Provider(msg)) => assert!(msg.contains("sticky"), "says why: {msg}"),
            Err(other) => panic!("expected Provider(..sticky..), got {other:?}"),
            Ok(_) => panic!("an owner password under a sticky ancestor must be refused"),
        }
        chmod(base.path(), 0o700);
    }

    // ---------------------------------------------------------------
    // Templates, Names, key files and pins.
    //
    // Unlike the conformance suite further down, these need no TPM --
    // they exercise the templates, file handling, policy interaction,
    // and the client-side Name computation -- so they run under a plain
    // `cargo test --features tpm2`.
    // ---------------------------------------------------------------

    #[test]
    fn a_service_key_is_tpm_generated_fixed_and_hmac_only_and_the_srk_is_the_tcg_storage_key() {
        let Public::KeyedHash { object_attributes: key, auth_policy, parameters, .. } = service_key_template().unwrap() else {
            panic!("expected a keyed-hash template");
        };
        assert!(key.fixed_tpm() && key.fixed_parent() && key.sensitive_data_origin(), "never exported, generated in the TPM");
        assert!(key.sign_encrypt() && !key.decrypt() && !key.restricted(), "usable for TPM2_HMAC, and only that");
        assert!(key.user_with_auth() && key.no_da());
        assert!(auth_policy.value().is_empty(), "no policy that could authorize the key some other way");
        assert_eq!(parameters, PublicKeyedHashParameters::new(KeyedHashScheme::HMAC_SHA_256));

        // The self-test's key differs only in having a supplied value.
        let Public::KeyedHash { object_attributes: known, .. } = hmac_key_template(false).unwrap() else {
            panic!("expected a keyed-hash template");
        };
        assert!(!known.sensitive_data_origin());
        assert!(verify_matches_template(&service_key_template().unwrap(), &hmac_key_template(false).unwrap()).is_err());

        let Public::Ecc { object_attributes: srk, unique, .. } = srk_template().unwrap() else {
            panic!("expected an ECC template");
        };
        assert!(srk.restricted() && srk.decrypt() && !srk.sign_encrypt(), "a storage key the TPM won't run ECDH with");
        assert!(srk.fixed_tpm() && srk.fixed_parent() && srk.sensitive_data_origin() && srk.user_with_auth() && srk.no_da());
        assert_eq!(unique.x().value(), [0u8; 32], "the TCG template's unique is two 32-byte zero coordinates");
        assert_eq!(unique.y().value(), [0u8; 32]);
    }

    #[test]
    fn computed_name_has_the_sha256_prefix_and_tracks_the_public_area() {
        let a = fake_service_public();
        let b = fake_service_public();

        let name = computed_name(&a).unwrap();
        assert_eq!(name.len(), 2 + 32, "a SHA-256 TPM Name is the 2-byte alg id plus a 32-byte digest");
        assert_eq!(&name[..2], &TPM_ALG_SHA256);
        // The digest really is over the marshalled public area.
        assert_eq!(&name[2..], Sha256::digest(a.marshall().unwrap()).as_slice());
        // A different key is a different public area, so a different Name.
        assert_ne!(name, computed_name(&b).unwrap());
    }

    #[test]
    fn hex_encodes_lowercase_and_zero_pads() {
        assert_eq!(hex(&[0x00, 0x0b, 0xff, 0x10]), "000bff10");
        assert_eq!(hex(&[]), "");
    }

    // A public area shaped exactly like a service key the TPM made: the
    // service-key template with a random `unique` (the seed's digest).
    fn fake_service_public() -> Public {
        let mut unique = [0u8; 32];
        getrandom::fill(&mut unique).unwrap();
        let Public::KeyedHash { object_attributes, name_hashing_algorithm, auth_policy, parameters, .. } =
            service_key_template().unwrap()
        else {
            panic!("expected a keyed-hash template");
        };
        Public::KeyedHash {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            unique: Digest::try_from(unique.to_vec()).unwrap(),
        }
    }

    fn fake_blob(public: &Public) -> KeyBlob {
        KeyBlob { public: public.marshall().unwrap(), private: vec![0x5a; 126] }
    }

    // `doc`, layered over the policy in force, for the duration of `f`.
    fn with_policy<T>(doc: &str, f: impl FnOnce() -> T) -> T {
        let _policy = TestPolicy::write(doc);
        f()
    }

    // Points `tpm.key_dir` at a fresh private directory for the duration
    // of `f`, layered over the policy in force -- so the harness's TCTI,
    // and any policy the test itself set, still apply.
    fn with_key_dir<T>(f: impl FnOnce(&Path) -> T) -> T {
        let dir = crate::secure_file::private_tempdir();
        let keys = dir.path().join("tpm");
        std::fs::create_dir(&keys).unwrap();
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
        with_policy(&format!("[tpm]\nkey_dir = \"{}\"\n", keys.display()), || f(&keys))
    }

    const SERVICE: &str = "com.company.orders";

    #[test]
    #[serial]
    fn a_written_key_file_reads_back_as_the_same_key() {
        with_key_dir(|dir| {
            assert!(read_key_file(SERVICE).unwrap().is_none(), "no file: not provisioned");
            let public = fake_service_public();
            write_key_file(SERVICE, &fake_blob(&public)).unwrap();

            let path = dir.join("com.company.orders.tpmkey");
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.starts_with("-----BEGIN TSS2 PRIVATE KEY-----\n"), "{text}");
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            // SAFETY: geteuid has no preconditions.
            let expected = if unsafe { libc::geteuid() } == 0 { 0o440 } else { 0o400 };
            assert_eq!(mode, expected);
            assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1, "the temporary file is gone");

            let file = read_key_file(SERVICE).unwrap().unwrap();
            assert_eq!(file.public, public);
            assert_eq!(file.private.value(), [0x5a; 126]);
        });
    }

    #[test]
    #[serial]
    fn a_second_write_never_replaces_the_first_key() {
        // A key file that is there when one is to be written -- which,
        // under the lock, only something other than provisioning put there
        // -- is left alone, and the write fails, saying so: the caller's
        // authValue file is not that key's.
        with_key_dir(|dir| {
            let first = fake_service_public();
            write_key_file(SERVICE, &fake_blob(&first)).unwrap();
            match write_key_file(SERVICE, &fake_blob(&fake_service_public())) {
                Err(Error::Provider(msg)) => assert!(msg.contains("appeared") && msg.contains("discarded"), "{msg}"),
                other => panic!("expected a refusal, got {other:?}"),
            }
            assert_eq!(read_key_file(SERVICE).unwrap().unwrap().public, first);
            assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1, "no temporary file left behind");
        });
    }

    #[test]
    fn a_group_readable_auth_file_must_have_the_group_policy_names() {
        // The group policy names: fine.
        assert_eq!(auth_file_group_problem(1234, Some(("orders", 1234))), None);
        // Another group -- the key directory's, say, after a chgrp or a
        // restore: refused, naming both.
        let other = auth_file_group_problem(999, Some(("orders", 1234))).expect("another group must be refused");
        assert!(other.contains("gid 999") && other.contains("\"orders\"") && other.contains("chgrp orders"), "{other}");
        // Any group at all, when policy names none for the service.
        let none = auth_file_group_problem(0, None).expect("no group may read it unless policy names one");
        assert!(none.contains("tpm.auth_groups") && none.contains("chmod 0400"), "{none}");
    }

    #[test]
    #[serial]
    fn writing_into_a_missing_key_dir_says_how_to_create_it() {
        let dir = crate::secure_file::private_tempdir();
        let missing = dir.path().join("not-yet");
        with_policy(&format!("[tpm]\nkey_dir = \"{}\"\n", missing.display()), || {
            assert!(read_key_file(SERVICE).unwrap().is_none(), "a missing directory means nothing is provisioned");
            match write_key_file(SERVICE, &fake_blob(&fake_service_public())) {
                Err(Error::Provider(msg)) => assert!(msg.contains("install -d -m 0750 -o root -g <key-users>"), "{msg}"),
                other => panic!("expected instructions, got {other:?}"),
            }
        });
    }

    #[test]
    #[serial]
    fn an_untrustworthy_key_file_is_an_error_never_not_provisioned() {
        with_key_dir(|dir| {
            let path = dir.join("com.company.orders.tpmkey");
            let pem = tpm_key_file::encode(&fake_blob(&fake_service_public())).unwrap();
            let put = |mode: u32| {
                let _ = std::fs::remove_file(&path);
                std::fs::write(&path, &pem).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            };
            put(0o600);
            assert!(read_key_file(SERVICE).unwrap().is_some(), "owner-only is fine");

            // Readable or writable by others: refused. Group read is allowed
            // only on a root-owned file.
            let mut modes = vec![0o604, 0o620, 0o644];
            // SAFETY: geteuid has no preconditions.
            if unsafe { libc::geteuid() } != 0 {
                modes.push(0o640);
            }
            for mode in modes {
                put(mode);
                assert!(matches!(read_key_file(SERVICE), Err(Error::Provider(_))), "mode {mode:o} must be refused");
            }

            // A symlink to a perfectly good file: refused.
            put(0o600);
            let real = dir.join("real.tpmkey");
            std::fs::rename(&path, &real).unwrap();
            std::os::unix::fs::symlink(&real, &path).unwrap();
            assert!(matches!(read_key_file(SERVICE), Err(Error::Provider(_))), "a symlinked key file must be refused");
        });
    }

    #[test]
    #[serial]
    fn a_key_file_under_a_shared_directory_is_refused() {
        with_key_dir(|dir| {
            write_key_file(SERVICE, &fake_blob(&fake_service_public())).unwrap();
            let parent = dir.parent().unwrap();
            for mode in [0o1777, 0o770] {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode)).unwrap();
                let read = read_key_file(SERVICE);
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
                match read {
                    Err(Error::Provider(msg)) => assert!(msg.contains("writable by group or others"), "{msg}"),
                    other => panic!("mode {mode:o}: expected a refusal, got {:?}", other.map(|f| f.is_some())),
                }
            }
        });
    }

    #[test]
    #[serial]
    fn a_key_file_holding_a_key_this_library_would_not_create_is_refused() {
        with_key_dir(|_| {
            // fixedTPM clear: a key that could have been imported, with a
            // value someone outside the TPM knows.
            let Public::KeyedHash { object_attributes, name_hashing_algorithm, auth_policy, parameters, unique } =
                fake_service_public()
            else {
                unreachable!()
            };
            let importable = Public::KeyedHash {
                object_attributes: tss_esapi::attributes::ObjectAttributes::from(
                    tss_esapi::tss2_esys::TPMA_OBJECT::from(object_attributes) & !0x2, // TPMA_OBJECT_FIXEDTPM
                ),
                name_hashing_algorithm,
                auth_policy,
                parameters,
                unique,
            };
            write_key_file(SERVICE, &fake_blob(&importable)).unwrap();
            match read_key_file(SERVICE) {
                Err(Error::Provider(msg)) => assert!(msg.contains("not a key this library creates"), "{msg}"),
                other => panic!("expected a refusal, got {:?}", other.map(|f| f.is_some())),
            }
        });
    }

    #[test]
    #[serial]
    fn a_damaged_key_file_is_refused_with_its_path() {
        with_key_dir(|dir| {
            let path = dir.join("com.company.orders.tpmkey");
            for contents in [&b"not a key file"[..], &[0u8; 5000][..]] {
                let _ = std::fs::remove_file(&path);
                std::fs::write(&path, contents).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                match read_key_file(SERVICE) {
                    Err(Error::Provider(msg)) => assert!(msg.contains(&path.display().to_string()), "{msg}"),
                    other => panic!("expected a refusal, got {:?}", other.map(|f| f.is_some())),
                }
            }
        });
    }

    const SOME_NAME: &str = "000b0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    #[test]
    #[serial]
    fn pins_gate_a_key_file_as_policy_says() {
        let public = fake_service_public();
        let real = hex(&computed_name(&public).unwrap());
        let base = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n";

        let _no_policy = TestPolicy::minimal();
        assert!(pin_allows(SERVICE, &public).unwrap(), "with nothing set, any key file is usable");
        drop(_no_policy);

        let allowlist = format!("{base}[tpm]\nrequire_pinned_names = true\n");
        assert!(!with_policy(&allowlist, || pin_allows(SERVICE, &public)).unwrap(), "unpinned under the allowlist");

        let pinned = format!("{allowlist}[tpm.pinned_names]\n\"{SERVICE}\" = \"{real}\"\n");
        assert!(with_policy(&pinned, || pin_allows(SERVICE, &public)).unwrap());
        // Pinned under another spelling: the same normalization as the C ABI.
        assert!(with_policy(&pinned, || pin_allows(&crate::normalize_service("COM.COMPANY.ORDERS"), &public)).unwrap());

        let wrong = format!("{base}[tpm.pinned_names]\n\"{SERVICE}\" = \"{SOME_NAME}\"\n");
        match with_policy(&wrong, || pin_allows(SERVICE, &public)) {
            Err(Error::Provider(msg)) => assert!(msg.contains(&real) && msg.contains(SOME_NAME), "{msg}"),
            other => panic!("a key that isn't the pinned one must be an error, got {other:?}"),
        }

        // A broken policy fails closed: an error, not "usable".
        assert!(with_policy("[selection]\nmode = \"require\"\n", || pin_allows(SERVICE, &public)).is_err());
    }

    #[test]
    fn the_pinning_instructions_carry_the_key_files_real_name() {
        let public = fake_service_public();
        let message = unpinned_service_instructions(SERVICE, &public);
        let expected = format!("\"{SERVICE}\" = \"{}\"", hex(&computed_name(&public).unwrap()));
        assert!(message.contains(&expected), "{message}");
    }

    // ---- TCTI selection: policy, else the default; never the environment ----

    fn tcti_of(result: Result<TctiNameConf>) -> String {
        format!("{:?}", result.expect("a TCTI should resolve"))
    }

    #[test]
    #[serial]
    fn tcti_defaults_to_the_kernel_resource_manager() {
        let _no_policy = TestPolicy::minimal();
        assert_eq!(tcti_of(resolve_tcti()), tcti_of(TctiNameConf::from_str(DEFAULT_TCTI).map_err(|e| Error::Provider(e.to_string()))));
    }

    #[test]
    #[serial]
    fn the_policy_tcti_is_used() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\ntcti = \"swtpm:host=127.0.0.1,port=9999\"\n";
        let shown = tcti_of(with_policy(doc, resolve_tcti));
        assert!(shown.contains("9999"), "policy TCTI must be used, got {shown}");
    }

    #[test]
    #[serial]
    fn the_environment_never_chooses_the_tpm() {
        // Whoever chooses the TPM chooses which TPM loads the key files,
        // so the tpm2-tools variables are ignored in every build -- this
        // test binary included.
        let _no_policy = TestPolicy::minimal();
        let saved: Vec<_> = ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"].iter().map(|n| (*n, std::env::var_os(n))).collect();
        for (name, _) in &saved {
            std::env::set_var(name, "swtpm:host=127.0.0.1,port=7777");
        }
        let resolved = resolve_tcti();
        let explicit = tcti_is_explicit();
        for (name, value) in saved {
            match value {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
        assert!(!tcti_of(resolved).contains("7777"), "an environment TCTI must be ignored");
        assert!(!explicit);
    }

    #[test]
    #[serial]
    fn an_unusable_policy_tcti_makes_the_tpm_unavailable_not_the_default() {
        // Passes the policy's kind check but can't be parsed as a TCTI.
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\ntcti = \"mssim:port=notaport\"\n";
        assert!(with_policy(doc, resolve_tcti).is_err(), "a bad policy TCTI must not fall back to the default device");

        // And a broken policy file is an error too, not the default.
        assert!(with_policy("[selection]\nmode = \"require\"\n", resolve_tcti).is_err());
    }

    #[test]
    fn tss2_log_at_debug_or_trace_is_refused_and_lower_levels_are_not() {
        for leaky in [
            "all+debug",
            "all+trace",
            "all+DEBUG",
            "tcti+debug",
            "esys+Trace",
            "all+warning,tcti+debug",
            "esys+info,all+trace",
            "all+debugging", // tpm2-tss matches levels by prefix
        ] {
            assert!(tss2_log_exposes_secrets(leaky), "{leaky:?} must be refused");
        }
        for safe in ["", "all+none", "all+error", "all+warning", "all+info", "esys+info,tcti+warning", "debug", "trace"] {
            assert!(!tss2_log_exposes_secrets(safe), "{safe:?} must be allowed");
        }
    }

    // ---- authValue files (no TPM needed) ----

    #[test]
    #[serial]
    fn provisioning_an_auth_file_writes_32_private_bytes_and_never_replaces_one() {
        with_key_dir(|dir| {
            assert!(read_auth_file(SERVICE).unwrap().is_none(), "no file: none provisioned");
            refuse_orphaned_auth_file(SERVICE).expect("nothing there to protect");
            let value = generate_auth_value().unwrap();
            let (first, _) = provision_auth_file(SERVICE, &value).unwrap();
            let path = dir.join("com.company.orders.tpmauth");
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(bytes.len(), AUTH_VALUE_LEN);
            assert_ne!(bytes[AUTH_VALUE_LEN - 1], 0, "the TPM would drop a trailing zero");
            // Whoever writes it, no group may read it unless policy names
            // one: as root, root:root 0400; as anyone else, their own 0400.
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o400);
            if running_as_root() {
                assert_eq!(meta.gid(), 0, "never the key directory's group");
            }
            assert_eq!(first.value(), bytes.as_slice());
            assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1, "no temporary file left behind");

            assert_eq!(first.value(), &value[..]);
            assert_ne!(generate_auth_value().unwrap()[..], value[..], "a fresh value every time");

            // An authValue file with no key file may be half of a key whose
            // key file is only missing for now: provisioning is refused
            // before the TPM is asked for a key, the message names both
            // files, and the write itself refuses too.
            for refused in [refuse_orphaned_auth_file(SERVICE), provision_auth_file(SERVICE, &generate_auth_value().unwrap()).map(|_| ())] {
                match refused {
                    Err(Error::Provider(msg)) => {
                        assert!(msg.contains("never replaces an authValue file"), "{msg}");
                        assert!(msg.contains("com.company.orders.tpmauth") && msg.contains("com.company.orders.tpmkey"), "{msg}");
                    }
                    other => panic!("expected a refusal, got {other:?}"),
                }
            }
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "left exactly as it was");
            assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1, "no temporary file left behind");
            // Even one this process couldn't read or use.
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink("/nonexistent", &path).unwrap();
            assert!(refuse_orphaned_auth_file(SERVICE).is_err(), "whatever is at the name");
            std::fs::remove_file(&path).unwrap();

            // Taking back the file of a key whose key file couldn't be
            // written -- unless it is no longer the file written: one put
            // in its place since (a restore) is not this call's to delete.
            let (_, written) = provision_auth_file(SERVICE, &value).unwrap();
            // Renamed over it, so both exist at once and can't share an inode.
            let restored = dir.join("restored");
            std::fs::write(&restored, [0x5a; AUTH_VALUE_LEN]).unwrap();
            std::fs::rename(&restored, &path).unwrap();
            remove_new_auth_file(SERVICE, written);
            assert_eq!(std::fs::read(&path).unwrap(), [0x5a; AUTH_VALUE_LEN], "someone else's file is left alone");
            std::fs::remove_file(&path).unwrap();

            let (_, written) = provision_auth_file(SERVICE, &value).unwrap();
            remove_new_auth_file(SERVICE, written);
            assert!(!path.exists());
            refuse_orphaned_auth_file(SERVICE).expect("so the next attempt isn't blocked");
        });
    }

    #[test]
    #[serial]
    fn an_auth_file_this_process_cannot_read_says_how_to_grant_it() {
        if running_as_root() {
            eprintln!("skipping: root reads any file");
            return;
        }
        with_key_dir(|dir| {
            let path = dir.join("com.company.orders.tpmauth");
            std::fs::write(&path, [7u8; AUTH_VALUE_LEN]).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            match read_auth_file(SERVICE) {
                Err(Error::Provider(msg)) => {
                    assert!(msg.contains("can't be read by this process") && msg.contains("tpm.auth_groups"), "{msg}");
                    assert!(msg.contains(&format!("chgrp <group> {}", path.display())), "{msg}");
                }
                other => panic!("expected an error, got {:?}", other.map(|a| a.map(|_| ()))),
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        });
    }

    // A non-blocking exclusive `flock` on `path` through an open file
    // description of its own, as another process's would be: whether it
    // was granted, and the descriptor holding it.
    fn try_flock(path: &Path) -> (bool, std::fs::File) {
        let file = std::fs::File::open(path).unwrap();
        // SAFETY: `file` is open for the duration of the call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        (rc == 0, file)
    }

    #[test]
    #[serial]
    fn the_key_dir_lock_excludes_every_other_holder_until_dropped() {
        with_key_dir(|dir| {
            let lock_file = dir.join(LOCK_FILE_NAME);
            let lock = KeyDirLock::acquire().unwrap();
            assert!(!try_flock(&lock_file).0, "held: nobody else gets it");
            // A second provisioner waits, then gives up without changing anything.
            match KeyDirLock::acquire_within(std::time::Duration::from_millis(120)) {
                Err(Error::Provider(msg)) => assert!(msg.contains("still held") && msg.contains("nothing was changed"), "{msg}"),
                other => panic!("expected a timeout, got {:?}", other.map(|_| ())),
            }
            drop(lock);
            assert!(try_flock(&lock_file).0, "dropped: free again");
            KeyDirLock::acquire().expect("and it can be taken again");
        });
        // A missing key directory: the same instructions as writing into one.
        let dir = crate::secure_file::private_tempdir();
        with_policy(&format!("[tpm]\nkey_dir = \"{}\"\n", dir.path().join("not-yet").display()), || {
            match KeyDirLock::acquire() {
                Err(Error::Provider(msg)) => assert!(msg.contains("install -d -m 0750"), "{msg}"),
                other => panic!("expected instructions, got {:?}", other.map(|_| ())),
            }
        });
    }

    #[test]
    #[serial]
    fn a_lock_held_on_the_key_directory_itself_blocks_nothing() {
        // What any account that can open the directory could do: every
        // service using TPM keys can, and `flock` asks no more of it.
        with_key_dir(|dir| {
            let (granted, _held) = try_flock(dir);
            assert!(granted);
            KeyDirLock::acquire_within(std::time::Duration::from_millis(120)).expect("the directory's own lock is not the one taken");
        });
    }

    #[test]
    #[serial]
    fn the_lock_file_is_one_only_its_owner_can_open() {
        with_key_dir(|dir| {
            let lock_file = dir.join(LOCK_FILE_NAME);
            drop(KeyDirLock::acquire().unwrap());
            let meta = std::fs::symlink_metadata(&lock_file).unwrap();
            assert!(meta.file_type().is_file());
            assert_eq!(meta.mode() & 0o7777, 0o600);
            assert_eq!(meta.len(), 0, "nothing is ever written to it");

            // One left with a broader mode is narrowed before it is locked.
            std::fs::set_permissions(&lock_file, std::fs::Permissions::from_mode(0o664)).unwrap();
            drop(KeyDirLock::acquire().unwrap());
            assert_eq!(std::fs::metadata(&lock_file).unwrap().mode() & 0o7777, 0o600);

            // Anything but a regular file at the name is refused, not
            // followed or waited on: a symlink, a FIFO, a directory.
            std::fs::remove_file(&lock_file).unwrap();
            let elsewhere = dir.join("elsewhere");
            std::fs::write(&elsewhere, b"").unwrap();
            std::os::unix::fs::symlink(&elsewhere, &lock_file).unwrap();
            assert!(matches!(KeyDirLock::acquire(), Err(Error::Provider(_))), "a symlink is not followed");
            std::fs::remove_file(&lock_file).unwrap();

            let c_path = std::ffi::CString::new(lock_file.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: `c_path` is a NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
            match KeyDirLock::acquire() {
                Err(Error::Provider(msg)) => assert!(msg.contains("not a regular file"), "{msg}"),
                other => panic!("a FIFO must be refused, got {:?}", other.map(|_| ())),
            }
            std::fs::remove_file(&lock_file).unwrap();

            std::fs::create_dir(&lock_file).unwrap();
            assert!(matches!(KeyDirLock::acquire(), Err(Error::Provider(_))), "a directory is refused");
        });
    }

    #[test]
    fn the_unpinned_srk_refusal_carries_the_name_ready_to_pin() {
        let name = [vec![0x00, 0x0b], vec![0xa5; 32]].concat();
        let msg = unpinned_srk_instructions(&name);
        let name_hex = hex(&name);
        assert!(msg.contains(&format!("pinned_session_salt_key_name = \"{name_hex}\"")), "{msg}");
        assert!(msg.contains("Nothing was created") && msg.contains("allow_unpinned_provisioning = true"), "{msg}");
        // What it prints is what the policy accepts.
        let doc = format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\npinned_session_salt_key_name = \"{name_hex}\"\n");
        assert_eq!(crate::policy::Policy::from_toml_str(&doc).unwrap().pinned_session_salt_key_name(), Some(name.as_slice()));
    }

    #[test]
    #[serial]
    fn an_auth_file_this_library_would_not_write_is_refused() {
        with_key_dir(|dir| {
            let path = dir.join("com.company.orders.tpmauth");
            let put = |bytes: &[u8], mode: u32| {
                let _ = std::fs::remove_file(&path);
                std::fs::write(&path, bytes).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            };
            let refused = |why: &str| match read_auth_file(SERVICE) {
                Err(Error::Provider(msg)) => assert!(msg.contains(why), "expected {why:?}, got {msg}"),
                other => panic!("expected a refusal ({why}), got {:?}", other.map(|a| a.map(|_| ()))),
            };
            put(&[7u8; 31], 0o400);
            refused("is 31 bytes");
            put(&[7u8; 33], 0o400);
            refused("could not be read");
            let mut trailing_zero = [7u8; AUTH_VALUE_LEN];
            trailing_zero[AUTH_VALUE_LEN - 1] = 0;
            put(&trailing_zero, 0o400);
            refused("zero byte");
            put(&[7u8; AUTH_VALUE_LEN], 0o440); // group-readable, but owned by this user rather than root
            refused("can't be trusted");
            put(&[7u8; AUTH_VALUE_LEN], 0o400);
            assert!(read_auth_file(SERVICE).unwrap().is_some());
        });
    }

    #[test]
    #[serial]
    fn a_key_file_without_its_auth_file_is_an_error_not_unprovisioned() {
        with_key_dir(|_| {
            write_key_file(SERVICE, &fake_blob(&fake_service_public())).unwrap();
            match required_auth_file(SERVICE) {
                Err(Error::Provider(msg)) => {
                    assert!(msg.contains("no authValue file") && msg.contains(".tpmauth"), "{msg}");
                    // Retiring needs the authValue too, so the message must
                    // not send the operator there: it names what works.
                    assert!(!msg.contains("retire the service"), "{msg}");
                    assert!(msg.contains("delete") && msg.contains("com.company.orders.tpmkey by hand"), "{msg}");
                }
                other => panic!("expected an error, got {:?}", other.map(|_| ())),
            }
        });
    }

    // ---- a TPM device that exists but can't be opened (no TPM needed) ----

    // A provider in the state `new()` leaves it in when `/dev/tpmrm0`
    // exists but this process couldn't open it.
    fn unreachable_provider() -> Tpm2Provider {
        let device = crate::secure_file::private_tempdir();
        Tpm2Provider {
            context: Arc::new(Mutex::new(None)),
            refused: None,
            unreachable: unreachable_default_device(device.path()),
            no_device: None,
        }
    }

    // A provider in the state `new()` leaves it in when there is no
    // `/dev/tpmrm0` at all.
    fn no_device_provider() -> Tpm2Provider {
        Tpm2Provider {
            context: Arc::new(Mutex::new(None)),
            refused: None,
            unreachable: None,
            no_device: Some(missing_default_device(Path::new(DEFAULT_DEVICE))),
        }
    }

    #[test]
    #[serial]
    fn a_missing_tpm_device_is_absent_except_for_a_service_with_a_key_file() {
        with_key_dir(|_| {
            let tpm = no_device_provider();
            assert!(!tpm.probe(), "no device: the TPM takes no part in the chain");
            tpm.claims_while_absent(SERVICE).expect("no key file: nothing ties the service to the TPM");

            // With a key file, the TPM is this service's provider, and its
            // disappearance is an outage: every path refuses, so the chain
            // can't hand the service's wraps to whatever comes next.
            write_key_file(SERVICE, &fake_blob(&fake_service_public())).unwrap();
            assert!(!tpm.probe());
            let refused = |result: Result<()>| match result {
                Err(Error::Provider(msg)) => assert!(
                    msg.contains("has a TPM key file") && msg.contains("there is no TPM device at /dev/tpmrm0") && msg.contains("restore the TPM"),
                    "{msg}"
                ),
                other => panic!("expected the TPM to refuse, got {other:?}"),
            };
            refused(tpm.claims_while_absent(SERVICE));
            refused(tpm.kek_exists(SERVICE).map(|_| ()));
            refused(tpm.load_kek(SERVICE, false).map(|_| ()));
            refused(tpm.load_kek(SERVICE, true).map(|_| ()));
            refused(tpm.retire_kek(SERVICE, &[0; crate::payload::FINGERPRINT_LEN]));
            tpm.claims_while_absent("com.company.billing").expect("another service, with no key file, is unaffected");
        });
    }

    // The same through the chain, on a host that really has no TPM device:
    // the wrap fails naming the TPM, rather than reporting no KEK (which a
    // caller answers by creating one somewhere weaker) or using a later
    // provider's.
    #[test]
    #[serial]
    fn the_chain_stops_at_a_tpm_key_file_whose_tpm_is_gone() {
        with_key_dir(|_| {
            if Tpm2Provider::new().no_device.is_none() {
                eprintln!("skipping: this host has a TPM device, or the test harness names a TCTI");
                return;
            }
            write_key_file(SERVICE, &fake_blob(&fake_service_public())).unwrap();
            for result in [
                crate::provider::select_existing(SERVICE).map(|_| ()),
                crate::provider::create_kek(SERVICE).map(|_| ()),
                crate::provider::kek_exists(SERVICE).map(|_| ()),
            ] {
                match result {
                    Err(Error::Provider(msg)) => assert!(msg.starts_with("TPM2: ") && msg.contains("there is no TPM device"), "{msg}"),
                    other => panic!("expected the TPM to stop the chain, got {other:?}"),
                }
            }
        });
    }

    #[test]
    fn conformance_verdicts_are_kept_per_tpm() {
        let a = "swtpm:host=verdict-test-a".to_string();
        let b = "swtpm:host=verdict-test-b".to_string();
        assert_eq!(cached_verdict(&a), None);
        assert!(!record_verdict(a.clone(), false));
        assert!(!record_verdict(a.clone(), true), "the first definitive verdict for a TPM stands");
        assert_eq!(cached_verdict(&a), Some(false));
        assert_eq!(cached_verdict(&b), None, "another TPM is tested on its own");
        assert!(record_verdict(b.clone(), true));
        assert_eq!(cached_verdict(&b), Some(true));
    }

    #[test]
    fn only_a_device_that_exists_counts_as_unreachable() {
        let device = crate::secure_file::private_tempdir();
        let reason = unreachable_default_device(device.path()).expect("the device exists");
        assert!(reason.contains("could not open the TPM") && reason.contains("tss"), "{reason}");
        assert_eq!(unreachable_default_device(&device.path().join("no-such-tpm")), None, "no device: no TPM here");
        assert_eq!(DEFAULT_TCTI.strip_prefix("device:"), Some(DEFAULT_DEVICE));
    }

    #[test]
    #[serial]
    fn an_unopenable_tpm_steps_aside_for_a_service_without_a_key_file() {
        with_key_dir(|_| {
            let tpm = unreachable_provider();
            assert!(tpm.probe(), "the TPM is there, so the chain asks it");
            assert!(!tpm.kek_exists(SERVICE).unwrap());
            for create in [false, true] {
                match tpm.load_kek(SERVICE, create) {
                    Err(Error::KeyNotProvisioned(msg)) => assert!(msg.contains("can't open the TPM"), "{msg}"),
                    other => panic!("create {create}: expected the chain to move on, got {:?}", other.map(|_| ())),
                }
            }
        });
    }

    #[test]
    #[serial]
    fn an_unopenable_tpm_stops_the_chain_for_a_service_with_a_key_file() {
        with_key_dir(|dir| {
            write_key_file(SERVICE, &fake_blob(&fake_service_public())).unwrap();
            let tpm = unreachable_provider();
            let refused = |result: Result<()>| match result {
                Err(Error::Provider(msg)) => {
                    assert!(msg.contains("has a TPM key file") && msg.contains("com.company.orders.tpmkey"), "{msg}")
                }
                other => panic!("expected the TPM to refuse, got {other:?}"),
            };
            refused(tpm.kek_exists(SERVICE).map(|_| ()));
            refused(tpm.load_kek(SERVICE, false).map(|_| ()));
            refused(tpm.load_kek(SERVICE, true).map(|_| ()));
            refused(tpm.retire_kek(SERVICE, &[0; crate::payload::FINGERPRINT_LEN]));

            // A process not allowed to look in the key directory was never
            // given TPM keys: it moves on, as with no key file.
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o000)).unwrap();
            let blind = std::fs::read_dir(dir).is_err(); // false as root, which sees through the mode
            let exists = tpm.kek_exists(SERVICE);
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            if blind {
                assert!(!exists.unwrap(), "an unreadable key directory is not this service's TPM");
            }
        });
    }

    #[test]
    fn generated_auth_values_never_end_in_zero_and_differ() {
        let values: Vec<_> = (0..256).map(|_| generate_auth_value().unwrap()).collect();
        assert!(values.iter().all(|v| v[AUTH_VALUE_LEN - 1] != 0));
        assert_ne!(*values[0], *values[1]);
    }

    // ---------------------------------------------------------------
    // Conformance suite, against a real or simulated TPM.
    //
    // These validate (against swtpm, a physical TPM, Intel PTT, AMD
    // fTPM, ...) what the key files depend on: the SRK is reproducible, a
    // key file reloads to the same key, the TPM refuses a key file that
    // isn't its own, and the Name formula matches the TPM's. All require
    // a TPM2 device and are `#[ignore]`d so a normal `cargo test` stays
    // portable; run them with `cargo test --features tpm2 -- --ignored`
    // (see docker/README.md and scripts/native-tpm-test.sh). Each test
    // uses its own key directory.
    // ---------------------------------------------------------------

    // Constructs a fresh `Tpm2Provider`, confirms it's actually reachable,
    // and hands the caller a `&mut Context` to drive directly.
    fn with_tpm_context<T>(f: impl FnOnce(&mut Context) -> Result<T>) -> Result<T> {
        let provider = Tpm2Provider::new();
        if !provider.probe() {
            return Err(Error::Provider("no TPM available for conformance test".into()));
        }
        with_context(&provider.context, f)
    }

    fn provider() -> Tpm2Provider {
        let provider = Tpm2Provider::new();
        assert!(provider.probe(), "no TPM available");
        provider
    }

    // Runs the exact same `load_kek` + `prf` path production code uses
    // and returns the PRF output for `input`.
    fn prf_output(service: &str, create: bool, input: &[u8]) -> Result<[u8; 32]> {
        let handle = provider().load_kek(service, create)?;
        Ok(*handle.prf(&[input])?[0])
    }

    // The fingerprint of the key a handle uses: what a payload carries.
    fn fingerprint(handle: &dyn KekHandle) -> [u8; 32] {
        crate::crypto::kek_fingerprint(handle).unwrap()
    }

    fn srk_name() -> Vec<u8> {
        with_tpm_context(|ctx| {
            let (handle, _public, name) = create_srk_unpinned(ctx)?;
            let _ = ctx.flush_context(handle.into());
            Ok(name.value().to_vec())
        })
        .unwrap()
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn provisioning_writes_a_key_file_that_every_later_call_uses() {
        with_key_dir(|dir| {
            let tpm = provider();
            assert!(!tpm.kek_exists(SERVICE).unwrap());
            assert!(matches!(tpm.load_kek(SERVICE, false), Err(Error::KeyNotProvisioned(_))), "no key file: not provisioned");

            let created = fingerprint(&*tpm.load_kek(SERVICE, true).unwrap());
            assert!(tpm.kek_exists(SERVICE).unwrap());
            let file = dir.join("com.company.orders.tpmkey");
            let bytes = std::fs::read(&file).unwrap();

            // Provisioning again is idempotent: the same key, the file untouched.
            assert_eq!(fingerprint(&*tpm.load_kek(SERVICE, true).unwrap()), created);
            assert_eq!(std::fs::read(&file).unwrap(), bytes);

            // A new connection -- as a new process would have -- loads the
            // same key, and its HMAC is repeatable.
            let first = prf_output(SERVICE, false, b"input").unwrap();
            assert_eq!(first, prf_output(SERVICE, false, b"input").unwrap(), "repeatable");
            assert_eq!(fingerprint(&*provider().load_kek(SERVICE, false).unwrap()), created);
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn different_services_get_different_keys() {
        with_key_dir(|_| {
            let tpm = provider();
            let keys: Vec<_> = ["orders", "billing", "payments"].iter().map(|s| fingerprint(&*tpm.load_kek(s, true).unwrap())).collect();
            assert_ne!(keys[0], keys[1]);
            assert_ne!(keys[0], keys[2]);
            assert_ne!(keys[1], keys[2]);
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn concurrent_provisioning_leaves_one_key() {
        // A simulator TCTI has no resource manager, so concurrent
        // connections share its three transient-object slots and run out
        // (TPM_RC_OBJECT_MEMORY) -- one reason those TCTIs are for tests
        // only. There, the provisioners run one after another: the race
        // itself is then only covered by `a_second_write_never_replaces_the_first_key`.
        let simulator = crate::policy::tpm_tcti().unwrap().is_some_and(|t| t.starts_with("swtpm:") || t.starts_with("mssim:"));
        with_key_dir(|_| {
            let provision = || Tpm2Provider::new().load_kek(SERVICE, true).and_then(|h| crate::crypto::kek_fingerprint(&*h));
            let keys: Vec<_> = if simulator {
                (0..4).map(|_| provision().unwrap()).collect()
            } else {
                (0..4)
                    .map(|_| std::thread::spawn(provision))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|t| t.join().unwrap().unwrap())
                    .collect()
            };
            assert!(keys.iter().all(|k| *k == keys[0]), "every provisioner must end up with the one key on disk");
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn the_tpm_refuses_a_key_file_whose_halves_dont_belong_together() {
        // Another key's public area paired with this key's private area
        // passes every file check (both are genuine service keys), so this
        // is the TPM's own integrity check at TPM2_Load.
        with_key_dir(|dir| {
            let tpm = provider();
            tpm.load_kek("orders", true).unwrap();
            tpm.load_kek("billing", true).unwrap();
            let orders = read_key_file("orders").unwrap().unwrap();
            let billing = read_key_file("billing").unwrap().unwrap();
            let spliced = KeyBlob { public: billing.public.marshall().unwrap(), private: orders.private.value().to_vec() };
            let path = dir.join("spliced.tpmkey");
            std::fs::write(&path, tpm_key_file::encode(&spliced).unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
            // The private half's own authValue, so only the TPM's check is left to catch it.
            let auth = dir.join("spliced.tpmauth");
            std::fs::copy(dir.join("orders.tpmauth"), &auth).unwrap();
            std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o400)).unwrap();

            let handle = tpm.load_kek("spliced", false).expect("the file checks can't see the splice");
            match handle.prf(&[b"input"]) {
                Err(Error::Provider(msg)) => assert!(msg.contains("TPM2_Load"), "{msg}"),
                other => panic!("the TPM must refuse the spliced key file, got {:?}", other.map(|_| ())),
            }
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn tpm_conformance_self_test_passes_on_a_compatible_tpm() {
        // Exercises `validate_tpm_compatibility` the same way `open_context`
        // does at connection time: a compatible TPM must pass it, and
        // `Tpm2Provider::new()` must therefore still report itself available.
        assert!(with_tpm_context(validate_tpm_compatibility).unwrap(), "the SRK must be reproducible and TPM2_HMAC standard");
        assert!(Tpm2Provider::new().probe());
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn tpm_reported_name_matches_the_client_recomputed_name() {
        // This is the test that proves `verify_name`'s formula (and
        // tss-esapi's marshalling) agrees with the TPM's own Name
        // computation -- if it doesn't, nothing else here works. Read back
        // with TPM2_ReadPublic, not ESAPI's cached Name.
        with_key_dir(|_| {
            provider().load_kek(SERVICE, true).unwrap();
            let file = read_key_file(SERVICE).unwrap().unwrap();
            let auth = read_auth_file(SERVICE).unwrap().unwrap();
            let name = with_tpm_context(|ctx| {
                let srk = create_srk(ctx)?;
                let key = load_service_key(ctx, srk, SERVICE, &file.public, &file.private, &auth)?;
                let read = ctx.read_public(key).map_err(|e| Error::Provider(e.to_string()));
                let _ = ctx.flush_context(key.into());
                let _ = ctx.flush_context(srk.into());
                Ok(read?.1)
            })
            .unwrap();
            assert_eq!(
                name.value(),
                computed_name(&file.public).unwrap().as_slice(),
                "the TPM's own Name disagrees with nameAlg || SHA-256(marshalled public area)"
            );
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn tpm2_hmac_is_hmac_sha256_for_every_input_length() {
        // The self-test checks the longest input; the PRF's real inputs
        // are shorter and vary (the fingerprint block, and wrap blocks for
        // every service-name length). Each must match software HMAC.
        let lengths = [0, 1, 37, 63, 64, 65, 200, crate::crypto::MAX_PRF_INPUT_LEN];
        for len in lengths {
            let input = vec![0xa5; len];
            let on_tpm = with_tpm_context(|ctx| hmac_known_answer(ctx, &input)).unwrap();
            assert_eq!(on_tpm, *crate::provider::software_prf(&KNOWN_ANSWER_KEY, &[&input])[0], "{len}-byte input");
        }
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn the_prf_is_repeatable_and_separates_keys_and_inputs() {
        with_key_dir(|_| {
            let first = prf_output(SERVICE, true, b"salt-1").unwrap();
            assert_eq!(first, prf_output(SERVICE, false, b"salt-1").unwrap(), "repeatable for the same service and input");
            assert_ne!(first, prf_output(SERVICE, false, b"salt-2").unwrap(), "different inputs must yield different outputs");
            assert_ne!(first, prf_output("com.company.billing", true, b"salt-1").unwrap(), "different KEKs must differ");

            // Several inputs in one call: one key load, the same outputs.
            let both = provider().load_kek(SERVICE, false).unwrap().prf(&[b"salt-1", b"salt-2"]).unwrap();
            assert_eq!(*both[0], first);
            assert_eq!(*both[1], prf_output(SERVICE, false, b"salt-2").unwrap());
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn retiring_deletes_the_key_file_only_with_the_right_fingerprint() {
        with_key_dir(|dir| {
            let tpm = provider();
            let right = fingerprint(&*tpm.load_kek(SERVICE, true).unwrap());
            let mut wrong = right;
            wrong[0] ^= 1;
            assert!(matches!(tpm.retire_kek(SERVICE, &wrong), Err(Error::KekFingerprintMismatch)));
            assert!(dir.join("com.company.orders.tpmkey").exists(), "a wrong fingerprint deletes nothing");
            tpm.retire_kek(SERVICE, &right).unwrap();
            assert!(!dir.join("com.company.orders.tpmkey").exists());
            assert!(!tpm.kek_exists(SERVICE).unwrap());
            assert!(matches!(tpm.retire_kek(SERVICE, &right), Err(Error::KekNotFound)));
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn retiring_refuses_a_key_file_name_swapped_for_a_symlink_to_it() {
        // The key file is moved aside and a symlink to it put at its name:
        // following the link, the file looks unchanged, but deleting the
        // name would remove only the link and leave the key loadable.
        with_key_dir(|dir| {
            let tpm = provider();
            let right = fingerprint(&*tpm.load_kek(SERVICE, true).unwrap());
            let name = dir.join("com.company.orders.tpmkey");
            let moved = dir.join("moved-aside.tpmkey");
            std::fs::rename(&name, &moved).unwrap();
            std::os::unix::fs::symlink(&moved, &name).unwrap();
            // Reading refuses the symlink outright, so retire can't proceed either.
            match tpm.retire_kek(SERVICE, &right) {
                Err(Error::Provider(msg)) => assert!(msg.contains("can't be trusted") || msg.contains("changed"), "{msg}"),
                other => panic!("expected a refusal, got {other:?}"),
            }
            assert!(moved.exists(), "the key file itself is untouched");
            assert_eq!(FileIdentity::of(&name), FileIdentity::of(&moved));
            assert_ne!(FileIdentity::of_entry(&name), FileIdentity::of_entry(&moved), "what retire compares tells them apart");
        });
    }

    // ---- session parameter encryption ----

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn an_encrypted_session_hmac_equals_a_plain_session_hmac() {
        // Correctness: parameter encryption must be transparent -- the
        // TPM computes the same HMAC, ESAPI decrypts the response, and the
        // caller sees identical bytes. If the SRK weren't an acceptable
        // `tpmKey`, or the attributes were wrong, this is where it would
        // fail.
        with_key_dir(|_| {
            provider().load_kek(SERVICE, true).unwrap();
            let file = read_key_file(SERVICE).unwrap().unwrap();
            let auth = read_auth_file(SERVICE).unwrap().unwrap();
            let input = vec![0x42; crate::crypto::MAX_PRF_INPUT_LEN];
            let (plain, encrypted) = with_tpm_context(|ctx| {
                let srk = create_srk(ctx)?;
                let key = load_service_key(ctx, srk, SERVICE, &file.public, &file.private, &auth)?;
                let plain = start_plain_session(ctx).and_then(|session| {
                    let mac = tpm_hmac(ctx, Some(session), key, &input);
                    let _ = ctx.flush_context(SessionHandle::from(session).into());
                    mac
                });
                let encrypted = start_encrypted_session(ctx, srk).and_then(|session| {
                    let mac = tpm_hmac(ctx, Some(session), key, &input);
                    let _ = ctx.flush_context(SessionHandle::from(session).into());
                    mac
                });
                let _ = ctx.flush_context(key.into());
                let _ = ctx.flush_context(srk.into());
                Ok((plain?, encrypted?))
            })
            .unwrap();
            assert_eq!(*plain, *encrypted, "the HMAC must be identical through an encrypted session");
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn encrypted_sessions_really_carry_the_encryption_attributes() {
        // The test above cannot tell an encrypting session from one that
        // silently isn't: the HMAC is identical either way. This checks
        // what decides it -- the session's own attributes, as ESAPI
        // reports them for the session `tpm_prf` would use.
        let attributes = with_tpm_context(|ctx| {
            let srk = create_srk(ctx)?;
            let session = start_encrypted_session(ctx, srk);
            let attributes = session.as_ref().ok().map(|s| ctx.tr_sess_get_attributes(*s));
            if let Ok(s) = session {
                let _ = ctx.flush_context(SessionHandle::from(s).into());
            }
            let _ = ctx.flush_context(srk.into());
            Ok(attributes)
        })
        .unwrap()
        .expect("an encrypted session must start")
        .expect("its attributes must be readable");
        assert!(attributes.decrypt(), "the command's first parameter (buffer) must be encrypted");
        assert!(attributes.encrypt(), "the response's first parameter (outHMAC) must be encrypted");
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn the_tpm_refuses_hmac_with_the_srk() {
        // The SRK is restricted and not a keyed-hash key, so anyone who
        // recreates it from its public template still can't use it as a
        // PRF. A service key, for contrast, accepts the same input.
        with_key_dir(|_| {
            provider().load_kek(SERVICE, true).unwrap();
            let file = read_key_file(SERVICE).unwrap().unwrap();
            let auth = read_auth_file(SERVICE).unwrap().unwrap();
            let (refused, accepted) = with_tpm_context(|ctx| {
                let srk = create_srk(ctx)?;
                let refused = tpm_hmac(ctx, None, srk, b"input").is_err();
                let key = load_service_key(ctx, srk, SERVICE, &file.public, &file.private, &auth)?;
                let accepted = tpm_hmac(ctx, None, key, b"input").is_ok();
                let _ = ctx.flush_context(key.into());
                let _ = ctx.flush_context(srk.into());
                Ok((refused, accepted))
            })
            .unwrap();
            assert!(refused, "TPM2_HMAC with the restricted SRK must be refused by the TPM");
            assert!(accepted, "the control: a service key accepts the same input");
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn provisioning_under_an_unpinned_srk_is_refused_unless_policy_allows_it() {
        let name_hex = hex(&srk_name());
        with_key_dir(|dir| {
            // Neither pinned nor allowed: refused with the Name to pin, and
            // nothing written for the service -- no key file, no authValue file.
            with_policy("[tpm]\nallow_unpinned_provisioning = false\n", || {
                let tpm = provider();
                match tpm.load_kek(SERVICE, true) {
                    Err(Error::Provider(msg)) => {
                        assert!(msg.contains(&format!("pinned_session_salt_key_name = \"{name_hex}\"")), "{msg}");
                    }
                    other => panic!("expected the refusal, got {:?}", other.map(|_| ())),
                }
                assert!(!tpm.kek_exists(SERVICE).unwrap());
                assert!(!key_file_path(dir, SERVICE).exists() && !auth_file_path(dir, SERVICE).exists());
                // The primitive refuses on its own account too.
                let auth = Auth::try_from(generate_auth_value().unwrap().to_vec()).unwrap();
                assert!(matches!(with_tpm_context(|ctx| create_service_key(ctx, &auth)), Err(Error::Provider(_))));
            });

            // Pinned: provisioned, whatever the opt-out says.
            with_policy(
                &format!("[tpm]\nallow_unpinned_provisioning = false\npinned_session_salt_key_name = \"{name_hex}\"\n"),
                || {
                    provider().load_kek(SERVICE, true).expect("a pinned SRK provisions");
                },
            );
            assert!(key_file_path(dir, SERVICE).exists());
            // A key that exists is used with or without a pin: the gate is
            // on creating one.
            with_policy("[tpm]\nallow_unpinned_provisioning = false\n", || prf_output(SERVICE, false, b"input")).unwrap();

            // Allowed: provisioned without a pin, and audited.
            let other = "com.company.unpinned";
            with_policy("[tpm]\nallow_unpinned_provisioning = true\n", || {
                provider().load_kek(other, true).expect("the opt-out provisions");
            });
            let audited = crate::audit::captured_containing(other);
            assert!(audited.iter().any(|r| r.contains("event=1007 ")), "{audited:?}");
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn the_srk_is_pinnable_and_a_wrong_pin_stops_every_key() {
        let real = srk_name();
        assert_eq!(real, srk_name(), "the SRK must be stable, or it could never be pinned");

        with_key_dir(|_| {
            provider().load_kek(SERVICE, true).unwrap();
            let policy_for = |name_hex: &str| {
                format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"on\"\npinned_session_salt_key_name = \"{name_hex}\"\n")
            };
            with_policy(&policy_for(&hex(&real)), || prf_output(SERVICE, false, b"input"))
                .expect("a correctly pinned SRK must work");

            let mut wrong = real.clone();
            wrong[2] ^= 0xff;
            match with_policy(&policy_for(&hex(&wrong)), || prf_output(SERVICE, false, b"input")) {
                Err(Error::Provider(msg)) => assert!(msg.contains("storage root key Name"), "{msg}"),
                other => panic!("an SRK whose Name doesn't match the pin must be refused, got {other:?}"),
            }
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn session_encryption_on_and_off_give_the_same_prf() {
        // The full production path -- load_kek + prf -- under both modes.
        // On is the default: no policy setting needed.
        with_key_dir(|_| {
            assert!(session_encryption_enabled(), "encryption is on by default");
            let on = prf_output(SERVICE, true, b"input").unwrap();
            let off = with_policy("[tpm]\nsession_encryption = \"off\"\n", || {
                assert!(!session_encryption_enabled());
                prf_output(SERVICE, false, b"input").unwrap()
            });
            assert_eq!(on, off, "parameter encryption must not change the HMAC");
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn the_key_is_unusable_without_its_auth_value_and_a_wrong_one_costs_no_lockout() {
        // What makes the authValue the bus's protection: the TPM refuses
        // TPM2_HMAC with the key unless the session proves it. The key is
        // noDA, so a wrong value is TPM_RC_BAD_AUTH and never counts
        // toward lockout -- this test can run as often as it likes.
        with_key_dir(|dir| {
            provider().load_kek(SERVICE, true).unwrap();
            let file = read_key_file(SERVICE).unwrap().unwrap();
            let mut wrong = read_auth_file(SERVICE).unwrap().unwrap().value().to_vec();
            wrong[0] ^= 0x01;
            for (what, auth) in [("empty", Auth::default()), ("wrong", Auth::try_from(wrong).unwrap())] {
                for encrypted in [true, false] {
                    let result = with_tpm_context(|ctx| {
                        let srk = create_srk(ctx)?;
                        let key = load_service_key(ctx, srk, SERVICE, &file.public, &file.private, &auth)?;
                        let session = if encrypted { start_encrypted_session(ctx, srk) } else { start_plain_session(ctx) };
                        let mac = session.and_then(|session| {
                            let mac = tpm_hmac(ctx, Some(session), key, b"input");
                            let _ = ctx.flush_context(SessionHandle::from(session).into());
                            mac
                        });
                        let _ = ctx.flush_context(key.into());
                        let _ = ctx.flush_context(srk.into());
                        mac
                    });
                    match result {
                        Err(Error::Provider(msg)) => assert!(msg.contains("TPM2_HMAC failed"), "{what}, encrypted {encrypted}: {msg}"),
                        Ok(_) => panic!("the TPM must refuse the key with an {what} authValue (encrypted {encrypted})"),
                        Err(other) => panic!("{what}, encrypted {encrypted}: unexpected {other:?}"),
                    }
                }
            }
            // The right value still works afterwards: nothing was locked out.
            prf_output(SERVICE, false, b"input").unwrap();

            // The provider itself: its authValue file replaced, the key is refused.
            let path = dir.join("com.company.orders.tpmauth");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(&path, [0x5au8; AUTH_VALUE_LEN]).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
            assert!(prf_output(SERVICE, false, b"input").is_err(), "a replaced authValue file must not authorize the key");
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn provisioning_and_retiring_cover_the_auth_file() {
        with_key_dir(|dir| {
            let tpm = provider();
            let key_path = dir.join("com.company.orders.tpmkey");
            let auth_path = dir.join("com.company.orders.tpmauth");
            let right = fingerprint(&*tpm.load_kek(SERVICE, true).unwrap());
            assert!(key_path.exists() && auth_path.exists(), "provisioning writes both files");

            // A key file whose authValue file is gone: an error, never "no KEK".
            let saved = std::fs::read(&auth_path).unwrap();
            std::fs::remove_file(&auth_path).unwrap();
            assert!(matches!(tpm.kek_exists(SERVICE), Err(Error::Provider(_))));
            assert!(matches!(tpm.load_kek(SERVICE, false), Err(Error::Provider(_))));
            assert!(matches!(tpm.load_kek(SERVICE, true), Err(Error::Provider(_))), "provisioning never replaces a lost authValue");
            // Nor can it be retired -- and the error says what can be done.
            match tpm.retire_kek(SERVICE, &right) {
                Err(Error::Provider(msg)) => assert!(msg.contains("by hand"), "{msg}"),
                other => panic!("expected an error, got {other:?}"),
            }
            assert!(key_path.exists(), "nothing deleted");
            std::fs::write(&auth_path, &saved).unwrap();
            std::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o400)).unwrap();
            assert_eq!(fingerprint(&*tpm.load_kek(SERVICE, false).unwrap()), right, "restored from backup, it works again");

            tpm.retire_kek(SERVICE, &right).unwrap();
            assert!(!key_path.exists() && !auth_path.exists(), "retiring deletes both");

            // An authValue file left with no key file -- a retire that
            // couldn't delete it, a key file deleted by hand, or a key file
            // that is only missing for now -- is never replaced, and never
            // what the next key is created with: provisioning is refused
            // until an administrator deletes it.
            std::fs::write(&auth_path, &saved).unwrap();
            std::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o400)).unwrap();
            match tpm.load_kek(SERVICE, true) {
                Err(Error::Provider(msg)) => assert!(msg.contains("never replaces an authValue file"), "{msg}"),
                other => panic!("expected a refusal, got {:?}", other.map(|_| ())),
            }
            assert_eq!(std::fs::read(&auth_path).unwrap(), saved, "the orphan is untouched");
            assert!(!key_path.exists(), "and no key file was written");
            assert!(!tpm.kek_exists(SERVICE).unwrap(), "still not provisioned");
            std::fs::remove_file(&auth_path).unwrap();
            let again = fingerprint(&*tpm.load_kek(SERVICE, true).unwrap());
            assert_ne!(again, right, "a new key");
            assert_ne!(std::fs::read(&auth_path).unwrap(), saved, "under a new authValue");
            prf_output(SERVICE, false, b"input").unwrap();
            tpm.retire_kek(SERVICE, &again).unwrap();
        });
    }

    // ---- operator helpers: obtain the Names to pin in policy ----
    //
    // Not assertions. Run with `-- --ignored --exact --nocapture` to print
    // the Name the *real* TPM reports, for `tpm.pinned_session_salt_key_name`
    // and `tpm.pinned_names`. `scripts/native-tpm-test.sh` drives these.

    #[test]
    #[ignore = "operator helper (prints the storage root key's Name to pin); requires a TPM2 device"]
    #[serial]
    fn print_session_salt_key_name_for_pinning() {
        println!("SALT_KEY_NAME={}", hex(&srk_name()));
    }

    #[test]
    #[ignore = "operator helper (prints a provisioned service key's Name to pin); requires a TPM2 device"]
    #[serial]
    fn print_service_key_name_for_pinning() {
        // Which service, via env -- there is no other way to pass a value
        // to a test. Normalized exactly as the C ABI would normalize it.
        // Read from its key file in the policy's key directory, which
        // `provision` must already have created.
        let service = std::env::var("HKDFGUARD_PIN_SERVICE").unwrap_or_else(|_| SERVICE.to_string());
        let service = crate::normalize_service(&service);
        let file = read_key_file(&service)
            .expect("the key file can't be read")
            .expect("no key file for this service: run `hkdfguard provision` first");
        println!("SERVICE={service}");
        println!("SERVICE_KEY_NAME={}", hex(&computed_name(&file.public).unwrap()));
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn require_pinned_names_makes_provisioning_a_real_gate() {
        with_key_dir(|_| {
            let service = "com.company.allowlisted";
            let allowlist_only = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_pinned_names = true\n";

            // Unpinned: provisioning creates the key file but is refused with
            // the exact Name to pin, and the service doesn't exist yet.
            let message = with_policy(allowlist_only, || {
                let tpm = provider();
                let message = match tpm.load_kek(service, true) {
                    Err(Error::Provider(msg)) => msg,
                    Err(other) => panic!("expected Provider error with pinning instructions, got {other:?}"),
                    Ok(_) => panic!("creating an unpinned service must be refused"),
                };
                assert!(!tpm.kek_exists(service).unwrap(), "an unpinned service must not exist");
                assert!(matches!(tpm.load_kek(service, false), Err(Error::KeyNotProvisioned(_))));
                message
            });
            let file = read_key_file(service).unwrap().expect("the key file was created");
            let actual = hex(&computed_name(&file.public).unwrap());
            assert!(
                message.contains(&format!("\"{service}\" = \"{actual}\"")),
                "the refusal must carry a paste-ready pin of the key file's real Name; got: {message}"
            );

            // Pinned (as the operator would, from that message): now it exists,
            // loads, and works end to end.
            let pinned = format!("{allowlist_only}[tpm.pinned_names]\n\"{service}\" = \"{actual}\"\n");
            with_policy(&pinned, || {
                let tpm = provider();
                assert!(tpm.kek_exists(service).unwrap(), "a pinned service must exist");
                tpm.load_kek(service, true).unwrap();
                assert_ne!(*tpm.load_kek(service, false).unwrap().prf(&[b"input"]).unwrap()[0], [0u8; 32]);
                assert!(!tpm.kek_exists("com.company.notpinned").unwrap(), "other services are still refused");
            });
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn a_correctly_pinned_name_is_accepted_and_a_wrong_one_is_rejected() {
        with_key_dir(|_| {
            provider().load_kek(SERVICE, true).unwrap();
            let actual = computed_name(&read_key_file(SERVICE).unwrap().unwrap().public).unwrap();
            let pin = |name: &[u8]| format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\n\"{SERVICE}\" = \"{}\"\n", hex(name));

            with_policy(&pin(&actual), || prf_output(SERVICE, false, b"input")).expect("a correctly pinned Name must be accepted");

            // Pinned to anything else: refused, and refused before the key
            // is ever used for HMAC.
            let mut wrong = actual.clone();
            wrong[2] ^= 0xff; // corrupt the digest, keeping the alg prefix valid
            assert!(with_policy(&pin(&wrong), || prf_output(SERVICE, false, b"input")).is_err());
        });
    }
}

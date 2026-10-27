//! Provider 1: TPM2 (preferred provider).
//!
//! ```text
//!  ______________________________________________________________________
//! | HARDWARE-DEPENDENT CODE                                                |
//! |                                                                        |
//! | Verified: built and linked against real `libtss2-esys` 4.0.1 on       |
//! | Ubuntu 24.04, with the `#[ignore]`d conformance suite passing against |
//! | swtpm (docker/run-tests.sh) and against a real firmware TPM -- Intel  |
//! | PTT (scripts/native-tpm-test.sh). Not yet exercised against a        |
//! | discrete TPM chip (e.g. Infineon, Nuvoton). Re-run both after any    |
//! | change here.                                                          |
//! |______________________________________________________________________|
//! ```
//!
//! ## Design
//!
//! Each service's KEK is an ordinary TPM key: an unrestricted ECC P-256
//! decryption key created by `TPM2_Create` under the Owner hierarchy's
//! storage root key (SRK), and stored as a **key file**,
//! `<tpm.key_dir>/<service>.tpmkey` (default `/var/lib/hkdfguard/tpm`).
//! Every ECDH re-derives the SRK with `TPM2_CreatePrimary` from the
//! standard TCG template, loads the key file under it with `TPM2_Load`,
//! runs `TPM2_ECDH_ZGen`, and flushes both: nothing stays resident in the
//! TPM, and no persistent handle has to be allocated, authorized, mapped
//! to a service or kept from colliding.
//!
//! What the TPM itself guarantees about a key file:
//!
//! - **Its private key never leaves this TPM.** The file's private area is
//!   encrypted and integrity-protected under the SRK, whose seed is
//!   generated inside the TPM and never exported. The file is useless on
//!   any other TPM, and `TPM2_Load` refuses a file whose two halves don't
//!   belong together.
//! - **The TPM generated it.** Every key file is checked to carry
//!   `fixedTPM`, `fixedParent` and `sensitiveDataOrigin` (see
//!   [`verify_matches_template`]). The TPM refuses to import an object with
//!   `fixedTPM` set, so such a key can only have been created inside this
//!   TPM and never duplicated out: a key file can't hold a private key
//!   anyone knows.
//!
//! What it does not guarantee: the key has no password, so anyone who can
//! read the key file *and* open the TPM can use the key. Reading the file
//! is the access control, as the PKCS#11 PIN file is for that provider --
//! hence its mode (`root:<key-users> 0440`, see [`write_key_file`]). And a
//! `TPM2_Clear` replaces the Owner hierarchy's seed: the SRK changes, and
//! every key file becomes permanently unloadable.
//!
//! Provisioning is real: `load_kek(service, true)` creates the key file if
//! there is none, and a service with no key file has no KEK here
//! ([`Error::KeyNotProvisioned`]), so the provider chain moves on.
//! `retire_kek` deletes the file.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::tpm_key_file::{self, KeyBlob}; // the key file's on-disk format
use crate::provider::{Backend, KekHandle, KekProvider, ProviderType, SharedSecret}; // traits/types this module implements
use crate::secure_file::{FileIdentity, Owner};
use elliptic_curve::sec1::ToSec1Point; // lets us split the payload's point into X/Y coordinates
use p256::PublicKey; // the P-256 point type `ecdh` takes
use sha2::{Digest as ShaDigest, Sha256}; // the payload's key_id tag and TPM Names (aliased to avoid clashing with tss-esapi's own `Digest`)
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf}; // the key directory and key files
use std::str::FromStr; // brings `TctiNameConf::from_str` into scope
use std::sync::{Arc, Mutex, OnceLock}; // shared, lock-protected TPM context; `OnceLock` for the per-process conformance verdict

use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder}; // TPM object-attribute and session-attribute bitfields
use tss_esapi::constants::{PropertyTag, SessionType}; // TPM_PT_MANUFACTURER lookup, and the HMAC session type
use tss_esapi::handles::{KeyHandle, ObjectHandle, SessionHandle}; // opaque TPM-side handles to a loaded key / a started session
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm}; // enum constants for "SHA-256" and "ECC"
use tss_esapi::interface_types::ecc::EccCurve; // enum constant for "NIST P-256"
use tss_esapi::interface_types::resource_handles::Hierarchy; // selects the Owner hierarchy for CreatePrimary
use tss_esapi::interface_types::session_handles::AuthSession; // a started session, as passed to execute_with_session
use tss_esapi::structures::{
    EccParameter, EccPoint, EccScheme, KeyDerivationFunctionScheme, Name, Private, Public, PublicBuilder,
    PublicEccParametersBuilder, SymmetricDefinition, SymmetricDefinitionObject,
}; // the TPM public-template types this module builds, the TPM Name value, the key file's private area, and the session cipher
use tss_esapi::traits::{Marshall, UnMarshall}; // TPMT_PUBLIC to and from its wire bytes
use tss_esapi::{Context, TctiNameConf}; // the ESAPI connection handle and its configuration type

// ---------------------------------------------------------------------
// Key files.
// ---------------------------------------------------------------------

/// Where key files live when the policy names no `tpm.key_dir`.
const DEFAULT_KEY_DIR: &str = "/var/lib/hkdfguard/tpm";

/// A key file's name is the service name plus this. Service names never
/// start with '.', so the hidden temporary files [`write_key_file`] makes
/// can never be mistaken for one.
const KEY_FILE_SUFFIX: &str = ".tpmkey";

/// `tpm.key_dir` from policy, else [`DEFAULT_KEY_DIR`]. `Err` on a policy
/// that exists but can't be trusted.
fn key_dir() -> Result<PathBuf> {
    Ok(crate::policy::tpm_key_dir()?.unwrap_or_else(|| PathBuf::from(DEFAULT_KEY_DIR)))
}

fn key_file_path(dir: &Path, service: &str) -> PathBuf {
    dir.join(format!("{service}{KEY_FILE_SUFFIX}"))
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
    use crate::secure_file::{check_location, open_checked, FileRequirements, FORBID_GROUP_OTHER_ACCESS};
    use std::io::Read;

    let path = key_file_path(&key_dir()?, service);
    let owner = key_owner()?;
    let requirements = FileRequirements {
        owner: Some(owner),
        forbidden_mode_bits: FORBID_GROUP_OTHER_ACCESS,
        follow_symlinks: false,
        allow_group_read_if_root_owned: true, // root:<key-users> 0440, for a service that doesn't run as root
    };
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
    verify_matches_template(&service_key_template()?, &public)
        .map_err(|e| fail(format!("is not a key this library creates: {e}")))?;
    encode_tpm_public_key(&public).map_err(|e| fail(format!("holds no valid public key: {e}")))?;
    let private = Private::try_from(blob.private).map_err(|e| fail(format!("holds an unreadable private area: {e}")))?;
    Ok(Some(KeyFile { public, private, identity }))
}

/// Writes `service`'s new key file, unless one appeared first.
///
/// The key directory must already exist, set up by an administrator: its
/// group decides who may read the keys. A key file written by root takes
/// the directory's group, mode `0440`, so with the directory
/// `root:<key-users>` every service in that group can use the keys; one
/// written by another user (the developer model) is `0400`, since a
/// group-readable key file its own user owns is refused (see
/// [`read_key_file`]).
///
/// The file is written to a hidden temporary name, synced, then
/// hard-linked to its real name, which fails if that name exists: two
/// processes provisioning the same service at once can't overwrite each
/// other's key, and a crash never leaves a partial key file under the real
/// name. The loser's key is discarded unused and everyone uses the
/// winner's -- so the caller re-reads the file rather than trusting
/// `blob`.
fn write_key_file(service: &str, blob: &KeyBlob) -> Result<()> {
    use std::io::Write;

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
    let dir_gid = std::fs::metadata(&dir)
        .map_err(|e| Error::Provider(format!("TPM key directory {}: {e}", dir.display())))?
        .gid();
    let pem = tpm_key_file::encode(blob).map_err(|e| Error::Provider(format!("could not encode the TPM key file: {e}")))?;

    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|_| Error::Crypto("the OS random number generator failed"))?;
    let temp = dir.join(format!(".{service}{KEY_FILE_SUFFIX}.{:016x}", u64::from_ne_bytes(nonce)));
    let target = key_file_path(&dir, service);
    let fail = |what: &str, e: std::io::Error| Error::Provider(format!("could not {what} TPM key file {}: {e}", target.display()));

    // SAFETY: geteuid has no preconditions.
    let as_root = unsafe { libc::geteuid() } == 0;
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL: never through an existing file or symlink
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        if as_root {
            std::os::unix::fs::fchown(&file, None, Some(dir_gid))?;
            file.set_permissions(std::fs::Permissions::from_mode(0o440))?;
        }
        file.write_all(pem.as_bytes())?;
        file.sync_all()
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(fail("write", e));
    }
    let linked = std::fs::hard_link(&temp, &target);
    let _ = std::fs::remove_file(&temp);
    match linked {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            log::info!("hkdfguard: another process provisioned the TPM key for this service first; using its key");
        }
        Err(e) => return Err(fail("create", e)),
    }
    sync_dir(&dir).map_err(|e| fail("persist", e))
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

/// Reads the Owner-hierarchy authorization value from `path`
/// (`tpm.owner_auth_file`). Held to the same standard as the policy file's
/// other secrets -- root-owned, `0400` or `root:<service-group> 0440`, not
/// a symlink, in a root-controlled directory -- and used verbatim: no
/// trimming, so it matches exactly what `tpm2_changeauth -c o file:<path>`
/// set. Every failure, a missing file included, is an error: the policy
/// says the owner has this password, so trying with none would fail anyway
/// and hide why.
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
// TPM was reachable at construction time (this provider is then simply
// unavailable).
pub struct Tpm2Provider {
    // A TPM ESYS context is not safe to drive concurrently; serialize
    // access to the (typically low-throughput, one DEK-wrap-at-a-time) TPM
    // channel behind a mutex. Shared (via Arc) with every handle so the
    // actual Load+ECDH_ZGen round trip can happen lazily in
    // `KekHandle::ecdh`, once the payload's point is known.
    context: Arc<Mutex<Option<Context>>>,
    // Set when a TPM is there but can't be trusted or used (see
    // `crate::provider::Backend::Refused`); every call then fails with it.
    refused: Option<String>,
}

impl Tpm2Provider {
    pub fn new() -> Self {
        // try to connect once, at construction time
        let (context, refused) = match open_context() {
            Backend::Ready(ctx) => (Some(ctx), None),
            Backend::Absent => (None, None),
            Backend::Refused(reason) => {
                crate::provider::log_once(log::Level::Error, format!("hkdfguard: TPM refused: {reason}"));
                (None, Some(reason))
            }
        };
        Tpm2Provider { context: Arc::new(Mutex::new(context)), refused }
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
                 responses (including ECDH shared secrets), session keys and plaintext parameters to \
                 its log; unset TSS2_LOG or lower it to info or below"
                    .to_string(),
            );
        }
    }

    let tcti = match resolve_tcti() {
        Ok(tcti) => tcti,
        Err(e) => return Backend::Refused(e.to_string()),
    };
    let mut ctx = match Context::new(tcti) {
        Ok(ctx) => ctx,
        // The default device failing to open is the normal state of a host
        // with no TPM, or one this service isn't meant to use (not in the
        // `tss` group). A TCTI someone configured on purpose is different:
        // its TPM is meant to be used, so failing to reach it is an outage.
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
    // so the password authorizes without ever crossing the bus. It is not
    // an input to the SRK's derivation, so setting it changes no KEK.
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
    // credential, so it's established once per process rather than on
    // every connection -- providers are constructed (and this runs) per
    // call. Only a definitive verdict is cached; a self-test that couldn't
    // run at all (TPM busy, command error) refuses the TPM for *this* call
    // only and is retried next time.
    let compatible = match TPM_CONFORMANCE_VERDICT.get() {
        Some(verdict) => *verdict,
        None => match validate_tpm_compatibility(&mut ctx) {
            Ok(verdict) => *TPM_CONFORMANCE_VERDICT.get_or_init(|| verdict), // first definitive verdict wins; a concurrent one agrees
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
/// and response bytes -- `TPM2_ECDH_ZGen`'s response is the shared secret
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

/// Once-per-process result of `validate_tpm_compatibility`: `true` if the
/// TPM this process talks to behaves as hkdfguard requires, `false` if it
/// definitively doesn't. Unset until a self-test has actually completed.
static TPM_CONFORMANCE_VERDICT: OnceLock<bool> = OnceLock::new();

/// Empirically validates, against the real TPM this process just
/// connected to, the one behavior the key files depend on: the SRK must be
/// reproducible. `TPM2_CreatePrimary` from the same template must return
/// the same key every time, or a key file created under one SRK could
/// never be loaded under the next. Called once, at connection time (see
/// `open_context`) -- refusing a TPM that can't honor this up front beats
/// creating key files that turn out to be unloadable.
///
/// Returns `Ok(true)` if the TPM is compatible, `Ok(false)` if it
/// definitively is not (a verdict `open_context` caches for the process),
/// and `Err` only if the self-test itself couldn't be carried out -- a
/// command failure, which says nothing about the TPM's determinism and so
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
    Ok(true)
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
    let Public::Ecc {
        name_hashing_algorithm,
        ..
    } = public
    else {
        return Err(Error::Provider(
            "TPM key is not an ECC public key".into(), // defensive: our own templates always request ECC
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
/// KDF, symmetric) as `template`. Only `unique` -- the public point -- may
/// differ.
///
/// For a service key this is what proves a key file holds a key the TPM
/// generated and will never export (`fixedTPM`, `fixedParent`,
/// `sensitiveDataOrigin`; see the module doc), and that it has no auth
/// policy that could let it be used some other way. For the SRK it proves
/// the TPM returned the standard storage key, not some other object.
fn verify_matches_template(template: &Public, returned: &Public) -> Result<()> {
    match (template, returned) {
        (
            Public::Ecc { object_attributes: ta, name_hashing_algorithm: tn, auth_policy: tp, parameters: tparams, .. },
            Public::Ecc { object_attributes: ra, name_hashing_algorithm: rn, auth_policy: rp, parameters: rparams, .. },
        ) => {
            let mut differs = Vec::new();
            if ta != ra {
                differs.push("object attributes");
            }
            if tn != rn {
                differs.push("name algorithm");
            }
            if tp != rp {
                differs.push("auth policy");
            }
            if tparams != rparams {
                differs.push("ECC parameters");
            }
            if differs.is_empty() {
                Ok(())
            } else {
                Err(Error::Provider(format!(
                    "the key does not match the expected template ({} differ)",
                    differs.join(", ")
                )))
            }
        }
        _ => Err(Error::Provider("the key is not an ECC key".into())),
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
/// public template.
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

/// A service key's template: an unrestricted ECC P-256 decryption key
/// (required for `TPM2_ECDH_ZGen`), non-signing, generated by the TPM
/// (`sensitiveDataOrigin`) and fixed to this TPM and this parent, so never
/// duplicable or exportable. No auth policy and an empty password: reading
/// the key file is the access control (see the module doc). `noDA`, since
/// an empty password can't be guessed and its use must never count toward
/// the TPM's dictionary-attack lockout.
fn service_key_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true) // key can never be moved to a different TPM
        .with_fixed_parent(true) // key can never be re-parented/duplicated
        .with_sensitive_data_origin(true) // the private part is generated by the TPM itself
        .with_user_with_auth(true) // standard "USER role" authorization (the empty password) is sufficient to use the key
        .with_no_da(true)
        .with_decrypt(true) // required: a decryption-family key (ECDH)
        .with_sign_encrypt(false) // this key must not be usable for signing
        .with_restricted(false)
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM object attributes: {e}")))?;
    let ecc_params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null) // no fixed signing/KDF scheme baked into the key itself
        .with_curve(EccCurve::NistP256) // the mandated curve
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null) // no on-TPM KDF; this crate does its own HKDF afterward
        .with_is_decryption_key(true) // mirrors the object attribute above, for the builder's own consistency checks
        .with_is_signing_key(false)
        .with_restricted(false)
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM ECC parameters: {e}")))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default()) // ignored by TPM2_Create: the TPM fills in the generated point
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
fn create_srk_unpinned(ctx: &mut Context) -> Result<(KeyHandle, Public, Name)> {
    let template = srk_template()?;
    let handle = ctx
        .execute_with_nullauth_session(|ctx| ctx.create_primary(Hierarchy::Owner, template.clone(), None, None, None, None))
        .map_err(|e| {
            note_owner_auth_failure(&e);
            Error::Provider(format!("TPM2_CreatePrimary (storage root key) failed: {e}"))
        })?
        .key_handle;
    let (public, name, _qualified_name) = match ctx.read_public(handle) {
        Ok(v) => v,
        Err(e) => {
            let _ = ctx.flush_context(handle.into());
            return Err(Error::Provider(format!("TPM2_ReadPublic (storage root key) failed: {e}")));
        }
    };
    let checked = verify_matches_template(&template, &public).and_then(|()| {
        let expected = computed_name(&public)?;
        if name.value() == expected.as_slice() {
            Ok(())
        } else {
            Err(Error::Provider(format!(
                "storage root key Name mismatch: TPM reported {} for a public area whose Name is {}",
                hex(name.value()),
                hex(&expected)
            )))
        }
    });
    if let Err(e) = checked {
        let _ = ctx.flush_context(handle.into());
        return Err(e);
    }
    Ok((handle, public, name))
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

/// Creates a new service key under the SRK. Returns it as a key file's
/// contents; nothing stays loaded.
fn create_service_key(ctx: &mut Context) -> Result<KeyBlob> {
    let template = service_key_template()?;
    let srk = create_srk(ctx)?;
    let created = ctx.execute_with_nullauth_session(|ctx| ctx.create(srk, template.clone(), None, None, None, None));
    let _ = ctx.flush_context(srk.into());
    let created = created.map_err(|e| Error::Provider(format!("TPM2_Create (service key) failed: {e}")))?;
    verify_matches_template(&template, &created.out_public)?;
    encode_tpm_public_key(&created.out_public)?;
    Ok(KeyBlob {
        public: created
            .out_public
            .marshall()
            .map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))?,
        private: created.out_private.value().to_vec(),
    })
}

/// Loads a key file's key under `srk` and verifies the Name the TPM
/// reports for it (see [`verify_name`]). Returns the loaded handle; the
/// caller flushes it.
fn load_service_key(ctx: &mut Context, srk: KeyHandle, service: &str, public: &Public, private: &Private) -> Result<KeyHandle> {
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
        .and_then(|name| verify_name(service, public, &name));
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
// A discrete TPM sits on an LPC or SPI bus that an interposer can read
// byte-for-byte. `TPM2_ECDH_ZGen`'s response is the shared point Z for
// one payload; a captured response opens that payload (the per-payload
// hashed point in crypto.rs keeps it from opening any other), and an
// interposer that stays on the bus captures every subsequent one. A
// firmware TPM (Intel PTT, AMD fTPM) or a virtual TPM has
// no external bus, so this is pure overhead there -- hence the `auto`
// policy mode, which skips it only for known-internal manufacturers.
// That decision rests on `TPM_PT_MANUFACTURER`, read over the very bus in
// question, so an active interposer can forge it: `auto` defeats passive
// sniffing only. Once the SRK is pinned, `auto` stops asking and always
// encrypts (see `session_encryption_enabled`).
//
// The mechanism is the TPM 2.0 specification's own (Part 1 §19.6): an
// HMAC session started with `tpmKey` set to a TPM-resident decrypt key --
// here the SRK, already loaded to be the key file's parent -- so the
// session salt is encrypted to that key (one-pass ECDH) and the session
// key derived from it is never on the bus in cleartext; with
// `TPMA_SESSION.encrypt` set, the first response parameter -- here
// `outPoint`, i.e. Z -- is AES-128-CFB encrypted under a key derived from
// the session key. The cryptography lives in tpm2-tss's ESAPI layer,
// which tss-esapi wraps; this module only configures the session.
//
// Three things are load-bearing. An *unsalted* session's key derives
// from the two nonces, both visible on the bus, so the interposer computes
// it too -- salting is the entire defense, not an option. The SRK is
// *restricted*: the TPM uses its private half only for its children and
// inside `TPM2_StartAuthSession`, so nobody -- not even a process that can
// send the TPM commands and recreate the SRK from its public template --
// can run ECDH with it to recover a session's salt. And the SRK's public
// half is itself learned over the bus at `TPM2_ReadPublic`, so an
// interposer can substitute its own and man-in-the-middle the session;
// that is what `tpm.pinned_session_salt_key_name` defeats, and why
// `required` mode refuses to run without a pin.
//
// Nothing secret crosses the bus outside the session: `TPM2_Load` sends
// the key file's private area, which is encrypted under the SRK, and the
// key has no password to send.

/// `TPM_PT_MANUFACTURER` identifiers of TPMs that live inside the SoC or
/// a hypervisor and so have no external bus to probe. Anything not listed
/// is treated as discrete and encrypted: `auto` only ever *skips*
/// encryption for a TPM positively known to be internal.
///
/// The property is four ASCII bytes packed big-endian; vendors shorter
/// than four characters pad with a space *or* a NUL depending on the
/// implementation (libtpms/swtpm reports `"IBM\0"`), so comparison is on
/// the identifier with trailing padding stripped.
const NO_EXTERNAL_BUS_MANUFACTURERS: &[&[u8]] = &[
    b"INTC", // Intel PTT (fTPM inside the CSME)
    b"AMD",  // AMD fTPM (inside the PSP)
    b"QCOM", // Qualcomm fTPM
    b"MSFT", // Hyper-V vTPM
    b"IBM",  // IBM software TPM, i.e. swtpm / libtpms
    b"GOOG", // Google Cloud vTPM
    b"VMW",  // VMware vTPM
];

/// The manufacturer identifier with trailing space/NUL padding removed.
fn manufacturer_id_bytes(id: u32) -> Vec<u8> {
    let bytes = id.to_be_bytes();
    let end = bytes
        .iter()
        .rposition(|b| *b != b' ' && *b != 0)
        .map_or(0, |i| i + 1);
    bytes[..end].to_vec()
}

fn manufacturer_has_no_external_bus(id: u32) -> bool {
    let trimmed = manufacturer_id_bytes(id);
    NO_EXTERNAL_BUS_MANUFACTURERS.contains(&trimmed.as_slice())
}

/// Once-per-process `auto`-mode verdict: does this TPM lack an external
/// bus? A fact about the hardware, so cached like the conformance
/// verdict. Only consulted under `auto`; `required`/`off` are policy and
/// are re-read on every call like everything else.
static TPM_NO_EXTERNAL_BUS: OnceLock<bool> = OnceLock::new();

/// Logged once: `auto` chose to encrypt but the SRK isn't pinned.
static UNPINNED_SALT_KEY_WARNED: OnceLock<()> = OnceLock::new();

/// Whether `TPM2_ECDH_ZGen` should run inside an encrypted session on
/// this call, per `tpm.session_encryption`.
fn session_encryption_enabled(ctx: &mut Context) -> Result<bool> {
    use crate::policy::SessionEncryption;
    match crate::policy::tpm_session_encryption() {
        SessionEncryption::Required => Ok(true),
        SessionEncryption::Off => Ok(false),
        SessionEncryption::Auto => {
            // A pinned SRK is the operator's statement that this TPM may
            // have a bus worth defending, and it is what makes the
            // encryption hold against an active interposer. Don't let a
            // manufacturer string read over that same bus -- which such an
            // interposer can rewrite to "INTC" -- switch it back off.
            if crate::policy::pinned_session_salt_key_name()?.is_some() {
                return Ok(true);
            }
            if let Some(internal) = TPM_NO_EXTERNAL_BUS.get() {
                return Ok(!internal);
            }
            let internal = match ctx.get_tpm_property(PropertyTag::Manufacturer) {
                Ok(Some(id)) if manufacturer_has_no_external_bus(id) => {
                    log::info!(
                        "hkdfguard: TPM manufacturer {:?} has no external bus; session encryption skipped (tpm.session_encryption = \"auto\")",
                        String::from_utf8_lossy(&id.to_be_bytes())
                    );
                    true
                }
                Ok(Some(id)) => {
                    log::info!(
                        "hkdfguard: TPM manufacturer {:?} treated as discrete; ECDH runs in a salted, parameter-encrypted session",
                        String::from_utf8_lossy(&id.to_be_bytes())
                    );
                    false
                }
                Ok(None) => {
                    log::warn!("hkdfguard: TPM did not report a manufacturer; assuming discrete and encrypting sessions");
                    false
                }
                Err(e) => {
                    return Err(Error::Provider(format!("TPM2_GetCapability(manufacturer) failed: {e}")));
                }
            };
            Ok(!*TPM_NO_EXTERNAL_BUS.get_or_init(|| internal))
        }
    }
}

/// Starts a salted HMAC session, salted to `srk`, with response and
/// command parameter encryption (AES-128-CFB). The caller flushes it.
fn start_encrypted_session(ctx: &mut Context, srk: KeyHandle) -> Result<AuthSession> {
    if crate::policy::pinned_session_salt_key_name()?.is_none() {
        UNPINNED_SALT_KEY_WARNED.get_or_init(|| {
            log::warn!(
                "hkdfguard: encrypting TPM sessions with an unpinned storage root key; this defeats passive bus sniffing \
                 but not an active interposer -- set tpm.pinned_session_salt_key_name to close that"
            );
        });
    }
    let session = ctx
        .start_auth_session(
            Some(srk), // salted: the session key depends on a secret only this TPM can unwrap
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| Error::Provider(format!("TPM2_StartAuthSession failed: {e}")))?
        .ok_or_else(|| Error::Provider("TPM2_StartAuthSession returned no session".into()))?;

    let (attributes, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true) // encrypt the command's first parameter (inPoint)
        .with_encrypt(true) // encrypt the response's first parameter (outPoint, i.e. Z)
        .with_continue_session(true)
        .build();
    if let Err(e) = ctx.tr_sess_set_attributes(session, attributes, mask) {
        let _ = ctx.flush_context(SessionHandle::from(session).into());
        return Err(Error::Provider(format!("failed to set TPM session attributes: {e}")));
    }
    // Read the attributes back and refuse a session that won't encrypt.
    // Encryption is invisible to the caller -- an unencrypted session
    // returns the very same Z -- so nothing downstream would notice a
    // stack that accepted the attributes and then dropped them, and Z
    // would cross the bus in the clear. A local ESAPI call: no TPM round
    // trip.
    let encrypts = ctx.tr_sess_get_attributes(session).map(|a| a.decrypt() && a.encrypt());
    match encrypts {
        Ok(true) => Ok(session),
        Ok(false) => {
            let _ = ctx.flush_context(SessionHandle::from(session).into());
            Err(Error::Provider(
                "the TPM session did not keep its decrypt/encrypt attributes; refusing to send Z through it unencrypted"
                    .into(),
            ))
        }
        Err(e) => {
            let _ = ctx.flush_context(SessionHandle::from(session).into());
            Err(Error::Provider(format!("failed to read back TPM session attributes: {e}")))
        }
    }
}

/// `TPM2_ECDH_ZGen` with `key`, inside a session salted to `srk` with
/// parameter encryption. Owns the session's lifecycle: it is flushed on
/// every path, so no session slot (TPMs have very few) can leak.
fn ecdh_z_gen_encrypted(ctx: &mut Context, srk: KeyHandle, key: KeyHandle, peer_point: &EccPoint) -> Result<EccPoint> {
    let session = start_encrypted_session(ctx, srk)?;
    let z = ctx
        .execute_with_session(Some(session), |ctx| ctx.ecdh_z_gen(key, peer_point.clone()))
        .map_err(|e| Error::Provider(format!("TPM2_ECDH_ZGen (encrypted session) failed: {e}")));
    let _ = ctx.flush_context(SessionHandle::from(session).into());
    z
}

// ---------------------------------------------------------------------
// Handles.
// ---------------------------------------------------------------------

// Handle type returned from `load_kek`. Holds the key file as it was read
// once in `load_kek`, so `public_key` and `ecdh` within one wrap/unwrap
// use the same key even if the file is replaced in between; the key is
// loaded into the TPM only inside `ecdh`, and flushed before it returns.
struct Tpm2Handle {
    key_id: Vec<u8>,                      // diagnostic-only tag embedded in the wrapped payload
    service: String,                      // the service name, for its policy pin
    public: Public,                       // the key file's public area
    private: Private,                     // the key file's private area, encrypted under the SRK
    context: Arc<Mutex<Option<Context>>>, // shared handle back to the TPM connection
}

impl KekHandle for Tpm2Handle {
    fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    fn ecdh(&self, point: &PublicKey) -> Result<SharedSecret> {
        let peer_point = encode_peer_point(point)?; // the payload's point, TPM-encoded
        let z = with_context(&self.context, |ctx| {
            let srk = create_srk(ctx)?;
            // Loads the key and verifies its Name (and any policy-pinned
            // Name) *before* it is used for ECDH -- so a key that isn't
            // the one policy expects never computes a shared secret at all.
            let key = match load_service_key(ctx, srk, &self.service, &self.public, &self.private) {
                Ok(key) => key,
                Err(e) => {
                    let _ = ctx.flush_context(srk.into());
                    return Err(e);
                }
            };
            // TPM2_ECDH_ZGen: computes the shared point Z inside the TPM.
            // Under an encrypted session its response -- Z itself -- is
            // AES-CFB encrypted before it crosses the bus; see
            // `ecdh_z_gen_encrypted`.
            let z = match session_encryption_enabled(ctx) {
                Err(e) => Err(e),
                Ok(true) => ecdh_z_gen_encrypted(ctx, srk, key, &peer_point),
                Ok(false) => ctx
                    .execute_with_nullauth_session(|ctx| ctx.ecdh_z_gen(key, peer_point.clone()))
                    .map_err(|e| Error::Provider(format!("TPM2_ECDH_ZGen failed: {e}"))),
            };
            // Always flush both, even on ECDH failure, so no transient
            // object slot leaks.
            let _ = ctx.flush_context(key.into());
            let _ = ctx.flush_context(srk.into());
            z
        })?;

        let x_bytes = z.x().value(); // the shared secret is conventionally just the X-coordinate of Z
        if x_bytes.len() != 32 {
            return Err(Error::Provider(
                "TPM returned unexpected ECDH shared point size".into(), // defensive: should always be 32 for P-256
            ));
        }
        let mut secret = SharedSecret::new([0u8; 32]); // zeroizing from the start: no un-wiped intermediate copy on the stack
        secret.copy_from_slice(x_bytes);
        Ok(secret)
    }

    // Straight from the key file's public area: no TPM round trip. `ecdh`
    // loads the same public area, and `TPM2_Load` refuses it unless the
    // private area belongs to it, so this is the key `ecdh` uses.
    fn public_key(&self) -> Result<PublicKey> {
        encode_tpm_public_key(&self.public)
    }
}

// Converts the ECC public point in a key's public area into a
// `p256::PublicKey`.
fn encode_tpm_public_key(public: &Public) -> Result<PublicKey> {
    let Public::Ecc { unique, .. } = public else {
        return Err(Error::Provider(
            "TPM key is not an ECC public key".into(), // defensive: our own template always requests ECC
        ));
    };

    let x = unique.x().value();
    let y = unique.y().value();
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::Provider(
            "TPM key has an unexpected ECC public key coordinate size".into(), // should always be 32 for P-256
        ));
    }

    let mut point = [0u8; 65]; // uncompressed SEC1 point: 0x04 || X || Y
    point[0] = 0x04;
    point[1..33].copy_from_slice(x);
    point[33..65].copy_from_slice(y);

    PublicKey::from_sec1_bytes(&point)
        .map_err(|_| Error::Provider("TPM key holds an invalid ECC public key".into()))
}

impl KekProvider for Tpm2Provider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Tpm2
    }

    fn probe(&self) -> bool {
        self.refused.is_some() || self.connected()
    }

    // A service has a KEK here when it has a usable key file -- and, under
    // `tpm.require_pinned_names`, a pinned Name. Side-effect free: nothing
    // is sent to the TPM.
    fn kek_exists(&self, service: &str) -> Result<bool> {
        self.check_not_refused()?;
        if !self.connected() {
            return Ok(false);
        }
        match read_key_file(service)? {
            Some(file) => pin_allows(service, &file.public),
            None => Ok(false),
        }
    }

    fn load_kek(&self, service: &str, create_if_missing: bool) -> Result<Box<dyn KekHandle>> {
        self.check_not_refused()?;
        if !self.connected() {
            return Err(Error::Provider("TPM context not available".into()));
        }
        let file = match read_key_file(service)? {
            Some(file) => file,
            None if !create_if_missing => return Err(Error::KeyNotProvisioned("no TPM key file for this service")),
            None => {
                let blob = with_context(&self.context, create_service_key)?;
                write_key_file(service, &blob)?;
                // Re-read rather than trusting `blob`: a concurrent
                // provisioning may have won, and the file on disk is the
                // key every later call uses.
                read_key_file(service)?
                    .ok_or_else(|| Error::Provider("the TPM key file vanished right after it was written".into()))?
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
            // loads on *this* TPM first.
            with_context(&self.context, |ctx| {
                let srk = create_srk(ctx)?;
                let key = load_service_key(ctx, srk, service, &file.public, &file.private);
                if let Ok(key) = &key {
                    let _ = ctx.flush_context((*key).into());
                }
                let _ = ctx.flush_context(srk.into());
                key.map(|_| ())
            })?;
        }
        Ok(Box::new(Tpm2Handle {
            key_id: service_fingerprint(service),
            service: service.to_string(),
            public: file.public,
            private: file.private,
            context: Arc::clone(&self.context), // clone the Arc (cheap: just bumps a refcount), not the underlying context
        }))
    }

    // Deletes the key file, once its key is confirmed to have
    // `expected_fingerprint` and the file is confirmed to be the one read.
    // The TPM keeps no copy, so every DEK wrapped under it is then
    // unrecoverable -- unless a copy of the key file survives (a backup),
    // which still loads on this TPM.
    fn retire_kek(&self, service: &str, expected_fingerprint: &[u8; crate::payload::FINGERPRINT_LEN]) -> Result<()> {
        self.check_not_refused()?;
        let Some(file) = read_key_file(service)? else {
            return Err(Error::KekNotFound);
        };
        if crate::crypto::kek_fingerprint(&encode_tpm_public_key(&file.public)?) != *expected_fingerprint {
            return Err(Error::KekFingerprintMismatch);
        }
        let dir = key_dir()?;
        let path = key_file_path(&dir, service);
        if FileIdentity::of(&path) != Some(file.identity) {
            return Err(Error::Provider("the TPM key file changed while it was being retired; nothing was deleted".into()));
        }
        std::fs::remove_file(&path)
            .map_err(|e| Error::Provider(format!("could not delete TPM key file {}: {e}", path.display())))?;
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

// Converts the payload's P-256 point (a `p256::PublicKey`)
// into the TPM crate's `EccPoint` representation, as required by
// `ecdh_z_gen`.
fn encode_peer_point(peer_public: &PublicKey) -> Result<EccPoint> {
    let encoded = peer_public.to_sec1_point(false); // uncompressed SEC1 encoding, so X and Y are both directly available
    let x = encoded
        .x()
        .ok_or(Error::Provider("point has no X coordinate".into()))?; // should never actually be missing for a valid point
    let y = encoded
        .y()
        .ok_or(Error::Provider("point has no Y coordinate".into()))?;

    let x_param = EccParameter::try_from(x.to_vec())
        .map_err(|e| Error::Provider(format!("failed to encode peer point X: {e}")))?;
    let y_param = EccParameter::try_from(y.to_vec())
        .map_err(|e| Error::Provider(format!("failed to encode peer point Y: {e}")))?;

    Ok(EccPoint::new(x_param, y_param))
}

#[cfg(test)]
mod tests {
    use super::*; // bring `Tpm2Provider` etc. into scope
    use p256::elliptic_curve::Generate as _; // `SecretKey::generate()`, from the OS CSPRNG
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
        let _no_policy = TestPolicy::absent(); // so `note_owner_auth_failure` reads "no owner_auth_file"
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
        std::fs::write(&owner_auth, b"secret").unwrap();
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
    fn a_service_key_is_tpm_generated_fixed_and_unrestricted_and_the_srk_is_the_tcg_storage_key() {
        let Public::Ecc { object_attributes: key, auth_policy, .. } = service_key_template().unwrap() else {
            panic!("expected an ECC template");
        };
        assert!(key.fixed_tpm() && key.fixed_parent() && key.sensitive_data_origin(), "never exported, generated in the TPM");
        assert!(key.decrypt() && !key.sign_encrypt() && !key.restricted(), "usable for ECDH_ZGen, and only that");
        assert!(key.user_with_auth() && key.no_da());
        assert!(auth_policy.value().is_empty(), "no policy that could authorize the key some other way");

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
    // service-key template with a real, random P-256 point.
    fn fake_service_public() -> Public {
        public_with_attributes(service_key_template().unwrap())
    }

    fn public_with_attributes(template: Public) -> Public {
        let point = p256::SecretKey::generate().public_key().to_sec1_point(false);
        let coordinate = |c: &[u8]| EccParameter::try_from(c.to_vec()).unwrap();
        let Public::Ecc { object_attributes, name_hashing_algorithm, auth_policy, parameters, .. } = template else {
            panic!("expected an ECC template");
        };
        Public::Ecc {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            unique: EccPoint::new(coordinate(point.x().unwrap()), coordinate(point.y().unwrap())),
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
        // Two processes provisioning at once: both write, one key wins,
        // and the loser's write is a no-op, not an overwrite.
        with_key_dir(|_| {
            let first = fake_service_public();
            write_key_file(SERVICE, &fake_blob(&first)).unwrap();
            write_key_file(SERVICE, &fake_blob(&fake_service_public())).unwrap();
            assert_eq!(read_key_file(SERVICE).unwrap().unwrap().public, first);
        });
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
            // private key someone outside the TPM knows.
            let Public::Ecc { object_attributes, name_hashing_algorithm, auth_policy, parameters, unique } =
                fake_service_public()
            else {
                unreachable!()
            };
            let importable = Public::Ecc {
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

        let _no_policy = TestPolicy::absent();
        assert!(pin_allows(SERVICE, &public).unwrap(), "with no policy, any key file is usable");
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
        let _no_policy = TestPolicy::absent();
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
        let _no_policy = TestPolicy::absent();
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

    #[test]
    fn manufacturer_classification_skips_only_known_internal_tpms() {
        let id = |s: &[u8; 4]| u32::from_be_bytes(*s);
        // Known fTPM / vTPM vendors: no bus, skip -- whether the short
        // identifier is padded with spaces or with NULs.
        for m in [b"INTC", b"AMD ", b"AMD\0", b"IBM ", b"IBM\0", b"MSFT", b"VMW\0"] {
            assert!(manufacturer_has_no_external_bus(id(m)), "{:?}", String::from_utf8_lossy(m));
        }
        // Discrete vendors: encrypt.
        for m in [b"IFX ", b"IFX\0", b"STM ", b"NTC ", b"ATML"] {
            assert!(!manufacturer_has_no_external_bus(id(m)), "{:?}", String::from_utf8_lossy(m));
        }
        // Unknown: encrypt -- auto only ever skips for a positive match.
        assert!(!manufacturer_has_no_external_bus(id(b"ZZZZ")));
        assert!(!manufacturer_has_no_external_bus(0)); // all-NUL trims to empty, which matches nothing

        // Padding is stripped, and only padding.
        assert_eq!(manufacturer_id_bytes(id(b"IBM\0")), b"IBM");
        assert_eq!(manufacturer_id_bytes(id(b"IBM ")), b"IBM");
        assert_eq!(manufacturer_id_bytes(id(b"INTC")), b"INTC");
        assert_eq!(manufacturer_id_bytes(0), b"");
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

    // Runs the exact same `load_kek` + `ecdh` path production code uses
    // and returns the resulting shared secret.
    fn ecdh_secret(service: &str, create: bool, peer: &PublicKey) -> Result<[u8; 32]> {
        let handle = provider().load_kek(service, create)?;
        let secret = handle.ecdh(peer)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(secret.as_slice());
        Ok(out)
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

            let created = tpm.load_kek(SERVICE, true).unwrap().public_key().unwrap();
            assert!(tpm.kek_exists(SERVICE).unwrap());
            let file = dir.join("com.company.orders.tpmkey");
            let bytes = std::fs::read(&file).unwrap();

            // Provisioning again is idempotent: the same key, the file untouched.
            assert_eq!(tpm.load_kek(SERVICE, true).unwrap().public_key().unwrap(), created);
            assert_eq!(std::fs::read(&file).unwrap(), bytes);

            // A new connection -- as a new process would have -- loads the
            // same key, and the TPM's ECDH agrees with the file's public key.
            let peer = p256::SecretKey::generate();
            let z = ecdh_secret(SERVICE, false, &peer.public_key()).unwrap();
            let expected = p256::ecdh::diffie_hellman(peer.to_nonzero_scalar(), created.as_affine());
            assert_eq!(z.as_slice(), expected.raw_secret_bytes().as_slice(), "Z must be ECDH with the key file's public key");
            assert_eq!(z, ecdh_secret(SERVICE, false, &peer.public_key()).unwrap(), "repeatable");
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn different_services_get_different_keys() {
        with_key_dir(|_| {
            let tpm = provider();
            let keys: Vec<_> =
                ["orders", "billing", "payments"].iter().map(|s| tpm.load_kek(s, true).unwrap().public_key().unwrap()).collect();
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
            let provision = || Tpm2Provider::new().load_kek(SERVICE, true).map(|h| h.public_key());
            let keys: Vec<_> = if simulator {
                (0..4).map(|_| provision().unwrap().unwrap()).collect()
            } else {
                (0..4)
                    .map(|_| std::thread::spawn(provision))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|t| t.join().unwrap().unwrap().unwrap())
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

            let handle = tpm.load_kek("spliced", false).expect("the file checks can't see the splice");
            match handle.ecdh(&crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap()) {
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
        assert!(with_tpm_context(validate_tpm_compatibility).unwrap(), "the SRK must be reproducible");
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
            let name = with_tpm_context(|ctx| {
                let srk = create_srk(ctx)?;
                let key = load_service_key(ctx, srk, SERVICE, &file.public, &file.private)?;
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
    #[serial]
    fn tpm_accepts_hashed_payload_points() {
        // The forgery-resistant protocol derives the wrapping key from
        // ECDH(KEK_priv, H_salt) for a point hashed from the payload
        // salt, whose discrete log nobody knows. If a backend refused to
        // do ECDH against such a caller-supplied point, the entire
        // construction would be unusable there -- so confirm it against
        // a real TPM before building on it, rather than assuming.
        with_key_dir(|_| {
            let h = crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap();
            let z1 = ecdh_secret(SERVICE, true, &h).unwrap();
            let z2 = ecdh_secret(SERVICE, false, &h).unwrap();
            assert_eq!(z1, z2, "ECDH against the same point must be repeatable for the same service");
            assert_ne!(z1, [0u8; 32], "shared secret must not be all zeroes");

            // Each service's KEK must produce its own Z against the same point.
            let z_billing = ecdh_secret("com.company.billing", true, &h).unwrap();
            assert_ne!(z1, z_billing, "different KEKs must yield different Z against the same point");

            // And each salt's point must produce its own Z for the same KEK.
            let h2 = crate::crypto::payload_ecdh_point(&[0x43u8; 32]).unwrap();
            assert_ne!(z1, ecdh_secret(SERVICE, false, &h2).unwrap(), "different salts must yield different Z for the same KEK");
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn retiring_deletes_the_key_file_only_with_the_right_fingerprint() {
        with_key_dir(|dir| {
            let tpm = provider();
            let public = tpm.load_kek(SERVICE, true).unwrap().public_key().unwrap();
            let right = crate::crypto::kek_fingerprint(&public);
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

    // ---- session parameter encryption ----

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn encrypted_session_ecdh_yields_the_same_z_as_a_plain_session() {
        // Correctness: parameter encryption must be transparent -- the
        // TPM computes the same Z, ESAPI decrypts the response, and the
        // caller sees identical bytes. If the SRK weren't an acceptable
        // `tpmKey`, or the attributes were wrong, this is where it would
        // fail.
        with_key_dir(|_| {
            provider().load_kek(SERVICE, true).unwrap();
            let file = read_key_file(SERVICE).unwrap().unwrap();
            let peer = encode_peer_point(&crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap()).unwrap();
            let (plain, encrypted) = with_tpm_context(|ctx| {
                let srk = create_srk(ctx)?;
                let key = load_service_key(ctx, srk, SERVICE, &file.public, &file.private)?;
                let plain = ctx
                    .execute_with_nullauth_session(|ctx| ctx.ecdh_z_gen(key, peer.clone()))
                    .map_err(|e| Error::Provider(format!("plain ECDH failed: {e}")));
                let encrypted = ecdh_z_gen_encrypted(ctx, srk, key, &peer);
                let _ = ctx.flush_context(key.into());
                let _ = ctx.flush_context(srk.into());
                Ok((plain?, encrypted?))
            })
            .unwrap();
            assert_eq!(plain.x().value(), encrypted.x().value(), "Z must be identical through an encrypted session");
            assert_eq!(plain.y().value(), encrypted.y().value());
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn encrypted_sessions_really_carry_the_encryption_attributes() {
        // The test above cannot tell an encrypting session from one that
        // silently isn't: Z is identical either way. This checks what
        // decides it -- the session's own attributes, as ESAPI reports
        // them for the session `ecdh_z_gen_encrypted` would use.
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
        assert!(attributes.decrypt(), "the command's first parameter (inPoint) must be encrypted");
        assert!(attributes.encrypt(), "the response's first parameter (Z) must be encrypted");
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn the_tpm_refuses_ecdh_with_the_srk() {
        // The SRK is restricted, so anyone who recreates it from its
        // public template still can't use it to recover a session's salt:
        // the TPM itself refuses ECDH_ZGen with it. A service key, for
        // contrast, accepts the same point.
        with_key_dir(|_| {
            provider().load_kek(SERVICE, true).unwrap();
            let file = read_key_file(SERVICE).unwrap().unwrap();
            let point = encode_peer_point(&crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap()).unwrap();
            let (refused, accepted) = with_tpm_context(|ctx| {
                let srk = create_srk(ctx)?;
                let refused = ctx.execute_with_nullauth_session(|ctx| ctx.ecdh_z_gen(srk, point.clone())).is_err();
                let key = load_service_key(ctx, srk, SERVICE, &file.public, &file.private)?;
                let accepted = ctx.execute_with_nullauth_session(|ctx| ctx.ecdh_z_gen(key, point.clone())).is_ok();
                let _ = ctx.flush_context(key.into());
                let _ = ctx.flush_context(srk.into());
                Ok((refused, accepted))
            })
            .unwrap();
            assert!(refused, "TPM2_ECDH_ZGen with the restricted SRK must be refused by the TPM");
            assert!(accepted, "the control: a service key accepts the same point");
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
            let h = crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap();
            let policy_for = |name_hex: &str| {
                format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"required\"\npinned_session_salt_key_name = \"{name_hex}\"\n")
            };
            with_policy(&policy_for(&hex(&real)), || ecdh_secret(SERVICE, false, &h))
                .expect("a correctly pinned SRK must work");

            let mut wrong = real.clone();
            wrong[2] ^= 0xff;
            match with_policy(&policy_for(&hex(&wrong)), || ecdh_secret(SERVICE, false, &h)) {
                Err(Error::Provider(msg)) => assert!(msg.contains("storage root key Name"), "{msg}"),
                other => panic!("an SRK whose Name doesn't match the pin must be refused, got {other:?}"),
            }
        });
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn auto_mode_skips_encryption_on_an_internal_tpm_unless_pinned_and_required_forces_it() {
        // swtpm and firmware TPMs report a known no-bus manufacturer, so
        // `auto` (the default, no policy file) skips encryption; `required`
        // still encrypts. Both paths must still produce a working ECDH.
        let (auto, reported) = with_tpm_context(|ctx| {
            let reported = ctx
                .get_tpm_property(PropertyTag::Manufacturer)
                .map_err(|e| Error::Provider(e.to_string()))?;
            Ok((session_encryption_enabled(ctx)?, reported))
        })
        .unwrap();
        // Report what the TPM actually said, so a classification miss
        // explains itself instead of just failing.
        assert!(
            !auto,
            "auto must skip encryption on an internal TPM; TPM_PT_MANUFACTURER was {:?} (raw {reported:?})",
            reported.map(|id| String::from_utf8_lossy(&id.to_be_bytes()).into_owned())
        );

        let real = hex(&srk_name());
        // `auto` with a pinned SRK encrypts too, even on a TPM whose
        // manufacturer it would otherwise skip: the manufacturer is read
        // over the bus, so an interposer could have written it.
        let pinned_auto = with_policy(
            &format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"auto\"\npinned_session_salt_key_name = \"{real}\"\n"),
            || with_tpm_context(session_encryption_enabled),
        )
        .unwrap();
        assert!(pinned_auto, "auto with a pinned SRK must encrypt, whatever the manufacturer");

        let required = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"required\"\npinned_session_salt_key_name = \"{real}\"\n"
        );
        with_policy(&required, || {
            assert!(with_tpm_context(session_encryption_enabled).unwrap(), "required must encrypt regardless of manufacturer");
            // And the full production path -- load_kek + ecdh -- works under it.
            with_key_dir(|_| {
                let h = crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap();
                assert_ne!(ecdh_secret(SERVICE, true, &h).unwrap(), [0u8; 32], "ECDH through the encrypted session must succeed");
            });
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
                let h = crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap();
                assert_ne!(*tpm.load_kek(service, false).unwrap().ecdh(&h).unwrap(), [0u8; 32]);
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
            let h = crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap();
            let pin = |name: &[u8]| format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\n\"{SERVICE}\" = \"{}\"\n", hex(name));

            with_policy(&pin(&actual), || ecdh_secret(SERVICE, false, &h)).expect("a correctly pinned Name must be accepted");

            // Pinned to anything else: refused, and refused before the key
            // is ever loaded for ECDH.
            let mut wrong = actual.clone();
            wrong[2] ^= 0xff; // corrupt the digest, keeping the alg prefix valid
            assert!(with_policy(&pin(&wrong), || ecdh_secret(SERVICE, false, &h)).is_err());
        });
    }
}

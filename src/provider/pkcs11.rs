//! Provider 2: PKCS#11 (used when TPM2 is unavailable).
//!
//! ```text
//!  ______________________________________________________________________
//! | HARDWARE/MODULE-DEPENDENT CODE                                        |
//! |                                                                        |
//! | Verified (see docker/): natively built against real `cryptoki` 0.6.2  |
//! | on Ubuntu 24.04 (x86_64 and aarch64), and the `#[ignore]`d tests pass |
//! | against a real SoftHSM2 token -- C_GenerateKeyPair + CKM_ECDH1_DERIVE |
//! | executed for real and produced the same key deterministically across |
//! | two calls. Not yet exercised against a hardware HSM/YubiHSM; re-run  |
//! | `docker/run-tests.sh` after any change here, and re-test against     |
//! | your production module/HSM before relying on this with it.           |
//! |______________________________________________________________________|
//! ```
//!
//! ## Configuration
//!
//! All of it comes from the `[pkcs11]` table of the root-owned policy file.
//!
//! - `module`: absolute path to the PKCS#11 module. **PKCS#11 is used only
//!   when this is set.** There is no default search: the commonly installed
//!   module, SoftHSM2, is a software token that would otherwise be picked
//!   up -- and counted as hardware -- just for being installed. The
//!   (symlink-resolved) module file, its directory, and every directory
//!   above it must be owned by root and not writable by group or others
//!   (sticky ancestors excepted) -- see [`validate_module_path`]:
//!   the module is `dlopen`ed into this process. Only the module file
//!   itself is checked: the libraries *it* depends on are found the usual
//!   way (its RPATH/RUNPATH, `LD_LIBRARY_PATH`, the loader cache). That is
//!   the same trust any library the host process loads gets, not a
//!   boundary this crate draws -- whoever controls the process's
//!   environment already controls what runs in it -- but keep a vendor
//!   module's dependencies in root-owned locations too.
//! - `token_label` / `token_serial`: which token to use, among initialized
//!   ones. Exactly one must match. With neither set, there must be exactly
//!   one initialized token. Slot numbers are never used: they can change
//!   across reboots and hot-plugging.
//! - `pin_file`: the user-PIN file (default
//!   `/etc/hkdfguard/pkcs11.pin`). Owned by root, no access for others,
//!   group read allowed (`0400`, or `root:<service-group> 0440` for a
//!   non-root service), in directories only root can change; one
//!   trailing newline is ignored. The PIN itself is never read from the
//!   environment (`/proc/<pid>/environ` is readable by same-user processes
//!   and inherited by children); the retired `HKDFGUARD_PKCS11_PIN` is
//!   ignored with a warning.
//!
//! ## Design
//!
//! For each service, finds (or generates, if absent) a **non-extractable**
//! token-persistent EC P-256 key pair labelled `hkdfguard:<service>`
//! (`CKA_TOKEN=true`, `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`,
//! `CKA_DERIVE=true`, and `CKA_MODIFIABLE=false` / `CKA_COPYABLE=false`, so
//! those can't be relaxed afterwards). Exactly one object of each class may
//! carry that label, with the `CKA_ID` hkdfguard gives it: anything else
//! is refused rather than guessed between. The session is read-only; a
//! read/write one is opened only for the moment it takes to generate a
//! key pair. ECDH is performed on-token via `CKM_ECDH1_DERIVE`
//! (`CKD_NULL` -- no token-side KDF; this crate does its own HKDF-SHA512
//! outside, per the shared protocol), which derives a session-local,
//! extractable generic-secret object holding the raw shared X-coordinate.
//! That value is read out, the temporary derived object is destroyed
//! immediately, and the raw bytes are wrapped in a zeroizing buffer before
//! returning -- the *persistent* private key never leaves the token.
//!
//! A key found under a service's label is used only if it still carries
//! those protections, including `CKA_ALWAYS_SENSITIVE` and
//! `CKA_NEVER_EXTRACTABLE`, which the token sets only on a key generated
//! on it and never exposed -- so an imported key with a known scalar,
//! labelled and tagged to match, is refused (see `check_protections`).
//!
//! A wrong PIN is tried once: after the token rejects it, this process
//! attempts no further login with that PIN file until the file changes,
//! and a token that reports its user PIN locked or on its final attempt is
//! refused before any login -- so this library never locks the HSM user
//! out (see [`PIN_LATCHES`]). Two processes generating a service's pair at
//! the same moment is detected after the fact, and the later one discards
//! its own pair rather than leaving two under the label (see
//! `generate_key_pair`).
//!
//! `load_kek` locates the pair (or generates it, when creation was asked
//! for) up front and hands back a handle holding both object handles, so
//! `hkdfguard_create_kek` really creates, `hkdfguard_kek_exists` reports
//! what it created, and a load without creation declines with
//! `KeyNotProvisioned` when nothing is there -- letting the provider chain
//! move on to a provider that does hold the service's key.
//!
//! ## Module lifecycle
//!
//! A provider is constructed per C ABI call and dropped with it, and so is
//! its session and login. The module itself is different: `C_Initialize`
//! and `C_Finalize` are process-wide, so the module is loaded and
//! initialized once per process and never finalized (see [`MODULES`]).
//! Finalizing per call, while another thread's call is inside the module,
//! is undefined behavior and in practice fails both calls. Because a login
//! is per application per token, overlapping calls share one logged-in
//! state; `C_Login` answering "already logged in" is treated as success,
//! nothing ever calls `C_Logout`, and the login ends when the process's
//! last session on the token closes.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::{Backend, KekHandle, KekProvider, ProviderType, SharedSecret}; // traits/types this module implements
use elliptic_curve::sec1::ToEncodedPoint; // encodes our ephemeral public key into the raw bytes the token expects
use p256::PublicKey; // the caller's ephemeral public key type
use sha2::{Digest as ShaDigest, Sha256}; // used for the CKA_ID tag (aliased to avoid clashing with cryptoki's own naming)
use std::path::{Path, PathBuf}; // module-path validation and PIN-file location
use std::sync::{Arc, Mutex, PoisonError}; // shared, lock-protected PKCS#11 session, and the process-wide module registry
use zeroize::Zeroizing; // scrubs the shared secret read off the token as soon as it's no longer needed

use cryptoki::context::{CInitializeArgs, Pkcs11}; // loads the PKCS#11 module and initializes the library
use cryptoki::error::{Error as CryptokiError, RvError}; // to recognize the two return codes that mean "already done" rather than failure
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams}; // parameters for the CKM_ECDH1_DERIVE mechanism
use cryptoki::mechanism::Mechanism; // the mechanism enum (EccKeyPairGen, Ecdh1Derive, ...)
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle}; // PKCS#11 object attributes/handles
use cryptoki::session::{Session, UserType}; // an open session against a slot/token, and the login role
use cryptoki::slot::Slot; // identifies a PKCS#11 slot
use cryptoki::types::AuthPin; // wraps a PIN for login

// DER encoding of the secp256r1 (P-256 / prime256v1) OID, as required for
// CKA_EC_PARAMS.
const P256_EC_PARAMS: &[u8] = &[
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];

// SEC1 uncompressed P-256 point: 1 tag byte (0x04) + 32-byte X + 32-byte Y.
const UNCOMPRESSED_POINT_LEN: usize = 65;

// The open, logged-in, read-only session, plus what it takes to open a
// short-lived read/write one on the same token when a key pair has to be
// generated (a login applies to every session the process has open on a
// token, so that one needs no PIN). Dropped with the provider, i.e. at the
// end of the C ABI call that constructed it: the session is closed, and
// if it was the process's last session on the token, that ends the login
// too. `pkcs11` is a clone of the registry's handle (see [`MODULES`]), so
// dropping it never finalizes the module.
struct OpenSession {
    session: Session,
    pkcs11: Pkcs11,
    slot: Slot,
}

/// Every PKCS#11 module this process has loaded and initialized, by
/// canonical path. Kept for the life of the process and never finalized.
///
/// `C_Initialize` and `C_Finalize` act on the module as a whole, for the
/// whole process -- not on one caller's handle. Doing them per call, as an
/// earlier revision did, was unsafe the moment two calls overlapped: the
/// second `C_Initialize` fails with `CKR_CRYPTOKI_ALREADY_INITIALIZED`, the
/// failed context is dropped, and `cryptoki`'s drop runs `C_Finalize` --
/// tearing the module down under the first call's open session (undefined
/// behavior per the PKCS#11 specification; a crash on some modules). So a
/// module is initialized once and left so. This is a library handle, not
/// authority: sessions and logins are still opened per call and closed
/// when the call's provider drops (see [`OpenSession`]), and a login lasts
/// only while the process has a session open on the token.
static MODULES: Mutex<Vec<(PathBuf, Pkcs11)>> = Mutex::new(Vec::new());

// The initialized context for the module at `checked` (a canonical path
// that has passed `validate_module_path`), loading and initializing it the
// first time it is asked for. Serialized by the registry lock, so two
// first-time callers cannot both try to initialize.
fn load_module(checked: &Path) -> std::result::Result<Pkcs11, String> {
    let mut modules = MODULES.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, pkcs11)) = modules.iter().find(|(path, _)| path == checked) {
        return Ok(pkcs11.clone()); // a clone shares the one underlying library handle
    }
    let pkcs11 = Pkcs11::new(checked).map_err(|e| format!("could not load module {}: {e}", checked.display()))?;
    match pkcs11.initialize(CInitializeArgs::OsThreads) {
        // telling the module we may call it from multiple OS threads
        Ok(()) => {}
        // Something else in this process (the host application, another
        // library) initialized this module already. It is usable as it is,
        // and must never be finalized by code that did not initialize it --
        // which keeping it in the registry guarantees.
        Err(CryptokiError::Pkcs11(RvError::CryptokiAlreadyInitialized)) => {
            log::debug!("hkdfguard: PKCS#11 module {} was already initialized in this process", checked.display());
        }
        // `pkcs11` drops here. That runs C_Finalize on a module that was
        // never initialized, which the module answers with
        // CKR_CRYPTOKI_NOT_INITIALIZED: a no-op.
        Err(e) => return Err(format!("C_Initialize failed: {e}")),
    }
    modules.push((checked.to_path_buf(), pkcs11.clone()));
    Ok(pkcs11)
}

// Holds the shared, lazily-usable PKCS#11 session. `None` in `state` means
// no module/token/PIN was usable at construction time.
pub struct Pkcs11Provider {
    state: Arc<Mutex<Option<OpenSession>>>,
    // Set when PKCS#11 is configured but can't be used (see
    // `crate::provider::Backend::Refused`); every call then fails with it.
    refused: Option<String>,
}

impl Pkcs11Provider {
    pub fn new() -> Self {
        // try to set everything up once, at construction time
        let (state, refused) = match open_session() {
            Backend::Ready(open) => (Some(open), None),
            Backend::Absent => (None, None),
            Backend::Refused(reason) => {
                crate::provider::log_once(log::Level::Error, format!("hkdfguard: PKCS#11 refused: {reason}"));
                (None, Some(reason))
            }
        };
        Pkcs11Provider { state: Arc::new(Mutex::new(state)), refused }
    }

    fn connected(&self) -> bool {
        self.state.lock().map(|guard| guard.is_some()).unwrap_or(false) // a poisoned lock counts as not connected
    }

    fn check_not_refused(&self) -> Result<()> {
        match &self.refused {
            Some(reason) => Err(Error::Provider(format!("PKCS#11 refused: {reason}"))),
            None => Ok(()),
        }
    }
}

impl Default for Pkcs11Provider {
    fn default() -> Self {
        Self::new()
    }
}

/// Picks one token from the initialized tokens present, given as
/// `(label, serial)` pairs in slot order. With a label and/or serial
/// configured, exactly one token must match all that are set. Otherwise
/// there must be exactly one initialized token -- with several, guessing
/// would make which token holds the keys depend on enumeration order.
fn select_token(tokens: &[(String, String)], label: Option<&str>, serial: Option<&str>) -> std::result::Result<usize, String> {
    if label.is_some() || serial.is_some() {
        let matches: Vec<usize> = tokens
            .iter()
            .enumerate()
            .filter(|(_, (l, n))| label.is_none_or(|want| want == l) && serial.is_none_or(|want| want == n))
            .map(|(i, _)| i)
            .collect();
        return match matches.as_slice() {
            [one] => Ok(*one),
            [] => Err(format!("no initialized token matches pkcs11.token_label {label:?} / token_serial {serial:?}")),
            many => Err(format!(
                "{} tokens match pkcs11.token_label {label:?} / token_serial {serial:?}; set token_serial to choose one",
                many.len()
            )),
        };
    }
    match tokens.len() {
        1 => Ok(0),
        0 => Err("no initialized PKCS#11 token is present".to_string()),
        n => Err(format!("{n} initialized PKCS#11 tokens are present; set pkcs11.token_label (or token_serial) to choose one")),
    }
}

/// Checks a PKCS#11 module path before it's ever `dlopen`ed: it must be
/// absolute, and after resolving symlinks, the module file must be owned
/// by root and not writable by group or others, and so must its directory
/// and every directory above it (see [`crate::secure_file::check_dir_chain`]).
/// Returns the canonical (symlink-resolved) path -- the one that was
/// actually checked -- so that's exactly what gets loaded.
///
/// Loading a module runs its code inside this process. Checking only the
/// file and its immediate directory isn't enough: a non-root user who can
/// write to any ancestor can rename the module's directory away and put
/// their own in its place between this check and the `dlopen`. With the
/// whole chain root-controlled, nothing on the path can change in between.
fn validate_module_path(path: &Path) -> std::result::Result<PathBuf, String> {
    use crate::secure_file::{check_dir_chain, check_metadata, Owner, FORBID_GROUP_OTHER_WRITE};

    if !path.is_absolute() {
        return Err(format!("PKCS#11 module path {path:?} must be absolute"));
    }
    let canonical = std::fs::canonicalize(path).map_err(|e| format!("PKCS#11 module {path:?}: {e}"))?;

    let file_meta = std::fs::metadata(&canonical).map_err(|e| format!("PKCS#11 module {}: {e}", canonical.display()))?;
    check_metadata(&file_meta, Some(Owner::Root), FORBID_GROUP_OTHER_WRITE)
        .map_err(|e| format!("refusing to load PKCS#11 module {}: {e}", canonical.display()))?;

    let parent = canonical
        .parent()
        .ok_or_else(|| format!("PKCS#11 module {} has no parent directory", canonical.display()))?;
    check_dir_chain(parent, Owner::Root)
        .map_err(|e| format!("refusing to load PKCS#11 module {}: {e}", canonical.display()))?;

    Ok(canonical)
}

/// Default location of the PKCS#11 user-PIN file (`pkcs11.pin_file` overrides it).
const DEFAULT_PIN_FILE: &str = "/etc/hkdfguard/pkcs11.pin";

/// Longest PIN file accepted -- far above any real PIN length, only here
/// to bound the one up-front allocation `SecretBuffer` makes.
const MAX_PIN_FILE_LEN: usize = 256;

/// What identifies one version of the PIN file. A change to any of these
/// means an operator touched the file, which clears a latched login failure
/// (see [`PIN_LATCHES`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
}

impl FileIdentity {
    fn of(path: &Path) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(path).ok()?;
        Some(FileIdentity { dev: m.dev(), ino: m.ino(), len: m.len(), mtime: (m.mtime(), m.mtime_nsec()) })
    }
}

/// PIN files this process must not log in with again, each with the
/// identity the file had when its PIN was rejected and the reason.
///
/// Every `C_Login` with a wrong PIN spends one of the token's attempts, and
/// a real HSM locks the user PIN after a handful; recovering that needs the
/// security officer and, on some devices, re-initializing the token, which
/// loses the keys. `hkdfguard_wrap_dek` is the hot path and is not
/// rate-limited, so a service retrying wraps after a PIN rotation (or with
/// a mistyped PIN file) would otherwise burn through the attempts in
/// seconds. After one rejection this process attempts no further login
/// with that file until the file changes -- an operator corrected it -- or
/// the process restarts. The token's own flags are checked before each
/// login as well (see `open_session`), so a token already on its final
/// attempt is never pushed over by this library.
static PIN_LATCHES: Mutex<Vec<(PathBuf, Option<FileIdentity>, String)>> = Mutex::new(Vec::new());

/// Why logins with the PIN file at `pin_file` are refused, if they are.
/// `current` is the file's identity now; if it differs from the identity
/// recorded with the latch, the file was changed and the latch is cleared,
/// so that one login can find out whether the correction worked.
fn pin_login_blocked(pin_file: &Path, current: Option<FileIdentity>) -> Option<String> {
    let mut latches = PIN_LATCHES.lock().unwrap_or_else(PoisonError::into_inner);
    let i = latches.iter().position(|(path, _, _)| path == pin_file)?;
    if latches[i].1 != current {
        latches.remove(i);
        return None;
    }
    Some(latches[i].2.clone())
}

/// Records that the token rejected the PIN read from `pin_file` (which had
/// identity `identity` at the time), so no further login is attempted with
/// it -- see [`PIN_LATCHES`].
fn latch_pin_login(pin_file: &Path, identity: Option<FileIdentity>, reason: String) {
    let mut latches = PIN_LATCHES.lock().unwrap_or_else(PoisonError::into_inner);
    latches.retain(|(path, _, _)| path != pin_file);
    latches.push((pin_file.to_path_buf(), identity, reason));
}


/// Reads the PKCS#11 user PIN from `path`. The file must be a regular file
/// owned by root (see [`crate::secure_file::config_owner`]), readable by
/// nobody but its owner and -- since it is root's -- optionally its group,
/// so a non-root service reads it as `root:<service-group> 0440`. It must
/// not be one the service can write: a wrong PIN written into it would
/// burn an HSM login attempt on every call until the token locks the user
/// out. The directories it lives in are checked the same way. Symlinks are
/// followed (Kubernetes Secret volumes are symlinks) but the checks apply
/// to the file actually opened. One trailing `\n` (or `\r\n`) is stripped.
/// The raw file bytes live in a self-wiping `SecretBuffer` that is wiped
/// explicitly before this returns -- on every path -- and the PIN itself
/// comes back as an `AuthPin`, which zeroizes its own storage on drop.
fn read_pin_file(path: &Path) -> std::result::Result<AuthPin, std::io::Error> {
    use crate::secure_file::{check_location, config_owner, open_checked, FileRequirements, SecretBuffer, FORBID_GROUP_OTHER_ACCESS};
    use std::io::{Error as IoError, ErrorKind};

    let requirements = FileRequirements {
        owner: Some(config_owner()),
        forbidden_mode_bits: FORBID_GROUP_OTHER_ACCESS,
        follow_symlinks: true,
        allow_group_read_if_root_owned: true,
    };
    check_location(path, config_owner())?;
    let mut file = open_checked(path, &requirements)?;
    let mut raw = SecretBuffer::read_from(&mut file, MAX_PIN_FILE_LEN)?;

    let mut pin = raw.as_slice();
    if let Some(stripped) = pin.strip_suffix(b"\n") {
        pin = stripped.strip_suffix(b"\r").unwrap_or(stripped);
    }
    // Copy exactly the PIN bytes (no over-allocation, no growth) into the
    // String `AuthPin` takes ownership of, then wipe the file buffer
    // before anything can return -- including the error paths below.
    let result = if pin.is_empty() {
        Err(IoError::new(ErrorKind::InvalidData, "PIN file is empty"))
    } else {
        String::from_utf8(pin.to_vec())
            .map(AuthPin::new)
            .map_err(|e| {
                let mut rejected = e.into_bytes();
                zeroize::Zeroize::zeroize(&mut rejected); // the non-UTF-8 bytes are still PIN material
                IoError::new(ErrorKind::InvalidData, "PIN file is not valid UTF-8")
            })
    };
    raw.wipe();
    result
}

// Loads the PIN, loads the module, initializes the library, picks a slot,
// opens a read-only session, and logs in. `Absent` when PKCS#11 isn't
// configured on this host -- no `pkcs11.module` in policy, or no PIN file.
// Once it is configured,
// every later failure is `Refused`: the HSM is meant to be used, so a
// module that won't load, a missing token, or a wrong PIN is an outage to
// surface, not a reason to wrap under a weaker provider.
fn open_session() -> Backend<OpenSession> {
    if std::env::var_os("HKDFGUARD_PKCS11_PIN").is_some() {
        crate::provider::log_once(
            log::Level::Warn,
            format!(
                "hkdfguard: HKDFGUARD_PKCS11_PIN is no longer supported and is ignored; put the PIN in a root-owned mode-0400 (or 0440, group = the service's group) file named by pkcs11.pin_file in the policy (default {DEFAULT_PIN_FILE}) instead"
            ),
        );
    }

    let settings = match crate::policy::pkcs11_settings() {
        Ok(s) => s,
        Err(e) => return Backend::Refused(e.to_string()),
    };
    let Some(module) = settings.module.clone() else {
        log::debug!("hkdfguard: no PKCS#11 module configured (pkcs11.module); PKCS#11 provider not used");
        return Backend::Absent; // the normal state on a host without an HSM configured
    };

    let pin_path = settings.pin_file.clone().unwrap_or_else(|| PathBuf::from(DEFAULT_PIN_FILE));
    let pin = match read_pin_file(&pin_path) {
        Ok(pin) => pin,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Its directory is root-controlled (see `read_pin_file`), so
            // nobody else can make it absent.
            log::debug!("hkdfguard: no PKCS#11 PIN file at {}; PKCS#11 provider not used", pin_path.display());
            return Backend::Absent;
        }
        Err(e) => return Backend::Refused(format!("PIN file {}: {e}", pin_path.display())),
    };
    // A PIN this process has already seen the token reject is not tried
    // again until the file changes: see `PIN_LATCHES`.
    let pin_identity = FileIdentity::of(&pin_path);
    if let Some(reason) = pin_login_blocked(&pin_path, pin_identity) {
        return Backend::Refused(format!(
            "PKCS#11 login disabled in this process: {reason}; correct the PIN file {} (any change to it re-enables \
             login) or restart the process",
            pin_path.display()
        ));
    }

    let checked = match validate_module_path(&module) {
        Ok(checked) => checked,
        Err(reason) => return Backend::Refused(reason),
    };
    let pkcs11 = match load_module(&checked) {
        Ok(pkcs11) => pkcs11, // loaded and initialized once per process; see `MODULES`
        Err(reason) => return Backend::Refused(reason),
    };
    let refuse = |what: &str, e: &dyn std::fmt::Display| Backend::Refused(format!("{what}: {e}"));

    // Only initialized tokens can hold keys; SoftHSM2, for one, always
    // presents an extra blank token alongside the real ones.
    let slots = match pkcs11.get_slots_with_token() {
        Ok(slots) => slots,
        Err(e) => return refuse("could not list slots", &e),
    };
    let mut candidates: Vec<(Slot, (String, String))> = Vec::new();
    for slot in slots {
        let info = match pkcs11.get_token_info(slot) {
            Ok(info) => info,
            Err(e) => return refuse("could not read token info", &e),
        };
        if info.token_initialized() {
            candidates.push((slot, (info.label().to_string(), info.serial_number().to_string())));
        }
    }
    let tokens: Vec<(String, String)> = candidates.iter().map(|(_, t)| t.clone()).collect();
    let slot: Slot = match select_token(
        &tokens,
        settings.token_label.as_deref(),
        settings.token_serial.as_deref(),
    ) {
        Ok(i) => candidates[i].0,
        Err(reason) => return Backend::Refused(reason),
    };

    // The token reports the user PIN's state. Read it before spending an
    // attempt: a token that is locked, or down to its last try, is refused
    // without a login, so this library is never what locks the HSM user
    // out. (A correct PIN would reset the counter, but an automated caller
    // cannot know its PIN is correct; an operator can, with the vendor's
    // tools, and that is who should spend the final attempt.)
    match pkcs11.get_token_info(slot) {
        Ok(info) if info.user_pin_locked() => {
            return Backend::Refused(
                "the token reports its user PIN locked; a security officer must unlock it before PKCS#11 can be used".into(),
            )
        }
        Ok(info) if info.user_pin_final_try() => {
            return Backend::Refused(
                "the token reports the user PIN on its final attempt; refusing to spend it -- verify the PIN file \
                 against the token with the vendor's tools before retrying"
                    .into(),
            )
        }
        Ok(info) => {
            if info.user_pin_count_low() {
                log::warn!("hkdfguard: the PKCS#11 token reports failed user-PIN attempts; check the PIN file before the token locks");
            }
        }
        Err(e) => return refuse("could not read token info", &e),
    }

    // Read-only: finding keys and ECDH need nothing more, and only key
    // generation opens a read/write session (see `generate_key_pair`).
    let session = match pkcs11.open_ro_session(slot) {
        Ok(session) => session,
        Err(e) => return refuse("could not open a session", &e),
    };
    // C_Login as the normal user role, required before key generation/derivation.
    // A login is per application per token, not per session: while another
    // call's session is still open on this token, the process is already
    // logged in and C_Login says so. That is success, not an error -- and
    // it is why no code here ever calls C_Logout, which would log the
    // other call out mid-operation; closing the last session ends the
    // login instead.
    match session.login(UserType::User, Some(&pin)) {
        Ok(()) | Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn)) => {}
        // The token rejected the configured PIN, or is now locked. One
        // attempt was spent finding that out; none more will be, from this
        // process, until the PIN file changes.
        Err(CryptokiError::Pkcs11(rv @ (RvError::PinIncorrect | RvError::PinLocked))) => {
            let reason = format!("the token rejected the configured PIN ({rv:?})");
            latch_pin_login(&pin_path, pin_identity, reason.clone());
            return Backend::Refused(format!(
                "C_Login failed: {reason}; no further login will be attempted by this process until the PIN file {} \
                 changes, so the token's remaining attempts are not spent",
                pin_path.display()
            ));
        }
        Err(e) => return refuse("C_Login failed", &e),
    }
    drop(pin); // AuthPin zeroizes its storage on drop; don't keep the PIN around for the session's lifetime

    Backend::Ready(OpenSession { session, pkcs11, slot })
}

// Handle type returned from `load_kek`: the service's key pair, already
// located on the token (or just generated there), plus a shared reference
// to the session those object handles belong to. PKCS#11 object handles
// stay valid for as long as the session that produced them is open, and
// that session lives in `state`, which this handle keeps alive.
struct Pkcs11Handle {
    key_id: Vec<u8>, // diagnostic-only tag embedded in the wrapped payload
    keys: KeyPair,   // the private key `ecdh` derives with, and the public half `public_key` reads
    state: Arc<Mutex<Option<OpenSession>>>, // shared handle back to the open PKCS#11 session
}

impl KekHandle for Pkcs11Handle {
    fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    fn ecdh(&self, ephemeral_public_key: &PublicKey) -> Result<SharedSecret> {
        let mut guard = self
            .state
            .lock() // only one caller may drive the session at a time
            .map_err(|_| Error::Provider("PKCS#11 session lock poisoned".into()))?;
        let open = guard
            .as_mut()
            .ok_or(Error::Provider("PKCS#11 session not available".into()))?; // session setup failed at construction time

        let peer_point_bytes = ephemeral_public_key.to_encoded_point(false).as_bytes().to_vec(); // raw uncompressed point bytes the token expects as CKM_ECDH1_DERIVE's public data

        let params = Ecdh1DeriveParams::new(EcKdf::null(), &peer_point_bytes); // CKD_NULL: no extra KDF on-token, we do HKDF ourselves afterward
        let derive_template = [
            // attributes for the *temporary* object the derive operation will create
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Token(false),      // session object only, never written to the token's persistent storage
            Attribute::Sensitive(false),  // must be readable, since we need to read the shared secret back out
            Attribute::Extractable(true), // ditto
            Attribute::ValueLen(32.into()), // we want exactly 32 bytes (the X-coordinate size for P-256)
        ];

        let derived = open
            .session
            .derive_key(
                &Mechanism::Ecdh1Derive(params), // C_DeriveKey with CKM_ECDH1_DERIVE
                self.keys.private,                // our service's non-extractable persistent private key
                &derive_template,
            )
            .map_err(|e| Error::Provider(format!("CKM_ECDH1_DERIVE failed: {e}")))?;

        // Read the raw shared-secret bytes out of the temporary object,
        // then remove that object at once -- whether or not the read worked,
        // so a failed read never leaves an extractable copy of the secret on
        // the token for the rest of the session.
        let value = read_value(&open.session, derived, 32); // already Zeroizing-wrapped
        let _ = open.session.destroy_object(derived); // best-effort; the session closing later would clean it up anyway
        let value = value?;

        if value.len() != 32 {
            return Err(Error::Provider(
                "PKCS#11 token returned unexpected shared secret length".into(), // defensive; should always be 32 given ValueLen above
            ));
        }
        let mut secret = SharedSecret::new([0u8; 32]); // zeroizing from the start: no un-wiped intermediate copy on the stack
        secret.copy_from_slice(&value);
        Ok(secret) // `value` (the heap copy) is dropped and scrubbed right after this line
    }

    fn public_key(&self) -> Result<PublicKey> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| Error::Provider("PKCS#11 session lock poisoned".into()))?;
        let open = guard
            .as_mut()
            .ok_or(Error::Provider("PKCS#11 session not available".into()))?;

        // The public half of the exact pair `load_kek` located, so the
        // fingerprint always describes the key `ecdh` derives with.
        let point_bytes = read_ec_point(&open.session, self.keys.public)?;
        parse_ec_point(&point_bytes)
    }
}

impl KekProvider for Pkcs11Provider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Pkcs11
    }

    fn probe(&self) -> bool {
        self.refused.is_some() || self.connected()
    }

    // Side-effect-free: asks the token whether the service's private key
    // is there, without creating anything. A refused provider, or a
    // duplicate or foreign object under the label, is an error -- never
    // read as "no key", see `provider::kek_exists`.
    fn kek_exists(&self, service: &str) -> Result<bool> {
        self.check_not_refused()?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| Error::Provider("PKCS#11 session lock poisoned".into()))?;
        let open = guard
            .as_mut()
            .ok_or(Error::Provider("PKCS#11 session not available".into()))?;
        Ok(find_key_pair(&open.session, service)?.is_some())
    }

    // Locates the service's key pair on the token now -- generating it if
    // `create_if_missing` and none exists -- and returns a handle holding
    // both object handles. With `create_if_missing` false and no pair
    // present, declines with `KeyNotProvisioned`: that is what lets the
    // provider chain move on to a provider that does hold the service's
    // key, and what keeps `hkdfguard_create_kek` the only path that creates
    // one. (An earlier revision deferred all of this to `ecdh`, so
    // create_kek reported success without creating anything and the chain
    // could never move past PKCS#11.)
    fn load_kek(&self, service: &str, create_if_missing: bool) -> Result<Box<dyn KekHandle>> {
        self.check_not_refused()?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| Error::Provider("PKCS#11 session lock poisoned".into()))?;
        let open = guard
            .as_mut()
            .ok_or(Error::Provider("PKCS#11 session not available".into()))?;

        let keys = match find_key_pair_handles(&open.session, service)? {
            Some(keys) => keys,
            None if create_if_missing => generate_key_pair(open, service)?, // none exists yet and creation was requested
            None => {
                return Err(Error::KeyNotProvisioned(
                    "no PKCS#11 KEK created yet for this service",
                ))
            }
        };
        Ok(Box::new(Pkcs11Handle {
            key_id: format!("hkdfguard:{service}").into_bytes(),
            keys,
            state: Arc::clone(&self.state), // cheap refcount bump, not a clone of the underlying session
        }))
    }
}

// The CKA_LABEL used to identify a service's key pair on the token.
fn key_label(service: &str) -> String {
    format!("hkdfguard:{service}")
}

// The CKA_ID hkdfguard gives a service's key pair: a non-secret tag that,
// with the label, identifies objects this crate created.
fn key_id(service: &str) -> Vec<u8> {
    Sha256::digest(service.as_bytes()).to_vec()
}

// Looks up the service's private key object, without creating anything.
// `None` means no key pair has been generated for this service yet.
fn find_key_pair(session: &Session, service: &str) -> Result<Option<ObjectHandle>> {
    find_unique(session, ObjectClass::PRIVATE_KEY, service)
}

// The public half -- used only by `Pkcs11Handle::public_key` (the private
// key it pairs with is never extractable, so the fingerprint has to come
// from this object instead).
fn find_public_key(session: &Session, service: &str) -> Result<Option<ObjectHandle>> {
    find_unique(session, ObjectClass::PUBLIC_KEY, service)
}

/// The two halves of a service's key pair, as object handles valid for the
/// session that found them.
#[derive(Clone, Copy)]
struct KeyPair {
    private: ObjectHandle,
    public: ObjectHandle,
}

// Locates both halves of the service's key pair. `None` means neither is
// present: nothing provisioned. One half without the other is an error,
// not "absent": the token is not in a state hkdfguard produced, and
// generating a fresh pair over it would either leave two objects under the
// label (which `find_unique` then refuses) or report a fingerprint for a
// key `ecdh` does not use.
fn find_key_pair_handles(session: &Session, service: &str) -> Result<Option<KeyPair>> {
    match (find_key_pair(session, service)?, find_public_key(session, service)?) {
        (Some(private), Some(public)) => Ok(Some(KeyPair { private, public })),
        (None, None) => Ok(None),
        (Some(_), None) => Err(Error::Provider(
            "PKCS#11: this service's private key is on the token but its public key is missing; \
             the pair is unusable until an operator removes or restores it"
                .into(),
        )),
        (None, Some(_)) => Err(Error::Provider(
            "PKCS#11: this service's public key is on the token without its private key; \
             remove it before provisioning the service again"
                .into(),
        )),
    }
}

// Finds the one EC object of `class` labelled for `service`. More than one
// is an error, not a pick: which one the token lists first is up to the
// token, so the same service could get a different key from one call to
// the next -- or one planted alongside the real one. The match must also
// carry the CKA_ID `generate_key_pair` gives it. Errors never name the
// service: the C ABI logs them, and service names stay out of the log.
fn find_unique(session: &Session, class: ObjectClass, service: &str) -> Result<Option<ObjectHandle>> {
    let what = if class == ObjectClass::PRIVATE_KEY { "private key" } else { "public key" };
    let find_template = [
        Attribute::Class(class),
        Attribute::KeyType(KeyType::EC),
        Attribute::Label(key_label(service).into_bytes()),
    ];
    let found = session
        .find_objects(&find_template) // C_FindObjects
        .map_err(|e| Error::Provider(format!("PKCS#11 find_objects failed: {e}")))?;
    let handle = match found.as_slice() {
        [] => return Ok(None),
        [one] => *one,
        many => {
            return Err(Error::Provider(format!(
                "{} EC {what} objects on the token carry this service's label; refusing to choose \
                 between them -- delete the ones hkdfguard did not create",
                many.len()
            )))
        }
    };
    let attrs = session
        .get_attributes(handle, &[AttributeType::Id])
        .map_err(|e| Error::Provider(format!("PKCS#11 get_attributes (ID) failed: {e}")))?;
    let expected = key_id(service);
    if !attrs.iter().any(|a| matches!(a, Attribute::Id(id) if *id == expected)) {
        return Err(Error::Provider(format!(
            "the EC {what} carrying this service's label does not have the CKA_ID hkdfguard gives \
             its keys; refusing to use an object it did not create"
        )));
    }
    check_protections(session, handle, class)?;
    Ok(Some(handle))
}

/// The attribute values every object `generate_key_pair` makes carries, by
/// class. For the private key this is more than "locked down now":
/// `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE` are set by the token,
/// and are true only for a key that was generated on it and never had its
/// value exposed. A key imported from outside (`C_CreateObject`,
/// `C_UnwrapKey`) has them false, whatever else its template says.
fn required_protections(class: ObjectClass) -> Vec<Attribute> {
    let mut required = vec![Attribute::EcParams(P256_EC_PARAMS.to_vec()), Attribute::Token(true)];
    if class == ObjectClass::PRIVATE_KEY {
        required.extend([
            Attribute::Derive(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::AlwaysSensitive(true),
            Attribute::NeverExtractable(true),
        ]);
    }
    required
}

// Refuses an object under the service's label that lacks the protections
// hkdfguard generates its keys with -- see `required_protections`.
//
// The `CKA_ID` check before this proves nothing about provenance: the ID
// is SHA-256 of the service name, which anyone can compute. Without this
// check, anyone holding the user PIN could replace the pair with one whose
// private scalar they know, labelled and tagged to match; every new wrap
// would then go to a key they can use off the token. A PIN holder can
// already use the real key *on* the token, so this does not create a new
// boundary -- it keeps "the key never leaves the HSM" true.
fn check_protections(session: &Session, handle: ObjectHandle, class: ObjectClass) -> Result<()> {
    let what = if class == ObjectClass::PRIVATE_KEY { "private key" } else { "public key" };
    let required = required_protections(class);
    let types: Vec<AttributeType> = required.iter().map(Attribute::attribute_type).collect();
    let present = session
        .get_attributes(handle, &types)
        .map_err(|e| Error::Provider(format!("PKCS#11 get_attributes (protections) failed: {e}")))?;
    // An attribute the token won't report is left out of `present` (cryptoki
    // drops what C_GetAttributeValue marks unavailable): a failure too.
    let failing: Vec<String> = required
        .iter()
        .filter(|want| !present.contains(want))
        .map(|want| format!("{:?}", want.attribute_type()))
        .collect();
    if !failing.is_empty() {
        return Err(Error::Provider(format!(
            "the EC {what} carrying this service's label lacks the protections hkdfguard generates its keys \
             with ({}); it may have been imported or altered -- refusing to use it",
            failing.join(", ")
        )));
    }
    Ok(())
}

// Generates a new, non-extractable EC key pair on the token for `service`
// and returns both halves' handles, as found again through the read-only
// session -- so a pair that somehow isn't unique or doesn't match is
// refused here, at creation, rather than on a later call. Callers check
// (via `find_key_pair_handles`) that none exists yet -- this always
// generates a fresh pair.
//
// The read/write session it needs is opened here and closed again on
// return. It shares the read-only session's login, and that session stays
// open, so closing this one doesn't log the process out.
fn generate_key_pair(open: &OpenSession, service: &str) -> Result<KeyPair> {
    let label = key_label(service);
    let key_id = key_id(service);

    let public_template = [
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Token(true),  // persist on the token, not just this session
        Attribute::Private(false), // the public half doesn't need PKCS#11-level access restriction
        Attribute::Verify(false),  // this key pair is for ECDH, not signing/verification
        Attribute::Modifiable(false), // its label, ID and point can't be changed afterwards
        Attribute::EcParams(P256_EC_PARAMS.to_vec()), // selects the P-256 curve
        Attribute::Label(label.clone().into_bytes()),
        Attribute::Id(key_id.clone()),
    ];
    let private_template = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Token(true),        // persist on the token
        Attribute::Private(true),      // requires login to use
        Attribute::Sensitive(true),    // value can never be read out
        Attribute::Extractable(false), // and can never be wrapped/exported either
        Attribute::Derive(true),       // required: we need to use this key with C_DeriveKey (ECDH)
        Attribute::Sign(false),        // must not be usable for signing
        Attribute::Modifiable(false),  // none of the above can be changed afterwards (e.g. CKA_SIGN)
        Attribute::Copyable(false),    // nor carried into a copy made with different attributes
        Attribute::Label(label.into_bytes()),
        Attribute::Id(key_id),
    ];

    // PKCS#11 has no create-if-absent: two processes (two hosts sharing a
    // network HSM, two services on one host) that both find no key for the
    // service can both generate one. The token then holds two pairs under
    // the label, `find_unique` refuses the service for good, and deleting
    // the wrong pair would lose whatever the other process already wrapped
    // under it. So after generating, look again: if the label is no longer
    // unique, this process yields -- it destroys the pair *it* made and
    // uses the one the other process left. Should both yield at once, the
    // second attempt generates again; if that collides too, the operator
    // sees an error and reruns provision.
    for attempt in 1..=2 {
        {
            let rw = open
                .pkcs11
                .open_rw_session(open.slot)
                .map_err(|e| Error::Provider(format!("PKCS#11 could not open a read/write session to generate a key: {e}")))?;
            let (public, private) = rw
                .generate_key_pair(
                    &Mechanism::EccKeyPairGen, // C_GenerateKeyPair with the EC key pair generation mechanism
                    &public_template,
                    &private_template,
                )
                .map_err(|e| Error::Provider(format!("PKCS#11 EC key pair generation failed: {e}")))?;

            let unique = count_labelled(&rw, ObjectClass::PRIVATE_KEY, service)? == 1
                && count_labelled(&rw, ObjectClass::PUBLIC_KEY, service)? == 1;
            if !unique {
                for ours in [private, public] {
                    rw.destroy_object(ours).map_err(|e| {
                        Error::Provider(format!(
                            "PKCS#11: another process created this service's key pair concurrently, and this \
                             process's duplicate could not be removed: {e}; delete it by hand"
                        ))
                    })?;
                }
                log::warn!(
                    "hkdfguard: another process created this service's PKCS#11 key pair at the same time \
                     (attempt {attempt}); this process discarded its own pair in favor of that one"
                );
            }
        } // the read/write session closes here; its object handles are no longer valid

        // Through the read-only session, whose handles the caller keeps.
        if let Some(keys) = find_key_pair_handles(&open.session, service)? {
            return Ok(keys);
        }
        // Nothing left: the other process yielded at the same moment. Generate again.
    }
    Err(Error::Provider(
        "PKCS#11: the key pair just generated could not be found (repeated concurrent creation); run provision again".into(),
    ))
}

// How many EC objects of `class` carry the service's label.
fn count_labelled(session: &Session, class: ObjectClass, service: &str) -> Result<usize> {
    session
        .find_objects(&[
            Attribute::Class(class),
            Attribute::KeyType(KeyType::EC),
            Attribute::Label(key_label(service).into_bytes()),
        ])
        .map(|found| found.len())
        .map_err(|e| Error::Provider(format!("PKCS#11 find_objects failed: {e}")))
}

// Reads a single attribute (here, always CKA_VALUE) off a PKCS#11 object
// and returns its raw bytes, validating the expected length. The bytes
// are wrapped in `Zeroizing` immediately -- `get_attributes` necessarily
// returns a heap `Vec<u8>` (the cryptoki crate allocates it to marshal
// the C_GetAttributeValue result), and since it holds live key-derivation
// output (the ECDH shared secret, in this module's only caller), it must
// not be dropped un-scrubbed.
fn read_value(session: &Session, handle: ObjectHandle, expected_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let attrs = session
        .get_attributes(handle, &[AttributeType::Value]) // C_GetAttributeValue for just CKA_VALUE
        .map_err(|e| Error::Provider(format!("PKCS#11 get_attributes failed: {e}")))?;

    for attr in attrs {
        if let Attribute::Value(bytes) = attr {
            // Wrap every CKA_VALUE the moment it's taken out of the
            // attribute list, so one of an unexpected size is still
            // zeroed as it's dropped here rather than freed with the
            // derived secret still in it.
            let bytes = Zeroizing::new(bytes);
            if bytes.len() == expected_len {
                return Ok(bytes); // found a CKA_VALUE of the expected size
            }
        }
    }
    Err(Error::Provider(
        "PKCS#11 token did not return a CKA_VALUE for derived secret".into(), // shouldn't happen given how `derive_template` was built
    ))
}

// Reads the CKA_EC_POINT attribute off a public-key object -- unlike
// CKA_VALUE on a private key, this is never sensitive (it's the whole
// point of a public key), so no `Zeroizing` wrapper is needed here.
fn read_ec_point(session: &Session, handle: ObjectHandle) -> Result<Vec<u8>> {
    let attrs = session
        .get_attributes(handle, &[AttributeType::EcPoint]) // C_GetAttributeValue for CKA_EC_POINT
        .map_err(|e| Error::Provider(format!("PKCS#11 get_attributes (EC_POINT) failed: {e}")))?;

    for attr in attrs {
        if let Attribute::EcPoint(bytes) = attr {
            return Ok(bytes);
        }
    }
    Err(Error::Provider(
        "PKCS#11 token did not return a CKA_EC_POINT for the public key".into(),
    ))
}

// Parses a PKCS#11 CKA_EC_POINT attribute value into a `p256::PublicKey`.
// The PKCS#11 spec defines this as the ANSI X9.62 ECPoint encoding, which
// for an uncompressed point *is* the raw `0x04 || X || Y` bytes -- but some
// tokens/implementations additionally DER-wrap that in an OCTET STRING
// (tag 0x04, length 0x41 = 65), which happens to share its leading byte
// with the uncompressed-point marker, so length (65 vs 67) is what
// actually disambiguates the two rather than the leading byte.
fn parse_ec_point(bytes: &[u8]) -> Result<PublicKey> {
    let raw: &[u8] = match bytes.len() {
        UNCOMPRESSED_POINT_LEN => bytes,
        n if n == UNCOMPRESSED_POINT_LEN + 2
            && bytes[0] == 0x04
            && bytes[1] as usize == UNCOMPRESSED_POINT_LEN =>
        {
            &bytes[2..] // strip the outer DER OCTET STRING tag + length byte
        }
        n => {
            return Err(Error::Provider(format!(
                "PKCS#11 token returned an EC point of unexpected length {n}"
            )))
        }
    };
    PublicKey::from_sec1_bytes(raw)
        .map_err(|_| Error::Provider("PKCS#11 token returned an invalid EC point".into()))
}

#[cfg(test)]
mod tests {
    use super::*; // bring `Pkcs11Provider` etc. into scope
    use secrecy::ExposeSecret;
    use std::os::unix::fs::PermissionsExt;

    // In a private directory of its own: `$TMPDIR` itself is usually
    // `/tmp`, which anyone can write to, and the PIN's location is checked.
    struct PinFile {
        dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl PinFile {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    fn pin_file(contents: &[u8], mode: u32) -> PinFile {
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join("pkcs11.pin");
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        PinFile { dir, path }
    }

    #[test]
    fn pin_file_in_a_directory_others_can_write_is_rejected() {
        let f = pin_file(b"1234\n", 0o600);
        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = read_pin_file(f.path()).expect_err("someone else could swap in a wrong PIN");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn pin_file_is_read_and_one_trailing_newline_stripped() {
        let f = pin_file(b"1234\n", 0o600);
        assert_eq!(read_pin_file(f.path()).unwrap().expose_secret(), "1234");

        let f = pin_file(b"5678\r\n", 0o400);
        assert_eq!(read_pin_file(f.path()).unwrap().expose_secret(), "5678");

        let f = pin_file(b"no-newline", 0o600);
        assert_eq!(read_pin_file(f.path()).unwrap().expose_secret(), "no-newline");
    }

    #[test]
    fn pin_file_readable_by_group_or_others_is_rejected() {
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        // 0640 is the supported layout for a *root-owned* PIN (group = the
        // service's group); on a file the service owns, it's a leak.
        let modes: &[u32] = if root { &[0o604, 0o644, 0o660] } else { &[0o640, 0o604, 0o644, 0o660] };
        for &mode in modes {
            let f = pin_file(b"1234\n", mode);
            let err = read_pin_file(f.path()).expect_err("must be rejected");
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "mode {mode:o}");
        }
    }

    #[test]
    fn empty_or_non_utf8_pin_file_is_rejected() {
        let f = pin_file(b"\n", 0o600);
        assert_eq!(read_pin_file(f.path()).err().unwrap().kind(), std::io::ErrorKind::InvalidData);

        let f = pin_file(&[0xFF, 0xFE, b'\n'], 0o600);
        assert_eq!(read_pin_file(f.path()).err().unwrap().kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_rejected_pin_latches_until_the_pin_file_changes() {
        let path = Path::new("/nonexistent/hkdfguard-latch-test-a/pkcs11.pin");
        let first = FileIdentity { dev: 1, ino: 2, len: 5, mtime: (10, 0) };
        let v1 = Some(first);
        assert!(pin_login_blocked(path, v1).is_none(), "nothing latched yet");

        latch_pin_login(path, v1, "rejected".into());
        assert_eq!(pin_login_blocked(path, v1).as_deref(), Some("rejected"));
        assert!(pin_login_blocked(path, v1).is_some(), "stays latched while the file is unchanged");

        let v2 = Some(FileIdentity { mtime: (11, 0), ..first }); // the operator rewrote the file
        assert!(pin_login_blocked(path, v2).is_none(), "a changed file clears the latch, so one login can try it");
        assert!(pin_login_blocked(path, v1).is_none(), "and it stays cleared");
    }

    #[test]
    fn pin_latch_is_per_pin_file_and_survives_a_vanished_file() {
        let a = Path::new("/nonexistent/hkdfguard-latch-test-b/a.pin");
        let b = Path::new("/nonexistent/hkdfguard-latch-test-b/b.pin");
        let id = Some(FileIdentity { dev: 1, ino: 9, len: 5, mtime: (1, 1) });
        latch_pin_login(a, id, "a rejected".into());
        assert!(pin_login_blocked(b, id).is_none(), "another PIN file is unaffected");
        assert!(pin_login_blocked(a, id).is_some());

        // A file that cannot be stat'ed now (identity None) differs from
        // the recorded identity, so the latch clears -- the file was
        // replaced or removed, which is a change.
        assert!(pin_login_blocked(a, None).is_none());

        // Latching with no identity (the file vanished before it was
        // stat'ed) still blocks while it stays unreadable.
        latch_pin_login(a, None, "a rejected again".into());
        assert!(pin_login_blocked(a, None).is_some());
        assert!(pin_login_blocked(a, id).is_none(), "and clears once a file is there");
    }

    #[test]
    fn missing_pin_file_is_not_found() {
        let err = read_pin_file(Path::new("/nonexistent-hkdfguard-pin-file")).err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    fn tok(label: &str, serial: &str) -> (String, String) {
        (label.to_string(), serial.to_string())
    }

    #[test]
    fn a_configured_label_or_serial_must_match_exactly_one_token() {
        let tokens = [tok("prod-kek", "1111"), tok("staging", "2222"), tok("prod-kek", "3333")];
        assert_eq!(select_token(&tokens, Some("staging"), None), Ok(1));
        assert_eq!(select_token(&tokens, None, Some("3333")), Ok(2));
        assert_eq!(select_token(&tokens, Some("prod-kek"), Some("1111")), Ok(0));
        assert!(select_token(&tokens, Some("prod-kek"), None).is_err(), "two tokens share the label");
        assert!(select_token(&tokens, Some("missing"), None).is_err());
        assert!(select_token(&tokens, Some("staging"), Some("1111")).is_err(), "label and serial must both match");
    }

    #[test]
    fn without_a_label_there_must_be_exactly_one_token() {
        assert_eq!(select_token(&[tok("only", "1")], None, None), Ok(0));
        assert!(select_token(&[], None, None).is_err());
        assert!(
            select_token(&[tok("a", "1"), tok("b", "2")], None, None).is_err(),
            "with several tokens, picking the first would make the key's home depend on enumeration order"
        );
    }

    #[test]
    #[serial_test::serial]
    fn without_a_module_in_policy_pkcs11_is_absent_however_it_is_built() {
        // No default module search in any build: SoftHSM2 being installed
        // must never make it the "HSM".
        let _policy = crate::policy::test_support::TestPolicy::exact("[selection]\nmode = \"prefer\"\n"); // not layered: the harness's may name a module
        let provider = Pkcs11Provider::new();
        assert!(!provider.probe());
    }

    #[test]
    fn module_path_must_be_absolute() {
        assert!(validate_module_path(Path::new("libsofthsm2.so")).is_err());
        assert!(validate_module_path(Path::new("./libsofthsm2.so")).is_err());
    }

    #[test]
    fn module_path_owned_by_non_root_is_rejected() {
        if crate::secure_file::skip_as_root() {
            return; // as root, any temp file is root-owned, so there's nothing to reject
        }
        let f = pin_file(b"not really a module", 0o755);
        let err = validate_module_path(f.path()).unwrap_err();
        assert!(err.contains("refusing"), "unexpected error: {err}");
    }

    #[test]
    fn root_owned_system_binary_passes_path_validation() {
        // Validation only -- nothing is loaded. /bin/sh is root-owned,
        // 0755, in a root-owned 0755 directory on every Unix this builds on
        // (and canonicalizing through a merged-/usr symlink still lands in
        // a root-owned directory).
        let checked = validate_module_path(Path::new("/bin/sh")).unwrap();
        assert!(checked.is_absolute());
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"] // skipped by default; run explicitly with `-- --ignored`
    fn same_service_reuses_same_key_pair() {
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");

        let eph = p256::SecretKey::random(&mut rand_core::OsRng); // stand-in "caller" ephemeral key for this test
        let eph_pub = eph.public_key();

        let h1 = provider.load_kek("com.company.orders", true).unwrap(); // first call: generates the key pair on the token
        let h2 = provider.load_kek("com.company.orders", true).unwrap(); // second call: must find and reuse the same one
        assert_eq!(*h1.ecdh(&eph_pub).unwrap(), *h2.ecdh(&eph_pub).unwrap()); // same underlying key -> same shared secret

        // `public_key()` must report the exact key `ecdh` actually used --
        // verified independently, by doing ECDH from the ephemeral side
        // against the reported public key and checking it agrees with
        // `h1.ecdh` above.
        let reported_public = h1.public_key().unwrap();
        let via_reported = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), reported_public.as_affine());
        assert_eq!(h1.ecdh(&eph_pub).unwrap().as_slice(), via_reported.raw_secret_bytes().as_slice());
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn load_kek_creates_only_when_asked_and_kek_exists_tracks_it() {
        // The create_kek -> kek_exists -> wrap sequence the C ABI drives, at
        // the provider level. An earlier revision deferred the token lookup
        // to `ecdh`, so `load_kek(_, true)` created nothing (create_kek
        // reported success with no key) and `load_kek(_, false)` never
        // declined (the chain could not move past PKCS#11).
        let service = "com.hkdfguard.test.provisioning";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        with_open(&provider, |open| destroy_all_for(open, service));

        assert!(!provider.kek_exists(service).unwrap());
        assert!(
            matches!(provider.load_kek(service, false), Err(Error::KeyNotProvisioned(_))),
            "loading without creating must decline, so the chain can move on"
        );
        assert!(!provider.kek_exists(service).unwrap(), "a declined load must not have created anything");

        let created = provider.load_kek(service, true).unwrap(); // hkdfguard_create_kek's path
        assert!(provider.kek_exists(service).unwrap(), "create must leave a key the token reports");
        let loaded = provider.load_kek(service, false).unwrap(); // hkdfguard_wrap_dek's path
        let eph = p256::SecretKey::random(&mut rand_core::OsRng).public_key();
        assert_eq!(*created.ecdh(&eph).unwrap(), *loaded.ecdh(&eph).unwrap(), "both handles must drive the same key");
        assert_eq!(created.public_key().unwrap(), loaded.public_key().unwrap());

        with_open(&provider, |open| destroy_all_for(open, service));
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn concurrent_providers_share_one_initialized_module() {
        // Every C ABI call constructs its own provider; several at once must
        // all work. An earlier revision ran C_Initialize/C_Finalize per
        // provider, so overlapping calls finalized the module under each
        // other's open sessions and failed (or crashed the module).
        let service = "com.company.orders";
        let eph = p256::SecretKey::random(&mut rand_core::OsRng).public_key();
        let expected = {
            let setup = Pkcs11Provider::new();
            assert!(setup.probe(), "no PKCS#11 session available");
            *setup.load_kek(service, true).unwrap().ecdh(&eph).unwrap()
        };

        let threads: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(move || {
                    (0..8)
                        .map(|_| {
                            let provider = Pkcs11Provider::new();
                            provider.load_kek(service, false).and_then(|h| h.ecdh(&eph)).map(|z| *z)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for thread in threads {
            for result in thread.join().expect("a thread panicked") {
                assert_eq!(result.expect("a concurrent PKCS#11 call failed"), expected);
            }
        }
    }

    /// The SoftHSM2 token label both test harnesses create --
    /// docker/entrypoint-test.sh and scripts/native-tpm-test.sh. Change all
    /// three together.
    const SOFTHSM_TEST_TOKEN_LABEL: &str = "hkdfguard-test";

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + the harness token (SOFTHSM_TEST_TOKEN_LABEL)"]
    #[serial_test::serial]
    fn policy_selects_the_module_and_the_token_by_label() {
        // The harness policy names the module and PIN file; each case here
        // layers its own token label over it, exactly as production reads it.
        use crate::policy::test_support::TestPolicy;
        let policy_for = |label: &str| {
            format!("[selection]\nmode = \"require\"\nprovider = \"pkcs11\"\n[pkcs11]\ntoken_label = \"{label}\"\n")
        };

        let matched = {
            let _policy = TestPolicy::write(&policy_for(SOFTHSM_TEST_TOKEN_LABEL));
            Pkcs11Provider::new().probe()
        };
        let (unmatched_present, unmatched_load) = {
            let _policy = TestPolicy::write(&policy_for("no-such-token"));
            let unmatched = Pkcs11Provider::new();
            (unmatched.probe(), unmatched.load_kek("com.company.orders", false).err())
        };

        assert!(matched, "the token labelled {SOFTHSM_TEST_TOKEN_LABEL} must be selected");
        // Configured but unusable: refused -- present, so the chain stops
        // here, and failing every call -- never another token, and never
        // a quiet fall-through to a weaker provider.
        assert!(unmatched_present, "a configured PKCS#11 that can't be used is refused, not absent");
        match unmatched_load {
            Some(Error::Provider(msg)) => assert!(msg.contains("no-such-token"), "unexpected: {msg}"),
            other => panic!("a label that matches no token must fail the call, got {other:?}"),
        }
    }

    // Runs `f` with the provider's open session (the provider must be
    // connected).
    fn with_open<T>(provider: &Pkcs11Provider, f: impl FnOnce(&OpenSession) -> T) -> T {
        let guard = provider.state.lock().unwrap();
        f(guard.as_ref().expect("no PKCS#11 session available"))
    }

    // Removes every object labelled for `service`, so a test leaves the
    // token as it found it (and can be rerun against a persistent one).
    fn destroy_all_for(open: &OpenSession, service: &str) {
        let rw = open.pkcs11.open_rw_session(open.slot).unwrap();
        let found = rw.find_objects(&[Attribute::Label(key_label(service).into_bytes())]).unwrap();
        for object in found {
            rw.destroy_object(object).unwrap();
        }
    }

    // Generates an EC key pair labelled for `service` straight on the
    // token, the way something other than hkdfguard might, with `id`.
    fn plant_key_pair(open: &OpenSession, service: &str, id: Vec<u8>) {
        plant_key_pair_with(open, service, id, &[]);
    }

    // As `plant_key_pair`, with `extra_private` added to the private key's template.
    fn plant_key_pair_with(open: &OpenSession, service: &str, id: Vec<u8>, extra_private: &[Attribute]) {
        let rw = open.pkcs11.open_rw_session(open.slot).unwrap();
        let label = key_label(service).into_bytes();
        let mut private = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Derive(true),
            Attribute::Label(label.clone()),
            Attribute::Id(id.clone()),
        ];
        private.extend_from_slice(extra_private);
        rw.generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::EcParams(P256_EC_PARAMS.to_vec()),
                Attribute::Label(label),
                Attribute::Id(id),
            ],
            &private,
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn a_key_with_the_right_label_and_id_but_weaker_protections_is_refused() {
        // Right label, right CKA_ID -- which anyone can compute -- but
        // extractable: not a key hkdfguard generated. Must be refused
        // before it is used, even with creation allowed.
        let service = "com.hkdfguard.test.weakkey";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        with_open(&provider, |open| {
            destroy_all_for(open, service);
            plant_key_pair_with(open, service, key_id(service), &[Attribute::Sensitive(false), Attribute::Extractable(true)]);
        });

        let err = provider.load_kek(service, true).err().expect("a weakly protected key must be refused");
        let msg = err.to_string();
        assert!(msg.contains("lacks the protections"), "unexpected error: {msg}");
        assert!(msg.contains("Extractable"), "the error must say which protection is missing: {msg}");
        assert!(!msg.contains(service), "errors must not name the service: {msg}");
        assert!(provider.kek_exists(service).is_err(), "kek_exists must not answer either way");

        with_open(&provider, |open| destroy_all_for(open, service));
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn generated_keys_are_locked_down_and_the_session_is_read_only() {
        let service = "com.hkdfguard.test.lockeddown";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        with_open(&provider, |open| destroy_all_for(open, service));

        let eph = p256::SecretKey::random(&mut rand_core::OsRng).public_key();
        provider.load_kek(service, true).unwrap().ecdh(&eph).unwrap(); // generates the pair

        with_open(&provider, |open| {
            let info = open.session.get_session_info().unwrap();
            assert!(!info.read_write(), "the provider's own session must be read-only");

            let private = find_key_pair(&open.session, service).unwrap().unwrap();
            let attrs = open
                .session
                .get_attributes(
                    private,
                    &[AttributeType::Modifiable, AttributeType::Copyable, AttributeType::Sensitive, AttributeType::Extractable],
                )
                .unwrap();
            for expected in [
                Attribute::Modifiable(false),
                Attribute::Copyable(false),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
            ] {
                assert!(attrs.contains(&expected), "private key must have {expected:?}; has {attrs:?}");
            }
            let public = find_public_key(&open.session, service).unwrap().unwrap();
            let attrs = open.session.get_attributes(public, &[AttributeType::Modifiable]).unwrap();
            assert!(attrs.contains(&Attribute::Modifiable(false)), "public key must be unmodifiable; has {attrs:?}");

            destroy_all_for(open, service);
        });
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn a_second_object_with_the_same_label_is_refused_not_chosen_between() {
        let service = "com.hkdfguard.test.duplicate";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        with_open(&provider, |open| destroy_all_for(open, service));

        let eph = p256::SecretKey::random(&mut rand_core::OsRng).public_key();
        provider.load_kek(service, true).unwrap().ecdh(&eph).unwrap();
        with_open(&provider, |open| plant_key_pair(open, service, key_id(service)));

        // Refused when the key is loaded -- before any ECDH is attempted.
        let err = provider.load_kek(service, false).err().expect("a duplicate label must be refused");
        assert!(err.to_string().contains("refusing to choose"), "unexpected error: {err}");
        assert!(!err.to_string().contains(service), "errors must not name the service: {err}");
        assert!(provider.kek_exists(service).is_err(), "kek_exists must not answer either way");

        with_open(&provider, |open| destroy_all_for(open, service));
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn a_key_with_the_label_but_not_the_id_is_refused() {
        let service = "com.hkdfguard.test.foreignid";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        with_open(&provider, |open| {
            destroy_all_for(open, service);
            plant_key_pair(open, service, b"not hkdfguard's".to_vec());
        });

        // Refused when the key is loaded, even with creation allowed: a
        // foreign object under the label is never silently generated over.
        let err = provider.load_kek(service, true).err().expect("a foreign CKA_ID must be refused");
        assert!(err.to_string().contains("CKA_ID"), "unexpected error: {err}");

        with_open(&provider, |open| destroy_all_for(open, service));
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    fn token_accepts_hashed_payload_points() {
        // Same check as the TPM2 provider's own version: the
        // forgery-resistant protocol needs CKM_ECDH1_DERIVE against a
        // caller-supplied point hashed from the payload salt, so confirm
        // this module accepts such points rather than assuming. A module
        // that rejected them would make the construction unusable on
        // that HSM.
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");

        let h = crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap();

        let handle = provider.load_kek("com.company.orders", true).unwrap();
        let z1 = handle.ecdh(&h).unwrap();
        let z2 = handle.ecdh(&h).unwrap();
        assert_eq!(*z1, *z2, "ECDH against the same point must be repeatable for the same key");
        assert_ne!(z1.as_slice(), [0u8; 32], "shared secret must not be all zeroes");

        // A different service's key must yield a different Z against the
        // same point.
        let other = provider.load_kek("com.company.billing", true).unwrap();
        assert_ne!(*z1, *other.ecdh(&h).unwrap(), "different keys must yield different Z against the same point");

        // A different salt's point yields a different Z for the same key.
        let h2 = crate::crypto::payload_ecdh_point(&[0x43u8; 32]).unwrap();
        assert_ne!(*z1, *handle.ecdh(&h2).unwrap(), "different salts must yield different Z");
    }
}

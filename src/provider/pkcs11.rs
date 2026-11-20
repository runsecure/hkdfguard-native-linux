//! Provider 2: PKCS#11 (used when TPM2 is unavailable).
//!
//! ```text
//!  ______________________________________________________________________
//! | HARDWARE/MODULE-DEPENDENT CODE                                        |
//! |                                                                        |
//! | Verified: built against `cryptoki` 0.12, and the `#[ignore]`d tests  |
//! | pass against a real SoftHSM2 token -- C_GenerateKey +               |
//! | CKM_SHA256_HMAC executed for real, matching software HMAC-SHA-256.  |
//! | Not yet exercised against a hardware HSM/YubiHSM; re-run             |
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
//!   above it must be owned by root and not writable by group or others,
//!   sticky or not (so never anywhere under `/tmp`) -- see
//!   [`validate_module_path`]: the module is `dlopen`ed into this process. Only the module file
//!   itself is checked: the libraries *it* depends on are found the usual
//!   way (its RPATH/RUNPATH, `LD_LIBRARY_PATH`, the loader cache). That is
//!   the same trust any library the host process loads gets, not a
//!   boundary this crate draws -- whoever controls the process's
//!   environment already controls what runs in it -- but keep a vendor
//!   module's dependencies in root-owned locations too.
//!
//!   Two limits of that check. **The module's own configuration is not
//!   covered.** Most modules find their token through the environment
//!   (`SOFTHSM2_CONF`, `YUBIHSM_PKCS11_CONF`, `ChrystokiConfigurationPath`,
//!   `OPENSC_CONF`, the `CKNFAST_*` variables, ...), and for a network HSM
//!   that names the host the PIN is sent to. Whoever sets the service's
//!   environment can point the module at a token they run, and `C_Login`
//!   then hands it the root-only PIN; the token's label and serial are its
//!   own claims, so they can't tell. Set the module's configuration in a
//!   root-owned file the service's environment can't override. **A
//!   sticky directory on a read-only mount passes whatever its write
//!   bits**, as everywhere in this crate: a read-only mount's mode bits don't say who
//!   can write the same directory through another, writable mount of it
//!   (a read-only bind mount of a host directory, say). For code that is
//!   loaded and run, keep the module's directories root-owned and
//!   unwritable on every mount, not only the one this process sees.
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
//!   and inherited by children); `HKDFGUARD_PKCS11_PIN`, if set, is
//!   ignored with a warning.
//!
//! ## Design
//!
//! For each service, finds (or generates, if absent) a **non-extractable**
//! token-persistent 256-bit generic secret key labelled
//! `hkdfguard:<service>` (`CKA_TOKEN=true`, `CKA_SENSITIVE=true`,
//! `CKA_EXTRACTABLE=false`, `CKA_SIGN=true` and no other use, and
//! `CKA_MODIFIABLE=false` / `CKA_COPYABLE=false`, so those can't be
//! relaxed afterwards). Exactly one such object may carry that label, with
//! the `CKA_ID` hkdfguard gives it: anything else is refused rather than
//! guessed between. The session is read-only; a read/write one is opened
//! only for the moment it takes to generate a key. The PRF is a
//! single-part `C_Sign` with `CKM_SHA256_HMAC`, which returns only the
//! HMAC: the key never leaves the token. Every PKCS#11 token since v2.20
//! supports both mechanisms; SoftHSM2 needs the key to be at least 32
//! bytes, as it is.
//!
//! A key found under a service's label is used only if it still carries
//! those protections -- not modifiable or copyable included -- and
//! `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE` and `CKA_LOCAL`, which
//! the token sets only on a key it generated itself and never exposed --
//! so an imported or derived key, labelled and tagged to match, is refused
//! (see `check_protections`).
//! It is `CKA_PRIVATE`, and only private objects are ever looked up, so
//! nothing made by a session without the PIN is seen at all (see
//! `labelled_template`).
//!
//! A wrong PIN is tried once per process: after the token rejects it, this
//! process attempts no further login with that PIN file until the file
//! changes, and a token that reports its user PIN locked or on its final
//! attempt is refused before any login (see [`PIN_LATCHES`]). That bounds
//! one process, not a host: every worker of a prefork server, and every
//! start of a service in a restart loop, is a new process with one attempt
//! to spend, and not every token reports its final attempt. With
//! `pkcs11.pin_state_dir` set, the rejection is recorded for all of them,
//! and a wrong PIN then costs one attempt in total (see
//! `SHARED_LATCH_FILE`). Two processes generating a service's key at
//! the same moment is detected after the fact, and the later one discards
//! its own key rather than leaving two under the label (see
//! `generate_key`).
//!
//! ## What the PIN decides, and what pinning adds
//!
//! The token knows one authority for these keys: its user PIN. Every
//! service that uses the token must be able to read the PIN file, and
//! whoever holds the PIN can drive the token without this library --
//! delete a service's key, or delete it and generate another under the
//! same label, which would pass every check above. So the production
//! security model's "only root creates or retires a KEK" is this library's
//! own rule here (`hkdfguard_create_kek` and `retire` refuse anyone else);
//! the token doesn't enforce it, and services sharing one token are kept
//! apart by labels alone. No PIN holder can learn a key's value.
//!
//! `pkcs11.pinned_keys` is what root can add: the fingerprint of each
//! service's key, recorded in the policy only root writes. A key with any
//! other fingerprint is then refused, and so is a pinned service whose key
//! is gone -- an error, never "no key here", so the provider chain doesn't
//! hand the service to a weaker provider. `pkcs11.require_pinned_keys`
//! makes the pins an allowlist (see [`Pins`]).
//!
//! `load_kek` locates the key (or generates it, when creation was asked
//! for) up front and hands back a handle holding its object handle, so
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
//! initialized once per process and never finalized (see [`MODULES`]); a
//! child created with `fork()` initializes it again for itself, as
//! PKCS#11 asks.
//! Finalizing per call, while another thread's call is inside the module,
//! is undefined behavior and in practice fails both calls. Because a login
//! is per application per token, overlapping calls share one logged-in
//! state; `C_Login` answering "already logged in" is treated as success,
//! nothing ever calls `C_Logout`, and the login ends when the process's
//! last session on the token closes.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::{Backend, KekHandle, KekProvider, PrfOutput, ProviderType, KEK_LEN}; // traits/types this module implements
use sha2::{Digest as ShaDigest, Sha256}; // used for the CKA_ID tag (aliased to avoid clashing with cryptoki's own naming)
use std::path::{Path, PathBuf}; // module-path validation and PIN-file location
use std::sync::{Arc, Mutex, PoisonError}; // shared, lock-protected PKCS#11 session, and the process-wide module registry
use zeroize::Zeroizing; // scrubs each HMAC output read off the token as soon as it's no longer needed

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11}; // loads the PKCS#11 module and initializes the library
use cryptoki::error::{Error as CryptokiError, RvError}; // to recognize the two return codes that mean "already done" rather than failure
use cryptoki::mechanism::Mechanism; // the mechanism enum (GenericSecretKeyGen, Sha256Hmac, ...)
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle}; // PKCS#11 object attributes/handles
use cryptoki::session::{Session, SessionState, UserType}; // an open session against a slot/token, its login state, and the login role
use cryptoki::slot::Slot; // identifies a PKCS#11 slot
use cryptoki::types::AuthPin; // wraps a PIN for login

// The open, logged-in, read-only session, plus what it takes to open a
// short-lived read/write one on the same token when a key has to be
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
    /// Proof the login hasn't ended since this call logged in; `None` on a
    /// token that can't hold one (see [`LoginWitness`]).
    witness: Option<LoginWitness>,
}

/// A private session object, created right after this call's login, that
/// shows whether the process has been logged out of the token since.
///
/// A login is the application's, not a session's, so something else in the
/// process using the same module -- the host application, another library
/// -- can call `C_Logout` underneath a call, and `C_Login` again. While it
/// is logged out the token hides every private object, so a search for a
/// service's key comes back empty. Checking the session state after the
/// search catches a logout that is still in effect, but not one followed
/// by a new login before the check. This does: `C_Logout` destroys every
/// private session object the application has, and a later login doesn't
/// bring them back. So if this object is still there, with the random value
/// it was created with, the login was never interrupted, and an empty search
/// really means no key.
///
/// It is a `CKO_DATA` object, `CKA_TOKEN` false, so it never reaches the
/// token's storage and goes away when the session closes.
struct LoginWitness {
    handle: ObjectHandle,
    value: [u8; 16],
}

impl LoginWitness {
    /// `Err` saying why if it couldn't create one.
    fn create(session: &Session) -> std::result::Result<LoginWitness, String> {
        let mut value = [0u8; 16];
        // A random value, so an object that happens to reuse the handle
        // after a logout can't pass for this one. Not a secret.
        getrandom::fill(&mut value).map_err(|e| format!("no random value for it: {e}"))?;
        let handle = session
            .create_object(&[
                Attribute::Class(ObjectClass::DATA),
                Attribute::Token(false),
                Attribute::Private(true),
                Attribute::Label(b"hkdfguard login witness".to_vec()),
                Attribute::Value(value.to_vec()),
            ])
            .map_err(|e| e.to_string())?;
        Ok(LoginWitness { handle, value })
    }

    /// Whether the object is still there with its value: no logout has
    /// happened since it was created.
    fn intact(&self, session: &Session) -> bool {
        matches!(
            session.get_attributes(self.handle, &[AttributeType::Value]).as_deref(),
            Ok([Attribute::Value(v)]) if v.as_slice() == self.value
        )
    }
}

/// Every PKCS#11 module this process has loaded and initialized, by
/// canonical path. Kept for the life of the process and never finalized.
///
/// `C_Initialize` and `C_Finalize` act on the module as a whole, for the
/// whole process -- not on one caller's handle. Doing them per call is
/// unsafe the moment two calls overlap: the
/// second `C_Initialize` fails with `CKR_CRYPTOKI_ALREADY_INITIALIZED`, the
/// failed context is dropped, and `cryptoki`'s drop runs `C_Finalize` --
/// tearing the module down under the first call's open session (undefined
/// behavior per the PKCS#11 specification; a crash on some modules). So a
/// module is initialized once and left so. This is a library handle, not
/// authority: sessions and logins are still opened per call and closed
/// when the call's provider drops (see [`OpenSession`]), and a login lasts
/// only while the process has a session open on the token.
///
/// Each entry also records the process that initialized it. PKCS#11 asks a
/// child created with `fork()` to call `C_Initialize` itself before using
/// a module it inherited: the parent's sessions, logins and (for a network
/// HSM) connections are not the child's, and most modules refuse every
/// call from a child that hasn't, with `CKR_CRYPTOKI_NOT_INITIALIZED`. So
/// an entry from another pid is initialized again before it is handed out
/// -- once per process, like the first time. Forking is supported from a
/// process with one thread, as POSIX only lets a child of a multithreaded
/// process call async-signal-safe functions until it `exec`s; a lock some
/// other thread held at the fork would stay held in the child.
static MODULES: Mutex<Vec<Module>> = Mutex::new(Vec::new());

struct Module {
    path: PathBuf,
    pkcs11: Pkcs11,
    /// The process that last ran `C_Initialize` on it (or found it already
    /// initialized).
    initialized_by: libc::pid_t,
}

fn this_process() -> libc::pid_t {
    // SAFETY: getpid takes no arguments and cannot fail.
    unsafe { libc::getpid() }
}

// `C_Initialize`, telling the module it may be called from several OS
// threads. "Already initialized" is success: something else in this
// process (the host application, another library) initialized the module,
// or the module is not fork-aware and still counts the parent's
// initialization. It is usable as it is, and must never be finalized by
// code that did not initialize it -- which keeping it in the registry
// guarantees.
fn initialize_module(pkcs11: &Pkcs11, checked: &Path) -> std::result::Result<(), String> {
    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) => Ok(()),
        Err(CryptokiError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {
            log::debug!("hkdfguard: PKCS#11 module {} was already initialized in this process", checked.display());
            Ok(())
        }
        Err(e) => Err(format!("C_Initialize failed: {e}")),
    }
}

// The initialized context for the module at `checked` (a canonical path
// that has passed `validate_module_path`), loading and initializing it the
// first time this process asks for it. Serialized by the registry lock, so
// two first-time callers cannot both try to initialize.
fn load_module(checked: &Path) -> std::result::Result<Pkcs11, String> {
    let mut modules = MODULES.lock().unwrap_or_else(PoisonError::into_inner);
    let pid = this_process();
    if let Some(module) = modules.iter_mut().find(|m| m.path == checked) {
        if module.initialized_by != pid {
            // Inherited from the process this one was forked from. A
            // failure leaves the entry as it was, so the next call tries
            // again.
            initialize_module(&module.pkcs11, checked)
                .map_err(|e| format!("{e} (re-initializing the module in a process forked from the one that loaded it)"))?;
            module.initialized_by = pid;
        }
        return Ok(module.pkcs11.clone()); // a clone shares the one underlying library handle
    }
    let pkcs11 = Pkcs11::new(checked).map_err(|e| format!("could not load module {}: {e}", checked.display()))?;
    // On failure `pkcs11` drops, which unloads the module without calling
    // C_Finalize (cryptoki finalizes only when asked to explicitly).
    initialize_module(&pkcs11, checked)?;
    modules.push(Module { path: checked.to_path_buf(), pkcs11: pkcs11.clone(), initialized_by: pid });
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
/// absolute; every directory that decides what it names -- each one it
/// passes through, and each one a symlink along the way lives in, every
/// one up to `/` -- must be owned by root and not writable by group or
/// others, sticky or not (see [`crate::secure_file::resolve_trusted`]); and
/// the module file it resolves to must be owned by root and not writable
/// by anyone else.
/// Returns the canonical (symlink-resolved) path -- the one that was
/// actually checked -- so that's exactly what gets loaded.
///
/// Loading a module runs its code inside this process. Checking only the
/// file and its immediate directory isn't enough: a non-root user who can
/// write to any ancestor can rename the module's directory away and put
/// their own in its place between this check and the `dlopen`. Nor is
/// checking only where the path ends up: with `module =
/// "/opt/vendor/current/libhsm.so"` and `/opt/vendor` owned by a deploy
/// account, that account can point `current` at any root-owned directory
/// holding a `libhsm.so` -- a software token's, say, whose "HSM" then holds
/// every KEK in files -- and the file loaded would pass every check made
/// on it. With every directory on the way root-controlled, nothing about
/// what the path names can change, before the check or after it.
fn validate_module_path(path: &Path) -> std::result::Result<PathBuf, String> {
    use crate::secure_file::{check_dir_chain, check_metadata, Owner, FORBID_GROUP_OTHER_WRITE};

    if !path.is_absolute() {
        return Err(format!("PKCS#11 module path {path:?} must be absolute"));
    }
    // Resolved one component at a time, each directory a lookup happens in
    // checked first -- the ones symlinks on the way live in included.
    let canonical = crate::secure_file::resolve_trusted(path, &Owner::Root)
        .map_err(|e| format!("refusing to load PKCS#11 module {path:?}: {e}"))?
        .ok_or_else(|| format!("PKCS#11 module {path:?}: no such file"))?;

    let file_meta = std::fs::metadata(&canonical).map_err(|e| format!("PKCS#11 module {}: {e}", canonical.display()))?;
    check_metadata(&file_meta, Some(Owner::Root), FORBID_GROUP_OTHER_WRITE)
        .map_err(|e| format!("refusing to load PKCS#11 module {}: {e}", canonical.display()))?;
    // Code this process will run: nobody but root may be able to rewrite
    // it, through a POSIX ACL entry either.
    let grants = crate::secure_file::acl_grants_of_path(&canonical)
        .map_err(|e| format!("refusing to load PKCS#11 module {}: {e}", canonical.display()))?;
    if let Some(problem) = crate::secure_file::acl_problem(&grants, &Owner::Root, true, false) {
        return Err(format!("refusing to load PKCS#11 module {}: {problem}", canonical.display()));
    }

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

use crate::secure_file::FileIdentity;

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
/// login as well (see `open_session`), so a token that reports itself on
/// its final attempt is never pushed over by this library. This list is
/// one process's: what carries a rejection to the others is the record in
/// `pkcs11.pin_state_dir` (see `SHARED_LATCH_FILE`).
static PIN_LATCHES: Mutex<Vec<(PathBuf, Option<FileIdentity>, String)>> = Mutex::new(Vec::new());

/// Serializes the PIN-state check, `C_Login` and the latching of its
/// result, so concurrent first calls spend one PIN attempt between them,
/// not one each (see `open_session`). A login with the right PIN, or one
/// already in effect, returns at once, so this costs nothing after the
/// first call.
static PIN_LOGIN_GATE: Mutex<()> = Mutex::new(());

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

/// Why `C_Login` failing with `rv` means the configured PIN was rejected --
/// wrong, malformed, the wrong length, expired, or locked -- or `None` for a
/// failure that says nothing about the PIN. Every PIN-class answer latches
/// (see [`PIN_LATCHES`]), not only `CKR_PIN_INCORRECT`: tokens differ in
/// which of them count against the user's attempts, many never set the
/// final-try flag `open_session` checks first, and the same PIN tried again
/// can't get a different answer.
fn pin_rejection(rv: RvError) -> Option<String> {
    match rv {
        RvError::PinExpired => Some(
            "the token reports the configured PIN expired (CKR_PIN_EXPIRED): change it with the vendor's tools, then \
             write the new one to the PIN file"
                .to_string(),
        ),
        RvError::PinIncorrect | RvError::PinInvalid | RvError::PinLenRange | RvError::PinLocked => {
            Some(format!("the token rejected the configured PIN ({rv:?})"))
        }
        _ => None,
    }
}

/// Records that the token rejected the PIN read from `pin_file` (which had
/// identity `identity` at the time), so no further login is attempted with
/// it -- see [`PIN_LATCHES`].
fn latch_pin_login(pin_file: &Path, identity: Option<FileIdentity>, reason: String) {
    let mut latches = PIN_LATCHES.lock().unwrap_or_else(PoisonError::into_inner);
    latches.retain(|(path, _, _)| path != pin_file);
    latches.push((pin_file.to_path_buf(), identity, reason));
}

// ---------------------------------------------------------------------
// The rejected-PIN record shared between processes.
// ---------------------------------------------------------------------
//
// `PIN_LATCHES` is one process's memory. Prefork workers each have their
// own, and a service in a restart loop starts with an empty one every
// time: with a stale PIN file, each worker and each restart spends one of
// the token's attempts, and a handful of those lock it. When policy names
// a `pkcs11.pin_state_dir`, a rejection is also written there, and every
// process reads it before logging in. The record names the PIN file's
// version (`FileIdentity`), so it stops applying the moment the file
// changes, as the in-process latch does.
//
// The directory decides who is believed. Whoever can write it can stop
// PKCS#11 logins (a forged record, a held lock) but nothing more: the
// record holds no secret and is never a reason to log in. It is meant to
// be writable by exactly the accounts that read the PIN file, each of
// which could lock the token outright with the PIN it holds.

/// The rejection record's name in `pkcs11.pin_state_dir`.
const SHARED_LATCH_FILE: &str = "pin-rejected";
/// The file processes lock around a login whose PIN they haven't yet seen
/// accepted (see [`SharedLoginLock`]).
const SHARED_LOGIN_LOCK_FILE: &str = "login.lock";
const SHARED_LATCH_HEADER: &str = "hkdfguard-pin-rejected 1";
/// More than any record this code writes; bounds the read.
const MAX_SHARED_LATCH_LEN: u64 = 1024;
/// How long a first login waits for another process's first login.
const SHARED_LOGIN_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// The PIN-file version this process has seen the token accept. A login
/// with it needs no cross-process lock: only a PIN nobody has vouched for
/// can cost an attempt in every process at once.
static PIN_CONFIRMED: Mutex<Option<(PathBuf, Option<FileIdentity>)>> = Mutex::new(None);

fn pin_confirmed(pin_file: &Path, identity: Option<FileIdentity>) -> bool {
    let confirmed = PIN_CONFIRMED.lock().unwrap_or_else(PoisonError::into_inner);
    matches!(&*confirmed, Some((path, id)) if path == pin_file && *id == identity)
}

fn set_pin_confirmed(confirmed: Option<(PathBuf, Option<FileIdentity>)>) {
    *PIN_CONFIRMED.lock().unwrap_or_else(PoisonError::into_inner) = confirmed;
}

/// Checks `pkcs11.pin_state_dir`: a real directory (not a link to one),
/// owned by root or this account, that not everyone can write. In a
/// world-writable one, any local account could forge a rejection or hold
/// the login lock.
fn check_pin_state_dir(dir: &Path) -> std::result::Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let fail = |why: String| format!("pkcs11.pin_state_dir {}: {why}", dir.display());
    let meta = std::fs::symlink_metadata(dir).map_err(|e| {
        fail(format!("{e}. Create it, writable by the accounts that read the PIN file and by nobody else, or remove the setting"))
    })?;
    if !meta.file_type().is_dir() {
        return Err(fail("is not a directory".into()));
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(fail(format!("is owned by uid {}, not by root or this account", meta.uid())));
    }
    if meta.mode() & 0o002 != 0 {
        return Err(fail(format!(
            "is writable by everyone (mode {:o}), so any account could stop PKCS#11 logins",
            meta.mode() & 0o7777
        )));
    }
    Ok(())
}

fn shared_latch_text(identity: FileIdentity, reason: &str) -> String {
    let reason: String = reason.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(400).collect();
    format!(
        "{SHARED_LATCH_HEADER}\n{} {} {} {} {}\n{reason}\n",
        identity.dev, identity.ino, identity.len, identity.mtime.0, identity.mtime.1
    )
}

/// The PIN-file version a record names and why its PIN was rejected, or
/// `None` for anything that isn't a whole record this code wrote. The
/// reason is shown to an operator, so only printable ASCII survives.
fn parse_shared_latch(text: &str) -> Option<(FileIdentity, String)> {
    let mut lines = text.lines();
    if lines.next()? != SHARED_LATCH_HEADER {
        return None;
    }
    let mut fields = lines.next()?.split(' ');
    let identity = FileIdentity {
        dev: fields.next()?.parse().ok()?,
        ino: fields.next()?.parse().ok()?,
        len: fields.next()?.parse().ok()?,
        mtime: (fields.next()?.parse().ok()?, fields.next()?.parse().ok()?),
    };
    if fields.next().is_some() {
        return None;
    }
    let reason = lines.next()?.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(400).collect();
    Some((identity, reason))
}

/// Why another process's login with this very version of the PIN file was
/// rejected, if `dir` holds a record saying so. A record for any other
/// version -- the file has changed since -- says nothing, and neither does
/// one that can't be read or parsed: this only ever withholds a login.
fn read_shared_latch(dir: &Path, current: Option<FileIdentity>) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let current = current?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(dir.join(SHARED_LATCH_FILE))
        .ok()?;
    if !file.metadata().ok()?.file_type().is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_SHARED_LATCH_LEN).read_to_string(&mut text).ok()?;
    let (rejected, reason) = parse_shared_latch(&text)?;
    (rejected == current).then_some(reason)
}

/// Records for every process using `dir` that the token rejected the PIN
/// in the file version `identity`. Written whole under another name and
/// renamed into place, so a reader sees the old record or the new one.
/// Best effort: if it can't be written, this process's own latch still
/// holds, and the warning says other processes will each try once.
fn write_shared_latch(dir: &Path, identity: Option<FileIdentity>, reason: &str) {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let Some(identity) = identity else { return };
    let temp = dir.join(format!(".{SHARED_LATCH_FILE}.{}", std::process::id()));
    let _ = std::fs::remove_file(&temp); // a leftover of an earlier process with this pid
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .and_then(|mut file| {
            // Readable by the other accounts sharing the directory,
            // whatever this process's umask: it holds nothing secret.
            file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
            file.write_all(shared_latch_text(identity, reason).as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temp, dir.join(SHARED_LATCH_FILE)));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temp);
        log::warn!(
            "hkdfguard: the rejected PKCS#11 PIN could not be recorded in pkcs11.pin_state_dir {} ({e}); other \
             processes will each spend one login attempt finding out for themselves",
            dir.display()
        );
    }
}

/// Held by a process while it logs in with a PIN-file version it hasn't
/// yet seen accepted, so that processes starting together -- prefork
/// workers -- learn of a wrong PIN from the first of them, not one attempt
/// each. An exclusive `flock` on a file in `pkcs11.pin_state_dir`,
/// released when dropped, or when its holder dies.
struct SharedLoginLock {
    _file: std::fs::File,
}

impl SharedLoginLock {
    fn acquire(dir: &Path, wait: std::time::Duration) -> std::result::Result<SharedLoginLock, String> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let path = dir.join(SHARED_LOGIN_LOCK_FILE);
        let fail = |why: String| format!("PKCS#11 login lock {}: {why}", path.display());
        // Read-only is all `flock` needs, so an account that shares the
        // directory but not this file's owner can still take the lock.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
            .mode(0o644)
            .open(&path)
            .map_err(|e| fail(format!("could not be opened ({e})")))?;
        let meta = file.metadata().map_err(|e| fail(e.to_string()))?;
        if !meta.file_type().is_file() {
            return Err(fail("is not a regular file".into()));
        }
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o644)); // ours if we just made it; else already set
        let deadline = std::time::Instant::now() + wait;
        loop {
            // SAFETY: `file` is an open descriptor for the life of this call.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(SharedLoginLock { _file: file });
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::EWOULDBLOCK) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Some(libc::EWOULDBLOCK) => {
                    return Err(fail(format!(
                        "still held after {} seconds by another process's first login; no login was attempted",
                        wait.as_secs()
                    )))
                }
                _ => return Err(fail(format!("could not be locked: {e}"))),
            }
        }
    }
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
///
/// Also returns the identity of the file the PIN was read from, taken from
/// the open descriptor, not the path: a latch (see [`PIN_LATCHES`]) must
/// name exactly the version of the file whose PIN the token rejected, not
/// whatever an operator's rewrite put at the path a moment later.
fn read_pin_file(path: &Path) -> std::result::Result<(AuthPin, Option<FileIdentity>), std::io::Error> {
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
    let identity = FileIdentity::of_file(&file);

    let mut pin = raw.as_slice();
    if let Some(stripped) = pin.strip_suffix(b"\n") {
        pin = stripped.strip_suffix(b"\r").unwrap_or(stripped);
    }
    // Copy exactly the PIN bytes (no over-allocation, no growth) into the
    // String `AuthPin` takes ownership of, then wipe the file buffer
    // before anything can return -- including the error paths below.
    // Exact capacity also matters to `AuthPin::from`: it turns the String
    // into a `Box<str>`, which reallocates -- leaving an unwiped copy of
    // the PIN behind -- only when there is spare capacity.
    let result = if pin.is_empty() {
        Err(IoError::new(ErrorKind::InvalidData, "PIN file is empty"))
    } else {
        String::from_utf8(pin.to_vec())
            .map(AuthPin::from)
            .map_err(|e| {
                let mut rejected = e.into_bytes();
                zeroize::Zeroize::zeroize(&mut rejected); // the non-UTF-8 bytes are still PIN material
                IoError::new(ErrorKind::InvalidData, "PIN file is not valid UTF-8")
            })
    };
    raw.wipe();
    result.map(|pin| (pin, identity))
}

// Loads the PIN, loads the module, initializes the library, picks a slot,
// opens a read-only session, and logs in. `Absent` only when PKCS#11 isn't
// configured on this host: no `pkcs11.module` in policy. Once it is, every
// later failure is `Refused` -- a missing PIN file included: the HSM is
// meant to be used, so a PIN file not yet provisioned, misnamed, or gone
// mid-rotation, a module that won't load, a missing token, or a wrong PIN
// is an outage to surface, not a reason to wrap under a weaker provider.
// The one exception is a missing PIN file under the developer model, where
// the PIN file is the switch (the -dev overlay's "SoftHSM2, else
// ephemeral"): there it is `Absent`, with a warning.
fn open_session() -> Backend<OpenSession> {
    if std::env::var_os("HKDFGUARD_PKCS11_PIN").is_some() {
        crate::provider::log_once(
            log::Level::Warn,
            format!(
                "hkdfguard: HKDFGUARD_PKCS11_PIN is set but ignored: the PIN is read only from a root-owned mode-0400 (or 0440, group = the service's group) file named by pkcs11.pin_file in the policy (default {DEFAULT_PIN_FILE})"
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
    let (pin, pin_identity) = match read_pin_file(&pin_path) {
        Ok(read) => read,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if matches!(crate::security_model::current(), Ok(crate::security_model::SecurityModel::Developer)) {
                crate::provider::log_once(
                    log::Level::Warn,
                    format!(
                        "hkdfguard: developer security model: pkcs11.module is set but its PIN file {} does not exist; PKCS#11 provider not used",
                        pin_path.display()
                    ),
                );
                return Backend::Absent;
            }
            return Backend::Refused(format!(
                "pkcs11.module is set, but its PIN file {} does not exist. Create it (root-owned, mode 0400, or \
                 root:<service-group> 0440), or remove pkcs11.module from the policy to stop using PKCS#11",
                pin_path.display()
            ));
        }
        Err(e) => return Backend::Refused(format!("PIN file {}: {e}", pin_path.display())),
    };
    // A PIN this process has already seen the token reject is not tried
    // again until the file changes: see `PIN_LATCHES`. Checked here to fail
    // fast, and again under `PIN_LOGIN_GATE` just before the login --
    // against the identity of the file this PIN came from.
    let login_disabled = |reason: String| {
        Backend::Refused(format!(
            "PKCS#11 login disabled in this process: {reason}; correct the PIN file {} (any change to it re-enables \
             login) or restart the process",
            pin_path.display()
        ))
    };
    if let Some(reason) = pin_login_blocked(&pin_path, pin_identity) {
        return login_disabled(reason);
    }
    // The same, as other processes saw it: see `SHARED_LATCH_FILE`.
    let state_dir = settings.pin_state_dir.clone();
    let shared_login_disabled = |dir: &Path, reason: String| {
        Backend::Refused(format!(
            "PKCS#11 login disabled: the token rejected the PIN in {} for another process ({reason}). Correct the \
             PIN file (any change to it re-enables login); if the PIN is right and the token was at fault, delete {}",
            pin_path.display(),
            dir.join(SHARED_LATCH_FILE).display()
        ))
    };
    if let Some(dir) = &state_dir {
        if let Err(reason) = check_pin_state_dir(dir) {
            return Backend::Refused(reason);
        }
        if let Some(reason) = read_shared_latch(dir, pin_identity) {
            return shared_login_disabled(dir, reason);
        }
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

    // From here through the login's verdict, one call at a time: otherwise
    // every call that passed the check above before the first rejection
    // came back would spend an attempt of its own, and a burst of first
    // calls could lock a token that allows three. The latch is re-checked
    // under the gate, so a queued call sees a rejection the one ahead of it
    // just recorded.
    let _login_gate = PIN_LOGIN_GATE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(reason) = pin_login_blocked(&pin_path, pin_identity) {
        return login_disabled(reason);
    }
    // And one process at a time, until this process has seen the token
    // accept this PIN: see `SharedLoginLock`. The record is re-read under
    // the lock, for the same reason the latch was under the gate.
    let shared_lock = match &state_dir {
        Some(dir) if !pin_confirmed(&pin_path, pin_identity) => {
            let lock = match SharedLoginLock::acquire(dir, SHARED_LOGIN_LOCK_WAIT) {
                Ok(lock) => lock,
                Err(reason) => return Backend::Refused(reason),
            };
            if let Some(reason) = read_shared_latch(dir, pin_identity) {
                return shared_login_disabled(dir, reason);
            }
            Some(lock)
        }
        _ => None,
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

    // Read-only: finding keys and HMAC need nothing more, and only key
    // generation opens a read/write session (see `generate_key`).
    let session = match pkcs11.open_ro_session(slot) {
        Ok(session) => session,
        Err(e) => return refuse("could not open a session", &e),
    };
    // C_Login as the normal user role, required before key generation or use.
    // A login is per application per token, not per session: while another
    // call's session is still open on this token, the process is already
    // logged in and C_Login says so. That is success, not an error -- and
    // it is why no code here ever calls C_Logout, which would log the
    // other call out mid-operation; closing the last session ends the
    // login instead.
    match session.login(UserType::User, Some(&pin)) {
        Ok(()) => set_pin_confirmed(Some((pin_path.clone(), pin_identity))),
        // Says nothing about this PIN: another call's login is in effect.
        Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
        // The token rejected the configured PIN. One attempt was spent
        // finding that out; none more will be, from this process, until the
        // PIN file changes.
        Err(CryptokiError::Pkcs11(rv, _)) if pin_rejection(rv).is_some() => {
            let reason = pin_rejection(rv).unwrap_or_default();
            latch_pin_login(&pin_path, pin_identity, reason.clone());
            set_pin_confirmed(None);
            if let Some(dir) = &state_dir {
                write_shared_latch(dir, pin_identity, &reason);
            }
            return Backend::Refused(format!(
                "C_Login failed: {reason}; no further login will be attempted by this process until the PIN file {} \
                 changes, so the token's remaining attempts are not spent",
                pin_path.display()
            ));
        }
        Err(e) => return refuse("C_Login failed", &e),
    }
    drop(pin); // AuthPin zeroizes its storage on drop; don't keep the PIN around for the session's lifetime
    drop(shared_lock); // the verdict is in: other processes' first logins may go ahead

    // Straight after the login, before any search it is to vouch for. A
    // token that can't hold one (a module that refuses session objects in
    // a read-only session, say) still gets the session-state check; only a
    // logout immediately followed by a new login, both inside one key
    // search, then goes unseen.
    let witness = match LoginWitness::create(&session) {
        Ok(witness) => Some(witness),
        Err(e) => {
            crate::provider::log_once(
                log::Level::Warn,
                format!(
                    "hkdfguard: the PKCS#11 token could not create a private session object ({e}); a logout by \
                     other code in this process, followed at once by a new login, could go unnoticed during a key search"
                ),
            );
            None
        }
    };

    Backend::Ready(OpenSession { session, pkcs11, slot, witness })
}

// Handle type returned from `load_kek`: the service's key, already located
// on the token (or just generated there), plus a shared reference to the
// session that object handle belongs to. PKCS#11 object handles stay valid
// for as long as the session that produced them is open, and that session
// lives in `state`, which this handle keeps alive.
struct Pkcs11Handle {
    key_id: Vec<u8>,     // diagnostic-only tag embedded in the wrapped payload
    key: ObjectHandle,   // the service's HMAC key on the token
    state: Arc<Mutex<Option<OpenSession>>>, // shared handle back to the open PKCS#11 session
}

impl KekHandle for Pkcs11Handle {
    fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    fn prf(&self, inputs: &[&[u8]]) -> Result<Vec<PrfOutput>> {
        let mut guard = self
            .state
            .lock() // only one caller may drive the session at a time
            .map_err(|_| Error::Provider("PKCS#11 session lock poisoned".into()))?;
        let open = guard
            .as_mut()
            .ok_or(Error::Provider("PKCS#11 session not available".into()))?; // session setup failed at construction time
        crate::provider::collect_outputs(inputs, |input| token_hmac(&open.session, self.key, input))
    }
}

/// One `C_Sign` with `CKM_SHA256_HMAC`: a single-part HMAC on the token,
/// the key never leaving it. The output is wrapped in a zeroizing buffer
/// straight away: `sign` returns it in a heap `Vec`.
fn token_hmac(session: &Session, key: ObjectHandle, input: &[u8]) -> Result<PrfOutput> {
    let mac = Zeroizing::new(
        session
            .sign(&Mechanism::Sha256Hmac, key, input)
            .map_err(|e| Error::Provider(format!("PKCS#11 C_Sign (CKM_SHA256_HMAC) failed: {e}")))?,
    );
    if mac.len() != 32 {
        return Err(Error::Provider(format!("PKCS#11 token returned a {}-byte HMAC-SHA-256", mac.len())));
    }
    // Self-wiping from here on. Returning it moves it, though, and a move
    // may leave a copy in the stack frame it came from; and the PKCS#11
    // module's own buffers are the module's to wipe.
    let mut out = PrfOutput::new([0u8; 32]);
    out.copy_from_slice(&mac);
    Ok(out)
}

/// A handle around `key` on `session`, for computing its fingerprint
/// outside a provider-held session (see `retire_kek`).
struct SessionKey<'a> {
    session: &'a Session,
    key: ObjectHandle,
}

impl KekHandle for SessionKey<'_> {
    fn key_id(&self) -> &[u8] {
        &[]
    }

    fn prf(&self, inputs: &[&[u8]]) -> Result<Vec<PrfOutput>> {
        crate::provider::collect_outputs(inputs, |input| token_hmac(self.session, self.key, input))
    }
}

impl KekProvider for Pkcs11Provider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Pkcs11
    }

    fn probe(&self) -> bool {
        self.refused.is_some() || self.connected()
    }

    // No module configured: not present, unless policy pins a key for this
    // service -- which says its KEK is on a token.
    fn claims_while_absent(&self, service: &str) -> Result<()> {
        match service_pins(service)? {
            Pins::OneOf(_) => Err(pinned_but_missing()),
            Pins::Any | Pins::Unpinned => Ok(()),
        }
    }

    // Side-effect-free: asks the token whether the service's key is there,
    // without creating anything. A refused provider, or a duplicate or
    // foreign object under the label, is an error -- never read as "no
    // key", see `provider::kek_exists`. So is a pinned service whose key is
    // gone, or isn't the pinned one (see `Pins`).
    fn kek_exists(&self, service: &str) -> Result<bool> {
        self.check_not_refused()?;
        let pins = service_pins(service)?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| Error::Provider("PKCS#11 session lock poisoned".into()))?;
        let open = guard
            .as_mut()
            .ok_or(Error::Provider("PKCS#11 session not available".into()))?;
        if matches!(pins, Pins::Unpinned) {
            return Ok(false); // the allowlist is on and this service isn't on it
        }
        match find_key(&open.session, service, open)? {
            Some(key) => {
                check_pins(&open.session, key, &pins)?;
                Ok(true)
            }
            None if matches!(pins, Pins::OneOf(_)) => Err(pinned_but_missing()),
            None => Ok(false),
        }
    }

    // Locates the service's key on the token now -- generating it if
    // `create_if_missing` and none exists -- and returns a handle holding
    // its object handle. With `create_if_missing` false and no key
    // present, declines with `KeyNotProvisioned`: that is what lets the
    // provider chain move on to a provider that does hold the service's
    // key, and what keeps `hkdfguard_create_kek` the only path that creates
    // one. (Deferring all of this to `prf` would let create_kek report
    // success without creating anything, and the chain could never move
    // past PKCS#11.)
    fn load_kek(&self, service: &str, create_if_missing: bool) -> Result<Box<dyn KekHandle>> {
        self.check_not_refused()?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| Error::Provider("PKCS#11 session lock poisoned".into()))?;
        let open = guard
            .as_mut()
            .ok_or(Error::Provider("PKCS#11 session not available".into()))?;

        let pins = service_pins(service)?;
        if matches!(pins, Pins::Unpinned) && !create_if_missing {
            return Err(Error::KeyNotProvisioned(
                "pkcs11.require_pinned_keys is set and policy pins no key for this service",
            ));
        }
        let key = match find_key(&open.session, service, open)? {
            Some(key) => key,
            // A pinned service keeps its KEK here, by the administrator's
            // own statement, and that key is gone: an error, whether or not
            // creation was asked for. Declining would send the call on to
            // the next provider, and a key generated now could never be the
            // pinned one.
            None if matches!(pins, Pins::OneOf(_)) => return Err(pinned_but_missing()),
            None if create_if_missing => generate_key(open, service)?, // none exists yet and creation was requested
            None => {
                return Err(Error::KeyNotProvisioned(
                    "no PKCS#11 KEK created yet for this service",
                ))
            }
        };
        if matches!(pins, Pins::Unpinned) {
            // Provisioning under the allowlist ends with a root-owned policy
            // edit, which this process can't make. The key now exists:
            // report its fingerprint, ready to pin.
            return Err(Error::Provider(unpinned_service_instructions(service, &open.session, key)));
        }
        check_pins(&open.session, key, &pins)?;
        Ok(Box::new(Pkcs11Handle {
            key_id: format!("hkdfguard:{service}").into_bytes(),
            key,
            state: Arc::clone(&self.state), // cheap refcount bump, not a clone of the underlying session
        }))
    }

    // Deletes the service's key from the token, after confirming the
    // fingerprint with the very object deleted. Everything runs through one
    // read/write session -- find, compute the fingerprint, destroy -- so the
    // handle checked is the handle destroyed. The key must be exactly what
    // `load_kek` would use (one object, hkdfguard's label and ID, its
    // protections; see `find_unique`): a duplicate or foreign key is refused
    // here as it is everywhere else, and left for an operator to inspect,
    // rather than guessed between.
    fn retire_kek(&self, service: &str, expected_fingerprint: &[u8; crate::payload::FINGERPRINT_LEN]) -> Result<()> {
        self.check_not_refused()?;
        let guard = self
            .state
            .lock()
            .map_err(|_| Error::Provider("PKCS#11 session lock poisoned".into()))?;
        let open = guard.as_ref().ok_or(Error::Provider("PKCS#11 session not available".into()))?;
        let rw = open
            .pkcs11
            .open_rw_session(open.slot)
            .map_err(|e| Error::Provider(format!("PKCS#11 could not open a read/write session to retire a key: {e}")))?;

        let key = find_key(&rw, service, open)?.ok_or(Error::KekNotFound)?;
        if crate::crypto::kek_fingerprint(&SessionKey { session: &rw, key })? != *expected_fingerprint {
            return Err(Error::KekFingerprintMismatch);
        }

        rw.destroy_object(key)
            .map_err(|e| Error::Provider(format!("PKCS#11 could not delete this service's key: {e}; nothing was removed")))?;

        // Confirmed gone, as the token itself reports it.
        if count_labelled(&rw, service)? != 0 {
            return Err(Error::Provider(
                "PKCS#11 reported this service's key deleted, but objects under its label remain on the token".into(),
            ));
        }
        Ok(())
    }
}

/// What policy accepts as `service`'s key on the token.
///
/// The token decides who may use and manage keys by one thing, the user
/// PIN, and every service using the token reads it. A PIN holder can
/// delete a service's key, or delete it and generate another under the
/// same label -- one that passes [`check_protections`], being as
/// token-generated as the first. Pins are how policy, which only root
/// writes, says which key is the service's.
enum Pins {
    /// No pin, and no allowlist: any key that passes the attribute checks.
    Any,
    /// A key with one of these fingerprints, and no other. Its absence is
    /// an error too, never "no key here".
    OneOf(Vec<[u8; crate::payload::FINGERPRINT_LEN]>),
    /// No pin, under `pkcs11.require_pinned_keys`: no key at all.
    Unpinned,
}

/// Looks up `service`'s pins. A policy file that exists but is broken
/// fails closed: the pin lookup errors rather than reporting none.
fn service_pins(service: &str) -> Result<Pins> {
    if let Some(fingerprints) = crate::policy::pinned_pkcs11_keys(service)? {
        return Ok(Pins::OneOf(fingerprints));
    }
    if crate::policy::require_pkcs11_pinned_keys() {
        return Ok(Pins::Unpinned);
    }
    Ok(Pins::Any)
}

/// Refuses `key` unless its fingerprint is one `pins` accepts, computed on
/// the token with the object about to be used. A mismatch is an error, not
/// "not provisioned": the key under this service's label isn't the one the
/// administrator recorded, and the chain must not move on as if nothing
/// were there.
fn check_pins(session: &Session, key: ObjectHandle, pins: &Pins) -> Result<()> {
    let Pins::OneOf(accepted) = pins else {
        return Ok(());
    };
    let fingerprint = crate::crypto::kek_fingerprint(&SessionKey { session, key })?;
    match pin_mismatch(&fingerprint, accepted) {
        None => Ok(()),
        Some(message) => Err(Error::Provider(message)),
    }
}

/// Why a key with `fingerprint` isn't one of `accepted`; `None` if it is.
fn pin_mismatch(fingerprint: &[u8; crate::payload::FINGERPRINT_LEN], accepted: &[[u8; crate::payload::FINGERPRINT_LEN]]) -> Option<String> {
    if accepted.contains(fingerprint) {
        return None;
    }
    let accepted: Vec<String> = accepted.iter().map(|f| hex(f)).collect();
    Some(format!(
        "the PKCS#11 key for this service has fingerprint {}, which is not the one pinned in policy \
         (pkcs11.pinned_keys: {}): the key on the token was replaced since it was pinned. Pin the new fingerprint \
         only once you know who generated that key; DEKs wrapped under the old one can't be unwrapped with it",
        hex(fingerprint),
        accepted.join(", ")
    ))
}

/// The error for a service policy pins a key for, when the token holds
/// none under its label. Never "not provisioned": see `load_kek`.
fn pinned_but_missing() -> Error {
    Error::Provider(
        "policy pins a PKCS#11 key for this service (pkcs11.pinned_keys), but the token holds none: it was deleted, \
         or this is not the token it was provisioned on. Refusing rather than using a weaker provider, or generating \
         a key that could not be the pinned one. If the key is gone for good -- retired, say -- remove the service's \
         pin from the policy, then provision it again"
            .into(),
    )
}

/// The message `provision` gets for an unpinned service under
/// `pkcs11.require_pinned_keys`: its key's fingerprint, in the form to
/// paste into policy. The fingerprint and service name are both public.
fn unpinned_service_instructions(service: &str, session: &Session, key: ObjectHandle) -> String {
    match crate::crypto::kek_fingerprint(&SessionKey { session, key }) {
        Ok(fingerprint) => format!(
            "pkcs11.require_pinned_keys is set and service \"{service}\" has no pinned key. Its key is on the token, \
             with fingerprint {fingerprint}; to provision it, add this to the policy file and run provision \
             again:\n  [pkcs11.pinned_keys]\n  \"{service}\" = \"{fingerprint}\"",
            fingerprint = hex(&fingerprint)
        ),
        Err(e) => format!(
            "pkcs11.require_pinned_keys is set and this service has no pinned key; computing its key's fingerprint \
             to report it failed: {e}"
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// The CKA_LABEL used to identify a service's key on the token.
fn key_label(service: &str) -> String {
    format!("hkdfguard:{service}")
}

// The CKA_ID hkdfguard gives a service's key: a non-secret tag that, with
// the label, identifies objects this crate created.
fn key_id(service: &str) -> Vec<u8> {
    Sha256::digest(service.as_bytes()).to_vec()
}

// The search template for a service's key: hkdfguard's label, and the
// class and key type it generates.
//
// Only `CKA_PRIVATE = true` objects are ever enumerated. Creating a
// private object needs a login; a session that isn't logged in can still
// create *public* ones (`CKA_PRIVATE = false`) on most tokens. Without
// this filter, someone with access to the token but not the PIN could
// plant a key under the service's label before it is provisioned --
// generated on the token, so it passes every protection check -- and
// then, with no login, compute every payload's wrapping key with it. Or
// plant a second object under the label and make the lookup fail as a
// duplicate. Filtered, objects made without the PIN are invisible here.
fn labelled_template(service: &str) -> [Attribute; 4] {
    [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Label(key_label(service).into_bytes()),
        Attribute::Private(true),
    ]
}

// Finds the one key labelled for `service`, without creating anything.
// `None` means none has been generated for this service yet. More than
// one is an error, not a pick: which one the token lists first is up to
// the token, so the same service could get a different key from one call
// to the next -- or one planted alongside the real one. The match must
// also carry the CKA_ID `generate_key` gives it. Errors never name the
// service: the C ABI logs them, and service names stay out of the log.
// `session` is the one searched; `open` is this call's, whose login
// witness says whether an empty result can be trusted.
fn find_key(session: &Session, service: &str, open: &OpenSession) -> Result<Option<ObjectHandle>> {
    let found = session
        .find_objects(&labelled_template(service)) // C_FindObjects
        .map_err(|e| Error::Provider(format!("PKCS#11 find_objects failed: {e}")))?;
    let handle = match found.as_slice() {
        [] => {
            require_user_session(session, open)?;
            return Ok(None);
        }
        [one] => *one,
        many => {
            return Err(Error::Provider(format!(
                "{} secret-key objects on the token carry this service's label; refusing to choose \
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
        return Err(Error::Provider(
            "the secret key carrying this service's label does not have the CKA_ID hkdfguard gives \
             its keys; refusing to use an object it did not create"
                .into(),
        ));
    }
    check_protections(session, handle)?;
    Ok(Some(handle))
}

/// Refuses to read an empty search result as "no key" unless the session is
/// logged in as the user. A service's key is a private object, and a
/// session that isn't logged in is simply not shown private objects: the
/// search comes back empty, exactly as if no key had ever been made.
///
/// The login is the application's, not the session's -- every session this
/// process has on the token shares it -- so it can end underneath a call:
/// the host application (or another library in it) using the same module
/// calls `C_Logout` or `C_CloseAllSessions`. Read as "no key", that would
/// send the chain on to the next provider, and every wrap after it to a
/// weaker KEK, while the real one sits on the token. Checked after the
/// search rather than before, so a logout at any point up to here is seen:
/// one still in effect by the session state, and one followed by a new
/// login -- which the state alone would miss -- by the call's
/// [`LoginWitness`] having gone.
fn require_user_session(session: &Session, open: &OpenSession) -> Result<()> {
    let info = session
        .get_session_info()
        .map_err(|e| Error::Provider(format!("PKCS#11 get_session_info failed: {e}")))?;
    match info.session_state() {
        SessionState::RoUser | SessionState::RwUser => {}
        state => {
            return Err(Error::Provider(format!(
                "the PKCS#11 session is not logged in as the user (state {state:?}), so the token would not show \
                 this service's key if it had one: something else in this process logged out of the token. \
                 Refusing to treat that as \"no key\" rather than using a weaker provider"
            )))
        }
    }
    match &open.witness {
        Some(witness) if !witness.intact(&open.session) => Err(Error::Provider(
            "the PKCS#11 login was interrupted during this call: something else in this process logged out of the \
             token (and in again), so the search for this service's key may have run while the token hid it. \
             Refusing to treat that as \"no key\" rather than using a weaker provider"
                .into(),
        )),
        _ => Ok(()),
    }
}

/// The attribute values every key `generate_key` makes carries. This is
/// more than "locked down now": `CKA_ALWAYS_SENSITIVE` and
/// `CKA_NEVER_EXTRACTABLE` are set by the token, and are true only for a
/// key that was generated on it and never had its value exposed. A key
/// imported from outside (`C_CreateObject`, `C_UnwrapKey`) has them false,
/// whatever else its template says.
///
/// Those two say the value was never exposed, not that the token made the
/// key itself, or that it will stay as it is:
///
/// - `CKA_LOCAL` is true only for a key made by `C_GenerateKey` (or a key
///   pair's). A key made by `C_DeriveKey` from a sensitive base can still
///   be always-sensitive and never-extractable, but its value is a function
///   of a base key and data its maker chose.
/// - `CKA_MODIFIABLE` false keeps every attribute as checked here: on a
///   modifiable key, anyone with the PIN could later turn on `CKA_DERIVE`
///   or `CKA_WRAP` -- `C_DeriveKey` with a mechanism that mixes in a key of
///   theirs is a known way to get material out of a non-extractable key.
/// - `CKA_COPYABLE` false keeps `C_CopyObject` from making a copy with
///   different attributes.
///
/// `generate_key` sets the last two in its template, so a token that
/// generated the key accepted them; the check costs no compatibility.
fn required_protections() -> Vec<Attribute> {
    // CKA_PRIVATE again after the find template: a token that ignores an
    // attribute in a search template must not slip a public object through.
    vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::ValueLen((KEK_LEN as u64).into()),
        Attribute::Sign(true),
        Attribute::Derive(false),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::AlwaysSensitive(true),
        Attribute::NeverExtractable(true),
        Attribute::Local(true),
        Attribute::Modifiable(false),
        Attribute::Copyable(false),
    ]
}

// Refuses an object under the service's label that lacks the protections
// hkdfguard generates its keys with -- see `required_protections`.
//
// The `CKA_ID` check before this proves nothing about provenance: the ID
// is SHA-256 of the service name, which anyone can compute. Without this
// check, anyone holding the user PIN could replace the key with one whose
// value they know, labelled and tagged to match; every new wrap would then
// go to a key they can use off the token. A PIN holder can already use the
// real key *on* the token, so this does not create a new boundary -- it
// keeps "the key never leaves the HSM" true.
fn check_protections(session: &Session, handle: ObjectHandle) -> Result<()> {
    let required = required_protections();
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
            "the secret key carrying this service's label lacks the protections hkdfguard generates its keys \
             with ({}); it may have been imported or altered -- refusing to use it",
            failing.join(", ")
        )));
    }
    Ok(())
}

// Generates a new, non-extractable HMAC key on the token for `service` and
// returns its handle, as found again through the read-only session -- so a
// key that somehow isn't unique or doesn't match is refused here, at
// creation, rather than on a later call. Callers check (via `find_key`)
// that none exists yet -- this always generates a fresh key.
//
// The read/write session it needs is opened here and closed again on
// return. It shares the read-only session's login, and that session stays
// open, so closing this one doesn't log the process out.
fn generate_key(open: &OpenSession, service: &str) -> Result<ObjectHandle> {
    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::ValueLen((KEK_LEN as u64).into()), // 256 bits; SoftHSM2 refuses HMAC-SHA-256 keys shorter than this
        Attribute::Token(true),        // persist on the token, not just this session
        Attribute::Private(true),      // only a logged-in session can create or use one -- see `labelled_template`
        Attribute::Sensitive(true),    // value can never be read out
        Attribute::Extractable(false), // and can never be wrapped/exported either
        Attribute::Sign(true),         // required: C_Sign with CKM_SHA256_HMAC is the PRF
        Attribute::Verify(false),
        Attribute::Derive(false),      // no other use: not a base key for C_DeriveKey
        Attribute::Encrypt(false),
        Attribute::Decrypt(false),
        Attribute::Wrap(false),
        Attribute::Unwrap(false),
        Attribute::Modifiable(false),  // none of the above can be changed afterwards
        Attribute::Copyable(false),    // nor carried into a copy made with different attributes
        Attribute::Label(key_label(service).into_bytes()),
        Attribute::Id(key_id(service)),
    ];

    // PKCS#11 has no create-if-absent: two processes (two hosts sharing a
    // network HSM, two services on one host) that both find no key for the
    // service can both generate one. The token then holds two keys under
    // the label, `find_key` refuses the service for good, and deleting the
    // wrong one would lose whatever the other process already wrapped
    // under it. So after generating, look again: if the label is no longer
    // unique, this process yields -- it destroys the key *it* made and
    // uses the one the other process left. Should both yield at once, the
    // second attempt generates again; if that collides too, the operator
    // sees an error and reruns provision.
    for attempt in 1..=2 {
        {
            let rw = open
                .pkcs11
                .open_rw_session(open.slot)
                .map_err(|e| Error::Provider(format!("PKCS#11 could not open a read/write session to generate a key: {e}")))?;
            let ours = rw
                .generate_key(&Mechanism::GenericSecretKeyGen, &template) // C_GenerateKey
                .map_err(|e| Error::Provider(format!("PKCS#11 HMAC key generation failed: {e}")))?;

            if count_labelled(&rw, service)? != 1 {
                rw.destroy_object(ours).map_err(|e| {
                    Error::Provider(format!(
                        "PKCS#11: another process created this service's key concurrently, and this \
                         process's duplicate could not be removed: {e}; delete it by hand"
                    ))
                })?;
                log::warn!(
                    "hkdfguard: another process created this service's PKCS#11 key at the same time \
                     (attempt {attempt}); this process discarded its own key in favor of that one"
                );
            }
        } // the read/write session closes here; its object handles are no longer valid

        // Through the read-only session, whose handle the caller keeps.
        if let Some(key) = find_key(&open.session, service, open)? {
            return Ok(key);
        }
        // Nothing left: the other process yielded at the same moment. Generate again.
    }
    Err(Error::Provider(
        "PKCS#11: the key just generated could not be found (repeated concurrent creation); run provision again".into(),
    ))
}

// How many private (CKA_PRIVATE = true) secret keys carry the service's
// label: the same set `find_key` considers. Counting public objects too
// would let one planted without the PIN look like a concurrent creation,
// so that this process destroys the key it just generated.
fn count_labelled(session: &Session, service: &str) -> Result<usize> {
    session
        .find_objects(&labelled_template(service))
        .map(|found| found.len())
        .map_err(|e| Error::Provider(format!("PKCS#11 find_objects failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*; // bring `Pkcs11Provider` etc. into scope
    use secrecy::ExposeSecret;
    use std::os::unix::fs::PermissionsExt;

    // In a private directory of its own under the test temp root: `$TMPDIR`
    // is usually `/tmp`, which anyone can write to, and the PIN's location
    // is checked -- sticky directories included.
    struct PinFile {
        dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl PinFile {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    // The PIN alone, for the tests that don't look at the file's identity.
    fn read_pin_file(path: &Path) -> std::io::Result<AuthPin> {
        super::read_pin_file(path).map(|(pin, _)| pin)
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
    fn pin_file_under_a_sticky_ancestor_is_rejected() {
        // A private 0700 directory inside a /tmp-style (1777) one: someone
        // else could create entries beside it, so the PIN is not trusted
        // there -- however private its own directory.
        let f = pin_file(b"1234\n", 0o600);
        let private = f.dir.path().join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = private.join("pkcs11.pin");
        std::fs::rename(f.path(), &path).unwrap();
        assert!(read_pin_file(&path).is_ok(), "a private chain is fine");

        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        let err = read_pin_file(&path).expect_err("a sticky ancestor is not trusted");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("sticky"), "says why: {err}");
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
    fn the_pin_files_identity_is_the_one_read_not_what_the_path_names_later() {
        // A latch must name the version of the file whose PIN the token
        // rejected. Taken by path after the read, an operator's correction
        // landing in between would be latched against the old PIN's
        // rejection, and stay blocked until the next change.
        let f = pin_file(b"1234\n", 0o600);
        let (_, read_identity) = super::read_pin_file(f.path()).unwrap();
        assert_eq!(read_identity, FileIdentity::of(f.path()), "unchanged: the same");

        // Replaced at its path (a new inode, as `install` or a Secret
        // update makes) after the read: the read's identity stays the old one.
        let replacement = f.path().with_extension("new");
        std::fs::write(&replacement, b"5678\n").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&replacement, f.path()).unwrap();
        assert_ne!(read_identity, FileIdentity::of(f.path()));
        let (pin, now) = super::read_pin_file(f.path()).unwrap();
        assert_eq!(pin.expose_secret(), "5678");
        assert_eq!(now, FileIdentity::of(f.path()));
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
    fn every_pin_class_login_failure_latches_and_nothing_else_does() {
        for rv in [RvError::PinIncorrect, RvError::PinInvalid, RvError::PinLenRange, RvError::PinLocked] {
            let reason = pin_rejection(rv).unwrap_or_else(|| panic!("{rv:?} must latch"));
            assert!(reason.contains("rejected the configured PIN") && reason.contains(&format!("{rv:?}")), "{reason}");
        }
        let expired = pin_rejection(RvError::PinExpired).expect("an expired PIN must latch");
        assert!(expired.contains("expired") && expired.contains("change it"), "{expired}");
        // Not about the PIN: a retry may well succeed.
        for rv in [RvError::DeviceError, RvError::SessionHandleInvalid, RvError::GeneralError, RvError::UserTypeInvalid] {
            assert_eq!(pin_rejection(rv), None, "{rv:?}");
        }
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
    fn a_rejection_recorded_in_the_state_dir_reaches_other_processes_until_the_pin_file_changes() {
        // What a second process does is exactly these calls, with nothing
        // in its own `PIN_LATCHES`.
        let dir = crate::secure_file::private_tempdir();
        let first = FileIdentity { dev: 7, ino: 42, len: 5, mtime: (-3, 999_999_999) };
        assert!(read_shared_latch(dir.path(), Some(first)).is_none(), "no record yet");

        write_shared_latch(dir.path(), Some(first), "the token rejected the configured PIN (PinIncorrect)");
        assert_eq!(
            read_shared_latch(dir.path(), Some(first)).as_deref(),
            Some("the token rejected the configured PIN (PinIncorrect)")
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(leftovers, [std::ffi::OsString::from(SHARED_LATCH_FILE)], "no temporary file is left behind");
        let mode = std::fs::metadata(dir.path().join(SHARED_LATCH_FILE)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o644, "readable by the other accounts sharing the directory, whatever the umask");

        let rewritten = FileIdentity { mtime: (11, 0), ..first }; // the operator corrected the file
        assert!(read_shared_latch(dir.path(), Some(rewritten)).is_none(), "a changed PIN file is not blocked");
        assert!(read_shared_latch(dir.path(), None).is_none(), "nor is a file whose version is unknown");

        // A later rejection of the corrected file replaces the record.
        write_shared_latch(dir.path(), Some(rewritten), "again");
        assert_eq!(read_shared_latch(dir.path(), Some(rewritten)).as_deref(), Some("again"));
        assert!(read_shared_latch(dir.path(), Some(first)).is_none());
    }

    #[test]
    fn only_a_whole_record_blocks_a_login() {
        let id = FileIdentity { dev: 1, ino: 2, len: 3, mtime: (4, 5) };
        let good = shared_latch_text(id, "why");
        assert_eq!(parse_shared_latch(&good), Some((id, "why".to_string())));

        for bad in [
            "",
            "garbage",
            "hkdfguard-pin-rejected 2\n1 2 3 4 5\nwhy\n",
            "hkdfguard-pin-rejected 1\n1 2 3 4\nwhy\n",
            "hkdfguard-pin-rejected 1\n1 2 3 4 5 6\nwhy\n",
            "hkdfguard-pin-rejected 1\n1 2 x 4 5\nwhy\n",
            "hkdfguard-pin-rejected 1\n1 2 3 4 5\n", // cut off before the reason: not written whole
        ] {
            assert_eq!(parse_shared_latch(bad), None, "{bad:?}");
        }

        // The reason reaches an operator's log: nothing but printable ASCII, on one line.
        let (_, reason) = parse_shared_latch("hkdfguard-pin-rejected 1\n1 2 3 4 5\nline\x1b[2Jone\u{e9}\n").unwrap();
        assert_eq!(reason, "line[2Jone");
        assert!(!shared_latch_text(id, "two\nlines").trim_end().ends_with("lines\n"));
        assert_eq!(parse_shared_latch(&shared_latch_text(id, "two\nlines")).unwrap().1, "twolines");

        // Whatever else is at the name -- a link, a directory, junk -- blocks nothing.
        let dir = crate::secure_file::private_tempdir();
        let record = dir.path().join(SHARED_LATCH_FILE);
        std::fs::write(&record, "junk").unwrap();
        assert!(read_shared_latch(dir.path(), Some(id)).is_none());
        std::fs::remove_file(&record).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, &good).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &record).unwrap();
        assert!(read_shared_latch(dir.path(), Some(id)).is_none(), "a link is not followed");
        std::fs::remove_file(&record).unwrap();
        std::fs::create_dir(&record).unwrap();
        assert!(read_shared_latch(dir.path(), Some(id)).is_none());
    }

    #[test]
    fn the_pin_state_dir_must_be_a_directory_not_everyone_can_write() {
        let base = crate::secure_file::private_tempdir();
        let dir = base.path().join("state");
        assert!(check_pin_state_dir(&dir).unwrap_err().contains("Create it"), "a missing one says what to do");

        std::fs::create_dir(&dir).unwrap();
        for mode in [0o700, 0o770, 0o2770, 0o755] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            check_pin_state_dir(&dir).unwrap_or_else(|e| panic!("mode {mode:o} must pass: {e}"));
        }
        for mode in [0o777, 0o1777, 0o702] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = check_pin_state_dir(&dir).unwrap_err();
            assert!(err.contains("writable by everyone"), "mode {mode:o}: {err}");
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let link = base.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(check_pin_state_dir(&link).unwrap_err().contains("not a directory"), "a link to one is refused");
        let file = base.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(check_pin_state_dir(&file).unwrap_err().contains("not a directory"));
    }

    #[test]
    fn first_logins_take_turns_across_processes() {
        // Two open file descriptions, as two processes have.
        let dir = crate::secure_file::private_tempdir();
        let none = std::time::Duration::ZERO;
        let held = SharedLoginLock::acquire(dir.path(), none).expect("free: taken at once");
        let err = SharedLoginLock::acquire(dir.path(), none).err().expect("held: the second must not get it");
        assert!(err.contains("no login was attempted"), "{err}");
        drop(held);
        SharedLoginLock::acquire(dir.path(), none).expect("released when its holder is done");

        // A FIFO at the name can't hang the open, and is refused.
        let fifo_dir = crate::secure_file::private_tempdir();
        let fifo = std::ffi::CString::new(fifo_dir.path().join(SHARED_LOGIN_LOCK_FILE).to_str().unwrap()).unwrap();
        // SAFETY: `fifo` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(SharedLoginLock::acquire(fifo_dir.path(), none).err().unwrap().contains("not a regular file"));
    }

    #[test]
    fn a_confirmed_pin_is_one_file_version() {
        let path = Path::new("/nonexistent/hkdfguard-confirmed-test/pkcs11.pin");
        let v1 = Some(FileIdentity { dev: 1, ino: 2, len: 5, mtime: (10, 0) });
        let v2 = Some(FileIdentity { dev: 1, ino: 3, len: 5, mtime: (10, 0) });
        set_pin_confirmed(Some((path.to_path_buf(), v1)));
        assert!(pin_confirmed(path, v1));
        assert!(!pin_confirmed(path, v2), "a rewritten file has not been confirmed");
        assert!(!pin_confirmed(Path::new("/nonexistent/other.pin"), v1));
        set_pin_confirmed(None);
        assert!(!pin_confirmed(path, v1));
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

    #[test]
    #[serial_test::serial]
    fn a_configured_module_with_no_pin_file_is_refused_not_skipped() {
        // `pkcs11.module` is the opt-in. With it set, a PIN file that isn't
        // there must stop the chain, not hand new KEKs to the next provider.
        // Checked before the module is loaded, so no token is needed.
        use crate::provider::{KekProvider, ProviderType};
        let dir = crate::secure_file::private_tempdir();
        let missing = dir.path().join("pkcs11.pin");
        let _policy = crate::policy::test_support::TestPolicy::write(&format!(
            "security_model = \"production\"\npreferred_order = [\"pkcs11\", \"ephemeral\"]\n\
             [pkcs11]\nmodule = \"/usr/lib/hkdfguard-test-no-such-module.so\"\npin_file = \"{}\"\n",
            missing.display()
        ));
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "a configured HSM with no PIN file is present, and refused");
        match provider.load_kek("com.company.orders", true) {
            Err(Error::Provider(msg)) => assert!(msg.contains("does not exist") && msg.contains("pkcs11.pin"), "{msg}"),
            other => panic!("expected a refusal, got {:?}", other.map(|_| ())),
        }

        // And the chain stops there: no KEK is created on Ephemeral.
        match crate::provider::create_kek("com.company.orders") {
            Err(Error::Provider(msg)) => assert!(msg.starts_with("PKCS11:") && msg.contains("PIN file"), "{msg}"),
            Err(other) => panic!("expected the PKCS#11 refusal, got {other:?}"),
            Ok((provider, _)) => {
                assert_ne!(provider.provider_type(), ProviderType::Ephemeral, "must not fall through to Ephemeral");
                panic!("expected the PKCS#11 refusal, got a KEK on {:?}", provider.provider_type());
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn under_the_developer_model_a_missing_pin_file_skips_pkcs11() {
        // The -dev overlay's policy: SoftHSM2 once its PIN file exists,
        // ephemeral until then.
        use crate::provider::{KekProvider, ProviderType};
        let dir = crate::secure_file::private_tempdir();
        let missing = dir.path().join("pkcs11.pin");
        let _policy = crate::policy::test_support::TestPolicy::write(&format!(
            "security_model = \"developer\"\npreferred_order = [\"pkcs11\", \"ephemeral\"]\n\
             [pkcs11]\nmodule = \"/usr/lib/hkdfguard-test-no-such-module.so\"\npin_file = \"{}\"\n",
            missing.display()
        ));
        assert!(!Pkcs11Provider::new().probe(), "no PIN file: PKCS#11 is not in use");
        match crate::provider::create_kek("com.company.orders") {
            Ok((provider, _)) => assert_eq!(provider.provider_type(), ProviderType::Ephemeral),
            Err(e) => panic!("expected a KEK on Ephemeral, got {e:?}"),
        }
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
    #[serial_test::serial]
    fn a_pinned_service_is_claimed_even_with_no_module_configured() {
        // Not layered, as above. A pin says the service's KEK is on a
        // token: with PKCS#11 not even configured, the chain must stop
        // here, not hand the service to the next provider.
        let pinned = "com.company.orders";
        let fingerprint = "ab".repeat(crate::payload::FINGERPRINT_LEN);
        let _policy = crate::policy::test_support::TestPolicy::exact(format!(
            "[selection]\nmode = \"prefer\"\n[pkcs11.pinned_keys]\n\"{pinned}\" = \"{fingerprint}\"\n"
        ));
        let provider = Pkcs11Provider::new();
        assert!(!provider.probe());
        match provider.claims_while_absent(pinned) {
            Err(Error::Provider(msg)) => assert!(msg.contains("pkcs11.pinned_keys") && msg.contains("Refusing"), "{msg}"),
            other => panic!("a pinned service must be claimed, got {other:?}"),
        }
        assert!(provider.claims_while_absent("com.company.unpinned").is_ok());
        assert!(matches!(service_pins(pinned).unwrap(), Pins::OneOf(pins) if pins == vec![[0xab; crate::payload::FINGERPRINT_LEN]]));
        assert!(matches!(service_pins("com.company.unpinned").unwrap(), Pins::Any));
    }

    #[test]
    #[serial_test::serial]
    fn pins_follow_policy_and_a_broken_policy_fails_closed() {
        use crate::policy::test_support::TestPolicy;
        {
            let _allowlist = TestPolicy::exact("[selection]\nmode = \"prefer\"\n[pkcs11]\nrequire_pinned_keys = true\n");
            assert!(matches!(service_pins("com.company.orders").unwrap(), Pins::Unpinned));
        }
        {
            let _none = TestPolicy::absent();
            assert!(matches!(service_pins("com.company.orders").unwrap(), Pins::Any));
        }
        let _broken = TestPolicy::exact("[selection]\nmode = \"require\"\n");
        assert!(service_pins("com.company.orders").is_err(), "a broken policy must not report 'nothing pinned'");
    }

    #[test]
    fn a_key_whose_fingerprint_is_not_pinned_is_named_with_the_pins() {
        let (pinned, other) = ([0x11u8; crate::payload::FINGERPRINT_LEN], [0x22u8; crate::payload::FINGERPRINT_LEN]);
        assert_eq!(pin_mismatch(&pinned, &[other, pinned]), None, "any one of the pins is accepted");
        let msg = pin_mismatch(&other, &[pinned]).expect("a different key is refused");
        assert!(msg.contains(&hex(&other)) && msg.contains(&hex(&pinned)) && msg.contains("replaced"), "{msg}");
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
    fn a_module_path_through_a_link_someone_else_could_retarget_is_rejected() {
        if crate::secure_file::skip_as_root() {
            return; // as root, the directory the link lives in is root-owned too
        }
        // The file the path ends at is one validation accepts (see the next
        // test): what is refused is the route to it, through a directory
        // this (non-root) user owns and could repoint at any time.
        let dir = crate::secure_file::private_tempdir();
        let system = Path::new("/bin/sh");
        validate_module_path(system).expect("the control: the target itself passes");

        let file_link = dir.path().join("libhsm.so");
        std::os::unix::fs::symlink(system, &file_link).unwrap();
        let dir_link = dir.path().join("current");
        std::os::unix::fs::symlink(system.parent().unwrap(), &dir_link).unwrap();
        for through in [file_link, dir_link.join("sh")] {
            assert_eq!(std::fs::canonicalize(&through).unwrap(), std::fs::canonicalize(system).unwrap(), "it does lead there");
            let err = validate_module_path(&through).unwrap_err();
            assert!(err.contains("refusing") && err.contains("not an allowed owner"), "{}: {err}", through.display());
        }
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

    // One PRF output, for comparing keys.
    fn prf_of(handle: &dyn KekHandle, input: &[u8]) -> [u8; 32] {
        *handle.prf(&[input]).unwrap()[0]
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"] // skipped by default; run explicitly with `-- --ignored`
    fn same_service_reuses_same_key() {
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");

        let h1 = provider.load_kek("com.company.orders", true).unwrap(); // first call: generates the key on the token
        let h2 = provider.load_kek("com.company.orders", true).unwrap(); // second call: must find and reuse the same one
        assert_eq!(prf_of(&*h1, b"input"), prf_of(&*h2, b"input")); // same underlying key -> same PRF output
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn token_hmac_is_standard_hmac_sha256() {
        // The PRF must be HMAC-SHA-256 exactly, not some token-specific
        // variant: checked with a key whose value is known, imported for
        // this test only (hkdfguard itself never imports keys, and refuses
        // one -- see `check_protections`).
        use hmac::{Hmac, KeyInit, Mac};
        let service = "com.hkdfguard.test.hmac-kat";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        let key_value = *b"hkdfguard-pkcs11-known-answer-ky";
        let input = crate::crypto::MAX_PRF_INPUT_LEN; // the longest input a provider is ever given
        let input = vec![0x5a; input];
        let on_token = with_open(&provider, |open| {
            destroy_all_for(open, service);
            let rw = open.pkcs11.open_rw_session(open.slot).unwrap();
            let key = rw
                .create_object(&[
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::Token(false),
                    Attribute::Sign(true),
                    Attribute::Value(key_value.to_vec()),
                ])
                .unwrap();
            *token_hmac(&rw, key, &input).unwrap()
        });
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key_value).unwrap();
        mac.update(&input);
        assert_eq!(on_token.as_slice(), mac.finalize().into_bytes().as_slice());
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn load_kek_creates_only_when_asked_and_kek_exists_tracks_it() {
        // The create_kek -> kek_exists -> wrap sequence the C ABI drives, at
        // the provider level. Deferring the token lookup to `prf` would
        // make `load_kek(_, true)` create nothing (create_kek reporting
        // success with no key) and `load_kek(_, false)` never decline (the
        // chain could not move past PKCS#11).
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
        assert_eq!(prf_of(&*created, b"input"), prf_of(&*loaded, b"input"), "both handles must drive the same key");

        with_open(&provider, |open| destroy_all_for(open, service));
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn a_pin_refuses_a_replaced_or_deleted_key_and_the_allowlist_gates_provisioning() {
        use crate::policy::test_support::TestPolicy;
        let service = "com.hkdfguard.test.pinned";
        let fingerprint_of = |provider: &Pkcs11Provider| hex(&crate::crypto::kek_fingerprint(&*provider.load_kek(service, false).unwrap()).unwrap());
        let pin = |fingerprint: &str| TestPolicy::write(&format!("[pkcs11.pinned_keys]\n\"{service}\" = \"{fingerprint}\"\n"));

        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        with_open(&provider, |open| destroy_all_for(open, service));
        drop(provider.load_kek(service, true).unwrap());
        let original = fingerprint_of(&provider);

        // Pinned to the key that is there: used as before.
        {
            let _policy = pin(&original);
            let provider = Pkcs11Provider::new();
            assert!(provider.kek_exists(service).unwrap());
            provider.load_kek(service, false).unwrap();
        }

        // What any PIN holder can do without this library: delete the key
        // and generate another under the same label. Every attribute check
        // passes; only the pin tells them apart.
        with_open(&provider, |open| destroy_all_for(open, service));
        drop(provider.load_kek(service, true).unwrap());
        assert_ne!(fingerprint_of(&provider), original);
        {
            let _policy = pin(&original);
            let provider = Pkcs11Provider::new();
            for refused in [provider.kek_exists(service).err(), provider.load_kek(service, false).err(), provider.load_kek(service, true).err()] {
                match refused {
                    Some(Error::Provider(msg)) => assert!(msg.contains("not the one pinned") && msg.contains(&original), "{msg}"),
                    other => panic!("a replaced key must be refused, got {other:?}"),
                }
            }
        }

        // Deleted outright: an error, never "no key here" -- and nothing is
        // generated in its place, even when creation is asked for.
        with_open(&provider, |open| destroy_all_for(open, service));
        {
            let _policy = pin(&original);
            let provider = Pkcs11Provider::new();
            for refused in [provider.kek_exists(service).err(), provider.load_kek(service, false).err(), provider.load_kek(service, true).err()] {
                match refused {
                    Some(Error::Provider(msg)) => assert!(msg.contains("the token holds none"), "{msg}"),
                    other => panic!("a pinned service's missing key must be an error, got {other:?}"),
                }
            }
            assert_eq!(with_open(&provider, |open| count_labelled(&open.session, service).unwrap()), 0, "nothing was generated");
        }

        // The allowlist: provisioning an unpinned service creates its key
        // and is refused with the fingerprint to pin; until then the
        // service has no KEK here.
        {
            let _policy = TestPolicy::write("[pkcs11]\nrequire_pinned_keys = true\n");
            let provider = Pkcs11Provider::new();
            assert!(!provider.kek_exists(service).unwrap());
            assert!(matches!(provider.load_kek(service, false), Err(Error::KeyNotProvisioned(_))));
            let message = match provider.load_kek(service, true) {
                Err(Error::Provider(msg)) => msg,
                other => panic!("expected pinning instructions, got {:?}", other.map(|_| ())),
            };
            assert!(!provider.kek_exists(service).unwrap(), "still unpinned: still no KEK here");
            // Read straight off the token: under the allowlist no handle is given out.
            let created = with_open(&provider, |open| {
                let key = find_key(&open.session, service, open).unwrap().expect("provisioning generated the key");
                hex(&crate::crypto::kek_fingerprint(&SessionKey { session: &open.session, key }).unwrap())
            });
            assert!(message.contains(&format!("\"{service}\" = \"{created}\"")), "{message}");

            let _pinned = pin(&created);
            let provider = Pkcs11Provider::new();
            assert!(provider.kek_exists(service).unwrap());
            provider.load_kek(service, true).expect("pinned: provisioned");
        }

        with_open(&provider, |open| destroy_all_for(open, service));
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn retire_kek_deletes_the_key_only_with_its_fingerprint() {
        let service = "com.hkdfguard.test.retire";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        with_open(&provider, |open| destroy_all_for(open, service));

        assert!(matches!(provider.retire_kek(service, &[0x11; 32]), Err(Error::KekNotFound)));

        let handle = provider.load_kek(service, true).unwrap();
        let fingerprint = crate::crypto::kek_fingerprint(&*handle).unwrap();
        drop(handle);

        assert!(
            matches!(provider.retire_kek(service, &[0x11; 32]), Err(Error::KekFingerprintMismatch)),
            "a wrong fingerprint must delete nothing"
        );
        assert!(provider.kek_exists(service).unwrap(), "still there after the mismatch");

        provider.retire_kek(service, &fingerprint).unwrap();
        assert!(!provider.kek_exists(service).unwrap(), "gone");
        with_open(&provider, |open| {
            assert_eq!(count_labelled(&open.session, service).unwrap(), 0);
        });
        assert!(matches!(provider.retire_kek(service, &fingerprint), Err(Error::KekNotFound)), "nothing left to retire");

        // The service can be provisioned again, under a new key.
        let again = provider.load_kek(service, true).unwrap();
        assert_ne!(crate::crypto::kek_fingerprint(&*again).unwrap(), fingerprint);
        drop(again);
        with_open(&provider, |open| destroy_all_for(open, service));
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn a_logged_out_session_is_an_error_not_a_missing_key() {
        // The login belongs to the process, not the session: anything else
        // in the process using the module can end it. The token then hides
        // every private object, and the search for the service's key comes
        // back empty -- which must not read as "no key here, try the next
        // provider".
        let service = "com.hkdfguard.test.loggedout";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        with_open(&provider, |open| destroy_all_for(open, service));
        assert!(!provider.kek_exists(service).unwrap(), "logged in, and no key: a plain no");
        drop(provider.load_kek(service, true).unwrap());

        with_open(&provider, |open| open.session.logout().unwrap());

        let refused = |result: Result<()>| match result {
            Err(Error::Provider(msg)) => {
                assert!(msg.contains("not logged in as the user"), "{msg}");
                assert!(!msg.contains(service), "errors must not name the service: {msg}");
            }
            other => panic!("expected an error, got {other:?}"),
        };
        refused(provider.kek_exists(service).map(|_| ()));
        refused(provider.load_kek(service, false).map(|_| ())); // not KeyNotProvisioned: the chain must stop here
        refused(provider.load_kek(service, true).map(|_| ())); // and no second key is generated beside the hidden one
        refused(provider.retire_kek(service, &[0x11; 32]));

        // A fresh provider logs in again, and finds the one key still there.
        drop(provider);
        let provider = Pkcs11Provider::new();
        assert!(provider.kek_exists(service).unwrap());
        with_open(&provider, |open| {
            assert_eq!(count_labelled(&open.session, service).unwrap(), 1);
            destroy_all_for(open, service);
        });
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn a_logout_followed_by_a_new_login_is_still_seen() {
        // Logged out and straight back in: the session state reads
        // "logged in" again, so only the login witness -- a private
        // session object, which C_Logout destroyed -- can tell that the
        // token was hiding private objects in between.
        let service = "com.hkdfguard.test.relogin";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        with_open(&provider, |open| {
            destroy_all_for(open, service);
            let witness = open.witness.as_ref().expect("SoftHSM2 creates the login witness");
            assert!(witness.intact(&open.session), "intact while the login lasts");
        });
        assert!(!provider.kek_exists(service).unwrap(), "logged in throughout, and no key: a plain no");

        let pin_path = crate::policy::pkcs11_settings().unwrap().pin_file.unwrap_or_else(|| PathBuf::from(DEFAULT_PIN_FILE));
        let pin = read_pin_file(&pin_path).unwrap();
        with_open(&provider, |open| {
            open.session.logout().unwrap();
            open.session.login(UserType::User, Some(&pin)).unwrap();
            let state = open.session.get_session_info().unwrap().session_state();
            assert!(matches!(state, SessionState::RoUser), "logged in again: {state:?}");
        });

        let refused = |result: Result<()>| match result {
            Err(Error::Provider(msg)) => {
                assert!(msg.contains("login was interrupted"), "{msg}");
                assert!(!msg.contains(service), "errors must not name the service: {msg}");
            }
            other => panic!("expected an error, got {other:?}"),
        };
        refused(provider.kek_exists(service).map(|_| ()));
        refused(provider.load_kek(service, false).map(|_| ())); // not KeyNotProvisioned: the chain must stop here
        refused(provider.load_kek(service, true).map(|_| ())); // nor generate a key beside one it may not have seen
        refused(provider.retire_kek(service, &[0x11; 32]));
        with_open(&provider, |open| assert_eq!(count_labelled(&open.session, service).unwrap(), 0, "nothing generated"));

        // A fresh provider has a witness of its own, and answers again.
        drop(provider);
        let provider = Pkcs11Provider::new();
        assert!(!provider.kek_exists(service).unwrap());
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn a_forked_child_initializes_the_module_for_itself() {
        // The parent loads and initializes the module; a child created with
        // fork() must run C_Initialize again before using it, as PKCS#11
        // asks, and then work like any other process. The child reports
        // through its exit status, never by panicking: it is a copy of the
        // test harness. 0 is a pass; anything else names the failed check.
        let service = "com.hkdfguard.test.forked";
        let parent = Pkcs11Provider::new();
        assert!(parent.probe(), "no PKCS#11 session available");
        with_open(&parent, |open| destroy_all_for(open, service));
        let expected = prf_of(&*parent.load_kek(service, true).unwrap(), b"input");
        drop(parent);
        let parent_pid = this_process();
        let initialized_by = || {
            let modules = MODULES.lock().unwrap();
            modules.iter().map(|m| m.initialized_by).collect::<Vec<_>>()
        };
        assert_eq!(initialized_by(), vec![parent_pid]);

        // SAFETY: this test runs alone (serial), so no other thread holds a
        // lock the child needs; the child only calls this module and _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let child = Pkcs11Provider::new();
            let code = if !child.connected() {
                1 // refused: the inherited module wasn't usable
            } else if initialized_by() != vec![this_process()] {
                2 // the module wasn't initialized again in this process
            } else {
                match child.load_kek(service, false).and_then(|h| h.prf(&[b"input"])).map(|out| *out[0]) {
                    Ok(out) if out == expected => 0,
                    Ok(_) => 3, // a different key
                    Err(_) => 4,
                }
            };
            // SAFETY: _exit takes a status and does not return.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waitpid writes the status of the child just forked.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "the forked child did not exit normally (status {status:#x})");
        assert_eq!(libc::WEXITSTATUS(status), 0, "forked-child check failed: see the numbered checks above");

        // The parent's own entry is untouched, and it still works.
        assert_eq!(initialized_by(), vec![parent_pid]);
        let parent = Pkcs11Provider::new();
        assert_eq!(prf_of(&*parent.load_kek(service, false).unwrap(), b"input"), expected);
        with_open(&parent, |open| destroy_all_for(open, service));
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn retire_kek_refuses_a_duplicate_key_rather_than_choosing_one_to_delete() {
        let service = "com.hkdfguard.test.retire.duplicate";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        with_open(&provider, |open| destroy_all_for(open, service));

        let handle = provider.load_kek(service, true).unwrap();
        let fingerprint = crate::crypto::kek_fingerprint(&*handle).unwrap();
        drop(handle);
        with_open(&provider, |open| plant_key(open, service, key_id(service)));

        let err = provider.retire_kek(service, &fingerprint).expect_err("a duplicate label must be refused");
        assert!(err.to_string().contains("refusing to choose"), "unexpected error: {err}");
        assert!(!err.to_string().contains(service), "errors must not name the service: {err}");
        with_open(&provider, |open| {
            assert_eq!(count_labelled(&open.session, service).unwrap(), 2, "nothing deleted");
        });
        with_open(&provider, |open| destroy_all_for(open, service));
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn concurrent_providers_share_one_initialized_module() {
        // Every C ABI call constructs its own provider; several at once must
        // all work. Running C_Initialize/C_Finalize per provider would let
        // overlapping calls finalize the module under each other's open
        // sessions and fail (or crash the module).
        let service = "com.company.orders";
        let expected = {
            let setup = Pkcs11Provider::new();
            assert!(setup.probe(), "no PKCS#11 session available");
            prf_of(&*setup.load_kek(service, true).unwrap(), b"input")
        };

        let threads: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(move || {
                    (0..8)
                        .map(|_| {
                            let provider = Pkcs11Provider::new();
                            provider.load_kek(service, false).and_then(|h| h.prf(&[b"input"])).map(|out| *out[0])
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

    // Generates a secret key labelled for `service` straight on the token,
    // the way something other than hkdfguard might, with `id`.
    fn plant_key(open: &OpenSession, service: &str, id: Vec<u8>) -> ObjectHandle {
        plant_key_with(open, service, id, &[])
    }

    // As `plant_key`, with `extra` added to the key's template.
    fn plant_key_with(open: &OpenSession, service: &str, id: Vec<u8>, extra: &[Attribute]) -> ObjectHandle {
        let rw = open.pkcs11.open_rw_session(open.slot).unwrap();
        let mut template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen((KEK_LEN as u64).into()),
            Attribute::Token(true),
            Attribute::Sign(true),
            Attribute::Label(key_label(service).into_bytes()),
            Attribute::Id(id),
        ];
        template.extend_from_slice(extra);
        if !extra.iter().any(|a| a.attribute_type() == AttributeType::Private) {
            template.push(Attribute::Private(true));
        }
        rw.generate_key(&Mechanism::GenericSecretKeyGen, &template).unwrap()
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
            plant_key_with(open, service, key_id(service), &[Attribute::Sensitive(false), Attribute::Extractable(true)]);
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
    fn a_generated_key_that_could_be_altered_or_copied_later_is_refused() {
        // Generated on the token, never exposed, right label and ID: it
        // passes every check but these. Left modifiable, a PIN holder could
        // turn on CKA_DERIVE afterwards; left copyable, copy it with other
        // attributes. Each is refused on its own, by name.
        let service = "com.hkdfguard.test.alterable";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        let locked = [Attribute::Sensitive(true), Attribute::Extractable(false), Attribute::Derive(false)];
        for (loosened, name) in [(Attribute::Modifiable(true), "Modifiable"), (Attribute::Copyable(true), "Copyable")] {
            with_open(&provider, |open| {
                destroy_all_for(open, service);
                let mut extra = locked.to_vec();
                extra.push(loosened.clone());
                extra.push(if name == "Modifiable" { Attribute::Copyable(false) } else { Attribute::Modifiable(false) });
                plant_key_with(open, service, key_id(service), &extra);
            });
            let msg = provider.load_kek(service, true).err().expect("a key that can be altered must be refused").to_string();
            assert!(msg.contains("lacks the protections") && msg.contains(name), "{name}: {msg}");
            assert!(!msg.contains(service), "errors must not name the service: {msg}");
            assert!(provider.kek_exists(service).is_err(), "{name}: kek_exists must not answer either way");
        }
        with_open(&provider, |open| destroy_all_for(open, service));
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn a_derived_key_is_refused_though_it_was_never_exposed() {
        // C_DeriveKey from a sensitive base key: always-sensitive and
        // never-extractable, so only CKA_LOCAL tells it from a generated
        // one -- and its value is a function of a base key and data its
        // maker chose. (CKM_AES_CBC_ENCRYPT_DATA: the derivation SoftHSM2
        // implements for secret keys.)
        let service = "com.hkdfguard.test.derivedkey";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        let derived = with_open(&provider, |open| {
            destroy_all_for(open, service);
            let rw = open.pkcs11.open_rw_session(open.slot).unwrap();
            let base = rw
                .generate_key(
                    &Mechanism::AesKeyGen,
                    &[
                        Attribute::Class(ObjectClass::SECRET_KEY),
                        Attribute::KeyType(KeyType::AES),
                        Attribute::ValueLen((KEK_LEN as u64).into()),
                        Attribute::Token(false),
                        Attribute::Sensitive(true),
                        Attribute::Extractable(false),
                        Attribute::Derive(true),
                    ],
                )
                .unwrap();
            let data = [0x5au8; KEK_LEN]; // chosen by the key's maker; a whole number of AES blocks
            let base_template = [
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::ValueLen((KEK_LEN as u64).into()),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
                Attribute::Label(key_label(service).into_bytes()),
                Attribute::Id(key_id(service)),
            ];
            // hkdfguard's other protections, set where the token lets a
            // derivation set them: some SoftHSM2 builds (RHEL 9's 2.6.1)
            // refuse one as read-only (CKR_ATTRIBUTE_READ_ONLY). Each left
            // out is then expected among the reasons the key is refused.
            let optional = [Attribute::Modifiable(false), Attribute::Copyable(false), Attribute::Derive(false)];
            let mut last = None;
            for mask in 0u8..(1 << optional.len()) {
                let left_out: Vec<AttributeType> =
                    optional.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, a)| a.attribute_type()).collect();
                let mut template = base_template.to_vec();
                template.extend(optional.iter().filter(|a| !left_out.contains(&a.attribute_type())).cloned());
                let params = cryptoki::mechanism::ekdf::AesCbcDeriveParams::new([0u8; 16], &data);
                match rw.derive_key(&Mechanism::AesCbcEncryptData(params), base, &template) {
                    Ok(key) => {
                        let attrs = rw.get_attributes(key, &[AttributeType::Local, AttributeType::AlwaysSensitive]).unwrap();
                        return Ok((attrs, left_out));
                    }
                    Err(e @ CryptokiError::Pkcs11(RvError::AttributeReadOnly, _)) => last = Some(e),
                    Err(e) => return Err(e),
                }
            }
            Err(last.unwrap())
        });
        // No skip: the suites run these tests against SoftHSM2, which
        // implements this derivation, and output is captured -- a skip
        // would print `ok` like a pass and prove nothing.
        let (attrs, left_out) = derived.unwrap_or_else(|e| {
            with_open(&provider, |open| destroy_all_for(open, service));
            panic!("the token couldn't derive a key with CKM_AES_CBC_ENCRYPT_DATA: {e}")
        });
        assert!(attrs.contains(&Attribute::Local(false)), "a derived key is not local: {attrs:?}");

        // Refused, for CKA_LOCAL -- and for nothing else but what the token
        // wouldn't let the derivation set.
        let msg = provider.load_kek(service, true).err().expect("a derived key must be refused").to_string();
        with_open(&provider, |open| destroy_all_for(open, service));
        assert!(msg.contains("lacks the protections"), "{msg}");
        let listed = msg.split_once("generates its keys with (").and_then(|(_, rest)| rest.split_once(')')).map(|(l, _)| l);
        let listed: Vec<&str> = listed.unwrap_or_else(|| panic!("no list of protections: {msg}")).split(", ").collect();
        let allowed: Vec<String> =
            std::iter::once("Local".to_string()).chain(left_out.iter().map(|t| format!("{t:?}"))).collect();
        assert!(listed.contains(&"Local"), "{msg}");
        assert!(listed.iter().all(|l| allowed.iter().any(|a| a == l)), "refused for {listed:?}; expected only {allowed:?}");
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn an_imported_key_with_every_attribute_right_is_refused() {
        // A key whose value its importer knows, with hkdfguard's whole
        // template: only CKA_ALWAYS_SENSITIVE / CKA_NEVER_EXTRACTABLE,
        // which the token sets itself, give it away.
        let service = "com.hkdfguard.test.importedkey";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        with_open(&provider, |open| {
            destroy_all_for(open, service);
            let rw = open.pkcs11.open_rw_session(open.slot).unwrap();
            rw.create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::Value(vec![0x42; KEK_LEN]),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
                Attribute::Derive(false),
                Attribute::Label(key_label(service).into_bytes()),
                Attribute::Id(key_id(service)),
            ])
            .unwrap();
        });

        let err = provider.load_kek(service, true).err().expect("an imported key must be refused");
        assert!(err.to_string().contains("AlwaysSensitive") || err.to_string().contains("NeverExtractable"), "{err}");

        with_open(&provider, |open| destroy_all_for(open, service));
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    #[serial_test::serial]
    fn a_key_made_without_the_pin_is_never_used() {
        // Generated on the token, so it passes every other protection
        // check -- yet its planter could compute HMACs with it with no
        // login. It must be invisible: provisioning makes hkdfguard's own key.
        // (Made here from the provider's logged-in session -- login is
        // per-application, so a test process can't hold an unauthenticated
        // one -- but an object's CKA_PRIVATE, not who made it, is what
        // matters.)
        let service = "com.hkdfguard.test.publickey";
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");
        let planted_mac = with_open(&provider, |open| {
            destroy_all_for(open, service);
            let planted = plant_key_with(
                open,
                service,
                key_id(service),
                &[Attribute::Private(false), Attribute::Sensitive(true), Attribute::Extractable(false)],
            );
            *token_hmac(&open.session, planted, b"input").unwrap()
        });
        assert!(!provider.kek_exists(service).unwrap(), "the planted key must not count as provisioned");

        let handle = provider.load_kek(service, true).expect("provisioning must make its own key, not refuse");
        assert_ne!(prf_of(&*handle, b"input"), planted_mac, "the service's KEK must be hkdfguard's, not the planted one");
        provider.load_kek(service, false).expect("nor block the lookups after it");

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

        provider.load_kek(service, true).unwrap(); // generates the key

        with_open(&provider, |open| {
            let info = open.session.get_session_info().unwrap();
            assert!(!info.read_write(), "the provider's own session must be read-only");

            let key = find_key(&open.session, service, open).unwrap().unwrap();
            let wanted = [
                Attribute::Modifiable(false),
                Attribute::Copyable(false),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Verify(false),
                Attribute::Encrypt(false),
                Attribute::Decrypt(false),
                Attribute::Wrap(false),
                Attribute::Unwrap(false),
                Attribute::Derive(false),
            ];
            let types: Vec<AttributeType> = wanted.iter().map(Attribute::attribute_type).collect();
            let attrs = open.session.get_attributes(key, &types).unwrap();
            for expected in wanted {
                assert!(attrs.contains(&expected), "the key must have {expected:?}; has {attrs:?}");
            }
            let value = open.session.get_attributes(key, &[AttributeType::Value]);
            assert!(
                !matches!(&value, Ok(v) if v.iter().any(|a| matches!(a, Attribute::Value(_)))),
                "the key's value must not be readable"
            );

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

        provider.load_kek(service, true).unwrap();
        with_open(&provider, |open| plant_key(open, service, key_id(service)));

        // Refused when the key is loaded -- before any HMAC is computed.
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
            plant_key(open, service, b"not hkdfguard's".to_vec());
        });

        // Refused when the key is loaded, even with creation allowed: a
        // foreign object under the label is never silently generated over.
        let err = provider.load_kek(service, true).err().expect("a foreign CKA_ID must be refused");
        assert!(err.to_string().contains("CKA_ID"), "unexpected error: {err}");

        with_open(&provider, |open| destroy_all_for(open, service));
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    fn different_keys_and_inputs_give_different_outputs() {
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");

        let handle = provider.load_kek("com.company.orders", true).unwrap();
        let first = prf_of(&*handle, b"salt-1");
        assert_eq!(first, prf_of(&*handle, b"salt-1"), "the PRF must be repeatable for the same key and input");
        assert_ne!(first, prf_of(&*handle, b"salt-2"), "different inputs must yield different outputs");

        let other = provider.load_kek("com.company.billing", true).unwrap();
        assert_ne!(first, prf_of(&*other, b"salt-1"), "different keys must yield different outputs");
    }
}

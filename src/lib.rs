//! hkdfguard-native-linux: `HMAC-SHA-256 KDF (SP 800-108) -> AES-256-GCM`
//! DEK wrapping backed by a priority-ordered chain of KEK providers (TPM2,
//! PKCS#11, external secret, ephemeral).
//!
//! This crate's only public interface is the stable C ABI below. No
//! Rust-specific type crosses that boundary, no provider handle (TPM,
//! OpenSSL, PKCS#11 object) is ever exposed, and no panic is allowed to
//! unwind across it -- see [`hkdfguard_wrap_dek`], [`hkdfguard_unwrap_dek`],
//! and [`hkdfguard_generate_and_wrap_dek`].

mod audit; // the audit trail: syslog (authpriv) records, the Windows build's Event Log events
mod crypto; // KEK PRF -> AES-GCM protocol
mod error; // internal error type + public status codes
mod key_file; // reading and checking a wrapped-DEK key file (hkdfguard_open_file)
mod payload; // wrapped-payload wire format
mod policy; // administrative key-selection policy (/etc/hkdfguard/policy.toml)
mod provider; // provider trait + selection chain
mod secure_file; // hardened, check-then-read-safe file access + self-wiping SecretBuffer
mod security_model; // production/developer: who may create and retire KEKs, and whose key files are trusted
#[cfg(test)]
mod test_tmp; // where tests make temp dirs: a private root, not the sticky /tmp nothing this crate reads may live under

pub use error::status; // re-export the status-code constants as part of this crate's public (Rust-side) surface

/// Administration for the `hkdfguard` CLI: operations deliberately kept
/// out of the C ABI, so no application linking the library can call them.
/// Rust-only and not a stable interface.
#[doc(hidden)]
pub mod admin {
    use super::*;

    pub use security_model::{DEPLOYERS_GROUP, OVER_BROAD_GROUPS};

    /// Why an administrative operation failed: the status code it maps to
    /// (as the C functions would return it), and a sentence for the
    /// operator. Never contains key material.
    #[derive(Debug)]
    pub struct AdminError {
        pub status: i32,
        pub message: String,
    }

    impl From<error::Error> for AdminError {
        fn from(e: error::Error) -> Self {
            AdminError { status: e.status_code(), message: e.to_string() }
        }
    }

    /// The KEK fingerprint a wrapped payload carries -- the KEK it was
    /// sealed to -- parsed with the library's own payload parser (version,
    /// field lengths, no trailing bytes), so the CLI never hard-codes this
    /// library's private layout. `None` if `payload` isn't a well-formed one.
    pub fn payload_fingerprint(payload: &[u8]) -> Option<[u8; payload::FINGERPRINT_LEN]> {
        payload::Payload::from_bytes(payload).ok().map(|p| p.fingerprint)
    }

    /// Permanently deletes the KEK `service` currently resolves to -- the
    /// one every wrap uses -- if its fingerprint is `expected_fingerprint`.
    /// Only a provider that stores one key per service can do this
    /// (TPM2, PKCS#11); any other refuses, saying why. The fingerprint is checked
    /// twice: against the KEK the service resolves to, and by the provider
    /// on the very objects it deletes. A setup call (serialized, held to
    /// the latency floor), and audited (1004) on success. Under the
    /// production security model, root only: anyone else gets
    /// `KEK_ACCESS_DENIED` and nothing is deleted.
    ///
    /// Every DEK wrapped under the KEK becomes unrecoverable. Returns the
    /// provider it was deleted from.
    pub fn retire_kek(service: &str, expected_fingerprint: &[u8; payload::FINGERPRINT_LEN]) -> Result<provider::ProviderType, AdminError> {
        let c_service = std::ffi::CString::new(service).map_err(|_| AdminError {
            status: status::INVALID_SERVICE_NAME,
            message: "the service name contains a NUL byte".to_string(),
        })?;
        let service = cstr_to_service(c_service.as_ptr()).map_err(|code| AdminError {
            status: code,
            message: "invalid service name: 1..=128 ASCII letters, digits and '.', not starting with '.' or containing \"..\""
                .to_string(),
        })?;

        let _policy = policy::snapshot_for_call();
        let result = gated_setup(|| -> Result<provider::ProviderType, error::Error> {
            if !security_model::may_administer_keks(security_model::current()?) {
                return Err(error::Error::AccessDenied("under the production security model only root retires a KEK"));
            }
            let (provider, handle) = provider::select_existing(&service)?;
            if crypto::kek_fingerprint(&*handle)? != *expected_fingerprint {
                return Err(error::Error::KekFingerprintMismatch);
            }
            drop(handle);
            provider.retire_kek(&service, expected_fingerprint)?;
            Ok(provider.provider_type())
        });
        match result {
            Ok(provider_type) => {
                audit::kek_retired(&service, provider_type, expected_fingerprint);
                Ok(provider_type)
            }
            Err(e) => {
                log::error!("hkdfguard: retire_kek failed for service \"{service}\": {e}");
                audit::operation_failed(audit::Op::RetireKek, &service, e.status_code());
                Err(e.into())
            }
        }
    }
}

use std::os::raw::{c_char, c_int, c_uint}; // C-ABI-compatible integer/char types
use std::ptr; // raw-pointer helpers (`copy_nonoverlapping`, `write_bytes`)
use std::sync::atomic::{AtomicU32, Ordering}; // per-process count of setup calls, for the misuse warning
use std::sync::Mutex; // serializes setup calls (see `gated_setup`)
use std::time::{Duration, Instant}; // the setup-call latency floor
use zeroize::Zeroize; // scrub sensitive stack buffers before returning

pub(crate) const MAX_SERVICE_LEN: usize = 128; // spec-mandated maximum service-name length in bytes

/// Serializes every setup call (`hkdfguard_create_kek`,
/// `hkdfguard_kek_exists`, `hkdfguard_kek_fingerprint`, and the CLI's
/// `admin::retire_kek`) so that, combined with the latency floor in
/// `gated_setup`, their aggregate rate is capped at one per
/// `policy::setup_min_delay()` regardless of how many threads call in.
static SETUP_GATE: Mutex<()> = Mutex::new(());

/// How many setup calls this process has made. They're meant to happen
/// once per application startup, so a count well beyond that is the
/// signature of a caller looping on them -- see `SETUP_CALLS_WARN_AT`.
static SETUP_CALLS: AtomicU32 = AtomicU32::new(0);

/// Setup-call count past which a warning is logged (once). Generous enough
/// for a multi-service application's genuine startup, small enough that a
/// hot loop trips it within seconds.
const SETUP_CALLS_WARN_AT: u32 = 10;

/// Test-only override of the setup latency floor. `Some(d)` uses `d`
/// instead of consulting the policy; `None` uses the policy exactly as
/// production does. Defaults to `Some(Duration::ZERO)` so the test suite's
/// dozens of setup calls don't each cost a second; the tests that exercise
/// the floor itself set it explicitly and are `#[serial]`.
#[cfg(test)]
static SETUP_DELAY_OVERRIDE_FOR_TESTS: Mutex<Option<Duration>> = Mutex::new(Some(Duration::ZERO));

#[cfg(test)]
fn set_setup_delay_for_tests(override_delay: Option<Duration>) {
    *SETUP_DELAY_OVERRIDE_FOR_TESTS.lock().unwrap_or_else(|p| p.into_inner()) = override_delay;
}

fn effective_setup_min_delay() -> Duration {
    #[cfg(test)]
    {
        if let Some(d) = *SETUP_DELAY_OVERRIDE_FOR_TESTS.lock().unwrap_or_else(|p| p.into_inner()) {
            return d;
        }
    }
    policy::setup_min_delay()
}

/// Runs `f` (the provider-touching part of a setup call) under the setup
/// gate: serialized against every other setup call, and not returning
/// until at least `policy::setup_min_delay()` has elapsed since entry --
/// whatever `f` returned, and however quickly. Argument validation happens
/// *before* callers reach this, so an invalid pointer or service string
/// still fails immediately; only calls that would actually reach a
/// provider pay the floor. See `policy::setup_min_delay` for the rationale.
fn gated_setup<T>(f: impl FnOnce() -> T) -> T {
    // A panic inside an earlier setup call (caught at the FFI boundary)
    // poisons the mutex; that's not a reason to stop gating, so recover
    // the guard rather than propagating the poison.
    let _serialized = SETUP_GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let entered = Instant::now();
    let floor = effective_setup_min_delay();

    let result = f();

    let count = SETUP_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    if count == SETUP_CALLS_WARN_AT + 1 {
        log::warn!(
            "hkdfguard: more than {SETUP_CALLS_WARN_AT} create_kek/kek_exists/kek_fingerprint calls in this process; \
             these are meant to run once per application startup, and each costs a fresh provider \
             connection plus at least {} ms",
            floor.as_millis()
        );
        audit::setup_calls_exceeded(SETUP_CALLS_WARN_AT, floor.as_millis());
    }

    if let Some(remaining) = floor.checked_sub(entered.elapsed()) {
        if !remaining.is_zero() {
            std::thread::sleep(remaining);
        }
    }
    result
}

/// Wraps a 32-byte Data Encryption Key (DEK) under the persistent
/// Key Encryption Key (KEK) identified by `service`, using the currently
/// strongest available provider.
///
/// # Parameters
/// - `service`: NUL-terminated UTF-8 string, 1..=128 bytes, identifying
///   the KEK; only ASCII alphanumeric characters and `.` are allowed, and
///   it may not start with `.` or contain two consecutive dots (`..`). A
///   null pointer, an empty string, a string over 128 bytes, non-UTF-8
///   bytes, a disallowed character, or a dot rule violation all yield
///   [`status::INVALID_SERVICE_NAME`]. Case-insensitive: normalized
///   to lowercase internally, so e.g. `"Com.Example.Orders"` and
///   `"com.example.orders"` always resolve to the same KEK. The caller
///   retains ownership; it is only read during the call.
/// - `dek` / `dek_len`: the 32-byte DEK to wrap. `dek_len` must be exactly
///   32.
/// - `out` / `out_len`: on input, `*out_len` is the capacity of `out` in
///   bytes. On success, the wrapped payload is written to `out` and
///   `*out_len` is set to its length. On [`status::BUFFER_TOO_SMALL`],
///   nothing is written to `out` and `*out_len` is set to the required
///   length; the caller should retry with a larger buffer (the wrapped
///   payload for a 32-byte DEK is at most a few hundred bytes; callers
///   that want a safe fixed size can allocate 512 bytes).
///
/// # Returns
/// One of the status codes in [`status`]. Never throws/unwinds.
///
/// # Safety
/// `service` must be a valid, NUL-terminated, readable C string pointer.
/// `dek` must be readable for `dek_len` bytes. `out_len` must be a valid,
/// readable and writable pointer to an `int`. `out` must be writable for
/// at least `*out_len` bytes, unless null (in which case `*out_len` must
/// be 0).
#[no_mangle] // keeps the exported symbol name exactly `hkdfguard_wrap_dek`, not a mangled Rust name
pub extern "C" fn hkdfguard_wrap_dek(
    service: *const c_char,
    dek: *const u8,
    dek_len: c_int,
    out: *mut u8,
    out_len: *mut c_int,
) -> c_int {
    // `catch_unwind` is what makes the "no panic ever crosses the ABI"
    // guarantee real: if anything inside `wrap_impl` panics, it's caught
    // here and converted into a normal error code instead of unwinding
    // into the C caller (which would be undefined behavior).
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wrap_impl(audit::Op::Wrap, service, dek, dek_len, out, out_len)
    })) {
        Ok(code) => code, // normal path: whatever status code `wrap_impl` returned
        Err(_) => {
            report_caught_panic("hkdfguard_wrap_dek", Some((audit::Op::Wrap, service)));
            status::INTERNAL_ERROR // a panic means a bug in this crate, not a normal failure
        }
    }
}

/// Unwraps a payload previously produced by [`hkdfguard_wrap_dek`] for the
/// same `service`, recovering the original 32-byte DEK.
///
/// # Parameters
/// - `service`: must match the value passed to `hkdfguard_wrap_dek` when
///   this payload was produced (case-insensitively -- see that function's
///   doc comment); any other mismatch is indistinguishable from tampering
///   and yields [`status::PAYLOAD_AUTH_FAILED`] (or, when the other
///   service's KEK differs, [`status::KEK_FINGERPRINT_MISMATCH`] first).
///   An invalid service string (see
///   `hkdfguard_wrap_dek`'s doc comment) yields
///   [`status::INVALID_SERVICE_NAME`].
/// - `wrapped` / `wrapped_len`: the wrapped payload bytes.
/// - `out` / `out_len`: on input, `*out_len` is the capacity of `out`. On
///   success, the 32-byte DEK is written to `out` and `*out_len` is set to
///   32. On any failure, including a caught panic, every byte of the
///   caller's original buffer capacity is zeroed and no key material is
///   left in `out` -- unless `out_len` is NULL, in which case there is no
///   declared capacity and `out` is left untouched.
///
/// # Returns
/// One of the status codes in [`status`]. Never throws/unwinds.
///
/// # Safety
/// Same pointer/length obligations as [`hkdfguard_wrap_dek`], applied to
/// `wrapped`/`wrapped_len` in place of `dek`/`dek_len`.
#[no_mangle]
pub extern "C" fn hkdfguard_unwrap_dek(
    service: *const c_char,
    wrapped: *const u8,
    wrapped_len: c_int,
    out: *mut u8,
    out_len: *mut c_int,
) -> c_int {
    // Captured before any work, so even a caught panic can honor the
    // "zeroed on every failure" contract. Reading through a raw pointer
    // can't panic; a NULL `out_len` just means there's no known capacity.
    let capacity = declared_capacity(out_len);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unwrap_impl(service, wrapped, wrapped_len, out, out_len, capacity)
    })) {
        Ok(code) => code,
        Err(_) => {
            zero_caller_buffer(out, capacity); // first: the reporting below runs host code
            report_caught_panic("hkdfguard_unwrap_dek", Some((audit::Op::Unwrap, service)));
            status::INTERNAL_ERROR
        }
    }
}

// Audits a panic caught at an ABI boundary as INTERNAL_ERROR (event
// 2005), as the Windows build audits anything that escapes. Only when the
// service name is valid: an invalid one is a caller mistake, never audited.
// Logs, and where `audit_as` names an operation audits, a panic caught at
// an ABI boundary. Called after the boundary's own cleanup (zeroing the
// caller's buffer), and inside a catch_unwind of its own: the logger is the
// host application's, and a panic out of it here would unwind across
// `extern "C"` and abort the process.
fn report_caught_panic(boundary: &str, audit_as: Option<(audit::Op, *const c_char)>) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        log::error!("hkdfguard: internal panic caught at {boundary} boundary");
        if let Some((op, service)) = audit_as {
            audit_internal_error(op, service);
        }
    }));
}

fn audit_internal_error(op: audit::Op, service: *const c_char) {
    if let Ok(service) = cstr_to_service(service) {
        audit::operation_failed(op, &service, status::INTERNAL_ERROR);
    }
}

// `*out_len` as the caller declared it, or 0 when `out_len` is NULL.
fn declared_capacity(out_len: *const c_int) -> c_int {
    if out_len.is_null() {
        return 0;
    }
    // SAFETY: non-null; caller contract guarantees a valid, initialized `int`.
    unsafe { *out_len }
}

// Zeroes the caller's whole declared `out` buffer, for every unwrap
// failure path. A no-op when there is no buffer or no positive capacity
// (a NULL `out_len` gives 0), since then nothing can be safely written.
fn zero_caller_buffer(out: *mut u8, capacity: c_int) {
    if !out.is_null() && capacity > 0 {
        // SAFETY: out is non-null and, per caller contract, writable for
        // the `capacity` bytes the caller declared on entry.
        unsafe { ptr::write_bytes(out, 0u8, capacity as usize) };
    }
}

/// Ensures a persistent KEK exists for `service`, creating one (on the
/// strongest available, policy-allowed provider) if it does not already.
/// Idempotent: safe to call again for a `service` that already has one --
/// this just confirms it's still there, doesn't rotate or recreate it.
///
/// This is the *only* way a KEK ever gets created; [`hkdfguard_wrap_dek`]
/// and [`hkdfguard_generate_and_wrap_dek`] both fail with
/// [`status::KEK_NOT_FOUND`] if called before this for a given `service`.
///
/// # Parameters
/// - `service`: see [`hkdfguard_wrap_dek`].
///
/// # Returns
/// One of the status codes in [`status`]. Never throws/unwinds.
///
/// # Safety
/// `service` must be a valid, NUL-terminated, readable C string pointer.
#[no_mangle]
pub extern "C" fn hkdfguard_create_kek(service: *const c_char) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| create_kek_impl(service))) {
        Ok(code) => code,
        Err(_) => {
            report_caught_panic("hkdfguard_create_kek", Some((audit::Op::CreateKek, service)));
            status::INTERNAL_ERROR
        }
    }
}

/// Reports whether a persistent KEK already exists for `service`, without
/// creating one. `Ok`/[`status::OK`] with `*exists` set to `0` means the
/// chain was fully walked and nothing has one yet -- call
/// [`hkdfguard_create_kek`] to provision one.
///
/// # Parameters
/// - `service`: see [`hkdfguard_wrap_dek`].
/// - `exists`: out-parameter; on [`status::OK`], set to `1` if a KEK
///   exists for `service`, `0` otherwise. Untouched on any other status.
///
/// # Returns
/// One of the status codes in [`status`]. Never throws/unwinds.
///
/// # Safety
/// `service` must be a valid, NUL-terminated, readable C string pointer.
/// `exists` must be a valid, writable pointer to an `int`.
#[no_mangle]
pub extern "C" fn hkdfguard_kek_exists(service: *const c_char, exists: *mut c_int) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| kek_exists_impl(service, exists))) {
        Ok(code) => code,
        Err(_) => {
            report_caught_panic("hkdfguard_kek_exists", Some((audit::Op::KekExists, service)));
            status::INTERNAL_ERROR
        }
    }
}

/// Writes the 32-byte fingerprint of the KEK `service` currently resolves to:
/// a fixed HMAC output under the KEK (see `docs/why-hmac-prf.md`) -- the
/// same value every payload wrapped under it carries, and that
/// [`hkdfguard_unwrap_dek`] checks. Public, not a secret: it reveals
/// nothing about the KEK. Lets
/// an operator record which KEK a service uses after provisioning, and
/// confirm it before retiring it. Never creates a KEK.
///
/// A setup call, like [`hkdfguard_kek_exists`]: whether it finds a KEK
/// answers the same question, so it is held to the same latency floor and
/// serialized with the other setup calls. Argument errors and the size
/// probe return immediately.
///
/// # Parameters
/// - `service`: see [`hkdfguard_wrap_dek`].
/// - `out` / `out_len`: on input, `*out_len` is the capacity of `out`. On
///   success, the 32 bytes are written and `*out_len` is set to 32. With a
///   capacity under 32 (a size probe: `out` NULL and `*out_len` 0), nothing
///   is written, `*out_len` is set to 32, and the result is
///   [`status::BUFFER_TOO_SMALL`]. Every other failure leaves `out` and
///   `*out_len` as they were.
///
/// # Returns
/// One of the status codes in [`status`]: [`status::KEK_NOT_FOUND`] if no
/// provider holds a KEK for `service`. Never throws/unwinds.
///
/// # Safety
/// `service` must be a valid, NUL-terminated, readable C string pointer.
/// `out_len` must be a valid, writable pointer to an `int`, and `out`
/// writable for `*out_len` bytes when non-NULL.
#[no_mangle]
pub extern "C" fn hkdfguard_kek_fingerprint(service: *const c_char, out: *mut u8, out_len: *mut c_int) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| kek_fingerprint_impl(service, out, out_len))) {
        Ok(code) => code,
        Err(_) => {
            report_caught_panic("hkdfguard_kek_fingerprint", Some((audit::Op::KekFingerprint, service)));
            status::INTERNAL_ERROR
        }
    }
}

/// Generates a fresh, cryptographically random 32-byte DEK and immediately
/// wraps it under the persistent KEK identified by `service`, in one call --
/// for callers that want a brand new Ephemeral Data Protection Key without
/// having to source their own randomness.
///
/// The newly generated plaintext DEK never crosses this ABI boundary: it is
/// zeroed internally the instant it has been wrapped, before this function
/// returns. To recover it later, unwrap the resulting payload via
/// [`hkdfguard_unwrap_dek`], passing the same `service`.
///
/// # Parameters
/// Same as [`hkdfguard_wrap_dek`], minus `dek`/`dek_len`.
///
/// # Returns
/// One of the status codes in [`status`]. Never throws/unwinds.
///
/// # Safety
/// Same pointer/length obligations as [`hkdfguard_wrap_dek`]'s `service`,
/// `out`, and `out_len` parameters.
#[no_mangle]
pub extern "C" fn hkdfguard_generate_and_wrap_dek(
    service: *const c_char,
    out: *mut u8,
    out_len: *mut c_int,
) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_and_wrap_impl(service, out, out_len)
    })) {
        Ok(code) => code,
        Err(_) => {
            report_caught_panic("hkdfguard_generate_and_wrap_dek", Some((audit::Op::GenerateAndWrap, service)));
            status::INTERNAL_ERROR
        }
    }
}

/// Hardens the *calling process* against memory disclosure: disables core
/// dumps and, on Linux, marks the process non-dumpable, which also stops
/// other non-root processes running as the same user from attaching with
/// `ptrace` or reading `/proc/<pid>/mem`. Keys and DEKs that pass through
/// this library's memory then can't be recovered from a crash dump or a
/// same-user debugger.
///
/// Opt-in, because it changes process-wide state the host application
/// owns: debuggers and crash reporters stop working for the process. The
/// one exception is the ephemeral provider, whose key's only protection is
/// this process's memory: it applies this itself before creating a key.
/// Call it once, early in startup, and *after* any privilege change --
/// the kernel resets the dumpable flag when a process's credentials
/// change. Root, and a process with `CAP_SYS_PTRACE`, can still inspect
/// the process; that is host configuration (see README).
///
/// Linux: sets `RLIMIT_CORE` to 0 (soft and hard, so it can't be raised
/// again) and `prctl(PR_SET_DUMPABLE, 0)`. Other platforms: only the core
/// limit. Idempotent.
///
/// Same as [`hkdfguard_harden_process_with_flags`] with no flags.
///
/// # Returns
/// [`status::OK`], or [`status::PROCESS_HARDENING_FAILED`] if either step
/// failed (logged with the OS error). Never throws/unwinds.
#[no_mangle]
pub extern "C" fn hkdfguard_harden_process() -> c_int {
    hkdfguard_harden_process_with_flags(0)
}

/// Flags for [`hkdfguard_harden_process_with_flags`]. Shared by every
/// platform's C ABI: a flag has the same bit everywhere, and every platform
/// accepts every flag defined here.
pub mod harden_flags {
    /// Fail with `PROCESS_HARDENING_FAILED` unless no other process of the
    /// same user can attach a debugger to, or inject code into, this
    /// process. On macOS that depends on the host executable's code
    /// signature (Hardened Runtime, no `get-task-allow`), which the library
    /// can only check, not change, so without this flag a weak signature
    /// is only logged. On Linux `PR_SET_DUMPABLE` already guarantees it
    /// whatever the binary, so the flag adds no further check.
    pub const REQUIRE_PROTECTED_SIGNATURE: u32 = 0x1;

    /// Every flag this build knows. Any other bit is refused, so a flag
    /// added later is never silently ignored by an older library.
    pub const ALL: u32 = REQUIRE_PROTECTED_SIGNATURE;
}

/// [`hkdfguard_harden_process`], with `flags` (a bitwise OR of
/// [`harden_flags`] constants, or 0) choosing how strict it is. See
/// [`harden_flags::REQUIRE_PROTECTED_SIGNATURE`].
///
/// # Returns
/// [`status::OK`]; [`status::INVALID_ARGUMENT`] if `flags` has a bit not
/// in [`harden_flags::ALL`], before anything is changed; or
/// [`status::PROCESS_HARDENING_FAILED`] if a step failed (logged with the
/// OS error). Never throws/unwinds.
#[no_mangle]
pub extern "C" fn hkdfguard_harden_process_with_flags(flags: c_uint) -> c_int {
    match std::panic::catch_unwind(|| harden_process_impl(flags)) {
        Ok(code) => code,
        Err(_) => {
            report_caught_panic("hkdfguard_harden_process", None);
            status::INTERNAL_ERROR
        }
    }
}

/// For the CLI: makes the ephemeral provider refuse to create or load a
/// key in this process. An ephemeral key lives only in the process that
/// creates it, so one created by a short-lived tool could never unwrap
/// anything for the application it is preparing. Not part of the C ABI.
#[doc(hidden)]
pub fn refuse_ephemeral_keys_in_this_process() {
    #[cfg(feature = "ephemeral")]
    provider::ephemeral::refuse_in_this_process();
}

pub(crate) fn harden_process_impl(flags: c_uint) -> c_int {
    if flags & !harden_flags::ALL != 0 {
        log::error!("hkdfguard: hkdfguard_harden_process_with_flags: unknown flag bits {:#x}", flags & !harden_flags::ALL);
        return status::INVALID_ARGUMENT;
    }
    // REQUIRE_PROTECTED_SIGNATURE needs nothing more here: on Linux the
    // non-dumpable flag below is what stops same-user debuggers, and it is
    // applied (or this fails) either way.

    let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: setrlimit reads a valid, fully initialized rlimit.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
        log::error!(
            "hkdfguard: could not disable core dumps (setrlimit RLIMIT_CORE): {}",
            std::io::Error::last_os_error()
        );
        return status::PROCESS_HARDENING_FAILED;
    }

    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes one integer argument; the rest are ignored.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) } != 0 {
            log::error!(
                "hkdfguard: could not mark the process non-dumpable (prctl PR_SET_DUMPABLE): {}",
                std::io::Error::last_os_error()
            );
            return status::PROCESS_HARDENING_FAILED;
        }
    }

    status::OK
}

// The actual logic behind `hkdfguard_generate_and_wrap_dek`, running inside
// the `catch_unwind` wrapper above. Generates the DEK, then delegates to
// `wrap_impl` (the exact same validation/wrap/copy-out logic
// `hkdfguard_wrap_dek` uses) so that crypto sequence exists in exactly one
// place rather than being duplicated between the two ABI entry points.
fn generate_and_wrap_impl(
    service: *const c_char,
    out: *mut u8,
    out_len: *mut c_int,
) -> c_int {
    // Cryptographically random 32-byte DEK, from the OS CSPRNG
    // (getrandom(2)) -- the Linux analog of Windows' `BCryptGenRandom` /
    // macOS's `SecRandomCopyBytes` used for the equivalent purpose
    // elsewhere in this project.
    let mut dek = zeroize::Zeroizing::new([0u8; crypto::DEK_LEN]); // scrubbed on drop, panic included
    if getrandom::fill(&mut dek[..]).is_err() {
        log::error!("hkdfguard: the OS random number generator failed; no DEK generated");
        if let Ok(service) = cstr_to_service(service) {
            audit::operation_failed(audit::Op::GenerateAndWrap, &service, status::CRYPTO_ERROR);
        }
        return status::CRYPTO_ERROR; // an RNG failure, like wrap's own (see crypto::wrap)
    }

    let code = wrap_impl(audit::Op::GenerateAndWrap, service, dek.as_ptr(), crypto::DEK_LEN as c_int, out, out_len);
    dek.zeroize(); // our local copy of the freshly generated DEK is no longer needed; scrub it now
    code
}

// Validates the caller's `service` C string and normalizes it to the
// crate's canonical form, or returns the appropriate status code if it's
// null, not UTF-8, empty, too long, or contains a disallowed character.
// Shared by both `wrap_impl` and `unwrap_impl` (and so, transitively, by
// `hkdfguard_generate_and_wrap_dek` too, via `wrap_impl`).
//
// Normalization is lowercasing: two service strings that differ only in
// case (e.g. "Com.Example.Orders" and "com.example.orders") always
// resolve to the exact same KEK, on both the wrap and unwrap side, since
// both go through this same function.
fn cstr_to_service(ptr: *const c_char) -> Result<String, c_int> {
    if ptr.is_null() {
        return Err(status::INVALID_SERVICE_NAME); // no service string supplied at all
    }
    // Bounded scan for the terminator, rather than `CStr::from_ptr`, which
    // would read until it found a NUL -- however far away that was --
    // *before* the length rule below could apply. A caller that passes an
    // unterminated buffer is violating the contract either way, but this
    // reads at most MAX_SERVICE_LEN + 1 bytes and then fails safe, instead
    // of over-reading until it happens to hit a zero byte. Byte-by-byte,
    // so a correctly terminated short string never has anything past its
    // own NUL touched.
    let mut len = 0usize;
    loop {
        if len > MAX_SERVICE_LEN {
            return Err(status::INVALID_SERVICE_NAME); // no NUL within 129 bytes: either over the limit or unterminated; reject without reading further
        }
        // SAFETY: caller contract (see function-level Safety docs)
        // guarantees `ptr` points to a readable, NUL-terminated string. Each
        // read is at offset `len` <= MAX_SERVICE_LEN, and the loop stops at
        // the first NUL, so no byte beyond the terminator -- and never more
        // than MAX_SERVICE_LEN + 1 bytes in total -- is ever read.
        if unsafe { *ptr.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return Err(status::INVALID_SERVICE_NAME); // a service string was supplied, but it's empty
    }
    // SAFETY: the loop above established that `len` bytes starting at `ptr`
    // are readable and non-NUL.
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    let s = std::str::from_utf8(bytes).map_err(|_| status::INVALID_SERVICE_NAME)?; // reject non-UTF-8 byte sequences
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.') {
        return Err(status::INVALID_SERVICE_NAME); // only ASCII alphanumeric characters and '.' are allowed
    }
    if s.starts_with('.') || s.contains("..") {
        // A service name is used directly as a file name by the
        // external-secret provider (`<mount>/<service>`), so it must
        // never be able to name "." (the mount itself), ".." (its
        // parent), or a hidden dot-file, and never contain an empty
        // label between dots.
        return Err(status::INVALID_SERVICE_NAME);
    }
    Ok(normalize_service(s))
}

// The canonical form a validated service string is reduced to: lowercase,
// so case never affects KEK identity. Exposed at `pub(crate)` (rather than
// inlined into `cstr_to_service` alone) so other code that needs to match
// this exact normalization -- e.g. the TPM2 provider's conformance tests,
// which check that varying a service string's case doesn't change the key
// the same way production's own normalization guarantees -- shares this
// one definition instead of risking drift from a second copy of it.
pub(crate) fn normalize_service(s: &str) -> String {
    s.to_ascii_lowercase()
}

// The actual logic behind `hkdfguard_create_kek`, running inside the
// `catch_unwind` wrapper above.
fn create_kek_impl(service: *const c_char) -> c_int {
    let service_str = match cstr_to_service(service) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let _policy = policy::snapshot_for_call(); // one read of the policy file serves the whole call
    gated_setup(|| {
        // Asked first, so the audit trail records a KEK being *created*
        // (1000/1001), not every idempotent re-run. If the question itself
        // fails, the create below reports the real error.
        let existed = provider::kek_exists(&service_str).unwrap_or(false);
        // Under the production model only root creates a persistent KEK;
        // anyone else gets the existing one, or KEK_ACCESS_DENIED.
        let created = security_model::current().and_then(|model| {
            if security_model::may_administer_keks(model) {
                provider::create_kek(&service_str)
            } else {
                provider::create_kek_unprivileged(&service_str)
            }
        });
        match created {
            Ok((provider, _handle)) => {
                if !existed {
                    audit::kek_created(&service_str, provider.provider_type(), provider::preferred_type());
                }
                status::OK
            }
            Err(e) => {
                log::error!("hkdfguard: create_kek failed for service \"{service_str}\": {e}"); // never key material
                let code = e.status_code();
                audit::operation_failed(audit::Op::CreateKek, &service_str, code);
                code
            }
        }
    })
}

// The actual logic behind `hkdfguard_kek_exists`, running inside the
// `catch_unwind` wrapper above.
fn kek_exists_impl(service: *const c_char, exists: *mut c_int) -> c_int {
    if exists.is_null() {
        return status::INVALID_ARGUMENT;
    }

    let service_str = match cstr_to_service(service) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let _policy = policy::snapshot_for_call(); // one read of the policy file serves the whole call
    gated_setup(|| match provider::kek_exists(&service_str) {
        Ok(found) => {
            // SAFETY: exists is non-null per check above; caller contract
            // guarantees it's a valid, writable pointer to an `int`.
            unsafe { *exists = if found { 1 } else { 0 } };
            status::OK
        }
        Err(e) => {
            log::error!("hkdfguard: kek_exists failed for service \"{service_str}\": {e}");
            let code = e.status_code();
            audit::operation_failed(audit::Op::KekExists, &service_str, code);
            code
        }
    })
}

// The actual logic behind `hkdfguard_kek_fingerprint`, running inside the
// `catch_unwind` wrapper above. Buffer rules as `wrap_impl`'s.
fn kek_fingerprint_impl(service: *const c_char, out: *mut u8, out_len: *mut c_int) -> c_int {
    if out_len.is_null() {
        return status::INVALID_ARGUMENT;
    }
    // SAFETY: out_len is non-null per check above; caller contract
    // guarantees it points at a valid, initialized `int`.
    let capacity = unsafe { *out_len };
    if capacity < 0 {
        return status::INVALID_ARGUMENT;
    }
    let service_str = match cstr_to_service(service) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if out.is_null() && capacity > 0 {
        return status::INVALID_ARGUMENT; // a declared capacity with nowhere to write
    }
    if (capacity as usize) < payload::FINGERPRINT_LEN {
        // SAFETY: out_len is non-null (checked above).
        unsafe { *out_len = payload::FINGERPRINT_LEN as c_int };
        return status::BUFFER_TOO_SMALL;
    }

    let _policy = policy::snapshot_for_call(); // one read of the policy file serves the whole call
    let fingerprint = gated_setup(|| {
        let (_provider, handle) = provider::select_existing(&service_str)?;
        crypto::kek_fingerprint(&*handle)
    });
    match fingerprint {
        Ok(fingerprint) => {
            // SAFETY: out is non-null and writable for `capacity` >= 32
            // bytes; out_len is non-null.
            unsafe {
                ptr::copy_nonoverlapping(fingerprint.as_ptr(), out, payload::FINGERPRINT_LEN);
                *out_len = payload::FINGERPRINT_LEN as c_int;
            }
            status::OK
        }
        Err(e) => {
            let e: error::Error = e;
            log::error!("hkdfguard: kek_fingerprint failed for service \"{service_str}\": {e}");
            let code = e.status_code();
            audit::operation_failed(audit::Op::KekFingerprint, &service_str, code);
            code
        }
    }
}

// The actual logic behind `hkdfguard_wrap_dek`, running inside the
// `catch_unwind` wrapper above. Returns a plain status code; never panics
// intentionally (validates everything before touching unsafe pointers).
fn wrap_impl(
    op: audit::Op, // Wrap or GenerateAndWrap, for the audit trail
    service: *const c_char,
    dek: *const u8,
    dek_len: c_int,
    out: *mut u8,
    out_len: *mut c_int,
) -> c_int {
    if dek.is_null() || out_len.is_null() {
        return status::INVALID_ARGUMENT;
    }
    if dek_len != crypto::DEK_LEN as c_int {
        return status::INVALID_ARGUMENT; // DEK must be exactly 32 bytes, per spec
    }

    // SAFETY: out_len is non-null per check above; caller contract
    // guarantees it points at a valid, initialized `int`.
    let capacity = unsafe { *out_len }; // how many bytes the caller says `out` can hold
    if capacity < 0 {
        return status::INVALID_ARGUMENT; // a negative capacity makes no sense
    }

    let service_str = match cstr_to_service(service) {
        Ok(s) => s,
        Err(code) => return code, // bad service string: bail out with the specific reason
    };

    // Buffer checks that need no provider, made before any provider work:
    // a size probe, or a call that could never write its result, costs no
    // TPM/HSM round trip.
    if out.is_null() && capacity > 0 {
        return status::INVALID_ARGUMENT; // a declared capacity with nowhere to write
    }
    if (capacity as usize) < crypto::MIN_WRAPPED_LEN {
        // No payload fits, whatever the provider. Report a capacity that
        // always suffices; the successful retry reports the exact length.
        // SAFETY: out_len is non-null (checked above).
        unsafe { *out_len = crypto::MAX_WRAPPED_LEN as c_int };
        return status::BUFFER_TOO_SMALL;
    }

    // SAFETY: dek is non-null and dek_len == DEK_LEN; caller contract
    // guarantees dek is readable for that many bytes.
    let dek_slice = unsafe { std::slice::from_raw_parts(dek, crypto::DEK_LEN) }; // borrow the caller's DEK bytes as a Rust slice
    let mut dek_array = zeroize::Zeroizing::new([0u8; crypto::DEK_LEN]); // owned copy, scrubbed on drop (panic included)
    dek_array.copy_from_slice(dek_slice);

    let _policy = policy::snapshot_for_call(); // one read of the policy file serves the whole call
    let result = crypto::wrap(&service_str, &dek_array); // do the actual KEK PRF -> AES-GCM work
    dek_array.zeroize(); // our local copy of the plaintext DEK is no longer needed; scrub it now

    let wrapped = match result {
        Ok(w) => w,
        Err(e) => {
            log::error!("hkdfguard: wrap failed for service \"{service_str}\": {e}"); // logs only the error description, never key material
            let code = e.status_code();
            audit::operation_failed(op, &service_str, code);
            return code;
        }
    };

    if (capacity as usize) < wrapped.len() {
        // Holds a payload of some size, just not this one (only possible
        // for a capacity between MIN_WRAPPED_LEN and the actual length):
        // report the exact size and write nothing.
        // SAFETY: out_len is non-null (checked above).
        unsafe { *out_len = wrapped.len() as c_int };
        return status::BUFFER_TOO_SMALL;
    }

    // SAFETY: out is non-null and, per caller contract, writable for at
    // least `capacity` >= wrapped.len() bytes.
    unsafe {
        ptr::copy_nonoverlapping(wrapped.as_ptr(), out, wrapped.len()); // copy the wrapped payload into the caller's buffer
        *out_len = wrapped.len() as c_int; // tell the caller exactly how many bytes were written
    }
    // Who wrapped, for which service, under which KEK, and a hash of the
    // exact payload handed back (public bytes only -- see `audit`).
    audit::dek_operation(op, &service_str, &wrapped);
    status::OK
}

// The actual logic behind `hkdfguard_unwrap_dek`, running inside the
// `catch_unwind` wrapper above.
fn unwrap_impl(
    service: *const c_char,
    wrapped: *const u8,
    wrapped_len: c_int,
    out: *mut u8,
    out_len: *mut c_int,
    capacity: c_int, // *out_len as declared on entry (0 if out_len is NULL), read by the caller
) -> c_int {
    // Every failure path below zeroes the caller's buffer using the
    // capacity declared on entry, before *out_len is ever overwritten.
    let zero_out_buffer = || zero_caller_buffer(out, capacity);

    if out_len.is_null() {
        return status::INVALID_ARGUMENT; // no declared capacity, so nothing can be safely zeroed
    }
    if wrapped.is_null() {
        zero_out_buffer();
        return status::INVALID_ARGUMENT;
    }

    if wrapped_len < 0 || capacity < 0 {
        zero_out_buffer();
        return status::INVALID_ARGUMENT;
    }

    let service_str = match cstr_to_service(service) {
        Ok(s) => s,
        Err(code) => {
            zero_out_buffer(); // even an invalid-argument failure must leave `out` zeroed, per spec
            return code;
        }
    };

    // Buffer checks, before any provider work: the DEK is always exactly
    // DEK_LEN bytes, so whether it fits is known without unwrapping.
    if (capacity as usize) < crypto::DEK_LEN {
        zero_out_buffer();
        // SAFETY: out_len is non-null (checked above).
        unsafe { *out_len = crypto::DEK_LEN as c_int }; // tell the caller exactly how big a buffer they need (always 32)
        return status::BUFFER_TOO_SMALL;
    }
    if out.is_null() {
        return status::INVALID_ARGUMENT; // a declared capacity with nowhere to write
    }

    // SAFETY: wrapped is non-null and wrapped_len >= 0; caller contract
    // guarantees it is readable for that many bytes.
    let wrapped_slice =
        unsafe { std::slice::from_raw_parts(wrapped, wrapped_len as usize) }; // borrow the caller's wrapped-payload bytes

    let _policy = policy::snapshot_for_call(); // one read of the policy file serves the whole call
    let mut dek = match crypto::unwrap(&service_str, wrapped_slice) {
        Ok(dek) => dek, // recovered plaintext DEK, in a self-zeroizing local
        Err(e) => {
            log::error!("hkdfguard: unwrap failed for service \"{service_str}\": {e}"); // log the reason, never the key material
            zero_out_buffer();
            let code = e.status_code();
            audit::operation_failed(audit::Op::Unwrap, &service_str, code);
            return code;
        }
    };

    // Unless policy turns it off (audit.unwrap_success = false): who
    // unwrapped, and the same payload hash its wrap record carries. Before
    // the DEK is written: `out` may be the caller's `wrapped` buffer, and
    // the record must hash the payload, never the DEK written over it.
    // `wrapped_slice` is not read again after this.
    if policy::audit_unwrap_success() {
        audit::dek_operation(audit::Op::Unwrap, &service_str, wrapped_slice);
    }

    // SAFETY: out is non-null and, per caller contract, writable for at
    // least `capacity` >= DEK_LEN bytes. `dek` is our own copy, so the two
    // never overlap even when `out` is the caller's `wrapped` buffer.
    unsafe {
        ptr::copy_nonoverlapping(dek.as_ptr(), out, crypto::DEK_LEN); // hand the recovered DEK to the caller
        *out_len = crypto::DEK_LEN as c_int; // always exactly 32 on success
    }
    dek.zeroize(); // our local copy has served its purpose; scrub it now rather than waiting for scope exit
    status::OK
}

/// Reports the security model in force and whether a key file this
/// process writes would be trusted under it -- the Windows build's
/// function, value for value. See [`security_model`].
///
/// # Parameters
/// - `out_model`: receives `HKDFGUARD_SECURITY_MODEL_PRODUCTION` (0) or
///   `HKDFGUARD_SECURITY_MODEL_DEVELOPER` (1).
/// - `out_may_write_key_files`: receives 1 if a key file this process
///   writes (owned by its effective uid) would be trusted by
///   [`hkdfguard_open_file`], else 0.
///
/// # Returns
/// [`status::OK`]; [`status::INVALID_ARGUMENT`] for a null pointer;
/// [`status::POLICY_INVALID`] if the policy can't be used; or
/// [`status::LINUX_GROUP_INVALID`] for a deployer group that can't be.
/// Both outputs are left unchanged on failure. Never throws/unwinds.
///
/// # Safety
/// Each pointer must be null or valid for writing an `int`.
#[no_mangle]
pub extern "C" fn hkdfguard_security_model(out_model: *mut c_int, out_may_write_key_files: *mut c_int) -> c_int {
    match std::panic::catch_unwind(|| security_model_impl(out_model, out_may_write_key_files)) {
        Ok(code) => code,
        Err(_) => {
            report_caught_panic("hkdfguard_security_model", None);
            status::INTERNAL_ERROR
        }
    }
}

fn security_model_impl(out_model: *mut c_int, out_may_write_key_files: *mut c_int) -> c_int {
    if out_model.is_null() || out_may_write_key_files.is_null() {
        return status::INVALID_ARGUMENT;
    }
    let _policy = policy::snapshot_for_call();
    match security_model::Trust::current() {
        Ok(trust) => {
            // SAFETY: both are non-null (checked above) and, per the caller
            // contract, valid for writing an `int`.
            unsafe {
                *out_model = trust.model().c_value();
                *out_may_write_key_files = trust.may_write_key_files() as c_int;
            }
            status::OK
        }
        Err(e) => {
            log::error!("hkdfguard: hkdfguard_security_model: {e}");
            e.status_code()
        }
    }
}

/// Whether [`hkdfguard_open_file`], under the security model in force,
/// trusts `principal` to own a key file or a directory above one
/// (`"uid:<n>"`), or to hold write access to one through its group
/// (`"gid:<n>"`), `<n>` in decimal. Lets a tool that prepares or writes key
/// files check a folder against the exact rule the library reads by. The
/// Windows build's function, which takes a SID string instead.
///
/// # Returns
/// [`status::OK`] with `*out_trusted` set to 1 or 0;
/// [`status::INVALID_ARGUMENT`] for a null pointer or a `principal` that
/// isn't one of those two forms; or [`status::POLICY_INVALID`] /
/// [`status::LINUX_GROUP_INVALID`] as [`hkdfguard_security_model`].
/// `*out_trusted` is left unchanged on failure. Never throws/unwinds.
///
/// # Safety
/// `principal` must be null or a readable C string; `out_trusted` null or
/// valid for writing an `int`.
#[no_mangle]
pub extern "C" fn hkdfguard_key_file_principal_trusted(principal: *const c_char, out_trusted: *mut c_int) -> c_int {
    match std::panic::catch_unwind(|| key_file_principal_trusted_impl(principal, out_trusted)) {
        Ok(code) => code,
        Err(_) => {
            report_caught_panic("hkdfguard_key_file_principal_trusted", None);
            status::INTERNAL_ERROR
        }
    }
}

// Longest `principal` accepted, terminator included: "gid:" and a u32.
const MAX_PRINCIPAL_BYTES: usize = 16;

#[derive(Debug, PartialEq, Eq)]
enum Principal {
    Uid(u32),
    Gid(u32),
}

// Parses "uid:<n>" or "gid:<n>", scanning at most MAX_PRINCIPAL_BYTES bytes
// for the terminator, as cstr_to_service does.
fn cstr_to_principal(ptr: *const c_char) -> Result<Principal, c_int> {
    if ptr.is_null() {
        return Err(status::INVALID_ARGUMENT);
    }
    let mut len = 0usize;
    loop {
        if len >= MAX_PRINCIPAL_BYTES {
            return Err(status::INVALID_ARGUMENT);
        }
        // SAFETY: caller contract guarantees a readable, NUL-terminated
        // string; the loop stops at the first NUL and never reads past
        // MAX_PRINCIPAL_BYTES bytes.
        if unsafe { *ptr.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: the loop above established that `len` bytes at `ptr` are readable.
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    let text = std::str::from_utf8(bytes).map_err(|_| status::INVALID_ARGUMENT)?;
    let (kind, number) = text.split_once(':').ok_or(status::INVALID_ARGUMENT)?;
    // Digits only: `u32::from_str` would also take a leading '+'.
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(status::INVALID_ARGUMENT);
    }
    let id: u32 = number.parse().map_err(|_| status::INVALID_ARGUMENT)?;
    match kind {
        "uid" => Ok(Principal::Uid(id)),
        "gid" => Ok(Principal::Gid(id)),
        _ => Err(status::INVALID_ARGUMENT),
    }
}

fn key_file_principal_trusted_impl(principal: *const c_char, out_trusted: *mut c_int) -> c_int {
    use secure_file::PrincipalTrust;
    if out_trusted.is_null() {
        return status::INVALID_ARGUMENT;
    }
    let principal = match cstr_to_principal(principal) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let _policy = policy::snapshot_for_call();
    let trust = match security_model::Trust::current() {
        Ok(trust) => trust,
        Err(e) => {
            log::error!("hkdfguard: hkdfguard_key_file_principal_trusted: {e}");
            return e.status_code();
        }
    };
    let trusted = match principal {
        Principal::Uid(uid) => trust.trusts_owner(uid),
        Principal::Gid(gid) => trust.trusts_group_writer(gid),
    };
    // SAFETY: out_trusted is non-null (checked above) and, per the caller
    // contract, valid for writing an `int`.
    unsafe { *out_trusted = trusted as c_int };
    status::OK
}

/// Reads a wrapped-key file into `out`, exactly as stored, after checking
/// it is a complete, well-formed wrapped DEK -- see [`key_file`] for the
/// checks. Never unwraps and never reaches a provider.
///
/// # Parameters
/// - `path`: NUL-terminated path, at most `PATH_MAX` bytes including the
///   terminator. Need not be UTF-8 (Linux paths are bytes).
/// - `out` / `out_len`: on input, `*out_len` is the capacity of `out`. On
///   success, the file's bytes are in `out` and `*out_len` is their count.
///   On [`status::BUFFER_TOO_SMALL`], `*out_len` is a capacity to retry
///   with. On every other failure `*out_len` is left unchanged, as with
///   [`hkdfguard_wrap_dek`] and [`hkdfguard_unwrap_dek`]. On any failure,
///   every byte of the declared capacity is zeroed -- unless `out_len` is
///   NULL.
///
/// # Returns
/// One of the status codes in [`status`]. Never throws/unwinds.
///
/// # Safety
/// `path` must be a readable C string pointer. `out_len` must be a valid,
/// readable and writable pointer to an `int`. `out` must be writable for
/// at least `*out_len` bytes, unless null (in which case `*out_len` must be
/// 0).
#[no_mangle]
pub extern "C" fn hkdfguard_open_file(path: *const c_char, out: *mut u8, out_len: *mut c_int) -> c_int {
    let capacity = declared_capacity(out_len);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open_file_impl(path, out, out_len, capacity))) {
        Ok(code) => code,
        Err(_) => {
            zero_caller_buffer(out, capacity); // first: the reporting below runs host code
            report_caught_panic("hkdfguard_open_file", None);
            status::INTERNAL_ERROR
        }
    }
}

// Longest `path` hkdfguard_open_file accepts, terminator included: Linux's
// PATH_MAX, which no path the kernel would open can exceed.
const MAX_PATH_BYTES: usize = libc::PATH_MAX as usize;

// Reads a NUL-terminated path from `ptr`, scanning at most MAX_PATH_BYTES
// bytes for the terminator -- the same bounded scan as `cstr_to_service`,
// so an unterminated buffer is refused instead of over-read.
fn cstr_to_path(ptr: *const c_char) -> Result<std::path::PathBuf, c_int> {
    use std::os::unix::ffi::OsStrExt;
    if ptr.is_null() {
        return Err(status::INVALID_ARGUMENT);
    }
    let mut len = 0usize;
    loop {
        if len >= MAX_PATH_BYTES {
            return Err(status::INVALID_ARGUMENT); // no NUL within PATH_MAX bytes
        }
        // SAFETY: caller contract guarantees a readable, NUL-terminated
        // string; the loop stops at the first NUL and never reads past
        // MAX_PATH_BYTES bytes.
        if unsafe { *ptr.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return Err(status::INVALID_ARGUMENT);
    }
    // SAFETY: the loop above established that `len` bytes at `ptr` are readable.
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    Ok(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
}

// The actual logic behind `hkdfguard_open_file`, running inside the
// `catch_unwind` wrapper above.
fn open_file_impl(path: *const c_char, out: *mut u8, out_len: *mut c_int, capacity: c_int) -> c_int {
    if out_len.is_null() {
        return status::INVALID_ARGUMENT; // no declared capacity, so nothing can be safely zeroed
    }
    // Every failure zeroes the declared buffer and leaves *out_len as the
    // caller set it, as wrap and unwrap do; only BUFFER_TOO_SMALL (`too_small`)
    // reports a size through it.
    let fail = |code: c_int| {
        zero_caller_buffer(out, capacity);
        code
    };
    let too_small = |needed: c_int| {
        zero_caller_buffer(out, capacity);
        // SAFETY: out_len is non-null (checked above).
        unsafe { *out_len = needed };
        status::BUFFER_TOO_SMALL
    };

    if capacity < 0 {
        return fail(status::INVALID_ARGUMENT);
    }
    let path = match cstr_to_path(path) {
        Ok(p) => p,
        Err(code) => return fail(code),
    };
    // Too small for any payload (including the 0 of a size probe):
    // answered without opening the file, as hkdfguard_wrap_dek does.
    if (capacity as usize) < crypto::MIN_WRAPPED_LEN {
        return too_small(crypto::MAX_WRAPPED_LEN as c_int);
    }
    if out.is_null() {
        return fail(status::INVALID_ARGUMENT); // a declared capacity with nowhere to write
    }

    // Whose key files are trusted: the security model, and under the
    // production one its deployer groups, as the policy says right now.
    let _policy = policy::snapshot_for_call();
    let trust = match security_model::Trust::current() {
        Ok(trust) => trust,
        Err(e) => {
            log::error!("hkdfguard: hkdfguard_open_file can't decide whose key files to trust: {e}");
            return fail(e.status_code());
        }
    };
    let wrapped = match key_file::read(&path, &trust) {
        Ok(contents) => {
            if trust.model() == security_model::SecurityModel::Developer {
                audit::developer_model_key_file(&path); // once per process
            }
            contents // wiped when it drops at the end of this function
        }
        Err(e) => {
            log::error!("hkdfguard: hkdfguard_open_file refused key file {}: {}", path.display(), e.describe());
            let code = e.status_code();
            // The one open_file failure that is audited: a possible key
            // exposure an administrator needs to hear about (event 2006).
            if code == status::FILE_PLAINTEXT_KEY {
                audit::plaintext_key_file(&path);
            }
            return fail(code);
        }
    };
    let len = wrapped.as_slice().len(); // at most MAX_WRAPPED_LEN, so it fits a c_int
    if len > capacity as usize {
        return too_small(len as c_int);
    }
    // SAFETY: out is non-null and, per caller contract, writable for
    // `capacity` >= len bytes.
    unsafe {
        ptr::copy_nonoverlapping(wrapped.as_slice().as_ptr(), out, len);
        *out_len = len as c_int;
    }
    status::OK
}

#[cfg(test)]
mod ffi_tests {
    use super::*; // bring the exported functions + `status` into scope
    use serial_test::serial; // these tests mutate shared env vars, so they must run one at a time
    use std::ffi::CString; // to build NUL-terminated strings to pass across the "FFI boundary" in tests
    // Disables the external-secret provider so tests deterministically
    // land on Ephemeral -- the only provider left reachable once
    // external-secret is unavailable.
    fn with_isolated_ephemeral_provider<F: FnOnce()>(f: F) {
        // Ephemeral is only reachable through an explicit policy opt-in
        // (see provider::allowed_chain), so write one.
        let _policy = policy::allow_ephemeral_policy_for_tests();
        f();
    }

    // Calls the real hkdfguard_create_kek FFI entry point and asserts it
    // succeeded -- wrap/generate_and_wrap only ever load an existing
    // KEK, so every test below that wraps something must provision it
    // first, exactly as a real caller would.
    fn create_kek_for_test(service: &CString) {
        assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
    }

    // ---- setup-call gate (create_kek / kek_exists latency floor) ----

    // Runs `f` with the setup latency floor overridden to `delay`, then
    // restores the suite-wide zero override whatever happens.
    fn with_setup_delay<F: FnOnce()>(delay: Option<Duration>, f: F) {
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                set_setup_delay_for_tests(Some(Duration::ZERO));
            }
        }
        let _restore = Restore;
        set_setup_delay_for_tests(delay);
        f();
    }

    #[test]
    #[serial]
    fn setup_calls_take_at_least_the_configured_floor() {
        with_isolated_ephemeral_provider(|| {
            with_setup_delay(Some(Duration::from_millis(50)), || {
                let service = CString::new("com.company.orders.setupfloor").unwrap();

                let started = Instant::now();
                assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
                assert!(started.elapsed() >= Duration::from_millis(50), "create_kek returned early");

                let mut exists: c_int = -1;
                let started = Instant::now();
                assert_eq!(hkdfguard_kek_exists(service.as_ptr(), &mut exists), status::OK);
                assert_eq!(exists, 1);
                assert!(started.elapsed() >= Duration::from_millis(50), "kek_exists returned early");
            });
        });
    }

    #[test]
    #[serial]
    fn setup_floor_applies_equally_to_a_missing_kek() {
        // The floor is on latency, not on success: "doesn't exist" must
        // cost the same as "exists", or a failing kek_exists would be a
        // cheap way around the floor's limit on provider load.
        with_isolated_ephemeral_provider(|| {
            with_setup_delay(Some(Duration::from_millis(50)), || {
                let service = CString::new("com.company.nevercreated.setupfloor").unwrap();
                let mut exists: c_int = -1;
                let started = Instant::now();
                assert_eq!(hkdfguard_kek_exists(service.as_ptr(), &mut exists), status::OK);
                assert_eq!(exists, 0);
                assert!(started.elapsed() >= Duration::from_millis(50));
            });
        });
    }

    // ---- hkdfguard_kek_fingerprint ----

    fn fingerprint_of(service: &CString) -> (c_int, [u8; payload::FINGERPRINT_LEN], c_int) {
        let mut out = [0u8; payload::FINGERPRINT_LEN];
        let mut out_len = payload::FINGERPRINT_LEN as c_int;
        let rc = hkdfguard_kek_fingerprint(service.as_ptr(), out.as_mut_ptr(), &mut out_len);
        (rc, out, out_len)
    }

    #[test]
    #[serial]
    fn kek_fingerprint_is_the_one_every_payload_carries() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders.fingerprint").unwrap();
            assert_eq!(fingerprint_of(&service).0, status::KEK_NOT_FOUND, "never creates a KEK");
            create_kek_for_test(&service);

            let (rc, fingerprint, out_len) = fingerprint_of(&service);
            assert_eq!(rc, status::OK);
            assert_eq!(out_len, 32);
            assert_ne!(fingerprint, [0u8; 32]);
            assert_eq!(fingerprint_of(&service).1, fingerprint, "stable from call to call");

            let dek = [0x42u8; crypto::DEK_LEN];
            let mut wrapped = vec![0u8; crypto::MAX_WRAPPED_LEN];
            let mut wrapped_len = wrapped.len() as c_int;
            assert_eq!(
                hkdfguard_wrap_dek(service.as_ptr(), dek.as_ptr(), dek.len() as c_int, wrapped.as_mut_ptr(), &mut wrapped_len),
                status::OK
            );
            let payload = payload::Payload::from_bytes(&wrapped[..wrapped_len as usize]).unwrap();
            assert_eq!(payload.fingerprint, fingerprint, "the value unwrap checks, and retire confirms");
        });
    }

    #[test]
    #[serial]
    fn kek_fingerprint_buffer_rules_match_wrap() {
        let service = CString::new("com.company.orders.fingerprint.args").unwrap();
        let mut out = [0xA5u8; 64];

        let mut out_len: c_int = 0; // size probe
        assert_eq!(hkdfguard_kek_fingerprint(service.as_ptr(), ptr::null_mut(), &mut out_len), status::BUFFER_TOO_SMALL);
        assert_eq!(out_len, 32);
        let mut out_len: c_int = 31;
        assert_eq!(hkdfguard_kek_fingerprint(service.as_ptr(), out.as_mut_ptr(), &mut out_len), status::BUFFER_TOO_SMALL);
        assert_eq!(out_len, 32);
        assert!(out.iter().all(|&b| b == 0xA5), "nothing written");

        let mut out_len: c_int = -1;
        assert_eq!(hkdfguard_kek_fingerprint(service.as_ptr(), out.as_mut_ptr(), &mut out_len), status::INVALID_ARGUMENT);
        assert_eq!(out_len, -1, "untouched");
        let mut out_len: c_int = 32;
        assert_eq!(hkdfguard_kek_fingerprint(service.as_ptr(), ptr::null_mut(), &mut out_len), status::INVALID_ARGUMENT);
        assert_eq!(hkdfguard_kek_fingerprint(service.as_ptr(), out.as_mut_ptr(), ptr::null_mut()), status::INVALID_ARGUMENT);
        let bad = CString::new("bad_name").unwrap();
        assert_eq!(hkdfguard_kek_fingerprint(bad.as_ptr(), out.as_mut_ptr(), &mut out_len), status::INVALID_SERVICE_NAME);
        assert_eq!(hkdfguard_kek_fingerprint(ptr::null(), out.as_mut_ptr(), &mut out_len), status::INVALID_SERVICE_NAME);
        assert_eq!(out_len, 32, "untouched");
    }

    #[test]
    #[serial]
    fn kek_fingerprint_pays_the_setup_floor_but_argument_errors_do_not() {
        with_isolated_ephemeral_provider(|| {
            with_setup_delay(Some(Duration::from_millis(50)), || {
                let service = CString::new("com.company.nevercreated.fingerprint").unwrap();
                let started = Instant::now();
                assert_eq!(fingerprint_of(&service).0, status::KEK_NOT_FOUND);
                assert!(started.elapsed() >= Duration::from_millis(50), "\"not found\" must cost the same as found");

                let mut out_len: c_int = 0;
                let started = Instant::now();
                assert_eq!(hkdfguard_kek_fingerprint(service.as_ptr(), ptr::null_mut(), &mut out_len), status::BUFFER_TOO_SMALL);
                assert!(started.elapsed() < Duration::from_millis(50), "the size probe is not gated");
            });
        });
    }

    // ---- admin::retire_kek (the CLI's retire) ----

    #[test]
    #[serial]
    fn retire_kek_never_deletes_without_the_right_fingerprint_or_a_provider_that_can() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders.retire").unwrap();
            let name = service.to_str().unwrap();

            let err = admin::retire_kek(name, &[0x11; 32]).unwrap_err();
            assert_eq!(err.status, status::KEK_NOT_FOUND, "{err:?}");

            create_kek_for_test(&service);
            let (_, fingerprint, _) = fingerprint_of(&service);

            let err = admin::retire_kek(name, &[0x11; 32]).unwrap_err();
            assert_eq!(err.status, status::KEK_FINGERPRINT_MISMATCH, "checked before the provider is asked: {err:?}");

            // The right fingerprint, but ephemeral keeps nothing to delete.
            let err = admin::retire_kek(name, &fingerprint).unwrap_err();
            assert_eq!(err.status, status::PROVIDER_ERROR, "{err:?}");
            assert!(err.message.contains("EPHEMERAL cannot retire a single service's KEK"), "{}", err.message);
            assert_eq!(fingerprint_of(&service).1, fingerprint, "still there, unchanged");

            let err = admin::retire_kek("bad_name", &fingerprint).unwrap_err();
            assert_eq!(err.status, status::INVALID_SERVICE_NAME);
            let err = admin::retire_kek("Com.Company.Orders.Retire", &[0x11; 32]).unwrap_err();
            assert_eq!(err.status, status::KEK_FINGERPRINT_MISMATCH, "normalized like every other call");
        });
    }

    #[test]
    #[serial]
    fn setup_floor_applies_to_failed_calls_too() {
        // create_kek must fail here, and must still take the full floor
        // rather than failing fast. Policy pins external-secret and its
        // mount doesn't exist, so the failure is deterministic: relying
        // instead on "no provider happens to be available" would make
        // this pass only on hosts without a reachable TPM or PKCS#11
        // token.
        let _policy = policy::require_provider_policy_for_tests("external-secret");
        with_setup_delay(Some(Duration::from_millis(50)), || {
            let service = CString::new("com.company.orders.setupfloorfail").unwrap();
            let started = Instant::now();
            assert_ne!(hkdfguard_create_kek(service.as_ptr()), status::OK);
            assert!(started.elapsed() >= Duration::from_millis(50));
        });
    }

    #[test]
    #[serial]
    fn invalid_arguments_are_rejected_before_the_floor() {
        // Validation failures never reach a provider, so they shouldn't
        // pay for one: an obviously-bad call returns immediately.
        with_setup_delay(Some(Duration::from_millis(500)), || {
            let bad = CString::new("..evil").unwrap();
            let started = Instant::now();
            assert_eq!(hkdfguard_create_kek(bad.as_ptr()), status::INVALID_SERVICE_NAME);
            assert_eq!(hkdfguard_kek_exists(bad.as_ptr(), ptr::null_mut()), status::INVALID_ARGUMENT);
            assert!(started.elapsed() < Duration::from_millis(500));
        });
    }

    #[test]
    #[serial]
    fn setup_calls_are_serialized_across_threads() {
        // Two concurrent calls must not overlap their floors: total wall
        // time is at least 2x the floor, i.e. the aggregate rate really is
        // capped at one call per floor regardless of thread count.
        with_isolated_ephemeral_provider(|| {
            with_setup_delay(Some(Duration::from_millis(60)), || {
                let started = Instant::now();
                let threads: Vec<_> = (0..2)
                    .map(|i| {
                        std::thread::spawn(move || {
                            let service = CString::new(format!("com.company.orders.serialized{i}")).unwrap();
                            assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
                        })
                    })
                    .collect();
                for t in threads {
                    t.join().unwrap();
                }
                assert!(
                    started.elapsed() >= Duration::from_millis(120),
                    "two gated calls overlapped: {:?}",
                    started.elapsed()
                );
            });
        });
    }

    #[test]
    #[serial]
    fn setup_floor_is_taken_from_the_policy_file() {
        // With the test override cleared, the floor comes from the same
        // policy file that names the providers -- exactly as in production.
        let _policy = crate::policy::test_support::TestPolicy::write(
            "preferred_order = [\"ephemeral\"]\n[selection]\nmode = \"prefer\"\n[startup_behavior]\nsetup_min_delay_ms = 80\n",
        );

        with_setup_delay(None, || {
            let service = CString::new("com.company.orders.policyfloor").unwrap();
            let started = Instant::now();
            assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
            let elapsed = started.elapsed();
            assert!(elapsed >= Duration::from_millis(80), "policy floor not honored: {elapsed:?}");
            // Sanity check that it's the policy's 80 ms and not the 1 s default.
            assert!(elapsed < Duration::from_millis(1000), "took {elapsed:?}; default floor used instead of policy");
        });

    }

    #[test]
    #[serial]
    fn unwrap_in_place_recovers_the_dek_and_audits_the_payload_not_the_dek() {
        // One buffer as both `wrapped` and `out`: the DEK lands in it, and
        // the audit record hashes the payload that was there before.
        use sha2::{Digest, Sha256};
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.unwrapinplace").unwrap();
            create_kek_for_test(&service);
            let dek = [0x6Bu8; 32];
            let mut buf = [0u8; crypto::MAX_WRAPPED_LEN];
            let mut len = buf.len() as c_int;
            assert_eq!(hkdfguard_wrap_dek(service.as_ptr(), dek.as_ptr(), 32, buf.as_mut_ptr(), &mut len), status::OK);
            let wrapped_hash: String = Sha256::digest(&buf[..len as usize]).iter().map(|b| format!("{b:02x}")).collect();
            let dek_prefixed_hash: String = {
                let mut aliased = buf[..len as usize].to_vec();
                aliased[..32].copy_from_slice(&dek);
                Sha256::digest(&aliased).iter().map(|b| format!("{b:02x}")).collect()
            };

            let mut out_len = buf.len() as c_int;
            let ptr = buf.as_mut_ptr();
            let rc = hkdfguard_unwrap_dek(service.as_ptr(), ptr, len, ptr, &mut out_len);
            assert_eq!(rc, status::OK);
            assert_eq!(out_len, 32);
            assert_eq!(buf[..32], dek, "the DEK is written into the shared buffer");

            let records = audit::captured_containing("service=\"com.company.unwrapinplace\"");
            let unwrap_record = records.iter().find(|r| r.contains("op=hkdfguard_unwrap_dek")).expect("an unwrap record");
            assert!(unwrap_record.contains(&wrapped_hash), "the record hashes the payload: {unwrap_record}");
            assert!(!unwrap_record.contains(&dek_prefixed_hash), "never the DEK written over it");
        });
    }

    #[test]
    #[serial]
    fn ffi_round_trip() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap(); // NUL-terminated, as the C ABI requires
            create_kek_for_test(&service);
            let dek = [0xABu8; 32];
            let mut wrapped_buf = [0u8; 512]; // generously-sized output buffer
            let mut wrapped_len: c_int = wrapped_buf.len() as c_int; // declare its capacity

            let rc = hkdfguard_wrap_dek(
                service.as_ptr(),
                dek.as_ptr(),
                32,
                wrapped_buf.as_mut_ptr(),
                &mut wrapped_len,
            );
            assert_eq!(rc, status::OK);

            let mut out = [0u8; 32]; // exact-size buffer for the recovered DEK
            let mut out_len: c_int = out.len() as c_int;
            let rc = hkdfguard_unwrap_dek(
                service.as_ptr(),
                wrapped_buf.as_ptr(),
                wrapped_len, // the actual wrapped length reported by the wrap call above
                out.as_mut_ptr(),
                &mut out_len,
            );
            assert_eq!(rc, status::OK);
            assert_eq!(out_len, 32);
            assert_eq!(out, dek); // must recover exactly the original DEK
        });
    }

    #[test]
    #[serial]
    fn unwrap_reports_each_kind_of_bad_payload_with_its_own_code() {
        // Structurally broken, an unknown version, and well-formed but
        // tampered are three different problems for the caller, so each has
        // its own status code rather than all collapsing into CRYPTO_ERROR.
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            create_kek_for_test(&service);
            let dek = [0x5Au8; 32];
            let mut wrapped_buf = [0u8; 512];
            let mut wrapped_len: c_int = wrapped_buf.len() as c_int;
            let rc = hkdfguard_wrap_dek(service.as_ptr(), dek.as_ptr(), 32, wrapped_buf.as_mut_ptr(), &mut wrapped_len);
            assert_eq!(rc, status::OK);
            let wrapped = wrapped_buf[..wrapped_len as usize].to_vec();

            let unwrap = |bytes: &[u8]| {
                let mut out = [0xAAu8; 32];
                let mut out_len: c_int = out.len() as c_int;
                let rc = hkdfguard_unwrap_dek(service.as_ptr(), bytes.as_ptr(), bytes.len() as c_int, out.as_mut_ptr(), &mut out_len);
                assert_eq!(out, [0u8; 32], "output buffer must be zeroed on failure");
                rc
            };

            assert_eq!(unwrap(&wrapped[..wrapped.len() - 1]), status::PAYLOAD_MALFORMED, "truncated");
            let mut trailing = wrapped.clone();
            trailing.push(0);
            assert_eq!(unwrap(&trailing), status::PAYLOAD_MALFORMED, "trailing bytes");
            let mut bad_provider = wrapped.clone();
            bad_provider[1] = 0xFF; // byte 1 is the provider tag
            assert_eq!(unwrap(&bad_provider), status::PAYLOAD_MALFORMED, "unknown provider type");

            let mut bad_version = wrapped.clone();
            bad_version[0] = payload::VERSION + 1; // byte 0 is the version
            assert_eq!(unwrap(&bad_version), status::PAYLOAD_UNSUPPORTED, "unknown version");

            let mut tampered = wrapped.clone();
            let last_ciphertext_byte = tampered.len() - payload::FINGERPRINT_LEN - 1; // inside the tag, before the fingerprint
            tampered[last_ciphertext_byte] ^= 0x01;
            assert_eq!(unwrap(&tampered), status::PAYLOAD_AUTH_FAILED, "tampered tag");
        });
    }

    #[test]
    #[serial]
    fn generate_and_wrap_round_trip() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            create_kek_for_test(&service);
            let mut wrapped_buf = [0u8; 512]; // generously-sized output buffer
            let mut wrapped_len: c_int = wrapped_buf.len() as c_int;

            let rc = hkdfguard_generate_and_wrap_dek(
                service.as_ptr(),
                wrapped_buf.as_mut_ptr(),
                &mut wrapped_len,
            );
            assert_eq!(rc, status::OK);

            // Unwrapping it recovers a real 32-byte DEK -- proving the
            // payload generate_and_wrap_dek produced is a genuine,
            // independently unwrappable wrapped payload, not just a
            // plausible-looking buffer.
            let mut out = [0u8; 32];
            let mut out_len: c_int = out.len() as c_int;
            let rc = hkdfguard_unwrap_dek(
                service.as_ptr(),
                wrapped_buf.as_ptr(),
                wrapped_len,
                out.as_mut_ptr(),
                &mut out_len,
            );
            assert_eq!(rc, status::OK);
            assert_eq!(out_len, 32);
        });
    }

    #[test]
    #[serial]
    fn generate_and_wrap_produces_independent_deks() {
        // Each call sources its own fresh CSPRNG randomness for the DEK
        // itself, not just a fresh salt/nonce -- this is the
        // check that actually distinguishes "generates a new DEK" from
        // "wraps a fixed/reused buffer."
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            create_kek_for_test(&service);

            let mut wrapped1 = [0u8; 512];
            let mut wrapped1_len: c_int = wrapped1.len() as c_int;
            assert_eq!(
                hkdfguard_generate_and_wrap_dek(service.as_ptr(), wrapped1.as_mut_ptr(), &mut wrapped1_len),
                status::OK
            );
            let mut dek1 = [0u8; 32];
            let mut dek1_len: c_int = dek1.len() as c_int;
            assert_eq!(
                hkdfguard_unwrap_dek(service.as_ptr(), wrapped1.as_ptr(), wrapped1_len, dek1.as_mut_ptr(), &mut dek1_len),
                status::OK
            );

            let mut wrapped2 = [0u8; 512];
            let mut wrapped2_len: c_int = wrapped2.len() as c_int;
            assert_eq!(
                hkdfguard_generate_and_wrap_dek(service.as_ptr(), wrapped2.as_mut_ptr(), &mut wrapped2_len),
                status::OK
            );
            let mut dek2 = [0u8; 32];
            let mut dek2_len: c_int = dek2.len() as c_int;
            assert_eq!(
                hkdfguard_unwrap_dek(service.as_ptr(), wrapped2.as_ptr(), wrapped2_len, dek2.as_mut_ptr(), &mut dek2_len),
                status::OK
            );

            assert_ne!(dek1, dek2, "two generate_and_wrap_dek calls must produce different DEKs");
        });
    }

    #[test]
    #[serial]
    fn generate_and_wrap_buffer_too_small_reports_required_size_without_writing() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            create_kek_for_test(&service);
            let mut tiny = [0xFFu8; 4]; // way too small to hold a wrapped payload
            let mut tiny_len: c_int = tiny.len() as c_int;

            let rc = hkdfguard_generate_and_wrap_dek(service.as_ptr(), tiny.as_mut_ptr(), &mut tiny_len);
            assert_eq!(rc, status::BUFFER_TOO_SMALL);
            assert!(tiny_len > 4); // *out_len was updated to the actually-required size
            assert_eq!(tiny, [0xFFu8; 4], "must not write on BUFFER_TOO_SMALL"); // buffer contents untouched
        });
    }

    #[test]
    fn generate_and_wrap_null_service_is_invalid_service_name() {
        let mut out = [0u8; 512];
        let mut out_len: c_int = out.len() as c_int;
        let rc = hkdfguard_generate_and_wrap_dek(std::ptr::null(), out.as_mut_ptr(), &mut out_len);
        assert_eq!(rc, status::INVALID_SERVICE_NAME);
    }

    #[test]
    fn generate_and_wrap_null_out_len_is_invalid_argument() {
        let service = CString::new("com.company.orders").unwrap();
        let mut out = [0u8; 512];
        let rc = hkdfguard_generate_and_wrap_dek(service.as_ptr(), out.as_mut_ptr(), std::ptr::null_mut());
        assert_eq!(rc, status::INVALID_ARGUMENT);
    }

    #[test]
    fn rejects_wrong_dek_length() {
        let service = CString::new("com.company.orders").unwrap();
        let dek = [0u8; 16]; // deliberately wrong size (should be 32)
        let mut wrapped_buf = [0u8; 512];
        let mut wrapped_len: c_int = wrapped_buf.len() as c_int;

        let rc = hkdfguard_wrap_dek(
            service.as_ptr(),
            dek.as_ptr(),
            16, // claims 16, which must be rejected regardless of the actual buffer contents
            wrapped_buf.as_mut_ptr(),
            &mut wrapped_len,
        );
        assert_eq!(rc, status::INVALID_ARGUMENT);
    }

    #[test]
    #[serial]
    fn buffer_too_small_reports_required_size_without_writing() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            create_kek_for_test(&service);
            let dek = [0x55u8; 32];
            let mut tiny = [0xFFu8; 4]; // way too small to hold a wrapped payload
            let mut tiny_len: c_int = tiny.len() as c_int;

            let rc = hkdfguard_wrap_dek(
                service.as_ptr(),
                dek.as_ptr(),
                32,
                tiny.as_mut_ptr(),
                &mut tiny_len,
            );
            assert_eq!(rc, status::BUFFER_TOO_SMALL);
            assert!(tiny_len > 4); // *out_len was updated to the actually-required size
            assert_eq!(tiny, [0xFFu8; 4], "must not write on BUFFER_TOO_SMALL"); // buffer contents untouched
        });
    }

    #[test]
    #[serial]
    fn unwrap_failure_zeroes_caller_buffer() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            let garbage = [0u8; 8]; // not a valid wrapped payload at all
            let mut out = [0xAAu8; 32]; // pre-filled with a recognizable non-zero pattern
            let mut out_len: c_int = out.len() as c_int;

            let rc = hkdfguard_unwrap_dek(
                service.as_ptr(),
                garbage.as_ptr(),
                garbage.len() as c_int,
                out.as_mut_ptr(),
                &mut out_len,
            );
            assert_eq!(rc, status::PAYLOAD_UNSUPPORTED); // must fail, since `garbage` isn't a valid payload (its version byte is 0)
            assert_eq!(out, [0u8; 32], "output buffer must be zeroed on failure"); // and the buffer must be scrubbed regardless
        });
    }

    #[test]
    fn null_service_is_invalid_service_name() {
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = out.len() as c_int;
        let rc = hkdfguard_wrap_dek(
            std::ptr::null(), // deliberately null service pointer
            dek.as_ptr(),
            32,
            out.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(rc, status::INVALID_SERVICE_NAME);

        let rc = hkdfguard_unwrap_dek(
            std::ptr::null(),
            out.as_ptr(),
            32,
            out.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(rc, status::INVALID_SERVICE_NAME);
    }

    #[test]
    fn wrap_null_pointers_and_negative_lengths() {
        let service = CString::new("com.company.orders").unwrap();
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = 512;

        // Null dek pointer
        assert_eq!(
            hkdfguard_wrap_dek(
                service.as_ptr(),
                std::ptr::null(),
                32,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_ARGUMENT
        );

        // Null out_len pointer
        assert_eq!(
            hkdfguard_wrap_dek(
                service.as_ptr(),
                dek.as_ptr(),
                32,
                out.as_mut_ptr(),
                std::ptr::null_mut()
            ),
            status::INVALID_ARGUMENT
        );

        // Negative dek length
        assert_eq!(
            hkdfguard_wrap_dek(
                service.as_ptr(),
                dek.as_ptr(),
                -1,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_ARGUMENT
        );

        // Negative out_len capacity
        let mut neg_len: c_int = -5;
        assert_eq!(
            hkdfguard_wrap_dek(
                service.as_ptr(),
                dek.as_ptr(),
                32,
                out.as_mut_ptr(),
                &mut neg_len
            ),
            status::INVALID_ARGUMENT
        );
    }

    #[test]
    fn unwrap_zeroes_the_buffer_on_every_failure_with_a_known_capacity() {
        let service = CString::new("com.company.orders").unwrap();
        let wrapped = [0u8; 64];

        // NULL `wrapped`: capacity is known, so the buffer must be zeroed.
        let mut out = [0xAAu8; 32];
        let mut out_len: c_int = 32;
        assert_eq!(
            hkdfguard_unwrap_dek(service.as_ptr(), std::ptr::null(), 64, out.as_mut_ptr(), &mut out_len),
            status::INVALID_ARGUMENT
        );
        assert_eq!(out, [0u8; 32], "a NULL wrapped pointer must still leave out zeroed");

        // Invalid service name, then a payload that fails to parse.
        for svc in [std::ptr::null(), service.as_ptr()] {
            let mut out = [0xAAu8; 32];
            let mut out_len: c_int = 32;
            assert_ne!(
                hkdfguard_unwrap_dek(svc, wrapped.as_ptr(), 64, out.as_mut_ptr(), &mut out_len),
                status::OK
            );
            assert_eq!(out, [0u8; 32]);
        }

        // NULL `out_len`: no declared capacity, so nothing may be written.
        let mut out = [0xAAu8; 32];
        assert_eq!(
            hkdfguard_unwrap_dek(service.as_ptr(), wrapped.as_ptr(), 64, out.as_mut_ptr(), std::ptr::null_mut()),
            status::INVALID_ARGUMENT
        );
        assert_eq!(out, [0xAAu8; 32], "with no declared capacity the buffer must be left untouched");
    }

    #[test]
    fn unwrap_null_pointers_and_negative_lengths() {
        let service = CString::new("com.company.orders").unwrap();
        let wrapped = [0u8; 64];
        let mut out = [0x55u8; 32];
        let mut out_len: c_int = 32;

        // Null wrapped pointer
        assert_eq!(
            hkdfguard_unwrap_dek(
                service.as_ptr(),
                std::ptr::null(),
                64,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_ARGUMENT
        );

        // Null out_len pointer
        assert_eq!(
            hkdfguard_unwrap_dek(
                service.as_ptr(),
                wrapped.as_ptr(),
                64,
                out.as_mut_ptr(),
                std::ptr::null_mut()
            ),
            status::INVALID_ARGUMENT
        );

        // Negative wrapped_len
        assert_eq!(
            hkdfguard_unwrap_dek(
                service.as_ptr(),
                wrapped.as_ptr(),
                -1,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_ARGUMENT
        );
        assert_eq!(out, [0u8; 32]);

        // Negative out_len
        let mut neg_len: c_int = -1;
        assert_eq!(
            hkdfguard_unwrap_dek(
                service.as_ptr(),
                wrapped.as_ptr(),
                64,
                out.as_mut_ptr(),
                &mut neg_len
            ),
            status::INVALID_ARGUMENT
        );
    }

    #[test]
    fn service_validation_edge_cases() {
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = 512;

        // Empty service string
        let empty_svc = CString::new("").unwrap();
        assert_eq!(
            hkdfguard_wrap_dek(
                empty_svc.as_ptr(),
                dek.as_ptr(),
                32,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_SERVICE_NAME
        );
        assert_eq!(
            hkdfguard_unwrap_dek(
                empty_svc.as_ptr(),
                out.as_ptr(),
                64,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_SERVICE_NAME
        );

        // Oversized service string (> 128 bytes)
        let long_svc_str = "a".repeat(256);
        let long_svc = CString::new(long_svc_str).unwrap();
        assert_eq!(
            hkdfguard_wrap_dek(
                long_svc.as_ptr(),
                dek.as_ptr(),
                32,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_SERVICE_NAME
        );
        assert_eq!(
            hkdfguard_unwrap_dek(
                long_svc.as_ptr(),
                out.as_ptr(),
                64,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_SERVICE_NAME
        );

        // Invalid UTF-8 service string (e.g. 0xFF, 0xFE)
        let invalid_utf8 = [0xFFu8, 0xFEu8, 0x00u8];
        assert_eq!(
            hkdfguard_wrap_dek(
                invalid_utf8.as_ptr() as *const c_char,
                dek.as_ptr(),
                32,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_SERVICE_NAME
        );
        assert_eq!(
            hkdfguard_unwrap_dek(
                invalid_utf8.as_ptr() as *const c_char,
                out.as_ptr(),
                64,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_SERVICE_NAME
        );
    }

    #[test]
    #[serial]
    fn unwrap_buffer_too_small_sets_required_length_and_zeroes() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            create_kek_for_test(&service);
            let dek = [0x77u8; 32];
            let mut wrapped = [0u8; 512];
            let mut wrapped_len: c_int = 512;

            assert_eq!(
                hkdfguard_wrap_dek(
                    service.as_ptr(),
                    dek.as_ptr(),
                    32,
                    wrapped.as_mut_ptr(),
                    &mut wrapped_len
                ),
                status::OK
            );

            let mut tiny_out = [0xAAu8; 16];
            let mut tiny_out_len: c_int = 16;
            assert_eq!(
                hkdfguard_unwrap_dek(
                    service.as_ptr(),
                    wrapped.as_ptr(),
                    wrapped_len,
                    tiny_out.as_mut_ptr(),
                    &mut tiny_out_len
                ),
                status::BUFFER_TOO_SMALL
            );
            assert_eq!(tiny_out_len, 32);
            assert_eq!(tiny_out, [0u8; 16]);
        });
    }

    #[test]
    #[serial]
    fn boundary_service_lengths_round_trip() {
        with_isolated_ephemeral_provider(|| {
            let dek = [0x12u8; 32];

            // 1-byte service name
            let svc1 = CString::new("x").unwrap();
            create_kek_for_test(&svc1);
            let mut wrapped = [0u8; 512];
            let mut wrapped_len: c_int = 512;
            assert_eq!(
                hkdfguard_wrap_dek(
                    svc1.as_ptr(),
                    dek.as_ptr(),
                    32,
                    wrapped.as_mut_ptr(),
                    &mut wrapped_len
                ),
                status::OK
            );
            let mut out = [0u8; 32];
            let mut out_len: c_int = 32;
            assert_eq!(
                hkdfguard_unwrap_dek(
                    svc1.as_ptr(),
                    wrapped.as_ptr(),
                    wrapped_len,
                    out.as_mut_ptr(),
                    &mut out_len
                ),
                status::OK
            );
            assert_eq!(out, dek);

            // 128-byte service name (the maximum)
            let svc128 = CString::new("s".repeat(128)).unwrap();
            create_kek_for_test(&svc128);
            let mut wrapped2 = [0u8; 512];
            let mut wrapped2_len: c_int = 512;
            assert_eq!(
                hkdfguard_wrap_dek(
                    svc128.as_ptr(),
                    dek.as_ptr(),
                    32,
                    wrapped2.as_mut_ptr(),
                    &mut wrapped2_len
                ),
                status::OK
            );
            let mut out2 = [0u8; 32];
            let mut out2_len: c_int = 32;
            assert_eq!(
                hkdfguard_unwrap_dek(
                    svc128.as_ptr(),
                    wrapped2.as_ptr(),
                    wrapped2_len,
                    out2.as_mut_ptr(),
                    &mut out2_len
                ),
                status::OK
            );
            assert_eq!(out2, dek);
        });
    }

    #[test]
    #[serial]
    fn service_name_over_128_bytes_is_invalid_service_name() {
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = 512;

        let svc129 = CString::new("s".repeat(129)).unwrap();
        assert_eq!(
            hkdfguard_wrap_dek(svc129.as_ptr(), dek.as_ptr(), 32, out.as_mut_ptr(), &mut out_len),
            status::INVALID_SERVICE_NAME
        );
    }

    #[test]
    #[serial]
    fn service_name_rejects_non_alphanumeric_dot_characters() {
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = 512;

        for bad in ["com_example.orders", "com example.orders", "com-example.orders", "com/example"] {
            let svc = CString::new(bad).unwrap();
            assert_eq!(
                hkdfguard_wrap_dek(svc.as_ptr(), dek.as_ptr(), 32, out.as_mut_ptr(), &mut out_len),
                status::INVALID_SERVICE_NAME,
                "should reject \"{bad}\""
            );
        }
    }

    #[test]
    fn service_name_rejects_leading_dot_and_consecutive_dots() {
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = 512;
        let mut exists: c_int = 0;

        // Every entry point rejects these before any provider sees them.
        for bad in [".", "..", "...", ".hidden", ".com.example", "..parent", "com..example", "com.example..", "a...b"] {
            let svc = CString::new(bad).unwrap();
            assert_eq!(hkdfguard_create_kek(svc.as_ptr()), status::INVALID_SERVICE_NAME, "create_kek {bad:?}");
            assert_eq!(hkdfguard_kek_exists(svc.as_ptr(), &mut exists), status::INVALID_SERVICE_NAME, "kek_exists {bad:?}");
            assert_eq!(
                hkdfguard_wrap_dek(svc.as_ptr(), dek.as_ptr(), 32, out.as_mut_ptr(), &mut out_len),
                status::INVALID_SERVICE_NAME,
                "wrap {bad:?}"
            );
            let mut dek_out = [0u8; 32];
            let mut dek_out_len: c_int = 32;
            assert_eq!(
                hkdfguard_unwrap_dek(svc.as_ptr(), out.as_ptr(), 64, dek_out.as_mut_ptr(), &mut dek_out_len),
                status::INVALID_SERVICE_NAME,
                "unwrap {bad:?}"
            );
        }
    }

    #[test]
    #[serial]
    fn service_name_with_single_interior_and_trailing_dots_is_still_accepted() {
        // The dot rules only forbid a leading dot and consecutive dots;
        // ordinary dotted names (and a single trailing dot) are unaffected.
        with_isolated_ephemeral_provider(|| {
            for ok in ["com.example.dottest", "a.b.c.d", "x", "com.example.trailing."] {
                let svc = CString::new(ok).unwrap();
                assert_eq!(hkdfguard_create_kek(svc.as_ptr()), status::OK, "{ok:?}");
            }
        });
    }

    #[test]
    #[serial]
    fn service_name_is_normalized_to_lowercase() {
        with_isolated_ephemeral_provider(|| {
            let dek = [0x55u8; 32];
            let mixed_case = CString::new("Com.Example.Orders").unwrap();
            create_kek_for_test(&mixed_case); // normalizes to lowercase internally, same as wrap/unwrap
            let mut wrapped = [0u8; 512];
            let mut wrapped_len: c_int = 512;
            assert_eq!(
                hkdfguard_wrap_dek(
                    mixed_case.as_ptr(),
                    dek.as_ptr(),
                    32,
                    wrapped.as_mut_ptr(),
                    &mut wrapped_len
                ),
                status::OK
            );

            // A different-case (but otherwise identical) service string
            // must unwrap the same payload -- proving both sides normalize
            // to the same canonical (lowercase) form.
            let lowercase = CString::new("com.example.orders").unwrap();
            let mut out = [0u8; 32];
            let mut out_len: c_int = 32;
            assert_eq!(
                hkdfguard_unwrap_dek(
                    lowercase.as_ptr(),
                    wrapped.as_ptr(),
                    wrapped_len,
                    out.as_mut_ptr(),
                    &mut out_len
                ),
                status::OK
            );
            assert_eq!(out, dek);

            // And a third, differently-cased variant of the very same name
            // must also unwrap it.
            let shouty_case = CString::new("COM.EXAMPLE.ORDERS").unwrap();
            let mut out2 = [0u8; 32];
            let mut out2_len: c_int = 32;
            assert_eq!(
                hkdfguard_unwrap_dek(
                    shouty_case.as_ptr(),
                    wrapped.as_ptr(),
                    wrapped_len,
                    out2.as_mut_ptr(),
                    &mut out2_len
                ),
                status::OK
            );
            assert_eq!(out2, dek);
        });
    }

    #[test]
    #[serial]
    fn create_kek_then_kek_exists_then_wrap_succeeds() {
        with_isolated_ephemeral_provider(|| {
            // A service name unique to this test: Ephemeral's key map is
            // process-global and never cleared between tests, so a
            // generic name another test also resolves via Ephemeral
            // could already exist by the time this "starts nonexistent"
            // assertion runs.
            let service = CString::new("com.company.orders.kekexiststest").unwrap();

            let mut exists: c_int = -1; // recognizable sentinel, must be overwritten
            assert_eq!(hkdfguard_kek_exists(service.as_ptr(), &mut exists), status::OK);
            assert_eq!(exists, 0);

            assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);

            assert_eq!(hkdfguard_kek_exists(service.as_ptr(), &mut exists), status::OK);
            assert_eq!(exists, 1);

            // hkdfguard_create_kek is idempotent: calling it again for a
            // service that already has one just confirms it, no error.
            assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);

            let dek = [0x66u8; 32];
            let mut wrapped = [0u8; 512];
            let mut wrapped_len: c_int = 512;
            assert_eq!(
                hkdfguard_wrap_dek(service.as_ptr(), dek.as_ptr(), 32, wrapped.as_mut_ptr(), &mut wrapped_len),
                status::OK
            );
        });
    }

    #[test]
    #[serial]
    fn wrap_before_create_kek_fails_with_kek_not_found() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.unprovisioned").unwrap();
            let dek = [0x11u8; 32];
            let mut wrapped = [0u8; 512];
            let mut wrapped_len: c_int = 512;

            let rc = hkdfguard_wrap_dek(service.as_ptr(), dek.as_ptr(), 32, wrapped.as_mut_ptr(), &mut wrapped_len);
            assert_eq!(rc, status::KEK_NOT_FOUND);
        });
    }

    #[test]
    #[serial]
    fn unwrap_after_kek_rotation_fails_with_fingerprint_mismatch() {
        // external-secret, not Ephemeral, is what's rotated here: this
        // test needs key material something *outside* this process can
        // rewrite, and Ephemeral is in-memory only -- there's no file to
        // rotate out from under it. Pinned by policy, or a reachable
        // TPM/PKCS#11 device would win the chain and there would be
        // nothing for the rotation below to rotate.
        let _policy = policy::require_provider_policy_for_tests("external-secret");
        let ext_dir = crate::secure_file::private_tempdir();
        let _secret_mount = crate::policy::test_support::secret_mount(ext_dir.path());
        let service_str = "com.company.rotated";
        let secret_path = ext_dir.path().join(service_str);
        let service = CString::new(service_str).unwrap();

        std::fs::write(&secret_path, provider::random_kek_for_tests()).unwrap();
        // Owner-only, as the provider requires of a KEK file. The rotation
        // rewrite below preserves this mode, so it's set once.
        std::fs::set_permissions(&secret_path, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600)).unwrap();
        create_kek_for_test(&service); // finds the pre-provisioned key; external-secret never creates one itself

        let dek = [0x33u8; 32];
        let mut wrapped = [0u8; 512];
        let mut wrapped_len: c_int = 512;
        assert_eq!(
            hkdfguard_wrap_dek(service.as_ptr(), dek.as_ptr(), 32, wrapped.as_mut_ptr(), &mut wrapped_len),
            status::OK
        );

        // Simulate an out-of-band KEK rotation: the deployment platform
        // rewrites the mounted secret file with a brand new, unrelated
        // key under the exact same service name.
        std::fs::write(&secret_path, provider::random_kek_for_tests()).unwrap();

        let mut out = [0xAAu8; 32]; // recognizable non-zero pattern
        let mut out_len: c_int = out.len() as c_int;
        let rc = hkdfguard_unwrap_dek(
            service.as_ptr(),
            wrapped.as_ptr(),
            wrapped_len,
            out.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(rc, status::KEK_FINGERPRINT_MISMATCH);
        assert_eq!(rc, -16, "pinned by the status table shared with Windows and macOS");
        assert_eq!(out, [0u8; 32], "output buffer must still be zeroed on failure");

    }

    #[test]
    fn unterminated_service_buffer_is_rejected_without_over_reading() {
        // A buffer of MAX_SERVICE_LEN + 1 non-NUL bytes and *no*
        // terminator at all. `CStr::from_ptr` would read past the end of
        // this array looking for a zero byte; the bounded scan reads
        // exactly the 129 bytes that exist, finds no NUL, and rejects.
        // An unbounded scan would make this test undefined behavior.
        let unterminated = [b'a'; MAX_SERVICE_LEN + 1];
        let rc = hkdfguard_create_kek(unterminated.as_ptr() as *const c_char);
        assert_eq!(rc, status::INVALID_SERVICE_NAME);

        // And the boundary still behaves: exactly MAX_SERVICE_LEN bytes
        // plus a terminator is accepted by the parser (it may then fail
        // for provider reasons, but never as an invalid service name).
        let mut at_limit = [b'a'; MAX_SERVICE_LEN + 1];
        at_limit[MAX_SERVICE_LEN] = 0;
        assert!(cstr_to_service(at_limit.as_ptr() as *const c_char).is_ok());

        // One byte over, terminated: rejected by the length rule.
        let mut over = [b'a'; MAX_SERVICE_LEN + 2];
        over[MAX_SERVICE_LEN + 1] = 0;
        assert_eq!(
            cstr_to_service(over.as_ptr() as *const c_char).unwrap_err(),
            status::INVALID_SERVICE_NAME
        );
    }

    #[test]
    fn create_kek_and_kek_exists_null_service_is_invalid_service_name() {
        assert_eq!(hkdfguard_create_kek(std::ptr::null()), status::INVALID_SERVICE_NAME);

        let mut exists: c_int = 0;
        assert_eq!(
            hkdfguard_kek_exists(std::ptr::null(), &mut exists),
            status::INVALID_SERVICE_NAME
        );
    }

    #[test]
    #[serial]
    fn kek_exists_null_out_pointer_is_invalid_argument() {
        let service = CString::new("com.company.orders").unwrap();
        assert_eq!(
            hkdfguard_kek_exists(service.as_ptr(), std::ptr::null_mut()),
            status::INVALID_ARGUMENT
        );
    }

    // ---- hkdfguard_open_file ----

    // hkdfguard_open_file reads the policy for its security model, so a test
    // of it holds a policy (and is #[serial]). These tests' key files are
    // this user's own, which the developer model trusts; the production
    // model's tests say so.
    fn developer_policy() -> policy::test_support::TestPolicy {
        policy::test_support::TestPolicy::write("security_model = \"developer\"\n")
    }

    // Writes `contents` owner-only into a fresh private directory, as the
    // CLI writes a key file; the directory is returned to keep it alive.
    fn key_file_with(contents: &[u8]) -> (tempfile::TempDir, CString) {
        use std::os::unix::fs::PermissionsExt;
        let dir = secure_file::private_tempdir();
        let path = dir.path().join("wrapped.key");
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (dir, CString::new(path.into_os_string().into_encoded_bytes()).unwrap())
    }

    // A real payload, from the real wrap entry point.
    fn wrapped_for_test(service: &CString, dek: &[u8; 32]) -> Vec<u8> {
        create_kek_for_test(service);
        let mut buf = [0u8; crypto::MAX_WRAPPED_LEN];
        let mut len = buf.len() as c_int;
        assert_eq!(hkdfguard_wrap_dek(service.as_ptr(), dek.as_ptr(), 32, buf.as_mut_ptr(), &mut len), status::OK);
        buf[..len as usize].to_vec()
    }

    // Calls hkdfguard_open_file with a buffer of `capacity` bytes, prefilled
    // with 0xAA so a failure's zeroing is visible.
    fn open_file(path: &CString, capacity: usize) -> (c_int, Vec<u8>, c_int) {
        let mut out = vec![0xAAu8; capacity];
        let mut out_len = capacity as c_int;
        let rc = hkdfguard_open_file(path.as_ptr(), out.as_mut_ptr(), &mut out_len);
        (rc, out, out_len)
    }

    fn sample_wrapped_bytes() -> Vec<u8> {
        payload::Payload {
            provider_type: provider::ProviderType::Ephemeral,
            key_id: b"ephemeral:com.company.orders".to_vec(),
            salt: [1; payload::SALT_LEN],
            nonce: [2; payload::NONCE_LEN],
            ciphertext: vec![3; crypto::DEK_LEN + crypto::TAG_LEN],
            fingerprint: [4; payload::FINGERPRINT_LEN],
        }
        .to_bytes()
    }

    #[test]
    #[serial]
    fn open_file_then_unwrap_recovers_the_dek() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders.openfile").unwrap();
            let dek = [0x5Cu8; 32];
            let wrapped = wrapped_for_test(&service, &dek);
            let (_dir, path) = key_file_with(&wrapped);

            let (rc, out, out_len) = open_file(&path, crypto::MAX_WRAPPED_LEN);
            assert_eq!(rc, status::OK);
            assert_eq!(out_len as usize, wrapped.len(), "out_len is the number of bytes read");
            assert_eq!(&out[..wrapped.len()], &wrapped[..], "the file's bytes, exactly as stored");
            assert!(out[wrapped.len()..].iter().all(|&b| b == 0xAA), "nothing written past the payload");

            let mut recovered = [0u8; 32];
            let mut recovered_len: c_int = 32;
            let rc = hkdfguard_unwrap_dek(service.as_ptr(), out.as_ptr(), out_len, recovered.as_mut_ptr(), &mut recovered_len);
            assert_eq!(rc, status::OK);
            assert_eq!(recovered, dek);
        });
    }

    #[test]
    #[serial]
    fn open_file_accepts_an_exact_size_buffer() {
        let _policy = developer_policy();
        let bytes = sample_wrapped_bytes();
        let (_dir, path) = key_file_with(&bytes);
        let (rc, out, out_len) = open_file(&path, bytes.len());
        assert_eq!(rc, status::OK);
        assert_eq!(out_len as usize, bytes.len());
        assert_eq!(out, bytes);
    }

    #[test]
    #[serial]
    fn open_file_reports_each_refusal_and_zeroes_the_buffer() {
        let _policy = developer_policy();
        let valid = sample_wrapped_bytes();
        let mut long = valid.clone();
        long.push(0);
        let mut bad_version = valid.clone();
        bad_version[0] = 2; // a version this library does not know
        let b64_dek = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode([9u8; 32]) + "\n"
        };
        let cases: [(&str, Vec<u8>, c_int); 8] = [
            ("empty", vec![], status::FILE_TOO_SHORT),
            ("truncated", valid[..valid.len() - 1].to_vec(), status::FILE_TOO_SHORT),
            ("appended", long, status::FILE_TOO_LONG),
            ("oversized", vec![0u8; crypto::MAX_WRAPPED_LEN + 1], status::FILE_TOO_LONG),
            ("bad version", bad_version, status::FILE_MALFORMED),
            ("raw DEK", vec![9u8; 32], status::FILE_PLAINTEXT_KEY),
            ("base64 DEK", b64_dek.into_bytes(), status::FILE_PLAINTEXT_KEY),
            ("garbage", vec![0xEEu8; 200], status::FILE_MALFORMED),
        ];
        for (name, contents, expected) in cases {
            let (_dir, path) = key_file_with(&contents);
            let (rc, out, out_len) = open_file(&path, crypto::MAX_WRAPPED_LEN);
            assert_eq!(rc, expected, "{name}");
            assert_eq!(out_len, crypto::MAX_WRAPPED_LEN as c_int, "{name}: *out_len left as the caller set it");
            assert!(out.iter().all(|&b| b == 0), "{name}: the whole buffer is zeroed");
        }
    }

    #[test]
    #[serial]
    fn open_file_reports_why_a_file_could_not_be_opened() {
        let _policy = developer_policy();
        let dir = secure_file::private_tempdir();
        let missing = CString::new(dir.path().join("absent.key").into_os_string().into_encoded_bytes()).unwrap();
        let (rc, out, out_len) = open_file(&missing, crypto::MAX_WRAPPED_LEN);
        assert_eq!((rc, out_len), (status::FILE_NOT_FOUND, crypto::MAX_WRAPPED_LEN as c_int));
        assert!(out.iter().all(|&b| b == 0));

        let directory = CString::new(dir.path().as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(open_file(&directory, crypto::MAX_WRAPPED_LEN).0, status::FILE_IO);

        if !secure_file::skip_as_root() {
            use std::os::unix::fs::PermissionsExt;
            let (dir, path) = key_file_with(&sample_wrapped_bytes());
            std::fs::set_permissions(dir.path().join("wrapped.key"), std::fs::Permissions::from_mode(0o000)).unwrap();
            assert_eq!(open_file(&path, crypto::MAX_WRAPPED_LEN).0, status::FILE_ACCESS_DENIED);
        }
    }

    #[test]
    #[serial]
    fn open_file_refuses_a_key_file_someone_else_could_have_replaced() {
        let _policy = developer_policy();
        use std::os::unix::fs::PermissionsExt;
        let bytes = sample_wrapped_bytes();
        let (dir, path) = key_file_with(&bytes);
        let file = dir.path().join("wrapped.key");
        for mode in [0o660, 0o606] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            let (rc, out, out_len) = open_file(&path, crypto::MAX_WRAPPED_LEN);
            assert_eq!((rc, out_len), (status::FILE_UNTRUSTED, crypto::MAX_WRAPPED_LEN as c_int), "mode {mode:o}");
            assert!(out.iter().all(|&b| b == 0), "mode {mode:o}: nothing of the file is handed over");
        }
        // Read-only for others is fine: the contents are ciphertext.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (rc, out, out_len) = open_file(&path, crypto::MAX_WRAPPED_LEN);
        assert_eq!(rc, status::OK);
        assert_eq!(&out[..out_len as usize], &bytes[..]);

        // A 0600 file in a directory others can write: they could rename
        // their own file over it.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let (rc, out, out_len) = open_file(&path, crypto::MAX_WRAPPED_LEN);
        assert_eq!((rc, out_len), (status::FILE_UNTRUSTED, crypto::MAX_WRAPPED_LEN as c_int), "writable directory");
        assert!(out.iter().all(|&b| b == 0));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn open_file_too_small_for_any_payload_answers_without_opening_the_file() {
        // A nonexistent path, so reaching the file would be FILE_NOT_FOUND.
        let missing = CString::new("/nonexistent-hkdfguard-open-file-test/wrapped.key").unwrap();
        for capacity in [0usize, 1, crypto::MIN_WRAPPED_LEN - 1] {
            let (rc, out, out_len) = open_file(&missing, capacity);
            assert_eq!(rc, status::BUFFER_TOO_SMALL, "capacity {capacity}");
            assert_eq!(out_len as usize, crypto::MAX_WRAPPED_LEN, "a size that always fits");
            assert!(out.iter().all(|&b| b == 0));
        }
        // The size probe: NULL out with a capacity of 0.
        let mut out_len: c_int = 0;
        assert_eq!(hkdfguard_open_file(missing.as_ptr(), ptr::null_mut(), &mut out_len), status::BUFFER_TOO_SMALL);
        assert_eq!(out_len as usize, crypto::MAX_WRAPPED_LEN);
    }

    #[test]
    #[serial]
    fn open_file_buffer_shorter_than_the_file_reports_its_exact_length() {
        let _policy = developer_policy();
        let bytes = sample_wrapped_bytes();
        let (_dir, path) = key_file_with(&bytes);
        let (rc, out, out_len) = open_file(&path, bytes.len() - 1);
        assert_eq!(rc, status::BUFFER_TOO_SMALL);
        assert_eq!(out_len as usize, bytes.len());
        assert!(out.iter().all(|&b| b == 0), "nothing of the file is left in a too-small buffer");
    }

    #[test]
    #[serial]
    fn open_file_invalid_arguments() {
        let _policy = developer_policy();
        let bytes = sample_wrapped_bytes();
        let (_dir, path) = key_file_with(&bytes);
        let mut out = [0xAAu8; crypto::MAX_WRAPPED_LEN];

        // NULL out_len: nothing to report through, nothing written.
        assert_eq!(hkdfguard_open_file(path.as_ptr(), out.as_mut_ptr(), ptr::null_mut()), status::INVALID_ARGUMENT);
        assert!(out.iter().all(|&b| b == 0xAA), "no declared capacity, so `out` is untouched");

        // NULL path, empty path.
        let empty = CString::new("").unwrap();
        for p in [ptr::null(), empty.as_ptr()] {
            let mut out_len = out.len() as c_int;
            assert_eq!(hkdfguard_open_file(p, out.as_mut_ptr(), &mut out_len), status::INVALID_ARGUMENT);
            assert_eq!(out_len, out.len() as c_int, "*out_len left unchanged");
        }

        // Negative capacity.
        let mut out_len: c_int = -1;
        assert_eq!(hkdfguard_open_file(path.as_ptr(), out.as_mut_ptr(), &mut out_len), status::INVALID_ARGUMENT);
        assert_eq!(out_len, -1, "*out_len left unchanged");

        // NULL out with a positive capacity.
        let mut out_len = out.len() as c_int;
        assert_eq!(hkdfguard_open_file(path.as_ptr(), ptr::null_mut(), &mut out_len), status::INVALID_ARGUMENT);
        assert_eq!(out_len, out.len() as c_int, "*out_len left unchanged");
    }

    #[test]
    fn open_file_unterminated_path_is_rejected_without_over_reading() {
        // Exactly MAX_PATH_BYTES non-NUL bytes and no terminator: the scan
        // must stop at the end of this buffer rather than run past it.
        let unterminated = vec![b'a'; MAX_PATH_BYTES];
        let mut out = [0u8; crypto::MAX_WRAPPED_LEN];
        let mut out_len = out.len() as c_int;
        let rc = hkdfguard_open_file(unterminated.as_ptr() as *const c_char, out.as_mut_ptr(), &mut out_len);
        assert_eq!(rc, status::INVALID_ARGUMENT);

        // One byte shorter, terminated, is a path (here, a missing one).
        let mut at_limit = vec![b'a'; MAX_PATH_BYTES];
        at_limit[MAX_PATH_BYTES - 1] = 0;
        assert!(cstr_to_path(at_limit.as_ptr() as *const c_char).is_ok());
    }

    #[test]
    #[serial]
    fn open_file_accepts_a_non_utf8_path() {
        let _policy = developer_policy();
        use std::os::unix::ffi::OsStrExt;
        let bytes = sample_wrapped_bytes();
        let dir = secure_file::private_tempdir();
        let name = std::ffi::OsStr::from_bytes(b"wrapped-\xFF.key");
        let file = dir.path().join(name);
        std::fs::write(&file, &bytes).unwrap();
        // Owner-only, as key_file_with sets it: under a umask of 002 the file
        // would be group-writable and refused as FILE_UNTRUSTED.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let path = CString::new(file.into_os_string().into_encoded_bytes()).unwrap();
        let (rc, out, out_len) = open_file(&path, crypto::MAX_WRAPPED_LEN);
        assert_eq!(rc, status::OK);
        assert_eq!(&out[..out_len as usize], &bytes[..]);
    }

    // ---- the audit trail (see `audit`; records are captured in memory in test builds) ----

    #[test]
    #[serial]
    fn create_wrap_and_unwrap_are_audited_with_the_service_and_one_payload_hash() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.audit.trail").unwrap();
            create_kek_for_test(&service);
            let created = audit::captured_containing("service=\"com.company.audit.trail\"");
            // The test policy prefers external-secret, which isn't set up
            // here, so the KEK lands on Ephemeral: a fallback (1001).
            assert!(
                created.iter().any(|r| r.starts_with("<84>")
                    && r.contains("event=1001 op=hkdfguard_create_kek")
                    && r.contains("provider=EPHEMERAL preferred=EXTERNAL_SECRET")),
                "creating the KEK off the first choice is audited as a fallback: {created:?}"
            );
            // A second create finds it: no second creation record.
            create_kek_for_test(&service);
            let again = audit::captured_containing("service=\"com.company.audit.trail\"");
            assert_eq!(
                again.iter().filter(|r| r.contains("event=1000 ") || r.contains("event=1001 ")).count(),
                1,
                "only a real creation is audited"
            );

            let wrapped = wrapped_for_test(&service, &[7u8; 32]);
            let mut out = [0u8; 32];
            let mut out_len = out.len() as c_int;
            assert_eq!(
                hkdfguard_unwrap_dek(service.as_ptr(), wrapped.as_ptr(), wrapped.len() as c_int, out.as_mut_ptr(), &mut out_len),
                status::OK
            );

            use sha2::{Digest, Sha256};
            let hash: String = Sha256::digest(&wrapped).iter().map(|b| format!("{b:02x}")).collect();
            let records = audit::captured_containing(&hash);
            assert!(records.iter().any(|r| r.contains("event=1002 op=hkdfguard_wrap_dek result=OK service=\"com.company.audit.trail\"")), "{records:?}");
            assert!(records.iter().any(|r| r.contains("event=1003 op=hkdfguard_unwrap_dek result=OK service=\"com.company.audit.trail\"")), "{records:?}");
            assert!(records.iter().all(|r| r.contains("kek_fingerprint=") && r.contains(" uid=")), "{records:?}");

            // A tampered payload: the failed unwrap is audited (2003).
            let mut tampered = wrapped.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            let mut out_len = out.len() as c_int;
            assert_ne!(
                hkdfguard_unwrap_dek(service.as_ptr(), tampered.as_ptr(), tampered.len() as c_int, out.as_mut_ptr(), &mut out_len),
                status::OK
            );
            let failures = audit::captured_containing("op=hkdfguard_unwrap_dek result=");
            assert!(failures.iter().any(|r| r.contains("event=2003 ") && r.contains("service=\"com.company.audit.trail\"")), "{failures:?}");

            // A caller mistake is not.
            let before = audit::captured_containing("com.company.audit.trail").len();
            let mut tiny = [0u8; 1];
            let mut tiny_len = 1;
            assert_eq!(
                hkdfguard_unwrap_dek(service.as_ptr(), wrapped.as_ptr(), wrapped.len() as c_int, tiny.as_mut_ptr(), &mut tiny_len),
                status::BUFFER_TOO_SMALL
            );
            assert_eq!(audit::captured_containing("com.company.audit.trail").len(), before);
        });
    }

    #[test]
    #[serial]
    fn audit_unwrap_success_false_silences_only_the_unwrap_success_record() {
        let _policy = crate::policy::test_support::TestPolicy::write(
            "preferred_order = [\"ephemeral\"]\n[selection]\nmode = \"prefer\"\n[audit]\nunwrap_success = false\n",
        );
        let service = CString::new("com.company.audit.quiet").unwrap();
        create_kek_for_test(&service);
        let wrapped = wrapped_for_test(&service, &[9u8; 32]);
        let mut out = [0u8; 32];
        let mut out_len = out.len() as c_int;
        assert_eq!(
            hkdfguard_unwrap_dek(service.as_ptr(), wrapped.as_ptr(), wrapped.len() as c_int, out.as_mut_ptr(), &mut out_len),
            status::OK
        );
        let records = audit::captured_containing("service=\"com.company.audit.quiet\"");
        assert!(records.iter().any(|r| r.contains("event=1002 ")), "wrap is still audited: {records:?}");
        assert!(!records.iter().any(|r| r.contains("event=1003 ")), "unwrap success is not: {records:?}");
    }

    #[test]
    #[serial]
    fn an_audit_section_with_a_non_boolean_is_an_invalid_policy() {
        let _policy = crate::policy::test_support::TestPolicy::write(
            "preferred_order = [\"ephemeral\"]\n[selection]\nmode = \"prefer\"\n[audit]\nunwrap_success = 0\n",
        );
        assert!(matches!(crate::policy::load(), Some(Err(_))));
        assert!(crate::policy::audit_unwrap_success(), "a broken policy keeps unwrap auditing on");
    }

    #[test]
    #[serial]
    fn a_plaintext_key_file_is_audited_with_its_path() {
        let _policy = developer_policy();
        let (_dir, path) = key_file_with(&[9u8; 32]);
        let (rc, _, _) = open_file(&path, crypto::MAX_WRAPPED_LEN);
        assert_eq!(rc, status::FILE_PLAINTEXT_KEY);
        let shown = path.to_str().unwrap();
        let records = audit::captured_containing(shown);
        assert!(records.iter().any(|r| r.contains("event=2006 op=hkdfguard_open_file")), "{records:?}");
    }

    // ---- the security model ----

    fn security_model_now() -> (c_int, c_int, c_int) {
        let (mut model, mut may_write) = (-7, -7);
        let rc = hkdfguard_security_model(&mut model, &mut may_write);
        (rc, model, may_write)
    }

    fn principal_trusted(principal: &str) -> (c_int, c_int) {
        let principal = CString::new(principal).unwrap();
        let mut trusted = -7;
        let rc = hkdfguard_key_file_principal_trusted(principal.as_ptr(), &mut trusted);
        (rc, trusted)
    }

    fn euid() -> u32 {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() }
    }

    #[test]
    #[serial]
    fn security_model_reports_production_by_default_and_developer_when_set() {
        let _none = policy::test_support::TestPolicy::absent();
        // Production trusts root and deployers, and with no deployer_groups
        // the only deployers are hkdfguard-deployers' members -- which the
        // account running this may be (docker/Dockerfile's `ci` is).
        let production_trusted =
            (euid() == 0 || security_model::Trust::this_user_is_packaged_deployer_for_tests()) as c_int;
        assert_eq!(security_model_now(), (status::OK, 0, production_trusted), "no policy file: production");
        drop(_none);
        let _dev = developer_policy();
        assert_eq!(security_model_now(), (status::OK, 1, 1), "developer: this account's files are trusted");
        let _prod = policy::test_support::TestPolicy::write("security_model = \"production\"\n");
        assert_eq!(security_model_now(), (status::OK, 0, production_trusted));
    }

    #[test]
    #[serial]
    fn security_model_fails_closed_and_leaves_its_outputs_alone() {
        let _bad = policy::test_support::TestPolicy::exact("security_model = \"lenient\"\n[selection]\nmode = \"prefer\"\n");
        assert_eq!(security_model_now(), (status::POLICY_INVALID, -7, -7));
        assert_eq!(principal_trusted("uid:0"), (status::POLICY_INVALID, -7));
        drop(_bad);
        let _missing = policy::test_support::TestPolicy::write("deployer_groups = [\"hkdfguard-no-such-group-xyz\"]\nsecurity_model = \"production\"\n");
        assert_eq!(security_model_now(), (status::LINUX_GROUP_INVALID, -7, -7));
        let mut model = 0;
        assert_eq!(hkdfguard_security_model(&mut model, ptr::null_mut()), status::INVALID_ARGUMENT);
        assert_eq!(hkdfguard_security_model(ptr::null_mut(), &mut model), status::INVALID_ARGUMENT);
    }

    #[test]
    #[serial]
    fn key_file_principal_trusted_answers_by_the_model_in_force() {
        let me = format!("uid:{}", euid());
        let _dev = developer_policy();
        assert_eq!(principal_trusted("uid:0"), (status::OK, 1), "root, always");
        assert_eq!(principal_trusted(&me), (status::OK, 1), "developer: this account");
        assert_eq!(principal_trusted("gid:0"), (status::OK, 0), "developer: no group may write");
        let _prod = policy::test_support::TestPolicy::write("security_model = \"production\"\n");
        assert_eq!(principal_trusted("uid:0"), (status::OK, 1));
        if euid() != 0 && crate::security_model::Trust::current().is_ok_and(|t| !t.may_write_key_files()) {
            assert_eq!(principal_trusted(&me), (status::OK, 0), "production: not for being the caller");
        }
    }

    #[test]
    fn key_file_principal_trusted_takes_only_uid_or_gid_and_a_decimal_number() {
        for bad in ["", "uid", "uid:", "uid:-1", "uid:+1", "uid: 1", "uid:0x10", "user:0", "UID:0", "uid:4294967296", "gid:99999999999"] {
            assert_eq!(principal_trusted(bad), (status::INVALID_ARGUMENT, -7), "{bad:?}");
        }
        assert_eq!(cstr_to_principal(CString::new("uid:4294967295").unwrap().as_ptr()), Ok(Principal::Uid(u32::MAX)));
        assert_eq!(cstr_to_principal(CString::new("gid:0").unwrap().as_ptr()), Ok(Principal::Gid(0)));
        assert_eq!(cstr_to_principal(ptr::null()), Err(status::INVALID_ARGUMENT));
        // No terminator within the limit: refused without reading past it.
        let unterminated = [b'1'; MAX_PRINCIPAL_BYTES];
        assert_eq!(cstr_to_principal(unterminated.as_ptr() as *const c_char), Err(status::INVALID_ARGUMENT));
        let mut trusted = 0;
        assert_eq!(hkdfguard_key_file_principal_trusted(ptr::null(), &mut trusted), status::INVALID_ARGUMENT);
        let root = CString::new("uid:0").unwrap();
        assert_eq!(hkdfguard_key_file_principal_trusted(root.as_ptr(), ptr::null_mut()), status::INVALID_ARGUMENT);
    }

    #[test]
    #[serial]
    fn production_open_file_refuses_this_account_s_own_key_file() {
        if euid() != 0 {
            let bytes = sample_wrapped_bytes();
            let (_dir, path) = key_file_with(&bytes);
            let _none = policy::test_support::TestPolicy::absent();
            if crate::security_model::Trust::current().is_ok_and(|t| !t.may_write_key_files()) {
                let (rc, out, _) = open_file(&path, crypto::MAX_WRAPPED_LEN);
                assert_eq!(rc, status::FILE_UNTRUSTED, "no policy file: production, and this account is no deployer");
                assert!(out.iter().all(|&b| b == 0));
            }
            drop(_none);
            let _dev = developer_policy();
            assert_eq!(open_file(&path, crypto::MAX_WRAPPED_LEN).0, status::OK);
        }
    }

    #[test]
    #[serial]
    fn a_key_file_read_under_the_developer_model_is_audited_once() {
        let _dev = developer_policy();
        let (_dir, path) = key_file_with(&sample_wrapped_bytes());
        assert_eq!(open_file(&path, crypto::MAX_WRAPPED_LEN).0, status::OK);
        assert_eq!(open_file(&path, crypto::MAX_WRAPPED_LEN).0, status::OK);
        let records = audit::captured_containing("event=1005");
        assert_eq!(records.len(), 1, "once per process: {records:?}");
        assert!(records[0].contains("security_model=developer"), "{records:?}");
    }

    #[test]
    #[serial]
    fn production_lets_only_root_create_a_kek_but_anyone_load_one() {
        if euid() == 0 {
            return; // root may create under every model: nothing to refuse
        }
        // External-secret never creates a KEK, and its mount is empty: the
        // walk finds none, so the result says who may create one.
        let mount = secure_file::private_tempdir();
        let _mount = policy::test_support::secret_mount(mount.path());
        let _external = policy::require_provider_policy_for_tests("external-secret");
        let service = CString::new("com.company.orders.productioncreate").unwrap();
        assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::PROVIDER_UNAVAILABLE, "developer: nobody could create one");
        {
            let _prod = policy::test_support::TestPolicy::write("security_model = \"production\"\n");
            assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::KEK_ACCESS_DENIED, "production: only root may");
            let records = audit::captured_containing("service=\"com.company.orders.productioncreate\"");
            assert!(records.iter().any(|r| r.contains("event=2000") && r.contains("KEK_ACCESS_DENIED")), "{records:?}");
            let err = admin::retire_kek("com.company.orders.productioncreate", &[0x11; 32]).unwrap_err();
            assert_eq!(err.status, status::KEK_ACCESS_DENIED, "production: only root retires: {err:?}");
        }

        // An ephemeral KEK lives in this process, so only this process can
        // make one: production doesn't stop it. Once it exists, create_kek
        // is the idempotent startup call it always was.
        let _ephemeral = policy::allow_ephemeral_policy_for_tests();
        let _prod = policy::test_support::TestPolicy::write("security_model = \"production\"\n");
        let service = CString::new("com.company.orders.productionephemeral").unwrap();
        assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
        assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
    }
}

/// Fuzzing support: the parsers behind the C ABI, reachable in-process by
/// the harnesses under `fuzz/`. Compiled only with `--cfg
/// hkdfguard_test_paths`, which no build that ships has (see
/// `policy::policy_file_path`), so nothing here is ever exported.
#[cfg(hkdfguard_test_paths)]
#[doc(hidden)]
pub mod fuzz_support {
    pub use crate::crypto::{MAX_KEY_ID_LEN, MAX_WRAPPED_LEN, MIN_WRAPPED_LEN};

    /// `Policy::from_toml_str`: the parse and validation
    /// `/etc/hkdfguard/policy.toml` goes through; the refusal on `Err`.
    pub fn parse_policy(doc: &str) -> Result<(), String> {
        crate::policy::Policy::from_toml_str(doc).map(|_| ()).map_err(|e| e.to_string())
    }

    /// `key_file::check`: the status code it would return on `Err`.
    pub fn key_file_check(bytes: &[u8]) -> Result<(), i32> {
        crate::key_file::check(bytes).map_err(|e| e.status_code())
    }

    /// `Payload::from_bytes`: the parsed key-id and ciphertext lengths.
    pub fn payload_from_bytes(bytes: &[u8]) -> Option<(usize, usize)> {
        crate::payload::Payload::from_bytes(bytes).ok().map(|p| (p.key_id.len(), p.ciphertext.len()))
    }
}

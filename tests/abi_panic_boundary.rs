//! The ABI boundary of the secret entry points when the host application's
//! logger panics: the panic is caught, the call returns INTERNAL_ERROR, an
//! unwrap's output buffer is zeroed, and the process carries on -- a panic
//! must never unwind across `extern "C"` (which aborts) or leave plaintext
//! in the caller's buffer.
//!
//! A test binary of its own: the logger is process-wide, and armed it
//! fails every call that logs. Needs a library that reads its own policy:
//!
//! ```sh
//! RUSTFLAGS="--cfg hkdfguard_test_paths" CARGO_TARGET_DIR=target/test-paths \
//!   cargo test --test abi_panic_boundary
//! ```

use hkdfguard::{hkdfguard_create_kek, hkdfguard_open_secret_file, hkdfguard_unwrap_secret, hkdfguard_wrap_secret, status};
use serial_test::serial;
use std::ffi::CString;
use std::fs;
use std::os::raw::c_int;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

#[path = "../src/test_tmp.rs"]
mod test_tmp;

const SERVICE: &str = "com.hkdfguard.panicboundary";
const MARKER: &str = "host logger panicked (test)";

/// A host logger that panics on every record while armed.
struct PanickingLogger(AtomicBool);

impl log::Log for PanickingLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, _: &log::Record) {
        if self.0.load(Ordering::SeqCst) {
            panic!("{MARKER}");
        }
    }
    fn flush(&self) {}
}

static LOGGER: PanickingLogger = PanickingLogger(AtomicBool::new(false));

/// Once per process: the logger, a quiet hook for its own panics, the
/// developer-model policy pinned to Ephemeral, and a KEK for [`SERVICE`].
/// Returns the directory holding the policy (kept for the process).
fn setup() -> &'static tempfile::TempDir {
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !info.to_string().contains(MARKER) {
                default_hook(info);
            }
        }));

        let dir = test_tmp::private_tempdir();
        let policy = dir.path().join("policy.toml");
        fs::write(
            &policy,
            "security_model = \"developer\"\n[selection]\nmode = \"require\"\nprovider = \"ephemeral\"\n\
             [startup_behavior]\nsetup_min_delay_ms = 0\n",
        )
        .unwrap();
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o644)).unwrap();
        std::env::set_var("HKDFGUARD_POLICY_FILE", &policy);
        let service = CString::new(SERVICE).unwrap();
        assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
        dir
    })
}

/// Runs `f` with the logger armed.
fn with_panicking_logger<T>(f: impl FnOnce() -> T) -> T {
    LOGGER.0.store(true, Ordering::SeqCst);
    let result = f();
    LOGGER.0.store(false, Ordering::SeqCst);
    result
}

fn wrap_secret(service: &str, name: &str, secret: &[u8]) -> (c_int, Vec<u8>) {
    let (service, name) = (CString::new(service).unwrap(), CString::new(name).unwrap());
    let mut out = [0u8; 512];
    let mut out_len = out.len() as c_int;
    let rc = hkdfguard_wrap_secret(service.as_ptr(), name.as_ptr(), secret.as_ptr(), secret.len() as c_int, out.as_mut_ptr(), &mut out_len);
    (rc, out[..if rc == status::OK { out_len as usize } else { 0 }].to_vec())
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\"")]
fn a_panic_in_wrap_secret_is_internal_error() {
    setup();
    // No KEK for this service: the failure is logged, and the log panics.
    let (rc, _) = with_panicking_logger(|| wrap_secret("com.hkdfguard.panicboundary.nokek", "vault.password", b"hunter2"));
    assert_eq!(rc, status::INTERNAL_ERROR);
    // The process, and the library, carry on.
    assert_eq!(wrap_secret(SERVICE, "vault.password", b"hunter2").0, status::OK);
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\"")]
fn a_panic_in_unwrap_secret_is_internal_error_and_zeroes_the_buffer() {
    setup();
    let (rc, wrapped) = wrap_secret(SERVICE, "vault.password", b"hunter2");
    assert_eq!(rc, status::OK);
    let service = CString::new(SERVICE).unwrap();
    let other_name = CString::new("ssl.certificate").unwrap();
    let mut out = [0xEEu8; 256];
    let mut out_len = out.len() as c_int;
    // The wrong name fails authentication; the failure is logged, and the log panics.
    let rc = with_panicking_logger(|| {
        hkdfguard_unwrap_secret(service.as_ptr(), other_name.as_ptr(), wrapped.as_ptr(), wrapped.len() as c_int, out.as_mut_ptr(), &mut out_len)
    });
    assert_eq!(rc, status::INTERNAL_ERROR);
    assert!(out.iter().all(|&b| b == 0), "the caller's buffer is zeroed");
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\"")]
fn a_panic_in_open_secret_file_is_internal_error_and_zeroes_the_buffer() {
    let dir = setup();
    // A plaintext password where the wrapped form belongs: refused, and the refusal logged.
    let path = dir.path().join("cert.pass");
    fs::write(&path, b"hunter2\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let path = CString::new(path.to_str().unwrap()).unwrap();
    let mut out = [0xEEu8; 502];
    let mut out_len = out.len() as c_int;
    let rc = with_panicking_logger(|| hkdfguard_open_secret_file(path.as_ptr(), out.as_mut_ptr(), &mut out_len));
    assert_eq!(rc, status::INTERNAL_ERROR);
    assert!(out.iter().all(|&b| b == 0), "the caller's buffer is zeroed");
    // Unarmed, the same call is the ordinary refusal.
    let mut out_len = out.len() as c_int;
    assert_eq!(hkdfguard_open_secret_file(path.as_ptr(), out.as_mut_ptr(), &mut out_len), status::FILE_TOO_SHORT);
}

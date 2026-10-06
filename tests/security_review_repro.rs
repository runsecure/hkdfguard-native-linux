//! Tests from the October 2026 security review, each driven through the
//! public C ABI exactly as a consumer would hit it.
//!
//! All four are regression tests for findings that have been fixed (two
//! High, one Medium, one Low): they assert the correct behavior.
//!
//! Every test here needs the library to read the test's own policy, which
//! only a `--cfg hkdfguard_test_paths` build does:
//!
//! ```sh
//! RUSTFLAGS="--cfg hkdfguard_test_paths" CARGO_TARGET_DIR=target/test-paths \
//!   cargo test --features pkcs11 --test security_review_repro -- --test-threads=1
//! ```
//!
//! The PKCS#11 tests additionally need a module and token, named by
//! `HKDFGUARD_REVIEW_PKCS11_MODULE` / `HKDFGUARD_REVIEW_PKCS11_PIN_FILE`
//! (token label `hkdfguard-test`, as the Docker harness creates); the TPM
//! test needs `HKDFGUARD_REVIEW_TPM=1` and a reachable TPM. Without those
//! they report themselves as skipped and pass.

use hkdfguard_v1::{hkdfguard_create_kek, hkdfguard_kek_exists, hkdfguard_unwrap_dek, hkdfguard_wrap_dek, status};
use serial_test::serial;
use std::ffi::CString;
use std::fs;
use std::os::raw::c_int;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new().permissions(fs::Permissions::from_mode(0o700)).tempdir().unwrap()
}

/// Writes `doc` as the policy and points the library at it for the
/// duration of `f`.
fn with_policy<F: FnOnce()>(doc: &str, f: F) {
    let dir = tempdir();
    let path = dir.path().join("policy.toml");
    fs::write(&path, doc).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let saved = std::env::var_os("HKDFGUARD_POLICY_FILE");
    std::env::set_var("HKDFGUARD_POLICY_FILE", &path);
    f();
    match saved {
        Some(v) => std::env::set_var("HKDFGUARD_POLICY_FILE", v),
        None => std::env::remove_var("HKDFGUARD_POLICY_FILE"),
    }
}

fn wrap(service: &CString, dek: &[u8; 32], out: &mut [u8], capacity: c_int) -> (c_int, c_int) {
    let mut len = capacity;
    let ptr = if out.is_empty() { std::ptr::null_mut() } else { out.as_mut_ptr() };
    let rc = hkdfguard_wrap_dek(service.as_ptr(), dek.as_ptr(), 32, ptr, &mut len);
    (rc, len)
}

fn unwrap(service: &CString, wrapped: &[u8]) -> (c_int, [u8; 32]) {
    let mut back = [0u8; 32];
    let mut back_len: c_int = 32;
    let rc = hkdfguard_unwrap_dek(service.as_ptr(), wrapped.as_ptr(), wrapped.len() as c_int, back.as_mut_ptr(), &mut back_len);
    (rc, back)
}

fn exists(service: &CString) -> (c_int, c_int) {
    let mut e: c_int = -1;
    let rc = hkdfguard_kek_exists(service.as_ptr(), &mut e);
    (rc, e)
}

// ---------------------------------------------------------------------
// Fixed (was Low): wrap and unwrap check the caller's buffer before any
// provider work. A size probe (NULL out, capacity 0) is answered with
// HKDFGUARD_WRAPPED_MAX_LEN even for a service with no KEK -- before the
// fix it walked the provider chain and answered KEK_NOT_FOUND -- and a
// NULL out with a positive capacity is refused before wrapping.
// ---------------------------------------------------------------------
#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs RUSTFLAGS=\"--cfg hkdfguard_test_paths\"")]
fn buffer_checks_come_before_any_provider_work() {
    with_policy("preferred_order = [\"ephemeral\"]\n[selection]\nmode = \"prefer\"\n[startup_behavior]\nsetup_min_delay_ms = 0\n", || {
        let service = CString::new("com.review.probe").unwrap();
        let dek = [0x42u8; 32];
        const MAX: c_int = 276; // HKDFGUARD_WRAPPED_MAX_LEN

        // No KEK: a pure size probe never reaches the chain.
        assert_eq!(wrap(&service, &dek, &mut [], 0), (status::BUFFER_TOO_SMALL, MAX));
        // NULL out with a positive capacity: refused before wrapping, not after.
        assert_eq!(wrap(&service, &dek, &mut [], 512).0, status::INVALID_ARGUMENT);
        // Unwrap's size is always 32, known without parsing the payload --
        // here not even a payload.
        let mut small = [0xAAu8; 16];
        let mut small_len: c_int = 16;
        let garbage = [0u8; 8];
        let rc = hkdfguard_unwrap_dek(service.as_ptr(), garbage.as_ptr(), 8, small.as_mut_ptr(), &mut small_len);
        assert_eq!((rc, small_len), (status::BUFFER_TOO_SMALL, 32));
        assert_eq!(small, [0u8; 16], "a failed unwrap still zeroes the caller's buffer");

        // With a KEK, a buffer of exactly the advertised maximum always works,
        // and reports the payload's true (smaller) length.
        assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
        let mut out = vec![0u8; MAX as usize];
        let (rc, len) = wrap(&service, &dek, &mut out, MAX);
        assert_eq!(rc, status::OK);
        assert!(len <= MAX);
        assert_eq!(unwrap(&service, &out[..len as usize]), (status::OK, dek));
    });
}

// ---------------------------------------------------------------------
// PKCS#11 fixtures.
// ---------------------------------------------------------------------
struct Pkcs11Fixture {
    module: String,
    pin_file: String,
}

fn pkcs11_fixture() -> Option<Pkcs11Fixture> {
    let module = std::env::var("HKDFGUARD_REVIEW_PKCS11_MODULE").ok()?;
    let pin_file = std::env::var("HKDFGUARD_REVIEW_PKCS11_PIN_FILE").ok()?;
    if !Path::new(&module).exists() {
        return None;
    }
    Some(Pkcs11Fixture { module, pin_file })
}

fn pkcs11_policy(f: &Pkcs11Fixture) -> String {
    format!(
        "[selection]\nmode = \"require\"\nprovider = \"pkcs11\"\n\
         [startup_behavior]\nsetup_min_delay_ms = 0\n\
         [pkcs11]\nmodule = \"{}\"\npin_file = \"{}\"\ntoken_label = \"hkdfguard-test\"\n",
        f.module, f.pin_file
    )
}

// ---------------------------------------------------------------------
// Fixed (was High): with PKCS#11 as the provider, hkdfguard_create_kek
// must actually create the key pair, so that kek_exists then answers 1
// and wrap/unwrap round-trip. Before the fix, create_kek returned OK
// without touching the token, kek_exists stayed 0, and wrap failed with
// PROVIDER_ERROR.
// ---------------------------------------------------------------------
#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs RUSTFLAGS=\"--cfg hkdfguard_test_paths\"")]
fn pkcs11_create_kek_then_exists_then_wrap_and_unwrap_round_trip() {
    let Some(fx) = pkcs11_fixture() else {
        eprintln!("SKIP: HKDFGUARD_REVIEW_PKCS11_MODULE / _PIN_FILE not set");
        return;
    };
    with_policy(&pkcs11_policy(&fx), || {
        // A service no test has ever created a key for on this token. (It
        // is left behind on the token; the C ABI has no delete.)
        let name = format!("com.review.pkcs11.create{}", std::process::id());
        let service = CString::new(name).unwrap();
        let dek = [0x11u8; 32];

        assert_eq!(exists(&service), (status::OK, 0), "precondition: the token has no key for this fresh service");
        let mut out = [0u8; 512];
        assert_eq!(wrap(&service, &dek, &mut out, 512).0, status::KEK_NOT_FOUND, "wrap before create_kek must say so");

        assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
        assert_eq!(exists(&service), (status::OK, 1), "create_kek must leave a key the token reports");
        assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK, "create_kek is idempotent");
        assert_eq!(exists(&service), (status::OK, 1));

        let (rc, len) = wrap(&service, &dek, &mut out, 512);
        assert_eq!(rc, status::OK, "wrap after create_kek must succeed");
        assert_eq!(out[1], 2, "byte 1 of the wire format is the provider tag; 2 = PKCS11");
        let (rc, back) = unwrap(&service, &out[..len as usize]);
        assert_eq!(rc, status::OK);
        assert_eq!(back, dek);
    });
}

// ---------------------------------------------------------------------
// Fixed (was High): PKCS#11 wraps from several threads at once must all
// succeed. Before the fix every call ran C_Initialize/C_Finalize on the
// module, so a second concurrent call's C_Initialize failed with
// CKR_CRYPTOKI_ALREADY_INITIALIZED, its context was dropped, and the drop
// ran C_Finalize under the first call's live session.
// ---------------------------------------------------------------------
#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs RUSTFLAGS=\"--cfg hkdfguard_test_paths\"")]
fn pkcs11_concurrent_wraps_all_succeed() {
    let Some(fx) = pkcs11_fixture() else {
        eprintln!("SKIP: HKDFGUARD_REVIEW_PKCS11_MODULE / _PIN_FILE not set");
        return;
    };
    with_policy(&pkcs11_policy(&fx), || {
        let service = CString::new("com.company.orders").unwrap();
        let dek = [0x33u8; 32];
        assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK, "precondition: a key pair for the service");

        const THREADS: usize = 4;
        const PER_THREAD: usize = 8;
        let service = std::sync::Arc::new(service);
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let service = std::sync::Arc::clone(&service);
                std::thread::spawn(move || {
                    (0..PER_THREAD)
                        .map(|_| {
                            let mut out = [0u8; 512];
                            let (rc, len) = wrap(&service, &dek, &mut out, 512);
                            if rc != status::OK {
                                return rc;
                            }
                            let (rc, back) = unwrap(&service, &out[..len as usize]);
                            if rc == status::OK && back != dek {
                                return -1000; // a round trip that returned the wrong DEK
                            }
                            rc
                        })
                        .collect::<Vec<c_int>>()
                })
            })
            .collect();
        let codes: Vec<c_int> = handles.into_iter().flat_map(|h| h.join().expect("a wrap thread panicked or crashed")).collect();
        let failures: Vec<c_int> = codes.iter().copied().filter(|&c| c != status::OK).collect();
        assert!(failures.is_empty(), "{} of {} concurrent PKCS#11 round trips failed: {failures:?}", failures.len(), codes.len());
    });
}

// ---------------------------------------------------------------------
// Fixed (was Medium): a *policy-named* derivation-secret file that is
// missing must make the TPM provider Refused (the call fails), like a
// policy-named TCTI that can't be opened -- never Absent, which under
// `prefer` quietly moved the wrap to a weaker provider that happened to
// hold a KEK for the service.
// ---------------------------------------------------------------------
#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs RUSTFLAGS=\"--cfg hkdfguard_test_paths\"")]
fn tpm_missing_policy_named_derivation_secret_fails_the_call() {
    if std::env::var_os("HKDFGUARD_REVIEW_TPM").is_none() {
        eprintln!("SKIP: HKDFGUARD_REVIEW_TPM not set (needs a reachable TPM and the tpm2 feature)");
        return;
    }
    // An external-secret mount holding a KEK for the service.
    let mount = tempdir();
    let service_name = "com.review.tpm.fallthrough";
    let key = p256::SecretKey::random(&mut rand_core::OsRng);
    let key_path = mount.path().join(service_name);
    fs::write(&key_path, key.to_bytes()).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    let service = CString::new(service_name).unwrap();
    let dek = [0x55u8; 32];

    // Control: a policy-named TCTI that can't be opened is Refused -> the
    // whole call fails, nothing falls through.
    let refused = format!(
        "preferred_order = [\"tpm2\", \"external-secret\"]\n[selection]\nmode = \"prefer\"\n\
         [startup_behavior]\nsetup_min_delay_ms = 0\n\
         [tpm]\ntcti = \"device:/dev/hkdfguard-no-such-tpm\"\n\
         [external_secret]\ndir = \"{}\"\n",
        mount.path().display()
    );
    with_policy(&refused, || {
        let mut out = [0u8; 512];
        assert_eq!(wrap(&service, &dek, &mut out, 512).0, status::PROVIDER_ERROR, "an unreachable policy-named TCTI fails the call");
    });

    // A policy-named derivation secret that is missing must behave the
    // same way: the call fails, nothing is wrapped by external-secret.
    let missing_secret = format!(
        "preferred_order = [\"tpm2\", \"external-secret\"]\n[selection]\nmode = \"prefer\"\n\
         [startup_behavior]\nsetup_min_delay_ms = 0\n\
         [tpm]\nderivation_secret_file = \"/etc/hkdfguard/hkdfguard-review-no-such-secret\"\n\
         [external_secret]\ndir = \"{}\"\n",
        mount.path().display()
    );
    with_policy(&missing_secret, || {
        let mut out = [0u8; 512];
        let (rc, _) = wrap(&service, &dek, &mut out, 512);
        assert_eq!(rc, status::PROVIDER_ERROR, "a missing policy-named derivation secret must fail the call, not fall through");
    });
}

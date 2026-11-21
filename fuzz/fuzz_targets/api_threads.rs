//! The C ABI called from several threads at once: the calls a service
//! makes -- create, exists, fingerprint, wrap, unwrap, the secret pair,
//! open_file -- interleaved however the scheduler likes, each thread
//! checking its own answers. What it is for is the state the calls share
//! (the policy, the provider registry, the ephemeral KEK's page): under
//! AddressSanitizer a use after free or a write through a stale pointer
//! there is a finding, and so is any answer that differs from the one the
//! same call gets alone. (A data race that corrupts nothing on the day is
//! ThreadSanitizer's to find, which needs the standard library rebuilt
//! with it: `-Zbuild-std`. This target is not run that way.)
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::ffi::CString;
use std::fs;
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::sync::OnceLock;

#[path = "common.rs"]
mod common;
use common::*;
use hkdfguard::{
    hkdfguard_create_kek, hkdfguard_generate_and_wrap_dek, hkdfguard_kek_exists, hkdfguard_kek_fingerprint, hkdfguard_open_file,
    hkdfguard_wrap_dek, status,
};

const MAX_THREADS: usize = 4;
const MAX_OPS: usize = 24;

#[derive(Arbitrary, Debug, Clone)]
enum Op {
    /// Idempotent: the KEK exists already, and must still afterwards.
    CreateKek,
    Exists { other: bool },
    Fingerprint,
    /// Wrap this DEK, then unwrap what came back.
    WrapUnwrap { dek: [u8; 32], upper: bool },
    GenerateUnwrap,
    UnwrapGenuine { cap: i16 },
    /// The genuine payload with one byte changed: never opens.
    UnwrapPatched { offset: u16, xor: u8 },
    SecretRoundTrip { secret: Vec<u8> },
    UnwrapSecretGenuine,
    OpenFile { cap: i16 },
    /// A service with no KEK: refused, and not served by this one's.
    WrapOther,
}

#[derive(Arbitrary, Debug)]
struct Input {
    threads: Vec<Vec<Op>>,
}

const FULL: Call = Call { cap: BIG as i16, out_null: false, out_len_null: false };
const DEK: Call = Call { cap: 32, out_null: false, out_len_null: false };

fn key_file() -> &'static CString {
    static FILE: OnceLock<CString> = OnceLock::new();
    FILE.get_or_init(|| {
        let path = dir().join(format!("threads-key-{}.bin", std::process::id()));
        let _ = fs::remove_file(&path);
        fs::write(&path, genuine_payload()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        CString::new(path.as_os_str().as_bytes()).unwrap()
    })
}

fn fingerprint() -> &'static Vec<u8> {
    static FP: OnceLock<Vec<u8>> = OnceLock::new();
    FP.get_or_init(|| {
        let svc = CString::new(SERVICE).unwrap();
        let ret = with_buffer(&DEK, |out, out_len| hkdfguard_kek_fingerprint(svc.as_ptr(), out, out_len));
        assert_eq!(ret.rc, status::OK, "fuzz setup: hkdfguard_kek_fingerprint");
        ret.written().to_vec()
    })
}

fn run(op: &Op) {
    let svc = CString::new(SERVICE).unwrap();
    let upper = CString::new(SERVICE_UPPER).unwrap();
    let other = CString::new(OTHER_SERVICE).unwrap();
    match op {
        Op::CreateKek => assert_eq!(hkdfguard_create_kek(svc.as_ptr()), status::OK, "create_kek for a service that has one"),
        Op::Exists { other: no_kek } => {
            let mut exists: c_int = FILL as c_int;
            let name = if *no_kek { &other } else { &svc };
            assert_eq!(hkdfguard_kek_exists(name.as_ptr(), &mut exists), status::OK);
            assert_eq!(exists, !*no_kek as c_int, "kek_exists (service without a KEK: {no_kek})");
        }
        Op::Fingerprint => {
            let ret = with_buffer(&DEK, |out, out_len| hkdfguard_kek_fingerprint(svc.as_ptr(), out, out_len));
            assert_eq!(ret.rc, status::OK);
            assert_eq!(ret.written(), &fingerprint()[..], "the KEK's fingerprint changed");
        }
        Op::WrapUnwrap { dek, upper: other_case } => {
            let name = if *other_case { &upper } else { &svc };
            let ret = with_buffer(&FULL, |out, out_len| hkdfguard_wrap_dek(name.as_ptr(), dek.as_ptr(), 32, out, out_len));
            check_contract(&ret, &FULL, false);
            assert_eq!(ret.rc, status::OK, "wrap_dek");
            let back = unwrap(&Service::Fuzz, ret.written(), &DEK);
            assert_eq!(back.rc, status::OK, "a payload wrap produced does not unwrap");
            assert_eq!(back.written(), &dek[..], "unwrap returned another thread's DEK, or none");
        }
        Op::GenerateUnwrap => {
            let ret = with_buffer(&FULL, |out, out_len| hkdfguard_generate_and_wrap_dek(svc.as_ptr(), out, out_len));
            check_contract(&ret, &FULL, false);
            assert_eq!(ret.rc, status::OK, "generate_and_wrap_dek");
            let back = unwrap(&Service::FuzzUpper, ret.written(), &DEK);
            assert_eq!((back.rc, back.out_len), (status::OK, Some(32)));
        }
        Op::UnwrapGenuine { cap } => {
            let call = Call { cap: *cap, out_null: false, out_len_null: false };
            let ret = unwrap(&Service::Fuzz, genuine_payload(), &call);
            check_contract(&ret, &call, true);
            if *cap >= 32 {
                assert_eq!(ret.rc, status::OK, "the genuine payload failed to unwrap");
                assert_eq!(ret.written(), &known_dek()[..]);
            } else {
                assert_ne!(ret.rc, status::OK, "unwrapped into {cap} bytes");
            }
        }
        Op::UnwrapPatched { offset, xor } => {
            let mut payload = genuine_payload().clone();
            let i = *offset as usize % payload.len();
            payload[i] ^= xor | 1;
            let ret = unwrap(&Service::Fuzz, &payload, &DEK);
            check_contract(&ret, &DEK, true);
            assert_ne!(ret.rc, status::OK, "a corrupted payload unwrapped");
        }
        Op::SecretRoundTrip { secret } => {
            let secret = &secret[..secret.len().min(SECRET_MAX)];
            let (rc, payload) = wrap_secret_ok(SERVICE, SECRET_NAME, secret);
            if secret.is_empty() {
                assert_eq!(rc, status::INVALID_ARGUMENT, "wrapped an empty secret");
                return;
            }
            assert_eq!(rc, status::OK, "wrap_secret");
            let full = Call { cap: SECRET_MAX as i16, out_null: false, out_len_null: false };
            let back = unwrap_secret(&Service::Fuzz, &SecretName::Genuine, &payload, &full);
            assert_eq!(back.rc, status::OK, "a secret payload wrap produced does not unwrap");
            assert_eq!(back.written(), secret, "unwrap returned another thread's secret, or none");
            assert_ne!(unwrap_secret(&Service::Fuzz, &SecretName::Other, &payload, &full).rc, status::OK);
        }
        Op::UnwrapSecretGenuine => {
            let full = Call { cap: SECRET_MAX as i16, out_null: false, out_len_null: false };
            let back = unwrap_secret(&Service::Fuzz, &SecretName::Genuine, genuine_secret_payload(), &full);
            assert_eq!(back.rc, status::OK);
            assert_eq!(back.written(), known_secret());
        }
        Op::OpenFile { cap } => {
            let call = Call { cap: *cap, out_null: false, out_len_null: false };
            let ret = with_buffer(&call, |out, out_len| hkdfguard_open_file(key_file().as_ptr(), out, out_len));
            check_contract(&ret, &call, true);
            if *cap as i64 >= genuine_payload().len() as i64 {
                assert_eq!(ret.rc, status::OK, "open_file of a genuine private key file");
                assert_eq!(ret.written(), &genuine_payload()[..]);
            } else {
                assert_ne!(ret.rc, status::OK);
            }
        }
        Op::WrapOther => {
            let dek = known_dek();
            let ret = with_buffer(&FULL, |out, out_len| hkdfguard_wrap_dek(other.as_ptr(), dek.as_ptr(), 32, out, out_len));
            assert_eq!(ret.rc, status::KEK_NOT_FOUND, "wrap under a service with no KEK");
            assert!(ret.untouched());
        }
    }
}

fuzz_target!(|input: Input| {
    setup();
    // Everything the threads share, made before any of them starts.
    let _ = (genuine_payload(), genuine_secret_payload(), key_file(), fingerprint());
    if input.threads.len() < 2 {
        return; // one thread is what every other target does
    }
    // A panic in a thread aborts the process (the hook `setup` installs),
    // so a failed assertion is recorded with this input.
    std::thread::scope(|scope| {
        for ops in input.threads.iter().take(MAX_THREADS) {
            scope.spawn(move || ops.iter().take(MAX_OPS).for_each(run));
        }
    });
});

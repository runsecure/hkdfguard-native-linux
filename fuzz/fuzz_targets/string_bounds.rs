//! Every C string the ABI takes -- the service, the secret name, a key
//! file path, a principal -- at the edges a hostile or careless caller
//! reaches: no terminator at all, the longest string the rule allows, one
//! byte longer, and a NUL earlier than the caller meant. Each string sits
//! against an inaccessible page (`common::Guarded`), so a read of one byte
//! past the bounded scan, or past a terminator, is a crash rather than
//! something a sanitizer has to notice.
//!
//! The early-NUL case is a differential: the string with bytes after its
//! first NUL and the string that ends there must be the same call, with
//! the same status and the same output -- nothing behind the terminator is
//! read, let alone used.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::ffi::CString;
use std::fs;
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::sync::OnceLock;

#[path = "common.rs"]
mod common;
use common::*;
use hkdfguard::{
    hkdfguard_create_kek, hkdfguard_generate_and_wrap_dek, hkdfguard_kek_exists, hkdfguard_kek_fingerprint,
    hkdfguard_key_file_principal_trusted, hkdfguard_open_file, hkdfguard_open_secret_file, hkdfguard_unwrap_dek,
    hkdfguard_unwrap_secret, hkdfguard_wrap_dek, hkdfguard_wrap_secret, status,
};

/// The functions that take a service string.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ServiceFn {
    CreateKek,
    Exists,
    Fingerprint,
    Wrap,
    Unwrap,
    Generate,
    WrapSecret,
    UnwrapSecret,
}

/// Which string argument is under test; every other argument of the call
/// is valid.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Arg {
    Service(ServiceFn),
    /// The secret name, of `hkdfguard_wrap_secret` or `hkdfguard_unwrap_secret`.
    SecretName { wrap: bool },
    /// The path, of `hkdfguard_open_file` or `hkdfguard_open_secret_file`.
    Path { secret: bool },
    Principal,
}

impl Arg {
    /// The most bytes the library may read looking for the terminator.
    fn scan_limit(&self) -> usize {
        match self {
            Arg::Service(_) => 128 + 1,   // MAX_SERVICE_LEN and its NUL
            Arg::SecretName { .. } => 64 + 1, // SECRET_NAME_MAX_LEN and its NUL
            Arg::Path { .. } => libc::PATH_MAX as usize,
            Arg::Principal => 16, // MAX_PRINCIPAL_BYTES
        }
    }
    /// What a string with no terminator inside the limit is refused with.
    fn refusal(&self) -> c_int {
        match self {
            Arg::Service(_) => status::INVALID_SERVICE_NAME,
            _ => status::INVALID_ARGUMENT,
        }
    }
    /// The string a well-behaved caller passes here.
    fn genuine(&self) -> Vec<u8> {
        match self {
            Arg::Service(_) => SERVICE.into(),
            Arg::SecretName { .. } => SECRET_NAME.into(),
            Arg::Path { secret } => key_file(*secret).as_bytes().to_vec(),
            // SAFETY: getuid takes no arguments and cannot fail.
            Arg::Principal => format!("uid:{}", unsafe { libc::getuid() }).into_bytes(),
        }
    }
    /// The longest string the rule accepts: one byte short of the limit.
    fn longest(&self) -> Vec<u8> {
        let n = self.scan_limit() - 1;
        match self {
            Arg::Service(_) | Arg::SecretName { .. } => vec![b'a'; n],
            Arg::Path { .. } => {
                let mut p = dir().as_os_str().as_bytes().to_vec();
                p.push(b'/');
                p.resize(n, b'a');
                p
            }
            // "uid:" and this uid, zero-padded to the full width.
            // SAFETY: as above.
            Arg::Principal => format!("uid:{:0width$}", unsafe { libc::getuid() }, width = n - 4).into_bytes(),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Text {
    Genuine,
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum Shape {
    /// `scan_limit` bytes of `fill` and no NUL: the scan must stop there.
    Unterminated,
    /// The longest string the rule accepts, its NUL the last readable byte.
    AtLimit,
    /// One byte longer than that, terminated.
    OverLimit,
    /// `head`, a NUL, then `tail`.
    EarlyNul { head: Text, tail: Vec<u8> },
}

#[derive(Arbitrary, Debug)]
struct Input {
    arg: Arg,
    shape: Shape,
    fill: u8,
}

/// A genuine DEK (or secret) key file, written once.
fn key_file(secret: bool) -> &'static CString {
    static FILES: OnceLock<[CString; 2]> = OnceLock::new();
    let files = FILES.get_or_init(|| {
        let make = |name: &str, payload: &[u8]| {
            let path = dir().join(format!("{name}-{}.bin", std::process::id()));
            let _ = fs::remove_file(&path);
            fs::write(&path, payload).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            CString::new(path.as_os_str().as_bytes()).unwrap()
        };
        [make("bounds-key", genuine_payload()), make("bounds-secret", genuine_secret_payload())]
    });
    &files[secret as usize]
}

/// What a call answered: its status and, where the function is
/// deterministic, everything it wrote.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    rc: c_int,
    out: Vec<u8>,
}

const FULL: Call = Call { cap: BIG as i16, out_null: false, out_len_null: false };

/// The call `arg` names, with `s` as the string under test.
fn call(arg: Arg, s: *const c_char) -> Outcome {
    let svc = CString::new(SERVICE).unwrap();
    let name = CString::new(SECRET_NAME).unwrap();
    let dek = known_dek();
    let (payload, secret_payload) = (genuine_payload(), genuine_secret_payload());
    // `fixed`: the output is a function of the arguments (no fresh nonce).
    let buffered = |fixed: bool, f: &dyn Fn(*mut u8, *mut c_int) -> c_int| {
        let ret = with_buffer(&FULL, f);
        check_contract(&ret, &FULL, false);
        Outcome { rc: ret.rc, out: if fixed { ret.written().to_vec() } else { Vec::new() } }
    };
    match arg {
        Arg::Service(ServiceFn::CreateKek) => Outcome { rc: hkdfguard_create_kek(s), out: Vec::new() },
        Arg::Service(ServiceFn::Exists) => {
            let mut exists: c_int = FILL as c_int;
            let rc = hkdfguard_kek_exists(s, &mut exists);
            Outcome { rc, out: exists.to_le_bytes().to_vec() }
        }
        Arg::Service(ServiceFn::Fingerprint) => buffered(true, &|out, out_len| hkdfguard_kek_fingerprint(s, out, out_len)),
        Arg::Service(ServiceFn::Wrap) => buffered(false, &|out, out_len| hkdfguard_wrap_dek(s, dek.as_ptr(), 32, out, out_len)),
        Arg::Service(ServiceFn::Unwrap) => {
            buffered(true, &|out, out_len| hkdfguard_unwrap_dek(s, payload.as_ptr(), payload.len() as c_int, out, out_len))
        }
        Arg::Service(ServiceFn::Generate) => buffered(false, &|out, out_len| hkdfguard_generate_and_wrap_dek(s, out, out_len)),
        Arg::Service(ServiceFn::WrapSecret) => buffered(false, &|out, out_len| {
            hkdfguard_wrap_secret(s, name.as_ptr(), known_secret().as_ptr(), known_secret().len() as c_int, out, out_len)
        }),
        Arg::Service(ServiceFn::UnwrapSecret) => buffered(true, &|out, out_len| {
            hkdfguard_unwrap_secret(s, name.as_ptr(), secret_payload.as_ptr(), secret_payload.len() as c_int, out, out_len)
        }),
        Arg::SecretName { wrap: true } => buffered(false, &|out, out_len| {
            hkdfguard_wrap_secret(svc.as_ptr(), s, known_secret().as_ptr(), known_secret().len() as c_int, out, out_len)
        }),
        Arg::SecretName { wrap: false } => buffered(true, &|out, out_len| {
            hkdfguard_unwrap_secret(svc.as_ptr(), s, secret_payload.as_ptr(), secret_payload.len() as c_int, out, out_len)
        }),
        Arg::Path { secret: false } => buffered(true, &|out, out_len| hkdfguard_open_file(s, out, out_len)),
        Arg::Path { secret: true } => buffered(true, &|out, out_len| hkdfguard_open_secret_file(s, out, out_len)),
        Arg::Principal => {
            let mut trusted: c_int = FILL as c_int;
            let rc = hkdfguard_key_file_principal_trusted(s, &mut trusted);
            Outcome { rc, out: trusted.to_le_bytes().to_vec() }
        }
    }
}

/// What the genuine string must get, the other arguments being genuine too.
fn check_genuine(arg: Arg, got: &Outcome) {
    assert_eq!(got.rc, status::OK, "{arg:?} refused its genuine string");
    let expected: Option<Vec<u8>> = match arg {
        Arg::Service(ServiceFn::Exists) | Arg::Principal => Some(1i32.to_le_bytes().to_vec()),
        Arg::Service(ServiceFn::Unwrap) => Some(known_dek().to_vec()),
        Arg::Service(ServiceFn::UnwrapSecret) | Arg::SecretName { wrap: false } => Some(known_secret().to_vec()),
        Arg::Path { secret: false } => Some(genuine_payload().clone()),
        Arg::Path { secret: true } => Some(genuine_secret_payload().clone()),
        _ => None,
    };
    if let Some(expected) = expected {
        assert_eq!(got.out, expected, "{arg:?} answered its genuine string with something else");
    }
}

fuzz_target!(|input: Input| {
    setup();
    let mut arg = input.arg;
    let fill = if input.fill == 0 { b'a' } else { input.fill };
    let limit = arg.scan_limit();
    // create_kek makes a KEK for whatever valid name it is given, for the
    // life of the process: only the strings it must refuse go to it.
    if matches!(arg, Arg::Service(ServiceFn::CreateKek)) && matches!(input.shape, Shape::AtLimit | Shape::EarlyNul { .. }) {
        arg = Arg::Service(ServiceFn::Exists);
    }

    match &input.shape {
        Shape::Unterminated => {
            let got = call(arg, Guarded::new(&vec![fill; limit]).ptr());
            assert_eq!(got.rc, arg.refusal(), "{arg:?}: {limit} bytes with no terminator");
        }
        Shape::OverLimit => {
            let mut s = vec![fill; limit];
            s.push(0);
            let got = call(arg, Guarded::new(&s).ptr());
            assert_eq!(got.rc, arg.refusal(), "{arg:?}: a terminated string of {limit} bytes, one over the limit");
        }
        Shape::AtLimit => {
            let mut s = arg.longest();
            s.push(0);
            let got = call(arg, Guarded::new(&s).ptr());
            assert_ne!(got.rc, status::INTERNAL_ERROR);
            match arg {
                // A valid name with no KEK: refused for that, never for its length.
                Arg::Service(_) => assert_ne!(got.rc, status::INVALID_SERVICE_NAME, "{arg:?}: the longest service name"),
                Arg::SecretName { wrap: true } => assert_eq!(got.rc, status::OK, "wrap under the longest secret name"),
                Arg::SecretName { wrap: false } => {
                    assert_eq!(got.rc, status::PAYLOAD_AUTH_FAILED, "the genuine payload under the longest (wrong) name")
                }
                // Scanned in full, then refused by the filesystem: no such file.
                Arg::Path { .. } => assert_ne!(got.rc, status::OK, "{arg:?}: a path of PATH_MAX - 1 bytes"),
                Arg::Principal => assert_eq!((got.rc, &got.out[..]), (status::OK, &1i32.to_le_bytes()[..]), "this uid, zero-padded"),
            }
        }
        Shape::EarlyNul { head, tail } => {
            let mut head = match head {
                Text::Genuine => arg.genuine(),
                Text::Raw(b) => b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())].to_vec(),
            };
            let genuine = head == arg.genuine();
            head.truncate(limit - 1); // a terminator inside the limit, as the case is about
            head.push(0);
            let mut long = head.clone();
            long.extend_from_slice(tail);

            // The NUL as the last readable byte: nothing after it may be read.
            let ended = call(arg, Guarded::new(&head).ptr());
            // And with bytes after it: the same call.
            let trailed = call(arg, Guarded::new(&long).ptr());
            assert_ne!(ended.rc, status::INTERNAL_ERROR);
            assert_eq!(ended, trailed, "{arg:?}: bytes after the first NUL changed the answer");
            if genuine {
                check_genuine(arg, &ended);
            }
        }
    }
});

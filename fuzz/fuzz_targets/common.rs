//! Shared by every C ABI harness: the one-time policy and KEK setup, the
//! C-ABI call helpers, and the contract checks every call must satisfy.
//!
//! The library must be built with `--cfg hkdfguard_test_paths` so that it
//! reads `HKDFGUARD_POLICY_FILE` and accepts a policy owned by this user.
//! `HKDFGUARD_FUZZ_DIR` names a `0700` directory whose every ancestor is
//! owned by root or this user and writable by nobody else (the library
//! refuses files under anything else; see `src/test_tmp.rs`).
#![allow(dead_code)]

use arbitrary::Arbitrary;
use std::ffi::CString;
use std::fs;
use std::os::raw::c_int;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::OnceLock;

use hkdfguard::{hkdfguard_create_kek, hkdfguard_unwrap_dek, hkdfguard_wrap_dek, status};

/// The service whose ephemeral KEK the harness creates at startup.
pub const SERVICE: &str = "com.hkdfguard.fuzz";
/// The same name, as the C ABI must treat it: case-insensitively.
pub const SERVICE_UPPER: &str = "COM.HKDFGUARD.Fuzz";
/// A valid service name no KEK was ever created for.
pub const OTHER_SERVICE: &str = "com.hkdfguard.other";
/// A generous payload buffer: the header's HKDFGUARD_WRAPPED_MAX_LEN is smaller.
pub const BIG: usize = 1024;

pub fn dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::var_os("HKDFGUARD_FUZZ_DIR")
            .map(PathBuf::from)
            .expect("set HKDFGUARD_FUZZ_DIR to a private directory (see fuzz/fuzz_targets/common.rs)");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    })
}

pub fn policy_path() -> PathBuf {
    dir().join(format!("policy-{}.toml", std::process::id()))
}

pub const FUZZ_POLICY: &str = "security_model = \"developer\"\n\
    [selection]\nmode = \"require\"\nprovider = \"ephemeral\"\n\
    [startup_behavior]\nsetup_min_delay_ms = 0\n";

pub fn write_policy(doc: &str) {
    let path = policy_path();
    fs::write(&path, doc).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
}

/// Once per process: abort on any panic (one the library catches at the
/// ABI boundary would otherwise be invisible to the fuzzer), install the
/// fuzz policy, and create the ephemeral KEK for [`SERVICE`].
pub fn setup() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        std::panic::set_hook(Box::new(|info| {
            eprintln!("PANIC (aborting so the fuzzer records it): {info}");
            std::process::abort();
        }));
        write_policy(FUZZ_POLICY);
        std::env::set_var("HKDFGUARD_POLICY_FILE", policy_path());
        let svc = CString::new(SERVICE).unwrap();
        let rc = hkdfguard_create_kek(svc.as_ptr());
        assert_eq!(rc, status::OK, "fuzz setup: hkdfguard_create_kek");
    });
}

pub fn known_dek() -> [u8; 32] {
    let mut dek = [0u8; 32];
    for (i, b) in dek.iter_mut().enumerate() {
        *b = 0x40 + i as u8;
    }
    dek
}

/// A genuine payload for [`SERVICE`] and [`known_dek`], wrapped once.
pub fn genuine_payload() -> &'static Vec<u8> {
    static PAYLOAD: OnceLock<Vec<u8>> = OnceLock::new();
    PAYLOAD.get_or_init(|| {
        setup();
        let svc = CString::new(SERVICE).unwrap();
        let dek = known_dek();
        let mut out = vec![0u8; BIG];
        let mut out_len: c_int = BIG as c_int;
        let rc = hkdfguard_wrap_dek(svc.as_ptr(), dek.as_ptr(), 32, out.as_mut_ptr(), &mut out_len);
        assert_eq!(rc, status::OK, "fuzz setup: hkdfguard_wrap_dek");
        out.truncate(out_len as usize);
        out
    })
}

#[derive(Arbitrary, Debug, Clone)]
pub enum Service {
    Fuzz,
    FuzzUpper,
    Other,
    Raw(Vec<u8>),
    Null,
}

impl Service {
    /// The C string to pass; `None` is a NULL pointer. Interior NULs end
    /// the string, as C would see it.
    pub fn cstring(&self) -> Option<CString> {
        let bytes: &[u8] = match self {
            Service::Fuzz => SERVICE.as_bytes(),
            Service::FuzzUpper => SERVICE_UPPER.as_bytes(),
            Service::Other => OTHER_SERVICE.as_bytes(),
            Service::Raw(b) => b,
            Service::Null => return None,
        };
        let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
        Some(CString::new(&bytes[..end]).unwrap())
    }

    pub fn is_fuzz(&self) -> bool {
        match self {
            Service::Fuzz | Service::FuzzUpper => true,
            Service::Raw(b) => self.cstring().map_or(false, |c| c.as_bytes().eq_ignore_ascii_case(SERVICE.as_bytes())) && !b.is_empty(),
            _ => false,
        }
    }
}

/// How the caller's output buffer is presented: its declared capacity
/// (negative included), and whether `out` or `out_len` is NULL.
#[derive(Arbitrary, Debug, Clone)]
pub struct Call {
    pub cap: i16,
    pub out_null: bool,
    pub out_len_null: bool,
}

impl Call {
    pub fn cap(&self) -> c_int {
        self.cap as c_int
    }
    /// Pointers valid, capacity non-negative: a call the contract promises
    /// an answer to.
    pub fn well_formed(&self) -> bool {
        !self.out_null && !self.out_len_null && self.cap >= 0
    }
}

pub const FILL: u8 = 0xAA;

pub struct Ret {
    pub rc: c_int,
    /// `*out_len` after the call, when `out_len` was not NULL.
    pub out_len: Option<c_int>,
    /// The caller's buffer: `max(cap, 0)` bytes, [`FILL`] before the call.
    pub buf: Vec<u8>,
}

impl Ret {
    pub fn untouched(&self) -> bool {
        self.buf.iter().all(|&b| b == FILL)
    }
    pub fn zeroed(&self) -> bool {
        self.buf.iter().all(|&b| b == 0)
    }
    pub fn written(&self) -> &[u8] {
        let n = self.out_len.unwrap_or(0).clamp(0, self.buf.len() as c_int) as usize;
        &self.buf[..n]
    }
}

/// Runs `f(out, out_len)` with the buffer `call` describes.
pub fn with_buffer(call: &Call, f: impl FnOnce(*mut u8, *mut c_int) -> c_int) -> Ret {
    let cap = call.cap();
    let mut buf = vec![FILL; cap.max(0) as usize];
    let out = if call.out_null { ptr::null_mut() } else { buf.as_mut_ptr() };
    let mut out_len = cap;
    let out_len_ptr = if call.out_len_null { ptr::null_mut() } else { &mut out_len as *mut c_int };
    let rc = f(out, out_len_ptr);
    Ret { rc, out_len: (!call.out_len_null).then_some(out_len), buf }
}

pub fn unwrap(service: &Service, payload: &[u8], call: &Call) -> Ret {
    let svc = service.cstring();
    let svc_ptr = svc.as_ref().map_or(ptr::null(), |c| c.as_ptr());
    let len: c_int = payload.len().try_into().expect("payload longer than c_int");
    with_buffer(call, |out, out_len| hkdfguard_unwrap_dek(svc_ptr, payload.as_ptr(), len, out, out_len))
}

/// What every call must satisfy whatever it returned. `zero_on_failure`:
/// the function promises the caller's declared capacity is zeroed on any
/// failure (unwrap, open_file), rather than left alone.
pub fn check_contract(ret: &Ret, call: &Call, zero_on_failure: bool) {
    assert_ne!(ret.rc, status::INTERNAL_ERROR, "INTERNAL_ERROR: a panic was caught at the ABI boundary");
    assert!(ret.rc <= 0, "unknown positive status {}", ret.rc);
    if call.out_len_null {
        assert!(ret.untouched(), "out_len NULL, but the buffer was written (rc {})", ret.rc);
    }
    if let Some(n) = ret.out_len {
        if ret.rc == status::OK {
            assert!(n >= 0 && n <= call.cap().max(0), "OK but *out_len {n} exceeds the capacity {}", call.cap());
        }
    }
    if zero_on_failure && ret.rc != status::OK && !call.out_len_null && !call.out_null {
        assert!(ret.zeroed(), "failure (rc {}) left bytes in the caller's buffer", ret.rc);
    }
}

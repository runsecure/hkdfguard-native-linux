//! The rest of the C ABI: `hkdfguard_wrap_dek` (every DEK length, then an
//! unwrap of whatever it produced, which must give the DEK back),
//! `hkdfguard_generate_and_wrap_dek`, the setup calls `kek_exists` and
//! `kek_fingerprint`, `security_model` and `key_file_principal_trusted`,
//! under every shape of service string and output buffer.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::ffi::CString;
use std::os::raw::c_int;
use std::ptr;

#[path = "common.rs"]
mod common;
use common::*;
use hkdfguard::{
    admin, hkdfguard_generate_and_wrap_dek, hkdfguard_kek_exists, hkdfguard_kek_fingerprint,
    hkdfguard_key_file_principal_trusted, hkdfguard_security_model, hkdfguard_wrap_dek, status,
};

#[derive(Arbitrary, Debug)]
enum Op {
    Wrap { dek: Vec<u8>, dek_null: bool },
    GenerateAndWrap,
    Exists { exists_null: bool },
    Fingerprint,
    SecurityModel { model_null: bool, may_write_null: bool },
    Principal(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    service: Service,
    op: Op,
    call: Call,
}

fn svc_ptr(svc: &Option<CString>) -> *const std::os::raw::c_char {
    svc.as_ref().map_or(ptr::null(), |c| c.as_ptr())
}

fn round_trip(service: &Service, payload: &[u8], expected_dek: Option<&[u8]>) {
    let call = Call { cap: 32, out_null: false, out_len_null: false };
    let ret = unwrap(service, payload, &call);
    assert_eq!(ret.rc, status::OK, "a payload wrap produced does not unwrap");
    assert_eq!(ret.out_len, Some(32));
    if let Some(dek) = expected_dek {
        assert_eq!(ret.written(), dek, "unwrap returned a different DEK");
    }
    // Case-insensitive service: the same payload opens under the other spelling.
    let other = match service {
        Service::Fuzz => Service::FuzzUpper,
        _ => Service::Fuzz,
    };
    let ret = unwrap(&other, payload, &call);
    assert_eq!(ret.rc, status::OK, "the payload does not unwrap under the other spelling of the service");
    assert!(admin::payload_fingerprint(payload).is_some(), "wrap produced a payload the parser rejects");
}

fuzz_target!(|input: Input| {
    setup();
    let svc = input.service.cstring();
    let call = &input.call;
    match &input.op {
        Op::Wrap { dek, dek_null } => {
            let dek_ptr = if *dek_null { ptr::null() } else { dek.as_ptr() };
            let dek_len: c_int = dek.len().try_into().unwrap();
            let ret = with_buffer(call, |out, out_len| hkdfguard_wrap_dek(svc_ptr(&svc), dek_ptr, dek_len, out, out_len));
            check_contract(&ret, call, false);
            match ret.rc {
                status::OK => {
                    assert!(!*dek_null && dek.len() == 32, "wrapped a DEK that is not 32 bytes");
                    assert!(input.service.is_fuzz(), "wrapped under service {:?}, which has no KEK", input.service);
                    let n = ret.out_len.unwrap();
                    assert!(n > 0, "OK with an empty payload");
                    round_trip(&input.service, ret.written(), Some(dek));
                }
                status::BUFFER_TOO_SMALL => {
                    assert!(ret.untouched(), "BUFFER_TOO_SMALL wrote to the buffer");
                    let n = ret.out_len.unwrap();
                    assert!(n > call.cap(), "BUFFER_TOO_SMALL reported {n}, not above the capacity {}", call.cap());
                    assert!(n as usize <= BIG, "BUFFER_TOO_SMALL asks for {n} bytes");
                }
                _ => {}
            }
            if input.service.is_fuzz() && call.well_formed() && call.cap() >= BIG as c_int && !*dek_null {
                let expected = if dek.len() == 32 { status::OK } else { status::INVALID_ARGUMENT };
                assert_eq!(ret.rc, expected, "wrap of a {}-byte DEK", dek.len());
            }
        }
        Op::GenerateAndWrap => {
            let ret = with_buffer(call, |out, out_len| hkdfguard_generate_and_wrap_dek(svc_ptr(&svc), out, out_len));
            check_contract(&ret, call, false);
            match ret.rc {
                status::OK => {
                    assert!(input.service.is_fuzz(), "generated under service {:?}, which has no KEK", input.service);
                    round_trip(&input.service, ret.written(), None);
                }
                status::BUFFER_TOO_SMALL => {
                    assert!(ret.untouched(), "BUFFER_TOO_SMALL wrote to the buffer");
                    assert!(ret.out_len.unwrap() > call.cap());
                }
                _ => {}
            }
            if input.service.is_fuzz() && call.well_formed() && call.cap() >= BIG as c_int {
                assert_eq!(ret.rc, status::OK);
            }
        }
        Op::Exists { exists_null } => {
            let mut exists: c_int = FILL as c_int;
            let p = if *exists_null { ptr::null_mut() } else { &mut exists as *mut c_int };
            let rc = hkdfguard_kek_exists(svc_ptr(&svc), p);
            assert_ne!(rc, status::INTERNAL_ERROR);
            if rc == status::OK {
                assert!(!*exists_null);
                assert_eq!(exists, input.service.is_fuzz() as c_int, "kek_exists for {:?}", input.service);
            } else if !*exists_null {
                assert_eq!(exists, FILL as c_int, "kek_exists wrote *exists on failure");
            }
            if !*exists_null && matches!(input.service, Service::Fuzz | Service::FuzzUpper | Service::Other) {
                assert_eq!(rc, status::OK);
            }
        }
        Op::Fingerprint => {
            let ret = with_buffer(call, |out, out_len| hkdfguard_kek_fingerprint(svc_ptr(&svc), out, out_len));
            check_contract(&ret, call, false);
            if ret.rc == status::OK {
                assert!(input.service.is_fuzz());
                assert_eq!(ret.out_len, Some(32));
                let expected = admin::payload_fingerprint(genuine_payload()).unwrap();
                assert_eq!(ret.written(), &expected[..], "the KEK fingerprint differs from the one payloads carry");
            }
            if input.service.is_fuzz() && call.well_formed() && call.cap() >= 32 {
                assert_eq!(ret.rc, status::OK);
            }
            if matches!(input.service, Service::Other) && call.well_formed() && call.cap() >= 32 {
                assert_eq!(ret.rc, status::KEK_NOT_FOUND);
            }
        }
        Op::SecurityModel { model_null, may_write_null } => {
            let (mut model, mut may_write): (c_int, c_int) = (FILL as c_int, FILL as c_int);
            let mp = if *model_null { ptr::null_mut() } else { &mut model as *mut c_int };
            let wp = if *may_write_null { ptr::null_mut() } else { &mut may_write as *mut c_int };
            let rc = hkdfguard_security_model(mp, wp);
            assert_ne!(rc, status::INTERNAL_ERROR);
            if rc == status::OK {
                if !*model_null {
                    assert_eq!(model, 1, "the fuzz policy is the developer model");
                }
                if !*may_write_null {
                    assert!(may_write == 0 || may_write == 1);
                }
            }
        }
        Op::Principal(bytes) => {
            let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
            let principal = CString::new(&bytes[..end]).unwrap();
            let mut trusted: c_int = FILL as c_int;
            let rc = hkdfguard_key_file_principal_trusted(principal.as_ptr(), &mut trusted);
            assert_ne!(rc, status::INTERNAL_ERROR);
            if rc == status::OK {
                assert!(trusted == 0 || trusted == 1, "trusted = {trusted}");
            } else {
                assert_eq!(trusted, FILL as c_int, "failure wrote *out_trusted");
            }
            let me = format!("uid:{}", unsafe { libc::getuid() });
            if principal.as_bytes() == me.as_bytes() || principal.as_bytes() == b"uid:0" {
                assert_eq!((rc, trusted), (status::OK, 1), "{} must be trusted under the developer model", principal.to_string_lossy());
            }
        }
    }
});

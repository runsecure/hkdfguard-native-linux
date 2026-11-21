//! `hkdfguard_wrap_secret` on secrets of every length (0 to past 256,
//! NULL included), every shape of secret name, service string and output
//! buffer; then an unwrap of whatever it produced, which must give the
//! secret back -- under that name only.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::os::raw::c_int;
use std::ptr;

#[path = "common.rs"]
mod common;
use common::*;
use hkdfguard::fuzz_support::{is_valid_secret_name, MAX_SECRET_WRAPPED_LEN, MIN_SECRET_WRAPPED_LEN};
use hkdfguard::{admin, hkdfguard_wrap_secret, status};

#[derive(Arbitrary, Debug)]
struct Input {
    service: Service,
    name: SecretName,
    secret: Vec<u8>,
    secret_null: bool,
    /// The length passed, when it differs from the secret's (capped at the
    /// buffer, so the library never reads past it).
    short_len: Option<u16>,
    call: Call,
}

fuzz_target!(|input: Input| {
    setup();
    let svc = input.service.cstring();
    let svc_ptr = svc.as_ref().map_or(ptr::null(), |c| c.as_ptr());
    let name_buf = input.name.bytes();
    let name_ptr = name_buf.as_ref().map_or(ptr::null(), |b| b.as_ptr().cast());
    let secret_ptr = if input.secret_null { ptr::null() } else { input.secret.as_ptr() };
    let secret_len: usize = input.short_len.map_or(input.secret.len(), |n| (n as usize).min(input.secret.len()));
    let secret = &input.secret[..secret_len];
    let call = &input.call;

    // The harness's restatement of the name rule and the library's agree.
    if let Some(name) = input.name.as_c() {
        if let Ok(name) = std::str::from_utf8(&name) {
            assert_eq!(is_valid_secret_name(name), name_is_valid(name.as_bytes()), "name rule differs for {name:?}");
        }
    }

    let ret = with_buffer(call, |out, out_len| {
        hkdfguard_wrap_secret(svc_ptr, name_ptr, secret_ptr, secret_len as c_int, out, out_len)
    });
    check_contract(&ret, call, false);
    let args_valid = !input.secret_null && (1..=SECRET_MAX).contains(&secret_len) && input.name.is_valid();

    match ret.rc {
        status::OK => {
            assert!(args_valid, "wrapped with invalid arguments: name {:?}, {secret_len} bytes, NULL {}", input.name, input.secret_null);
            assert!(input.service.is_fuzz(), "wrapped under service {:?}, which has no KEK", input.service);
            let payload = ret.written().to_vec();
            // Every secret, whatever its length, wraps to one size.
            assert_eq!(payload.len(), genuine_secret_payload().len(), "payload length depends on the secret");
            assert!((MIN_SECRET_WRAPPED_LEN..=MAX_SECRET_WRAPPED_LEN).contains(&payload.len()));
            assert!(admin::payload_fingerprint(&payload).is_some(), "wrap produced a payload the parser rejects");

            let full = Call { cap: SECRET_MAX as i16, out_null: false, out_len_null: false };
            for service in [Service::Fuzz, Service::FuzzUpper] {
                let back = unwrap_secret(&service, &input.name, &payload, &full);
                assert_eq!(back.rc, status::OK, "a payload wrap produced does not unwrap (service {service:?})");
                assert_eq!(back.written(), secret, "unwrap returned a different secret");
            }
            // Under any other name it fails authentication.
            let other = if input.name.as_c().as_deref() == Some(OTHER_SECRET_NAME.as_bytes()) {
                SecretName::Genuine
            } else {
                SecretName::Other
            };
            assert_eq!(unwrap_secret(&Service::Fuzz, &other, &payload, &full).rc, status::PAYLOAD_AUTH_FAILED);
            // And it is never a DEK.
            let dek = unwrap(&Service::Fuzz, &payload, &Call { cap: 32, out_null: false, out_len_null: false });
            assert_eq!(dek.rc, status::PAYLOAD_MALFORMED, "a secret payload is a malformed DEK payload");
        }
        status::BUFFER_TOO_SMALL => {
            assert!(ret.untouched(), "BUFFER_TOO_SMALL wrote to the buffer");
            let n = ret.out_len.unwrap();
            assert!(n > call.cap(), "BUFFER_TOO_SMALL reported {n}, not above the capacity {}", call.cap());
            assert!(n as usize <= MAX_SECRET_WRAPPED_LEN, "BUFFER_TOO_SMALL asks for {n} bytes");
            assert!(args_valid, "a size answer for invalid arguments: name {:?}, {secret_len} bytes", input.name);
        }
        _ => {}
    }
    if input.service.is_fuzz() && call.well_formed() && call.cap() as usize >= MAX_SECRET_WRAPPED_LEN {
        let expected = if args_valid { status::OK } else { status::INVALID_ARGUMENT };
        assert_eq!(ret.rc, expected, "wrap of {secret_len} bytes under {:?} (NULL {})", input.name, input.secret_null);
    }
});

//! `hkdfguard_unwrap_secret`: arbitrary bytes, a genuine DEK payload, and
//! structured corruptions of a genuine secret payload (bit flips,
//! truncation, trailing bytes), under every shape of service string,
//! secret name and output buffer. Also checks the domain separation from
//! the other direction: whatever the bytes, `hkdfguard_unwrap_dek` never
//! accepts them when they are (or derive from) a secret payload.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;
use common::*;
use hkdfguard::status;

#[derive(Arbitrary, Debug)]
enum Body {
    Genuine,
    GenuineDek,
    Raw(Vec<u8>),
    Patched { ops: Vec<(u16, u8)>, truncate: Option<u16>, extend: Vec<u8> },
}

#[derive(Arbitrary, Debug)]
struct Input {
    service: Service,
    name: SecretName,
    body: Body,
    call: Call,
}

fuzz_target!(|input: Input| {
    setup();
    let genuine = genuine_secret_payload();
    let bytes: Vec<u8> = match &input.body {
        Body::Genuine => genuine.clone(),
        Body::GenuineDek => genuine_payload().clone(),
        Body::Raw(b) => b.clone(),
        Body::Patched { ops, truncate, extend } => {
            let mut b = genuine.clone();
            for (off, x) in ops {
                let i = *off as usize % b.len();
                b[i] ^= x;
            }
            if let Some(t) = truncate {
                b.truncate(*t as usize);
            }
            b.extend_from_slice(extend);
            b
        }
    };

    let ret = unwrap_secret(&input.service, &input.name, &bytes, &input.call);
    check_contract(&ret, &input.call, true);

    match ret.rc {
        status::OK => {
            // Only the genuine payload authenticates, under its own KEK and
            // its own name (never another name, nor the uppercase spelling).
            assert!(input.service.is_fuzz(), "unwrapped under service {:?}", input.service);
            assert!(input.name.is_genuine(), "unwrapped under name {:?}", input.name);
            assert_eq!(bytes, *genuine, "a payload other than the genuine one unwrapped");
            assert_eq!(ret.written(), known_secret(), "unwrapped to a different secret");
            assert!(input.call.cap() as usize >= SECRET_MAX, "OK with less room than the longest secret");
        }
        status::BUFFER_TOO_SMALL => {
            assert_eq!(ret.out_len, Some(SECRET_MAX as i32), "BUFFER_TOO_SMALL must report HKDFGUARD_SECRET_MAX_LEN");
            assert!((input.call.cap() as usize) < SECRET_MAX);
            assert!(input.name.is_valid(), "a size answer for an invalid name {:?}", input.name);
        }
        rc => {
            if !input.name.is_valid() && !input.call.out_len_null {
                // An invalid name is refused on its own, whatever else is wrong
                // -- unless the service, checked first, already was.
                assert!(rc == status::INVALID_ARGUMENT || rc == status::INVALID_SERVICE_NAME, "invalid name {:?}: rc {rc}", input.name);
            }
        }
    }
    // A well-formed call on the genuine payload, service and name must succeed.
    if input.service.is_fuzz()
        && input.name.is_genuine()
        && bytes == *genuine
        && input.call.well_formed()
        && input.call.cap() as usize >= SECRET_MAX
    {
        assert_eq!(ret.rc, status::OK, "the genuine secret payload failed to unwrap");
    }
    // A DEK payload is never a secret, whatever name is tried.
    if matches!(input.body, Body::GenuineDek) {
        assert_ne!(ret.rc, status::OK, "a DEK payload unwrapped as a secret");
    }
    // And no secret payload, corrupted or not, is ever a DEK.
    if matches!(input.body, Body::Genuine | Body::Patched { .. }) {
        let dek = unwrap(&Service::Fuzz, &bytes, &Call { cap: 32, out_null: false, out_len_null: false });
        assert_ne!(dek.rc, status::OK, "a secret payload unwrapped as a DEK");
        assert_ne!(dek.rc, status::INTERNAL_ERROR);
    }
});

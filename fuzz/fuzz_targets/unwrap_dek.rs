//! `hkdfguard_unwrap_dek`: arbitrary bytes, and structured corruptions of
//! a genuine payload (bit flips, truncation, trailing bytes), under every
//! shape of service string and output buffer.
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
    Raw(Vec<u8>),
    Patched { ops: Vec<(u16, u8)>, truncate: Option<u16>, extend: Vec<u8> },
}

#[derive(Arbitrary, Debug)]
struct Input {
    service: Service,
    body: Body,
    call: Call,
}

fuzz_target!(|input: Input| {
    setup();
    let genuine = genuine_payload();
    let bytes: Vec<u8> = match &input.body {
        Body::Genuine => genuine.clone(),
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

    let ret = unwrap(&input.service, &bytes, &input.call);
    check_contract(&ret, &input.call, true);

    match ret.rc {
        status::OK => {
            // The only payload that can authenticate is the genuine one,
            // under its own KEK, and it must yield its DEK.
            assert!(input.service.is_fuzz(), "unwrapped under service {:?}", input.service);
            assert_eq!(bytes, *genuine, "a payload other than the genuine one unwrapped");
            assert_eq!(ret.out_len, Some(32));
            assert_eq!(ret.written(), &known_dek()[..]);
        }
        status::BUFFER_TOO_SMALL => {
            assert_eq!(ret.out_len, Some(32), "BUFFER_TOO_SMALL must report the DEK length");
        }
        _ => {}
    }
    // A well-formed call on the genuine payload must succeed.
    if input.service.is_fuzz() && bytes == *genuine && input.call.well_formed() && input.call.cap >= 32 {
        assert_eq!(ret.rc, status::OK, "the genuine payload failed to unwrap");
    }
});

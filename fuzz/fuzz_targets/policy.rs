//! The policy file: `Policy::from_toml_str` (parse and validation) on
//! arbitrary text, and now and then the same text installed as the
//! process's policy file and read through a C ABI call, which must fail
//! closed on anything the parser refuses.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::os::raw::c_int;

#[path = "common.rs"]
mod common;
use common::*;
use hkdfguard::fuzz_support::parse_policy;
use hkdfguard::{hkdfguard_security_model, status};

#[derive(Arbitrary, Debug)]
struct Input {
    doc: String,
    through_the_file: bool,
}

fuzz_target!(|input: Input| {
    setup();
    let verdict = parse_policy(&input.doc);
    if let Err(msg) = &verdict {
        assert!(!msg.is_empty(), "an empty refusal");
    }
    if input.through_the_file {
        write_policy(&input.doc);
        let (mut model, mut may_write): (c_int, c_int) = (-1, -1);
        let rc = hkdfguard_security_model(&mut model, &mut may_write);
        write_policy(FUZZ_POLICY);
        assert_ne!(rc, status::INTERNAL_ERROR);
        match verdict {
            Ok(()) => {
                assert_eq!(rc, status::OK, "a policy the parser accepts failed through the file");
                assert!(model == 0 || model == 1);
            }
            Err(_) => assert_eq!(rc, status::POLICY_INVALID, "an invalid policy did not fail closed"),
        }
    }
});

//! `hkdfguard_open_secret_file` on arbitrary file contents (every mode a
//! key file might have) and arbitrary paths, and the consistency of the
//! three judgements of a secret file's bytes: `key_file::check_kind`, the
//! payload parser, and what `open_secret_file` returns. Also that it and
//! `hkdfguard_open_file` never both accept the same bytes.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[path = "common.rs"]
mod common;
use common::*;
use hkdfguard::fuzz_support::{
    key_file_check, key_file_check_secret, payload_from_bytes, MAX_KEY_ID_LEN, MAX_SECRET_WRAPPED_LEN, MIN_SECRET_WRAPPED_LEN,
    SECRET_CIPHERTEXT_LEN,
};
use hkdfguard::{hkdfguard_open_file, hkdfguard_open_secret_file, status};

#[derive(Arbitrary, Debug)]
enum Mode {
    Owner,      // 0600
    OwnerRead,  // 0400
    Group,      // 0640: group read is allowed (the file is ciphertext)
    World,      // 0644
    GroupWrite, // 0660: refused under the developer model
    OtherWrite, // 0606: refused
}

impl Mode {
    fn bits(&self) -> u32 {
        match self {
            Mode::Owner => 0o600,
            Mode::OwnerRead => 0o400,
            Mode::Group => 0o640,
            Mode::World => 0o644,
            Mode::GroupWrite => 0o660,
            Mode::OtherWrite => 0o606,
        }
    }
    fn private(&self) -> bool {
        self.bits() & 0o022 == 0
    }
}

#[derive(Arbitrary, Debug)]
enum Prefix {
    None,
    GenuineSecret,
    GenuineDek,
    /// The genuine secret payload with bytes flipped in place: same
    /// length, so a corrupted header field (version, provider, key-id or
    /// ciphertext length) is judged on its own.
    PatchedSecret(Vec<(u16, u8)>),
}

#[derive(Arbitrary, Debug)]
enum Subject {
    /// A file of these bytes (after the prefix), in the fuzz directory.
    Content { prefix: Prefix, bytes: Vec<u8>, mode: Mode },
    /// Whatever path these bytes name.
    Path(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    subject: Subject,
    call: Call,
}

fn key_file_path() -> PathBuf {
    dir().join(format!("secret-{}.bin", std::process::id()))
}

/// `check_kind`, the parser and the length limits must agree on what a
/// secret file is: a payload the parser accepts, with a secret's
/// ciphertext length and a key id no wrap exceeds, within the bounds.
fn check_consistency(bytes: &[u8]) -> Result<(), i32> {
    let verdict = key_file_check_secret(bytes);
    let parsed = payload_from_bytes(bytes);
    let expected_ok = matches!(parsed, Some((kid, ct)) if ct == SECRET_CIPHERTEXT_LEN && kid <= MAX_KEY_ID_LEN)
        && bytes.len() <= MAX_SECRET_WRAPPED_LEN;
    assert_eq!(verdict.is_ok(), expected_ok, "check {verdict:?} vs parser {parsed:?} for {} bytes", bytes.len());
    // Never both a DEK file and a secret file.
    assert!(!(verdict.is_ok() && key_file_check(bytes).is_ok()), "{} bytes pass as a DEK file and a secret file", bytes.len());
    verdict
}

fuzz_target!(|input: Input| {
    setup();
    let call = &input.call;
    match &input.subject {
        Subject::Content { prefix, bytes, mode } => {
            let mut content = match prefix {
                Prefix::None => Vec::new(),
                Prefix::GenuineSecret => genuine_secret_payload().clone(),
                Prefix::GenuineDek => genuine_payload().clone(),
                Prefix::PatchedSecret(ops) => {
                    let mut b = genuine_secret_payload().clone();
                    for (off, x) in ops {
                        let i = *off as usize % b.len();
                        b[i] ^= x;
                    }
                    b
                }
            };
            content.extend_from_slice(bytes);
            let verdict = check_consistency(&content);

            let path = key_file_path();
            let _ = fs::remove_file(&path); // the last iteration's may be read-only
            fs::write(&path, &content).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode.bits())).unwrap();
            let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
            let ret = with_buffer(call, |out, out_len| hkdfguard_open_secret_file(cpath.as_ptr(), out, out_len));
            check_contract(&ret, call, true);

            let private = mode.private();
            match ret.rc {
                status::OK => {
                    assert!(verdict.is_ok(), "open_secret_file accepted a file check refuses ({verdict:?})");
                    assert!(private, "open_secret_file accepted a {:o} file, writable by others", mode.bits());
                    assert_eq!(ret.written(), &content[..], "open_secret_file returned different bytes");
                    // What it accepts, open_file refuses.
                    let dek = with_buffer(&Call { cap: 1024, out_null: false, out_len_null: false }, |out, out_len| {
                        hkdfguard_open_file(cpath.as_ptr(), out, out_len)
                    });
                    assert_ne!(dek.rc, status::OK, "a secret file opened as a DEK file");
                }
                status::BUFFER_TOO_SMALL => {
                    let needed = ret.out_len.unwrap() as usize;
                    if (call.cap() as usize) < MIN_SECRET_WRAPPED_LEN {
                        assert_eq!(needed, MAX_SECRET_WRAPPED_LEN, "a capacity below the minimum is answered with the maximum");
                    } else {
                        assert!(verdict.is_ok(), "BUFFER_TOO_SMALL for a file check refuses: its size leaked before the refusal");
                        assert_eq!(needed, content.len());
                    }
                }
                rc => {
                    if let Err(code) = verdict {
                        if private && call.well_formed() && call.cap() as usize >= MIN_SECRET_WRAPPED_LEN {
                            assert_eq!(rc, code, "open_secret_file's refusal differs from check_kind's");
                        }
                    }
                }
            }
            if verdict.is_ok() && private && call.well_formed() && call.cap() as usize >= content.len() {
                assert_eq!(ret.rc, status::OK, "a valid private secret file was refused");
            }
            if !private && call.well_formed() {
                assert_ne!(ret.rc, status::OK);
            }
            if matches!(prefix, Prefix::GenuineSecret) && bytes.is_empty() && private && call.well_formed() && call.cap() as usize >= content.len() {
                assert_eq!(ret.rc, status::OK, "the genuine secret payload, as a private file, was refused");
            }
        }
        Subject::Path(bytes) => {
            let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
            let cpath = CString::new(&bytes[..end]).unwrap();
            let ret = with_buffer(call, |out, out_len| hkdfguard_open_secret_file(cpath.as_ptr(), out, out_len));
            check_contract(&ret, call, true);
            assert_ne!(ret.rc, status::OK, "open_secret_file accepted {:?}", cpath);
            if end == 0 && call.well_formed() {
                assert_eq!(ret.rc, status::INVALID_ARGUMENT);
            }
        }
    }
});

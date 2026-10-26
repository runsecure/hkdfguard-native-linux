//! `hkdfguard_open_file` on arbitrary file contents (every mode a key file
//! might have) and arbitrary paths, and the consistency of the three
//! judgements of a key file's bytes: `key_file::check`, the payload parser,
//! and what `open_file` returns.
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
use hkdfguard::fuzz_support::{key_file_check, payload_from_bytes, MAX_KEY_ID_LEN, MAX_WRAPPED_LEN, MIN_WRAPPED_LEN};
use hkdfguard::{hkdfguard_open_file, status};

#[derive(Arbitrary, Debug)]
enum Mode {
    Owner,      // 0600
    OwnerRead,  // 0400
    Group,      // 0640: group read is allowed (the file is ciphertext)
    World,      // 0644: so is other read
    Exec,       // 0700
    GroupWrite, // 0660: refused under the developer model (no deployer group)
    OtherWrite, // 0606: refused
    All,        // 0666: refused
}

impl Mode {
    fn bits(&self) -> u32 {
        match self {
            Mode::Owner => 0o600,
            Mode::OwnerRead => 0o400,
            Mode::Group => 0o640,
            Mode::World => 0o644,
            Mode::Exec => 0o700,
            Mode::GroupWrite => 0o660,
            Mode::OtherWrite => 0o606,
            Mode::All => 0o666,
        }
    }
    /// Writable by nobody but the owner: what the header says is accepted.
    fn private(&self) -> bool {
        self.bits() & 0o022 == 0
    }
}

#[derive(Arbitrary, Debug)]
enum Subject {
    /// A file of these bytes, in the fuzz directory.
    Content { bytes: Vec<u8>, mode: Mode, genuine_prefix: bool },
    /// Whatever path these bytes name.
    Path(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    subject: Subject,
    call: Call,
}

fn key_file_path() -> PathBuf {
    dir().join(format!("key-{}.bin", std::process::id()))
}

/// `check`, the parser and the length limits must agree on what a key
/// file is: a payload the parser accepts, 48 bytes of ciphertext, a key
/// id no wrap exceeds, within the length bounds.
fn check_consistency(bytes: &[u8]) -> Result<(), i32> {
    let verdict = key_file_check(bytes);
    let parsed = payload_from_bytes(bytes);
    let expected_ok = matches!(parsed, Some((kid, ct)) if ct == 48 && kid <= MAX_KEY_ID_LEN) && bytes.len() <= MAX_WRAPPED_LEN;
    assert_eq!(verdict.is_ok(), expected_ok, "check {verdict:?} vs parser {parsed:?} for {} bytes", bytes.len());
    verdict
}

fuzz_target!(|input: Input| {
    setup();
    let call = &input.call;
    match &input.subject {
        Subject::Content { bytes, mode, genuine_prefix } => {
            let mut content = Vec::new();
            if *genuine_prefix {
                content.extend_from_slice(genuine_payload());
            }
            content.extend_from_slice(bytes);
            let verdict = check_consistency(&content);

            let path = key_file_path();
            let _ = fs::remove_file(&path); // the last iteration's may be read-only
            fs::write(&path, &content).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode.bits())).unwrap();
            let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
            let ret = with_buffer(call, |out, out_len| hkdfguard_open_file(cpath.as_ptr(), out, out_len));
            check_contract(&ret, call, true);

            let private = mode.private();
            match ret.rc {
                status::OK => {
                    assert!(verdict.is_ok(), "open_file accepted a file check refuses ({verdict:?})");
                    assert!(private, "open_file accepted a {:o} key file, writable by others", mode.bits());
                    assert_eq!(ret.written(), &content[..], "open_file returned different bytes");
                }
                status::BUFFER_TOO_SMALL => {
                    // Documented: a capacity below the smallest payload is
                    // answered with the maximum, before the file is opened;
                    // otherwise the file was read, checked, and its exact
                    // length reported. A refused file's length must never
                    // come back.
                    let needed = ret.out_len.unwrap() as usize;
                    if (call.cap() as usize) < MIN_WRAPPED_LEN {
                        assert_eq!(needed, MAX_WRAPPED_LEN);
                    } else {
                        assert!(verdict.is_ok(), "BUFFER_TOO_SMALL for a file check refuses: its size leaked before the refusal");
                        assert_eq!(needed, content.len());
                    }
                }
                rc => {
                    if let Err(code) = verdict {
                        if private && call.well_formed() && call.cap() as usize >= MIN_WRAPPED_LEN {
                            assert_eq!(rc, code, "open_file's refusal differs from check's");
                        }
                    }
                }
            }
            if verdict.is_ok() && private && call.well_formed() && call.cap() as usize >= content.len() {
                assert_eq!(ret.rc, status::OK, "a valid private key file was refused");
            }
            if !private && call.well_formed() {
                assert_ne!(ret.rc, status::OK);
            }
        }
        Subject::Path(bytes) => {
            let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
            let cpath = CString::new(&bytes[..end]).unwrap();
            let ret = with_buffer(call, |out, out_len| hkdfguard_open_file(cpath.as_ptr(), out, out_len));
            check_contract(&ret, call, true);
            // Nothing outside the fuzz directory is a trusted key file.
            assert_ne!(ret.rc, status::OK, "open_file accepted {:?}", cpath);
            if end == 0 {
                assert_eq!(ret.rc, status::INVALID_ARGUMENT);
            }
        }
    }
});

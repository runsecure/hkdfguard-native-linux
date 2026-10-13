//! Reading a wrapped-DEK key file, for `hkdfguard_open_file`.
//!
//! A key file is one wrapped payload exactly as `hkdfguard-v1-initialize
//! wrap` (or a caller storing `hkdfguard_wrap_dek`'s output) wrote it: the
//! raw bytes of [`crate::payload`], nothing before or after. Reading one
//! never unwraps it -- no provider is reached and no KEK is opened -- but
//! the file is checked as far as it can be without a KEK:
//!
//! - **Length.** A payload is [`MIN_WRAPPED_LEN`]..=[`MAX_WRAPPED_LEN`]
//!   bytes, and its header declares its own exact length (the `key_id`
//!   length; the ciphertext is always a 32-byte DEK plus its tag). A file
//!   shorter than that is [`KeyFileError::TooShort`], a longer one
//!   [`KeyFileError::TooLong`].
//! - **Form.** Version, provider tag, `key_id` length, and ciphertext
//!   length must be ones a wrap can produce, and the whole must parse;
//!   otherwise [`KeyFileError::Malformed`].
//! - **An unprotected key.** A file holding what looks like an *unwrapped*
//!   DEK -- 32 raw bytes, or the base64 text the CLI takes as its DEK input
//!   -- is [`KeyFileError::PlaintextKey`]: most likely the DEK itself saved
//!   where its wrapped form belongs. A 32-byte file is refused from its size
//!   alone, without its contents ever being read into this process. Neither
//!   form can be mistaken for a payload: both are shorter than the smallest
//!   one.

use crate::crypto::{DEK_LEN, MAX_KEY_ID_LEN, MAX_WRAPPED_LEN, MIN_WRAPPED_LEN, TAG_LEN};
use crate::error::status;
use crate::payload::{Payload, NONCE_LEN, SALT_LEN, VERSION};
use crate::provider::ProviderType;
use crate::secure_file::{self, FileRequirements, SecretBuffer};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::io;
use std::path::Path;
use zeroize::Zeroizing;

/// Why a key file was refused. Each maps to its own C status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFileError {
    /// The file, or a directory in its path, does not exist.
    NotFound,
    /// The calling process may not open the file.
    AccessDenied,
    /// Not a regular file (a directory, FIFO, device...), or the read failed.
    Io,
    /// Shorter than the smallest payload, or than its own header declares.
    TooShort,
    /// Longer than the largest payload, or than its own header declares.
    TooLong,
    /// The right length, but not a payload a wrap could have produced.
    Malformed,
    /// Looks like an unwrapped DEK: treat it as a key exposure.
    PlaintextKey,
}

impl KeyFileError {
    pub fn status_code(self) -> i32 {
        match self {
            KeyFileError::NotFound => status::FILE_NOT_FOUND,
            KeyFileError::AccessDenied => status::FILE_ACCESS_DENIED,
            KeyFileError::Io => status::FILE_IO,
            KeyFileError::TooShort => status::FILE_TOO_SHORT,
            KeyFileError::TooLong => status::FILE_TOO_LONG,
            KeyFileError::Malformed => status::FILE_MALFORMED,
            KeyFileError::PlaintextKey => status::FILE_PLAINTEXT_KEY,
        }
    }

    // For the log line `hkdfguard_open_file` writes on a refusal.
    pub fn describe(self) -> &'static str {
        match self {
            KeyFileError::NotFound => "the file, or a directory in its path, does not exist",
            KeyFileError::AccessDenied => "this process may not open the file",
            KeyFileError::Io => "not a regular file, or reading it failed",
            KeyFileError::TooShort => "the file is shorter than a wrapped DEK, or than its header declares",
            KeyFileError::TooLong => "the file is longer than a wrapped DEK, or than its header declares",
            KeyFileError::Malformed => "the file is not a well-formed wrapped DEK",
            KeyFileError::PlaintextKey => {
                "the file looks like an UNWRAPPED DEK (32 raw bytes, or its base64); treat it as a key exposure"
            }
        }
    }
}

/// Opens `path` and returns its contents once they pass [`check`].
///
/// Opened read-only, following symlinks, with `O_NONBLOCK` so a FIFO can't
/// hang the call; anything but a regular file is refused before a byte is
/// read. A file whose size alone says it is too long, or is a raw DEK, is
/// refused without being read. The bytes come back in a [`SecretBuffer`]:
/// a payload is ciphertext, but a refused file may have held a plaintext
/// key, and either way the buffer is wiped when dropped.
pub fn read(path: &Path) -> Result<SecretBuffer, KeyFileError> {
    let req = FileRequirements {
        owner: None,
        forbidden_mode_bits: 0,
        follow_symlinks: true,
        allow_group_read_if_root_owned: false,
    };
    let mut file = secure_file::open_checked(path, &req).map_err(open_error)?;
    let size = file.metadata().map_err(|_| KeyFileError::Io)?.len();
    if size == DEK_LEN as u64 {
        return Err(KeyFileError::PlaintextKey);
    }
    if size > MAX_WRAPPED_LEN as u64 {
        return Err(KeyFileError::TooLong);
    }
    // The size can change between the fstat and the read; `check` judges
    // what was actually read, and a file that grew past the limit fails
    // the read itself.
    let contents = SecretBuffer::read_from(&mut file, MAX_WRAPPED_LEN).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidData => KeyFileError::TooLong,
        _ => KeyFileError::Io,
    })?;
    check(contents.as_slice())?;
    Ok(contents)
}

fn open_error(e: io::Error) -> KeyFileError {
    match e.kind() {
        io::ErrorKind::NotFound => KeyFileError::NotFound,
        io::ErrorKind::PermissionDenied => KeyFileError::AccessDenied,
        _ if e.raw_os_error() == Some(libc::ENOTDIR) => KeyFileError::NotFound, // a path component is a file
        _ => KeyFileError::Io, // includes InvalidData: not a regular file
    }
}

/// Checks that `bytes` are a complete wrapped DEK payload: see the module
/// docs for what each refusal means.
pub fn check(bytes: &[u8]) -> Result<(), KeyFileError> {
    if looks_like_plaintext_dek(bytes) {
        return Err(KeyFileError::PlaintextKey);
    }
    let len = bytes.len();
    if len < MIN_WRAPPED_LEN {
        return Err(KeyFileError::TooShort);
    }
    if len > MAX_WRAPPED_LEN {
        return Err(KeyFileError::TooLong);
    }
    // From here `len >= MIN_WRAPPED_LEN`, so the fixed header fields read
    // below are all in bounds.
    if bytes[0] != VERSION || ProviderType::from_u8(bytes[1]).is_none() {
        return Err(KeyFileError::Malformed);
    }
    let key_id_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if key_id_len > MAX_KEY_ID_LEN {
        return Err(KeyFileError::Malformed); // no wrap records a longer one, so this is not a length the file could be "short" of
    }
    let declared = MIN_WRAPPED_LEN + key_id_len;
    if len < declared {
        return Err(KeyFileError::TooShort);
    }
    if len > declared {
        return Err(KeyFileError::TooLong);
    }
    // `len == declared`, so the ciphertext length field is in bounds.
    let ct_len_at = 4 + key_id_len + SALT_LEN + NONCE_LEN;
    let ct_len = u32::from_le_bytes(bytes[ct_len_at..ct_len_at + 4].try_into().unwrap()) as usize;
    if ct_len != DEK_LEN + TAG_LEN {
        return Err(KeyFileError::Malformed);
    }
    // Every field is now known to be consistent; the real parser has the
    // final word, so this and `unwrap` can never disagree on what parses.
    Payload::from_bytes(bytes).map_err(|_| KeyFileError::Malformed)?;
    Ok(())
}

/// Base64 of a 32-byte DEK, with its one `=` of padding.
const BASE64_DEK_LEN: usize = 44;

// 32 raw bytes, or the CLI's DEK input format: standard base64 of exactly
// 32 bytes, optionally followed by one "\n" or "\r\n".
fn looks_like_plaintext_dek(bytes: &[u8]) -> bool {
    if bytes.len() == DEK_LEN {
        return true;
    }
    let text = match bytes.strip_suffix(b"\n") {
        Some(t) => t.strip_suffix(b"\r").unwrap_or(t),
        None => bytes,
    };
    if text.len() != BASE64_DEK_LEN {
        return false;
    }
    let mut decoded = Zeroizing::new([0u8; BASE64_DEK_LEN]); // a decoded DEK is wiped as soon as it's been measured
    matches!(STANDARD.decode_slice(text, &mut decoded[..]), Ok(n) if n == DEK_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::FINGERPRINT_LEN;
    use std::os::unix::fs::PermissionsExt;

    fn payload_with_key_id(key_id_len: usize) -> Vec<u8> {
        Payload {
            provider_type: ProviderType::ExternalSecret,
            key_id: vec![b'k'; key_id_len],
            salt: [0x11; SALT_LEN],
            nonce: [0x22; NONCE_LEN],
            ciphertext: vec![0x33; DEK_LEN + TAG_LEN],
            fingerprint: [0x44; FINGERPRINT_LEN],
        }
        .to_bytes()
    }

    fn valid() -> Vec<u8> {
        payload_with_key_id(b"external:com.company.orders".len())
    }

    fn write(dir: &Path, name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn base64_dek() -> String {
        STANDARD.encode([0x5Au8; DEK_LEN])
    }

    // ---- check(): length ----

    #[test]
    fn accepts_every_key_id_length_a_wrap_can_produce() {
        for key_id_len in [0, 1, 32, MAX_KEY_ID_LEN] {
            let bytes = payload_with_key_id(key_id_len);
            assert_eq!(check(&bytes), Ok(()), "key_id of {key_id_len} bytes");
        }
        assert_eq!(payload_with_key_id(0).len(), MIN_WRAPPED_LEN);
        assert_eq!(payload_with_key_id(MAX_KEY_ID_LEN).len(), MAX_WRAPPED_LEN);
    }

    #[test]
    fn every_truncation_is_too_short_or_a_plaintext_key() {
        let bytes = valid();
        for len in 0..bytes.len() {
            let expected = if len == DEK_LEN { KeyFileError::PlaintextKey } else { KeyFileError::TooShort };
            assert_eq!(check(&bytes[..len]), Err(expected), "truncated to {len} bytes");
        }
    }

    #[test]
    fn empty_file_is_too_short() {
        assert_eq!(check(&[]), Err(KeyFileError::TooShort));
    }

    #[test]
    fn trailing_bytes_are_too_long() {
        for extra in [1usize, 16] {
            let mut bytes = valid();
            bytes.extend(std::iter::repeat_n(0u8, extra));
            assert!(bytes.len() <= MAX_WRAPPED_LEN);
            assert_eq!(check(&bytes), Err(KeyFileError::TooLong), "{extra} trailing bytes");
        }
    }

    #[test]
    fn anything_over_the_largest_payload_is_too_long() {
        let mut bytes = payload_with_key_id(MAX_KEY_ID_LEN);
        bytes.push(0);
        assert_eq!(check(&bytes), Err(KeyFileError::TooLong));
        assert_eq!(check(&vec![1u8; 64 * 1024]), Err(KeyFileError::TooLong));
    }

    #[test]
    fn header_declaring_more_than_the_file_holds_is_too_short() {
        let mut bytes = valid();
        let declared = u16::from_le_bytes([bytes[2], bytes[3]]) + 1;
        bytes[2..4].copy_from_slice(&declared.to_le_bytes());
        assert_eq!(check(&bytes), Err(KeyFileError::TooShort));
    }

    #[test]
    fn header_declaring_less_than_the_file_holds_is_too_long() {
        let mut bytes = valid();
        let declared = u16::from_le_bytes([bytes[2], bytes[3]]) - 1;
        bytes[2..4].copy_from_slice(&declared.to_le_bytes());
        assert_eq!(check(&bytes), Err(KeyFileError::TooLong));
    }

    // ---- check(): form ----

    #[test]
    fn unsupported_version_is_malformed() {
        for version in [0u8, 2, 0xFF] {
            let mut bytes = valid();
            bytes[0] = version;
            assert_eq!(check(&bytes), Err(KeyFileError::Malformed), "version {version}");
        }
    }

    #[test]
    fn unknown_or_retired_provider_is_malformed() {
        for provider in [0u8, 4, 6, 0xFF] {
            let mut bytes = valid();
            bytes[1] = provider;
            assert_eq!(check(&bytes), Err(KeyFileError::Malformed), "provider tag {provider}");
        }
    }

    #[test]
    fn key_id_longer_than_any_wrap_records_is_malformed() {
        let mut bytes = valid();
        bytes[2..4].copy_from_slice(&((MAX_KEY_ID_LEN + 1) as u16).to_le_bytes());
        assert_eq!(check(&bytes), Err(KeyFileError::Malformed));
        bytes[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(check(&bytes), Err(KeyFileError::Malformed));
    }

    #[test]
    fn ciphertext_length_other_than_a_wrapped_dek_is_malformed() {
        let key_id_len = b"external:com.company.orders".len();
        let ct_len_at = 4 + key_id_len + SALT_LEN + NONCE_LEN;
        for ct_len in [0u32, 47, 49, u32::MAX] {
            let mut bytes = valid();
            bytes[ct_len_at..ct_len_at + 4].copy_from_slice(&ct_len.to_le_bytes());
            assert_eq!(check(&bytes), Err(KeyFileError::Malformed), "ciphertext length {ct_len}");
        }
    }

    // ---- check(): unprotected key ----

    #[test]
    fn raw_dek_is_a_plaintext_key() {
        assert_eq!(check(&[0u8; DEK_LEN]), Err(KeyFileError::PlaintextKey));
        assert_eq!(check(&[0xFFu8; DEK_LEN]), Err(KeyFileError::PlaintextKey));
    }

    #[test]
    fn base64_dek_is_a_plaintext_key_with_or_without_a_newline() {
        let b64 = base64_dek();
        for text in [b64.clone(), format!("{b64}\n"), format!("{b64}\r\n")] {
            assert_eq!(check(text.as_bytes()), Err(KeyFileError::PlaintextKey), "{text:?}");
        }
    }

    #[test]
    fn near_misses_of_a_plaintext_key_are_just_too_short() {
        let b64 = base64_dek();
        for text in [
            STANDARD.encode([0x5Au8; DEK_LEN - 1]), // base64, but of 31 bytes
            "!".repeat(BASE64_DEK_LEN),             // 44 bytes, not base64
            format!("{b64}\n\n"),                   // more than one newline
            format!(" {b64}"),                      // leading space
        ] {
            assert_eq!(check(text.as_bytes()), Err(KeyFileError::TooShort), "{text:?}");
        }
        for len in [DEK_LEN - 1, DEK_LEN + 1] {
            assert_eq!(check(&vec![0u8; len]), Err(KeyFileError::TooShort), "{len} raw bytes");
        }
    }

    #[test]
    fn no_valid_payload_can_be_mistaken_for_a_plaintext_key() {
        // Both plaintext forms are far shorter than the smallest payload.
        assert!(BASE64_DEK_LEN + 2 < MIN_WRAPPED_LEN && DEK_LEN < MIN_WRAPPED_LEN);
    }

    // ---- read(): the file itself ----

    #[test]
    fn reads_a_valid_key_file_byte_for_byte() {
        let dir = secure_file::private_tempdir();
        let bytes = valid();
        let path = write(dir.path(), "wrapped.key", &bytes);
        assert_eq!(read(&path).unwrap().as_slice(), &bytes[..]);
    }

    #[test]
    fn follows_a_symlink_to_a_key_file() {
        let dir = secure_file::private_tempdir();
        let bytes = valid();
        let target = write(dir.path(), "wrapped.key", &bytes);
        let link = dir.path().join("current.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(read(&link).unwrap().as_slice(), &bytes[..]);
    }

    #[test]
    fn file_level_refusals_carry_the_same_reasons_as_check() {
        let dir = secure_file::private_tempdir();
        let mut long = valid();
        long.push(0);
        let mut bad_version = valid();
        bad_version[0] = 9;
        let cases: [(&str, Vec<u8>, KeyFileError); 7] = [
            ("empty", vec![], KeyFileError::TooShort),
            ("short", valid()[..100].to_vec(), KeyFileError::TooShort),
            ("long", long, KeyFileError::TooLong),
            ("huge", vec![0u8; 1024 * 1024], KeyFileError::TooLong),
            ("malformed", bad_version, KeyFileError::Malformed),
            ("raw-dek", vec![7u8; DEK_LEN], KeyFileError::PlaintextKey),
            ("b64-dek", format!("{}\n", base64_dek()).into_bytes(), KeyFileError::PlaintextKey),
        ];
        for (name, contents, expected) in cases {
            let path = write(dir.path(), name, &contents);
            assert_eq!(read(&path).err(), Some(expected), "{name}");
        }
    }

    #[test]
    fn missing_file_or_directory_is_not_found() {
        let dir = secure_file::private_tempdir();
        assert_eq!(read(&dir.path().join("absent.key")).err(), Some(KeyFileError::NotFound));
        assert_eq!(read(&dir.path().join("no-such-dir/absent.key")).err(), Some(KeyFileError::NotFound));
        let file = write(dir.path(), "a-file", &valid());
        assert_eq!(read(&file.join("wrapped.key")).err(), Some(KeyFileError::NotFound), "a path component is a file");
    }

    #[test]
    fn unreadable_file_is_access_denied() {
        if secure_file::skip_as_root() {
            return; // root reads a mode-000 file
        }
        let dir = secure_file::private_tempdir();
        let path = write(dir.path(), "wrapped.key", &valid());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(read(&path).err(), Some(KeyFileError::AccessDenied));
    }

    #[test]
    fn directory_is_refused_as_io() {
        let dir = secure_file::private_tempdir();
        assert_eq!(read(dir.path()).err(), Some(KeyFileError::Io));
    }

    #[test]
    fn fifo_is_refused_without_blocking() {
        let dir = secure_file::private_tempdir();
        let fifo = dir.path().join("wrapped.key");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: c is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(read(&fifo).err()).unwrap());
        let result = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("read blocked on a FIFO");
        assert_eq!(result, Some(KeyFileError::Io));
    }

    #[test]
    fn every_refusal_has_its_own_status_code() {
        let all = [
            KeyFileError::NotFound,
            KeyFileError::AccessDenied,
            KeyFileError::Io,
            KeyFileError::TooShort,
            KeyFileError::TooLong,
            KeyFileError::Malformed,
            KeyFileError::PlaintextKey,
        ];
        let mut codes: Vec<i32> = all.iter().map(|e| e.status_code()).collect();
        assert!(codes.iter().all(|&c| c < 0));
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }
}

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
//!   DEK -- 32 raw bytes, or 32 bytes as text: base64 (standard or URL-safe,
//!   padded or not; the CLI's DEK input is standard base64) or hex, with any
//!   surrounding whitespace -- is [`KeyFileError::PlaintextKey`]: most likely the DEK itself saved
//!   where its wrapped form belongs. A 32-byte file is refused from its size
//!   alone, normally without its contents being read into this process. Neither
//!   form can be mistaken for a payload: both are shorter than the smallest
//!   one.
//! - **Integrity.** The file must be owned by root or by this process's
//!   user, and must not be writable by group or others; otherwise
//!   [`KeyFileError::Untrusted`]. A wrapped DEK is ciphertext, so reading
//!   it gains nothing -- but *replacing* it does: anyone who can write the
//!   file and can also wrap under the service's KEK (on TPM2, any process
//!   in the `tss` group with the derivation secret) could plant a DEK they
//!   know, and `unwrap` would accept it as genuine. The CLI writes key
//!   files `0600` for the same reason. Symlinks are followed, and the
//!   checks apply to the file they resolve to. The same holds for the
//!   directories that decide what the path names -- the opened file's own
//!   and the one the path names it in, each up to `/`: owned by root or
//!   this user, and not writable by group or others unless sticky
//!   (`/tmp`-style). Otherwise someone else could rename a file of their
//!   choosing over the key, or retarget a symlink to one. (The OS itself
//!   refusing to open the file -- e.g. `EACCES` -- is the separate
//!   [`KeyFileError::AccessDenied`].)

use crate::crypto::{DEK_LEN, MAX_KEY_ID_LEN, MAX_WRAPPED_LEN, MIN_WRAPPED_LEN, TAG_LEN};
use crate::error::status;
use crate::payload::{Payload, NONCE_LEN, SALT_LEN, VERSION};
use crate::provider::ProviderType;
use crate::secure_file::{self, FileRequirements, Owner, SecretBuffer, FORBID_GROUP_OTHER_WRITE};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::io;
use std::path::Path;
use zeroize::Zeroizing;

/// Why a key file was refused. Each maps to its own C status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFileError {
    /// The file, or a directory in its path, does not exist.
    NotFound,
    /// The OS refused to let the calling process open the file (or search
    /// a directory in its path), e.g. `EACCES`.
    AccessDenied,
    /// The file, or a directory deciding what its path names, is owned by
    /// another user or is writable by group or others -- or the file was
    /// swapped between being checked and being opened -- so someone else
    /// could have replaced its contents.
    Untrusted,
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
            KeyFileError::Untrusted => status::FILE_UNTRUSTED,
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
            KeyFileError::Untrusted => {
                "the file or a directory deciding what its path names is owned by another user or writable by \
                 group/others, so someone else could have replaced it"
            }
            KeyFileError::Io => "not a regular file, or reading it failed",
            KeyFileError::TooShort => "the file is shorter than a wrapped DEK, or than its header declares",
            KeyFileError::TooLong => "the file is longer than a wrapped DEK, or than its header declares",
            KeyFileError::Malformed => "the file is not a well-formed wrapped DEK",
            KeyFileError::PlaintextKey => {
                "the file looks like an UNWRAPPED DEK (32 raw bytes, or its base64 or hex); treat it as a key exposure"
            }
        }
    }
}

/// Opens `path` and returns its contents once they pass [`check`].
///
/// The same sequence the external-secret provider uses for its secret
/// files (`open_secret_within_mount`):
///
/// 1. `path` is resolved once, symlinks and all, to the real file.
/// 2. The directories that decide what `path` names are checked (see the
///    module docs): the resolved file's, and the one `path` names it in,
///    where a symlink lives if `path` is one -- each up to `/`.
/// 3. The *resolved* path is opened read-only with `O_NOFOLLOW`, so a
///    symlink swapped in after step 1 fails the open instead of being
///    followed, and with `O_NONBLOCK` so a FIFO can't hang the call.
///    Anything but a regular file, and any file someone other than root or
///    this user could have written, is refused on the opened descriptor's
///    own metadata, before a byte is read.
/// 4. The descriptor is confirmed to be the file resolved and checked in
///    steps 1-2 ([`secure_file::verify_opened`]): through `/proc` where it
///    is mounted, and by device and inode where it isn't -- equally
///    conclusive, so a sandbox without `/proc` loses nothing.
///
/// A file whose size alone says it is too long, or is a raw DEK, is then
/// normally refused without being read (one rewritten between the size
/// check and the read is read, then refused on its contents). The bytes
/// come back in a [`SecretBuffer`]: a payload is ciphertext, but a refused
/// file may have held a plaintext key, and either way the buffer is wiped
/// when dropped.
pub fn read(path: &Path) -> Result<SecretBuffer, KeyFileError> {
    read_with_proc_root(path, Path::new("/proc"))
}

// `read`, with where `/proc` is mounted made a parameter so tests can run
// it as though `/proc` were missing.
fn read_with_proc_root(path: &Path, proc_root: &Path) -> Result<SecretBuffer, KeyFileError> {
    let req = FileRequirements {
        owner: Some(Owner::RootOrCurrentUser),
        forbidden_mode_bits: FORBID_GROUP_OTHER_WRITE,
        follow_symlinks: false,
        allow_group_read_if_root_owned: false, // group read isn't forbidden here anyway: the file is ciphertext
    };
    let target_real = std::fs::canonicalize(path).map_err(open_error)?;
    check_location(path, &target_real)?;
    let mut file = secure_file::open_checked(&target_real, &req).map_err(|e| match e.raw_os_error() {
        Some(libc::ELOOP) => KeyFileError::Untrusted, // became a symlink after it was resolved
        // No OS error behind it: `open_checked`'s own owner/mode check on
        // the opened descriptor refused the file, not the kernel.
        None if e.kind() == io::ErrorKind::PermissionDenied => KeyFileError::Untrusted,
        _ => open_error(e),
    })?;
    secure_file::verify_opened(&file, &target_real, &target_real, proc_root).map_err(|_| KeyFileError::Untrusted)?;
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

// The directories that decide what `path` names must be as trustworthy as
// the file: owned by root or this user, and not writable by group or others
// (sticky, `/tmp`-style, is fine -- see
// `secure_file::check_dir_chain_for_existing_file`). Otherwise someone else
// could rename a file of their choosing over the key, or retarget a symlink
// to one, and the file checks alone would pass on whatever they put there.
//
// Two directories are checked, each up to `/`: the resolved file's own --
// where the file actually read sits, which `read` confirms after the open --
// and the one `path` names it in, which holds the symlink if `path` is one.
// Directories that intermediate symlinks *within* the path live in are not
// walked; someone able to retarget one could at most redirect `path` to a
// different file that itself passes every check here (owned by root or
// this user, in trusted directories) -- never to one they wrote.
fn check_location(path: &Path, target_real: &Path) -> Result<(), KeyFileError> {
    let check = |dir: &Path| {
        secure_file::check_dir_chain_for_existing_file(dir, Owner::RootOrCurrentUser)
            .map_err(|_| KeyFileError::Untrusted)
    };
    // Only `/` has no parent, and `/` is a directory, not a key file.
    let target_dir = target_real.parent().ok_or(KeyFileError::Io)?;
    check(target_dir)?;

    let named_in = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let named_in = std::fs::canonicalize(named_in).map_err(|e| match e.kind() {
        io::ErrorKind::PermissionDenied => KeyFileError::AccessDenied, // the OS refused to resolve it
        _ => KeyFileError::Untrusted, // can't confirm what names the file, so it isn't trusted
    })?;
    if named_in != target_dir {
        check(&named_in)?;
    }
    Ok(())
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
/// Hex of a 32-byte DEK.
const HEX_DEK_LEN: usize = 2 * DEK_LEN;
/// Longest text form recognised, surrounding whitespace included. Every
/// length up to this is far below [`MIN_WRAPPED_LEN`], so no payload can
/// ever be mistaken for a plaintext key, however it is padded.
const MAX_PLAINTEXT_TEXT_LEN: usize = 96;
// Checked at compile time: plaintext detection can never refuse a real payload.
const _: () = assert!(MAX_PLAINTEXT_TEXT_LEN < MIN_WRAPPED_LEN && DEK_LEN < MIN_WRAPPED_LEN);

// 32 raw bytes, or 32 bytes written as text: base64 (standard or URL-safe,
// with or without its `=` padding -- the CLI's own DEK input format is
// standard, padded) or hex (either case), with any leading or trailing
// whitespace an editor or `echo` adds. Every one of these is refused as
// TooShort anyway; recognising them is what turns "wrong file" into "this
// key is exposed".
fn looks_like_plaintext_dek(bytes: &[u8]) -> bool {
    if bytes.len() == DEK_LEN {
        return true;
    }
    if bytes.len() > MAX_PLAINTEXT_TEXT_LEN {
        return false;
    }
    let text = bytes.trim_ascii();
    match text.len() {
        HEX_DEK_LEN => text.iter().all(u8::is_ascii_hexdigit),
        43 | BASE64_DEK_LEN => {
            use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
            let mut decoded = Zeroizing::new([0u8; BASE64_DEK_LEN]); // a decoded DEK is wiped as soon as it's been measured
            [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
                .iter()
                .any(|engine| matches!(engine.decode_slice(text, &mut decoded[..]), Ok(n) if n == DEK_LEN))
        }
        _ => false,
    }
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

    // Every text form of one DEK whose bytes need '+' and '/' in standard
    // base64 (so '-' and '_' in URL-safe): the encodings really differ.
    fn text_forms_of_a_dek() -> Vec<(&'static str, String)> {
        use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
        let dek = [0xFBu8; DEK_LEN];
        let hex: String = dek.iter().map(|b| format!("{b:02x}")).collect();
        vec![
            ("base64", STANDARD.encode(dek)),
            ("base64, no padding", STANDARD_NO_PAD.encode(dek)),
            ("URL-safe base64", URL_SAFE.encode(dek)),
            ("URL-safe base64, no padding", URL_SAFE_NO_PAD.encode(dek)),
            ("hex", hex.clone()),
            ("HEX", hex.to_ascii_uppercase()),
        ]
    }

    #[test]
    fn every_text_form_of_a_dek_is_a_plaintext_key_whatever_the_whitespace() {
        let forms = text_forms_of_a_dek();
        assert!(forms[0].1.contains('+') && forms[2].1.contains('-'), "the fixture must exercise both alphabets");
        for (name, text) in forms {
            for wrapped in [text.clone(), format!("{text}\n"), format!("{text}\r\n"), format!("{text}\n\n"), format!("  {text}\t\n")] {
                assert_eq!(check(wrapped.as_bytes()), Err(KeyFileError::PlaintextKey), "{name}: {wrapped:?}");
            }
        }
        // And the CLI's own DEK input, exactly as the docs show writing it.
        assert_eq!(check(format!("{}\n", base64_dek()).as_bytes()), Err(KeyFileError::PlaintextKey));
    }

    #[test]
    fn near_misses_of_a_plaintext_key_are_just_too_short() {
        let hex = "ab".repeat(DEK_LEN);
        for text in [
            STANDARD.encode([0x5Au8; DEK_LEN - 1]), // base64, but of 31 bytes
            STANDARD.encode([0x5Au8; DEK_LEN + 1]), // base64, but of 33 bytes
            "!".repeat(BASE64_DEK_LEN),             // 44 bytes, not base64
            hex[1..].to_string(),                   // 63 hex digits
            format!("{}g", &hex[1..]),              // 64 characters, one not hex
            format!("{}\n{}", &hex[..32], &hex[32..]), // hex split by a newline inside
        ] {
            assert_eq!(check(text.as_bytes()), Err(KeyFileError::TooShort), "{text:?}");
        }
        for len in [DEK_LEN - 1, DEK_LEN + 1] {
            assert_eq!(check(&vec![0u8; len]), Err(KeyFileError::TooShort), "{len} raw bytes");
        }
    }

    #[test]
    fn no_valid_payload_can_be_mistaken_for_a_plaintext_key() {
        // Every plaintext form, padding included, is shorter than the
        // smallest payload (asserted at compile time beside
        // MAX_PLAINTEXT_TEXT_LEN). The smallest real payload is accepted as one.
        assert_eq!(check(&payload_with_key_id(0)), Ok(()));
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
    fn group_or_other_writable_file_is_refused_and_read_only_modes_are_accepted() {
        let dir = secure_file::private_tempdir();
        let path = write(dir.path(), "wrapped.key", &valid());
        for mode in [0o600, 0o400, 0o640, 0o644, 0o444] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(read(&path).is_ok(), "mode {mode:o} lets nobody else write; it must be accepted");
        }
        for mode in [0o620, 0o660, 0o602, 0o606, 0o666, 0o622] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(read(&path).err(), Some(KeyFileError::Untrusted), "mode {mode:o} lets someone else replace the key");
        }
    }

    #[test]
    fn symlink_to_a_writable_file_is_refused_on_the_target() {
        let dir = secure_file::private_tempdir();
        let target = write(dir.path(), "wrapped.key", &valid());
        let link = dir.path().join("current.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(read(&link).err(), Some(KeyFileError::Untrusted));
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn writable_directory_holding_the_key_is_refused_but_sticky_is_fine() {
        let base = secure_file::private_tempdir();
        let dir = base.path().join("keys");
        std::fs::create_dir(&dir).unwrap();
        let path = write(&dir, "wrapped.key", &valid());

        chmod(&dir, 0o700);
        assert!(read(&path).is_ok());
        for mode in [0o770, 0o707, 0o777] {
            chmod(&dir, mode);
            assert_eq!(read(&path).err(), Some(KeyFileError::Untrusted), "dir mode {mode:o}: the key could be renamed over");
        }
        // Sticky: only the file's owner (checked) can rename or replace it.
        chmod(&dir, 0o1777);
        assert!(read(&path).is_ok(), "a sticky /tmp-style directory protects an existing, owner-checked file");
        chmod(&dir, 0o700);
    }

    #[test]
    fn writable_ancestor_directory_is_refused() {
        let base = secure_file::private_tempdir();
        let inner = base.path().join("a").join("b");
        std::fs::create_dir_all(&inner).unwrap();
        chmod(&base.path().join("a"), 0o700);
        chmod(&inner, 0o700);
        let path = write(&inner, "wrapped.key", &valid());
        assert!(read(&path).is_ok());

        chmod(&base.path().join("a"), 0o777);
        assert_eq!(read(&path).err(), Some(KeyFileError::Untrusted), "`b` itself could be swapped out");
        chmod(&base.path().join("a"), 0o700);
    }

    #[test]
    fn symlink_into_a_writable_directory_is_refused() {
        let trusted = secure_file::private_tempdir();
        let shared = secure_file::private_tempdir();
        let target = write(shared.path(), "wrapped.key", &valid());
        let link = trusted.path().join("current.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read(&link).is_ok());

        chmod(shared.path(), 0o777);
        assert_eq!(read(&link).err(), Some(KeyFileError::Untrusted), "the file actually read sits where others can replace it");
        chmod(shared.path(), 0o700);
    }

    #[test]
    fn symlink_in_a_writable_directory_is_refused_even_to_a_safe_target() {
        let trusted = secure_file::private_tempdir();
        let shared = secure_file::private_tempdir();
        let target = write(trusted.path(), "wrapped.key", &valid());
        let link = shared.path().join("current.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read(&link).is_ok());

        chmod(shared.path(), 0o777);
        assert_eq!(read(&link).err(), Some(KeyFileError::Untrusted), "others could retarget the link");
        chmod(shared.path(), 0o700);
    }

    #[test]
    fn without_proc_every_check_still_applies() {
        // A sandbox with /proc missing: the opened file is confirmed by
        // device and inode instead, and nothing else changes.
        let no_proc = Path::new("/nonexistent-hkdfguard-proc");
        let trusted = secure_file::private_tempdir();
        let shared = secure_file::private_tempdir();
        let bytes = valid();
        let path = write(trusted.path(), "wrapped.key", &bytes);
        assert_eq!(read_with_proc_root(&path, no_proc).unwrap().as_slice(), &bytes[..]);

        let link = trusted.path().join("current.key");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(read_with_proc_root(&link, no_proc).unwrap().as_slice(), &bytes[..], "symlinks still resolve");

        chmod(&path, 0o666);
        assert_eq!(read_with_proc_root(&path, no_proc).err(), Some(KeyFileError::Untrusted), "file checks");
        chmod(&path, 0o600);

        let elsewhere = write(shared.path(), "wrapped.key", &bytes);
        chmod(shared.path(), 0o777);
        assert_eq!(read_with_proc_root(&elsewhere, no_proc).err(), Some(KeyFileError::Untrusted), "directory checks");
        chmod(shared.path(), 0o700);
    }

    #[test]
    fn a_path_that_resolves_to_a_symlink_loop_is_refused() {
        let dir = secure_file::private_tempdir();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();
        assert!(read(&a).is_err());
    }

    #[test]
    fn file_owned_by_another_user_is_refused() {
        // Only root can create a file owned by someone else, so this proves
        // the owner rule only when the suite runs as root; non-root runs
        // cover the same rule through secure_file's own tests.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = secure_file::private_tempdir();
        let path = write(dir.path(), "wrapped.key", &valid());
        std::os::unix::fs::chown(&path, Some(65534), Some(65534)).unwrap(); // nobody
        assert_eq!(read(&path).err(), Some(KeyFileError::Untrusted));
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
            KeyFileError::Untrusted,
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

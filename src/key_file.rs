//! Reading a wrapped-DEK key file, for `hkdfguard_open_file`.
//!
//! A key file is one wrapped payload exactly as `hkdfguard wrap`
//! (or a caller storing `hkdfguard_wrap_dek`'s output) wrote it: the
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
//! - **Integrity.** The file must be owned by someone the security model
//!   trusts, and must not be writable by anyone else; otherwise
//!   [`KeyFileError::Untrusted`]. Under the production model (the
//!   default) that is root or a deployer, and group write is allowed only
//!   through a deployer group; under the developer model, root or this
//!   process's user, and no group write (see [`crate::security_model`]). A
//!   wrapped DEK is ciphertext, so reading it gains nothing -- but
//!   *replacing* it does: anyone who can write the file and can also wrap
//!   under the service's KEK (on TPM2, any process in the `tss` group that
//!   can read the service's TPM key file; under the developer model, the application
//!   itself) could plant a DEK they know, and `unwrap` would accept it as
//!   genuine. The CLI writes key files `0600` for the same reason.
//!   Symlinks are followed, and the checks apply to the file they resolve
//!   to. The same holds for every directory that decides what the path
//!   names -- each one it passes through, and each one a symlink along the
//!   way lives in, every one up to `/`: owned by someone trusted, and not
//!   writable by anyone else -- **sticky or not, at any level** (see
//!   [`secure_file::resolve_trusted`], the rule every file this crate reads
//!   is held to). Otherwise someone else could rename a file of their
//!   choosing over the key, or retarget a symlink to one. So a key file anywhere under `/tmp`,
//!   `/var/tmp`, `/dev/shm` or any other sticky, world-writable directory
//!   is refused, however private the directories beneath it: a key file
//!   belongs in a directory only its owner (or root) can write to, all the
//!   way up. The one exception is a read-only mount -- a Kubernetes Secret
//!   or ConfigMap volume is `1777` but nobody can write to it. (The OS
//!   itself refusing to open the file -- e.g. `EACCES` -- is the separate
//!   [`KeyFileError::AccessDenied`].)

use crate::crypto::{DEK_LEN, MAX_KEY_ID_LEN, MAX_WRAPPED_LEN, MIN_WRAPPED_LEN, TAG_LEN};
use crate::error::status;
use crate::payload::{Payload, NONCE_LEN, SALT_LEN, VERSION};
use crate::provider::ProviderType;
use crate::secure_file::{self, FileRequirements, PrincipalTrust, SecretBuffer};
use std::io;
use std::path::Path;

/// Why a key file was refused. Each maps to its own C status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFileError {
    /// The file, or a directory in its path, does not exist.
    NotFound,
    /// The OS refused to let the calling process open the file (or search
    /// a directory in its path), e.g. `EACCES`.
    AccessDenied,
    /// The file, or a directory deciding what its path names, is owned by
    /// someone the security model doesn't trust or is writable by someone
    /// else (sticky or not, so anywhere under `/tmp` included) -- or the
    /// file was swapped between being checked and being opened -- so
    /// someone else could have replaced its contents.
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
                "the file or a directory deciding what its path names is owned by someone the security model \
                 doesn't trust, or writable by someone else (sticky /tmp-style directories included), so someone \
                 else could have replaced it"
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

/// Opens `path` and returns its contents once they pass [`check`], with
/// every owner and writer judged by `trust`.
///
/// The same sequence the external-secret provider uses for its secret
/// files (`open_secret_within_mount`):
///
/// 1-2. `path` is resolved once, symlinks and all, to the real file, and
///    every directory a lookup happens in on the way is checked, each up to
///    `/` (see [`secure_file::resolve_trusted`]) -- including the ones the
///    symlinks it follows live in.
/// 3. The *resolved* path is opened read-only with `O_NOFOLLOW`, so a
///    symlink swapped in after step 1 fails the open instead of being
///    followed, and with `O_NONBLOCK` so a FIFO can't hang the call.
///    Anything but a regular file, and any file someone `trust` doesn't
///    accept could have written, is refused on the opened descriptor's own
///    metadata, before a byte is read.
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
pub fn read(path: &Path, trust: &dyn PrincipalTrust) -> Result<SecretBuffer, KeyFileError> {
    read_with_proc_root(path, trust, Path::new("/proc"))
}

// `read`, with where `/proc` is mounted made a parameter so tests can run
// it as though `/proc` were missing.
fn read_with_proc_root(path: &Path, trust: &dyn PrincipalTrust, proc_root: &Path) -> Result<SecretBuffer, KeyFileError> {
    // Owner and mode are judged below, against `trust`, on the opened
    // descriptor's metadata; `open_checked` only opens it safely.
    let req = FileRequirements {
        owner: None,
        forbidden_mode_bits: 0,
        follow_symlinks: false,
        allow_group_read_if_root_owned: false, // group read isn't forbidden here anyway: the file is ciphertext
    };
    let target_real = match secure_file::resolve_trusted(path, trust) {
        Ok(Some(real)) => real,
        Ok(None) => return Err(KeyFileError::NotFound),
        // A trust refusal carries no OS error; anything the OS refused does.
        Err(e) if e.raw_os_error().is_none() => return Err(KeyFileError::Untrusted),
        Err(e) => return Err(open_error(e)),
    };
    let untrusted = |e: io::Error| match e.raw_os_error() {
        Some(libc::ELOOP) => KeyFileError::Untrusted, // became a symlink after it was resolved
        // No OS error behind it: a check on the opened descriptor refused
        // the file, not the kernel.
        None if e.kind() == io::ErrorKind::PermissionDenied => KeyFileError::Untrusted,
        _ => open_error(e),
    };
    let mut file = secure_file::open_checked(&target_real, &req).map_err(untrusted)?;
    let meta = file.metadata().map_err(|_| KeyFileError::Io)?;
    secure_file::check_metadata_trusting(&meta, trust).map_err(untrusted)?;
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
//
// Constant-time in the contents: the only branches are on the length,
// which the file's size already gives away. Every byte is visited twice
// (once to find the text between the surrounding whitespace, once to test
// it against all three alphabets at once) and every decision is mask
// arithmetic, so how long this takes says nothing about where in a
// would-be key the first non-matching byte sits. Nothing is decoded, so
// the key is never reassembled either. The accepted set: whitespace is
// what `trim_ascii` removes (space, tab, LF, FF, CR); hex is 64 digits of
// either case; base64 is 43 characters, or 44 ending in `=`, all in one
// alphabet, whose last character's 2 unused bits are zero -- exactly what
// the base64 crate's STANDARD/URL_SAFE decoders, padded or not, accept as
// 32 bytes. The Windows and macOS builds implement the same steps.
fn looks_like_plaintext_dek(bytes: &[u8]) -> bool {
    if bytes.len() == DEK_LEN {
        return true;
    }
    if bytes.len() > MAX_PLAINTEXT_TEXT_LEN {
        return false;
    }
    ct::looks_like_text_dek(bytes) == 1
}

/// Branch-free byte classification for [`looks_like_plaintext_dek`]. Every
/// function returns 0 or 1 and is straight-line arithmetic on `u32`, with
/// no data-dependent branch or table lookup.
mod ct {
    /// 1 if `a == b`, else 0 (inputs below 2^31).
    fn eq(a: u32, b: u32) -> u32 {
        ((a ^ b).wrapping_sub(1)) >> 31
    }

    /// 1 if `lo <= c <= hi`, else 0 (inputs below 2^31).
    fn in_range(c: u32, lo: u32, hi: u32) -> u32 {
        // Both differences wrap negative exactly when c is inside.
        (((lo.wrapping_sub(1)).wrapping_sub(c) & c.wrapping_sub(hi + 1)) >> 31) & 1
    }

    /// `a` if `cond` is 1, `b` if it is 0.
    fn select(cond: u32, a: u32, b: u32) -> u32 {
        b ^ ((a ^ b) & cond.wrapping_neg())
    }

    fn is_whitespace(c: u32) -> u32 {
        eq(c, 0x20) | eq(c, 0x09) | eq(c, 0x0A) | eq(c, 0x0C) | eq(c, 0x0D)
    }

    fn is_hex(c: u32) -> u32 {
        in_range(c, b'0' as u32, b'9' as u32) | in_range(c, b'a' as u32, b'f' as u32) | in_range(c, b'A' as u32, b'F' as u32)
    }

    /// (member, 6-bit value) of `c` in the base64 alphabet whose 62nd and
    /// 63rd characters are `c62` and `c63`.
    fn base64(c: u32, c62: u8, c63: u8) -> (u32, u32) {
        let upper = in_range(c, b'A' as u32, b'Z' as u32);
        let lower = in_range(c, b'a' as u32, b'z' as u32);
        let digit = in_range(c, b'0' as u32, b'9' as u32);
        let s62 = eq(c, c62 as u32);
        let s63 = eq(c, c63 as u32);
        let value = (c.wrapping_sub(b'A' as u32) & upper.wrapping_neg())
            | (c.wrapping_sub(b'a' as u32 - 26) & lower.wrapping_neg())
            | (c.wrapping_add(52 - b'0' as u32) & digit.wrapping_neg())
            | (62 & s62.wrapping_neg())
            | (63 & s63.wrapping_neg());
        (upper | lower | digit | s62 | s63, value)
    }

    /// 1 if `bytes` (at most `MAX_PLAINTEXT_TEXT_LEN` long) is a DEK as
    /// text with surrounding whitespace, else 0. See
    /// `looks_like_plaintext_dek`.
    pub(super) fn looks_like_text_dek(bytes: &[u8]) -> u32 {
        use super::{BASE64_DEK_LEN, HEX_DEK_LEN};
        const HEX: u32 = HEX_DEK_LEN as u32;
        const PADDED: u32 = BASE64_DEK_LEN as u32;
        // Pass 1: the first and last non-whitespace positions.
        let (mut seen, mut start, mut end) = (0u32, 0u32, 0u32);
        for (i, &b) in bytes.iter().enumerate() {
            let i = i as u32;
            let text = is_whitespace(b as u32) ^ 1;
            start = select(text & (seen ^ 1), i, start);
            end = select(text, i, end);
            seen |= text;
        }
        let text_len = (end.wrapping_sub(start) + 1) & seen.wrapping_neg();

        // Pass 2: every byte between them against every alphabet, plus the
        // values of the last two (the last may be the `=` of padding).
        let (mut hex_ok, mut std_ok, mut url_ok, mut padded) = (1u32, 1u32, 1u32, 0u32);
        let (mut std_last, mut std_prev, mut url_last, mut url_prev) = (0u32, 0u32, 0u32, 0u32);
        for (i, &b) in bytes.iter().enumerate() {
            let (i, c) = (i as u32, b as u32);
            let inside = (in_range(i, start, end) & seen) ^ 1; // 1 outside the text
            let is_end = eq(i, end);
            let is_prev = eq(i.wrapping_add(1), end);
            let pad = is_end & eq(c, b'=' as u32);
            let (std_member, std_value) = base64(c, b'+', b'/');
            let (url_member, url_value) = base64(c, b'-', b'_');
            hex_ok &= is_hex(c) | inside;
            std_ok &= std_member | pad | inside;
            url_ok &= url_member | pad | inside;
            padded |= pad;
            std_last = select(is_end, std_value, std_last);
            std_prev = select(is_prev, std_value, std_prev);
            url_last = select(is_end, url_value, url_last);
            url_prev = select(is_prev, url_value, url_prev);
        }

        // 43 data characters carry 258 bits: the last one's low 2 must be 0.
        let shape = (eq(text_len, PADDED - 1) & (padded ^ 1)) | (eq(text_len, PADDED) & padded);
        let std_canonical = eq(select(padded, std_prev, std_last) & 3, 0);
        let url_canonical = eq(select(padded, url_prev, url_last) & 3, 0);
        let hex = hex_ok & eq(text_len, HEX);
        let base64 = shape & ((std_ok & std_canonical) | (url_ok & url_canonical));
        seen & (hex | base64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use crate::payload::FINGERPRINT_LEN;
    use crate::secure_file::Owner;
    use crate::security_model::Trust;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // Most tests here are about the file and its path, not whose it is: they
    // read under the developer model's rule (root or this user), which
    // `Owner::RootOrCurrentUser` is. The production model's own tests pass a
    // `Trust` explicitly.
    fn read(path: &Path) -> Result<SecretBuffer, KeyFileError> {
        super::read(path, &Owner::RootOrCurrentUser)
    }

    fn read_with_proc_root(path: &Path, proc_root: &Path) -> Result<SecretBuffer, KeyFileError> {
        super::read_with_proc_root(path, &Owner::RootOrCurrentUser, proc_root)
    }

    fn payload_with_key_id(key_id_len: usize) -> Vec<u8> {
        Payload {
            provider_type: ProviderType::ExternalSecret,
            key_type: crate::payload::KeyType::Symmetric256,
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
        for version in [0u8, 2, 3, 0xFF] {
            let mut bytes = valid();
            bytes[0] = version;
            assert_eq!(check(&bytes), Err(KeyFileError::Malformed), "version {version}");
        }
    }

    #[test]
    fn unknown_provider_is_malformed() {
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

    // The decoder-based definition the constant-time detector replaced:
    // trim, then hex, or any of the base64 crate's four engines yielding 32
    // bytes. Kept here as the reference the new code must agree with.
    fn reference_looks_like_plaintext_dek(bytes: &[u8]) -> bool {
        use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
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
                let mut decoded = [0u8; BASE64_DEK_LEN];
                [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
                    .iter()
                    .any(|engine| matches!(engine.decode_slice(text, &mut decoded[..]), Ok(n) if n == DEK_LEN))
            }
            _ => false,
        }
    }

    #[test]
    fn the_constant_time_detector_agrees_with_the_decoders() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut state = 0x9E37_79B9_7F4A_7C15u64; // xorshift: deterministic, no extra dev-dependency
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_= \t\n\x0b\x0c\r!g";
        let mut cases: Vec<Vec<u8>> = Vec::new();
        for _ in 0..20_000 {
            let mut dek = [0u8; DEK_LEN];
            dek.iter_mut().for_each(|b| *b = next() as u8);
            let mut text = match next() % 5 {
                0 => STANDARD.encode(dek).into_bytes(),
                1 => URL_SAFE_NO_PAD.encode(dek).into_bytes(),
                2 => dek.iter().map(|b| format!("{b:02X}")).collect::<String>().into_bytes(),
                3 => (0..(next() % 70) as usize).map(|_| alphabet[(next() as usize) % alphabet.len()]).collect(),
                _ => (0..(next() % 100) as usize).map(|_| next() as u8).collect(),
            };
            // Mutate: flip a character to another from the alphabet, and
            // surround with whitespace, some of the time.
            if !text.is_empty() && next() % 2 == 0 {
                let at = (next() as usize) % text.len();
                text[at] = alphabet[(next() as usize) % alphabet.len()];
            }
            if next() % 3 == 0 {
                let ws = b" \t\n\x0c\r\x0b";
                for _ in 0..next() % 4 {
                    text.insert(0, ws[(next() as usize) % ws.len()]);
                }
                for _ in 0..next() % 4 {
                    text.push(ws[(next() as usize) % ws.len()]);
                }
            }
            cases.push(text);
        }
        let mut positives = 0;
        for case in &cases {
            let want = reference_looks_like_plaintext_dek(case);
            positives += want as usize;
            assert_eq!(looks_like_plaintext_dek(case), want, "{:?}", String::from_utf8_lossy(case));
        }
        assert!(positives > 4_000 && positives < 16_000, "the corpus must exercise both answers ({positives} positive)");
    }

    #[test]
    fn the_detector_s_edge_cases_match_the_windows_build() {
        let b64 = STANDARD.encode([0u8; DEK_LEN]); // "AAAA...A="
        let plain = |s: &str| looks_like_plaintext_dek(s.as_bytes());
        assert!(plain(&format!("{}{b64}{}", " ".repeat(30), "\n".repeat(22))), "96 bytes in all");
        assert!(!plain(&format!("{}{b64}{}", " ".repeat(31), "\n".repeat(22))), "nothing over 96 bytes");
        assert!(!plain(&format!("{}B=", &b64[..42])), "unused trailing bits set");
        assert!(plain(&format!("{}E=", &b64[..42])), "trailing bits zero");
        assert!(plain(&format!("+{}A", &b64[1..42])), "43 characters, standard alphabet");
        assert!(!plain(&format!("+{}-A", &b64[1..41])), "mixed alphabets");
        assert!(!plain(&format!("{}==", &b64[..42])), "\"==\"");
        assert!(!plain(&format!("{b64}=")), "an extra '='");
        assert!(!plain(&format!("\x0b{b64}")), "vertical tab is not trimmed");
        assert!(plain(&format!("\x0c{b64}\x0c")), "form feed is");
        assert!(!plain(""), "empty");
        assert!(!plain(&" ".repeat(50)), "only whitespace");
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
    fn writable_directory_holding_the_key_is_refused_sticky_or_not() {
        let base = secure_file::private_tempdir();
        let dir = base.path().join("keys");
        std::fs::create_dir(&dir).unwrap();
        let path = write(&dir, "wrapped.key", &valid());

        for mode in [0o700, 0o750, 0o755] {
            chmod(&dir, mode);
            assert!(read(&path).is_ok(), "dir mode {mode:o}: nobody else can write");
        }
        for mode in [0o770, 0o707, 0o777] {
            chmod(&dir, mode);
            assert_eq!(read(&path).err(), Some(KeyFileError::Untrusted), "dir mode {mode:o}: the key could be renamed over");
        }
        // Sticky, /tmp-style: not trusted for a key file either.
        for mode in [0o1777, 0o1770, 0o1733] {
            chmod(&dir, mode);
            assert_eq!(read(&path).err(), Some(KeyFileError::Untrusted), "dir mode {mode:o}: a sticky shared directory");
        }
        chmod(&dir, 0o700);
    }

    #[test]
    fn key_under_a_sticky_ancestor_is_refused() {
        // A private 0700 directory inside a /tmp-style one: the layout of
        // `mktemp -d` under /tmp. Refused, however private the directory
        // holding the key.
        let base = secure_file::private_tempdir();
        let shared = base.path().join("shared");
        let private = shared.join("private");
        std::fs::create_dir_all(&private).unwrap();
        chmod(&private, 0o700);
        let path = write(&private, "wrapped.key", &valid());
        chmod(&shared, 0o700);
        assert!(read(&path).is_ok());

        chmod(&shared, 0o1777);
        assert_eq!(read(&path).err(), Some(KeyFileError::Untrusted), "a sticky ancestor is not trusted");
        // Reached through a symlink from a trusted directory: the resolved
        // file's chain is what is read, so still refused.
        let link = base.path().join("current.key");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(read(&link).err(), Some(KeyFileError::Untrusted), "the target sits under a sticky ancestor");
        chmod(&shared, 0o700);
        assert!(read(&link).is_ok());
    }

    #[test]
    fn key_in_the_system_temp_dir_is_refused() {
        // `mktemp -d`'s layout, for real: a 0700 directory under the system
        // temp dir (normally /tmp, 1777). Nothing to show if TMPDIR points
        // somewhere private.
        let dir = tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
        let shared = dir.path().ancestors().skip(1).any(|d| {
            std::fs::metadata(d).map(|m| m.permissions().mode() & 0o022 != 0).unwrap_or(false)
        });
        if !shared {
            eprintln!("skipping: {} has no group/other-writable ancestor", dir.path().display());
            return;
        }
        let path = write(dir.path(), "wrapped.key", &valid());
        assert_eq!(read(&path).err(), Some(KeyFileError::Untrusted));
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
    fn a_symlink_living_in_an_untrusted_directory_is_refused_even_into_a_trusted_one() {
        // The finding: `<untrusted>/link/wrapped.key`, with `link` pointing
        // into a trusted directory. Where the path is named and where it
        // ends up are both trusted, but whoever can write `<untrusted>` can
        // point `link` at any other key file they like.
        let trusted = secure_file::private_tempdir();
        let untrusted = secure_file::private_tempdir();
        let bytes = valid();
        write(trusted.path(), "wrapped.key", &bytes);
        let link = untrusted.path().join("link");
        std::os::unix::fs::symlink(trusted.path(), &link).unwrap();
        let through_link = link.join("wrapped.key");
        assert_eq!(read(&through_link).unwrap().as_slice(), &bytes[..], "fine while the link's directory is private");

        chmod(untrusted.path(), 0o777);
        assert_eq!(read(&through_link).err(), Some(KeyFileError::Untrusted));
        chmod(untrusted.path(), 0o700);

        // And a link further along a chain of them: `<trusted>/hop` ->
        // `<untrusted>/link/wrapped.key`.
        let hop = trusted.path().join("hop.key");
        std::os::unix::fs::symlink(&through_link, &hop).unwrap();
        chmod(untrusted.path(), 0o777);
        assert_eq!(read(&hop).err(), Some(KeyFileError::Untrusted), "every link on the way counts");
        chmod(untrusted.path(), 0o700);
        assert!(read(&hop).is_ok());
    }

    #[test]
    fn dotdot_after_a_symlink_is_resolved_where_the_link_leads() {
        // `<a>/link/../wrapped.key` names `wrapped.key` beside where `link`
        // points, as the kernel resolves it -- not `<a>/wrapped.key`.
        let a = secure_file::private_tempdir();
        let b = secure_file::private_tempdir();
        let inner = b.path().join("inner");
        std::fs::create_dir(&inner).unwrap();
        std::os::unix::fs::symlink(&inner, a.path().join("link")).unwrap();
        let in_b = valid();
        write(b.path(), "wrapped.key", &in_b);
        assert_eq!(read(&a.path().join("link/../wrapped.key")).unwrap().as_slice(), &in_b[..]);
        chmod(b.path(), 0o777);
        assert_eq!(read(&a.path().join("link/../wrapped.key")).err(), Some(KeyFileError::Untrusted), "and checked there");
        chmod(b.path(), 0o700);
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
    #[cfg_attr(miri, ignore = "makes a FIFO, which Miri can't")]
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

    // ---- read(): the production security model ----

    #[test]
    #[cfg_attr(miri, ignore = "needs the passwd database, which Miri can't reach")]
    fn production_refuses_this_user_s_own_key_file_unless_it_is_a_deployer() {
        let (uid, name, _) = Trust::this_user_for_tests();
        if uid == 0 {
            return; // root's files are trusted under every model: nothing to refuse
        }
        let dir = secure_file::private_tempdir();
        let path = write(dir.path(), "wrapped.key", &valid());
        let gid = std::fs::metadata(&path).unwrap().gid();
        assert!(read(&path).is_ok(), "the developer model trusts this user's own file");
        assert_eq!(
            super::read(&path, &Trust::production_for_tests(&[])).err(),
            Some(KeyFileError::Untrusted),
            "production: the application's own account may not persist a key file it would accept"
        );
        let deployer = Trust::production_for_tests(&[(gid.wrapping_add(4242), &[name.as_str()])]);
        assert!(super::read(&path, &deployer).is_ok(), "production: a deployer's file is trusted");
        let someone_else = Trust::production_for_tests(&[(gid.wrapping_add(4242), &["someone-else"])]);
        assert_eq!(super::read(&path, &someone_else).err(), Some(KeyFileError::Untrusted));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs the passwd database, which Miri can't reach")]
    fn production_lets_a_deployer_group_write_the_folder_and_nobody_else() {
        let (uid, name, _) = Trust::this_user_for_tests();
        let base = secure_file::private_tempdir();
        let dir = base.path().join("keys");
        std::fs::create_dir(&dir).unwrap();
        let path = write(&dir, "wrapped.key", &valid());
        let gid = std::fs::metadata(&dir).unwrap().gid();
        let deployers = Trust::production_for_tests(&[(gid, &[name.as_str()])]);
        let other_group = Trust::production_for_tests(&[(gid.wrapping_add(4242), &[name.as_str()])]);

        // `root:hkdfguard-deployers 2775`: deployers share the folder.
        for mode in [0o770, 0o775, 0o2775] {
            chmod(&dir, mode);
            assert!(super::read(&path, &deployers).is_ok(), "dir mode {mode:o}, group a deployer group");
            assert_eq!(super::read(&path, &other_group).err(), Some(KeyFileError::Untrusted), "dir mode {mode:o}, another group");
            if uid != 0 {
                assert_eq!(read(&path).err(), Some(KeyFileError::Untrusted), "dir mode {mode:o}: developer trusts no group");
            }
        }
        // Writable by others is never trusted, deployer group or not.
        for mode in [0o777, 0o1777, 0o757] {
            chmod(&dir, mode);
            assert_eq!(super::read(&path, &deployers).err(), Some(KeyFileError::Untrusted), "dir mode {mode:o}");
        }
        chmod(&dir, 0o700);

        // The same for the file itself.
        chmod(&path, 0o660);
        assert!(super::read(&path, &deployers).is_ok(), "file group-writable by a deployer group");
        assert_eq!(super::read(&path, &other_group).err(), Some(KeyFileError::Untrusted));
        chmod(&path, 0o662);
        assert_eq!(super::read(&path, &deployers).err(), Some(KeyFileError::Untrusted), "file writable by others");
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

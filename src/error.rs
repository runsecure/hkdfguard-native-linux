//! Internal error type and the stable C ABI status codes it maps to.
//!
//! Nothing in [`Error`] ever crosses the ABI boundary directly -- `lib.rs`
//! converts every variant to a plain `i32` via [`Error::status_code`] before
//! returning to the caller, and log messages built from `Error` values are
//! restricted to shapes/lengths/identifiers, never key material.
//!
//! Argument validation (null pointers, wrong DEK length, invalid UTF-8,
//! output buffer sizing) happens directly in `lib.rs` against the raw
//! `status` codes below, before any call into this crate's internal
//! `Result<_, Error>` plumbing -- so `Error` itself only has variants for
//! failures that can occur *after* validation, inside the provider/crypto
//! layer.

use std::fmt; // brings `fmt::Display`/`fmt::Formatter` into scope for the impl below

/// Status codes returned by the public C ABI. Kept in sync with
/// `include/hkdfguard.h` -- if you add a constant here, add it there too
/// (`header_defines_every_status_code` below checks).
///
/// The table is shared by all three platform implementations of this C ABI
/// (Linux, Windows, macOS): the same name always has the same number, and
/// every header defines every code, including ones a given platform never
/// returns. It is laid out in bands -- general (0..-8), policy (-9),
/// payload (-10..-15), KEK (-16..-31), key file (-32..-63) -- followed by
/// one platform-specific band per platform (Windows -64..-79, Linux
/// -80..-95, macOS -96..-111). A platform-band code always refines one
/// common code, so a caller may treat it as that code. Gaps are reserved:
/// a number is never reused for a different meaning.
pub mod status {
    // Each constant below is one possible return value of the exported C
    // functions; all are plain `i32`s so nothing Rust-specific crosses the
    // FFI boundary.

    // ---- General ----
    pub const OK: i32 = 0; // success
    pub const INVALID_ARGUMENT: i32 = -1; // null pointer, wrong DEK length, negative capacity, etc. -- never a service-string problem, see INVALID_SERVICE_NAME
    pub const BUFFER_TOO_SMALL: i32 = -2; // caller's output buffer capacity is smaller than required
    pub const PROVIDER_UNAVAILABLE: i32 = -3; // no KEK provider could be reached at all
    pub const PROVIDER_ERROR: i32 = -4; // a provider was reachable but failed to produce/load a key
    pub const CRYPTO_ERROR: i32 = -5; // a cryptographic operation failed for a reason other than authentication (RNG, hash-to-curve, HKDF, encryption)
    pub const INTERNAL_ERROR: i32 = -6; // an unexpected panic was caught at the FFI boundary
    // -7 is reserved and never returned. A `service` string that isn't
    // valid UTF-8 is one more way for it to be invalid, reported as
    // INVALID_SERVICE_NAME below -- see that constant's comment.
    pub const INVALID_SERVICE_NAME: i32 = -8; // `service` is null, empty, not valid UTF-8, over MAX_SERVICE_LEN bytes, contains a character other than an ASCII letter, digit, or '.', starts with '.', or contains ".." -- one code for every way the service identifier itself can be wrong
    pub const POLICY_INVALID: i32 = -9; // the policy file can't be trusted or used: unparsable, an invalid or contradictory setting, insecure ownership/permissions of it or its directory, or it requires a provider this build lacks

    // ---- Wrapped payload ----
    pub const PAYLOAD_MALFORMED: i32 = -10; // wrapped payload is structurally invalid: truncated, trailing bytes, an unknown provider type, or a field length no wrap produces
    pub const PAYLOAD_AUTH_FAILED: i32 = -11; // AES-GCM authentication failed: tampered payload, wrong service, or wrong KEK
    pub const PAYLOAD_UNSUPPORTED: i32 = -12; // wrapped payload's version is not one this library can parse
    // -13..-15 reserved.

    // ---- KEK ----
    pub const KEK_FINGERPRINT_MISMATCH: i32 = -16; // wrapped payload's embedded KEK fingerprint doesn't match the current KEK's public key
    pub const KEK_NOT_FOUND: i32 = -17; // no persistent KEK exists yet for this service; call hkdfguard_create_kek first
    pub const KEK_ACCESS_DENIED: i32 = -18; // shared-table code: the KEK exists but this process may not use it -- not currently returned on Linux
    pub const KEK_INVALID: i32 = -19; // shared-table code: the KEK exists but is corrupt or has an invalid ACL -- not currently returned on Linux
    pub const PROCESS_HARDENING_FAILED: i32 = -20; // hkdfguard_harden_process could not disable core dumps or ptrace access, or (with REQUIRE_PROTECTED_SIGNATURE) the process can still be debugged by its own user
    // -21..-31 reserved.

    // ---- Key file (hkdfguard_open_file's refusals) ----
    pub const FILE_NOT_FOUND: i32 = -32; // key file, or a directory in its path, does not exist
    pub const FILE_ACCESS_DENIED: i32 = -33; // the OS refused to let this process open the key file (e.g. EACCES)
    pub const FILE_IO: i32 = -34; // key file is not a regular file, or reading it failed
    pub const FILE_TOO_SHORT: i32 = -35; // key file is shorter than a wrapped DEK, or than its own header declares
    pub const FILE_TOO_LONG: i32 = -36; // key file is longer than a wrapped DEK, or than its own header declares
    pub const FILE_PLAINTEXT_KEY: i32 = -37; // key file looks like an UNWRAPPED DEK (32 raw bytes, or its base64 or hex) -- a likely key exposure
    pub const FILE_MALFORMED: i32 = -38; // key file is the right length but not a payload a wrap could have produced
    pub const FILE_UNTRUSTED: i32 = -39; // key file, or a directory deciding what its path names, is owned by another user or writable by group/others (or was swapped mid-open): someone else could have replaced it
    // -40..-63 reserved for future common codes.

    // ---- Platform bands ----
    // Defined here so the table stays complete; none is returned on Linux.
    // Windows -64..-79:
    pub const WIN_GROUP_INVALID: i32 = -64; // refines POLICY_INVALID; Windows only
    // Linux -80..-95: none defined yet.
    // macOS -96..-111, each refining PROVIDER_ERROR; macOS only:
    pub const MAC_ACCESS_CONTROL_CREATION_FAILED: i32 = -96;
    pub const MAC_KEY_GENERATION_FAILED: i32 = -97;
    pub const MAC_KEYCHAIN_WRITE_FAILED: i32 = -98;
    pub const MAC_KEK_VERIFICATION_FAILED: i32 = -99;
    pub const MAC_KEYCHAIN_READ_FAILED: i32 = -100;
}

#[derive(Debug)] // lets `Error` be formatted with `{:?}` in tests/logs
pub enum Error {
    /// No KEK provider is available at all (should only happen if every
    /// optional provider feature is disabled AND ephemeral is disabled).
    NoProviderAvailable, // terminal failure: the provider chain produced nothing usable
    /// A provider was selected but failed to create/load/operate on a KEK
    /// (TPM error, PKCS#11 error, filesystem error, malformed key file...).
    Provider(String), // carries a human-readable description of what went wrong, for logs only
    /// The policy file itself can't be used: it can't be parsed, a setting
    /// is invalid or contradicts another, it (or the directory it lives in)
    /// fails its ownership/permission checks, or it requires a provider
    /// this build lacks. Never a provider's own runtime failure -- that is
    /// `Provider`, even when the provider was configured by policy.
    Policy(String), // carries a human-readable description, for logs only
    /// Soft, expected condition: this provider is reachable in general but
    /// has no key for this particular service, either because it's not
    /// allowed to create one (the external-secret provider, always) or
    /// because creation wasn't requested (every other provider, when asked
    /// to only load an existing key -- see `KekProvider::load_kek`).
    /// Causes the selection chain to fall through quietly rather than
    /// logging a warning.
    KeyNotProvisioned(&'static str), // static message; no allocation needed since it's always a fixed string
    /// A cryptographic operation failed for a reason other than
    /// authentication: the OS RNG, hash-to-curve, HKDF, or encryption.
    /// Payload parsing and AEAD failures have their own variants below.
    Crypto(&'static str), // static message describing which crypto step failed
    /// The wrapped payload is structurally invalid: truncated, trailing
    /// bytes, an unknown provider type, or a field length no wrap produces.
    /// Detected before any key is used.
    Malformed(&'static str), // static message describing which structural check failed
    /// The wrapped payload's version is not one this library can parse.
    Unsupported(&'static str), // static message describing what was unsupported
    /// AES-GCM authentication failed: the payload was tampered with, or
    /// was wrapped for a different service or under a different KEK that
    /// the fingerprint check didn't catch. The decrypted bytes are wiped.
    AuthFailed,
    /// No provider in the (policy-allowed) chain has an existing KEK for
    /// this service. Distinct from `KeyNotProvisioned`, which is the
    /// per-provider decline signal that causes the chain to keep trying the
    /// next provider -- this is the aggregate "the whole chain was walked
    /// and nothing has one" result, surfaced to the caller so they know to
    /// call `hkdfguard_create_kek` first.
    KekNotFound,
    /// The wrapped payload's embedded KEK fingerprint (a SHA-256 hash of
    /// the persistent KEK's public key, appended to every payload -- see
    /// `crypto::kek_fingerprint`) doesn't match the public key of the KEK
    /// `service` currently resolves to: this payload was not wrapped
    /// under the key `unwrap` is about to use. Detected before any
    /// ECDH/AES-GCM is attempted -- unlike `AuthFailed`, this specifically
    /// means "wrong KEK," not "right KEK, but tampered/mismatched data."
    KekFingerprintMismatch,
}

impl Error {
    // Maps each internal error variant to the public status code the FFI
    // layer will actually return to the C caller.
    pub fn status_code(&self) -> i32 {
        match self {
            Error::NoProviderAvailable => status::PROVIDER_UNAVAILABLE, // no provider at all -> PROVIDER_UNAVAILABLE
            Error::Provider(_) => status::PROVIDER_ERROR, // provider-level failure -> PROVIDER_ERROR (message is dropped, never sent over FFI)
            Error::Policy(_) => status::POLICY_INVALID, // the policy file itself is unusable (message is dropped, never sent over FFI)
            Error::KeyNotProvisioned(_) => status::PROVIDER_ERROR, // treated the same as a generic provider error from the caller's perspective
            Error::Crypto(_) => status::CRYPTO_ERROR, // non-authentication crypto failure -> CRYPTO_ERROR
            Error::Malformed(_) => status::PAYLOAD_MALFORMED,
            Error::Unsupported(_) => status::PAYLOAD_UNSUPPORTED,
            Error::AuthFailed => status::PAYLOAD_AUTH_FAILED,
            Error::KekNotFound => status::KEK_NOT_FOUND,
            Error::KekFingerprintMismatch => status::KEK_FINGERPRINT_MISMATCH,
        }
    }
}

impl fmt::Display for Error {
    // Human-readable rendering used only in `log::error!`/`log::warn!`
    // calls -- never returned to the C caller.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoProviderAvailable => write!(f, "no KEK provider is available"), // fixed message, no data to interpolate
            Error::Provider(msg) => write!(f, "provider error: {msg}"), // interpolate the provider's own description
            Error::Policy(msg) => write!(f, "policy error: {msg}"), // interpolate the policy loader's own description
            Error::KeyNotProvisioned(msg) => write!(f, "no key provisioned: {msg}"), // interpolate the static reason string
            Error::Crypto(msg) => write!(f, "cryptographic error: {msg}"), // interpolate the static reason string
            Error::Malformed(msg) => write!(f, "malformed wrapped payload: {msg}"),
            Error::Unsupported(msg) => write!(f, "unsupported wrapped payload: {msg}"),
            Error::AuthFailed => write!(
                f,
                "AES-256-GCM authentication failed (tampered, wrong service, or wrong KEK)"
            ),
            Error::KekNotFound => write!(f, "no KEK exists for this service; call hkdfguard_create_kek first"),
            Error::KekFingerprintMismatch => write!(
                f,
                "wrapped payload's KEK fingerprint does not match the current KEK for this service"
            ),
        }
    }
}

impl std::error::Error for Error {} // opts `Error` into the standard error trait (needed so `{e}` formatting and `?` interop work smoothly)

pub type Result<T> = std::result::Result<T, Error>; // shorthand alias used throughout the crate instead of spelling out `Result<T, Error>`

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_status_codes_match_contract() {
        assert_eq!(
            Error::NoProviderAvailable.status_code(),
            status::PROVIDER_UNAVAILABLE
        );
        assert_eq!(
            Error::Provider("device failure".into()).status_code(),
            status::PROVIDER_ERROR
        );
        assert_eq!(
            Error::Policy("bad selection.mode".into()).status_code(),
            status::POLICY_INVALID
        );
        assert_eq!(
            Error::KeyNotProvisioned("missing file").status_code(),
            status::PROVIDER_ERROR
        );
        assert_eq!(
            Error::Crypto("rng failed").status_code(),
            status::CRYPTO_ERROR
        );
        assert_eq!(
            Error::Malformed("truncated").status_code(),
            status::PAYLOAD_MALFORMED
        );
        assert_eq!(
            Error::Unsupported("version").status_code(),
            status::PAYLOAD_UNSUPPORTED
        );
        assert_eq!(Error::AuthFailed.status_code(), status::PAYLOAD_AUTH_FAILED);
        assert_eq!(Error::KekNotFound.status_code(), status::KEK_NOT_FOUND);
        assert_eq!(
            Error::KekFingerprintMismatch.status_code(),
            status::KEK_FINGERPRINT_MISMATCH
        );
    }

    // Every status constant, with the number the cross-platform table
    // assigns it. Spelled out as literals on purpose: this is the shared
    // contract, so a change to any constant must also change this list.
    const CANONICAL_TABLE: &[(&str, i32, i32)] = &[
        ("OK", status::OK, 0),
        ("INVALID_ARGUMENT", status::INVALID_ARGUMENT, -1),
        ("BUFFER_TOO_SMALL", status::BUFFER_TOO_SMALL, -2),
        ("PROVIDER_UNAVAILABLE", status::PROVIDER_UNAVAILABLE, -3),
        ("PROVIDER_ERROR", status::PROVIDER_ERROR, -4),
        ("CRYPTO_ERROR", status::CRYPTO_ERROR, -5),
        ("INTERNAL_ERROR", status::INTERNAL_ERROR, -6),
        ("INVALID_SERVICE_NAME", status::INVALID_SERVICE_NAME, -8),
        ("POLICY_INVALID", status::POLICY_INVALID, -9),
        ("PAYLOAD_MALFORMED", status::PAYLOAD_MALFORMED, -10),
        ("PAYLOAD_AUTH_FAILED", status::PAYLOAD_AUTH_FAILED, -11),
        ("PAYLOAD_UNSUPPORTED", status::PAYLOAD_UNSUPPORTED, -12),
        ("KEK_FINGERPRINT_MISMATCH", status::KEK_FINGERPRINT_MISMATCH, -16),
        ("KEK_NOT_FOUND", status::KEK_NOT_FOUND, -17),
        ("KEK_ACCESS_DENIED", status::KEK_ACCESS_DENIED, -18),
        ("KEK_INVALID", status::KEK_INVALID, -19),
        ("PROCESS_HARDENING_FAILED", status::PROCESS_HARDENING_FAILED, -20),
        ("FILE_NOT_FOUND", status::FILE_NOT_FOUND, -32),
        ("FILE_ACCESS_DENIED", status::FILE_ACCESS_DENIED, -33),
        ("FILE_IO", status::FILE_IO, -34),
        ("FILE_TOO_SHORT", status::FILE_TOO_SHORT, -35),
        ("FILE_TOO_LONG", status::FILE_TOO_LONG, -36),
        ("FILE_PLAINTEXT_KEY", status::FILE_PLAINTEXT_KEY, -37),
        ("FILE_MALFORMED", status::FILE_MALFORMED, -38),
        ("FILE_UNTRUSTED", status::FILE_UNTRUSTED, -39),
        ("WIN_GROUP_INVALID", status::WIN_GROUP_INVALID, -64),
        ("MAC_ACCESS_CONTROL_CREATION_FAILED", status::MAC_ACCESS_CONTROL_CREATION_FAILED, -96),
        ("MAC_KEY_GENERATION_FAILED", status::MAC_KEY_GENERATION_FAILED, -97),
        ("MAC_KEYCHAIN_WRITE_FAILED", status::MAC_KEYCHAIN_WRITE_FAILED, -98),
        ("MAC_KEK_VERIFICATION_FAILED", status::MAC_KEK_VERIFICATION_FAILED, -99),
        ("MAC_KEYCHAIN_READ_FAILED", status::MAC_KEYCHAIN_READ_FAILED, -100),
    ];

    #[test]
    fn status_constants_match_the_shared_table() {
        for &(name, value, canonical) in CANONICAL_TABLE {
            assert_eq!(value, canonical, "status::{name} must be {canonical} in the cross-platform table");
        }
        let mut values: Vec<i32> = CANONICAL_TABLE.iter().map(|&(_, v, _)| v).collect();
        values.sort();
        values.dedup();
        assert_eq!(values.len(), CANONICAL_TABLE.len(), "every status code must be distinct");
    }

    #[test]
    fn header_defines_every_status_code() {
        // The header is what C callers compile against; a code defined
        // only here would be a number they can't name, and one defined
        // only there would be a number this crate can't return by name.
        let header = include_str!("../include/hkdfguard.h");
        for &(name, value, _) in CANONICAL_TABLE {
            let define = if name == "OK" {
                "#define HKDFGUARD_OK ".to_string()
            } else {
                format!("#define HKDFGUARD_ERR_{name} ")
            };
            let line = header
                .lines()
                .find(|l| l.starts_with(&define))
                .unwrap_or_else(|| panic!("include/hkdfguard.h must define {}", define.trim_start_matches("#define ").trim()));
            let expected = if value == 0 { "0".to_string() } else { format!("({value})") };
            let defined = line[define.len()..].split_whitespace().next().unwrap_or("");
            assert_eq!(defined, expected, "{}: {line}", define.trim());
        }
        // ...and the header defines nothing this table doesn't list.
        let defined_in_header = header
            .lines()
            .filter(|l| l.starts_with("#define HKDFGUARD_ERR_") || l.starts_with("#define HKDFGUARD_OK "))
            .count();
        assert_eq!(defined_in_header, CANONICAL_TABLE.len(), "include/hkdfguard.h defines a status code missing from CANONICAL_TABLE");
    }

    #[test]
    fn error_display_formatting() {
        assert_eq!(
            Error::NoProviderAvailable.to_string(),
            "no KEK provider is available"
        );
        assert_eq!(
            Error::Provider("TPM timeout".into()).to_string(),
            "provider error: TPM timeout"
        );
        assert_eq!(
            Error::Policy("bad mode".into()).to_string(),
            "policy error: bad mode"
        );
        assert_eq!(
            Error::KeyNotProvisioned("not found").to_string(),
            "no key provisioned: not found"
        );
        assert_eq!(
            Error::Crypto("bad MAC").to_string(),
            "cryptographic error: bad MAC"
        );
        assert_eq!(
            Error::Malformed("truncated").to_string(),
            "malformed wrapped payload: truncated"
        );
    }

    #[test]
    fn error_debug_formatting() {
        let err = Error::Provider("io err".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Provider"));
        assert!(dbg.contains("io err"));
    }
}

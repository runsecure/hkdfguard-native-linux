//! The provider-agnostic wrap/unwrap protocol:
//! `HMAC-SHA-256(KEK, SP 800-108 block) -> AES-256-GCM`.
//!
//! Every provider (TPM2, PKCS#11, external secret, ephemeral) implements
//! the same [`crate::provider::KekHandle::prf`] contract, so this module is
//! the *only* place the actual wrap/unwrap algorithm is implemented --
//! providers never see plaintext DEKs or derived keys.
//!
//! ## The construction
//!
//! A service's KEK is a 256-bit HMAC-SHA-256 key held by its provider.
//! Each payload's AES-256-GCM key is one block of the NIST SP 800-108
//! counter-mode KDF with that HMAC as its PRF, computed by the provider:
//!
//! ```text
//! K_wrap  = HMAC(KEK, [1]_32 || "hkdfguard-wrap-v2" || 0x00 || Context || [256]_32)
//! Context = len(service)_16 || service || header
//! ```
//!
//! `header` is every payload field before the ciphertext (see
//! [`crate::payload::Payload::header_bytes`]): version, provider tag,
//! key_id, the per-payload random salt, the nonce and the ciphertext
//! length. One 256-bit block is the whole output, so the provider makes
//! exactly one HMAC call per payload, and no device-side KDF mechanism is
//! needed.
//!
//! **Only this host can create a payload.** Computing `K_wrap` requires
//! the KEK, which never leaves the TPM, HSM or secret file. There is no
//! public value anyone could use instead: an ECIES- or KEM-style scheme,
//! where anyone holding a public key can encrypt to it, would let them mint
//! a payload that unwraps to a DEK of their choosing. DEKs arrive from a
//! build server and are wrapped locally, and a wrapped payload is never
//! meant to be produced or read anywhere else.
//!
//! **Every payload has its own key.** The salt is in `Context`, so a
//! captured `K_wrap` -- from a core dump, swap, a debugger attached by the
//! same uid, or the bus of a discrete TPM -- opens exactly the payload it
//! belongs to. HMAC outputs reveal nothing about the KEK, so it does not
//! help with any other payload or with forging one.
//!
//! **No public-key step.** Nothing here rests on a discrete-logarithm or
//! factoring problem, so a quantum computer gains nothing beyond Grover's
//! square-root speed-up against the 256-bit KEK and AES-256 key. Every
//! function is NIST-approved: HMAC-SHA-256 (FIPS 198-1), the SP 800-108
//! KDF, AES-256-GCM (SP 800-38D). See `docs/why-hmac-prf.md` for the full
//! rationale, and `docs/adr/0001-post-quantum-wrapping-suite.md` for the
//! decision.
//!
//! ## The KEK fingerprint
//!
//! Every payload carries a 32-byte fingerprint of the KEK it was wrapped
//! under: another SP 800-108 block, with its own label and no context,
//!
//! ```text
//! fingerprint = HMAC(KEK, [1]_32 || "hkdfguard-kek-fingerprint-v2" || 0x00 || [256]_32)
//! ```
//!
//! It is the same for every payload a KEK wraps, and public: one fixed PRF
//! output, which says nothing about the KEK. [`unwrap`] compares it with
//! the current KEK's before decrypting, so a payload wrapped under a
//! replaced or rotated KEK fails with a specific error rather than a
//! generic authentication failure -- see
//! [`crate::error::Error::KekFingerprintMismatch`]. Policy pins it for
//! external secrets, and `hkdfguard_kek_fingerprint` reports it. The
//! labels differ and contain no zero byte, so no fingerprint input is ever
//! a wrapping-key input.
//!
//! ## What is bound
//!
//! `K_wrap` is bound to the header and the length-framed service name
//! through `Context`; the AEAD's associated data is
//! [`crate::payload::Payload::authenticated_bytes`] -- the header plus the
//! fingerprint, i.e. every byte of the payload except the ciphertext. That
//! authenticates the `provider_type` tag (so a payload cannot be replayed
//! as another provider's) and the fingerprint. The fingerprint is not in
//! `Context`, which is what lets both PRF blocks go to the provider in one
//! call: `K_wrap` is keyed by the KEK, so it commits to the KEK's identity
//! without it.
//!
//! Memory note: the DEK plaintext is kept in stack-allocated `[u8; DEK_LEN]`
//! buffers for the *entire* wrap/unwrap operation -- we deliberately use
//! `AeadInOut::{encrypt,decrypt}_inout_detached` (in place) instead of the more
//! convenient `Aead::{encrypt,decrypt}`, because the latter allocates a
//! heap `Vec<u8>` internally and, on the decrypt side, that `Vec` would
//! momentarily hold the *decrypted plaintext DEK* on the heap before we
//! could wrap it in `Zeroizing`. The in-place/detached API never touches
//! `alloc` at all for the DEK itself.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::payload::{Payload, FINGERPRINT_LEN, NONCE_LEN, SALT_LEN}; // wire-format struct + its fixed field sizes
use crate::provider::{self, KekHandle, PrfOutput}; // provider selection functions, and the handle the PRF runs on
use aes_gcm::{AeadInOut, Aes256Gcm, Key, KeyInit, Nonce, Tag}; // in-place AEAD trait, concrete cipher, and its key/nonce/tag types (all fixed-size, stack-resident)
use zeroize::{Zeroize, Zeroizing}; // `Zeroize` for explicit scrubbing of stack arrays, `Zeroizing` for auto-scrubbing owned buffers

pub(crate) const TAG_LEN: usize = 16; // AES-GCM's standard 128-bit authentication tag size

// ---------------------------------------------------------------------
// SP 800-108 blocks.
// ---------------------------------------------------------------------

/// SP 800-108 label for a payload's wrapping key.
const WRAP_LABEL: &[u8] = b"hkdfguard-wrap-v2";

/// SP 800-108 label for the KEK fingerprint.
const FINGERPRINT_LABEL: &[u8] = b"hkdfguard-kek-fingerprint-v2";

/// `L`, the KDF's output length in bits: one HMAC-SHA-256 block.
const OUTPUT_BITS: u32 = 256;

/// One SP 800-108 counter-mode block, the input to a single PRF call:
/// `[i]_32 || Label || 0x00 || Context || [L]_32` with `i = 1`, both
/// integers big-endian as the standard specifies.
fn kdf_block(label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut block = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
    block.extend_from_slice(&1u32.to_be_bytes()); // [i]_32: the first and only block
    block.extend_from_slice(label);
    block.push(0x00); // separates Label from Context
    block.extend_from_slice(context);
    block.extend_from_slice(&OUTPUT_BITS.to_be_bytes()); // [L]_32
    block
}

/// The fingerprint's PRF input: the same for every KEK and every payload.
fn fingerprint_block() -> Vec<u8> {
    kdf_block(FINGERPRINT_LABEL, &[])
}

/// A payload's wrapping-key PRF input. The length prefix keeps the
/// concatenation unambiguous, so no two distinct (service, header) pairs
/// produce the same block. Public, so a heap `Vec` is fine.
fn wrap_block(service: &str, header: &[u8]) -> Vec<u8> {
    let mut context = Vec::with_capacity(2 + service.len() + header.len());
    context.extend_from_slice(&(service.len() as u16).to_le_bytes()); // unambiguous framing for the variable-length service name
    context.extend_from_slice(service.as_bytes());
    context.extend_from_slice(header);
    kdf_block(WRAP_LABEL, &context)
}

pub const DEK_LEN: usize = 32; // the mandated, fixed DEK size in bytes

/// Longest `key_id` any provider may record in a payload. Every provider's
/// tag is either a fixed-size hash (TPM2: 32 bytes) or a short prefix plus
/// the service name (at most [`crate::MAX_SERVICE_LEN`] bytes); `wrap`
/// refuses anything longer, so the payload size bound below always holds.
pub const MAX_KEY_ID_LEN: usize = 16 + crate::MAX_SERVICE_LEN;

/// Longest header a payload can have: version, provider tag, key_id length,
/// the longest key_id, salt, nonce and ciphertext length.
const MAX_HEADER_LEN: usize = 1 + 1 + 2 + MAX_KEY_ID_LEN + SALT_LEN + NONCE_LEN + 4;

/// Longest PRF input a provider is ever given: the wrapping-key block for
/// the longest service name and header. Every provider must accept it; a
/// TPM takes at most `TPM2_PT_INPUT_BUFFER` bytes per `TPM2_HMAC`, which
/// the PC Client profile puts at 1024.
pub const MAX_PRF_INPUT_LEN: usize = 4 + WRAP_LABEL.len() + 1 + 2 + crate::MAX_SERVICE_LEN + MAX_HEADER_LEN + 4;
const _: () = assert!(MAX_PRF_INPUT_LEN <= 1024, "a PRF input must fit one TPM2_HMAC command");
const _: () = assert!(FINGERPRINT_LABEL.len() + 9 <= MAX_PRF_INPUT_LEN);

/// Size of every wrapped payload apart from its `key_id`: version,
/// provider tag, key_id length, salt, nonce, ciphertext length, the
/// ciphertext with its tag, and the fingerprint.
const FIXED_WRAPPED_LEN: usize = 1 + 1 + 2 + SALT_LEN + NONCE_LEN + 4 + DEK_LEN + TAG_LEN + FINGERPRINT_LEN;

/// Smallest possible wrapped payload (an empty `key_id`). A caller capacity
/// below this cannot hold any payload, so `hkdfguard_wrap_dek` answers it
/// without touching a provider.
pub const MIN_WRAPPED_LEN: usize = FIXED_WRAPPED_LEN;

/// Largest possible wrapped payload, for any provider and any valid service
/// name. Mirrored as `HKDFGUARD_WRAPPED_MAX_LEN` in `include/hkdfguard.h`.
pub const MAX_WRAPPED_LEN: usize = FIXED_WRAPPED_LEN + MAX_KEY_ID_LEN;

/// The KEK fingerprint and a payload's wrapping key, from one PRF call to
/// the provider (see the module doc).
fn derive_keys(handle: &dyn KekHandle, service: &str, header: &[u8]) -> Result<([u8; FINGERPRINT_LEN], PrfOutput)> {
    let fingerprint_input = fingerprint_block();
    let wrap_input = wrap_block(service, header);
    let mut outputs = handle.prf(&[&fingerprint_input, &wrap_input])?;
    let (Some(wrapping_key), Some(fingerprint), None) = (outputs.pop(), outputs.pop(), outputs.pop()) else {
        return Err(Error::Provider("the KEK returned the wrong number of PRF outputs".into()));
    };
    Ok((*fingerprint, wrapping_key))
}

/// This KEK's fingerprint (see the module doc): what every payload it
/// wraps carries, what `hkdfguard_kek_fingerprint` reports, and what
/// policy pins for an external secret. Public, so returned unwrapped.
pub(crate) fn kek_fingerprint(handle: &dyn KekHandle) -> Result<[u8; FINGERPRINT_LEN]> {
    let mut outputs = handle.prf(&[&fingerprint_block()])?;
    match (outputs.pop(), outputs.pop()) {
        (Some(fingerprint), None) => Ok(*fingerprint),
        _ => Err(Error::Provider("the KEK returned the wrong number of PRF outputs".into())),
    }
}

/// The fingerprint of a KEK held in software, for a provider checking a
/// key before it hands out a handle (external-secret pins).
#[cfg(any(feature = "external-secret", test))]
pub(crate) fn software_kek_fingerprint(key: &[u8; provider::KEK_LEN]) -> [u8; FINGERPRINT_LEN] {
    *provider::software_prf(key, &[&fingerprint_block()])[0]
}

// Wraps `dek` under the persistent KEK for `service`, returning the
// serialized wrapped payload ready to store/transmit. The KEK must already
// exist (created via `provider::create_kek`, i.e. `hkdfguard_create_kek`);
// this never creates one itself -- see `provider::select_existing`.
pub fn wrap(service: &str, dek: &[u8; DEK_LEN]) -> Result<Vec<u8>> {
    let (provider, handle) = provider::select_existing(service)?; // walk the priority chain for an already-created KEK
    if handle.key_id().len() > MAX_KEY_ID_LEN {
        // Keeps MAX_WRAPPED_LEN (which callers size buffers from) true.
        return Err(Error::Provider(format!(
            "{} key_id is {} bytes, over the {MAX_KEY_ID_LEN}-byte wire-format bound",
            provider.provider_type().as_str(),
            handle.key_id().len()
        )));
    }

    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| Error::Crypto("the OS random number generator failed"))?; // per-payload salt: makes this payload's wrapping key its own
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| Error::Crypto("the OS random number generator failed"))?; // fresh random nonce for this one AES-GCM encryption

    // Build the payload up front, with the ciphertext buffer already at
    // its final size, so the header covers the real declared ciphertext
    // length. The wrapping key and the AEAD's associated data both have to
    // be fixed before encryption, and the ciphertext is always exactly
    // DEK_LEN + TAG_LEN, so there is no chicken-and-egg problem here.
    let mut payload = Payload {
        provider_type: provider.provider_type(), // records which provider produced this KEK, for `unwrap` to use later
        key_id: handle.key_id().to_vec(),        // provider's diagnostic tag
        salt,
        nonce: nonce_bytes,
        ciphertext: vec![0u8; DEK_LEN + TAG_LEN], // placeholder, filled in below
        fingerprint: [0u8; FINGERPRINT_LEN],      // filled in below, from the same PRF call as the wrapping key
    };
    salt.zeroize(); // already copied into the payload; don't leave a second copy on the stack

    let (fingerprint, mut wrapping_key) = derive_keys(&*handle, service, &payload.header_bytes())?; // only the KEK's holder can compute these (already stack-only: see `provider::PrfOutput`)
    payload.fingerprint = fingerprint; // identifies *which* KEK this payload is wrapped under, for `unwrap` to check before decrypting
    // Every non-ciphertext byte of the payload, as the AEAD's associated
    // data -- see `Payload::authenticated_bytes`. This is what
    // authenticates `provider_type` (so a payload can't be replayed as
    // another provider's) and the fingerprint.
    let authenticated = payload.authenticated_bytes();

    let cipher = Aes256Gcm::new(aes_key(&wrapping_key)); // set up AES-256-GCM with the derived key

    // Copy the DEK onto the stack (a plain array-to-array copy, no heap
    // involved) and encrypt it in place: `ct_buf` starts as plaintext and
    // ends as ciphertext, entirely within this stack frame. `Zeroizing`, so
    // the plaintext is scrubbed even if something below panics before the
    // encryption completes.
    let mut ct_buf = Zeroizing::new(*dek);
    let tag_result = cipher.encrypt_inout_detached(&Nonce::from(nonce_bytes), &authenticated, (&mut ct_buf[..]).into());
    wrapping_key.zeroize(); // the derived AES key is no longer needed either way; scrub it immediately

    let tag: Tag = match tag_result {
        Ok(tag) => tag,
        Err(_) => {
            // A failed in-place encryption leaves `ct_buf` in no known
            // state -- possibly still the plaintext DEK. Scrub it before
            // returning, like every other copy of key material here.
            ct_buf.zeroize();
            return Err(Error::Crypto("AES-256-GCM encryption failed"));
        }
    };
    // `ct_buf` now holds ciphertext, not plaintext -- safe to copy into the
    // (necessarily heap-backed, since it's variable-length) wire payload.
    payload.ciphertext.clear();
    payload.ciphertext.extend_from_slice(&ct_buf[..]);
    payload.ciphertext.extend_from_slice(&tag);
    debug_assert_eq!(
        payload.authenticated_bytes(),
        authenticated,
        "the authenticated bytes must not change once the ciphertext is filled in"
    );

    Ok(payload.to_bytes()) // serialize to the final wire format
}

// Reverses `wrap`: parses the payload, re-derives the same wrapping key,
// and decrypts+authenticates the original DEK back out. The recovered DEK
// lives only in the stack-allocated, self-zeroizing array returned to the
// caller -- never in a heap buffer at any point, and never in a buffer
// that a panic could leave un-wiped.
pub fn unwrap(service: &str, wrapped: &[u8]) -> Result<Zeroizing<[u8; DEK_LEN]>> {
    let payload = Payload::from_bytes(wrapped)?; // parse and structurally validate the wire format (ciphertext stays a heap Vec, but it's ciphertext, not a secret)

    if payload.ciphertext.len() != DEK_LEN + TAG_LEN {
        return Err(Error::Malformed("wrapped ciphertext has unexpected length")); // malformed/tampered length; bail out before touching any crypto
    }

    let provider = provider::get_by_type(payload.provider_type)?; // must use the exact provider that originally wrapped this DEK
    let handle = provider.load_kek(service, false)?; // load (never create) that provider's KEK for this service

    // Re-derive the same wrapping key from the same header, and the
    // current KEK's fingerprint, in one PRF call.
    let (current_fingerprint, mut wrapping_key) = derive_keys(&*handle, service, &payload.header_bytes())?;

    // Before decrypting, check that this payload was actually wrapped
    // under the KEK `service` resolves to *right now* -- catches a
    // rotated/replaced/wrong KEK with a specific, unambiguous error instead
    // of collapsing into a generic AEAD authentication failure
    // indistinguishable from tampering (see `Error::KekFingerprintMismatch`).
    if current_fingerprint != payload.fingerprint {
        wrapping_key.zeroize();
        return Err(Error::KekFingerprintMismatch);
    }

    // Must exactly mirror what `wrap` bound: every non-ciphertext byte of
    // the payload. Derived from the parsed payload, so any tampered
    // header byte changes both the derived key and the AEAD's associated
    // data -- the decryption below then fails authentication.
    let authenticated = payload.authenticated_bytes();

    // Split the wire ciphertext (still just ciphertext bytes, not secret)
    // into its AES-GCM ciphertext body and trailing tag, then copy the
    // body onto the stack -- this is the *only* place the decrypted DEK
    // will ever live.
    let (ct_part, tag_part) = payload.ciphertext.split_at(DEK_LEN);
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    dek.copy_from_slice(ct_part); // still ciphertext at this point
    let tag = Tag::try_from(tag_part).map_err(|_| Error::Malformed("wrapped ciphertext has unexpected length"))?;

    let cipher = Aes256Gcm::new(aes_key(&wrapping_key));
    let auth_result =
        cipher.decrypt_inout_detached(&Nonce::from(payload.nonce), &authenticated, (&mut dek[..]).into(), &tag); // decrypts `dek` in place; on success it now holds the real plaintext DEK
    wrapping_key.zeroize(); // the AES key is no longer needed regardless of whether decryption succeeded

    if auth_result.is_err() {
        // Authentication failed: `dek` may now contain unauthenticated
        // (attacker-influenced or simply garbage) bytes from the in-place
        // decryption -- scrub it before returning rather than ever
        // handing it back to the caller.
        dek.zeroize();
        return Err(Error::AuthFailed); // tampered, wrong service, or wrong KEK -- PAYLOAD_AUTH_FAILED, not CRYPTO_ERROR
    }

    Ok(dek) // genuine plaintext DEK, stack-resident from decryption through to the caller
}

// The derived key as the cipher's key type, by reference: no unwiped copy
// of the key is made on the way in.
fn aes_key(key: &PrfOutput) -> &Key<Aes256Gcm> {
    (&key[..]).try_into().expect("an AES-256 key is 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*; // bring `wrap`, `unwrap`, `DEK_LEN`, etc. into scope
    use serial_test::serial; // these tests mutate shared env vars, so they must run one at a time

    // Disables the external-secret provider and writes a policy that
    // explicitly opts Ephemeral in, so every test in this module
    // deterministically exercises the Ephemeral provider. Without that
    // policy Ephemeral is never used (see `provider::allowed_chain`).
    fn with_isolated_ephemeral_provider<F: FnOnce()>(f: F) {
        let _policy = crate::policy::allow_ephemeral_policy_for_tests();
        f();
    }

    #[test]
    #[serial]
    fn round_trips_through_ephemeral_provider() {
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap(); // wrap never creates -- provision the KEK first
            let dek = [0x42u8; DEK_LEN]; // arbitrary fixed test DEK
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let recovered = unwrap("com.company.orders", &wrapped).unwrap();
            assert_eq!(dek, *recovered); // must get back exactly what was wrapped
        });
    }

    #[test]
    #[serial]
    fn wrap_fails_until_create_kek_is_called() {
        with_isolated_ephemeral_provider(|| {
            let dek = [0x55u8; DEK_LEN];
            let err = wrap("com.company.never-created", &dek).unwrap_err();
            assert!(matches!(err, Error::KekNotFound));

            crate::provider::create_kek("com.company.never-created").unwrap();
            wrap("com.company.never-created", &dek).unwrap(); // now succeeds
        });
    }

    #[test]
    #[serial]
    fn wrong_service_fails_to_unwrap() {
        with_isolated_ephemeral_provider(|| {
            // Both services' KEKs must already exist: unwrap only ever
            // loads (never creates) the KEK for the service it's given, so
            // for this test to actually exercise the fingerprint mismatch
            // (rather than just "billing has no KEK yet"), billing needs a
            // real, distinct KEK of its own.
            crate::provider::create_kek("com.company.orders").unwrap();
            crate::provider::create_kek("com.company.billing").unwrap();
            let dek = [0x11u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let err = unwrap("com.company.billing", &wrapped).unwrap_err(); // deliberately wrong service name
            // Caught by the fingerprint check, before AEAD is even
            // attempted: billing's KEK is a different key from orders', so
            // its fingerprint can't match the payload's.
            assert!(matches!(err, Error::KekFingerprintMismatch));
        });
    }

    #[test]
    #[serial]
    fn tampered_ciphertext_fails_to_unwrap() {
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let dek = [0x99u8; DEK_LEN];
            let mut wrapped = wrap("com.company.orders", &dek).unwrap();
            // The wire format's last FINGERPRINT_LEN bytes are the KEK
            // fingerprint, not ciphertext -- flip the last byte actually
            // inside the ciphertext/tag region (right before that
            // trailer), so this still specifically exercises AEAD's own
            // tamper detection rather than the (unrelated) fingerprint check.
            let last_ciphertext_byte = wrapped.len() - FINGERPRINT_LEN - 1;
            wrapped[last_ciphertext_byte] ^= 0x01; // flip one bit in the ciphertext/tag
            let err = unwrap("com.company.orders", &wrapped).unwrap_err();
            assert!(matches!(err, Error::AuthFailed)); // AEAD authentication must catch the tamper
        });
    }

    #[test]
    #[serial]
    fn truncated_ciphertext_fails_to_unwrap() {
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let dek = [0x22u8; DEK_LEN];
            let mut wrapped = wrap("com.company.orders", &dek).unwrap();
            wrapped.truncate(wrapped.len() - 5); // chop bytes out of the ciphertext/tag region
            let err = unwrap("com.company.orders", &wrapped).unwrap_err();
            assert!(matches!(err, Error::Malformed(_))); // must be rejected by the explicit length check, not panic in `split_at`
        });
    }

    #[test]
    #[serial]
    fn same_dek_wrapped_twice_yields_different_ciphertexts() {
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let dek = [0x77u8; DEK_LEN];
            let a = wrap("com.company.orders", &dek).unwrap();
            let b = wrap("com.company.orders", &dek).unwrap(); // same DEK, same service, wrapped again
            assert_ne!(a, b, "random salt + random nonce must randomize output"); // must not be deterministic
        });
    }

    // ---- the SP 800-108 blocks ----

    #[test]
    fn kdf_block_is_the_sp800_108_counter_mode_layout() {
        // [i]_32 || Label || 0x00 || Context || [L]_32, big-endian, i = 1, L = 256.
        let block = kdf_block(b"LBL", b"ctx");
        assert_eq!(block, [&[0, 0, 0, 1][..], b"LBL", &[0], b"ctx", &[0, 0, 1, 0]].concat());
        assert_eq!(
            fingerprint_block(),
            [&[0, 0, 0, 1][..], b"hkdfguard-kek-fingerprint-v2", &[0], &[0, 0, 1, 0]].concat(),
            "the fingerprint block has no context"
        );
    }

    // A payload with distinctive, easily-perturbed field values.
    fn sample_payload() -> Payload {
        Payload {
            provider_type: crate::provider::ProviderType::Ephemeral,
            key_id: b"key-id".to_vec(),
            salt: [0x11u8; SALT_LEN],
            nonce: [0x22u8; NONCE_LEN],
            ciphertext: vec![0x33u8; DEK_LEN + TAG_LEN],
            fingerprint: [0x44u8; FINGERPRINT_LEN],
        }
    }

    #[test]
    fn the_wrap_block_binds_the_service_and_every_header_byte() {
        let header = sample_payload().header_bytes();
        let base = wrap_block("service.a", &header);
        assert_eq!(base, wrap_block("service.a", &header), "must be deterministic for identical inputs");
        assert_ne!(base, wrap_block("service.b", &header), "the service name must change the block");

        // Every header byte -- version, provider tag, key_id, the salt
        // (the per-payload separation), nonce and ciphertext length --
        // must reach the KDF input.
        for i in 0..header.len() {
            let mut tampered = header.clone();
            tampered[i] ^= 0x01;
            assert_ne!(base, wrap_block("service.a", &tampered), "flipping header byte {i} must change the block");
        }
    }

    #[test]
    fn the_wrap_block_excludes_the_fingerprint_and_ciphertext() {
        // Both come from the provider (or the AEAD) in the same call, so
        // they cannot be inputs to it; the AEAD's associated data covers
        // the fingerprint instead.
        let payload = sample_payload();
        let other = Payload { fingerprint: [0x55; FINGERPRINT_LEN], ciphertext: vec![0x66; DEK_LEN + TAG_LEN], ..sample_payload() };
        assert_eq!(payload.header_bytes(), other.header_bytes());
        assert_ne!(payload.authenticated_bytes(), other.authenticated_bytes());
    }

    #[test]
    fn service_name_framing_is_unambiguous() {
        // The length prefix on the service name is what stops two
        // different (service, header) pairs from concatenating to the same
        // context. Without it, ("ab", <header starting c>) and ("abc",
        // <header>) could collide.
        assert_ne!(wrap_block("ab", b"cXYZ"), wrap_block("abc", b"XYZ"), "service/header boundary must not be ambiguous");
    }

    #[test]
    fn no_wrap_block_is_ever_the_fingerprint_block() {
        // The labels differ in their first byte after the shared prefix,
        // and neither contains a zero byte, so the two kinds of input
        // cannot coincide whatever the context.
        assert!(!WRAP_LABEL.contains(&0) && !FINGERPRINT_LABEL.contains(&0));
        let fingerprint_input = fingerprint_block();
        for service in ["", "a", "com.company.orders"] {
            assert_ne!(wrap_block(service, b""), fingerprint_input);
            assert_ne!(wrap_block(service, &sample_payload().header_bytes()), fingerprint_input);
        }
    }

    #[test]
    fn max_prf_input_len_is_the_longest_wrap_block() {
        let service = "s".repeat(crate::MAX_SERVICE_LEN);
        let payload = Payload { key_id: vec![0x4b; MAX_KEY_ID_LEN], ..sample_payload() };
        assert_eq!(wrap_block(&service, &payload.header_bytes()).len(), MAX_PRF_INPUT_LEN);
        assert!(fingerprint_block().len() < MAX_PRF_INPUT_LEN);
    }

    /// A KEK that records every PRF input it is given.
    struct RecordingKek {
        key: [u8; crate::provider::KEK_LEN],
        seen: std::cell::RefCell<Vec<Vec<Vec<u8>>>>,
    }

    impl KekHandle for RecordingKek {
        fn key_id(&self) -> &[u8] {
            b"recording"
        }

        fn prf(&self, inputs: &[&[u8]]) -> Result<Vec<PrfOutput>> {
            self.seen.borrow_mut().push(inputs.iter().map(|i| i.to_vec()).collect());
            Ok(crate::provider::software_prf(&self.key, inputs))
        }
    }

    #[test]
    fn one_prf_call_yields_the_fingerprint_and_the_wrapping_key() {
        let kek = RecordingKek { key: [0x2a; 32], seen: Default::default() };
        let header = sample_payload().header_bytes();
        let (fingerprint, wrapping_key) = derive_keys(&kek, "service.a", &header).unwrap();

        let calls = kek.seen.borrow().clone();
        assert_eq!(calls.len(), 1, "one device session per wrap or unwrap");
        assert_eq!(calls[0], vec![fingerprint_block(), wrap_block("service.a", &header)]);
        assert_eq!(fingerprint, *crate::provider::software_prf(&kek.key, &[&fingerprint_block()])[0]);
        assert_eq!(*wrapping_key, *crate::provider::software_prf(&kek.key, &[&wrap_block("service.a", &header)])[0]);
        assert_eq!(kek_fingerprint(&kek).unwrap(), fingerprint, "the standalone fingerprint is the same value");
        assert_eq!(software_kek_fingerprint(&kek.key), fingerprint);
    }

    #[test]
    fn a_kek_returning_the_wrong_number_of_outputs_is_an_error() {
        struct Short;
        impl KekHandle for Short {
            fn key_id(&self) -> &[u8] {
                b""
            }
            fn prf(&self, _inputs: &[&[u8]]) -> Result<Vec<PrfOutput>> {
                Ok(vec![PrfOutput::new([0; 32])])
            }
        }
        assert!(derive_keys(&Short, "s", b"h").is_err());
    }

    #[test]
    fn kek_fingerprint_properties() {
        let key1 = crate::provider::random_kek_for_tests();
        let key2 = crate::provider::random_kek_for_tests();
        let f1 = software_kek_fingerprint(&key1);
        assert_eq!(f1, software_kek_fingerprint(&key1), "must be deterministic for the same KEK");
        assert_ne!(f1, software_kek_fingerprint(&key2), "different KEKs must yield different fingerprints");
    }

    // ---- what a KEK holder, and only a KEK holder, can do ----

    #[test]
    #[serial]
    fn a_captured_wrapping_key_opens_only_its_own_payload() {
        // The reason the salt is in the KDF context. Assume the worst: an
        // attacker captured one payload's wrapping key (core dump, swap,
        // discrete-TPM bus). It must be useless against any other payload
        // for the same service.
        with_isolated_ephemeral_provider(|| {
            let service = "com.company.capture";
            crate::provider::create_kek(service).unwrap();
            let dek_a = [0xA1u8; DEK_LEN];
            let dek_b = [0xB2u8; DEK_LEN];
            let payload_a = Payload::from_bytes(&wrap(service, &dek_a).unwrap()).unwrap();
            let payload_b = Payload::from_bytes(&wrap(service, &dek_b).unwrap()).unwrap();

            let (_provider, handle) = crate::provider::select_existing(service).unwrap();
            let (_, key_a) = derive_keys(&*handle, service, &payload_a.header_bytes()).unwrap();
            let (_, key_b) = derive_keys(&*handle, service, &payload_b.header_bytes()).unwrap();
            assert_ne!(*key_a, *key_b, "two payloads for one service must not share a wrapping key");

            // Key A genuinely opens payload A (so the capture is "real")...
            let open = |key: &PrfOutput, p: &Payload| -> std::result::Result<[u8; DEK_LEN], ()> {
                let aad = p.authenticated_bytes();
                let cipher = Aes256Gcm::new_from_slice(&key[..]).unwrap();
                let (ct, tag) = p.ciphertext.split_at(DEK_LEN);
                let mut buf = [0u8; DEK_LEN];
                buf.copy_from_slice(ct);
                cipher
                    .decrypt_inout_detached(&Nonce::try_from(&p.nonce[..]).unwrap(), &aad, (&mut buf[..]).into(), &Tag::try_from(tag).unwrap())
                    .map(|_| buf)
                    .map_err(|_| ())
            };
            assert_eq!(open(&key_a, &payload_a).unwrap(), dek_a);

            // ...and does nothing for payload B, even with B's public
            // salt, nonce, and header all in hand.
            assert!(open(&key_a, &payload_b).is_err(), "a captured wrapping key must not open a different payload");
        });
    }

    #[test]
    #[serial]
    fn without_the_kek_a_payload_cannot_be_forged() {
        // Everything public about a service -- the wire format, a genuine
        // payload's header and fingerprint -- is not enough: the wrapping
        // key is an HMAC under the KEK. A payload built under any other
        // key, with every header byte well-formed and the correct
        // fingerprint, fails authentication.
        with_isolated_ephemeral_provider(|| {
            let service = "com.company.forgery";
            crate::provider::create_kek(service).unwrap();
            let genuine = wrap(service, &[0x01u8; DEK_LEN]).unwrap();
            let payload = Payload::from_bytes(&genuine).unwrap();

            // The attacker's best attempt: the documented KDF, under a key
            // of their own.
            let attacker_key = crate::provider::random_kek_for_tests();
            let forged_key = crate::provider::software_prf(&attacker_key, &[&wrap_block(service, &payload.header_bytes())])
                .pop()
                .unwrap();
            let authenticated = payload.authenticated_bytes();
            let mut ct_buf = [0xEEu8; DEK_LEN];
            let tag = Aes256Gcm::new_from_slice(&forged_key[..])
                .unwrap()
                .encrypt_inout_detached(&Nonce::try_from(&payload.nonce[..]).unwrap(), &authenticated, (&mut ct_buf[..]).into())
                .unwrap();
            let forged = Payload { ciphertext: [&ct_buf[..], &tag[..]].concat(), ..Payload::from_bytes(&genuine).unwrap() };

            let err = unwrap(service, &forged.to_bytes()).unwrap_err();
            assert!(matches!(err, Error::AuthFailed), "a forged payload must fail AEAD authentication, got {err:?}");

            // The genuine payload still works, so the test isn't passing
            // for an unrelated reason.
            assert_eq!(*unwrap(service, &genuine).unwrap(), [0x01u8; DEK_LEN]);
        });
    }

    #[test]
    #[serial]
    fn tampering_with_the_wire_fingerprint_bytes_breaks_aead_authentication_directly() {
        // `unwrap`'s own fingerprint pre-check already rejects a tampered
        // fingerprint before AES-GCM is ever attempted, so going through
        // the public API can't observe AEAD's own tamper detection in
        // isolation. This test instead re-derives the same wrapping key
        // `wrap` used and decrypts directly with `Aes256Gcm`, to prove
        // independently that AAD including the fingerprint is what's
        // actually protecting those bytes cryptographically -- the
        // fingerprint is not in the KDF context, so the AAD is the only
        // thing that binds it.
        with_isolated_ephemeral_provider(|| {
            let service = "com.company.aadtest";
            crate::provider::create_kek(service).unwrap();
            let dek = [0x66u8; DEK_LEN];
            let wrapped = wrap(service, &dek).unwrap();
            let payload = Payload::from_bytes(&wrapped).unwrap();

            let (_provider, handle) = crate::provider::select_existing(service).unwrap();
            let (_, wrapping_key) = derive_keys(&*handle, service, &payload.header_bytes()).unwrap();
            let correct_aad = payload.authenticated_bytes();

            let (ct_part, tag_part) = payload.ciphertext.split_at(DEK_LEN);
            let tag = &Tag::try_from(tag_part).unwrap();
            let cipher = Aes256Gcm::new_from_slice(&wrapping_key[..]).unwrap();

            // Decrypting with the exact original AAD must succeed --
            // establishes this is a faithful re-derivation, not a setup bug.
            let mut buf = [0u8; DEK_LEN];
            buf.copy_from_slice(ct_part);
            assert!(cipher.decrypt_inout_detached(&Nonce::try_from(&payload.nonce[..]).unwrap(), &correct_aad, (&mut buf[..]).into(), tag).is_ok());
            assert_eq!(buf, dek);

            // A single bit flipped in *only* the fingerprint half of the
            // AAD (the ciphertext, tag, and nonce are all untouched) must
            // make AES-GCM itself refuse to authenticate.
            let mut tampered_fingerprint_aad = correct_aad.clone();
            *tampered_fingerprint_aad.last_mut().unwrap() ^= 0x01;
            let mut buf = [0u8; DEK_LEN];
            buf.copy_from_slice(ct_part);
            assert!(
                cipher.decrypt_inout_detached(&Nonce::try_from(&payload.nonce[..]).unwrap(), &tampered_fingerprint_aad, (&mut buf[..]).into(), tag).is_err(),
                "AES-GCM must reject a payload whose fingerprint-half AAD bytes were altered"
            );

            // Same for the provider_type tag, which is byte 1 of the
            // header. This byte steers which provider unwraps the payload,
            // so if it were unauthenticated it would be attacker-malleable.
            let mut tampered_provider_aad = correct_aad.clone();
            tampered_provider_aad[1] ^= 0x01;
            let mut buf = [0u8; DEK_LEN];
            buf.copy_from_slice(ct_part);
            assert!(
                cipher.decrypt_inout_detached(&Nonce::try_from(&payload.nonce[..]).unwrap(), &tampered_provider_aad, (&mut buf[..]).into(), tag).is_err(),
                "AES-GCM must reject a payload whose provider_type byte was altered"
            );
        });
    }

    #[test]
    #[serial]
    fn a_format_v1_payload_is_refused_as_unsupported() {
        // Format 1 was the pre-release ECDH suite. Its payloads have the
        // same layout, so the version byte alone must turn them away,
        // before any key is touched.
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let mut wrapped = wrap("com.company.orders", &[0x12u8; DEK_LEN]).unwrap();
            wrapped[0] = 1;
            assert!(matches!(unwrap("com.company.orders", &wrapped), Err(Error::Unsupported(_))));
        });
    }

    #[test]
    fn sha256_wipes_itself_on_drop() {
        // HMAC-SHA-256 keys SHA-256 states with the KEK held in software
        // (see `provider::software_prf`): sha2's `zeroize` feature is what
        // wipes them when they drop. Without it this stops compiling.
        fn wipes_on_drop<T: sha2::digest::zeroize::ZeroizeOnDrop>() {}
        wipes_on_drop::<sha2::Sha256>();
    }

    #[test]
    fn aes_gcm_wipes_its_key_schedule_on_drop() {
        // `wrap`/`unwrap` zeroize the wrapping key, but the cipher built from
        // it holds an expanded copy (AES round keys and the GHASH key) until
        // it drops: aes-gcm's `zeroize` feature is what wipes that copy.
        // Without it this stops compiling.
        fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wipes_on_drop::<Aes256Gcm>();
    }

    #[test]
    fn wrapped_length_bounds_hold_for_every_provider_tag_shape() {
        // The bounds the C ABI sizes buffers from. Fixed part: version,
        // provider, key_id length, salt, nonce, ciphertext length,
        // ciphertext + tag, fingerprint.
        assert_eq!(MIN_WRAPPED_LEN, 1 + 1 + 2 + 32 + 12 + 4 + 48 + 32);
        assert_eq!(MAX_WRAPPED_LEN, MIN_WRAPPED_LEN + MAX_KEY_ID_LEN);
        let longest_service = "s".repeat(crate::MAX_SERVICE_LEN);
        for key_id in [
            vec![0u8; 32],                                             // TPM2: SHA-256 of the service
            format!("hkdfguard:{longest_service}").into_bytes(),        // PKCS#11
            format!("external:{longest_service}").into_bytes(),         // external secret
            format!("ephemeral:{longest_service}").into_bytes(),        // ephemeral
        ] {
            let payload = Payload { key_id, ..sample_payload() };
            let len = payload.to_bytes().len();
            assert!((MIN_WRAPPED_LEN..=MAX_WRAPPED_LEN).contains(&len), "payload of {len} bytes is outside the bounds");
        }
    }

    #[test]
    fn header_publishes_the_same_maximum_payload_size() {
        let header = include_str!("../include/hkdfguard.h");
        let expected = format!("#define HKDFGUARD_WRAPPED_MAX_LEN {MAX_WRAPPED_LEN}");
        assert!(header.contains(&expected), "include/hkdfguard.h must contain `{expected}`");
    }

    #[test]
    #[serial]
    fn round_trips_various_dek_patterns() {
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let patterns: [[u8; DEK_LEN]; 4] = [
                [0x00u8; DEK_LEN],
                [0xFFu8; DEK_LEN],
                core::array::from_fn(|i| i as u8),
                core::array::from_fn(|i| (255 - i) as u8),
            ];

            for dek in patterns {
                let wrapped = wrap("com.company.orders", &dek).unwrap();
                let recovered = unwrap("com.company.orders", &wrapped).unwrap();
                assert_eq!(dek, *recovered);
            }
        });
    }

    #[test]
    #[serial]
    fn fingerprint_mismatch_detected_after_kek_rotation() {
        #[cfg(feature = "external-secret")]
        {
            // external-secret is the provider used here rather than
            // Ephemeral, specifically because this test needs key
            // material that something *outside* this process can
            // rewrite -- Ephemeral is in-memory only, so there's no file
            // to rotate out from under it. Pinned by policy, or a
            // reachable TPM/PKCS#11 device would win the chain and there
            // would be nothing for the rotation below to rotate.
            let _policy = crate::policy::require_provider_policy_for_tests("external-secret");
            let ext_dir = crate::secure_file::private_tempdir();
            let _secret_mount = crate::policy::test_support::secret_mount(ext_dir.path());
            let service = "com.company.rotated";
            let secret_path = ext_dir.path().join(service);

            std::fs::write(&secret_path, crate::provider::random_kek_for_tests()).unwrap();
            // Owner-only, as the provider requires of a KEK file. The rotation
            // rewrite below preserves this mode, so it's set once.
            std::fs::set_permissions(&secret_path, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600)).unwrap();

            let dek = [0x77u8; DEK_LEN];
            let wrapped = wrap(service, &dek).unwrap();

            // Simulate an out-of-band KEK rotation: the deployment
            // platform (Vault Agent, a Kubernetes Secret, ...) rewrites
            // the mounted secret file with a brand new, unrelated key
            // under the exact same service name -- the scenario this
            // whole feature exists to catch.
            std::fs::write(&secret_path, crate::provider::random_kek_for_tests()).unwrap();

            let err = unwrap(service, &wrapped).unwrap_err();
            // Caught by the fingerprint check, before AES-GCM is ever
            // attempted -- not a generic `Error::AuthFailed`, which is what
            // this would look like without that check.
            assert!(matches!(err, Error::KekFingerprintMismatch));

        }
    }

    #[test]
    #[serial]
    fn tampered_salt_fails_to_unwrap() {
        // The salt is the per-payload input to the key derivation. Tampering
        // with it changes the KDF context *and* the authenticated bytes, so
        // the re-derived key is wrong and the AEAD rejects the payload.
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let dek = [0x33u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let mut payload = Payload::from_bytes(&wrapped).unwrap();
            payload.salt[0] ^= 0x01;
            let tampered_bytes = payload.to_bytes();

            let err = unwrap("com.company.orders", &tampered_bytes).unwrap_err();
            assert!(matches!(err, Error::AuthFailed));
        });
    }

    #[test]
    #[serial]
    fn tampered_provider_type_fails_to_unwrap() {
        // The provider tag steers which provider unwraps the payload, so
        // it is authenticated. Changing it must fail rather than being
        // honored.
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let dek = [0x34u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();

            let mut bytes = wrapped.clone();
            bytes[1] = crate::provider::ProviderType::ExternalSecret as u8; // byte 1 is provider_type

            // The property that matters is that it never *succeeds*. Which
            // error surfaces depends on the substituted provider: it may
            // be unable to serve this service at all, or it may serve a
            // different KEK and fail the fingerprint check, or the
            // authentication fails because the tag was computed over the
            // original tag byte. The cryptographic proof that the AAD is
            // what protects this byte is
            // `tampering_with_the_wire_fingerprint_bytes_breaks_aead_authentication_directly`,
            // which flips it with the key held constant.
            assert!(
                unwrap("com.company.orders", &bytes).is_err(),
                "a payload whose provider_type was altered must never unwrap"
            );

            // The untampered payload still works.
            assert_eq!(*unwrap("com.company.orders", &wrapped).unwrap(), dek);
        });
    }

    #[test]
    #[serial]
    fn tampered_nonce_fails_to_unwrap() {
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let dek = [0x44u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let mut payload = Payload::from_bytes(&wrapped).unwrap();
            payload.nonce[0] ^= 0x01; // flip a bit in nonce
            let tampered_bytes = payload.to_bytes();

            let err = unwrap("com.company.orders", &tampered_bytes).unwrap_err();
            assert!(matches!(err, Error::AuthFailed));
        });
    }
}

/// Known-answer tests: every step of the protocol, and a whole wrapped
/// payload, checked against values frozen from a known-good build. Each
/// step is pure, standardized math (HMAC-SHA-256 over SP 800-108 blocks,
/// AES-256-GCM), so a dependency upgrade must not change any of them; if
/// one does, the upgrade changed what this library computes.
#[cfg(test)]
mod known_answer {
    use super::*;
    use serial_test::serial;

    const SERVICE: &str = "com.hkdfguard.kat";
    const KEK: [u8; crate::provider::KEK_LEN] = [0x2a; crate::provider::KEK_LEN];
    const DEK: [u8; DEK_LEN] = [0x5a; DEK_LEN];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // Each step, from fixed inputs: what `wrap` computes for DEK under the
    // external-secret KEK, with its random salt and nonce fixed.
    struct Steps {
        fingerprint: String,
        wrap_block: String,
        wrapping_key: String,
        ciphertext_and_tag: String,
        payload: String,
    }

    fn compute() -> Steps {
        let mut payload = Payload {
            provider_type: crate::provider::ProviderType::ExternalSecret,
            key_id: format!("external:{SERVICE}").into_bytes(),
            salt: [0x11; SALT_LEN],
            nonce: [0x22; NONCE_LEN],
            ciphertext: vec![0; DEK_LEN + TAG_LEN],
            fingerprint: [0; FINGERPRINT_LEN],
        };
        let block = wrap_block(SERVICE, &payload.header_bytes());
        let outputs = crate::provider::software_prf(&KEK, &[&fingerprint_block(), &block]);
        payload.fingerprint = *outputs[0];
        let aad = payload.authenticated_bytes();
        let mut buf = DEK;
        let tag = Aes256Gcm::new_from_slice(&outputs[1][..])
            .unwrap()
            .encrypt_inout_detached(&Nonce::try_from(&payload.nonce[..]).unwrap(), &aad, (&mut buf[..]).into())
            .unwrap();
        payload.ciphertext = [&buf[..], &tag[..]].concat();
        Steps {
            fingerprint: hex(&*outputs[0]),
            wrap_block: hex(&block),
            wrapping_key: hex(&*outputs[1]),
            ciphertext_and_tag: hex(&payload.ciphertext),
            payload: hex(&payload.to_bytes()),
        }
    }

    // Prints the values to freeze. Run when deliberately changing the
    // protocol: cargo test --lib crypto::known_answer::print -- --ignored --nocapture
    #[test]
    #[ignore = "prints the known-answer values; not a check"]
    fn print() {
        let s = compute();
        println!(
            "FINGERPRINT={}\nWRAP_BLOCK={}\nWRAPPING_KEY={}\nCIPHERTEXT_AND_TAG={}\nPAYLOAD={}",
            s.fingerprint, s.wrap_block, s.wrapping_key, s.ciphertext_and_tag, s.payload
        );
    }

    // Frozen from a known-good build, and reproduced independently with
    // Python's hmac module and pyca/cryptography (OpenSSL), which share no
    // code with this crate.
    const FINGERPRINT: &str = "116039009e7cf849d58fc5522ace2a75a34c6b90d44e1ef6ee645edef4c336a7";
    const WRAP_BLOCK: &str =
        "00000001686b646667756172642d777261702d7632001100636f6d2e686b646667756172642e6b617402031a0065787465726e616c3a636f6d2e686b646667756172642e6b617411111111111111111111111111111111111111111111111111111111111111112222222222222222222222223000000000000100";
    const WRAPPING_KEY: &str = "4678dca75b873906bd88f26b307789b6357fae1061c0aef296fffde54c29cbad";
    const CIPHERTEXT_AND_TAG: &str =
        "d16e223bbcfaf65514f46268b55783108b4476c9619cd3bf84e21add7aef34210ad2f8e8835e8f4141cce8180907a8e0";
    const PAYLOAD: &str =
        "02031a0065787465726e616c3a636f6d2e686b646667756172642e6b6174111111111111111111111111111111111111111111111111111111111111111122222222222222222222222230000000d16e223bbcfaf65514f46268b55783108b4476c9619cd3bf84e21add7aef34210ad2f8e8835e8f4141cce8180907a8e0116039009e7cf849d58fc5522ace2a75a34c6b90d44e1ef6ee645edef4c336a7";

    #[test]
    fn every_protocol_step_matches_its_known_answer() {
        let s = compute();
        assert_eq!(s.fingerprint, FINGERPRINT, "KEK fingerprint");
        assert_eq!(s.wrap_block, WRAP_BLOCK, "SP 800-108 wrapping-key block");
        assert_eq!(s.wrapping_key, WRAPPING_KEY, "HMAC-SHA-256 wrapping key");
        assert_eq!(s.ciphertext_and_tag, CIPHERTEXT_AND_TAG, "AES-256-GCM");
        assert_eq!(s.payload, PAYLOAD, "wire format");
    }

    #[test]
    #[serial]
    fn a_frozen_payload_unwraps_through_the_external_secret_provider() {
        let _policy = crate::policy::require_provider_policy_for_tests("external-secret");
        let dir = crate::secure_file::private_tempdir();
        let _mount = crate::policy::test_support::secret_mount(dir.path());
        write_kek(dir.path());
        let dek = unwrap(SERVICE, &unhex(PAYLOAD)).unwrap();
        assert_eq!(*dek, DEK);
        // And a fresh wrap under the same KEK carries the same fingerprint.
        let fresh = Payload::from_bytes(&wrap(SERVICE, &DEK).unwrap()).unwrap();
        assert_eq!(hex(&fresh.fingerprint), FINGERPRINT);
    }

    fn write_kek(dir: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(SERVICE);
        std::fs::write(&path, KEK).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

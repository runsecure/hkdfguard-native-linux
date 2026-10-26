//! The provider-agnostic wrap/unwrap protocol:
//! `ECDH(P-256, hashed per-payload point) -> HKDF-SHA512 -> AES-256-GCM`.
//!
//! Every provider (TPM2, PKCS#11, external secret, ephemeral) implements
//! the same [`crate::provider::KekHandle::ecdh`] contract, so
//! this module is the *only* place the actual wrap/unwrap algorithm is
//! implemented -- providers never see plaintext DEKs or derived keys.
//!
//! ## Why a hashed point rather than an ephemeral key
//!
//! The wrapping key comes from `Z = ECDH(KEK_priv, H_salt)`, where
//! `H_salt` is a P-256 point derived from the payload's random salt by
//! hashing (see [`payload_ecdh_point`]). Nobody knows the discrete log of
//! a hash output, so computing `Z` requires the KEK's private key, which
//! never leaves the TPM/HSM/secret file.
//!
//! An ECIES-style construction (a fresh ephemeral keypair per wrap) would
//! be forgeable: the KEK's *public* key is not secret (on a TPM, anyone
//! who can reach the device can recompute it), and `ECDH(eph_priv,
//! KEK_pub)` equals `ECDH(KEK_priv, eph_pub)` -- so anyone holding the
//! public key could derive the wrapping key and mint a payload that
//! unwrapped to a DEK of their choosing. Binding more context into the AAD
//! or KDF does not fix that, because the forger controls those inputs
//! too. An ephemeral key would also provide no forward secrecy here, since
//! its public half would be stored in the payload.
//!
//! Only this host can create a payload, and only this host can open
//! one -- which is exactly the deployment model: DEKs arrive from a build
//! server and are wrapped locally, and a wrapped payload is never meant
//! to be produced or read anywhere else.
//!
//! ## Why the point is per payload rather than one fixed `H`
//!
//! A single fixed point `H` for every payload would make `Z` a constant
//! per service: a single capture of `Z` -- from a core dump, swap, a
//! debugger attached by the same uid, or the bus of a discrete TPM --
//! would open every payload that service had ever wrapped or would ever
//! wrap, because the only other inputs to the wrapping key are public.
//! Hashing the salt to the curve makes `Z` unique per payload, so a
//! captured `Z` is worth exactly the one payload it belongs to. Forgery
//! resistance is unaffected: an attacker holding `KEK_pub` still cannot
//! compute `KEK_priv · H_salt` for any salt. The salt is public, so the
//! (non-constant-time) hashing is fine.
//!
//! See `docs/why-ecdh.md` for the full rationale.
//!
//! ## What is bound
//!
//! The salt does double duty: it selects the ECDH point, and it is the
//! HKDF salt. Both the derived key and the AEAD are bound to
//! [`crate::payload::Payload::authenticated_bytes`] -- every byte of the
//! payload except the ciphertext -- plus the length-framed service name.
//! That authenticates the `provider_type` tag (so a payload cannot be
//! replayed as another provider's) and the KEK fingerprint (so the key
//! commits to the KEK's identity, rather than it only being checked).
//!
//! [`unwrap`] additionally checks the wrapped payload's embedded KEK
//! fingerprint (see [`kek_fingerprint`]) against the public key of the KEK
//! `service` currently resolves to, *before* attempting ECDH/AES-GCM --
//! see [`crate::error::Error::KekFingerprintMismatch`].
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
use crate::provider; // provider selection functions (`select_existing`, `get_by_type`)
use aes_gcm::{AeadInOut, Aes256Gcm, Key, KeyInit, Nonce, Tag}; // in-place AEAD trait, concrete cipher, and its key/nonce/tag types (all fixed-size, stack-resident)
use elliptic_curve::sec1::ToSec1Point; // lets us serialize the KEK public key to SEC1 bytes
use hkdf::Hkdf; // HKDF-SHA512 key derivation
use p256::hash2curve::GroupDigest; // RFC 9380 hash-to-curve for the per-payload ECDH point
use p256::{NistP256, PublicKey}; // the curve (for `GroupDigest`) and its public key type
use sha2::{Digest, Sha256, Sha512}; // `Sha256` for the KEK fingerprint, `Sha512` for HKDF, `Digest` for `Sha256::digest`
use zeroize::{Zeroize, Zeroizing}; // `Zeroize` for explicit scrubbing of stack arrays, `Zeroizing` for auto-scrubbing owned buffers

const HKDF_INFO_PREFIX: &[u8] = b"hkdfguard-wrap-v1:"; // domain-separation prefix; concatenated with the service name as HKDF's "info"
pub(crate) const TAG_LEN: usize = 16; // AES-GCM's standard 128-bit authentication tag size
#[cfg(test)]
const UNCOMPRESSED_POINT_LEN: usize = 65; // SEC1 uncompressed P-256 point: 1 tag byte (0x04) + 32-byte X + 32-byte Y

// ---------------------------------------------------------------------
// The per-payload ECDH point `H_salt`.
// ---------------------------------------------------------------------
//
// The wrapping key is derived from `Z = ECDH(KEK_priv, H_salt)`, where
// `H_salt` is a P-256 point obtained by hashing the payload's salt to the
// curve. Nobody knows the discrete logarithm of a hash output, which is
// what makes a wrapped payload unforgeable: computing `Z` requires the
// KEK's private key (which never leaves the TPM/HSM/secret file). Knowing
// the KEK's *public* key -- not secret, and on a TPM recomputable by
// anyone who can reach the device -- is not enough. This is deliberately
// *not* ECIES; see the module doc for why an ephemeral key was forgeable.
//
// Deriving the point from the salt, rather than using one fixed point for
// every payload, keeps `Z` unique per payload: capturing one `Z` opens
// one payload, not the whole service's history. The salt is also HKDF's
// salt, so a single 32-byte header field provides both separations.
//
// The hash-to-curve is the standard RFC 9380 suite
// `P256_XMD:SHA-256_SSWU_RO_` (p256's `GroupDigest`): expand_message_xmd
// with SHA-256, two simplified-SWU maps, and their sum. Its output is
// indistinguishable from a random oracle over the whole group, and its
// correctness is checked against the RFC's own test vectors rather than a
// bespoke argument. P-256 has cofactor 1, so there is no small-subgroup
// concern.

/// RFC 9380 domain separation tag for the salt-to-point hash, in the
/// RFC's recommended `<app>-V<xx>-CS<yy>-with-<suite ID>` form; the suite
/// ID is appended from [`GroupDigest::HASH_TO_CURVE_ID`].
const PAYLOAD_POINT_DST_PREFIX: &[u8] = b"HkdfGuard-payload-ECDH-point-V01-CS01-with-";

/// Hashes `salt` to a P-256 point. Deterministic, so `unwrap` recovers the
/// same point `wrap` used from the salt carried in the payload header.
pub(crate) fn payload_ecdh_point(salt: &[u8; SALT_LEN]) -> Result<PublicKey> {
    let point = NistP256::hash_from_bytes(&[salt], &[PAYLOAD_POINT_DST_PREFIX, NistP256::HASH_TO_CURVE_ID])
        .map_err(|_| Error::Crypto("hash-to-curve failed for this payload salt"))?;
    // The sum of the two mapped points is the identity with negligible
    // probability; `from_affine` refuses it rather than returning a point
    // every KEK would agree on.
    PublicKey::from_affine(point.to_affine()).map_err(|_| Error::Crypto("payload salt hashed to the identity point"))
}

pub const DEK_LEN: usize = 32; // the mandated, fixed DEK size in bytes

/// Longest `key_id` any provider may record in a payload. Every provider's
/// tag is either a fixed-size hash (TPM2: 32 bytes) or a short prefix plus
/// the service name (at most [`crate::MAX_SERVICE_LEN`] bytes); `wrap`
/// refuses anything longer, so the payload size bound below always holds.
pub const MAX_KEY_ID_LEN: usize = 16 + crate::MAX_SERVICE_LEN;

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

/// Finalizes a SHA-256 hash of secret input into a zeroizing buffer, and
/// consumes the hasher so it is wiped at once.
///
/// A hasher holds the unprocessed tail of its input (up to 63 bytes, e.g.
/// the end of a derivation secret) in its block buffer, plus the chaining
/// state. With `sha2`'s `zeroize` feature (Cargo.toml) both are wiped when
/// the hasher drops, which here is the end of this function; the digest is
/// written straight into the zeroizing output, with no other copy. Best
/// effort: the compression function's own stack temporaries are out of
/// reach, as for every other stack copy here.
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))] // the TPM provider is the caller that hashes secrets
pub(crate) fn finalize_sha256_wiping(hasher: Sha256) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    let digest: &mut sha2::digest::Output<Sha256> = (&mut out[..]).try_into().expect("SHA-256 output is 32 bytes");
    Digest::finalize_into(hasher, digest);
    out
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

    let fingerprint = kek_fingerprint(&handle.public_key()?); // identifies *which* KEK this payload is wrapped under, for `unwrap` to check before any ECDH/AES-GCM

    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| Error::Crypto("the OS random number generator failed"))?; // per-payload salt: selects this payload's ECDH point and salts its HKDF
    let point = payload_ecdh_point(&salt)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| Error::Crypto("the OS random number generator failed"))?; // fresh random nonce for this one AES-GCM encryption

    // Build the payload up front, with the ciphertext buffer already at
    // its final size, so `authenticated_bytes` below covers the real
    // declared ciphertext length. The AEAD's associated data has to be
    // fixed before encryption, and the ciphertext is always exactly
    // DEK_LEN + TAG_LEN, so there is no chicken-and-egg problem here.
    let mut payload = Payload {
        provider_type: provider.provider_type(), // records which provider produced this KEK, for `unwrap` to use later
        key_id: handle.key_id().to_vec(),        // provider's diagnostic tag
        salt,
        nonce: nonce_bytes,
        ciphertext: vec![0u8; DEK_LEN + TAG_LEN], // placeholder, filled in below
        fingerprint,
    };
    // Every non-ciphertext byte of the payload, bound into both the key
    // derivation and the AEAD -- see `Payload::authenticated_bytes`. This
    // is what authenticates `provider_type` (so a payload can't be
    // replayed as another provider's) and the fingerprint (so the KEK
    // identity is committed to by the key itself, not only checked).
    let authenticated = payload.authenticated_bytes();

    let mut shared_secret = handle.ecdh(&point)?; // ECDH against this payload's hashed point -- only the KEK's holder can compute this (already stack-only: see `provider::SharedSecret`)
    let mut wrapping_key = derive_wrapping_key(&shared_secret, service, &salt, &authenticated)?; // HKDF-SHA512 turns the shared secret into a 32-byte AES key (also stack-only)
    shared_secret.zeroize(); // the raw ECDH shared secret is no longer needed; scrub it now rather than waiting for scope exit

    let cipher = Aes256Gcm::new(aes_key(&wrapping_key)); // set up AES-256-GCM with the derived key

    // Copy the DEK onto the stack (a plain array-to-array copy, no heap
    // involved) and encrypt it in place: `ct_buf` starts as plaintext and
    // ends as ciphertext, entirely within this stack frame. `Zeroizing`, so
    // the plaintext is scrubbed even if something below panics before the
    // encryption completes.
    let mut ct_buf = Zeroizing::new(*dek);
    let tag_result = cipher.encrypt_inout_detached(&Nonce::from(nonce_bytes), &authenticated, (&mut ct_buf[..]).into());
    wrapping_key.zeroize(); // the derived AES key is no longer needed either way; scrub it immediately
    salt.zeroize(); // already copied into the payload; don't leave a second copy on the stack

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
    let handle = provider.load_kek(service, false)?; // load (never create) that provider's KEK for this service -- TPM2 deterministically regenerates it instead of persisting one

    // Before spending any effort on ECDH/AES-GCM, check that this payload
    // was actually wrapped under the KEK `service` resolves to *right now*
    // -- catches a rotated/replaced/wrong KEK with a specific, unambiguous
    // error instead of collapsing into a generic AEAD authentication
    // failure indistinguishable from tampering (see `Error::KekFingerprintMismatch`).
    let current_fingerprint = kek_fingerprint(&handle.public_key()?);
    if current_fingerprint != payload.fingerprint {
        return Err(Error::KekFingerprintMismatch);
    }

    // Must exactly mirror what `wrap` bound: every non-ciphertext byte of
    // the payload. Derived from the parsed payload, so any tampered
    // header byte changes both the derived key and the AEAD's associated
    // data -- the decryption below then fails authentication.
    let authenticated = payload.authenticated_bytes();

    let mut shared_secret = handle.ecdh(&payload_ecdh_point(&payload.salt)?)?; // re-derive the same ECDH shared secret used during wrap, from the same salt
    let mut wrapping_key = derive_wrapping_key(&shared_secret, service, &payload.salt, &authenticated)?; // re-derive the same AES key
    shared_secret.zeroize(); // scrub the shared secret as soon as we've derived the key from it

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

// Turns a raw ECDH shared secret into a 32-byte AES-256 key via
// HKDF-SHA512, using the service name as domain-separating "info" so the
// same shared secret would never accidentally produce the same wrapping
// key for a different service.
fn derive_wrapping_key(
    shared_secret: &[u8; 32],
    service: &str,
    salt: &[u8; SALT_LEN],
    authenticated: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    // HKDF-Extract with the payload's random salt. The shared secret is
    // already unique per payload (the salt selected its ECDH point), so
    // this is belt-and-braces separation rather than the only thing
    // keeping two payloads' AES keys apart.
    //
    // `extract`, not `new`: `new` calls it and drops the 64-byte PRK
    // unwiped, and the wrapping key is a public function of the PRK - it
    // opens this payload as surely as `shared_secret` does. Wiped here, as
    // soon as the expand state holds what it needs. The HMAC pad blocks
    // `hmac` builds from it are beyond this crate's reach (`hmac` 0.13 has
    // no zeroize support); the SHA-512 states keyed with them are wiped by
    // `sha2`'s `zeroize` feature.
    let (mut prk, hk) = Hkdf::<Sha512>::extract(Some(salt), shared_secret);
    prk.as_mut_slice().zeroize();

    // `info` = prefix || len(service) || service || every non-ciphertext
    // payload byte. The length prefix keeps the concatenation
    // unambiguous, so no two distinct (service, header) pairs can produce
    // the same `info`. `info` is a public label, not a secret, so a heap
    // Vec here is fine.
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + 2 + service.len() + authenticated.len());
    info.extend_from_slice(HKDF_INFO_PREFIX); // fixed prefix for domain separation from any other use of HKDF in this protocol
    info.extend_from_slice(&(service.len() as u16).to_le_bytes()); // unambiguous framing for the variable-length service name
    info.extend_from_slice(service.as_bytes()); // then the service name itself
    info.extend_from_slice(authenticated); // and the payload header + fingerprint

    let mut out = Zeroizing::new([0u8; 32]); // 32 bytes = AES-256 key size; stack-backed array wrapped for auto-scrub on drop
    hk.expand(&info, &mut *out) // HKDF-Expand into the output buffer using `info` as context (truncated to 32 bytes; SHA-512's 64-byte native output is larger than the requested AES-256 key length, which RFC 5869 allows)
        .map_err(|_| Error::Crypto("HKDF-SHA512 expand failed"))?; // only fails if the requested output length were invalid (never true here)
    Ok(out)
}

// The derived key as the cipher's key type, by reference: no unwiped copy
// of the key is made on the way in.
fn aes_key(key: &Zeroizing<[u8; 32]>) -> &Key<Aes256Gcm> {
    (&key[..]).try_into().expect("an AES-256 key is 32 bytes")
}

/// Computes the "fingerprint" appended to every wrapped payload (see
/// [`crate::payload::Payload::fingerprint`]): a SHA-256 hash of the
/// persistent KEK's public key, SEC1-uncompressed-encoded. Not a secret
/// value -- the public key it hashes isn't secret either -- so the
/// equality check against it in [`unwrap`] exists purely to fail fast and
/// cheaply on "this payload wasn't wrapped under the KEK `service`
/// currently resolves to," before spending any effort on ECDH/AES-GCM.
pub(crate) fn kek_fingerprint(public_key: &PublicKey) -> [u8; FINGERPRINT_LEN] {
    let encoded = public_key.to_sec1_point(false); // uncompressed SEC1 point: 0x04 || X || Y
    let digest = Sha256::digest(encoded.as_bytes());
    let mut out = [0u8; FINGERPRINT_LEN];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*; // bring `wrap`, `unwrap`, `DEK_LEN`, etc. into scope
    use p256::elliptic_curve::Generate as _; // `SecretKey::generate()`, from the OS CSPRNG
    use p256::SecretKey; // test-only: stands in for an attacker scalar and for fingerprint fixtures
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
            // attempted: billing's KEK has a different public key than
            // orders', so the payload's embedded fingerprint can't match.
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

    // ---- the per-payload hashed ECDH point `H_salt` ----

    #[test]
    fn payload_point_is_deterministic_and_salt_dependent() {
        let salt_a = [0x11u8; SALT_LEN];
        let salt_b = [0x12u8; SALT_LEN];

        assert_eq!(
            payload_ecdh_point(&salt_a).unwrap(),
            payload_ecdh_point(&salt_a).unwrap(),
            "the same salt must always hash to the same point, or unwrap could never follow wrap"
        );
        assert_ne!(
            payload_ecdh_point(&salt_a).unwrap(),
            payload_ecdh_point(&salt_b).unwrap(),
            "different salts must hash to different points"
        );

        // A single flipped bit anywhere in the salt moves the point.
        let base = payload_ecdh_point(&salt_a).unwrap();
        for i in 0..SALT_LEN {
            let mut flipped = salt_a;
            flipped[i] ^= 0x80;
            assert_ne!(base, payload_ecdh_point(&flipped).unwrap(), "salt byte {i} must reach the point");
        }
    }

    #[test]
    fn payload_point_is_a_valid_usable_curve_point_for_many_salts() {
        // The hash must land on the curve for arbitrary salts,
        // including degenerate ones, and the result must be a real point
        // usable for ECDH from the scalar side.
        let mut salts: Vec<[u8; SALT_LEN]> = vec![[0u8; SALT_LEN], [0xffu8; SALT_LEN]];
        for _ in 0..64 {
            let mut s = [0u8; SALT_LEN];
            getrandom::fill(&mut s).unwrap();
            salts.push(s);
        }

        let k = SecretKey::generate();
        let other = SecretKey::generate();
        for salt in salts {
            let h = payload_ecdh_point(&salt).unwrap();

            let encoded = h.to_sec1_point(false);
            assert_eq!(encoded.as_bytes().len(), UNCOMPRESSED_POINT_LEN);
            assert_eq!(encoded.as_bytes()[0], 0x04);
            assert_eq!(PublicKey::from_sec1_bytes(encoded.as_bytes()).unwrap(), h);

            let z1 = p256::ecdh::diffie_hellman(k.to_nonzero_scalar(), h.as_affine());
            let z2 = p256::ecdh::diffie_hellman(k.to_nonzero_scalar(), h.as_affine());
            assert_eq!(z1.raw_secret_bytes(), z2.raw_secret_bytes());

            // Different KEKs still yield different Z against the same point.
            let z_other = p256::ecdh::diffie_hellman(other.to_nonzero_scalar(), h.as_affine());
            assert_ne!(z1.raw_secret_bytes(), z_other.raw_secret_bytes());
        }
    }

    #[test]
    #[serial]
    fn software_providers_accept_hashed_payload_points() {
        // The hardware backends get their own #[ignore]d versions of this
        // (see the tpm2 and pkcs11 provider tests); this covers the
        // providers that need no device, so the check runs on every build
        // rather than only where swtpm/SoftHSM2 are available.
        with_isolated_ephemeral_provider(|| {
            let h = payload_ecdh_point(&[0x42u8; SALT_LEN]).unwrap();

            let service = "com.company.orders.payloadpoint";
            crate::provider::create_kek(service).unwrap();
            let (_provider, handle) = crate::provider::select_existing(service).unwrap();

            let z1 = handle.ecdh(&h).unwrap();
            let z2 = handle.ecdh(&h).unwrap();
            assert_eq!(*z1, *z2, "ECDH against the same point must be repeatable");
            assert_ne!(*z1, [0u8; 32], "shared secret must not be all zeroes");

            let other_service = "com.company.billing.payloadpoint";
            crate::provider::create_kek(other_service).unwrap();
            let (_provider, other) = crate::provider::select_existing(other_service).unwrap();
            assert_ne!(
                *z1,
                *other.ecdh(&h).unwrap(),
                "different KEKs must yield different Z against the same point"
            );
        });
    }

    #[test]
    #[serial]
    fn a_captured_shared_secret_opens_only_its_own_payload() {
        // The reason the point is per payload. Assume the worst: an
        // attacker captured the raw ECDH secret Z for one payload (core
        // dump, swap, discrete-TPM bus). Under a fixed point that Z would be
        // constant per service and open every payload; here it must be
        // useless against any other payload for the same service.
        with_isolated_ephemeral_provider(|| {
            let service = "com.company.capture";
            crate::provider::create_kek(service).unwrap();
            let dek_a = [0xA1u8; DEK_LEN];
            let dek_b = [0xB2u8; DEK_LEN];
            let wrapped_a = wrap(service, &dek_a).unwrap();
            let wrapped_b = wrap(service, &dek_b).unwrap();
            let payload_a = Payload::from_bytes(&wrapped_a).unwrap();
            let payload_b = Payload::from_bytes(&wrapped_b).unwrap();

            let (_provider, handle) = crate::provider::select_existing(service).unwrap();
            let z_a = handle.ecdh(&payload_ecdh_point(&payload_a.salt).unwrap()).unwrap();
            let z_b = handle.ecdh(&payload_ecdh_point(&payload_b.salt).unwrap()).unwrap();
            assert_ne!(*z_a, *z_b, "two payloads for one service must not share a shared secret");

            // Z_A genuinely opens payload A (so the capture is "real")...
            let open = |z: &[u8; 32], p: &Payload| -> std::result::Result<[u8; DEK_LEN], ()> {
                let aad = p.authenticated_bytes();
                let key = derive_wrapping_key(z, service, &p.salt, &aad).unwrap();
                let cipher = Aes256Gcm::new_from_slice(&*key).unwrap();
                let (ct, tag) = p.ciphertext.split_at(DEK_LEN);
                let mut buf = [0u8; DEK_LEN];
                buf.copy_from_slice(ct);
                cipher
                    .decrypt_inout_detached(&Nonce::try_from(&p.nonce[..]).unwrap(), &aad, (&mut buf[..]).into(), &Tag::try_from(tag).unwrap())
                    .map(|_| buf)
                    .map_err(|_| ())
            };
            assert_eq!(open(&z_a, &payload_a).unwrap(), dek_a);

            // ...and does nothing for payload B, even with B's public
            // salt, nonce, and header all in hand.
            assert!(open(&z_a, &payload_b).is_err(), "a captured Z must not open a different payload");
        });
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
    fn derive_wrapping_key_binds_every_input() {
        let secret = [0x99u8; 32];
        let payload = sample_payload();
        let salt = payload.salt;
        let authenticated = payload.authenticated_bytes();

        let base = derive_wrapping_key(&secret, "service.a", &salt, &authenticated).unwrap();
        assert_eq!(
            *base,
            *derive_wrapping_key(&secret, "service.a", &salt, &authenticated).unwrap(),
            "must be deterministic for identical inputs"
        );

        // Service name.
        assert_ne!(
            *base,
            *derive_wrapping_key(&secret, "service.b", &salt, &authenticated).unwrap(),
            "the service name must change the derived key"
        );

        // Shared secret (i.e. a different KEK).
        assert_ne!(
            *base,
            *derive_wrapping_key(&[0x98u8; 32], "service.a", &salt, &authenticated).unwrap(),
            "a different shared secret must change the derived key"
        );

        // Salt -- the per-payload separation.
        let mut other_salt = salt;
        other_salt[0] ^= 0x01;
        assert_ne!(
            *base,
            *derive_wrapping_key(&secret, "service.a", &other_salt, &authenticated).unwrap(),
            "the salt must change the derived key, or every payload would share one"
        );

        // Every single byte of the authenticated header, including the
        // provider_type tag and the fingerprint, must reach the
        // key derivation -- not merely the AEAD's associated data.
        for i in 0..authenticated.len() {
            let mut tampered = authenticated.clone();
            tampered[i] ^= 0x01;
            assert_ne!(
                *base,
                *derive_wrapping_key(&secret, "service.a", &salt, &tampered).unwrap(),
                "flipping authenticated byte {i} must change the derived key"
            );
        }
    }

    #[test]
    fn service_name_framing_is_unambiguous() {
        // The length prefix on the service name is what stops two
        // different (service, header) pairs from concatenating to the same
        // `info`. Without it, ("ab", <header starting c>) and
        // ("abc", <header>) could collide.
        let secret = [0x99u8; 32];
        let salt = [0u8; SALT_LEN];

        let k1 = derive_wrapping_key(&secret, "ab", &salt, b"cXYZ").unwrap();
        let k2 = derive_wrapping_key(&secret, "abc", &salt, b"XYZ").unwrap();
        assert_ne!(*k1, *k2, "service/header boundary must not be ambiguous");
    }

    #[test]
    #[serial]
    fn tampering_with_the_wire_fingerprint_bytes_breaks_aead_authentication_directly() {
        // `wrap`/`unwrap`'s own fingerprint pre-check already rejects a
        // tampered fingerprint before AES-GCM is ever attempted (see
        // `wrong_service_fails_to_unwrap` and the module doc comment), so
        // going through the public API can't observe AEAD's own tamper
        // detection in isolation -- by the time `unwrap` builds its AAD,
        // the pre-check has already forced it to agree with whatever the
        // payload's fingerprint bytes currently are. This test instead
        // re-derives the same wrapping key `wrap` used and decrypts
        // directly with `Aes256Gcm`, to prove independently that AAD
        // including the fingerprint is what's actually protecting those
        // bytes cryptographically, not just the application-level check.
        with_isolated_ephemeral_provider(|| {
            let service = "com.company.aadtest";
            crate::provider::create_kek(service).unwrap();
            let dek = [0x66u8; DEK_LEN];
            let wrapped = wrap(service, &dek).unwrap();
            let payload = Payload::from_bytes(&wrapped).unwrap();

            let (provider, handle) = crate::provider::select_existing(service).unwrap();
            let _ = provider;
            let mut shared_secret = handle.ecdh(&payload_ecdh_point(&payload.salt).unwrap()).unwrap();
            let correct_aad = payload.authenticated_bytes();
            let wrapping_key =
                derive_wrapping_key(&shared_secret, service, &payload.salt, &correct_aad).unwrap();
            shared_secret.zeroize();

            let (ct_part, tag_part) = payload.ciphertext.split_at(DEK_LEN);
            let tag = &Tag::try_from(tag_part).unwrap();
            let cipher = Aes256Gcm::new_from_slice(&*wrapping_key).unwrap();

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
    fn a_public_key_holder_cannot_forge_a_payload() {
        // The point of the hashed-point design. Under an ephemeral-ECDH
        // protocol an attacker holding only the KEK's *public* key could
        // compute the same shared secret the provider would
        // (ECDH(eph_priv, KEK_pub) == ECDH(KEK_priv, eph_pub)), derive the
        // wrapping key, and mint a payload that unwrapped to a DEK of
        // their choosing. Here the shared secret is ECDH(KEK_priv,
        // H_salt), so reproducing it needs the KEK's private key or the
        // discrete log of a hash output -- neither of which a public-key
        // holder has.
        with_isolated_ephemeral_provider(|| {
            let service = "com.company.forgery";
            crate::provider::create_kek(service).unwrap();

            let genuine = wrap(service, &[0x01u8; DEK_LEN]).unwrap();
            let payload = Payload::from_bytes(&genuine).unwrap();

            // Everything the attacker is assumed to know: the KEK's public
            // key (not secret -- on a TPM anyone reaching the device can
            // recompute it), the wire format, the salt, and therefore the
            // exact point H_salt the host will use.
            let (_provider, handle) = crate::provider::select_existing(service).unwrap();
            let kek_public = handle.public_key().unwrap();
            let h = payload_ecdh_point(&payload.salt).unwrap();

            // 1. The attack is real: whenever the host runs ECDH against a
            // point the attacker chose -- as an ephemeral-key protocol's
            // unwrap does, against the E in the payload -- the attacker
            // knows the result from KEK_pub alone. (Without this, the rest
            // of the test could pass for a broken protocol too.)
            let attacker_scalar = SecretKey::generate();
            let attacker_point = attacker_scalar.public_key();
            let attacker_z = p256::ecdh::diffie_hellman(attacker_scalar.to_nonzero_scalar(), kek_public.as_affine());
            let mut host_z_on_attacker_point = handle.ecdh(&attacker_point).unwrap();
            assert_eq!(
                host_z_on_attacker_point.as_slice(),
                attacker_z.raw_secret_bytes().as_slice(),
                "ECDH against an attacker-chosen point gives the attacker the shared secret"
            );
            host_z_on_attacker_point.zeroize();

            // 2. So the protocol must never do that, and doesn't: the only
            // point unwrap ever uses is a hash of the salt. Recomputed here
            // independently of `payload_ecdh_point` -- RFC 9380
            // hash_to_curve with the expander and full DST spelled out --
            // so it is a hash output nobody knows the discrete log of,
            // whatever salt an attacker writes into a payload.
            let hashed = p256::hash2curve::hash_from_bytes::<NistP256, p256::hash2curve::ExpandMsgXmd<Sha256>>(
                &[&payload.salt],
                &[b"HkdfGuard-payload-ECDH-point-V01-CS01-with-P256_XMD:SHA-256_SSWU_RO_"],
            )
            .unwrap();
            let hashed = PublicKey::from_affine(hashed.to_affine()).unwrap();
            assert_eq!(h, hashed, "unwrap's point is exactly the hash of the payload's salt");
            assert_ne!(h, attacker_point, "and so never a point the attacker chose");

            // The attacker's best attempt at a wrapping key, then: ECDH of
            // their own scalar with KEK_pub, which is not what unwrap uses.
            let mut attacker_secret = [0u8; 32];
            attacker_secret.copy_from_slice(attacker_z.raw_secret_bytes().as_slice());
            let authenticated = payload.authenticated_bytes();
            let forged_key =
                derive_wrapping_key(&attacker_secret, service, &payload.salt, &authenticated).unwrap();

            // And concretely: a payload encrypted under the attacker's key
            // does not unwrap, even though every header byte is
            // well-formed and the fingerprint is correct.
            let attacker_dek = [0xEEu8; DEK_LEN];
            let mut ct_buf = attacker_dek;
            let cipher = Aes256Gcm::new_from_slice(&*forged_key).unwrap();
            let tag = cipher
                .encrypt_inout_detached(&Nonce::try_from(&payload.nonce[..]).unwrap(), &authenticated, (&mut ct_buf[..]).into())
                .unwrap();

            let mut forged = Payload {
                provider_type: payload.provider_type,
                key_id: payload.key_id.clone(),
                salt: payload.salt,
                nonce: payload.nonce,
                ciphertext: Vec::new(),
                fingerprint: payload.fingerprint, // the correct fingerprint: the pre-check will pass
            };
            forged.ciphertext.extend_from_slice(&ct_buf);
            forged.ciphertext.extend_from_slice(&tag);

            let err = unwrap(service, &forged.to_bytes()).unwrap_err();
            assert!(
                matches!(err, Error::AuthFailed),
                "a forged payload must fail AEAD authentication, got {err:?}"
            );

            // The genuine payload still works, so the test isn't passing
            // for an unrelated reason.
            assert_eq!(*unwrap(service, &genuine).unwrap(), [0x01u8; DEK_LEN]);
        });
    }

    #[test]
    fn wiping_finalize_matches_a_plain_finalize() {
        // Any change to the digest would change every TPM KEK, so the
        // wiping variant must agree with plain `finalize` byte for byte --
        // across tails that end mid-block, exactly at a block boundary, and
        // one byte short of one (where padding spills into a second block).
        for len in [0usize, 1, 31, 32, 55, 56, 63, 64, 65, 127, 200] {
            let input: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let expected = Sha256::digest(&input);

            let mut hasher = Sha256::new();
            hasher.update(&input);
            let got = finalize_sha256_wiping(hasher);
            assert_eq!(&got[..], &expected[..], "input length {len}");
        }
    }

    #[test]
    fn sha256_wipes_itself_on_drop() {
        // What makes the hasher `finalize_sha256_wiping` consumes safe to
        // drop: sha2's `zeroize` feature. Without it this stops compiling.
        fn wipes_on_drop<T: sha2::digest::zeroize::ZeroizeOnDrop>() {}
        wipes_on_drop::<Sha256>();
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
    fn payload_point_suite_matches_rfc9380_test_vectors() {
        // RFC 9380 Appendix J.1.1 (P256_XMD:SHA-256_SSWU_RO_), under the
        // RFC's own DST: confirms the library implements the suite that
        // `payload_ecdh_point` names, not merely something self-consistent.
        const DST: &[u8] = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
        for (msg, x, y) in [
            (
                &b""[..],
                "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
                "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
            ),
            (
                b"abc",
                "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
                "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
            ),
            (
                b"abcdef0123456789",
                "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
                "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
            ),
        ] {
            let point = NistP256::hash_from_bytes(&[msg], &[DST]).unwrap().to_affine();
            let got: String = point.to_sec1_point(false).as_bytes()[1..].iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, format!("{x}{y}"), "msg {msg:?}");
        }
    }

    #[test]
    fn payload_ecdh_point_known_vectors() {
        // Computed independently with a from-the-RFC Python implementation
        // of RFC 9380 hash_to_curve (itself checked against Appendix J.1.1)
        // under this crate's DST, so a change to the DST or suite shows up
        // here.
        let mut ascending = [0u8; SALT_LEN];
        for (i, b) in ascending.iter_mut().enumerate() {
            *b = i as u8;
        }
        for (salt, compressed) in [
            (ascending, "03877847fb8a2cfbcf800b4191284aaba0934fd52e7e1971d30fa14b296544229e"),
            ([0x00; SALT_LEN], "02a2b51e2ca3a067bd58078749da73319c73c7e25985053d8cc6f046a3346f38f5"),
            ([0xFF; SALT_LEN], "036fecbe49be33b5a13f69f948456292aa1f60c5bb3e3d0d702736765af0f160c0"),
        ] {
            let point = payload_ecdh_point(&salt).unwrap();
            let got: String = point.to_sec1_point(true).as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, compressed, "salt {salt:02x?}");
        }
    }

    #[test]
    fn kek_fingerprint_properties() {
        let key1 = SecretKey::generate().public_key();
        let key2 = SecretKey::generate().public_key();

        let f1 = kek_fingerprint(&key1);
        let f1_repeat = kek_fingerprint(&key1);
        assert_eq!(f1, f1_repeat, "must be deterministic for the same public key");
        assert_eq!(f1.len(), FINGERPRINT_LEN);

        let f2 = kek_fingerprint(&key2);
        assert_ne!(f1, f2, "different public keys must yield different fingerprints");
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

            let key_a = SecretKey::generate();
            std::fs::write(&secret_path, key_a.to_bytes()).unwrap();
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
            let key_b = SecretKey::generate();
            std::fs::write(&secret_path, key_b.to_bytes()).unwrap();

            let err = unwrap(service, &wrapped).unwrap_err();
            // Caught by the fingerprint check, before ECDH/AES-GCM is ever
            // attempted -- not a generic `Error::AuthFailed`, which is what
            // this would look like without that check.
            assert!(matches!(err, Error::KekFingerprintMismatch));

        }
    }

    #[test]
    #[serial]
    fn tampered_salt_fails_to_unwrap() {
        // The salt is the per-payload input to the key derivation. Tampering
        // with it changes the HKDF salt *and* the authenticated bytes, so
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
/// step is pure, standardized math (SHA-256, SEC1, ECDH, HKDF-SHA512,
/// AES-256-GCM, PKCS#8), so a dependency upgrade must not change any of
/// them; if one does, the upgrade changed what this library computes.
#[cfg(test)]
mod known_answer {
    use super::*;
    use p256::SecretKey;
    use serial_test::serial;

    const SERVICE: &str = "com.hkdfguard.kat";
    const KEK_SCALAR: [u8; 32] = [0x2a; 32];
    const SALT: [u8; SALT_LEN] = [0x11; SALT_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x22; NONCE_LEN];
    const DEK: [u8; DEK_LEN] = [0x5a; DEK_LEN];
    const HEADER: &[u8] = b"hkdfguard known-answer header";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn kek() -> SecretKey {
        SecretKey::from_slice(&KEK_SCALAR).unwrap()
    }

    // Each step, from the fixed inputs above.
    struct Steps {
        point: String,
        shared_secret: String,
        fingerprint: String,
        wrapping_key: String,
        ciphertext_and_tag: String,
        kek_pkcs8_der: String,
    }

    fn compute() -> Steps {
        use elliptic_curve::pkcs8::EncodePrivateKey;
        let point = payload_ecdh_point(&SALT).unwrap();
        let shared = p256::ecdh::diffie_hellman(kek().to_nonzero_scalar(), point.as_affine());
        let mut z = [0u8; 32];
        z.copy_from_slice(shared.raw_secret_bytes());
        let key = derive_wrapping_key(&z, SERVICE, &SALT, HEADER).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&*key).unwrap();
        let mut buf = DEK;
        let tag = cipher.encrypt_inout_detached(&Nonce::try_from(&NONCE[..]).unwrap(), HEADER, (&mut buf[..]).into()).unwrap();
        Steps {
            point: hex(point.to_sec1_point(true).as_bytes()),
            shared_secret: hex(&z),
            fingerprint: hex(&kek_fingerprint(&kek().public_key())),
            wrapping_key: hex(&*key),
            ciphertext_and_tag: hex(&[&buf[..], &tag[..]].concat()),
            kek_pkcs8_der: hex(kek().to_pkcs8_der().unwrap().as_bytes()),
        }
    }

    // Prints the values to freeze. Run when deliberately changing the
    // protocol: cargo test --lib crypto::known_answer::print -- --ignored --nocapture
    #[test]
    #[ignore = "prints the known-answer values; not a check"]
    #[serial]
    fn print() {
        let s = compute();
        println!("POINT={}\nSHARED_SECRET={}\nFINGERPRINT={}\nWRAPPING_KEY={}\nCIPHERTEXT_AND_TAG={}\nKEK_PKCS8_DER={}",
            s.point, s.shared_secret, s.fingerprint, s.wrapping_key, s.ciphertext_and_tag, s.kek_pkcs8_der);
        let _policy = crate::policy::require_provider_policy_for_tests("external-secret");
        let dir = crate::secure_file::private_tempdir();
        let _mount = crate::policy::test_support::secret_mount(dir.path());
        write_kek(dir.path());
        println!("WRAPPED={}", hex(&wrap(SERVICE, &DEK).unwrap()));
    }

    // Frozen from a known-good build, and reproduced independently with
    // pyca/cryptography (OpenSSL), which shares no code with this crate.
    const POINT: &str = "02b23092bba6aaf88b48a76e47eff090537c0f22de2d07f8ea53d688533a71fd78";
    const SHARED_SECRET: &str = "c25dfa74f08cf0cfc90c09b137e1ce621163a914e04d734e5d811ee9d8012707";
    const FINGERPRINT: &str = "550baec2e009d8c4ba938306605e9c55657d613e13ee25e208736c90567b6d88";
    const WRAPPING_KEY: &str = "513e5531a4a065f8cc55444d0642a87599525282156d338292860e7be62cfb31";
    const CIPHERTEXT_AND_TAG: &str =
        "c2d840acab45552dfabe45d3d2d3556d4134bd2ae71e2163e39a4a27ef53593f6591b2dc77414d94e6a0a78f236efb6d";
    const KEK_PKCS8_DER: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2aa144034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569e";
    /// A whole payload `wrap` produced for DEK under the external-secret
    /// KEK_SCALAR (random salt and nonce, so it can only be frozen, not
    /// recomputed).
    const WRAPPED: &str = "01031a0065787465726e616c3a636f6d2e686b646667756172642e6b6174839d341ef74e55fcdbdcdbffdfe2d6ba346cf22ee9e826be2a62f96bc20f2aba22160d8880117e22c0dec52d30000000a3b9f646bc8e4f13b8051e0dcb1867cadd3105c6ca229bfe8f910a8185b773f266fb491cf9707ab0d0930fd83f98b8f7550baec2e009d8c4ba938306605e9c55657d613e13ee25e208736c90567b6d88";

    #[test]
    fn every_protocol_step_matches_its_known_answer() {
        let s = compute();
        assert_eq!(s.point, POINT, "salt-to-point hash");
        assert_eq!(s.shared_secret, SHARED_SECRET, "ECDH");
        assert_eq!(s.fingerprint, FINGERPRINT, "KEK fingerprint");
        assert_eq!(s.wrapping_key, WRAPPING_KEY, "HKDF-SHA512 wrapping key");
        assert_eq!(s.ciphertext_and_tag, CIPHERTEXT_AND_TAG, "AES-256-GCM");
        assert_eq!(s.kek_pkcs8_der, KEK_PKCS8_DER, "PKCS#8 encoding");
    }

    #[test]
    fn a_frozen_pkcs8_kek_parses_to_the_same_key() {
        // The external-secret provider accepts PKCS#8 DER as well as a raw
        // scalar; both forms of KEK_SCALAR must be the same key.
        use elliptic_curve::pkcs8::DecodePrivateKey;
        let parsed = SecretKey::from_pkcs8_der(&unhex(KEK_PKCS8_DER)).unwrap();
        assert_eq!(parsed.to_bytes().as_slice(), &KEK_SCALAR[..]);
    }

    #[test]
    #[serial]
    fn a_frozen_payload_unwraps_through_the_external_secret_provider() {
        let _policy = crate::policy::require_provider_policy_for_tests("external-secret");
        let dir = crate::secure_file::private_tempdir();
        let _mount = crate::policy::test_support::secret_mount(dir.path());
        write_kek(dir.path());
        let dek = unwrap(SERVICE, &unhex(WRAPPED)).unwrap();
        assert_eq!(*dek, DEK);
    }

    fn write_kek(dir: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(SERVICE);
        std::fs::write(&path, KEK_SCALAR).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

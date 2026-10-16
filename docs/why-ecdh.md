# Why HKDFGuard wraps keys with ECDH against a hashed point

HKDFGuard derives each payload's wrapping key from an ECDH between the
service's KEK and a point hashed from the payload's own random salt. The
purpose of that choice is one property: **only something that can use the
KEK can produce a payload that unwraps.** A payload can't be forged by
anyone who merely knows the KEK's public key.

This document explains the threat, why the common alternative fails
against it, how this construction resists it, and what it costs.

## The construction

For every wrap:

1. Generate a random 32-byte `salt` and a random 12-byte AES-GCM nonce.
2. Hash the salt to a P-256 point:
   `H_salt = hash_to_curve("HkdfGuard-P256-payload-ECDH-point-v1:" || salt)`.
   Nobody knows the private key (discrete log) of `H_salt`.
3. Ask the KEK's provider (TPM, PKCS#11 token, or secret file) to compute
   `Z = KEK_priv · H_salt`. The private key never leaves the provider.
4. Derive the wrapping key:
   `K = HKDF-SHA512(salt, Z, info = prefix || service || payload header || KEK fingerprint)`.
5. Encrypt the DEK with AES-256-GCM under `K`, with the same header bytes
   as associated data.

The payload stores the salt, the nonce, the ciphertext and a SHA-256
fingerprint of the KEK's public key. It never stores the public key.
Unwrap recomputes `H_salt` from the stored salt, asks the provider for the
same `Z`, and reverses the steps.

## The threat: a forged payload

A forger's goal is a payload that the service accepts and unwraps to a DEK
**the forger chose**. If they manage it, they don't need to break any
encryption. The service encrypts its new data under a key the attacker
already knows.

The forger's way in is replacing a key file, or any other channel that
feeds bytes to `hkdfguard_unwrap_dek`. Unwrap succeeds, the fingerprint
matches, the AEAD tag verifies, and nothing looks wrong.

## Why ECIES-style wrapping is forgeable

The usual way to encrypt to a public key is ECIES, or HPKE in base mode:

1. Generate an ephemeral key pair `(e, E = e·G)`.
2. Compute `Z = e · KEK_pub` in software.
3. Derive the key, encrypt, and store `E` in the payload.
4. Unwrap computes `Z = KEK_priv · E` on the provider.

Both sides arrive at the same `Z` because `e · KEK_pub = KEK_priv · E`. That
same equation is the problem: **computing `Z` needs only `KEK_pub`**, and
the public key is not a secret.

- On a TPM, anyone who can open the device can recompute the key and read
  its public half.
- Public keys get logged, exported for pinning, and copied into
  monitoring.

Anyone holding `KEK_pub` can pick a DEK, generate their own `e`, and build
a payload that unwraps perfectly.

Binding more context into the AAD or the KDF doesn't help. The forger
controls those inputs too, and simply includes the correct values. The
ephemeral key adds no forward secrecy here either, because its public half
is stored in the payload next to the ciphertext.

## Why the hashed point resists it

With `Z = KEK_priv · H_salt`, a forger knows `KEK_pub = KEK_priv · G` and
can compute `H_salt` from any salt they like. Producing `KEK_priv · H_salt`
from those two points is the computational Diffie-Hellman problem on
P-256. That's the same assumption every P-256 key exchange relies on, so
**creating a payload requires the KEK's private key**, exactly as opening
one does.

The forger also can't choose a point whose discrete log they know, because
`H_salt` comes out of a hash. That's why the point is hashed rather than
taken from the payload.

The consequence is that a valid payload proves it was produced by
something able to use the KEK.

## Why the point is different for every payload

Each payload's salt gives it its own point, and so its own `Z`. A `Z` that
leaks (from a core dump, swap, a same-user debugger, or the bus of a
discrete TPM) opens only the one payload it belongs to. With a single fixed
point per service, `Z` would be a per-service constant, and one leak would
open every payload that service ever wrapped or will wrap.

## What else is bound

The HKDF `info` and the AEAD's associated data both cover every byte of
the payload except the ciphertext:

- the version
- the provider tag
- the key-id
- the salt
- the nonce
- the ciphertext length
- the KEK fingerprint

The `info` also covers the length-framed service name. So:

- **Another service:** a payload can't be replayed under a different
  service.
- **Another provider:** it can't be relabelled as another provider's.
- **Another KEK:** the derived key commits to the KEK's identity, not just
  a fingerprint that happens to be checked.

Before any ECDH or decryption, unwrap compares the stored fingerprint with
the current KEK's. A mismatch reports `HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH`
(-16), a wrong or rotated KEK, distinct from `HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED`
(-11), a tampered payload.

## What it costs

- **Every wrap uses the KEK.** On a TPM that's one `TPM2_ECDH_ZGen` per
  wrap as well as per unwrap. Wrapping can't happen while the provider is
  unavailable.
- **No wrapping from elsewhere.** A build server can't pre-wrap a DEK for a
  host; the host wraps it locally. That matches the deployment model:
  DEKs arrive from a pipeline and are wrapped on the host that will use
  them.
- **A custom step.** The hash-to-curve is try-and-increment over SHA-256,
  not RFC 9380. It's simple and sound (the salt is public, so not being
  constant-time leaks nothing; P-256 has cofactor 1), and a known-answer
  test pins its output. But a reviewer has to check it, rather than
  recognising a standard construction. The domain string and the payload
  version byte both carry `v1`, so a move to RFC 9380 would be a new
  payload version, never a silent change.

## Alternatives considered

| Alternative | Forgery-resistant? | Why not chosen |
|---|---|---|
| ECIES / HPKE base mode | No | Anyone with `KEK_pub` can forge, as above |
| HPKE auth mode, or a signature on each payload | Yes | Needs a second protected key on the wrapping side, so wrapping still needs a protected key. It adds a key and a mechanism to get the same property |
| A symmetric PRF (e.g. TPM-held HMAC key) instead of ECDH | Yes | Works on TPMs and HSMs, but the macOS Secure Enclave holds only P-256 keys. ECDH is the one primitive every HKDFGuard platform's hardware offers, and its public key gives a fingerprint and a TPM Name that can be pinned |
| ECDH against a hashed point (chosen) | Yes | — |

## What it does not protect against

- **Someone who can use the KEK.** On a TPM host that's any process that
  can open the device and read the derivation secret. Such a process can
  wrap any DEK it likes, legitimately. Against that threat, the protection
  is keeping who may use the KEK small, and `hkdfguard_open_file`'s
  refusal of key files that anyone else could have replaced.
- **A future quantum computer.** Shor's algorithm would recover `KEK_priv`
  from `KEK_pub`. A payload doesn't contain the public key, so key files
  copied off a host aren't enough on their own; the attacker would also
  need `KEK_pub` from the host. A hybrid that adds a symmetric PRF term
  to the key derivation would close this without giving up forgery
  resistance.

## Where it lives in the code

All in [`src/crypto.rs`](../src/crypto.rs):

- **Hash-to-curve:** `payload_ecdh_point`.
- **Wrap and unwrap:** `wrap` and `unwrap`.
- **Key derivation:** `derive_wrapping_key`.
- **KEK fingerprint:** `kek_fingerprint`.

Tests, also in `crypto.rs`:

- **The forgery itself:** `a_public_key_holder_cannot_forge_a_payload`
  builds an ECIES-style payload from the public key alone and checks that
  it's rejected.
- **Known answers:** `every_protocol_step_matches_its_known_answer` pins
  each step's output, so another implementation can check it matches.
- **Binding:** `derive_wrapping_key_binds_every_input`, and the
  `tampered_*` tests, which change one field at a time.

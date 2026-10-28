# Why HKDFGuard wraps keys with ECDH against a hashed point

> **Superseded.** This describes a pre-release design that was never
> released. HKDFGuard now uses a device-held HMAC key and
> the SP 800-108 KDF, which is safe against quantum computers and uses
> only NIST-approved functions: see [why-hmac-prf.md](why-hmac-prf.md) and
> [ADR-0001](adr/0001-post-quantum-wrapping-suite.md). Kept as the record
> of what was considered.

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
   `H_salt = hash_to_curve(salt)`, the standard RFC 9380 suite
   `P256_XMD:SHA-256_SSWU_RO_` with the domain separation tag
   `HkdfGuard-payload-ECDH-point-V01-CS01-with-P256_XMD:SHA-256_SSWU_RO_`.
   Nobody knows the private key (discrete log) of `H_salt`.
3. Ask the KEK's provider (TPM, PKCS#11 token, or secret file) to compute
   `Z = KEK_priv · H_salt`. The private key never leaves the provider.
4. Derive the wrapping key:
   `K = HKDF-SHA512(salt = salt, IKM = Z, info)`, where `Z` is the shared
   point's x-coordinate, big-endian, and
   `info = "hkdfguard-wrap-v1:" || u16_le(len(service)) || service || authenticated`.
   `authenticated` is every payload byte except the ciphertext: the header
   fields in wire order (version, provider tag, key-id length, key-id,
   salt, nonce, ciphertext length), then the KEK fingerprint.
5. Encrypt the DEK with AES-256-GCM under `K`, with `authenticated` as
   associated data.

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

## In standard terms: a PRF keyed by the KEK

"ECDH" describes the operation the hardware performs, but the protocol
isn't a key exchange: no second party has a key pair, and nothing is
agreed with anyone. What the construction computes is a **pseudorandom
function (PRF) keyed by the KEK's private key `k`**, evaluated at the
salt:

```
F(k, salt) = H2(salt, k · H1(salt))
```

- `H1` is the RFC 9380 hash-to-curve above.
- `k · H1(salt)` is `Z`, the one step that needs the KEK. A TPM, an HSM or
  a P-256 private key can compute it, which is why the protocol can be
  built on ECDH.
- `H2` is HKDF-SHA512 over the salt and `Z`'s x-coordinate.

This is the **2HashDH** function, introduced by Jarecki, Kiayias and
Krawczyk (ASIACRYPT 2014) and standardized as the PRF underneath the
oblivious PRFs of [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497). RFC
9497's P-256 suite uses the same RFC 9380 hash-to-curve. With `H1` and
`H2` modelled as random oracles, `F` is a PRF under the computational
Diffie-Hellman assumption on P-256. Telling its outputs from random,
even after seeing `F` at any other salts you choose, requires computing
`k · H1(salt)` for a fresh salt from `KEK_pub` alone.

Both properties this document claims follow from that:

- **Unforgeability.** The wrapping key for any salt is an output of `F`.
  A forger who doesn't already hold that salt's output faces AES-256-GCM
  under a key indistinguishable from random, and can't make a valid tag.
- **Per-payload isolation.** Outputs at different salts are independent,
  so a key (or a `Z`) leaked for one salt reveals nothing about any
  other.

Three differences from RFC 9497, none of which changes the argument:

- **No blinding.** RFC 9497 hides the input from the key holder. Here the
  key holder is this host's own TPM, HSM or secret file, so there is
  nothing to hide from it.
- **A different finalization.** `H2` is HKDF-SHA512 over the
  x-coordinate, with the payload header in `info` (see "What else is
  bound"), instead of RFC 9497's `Finalize` hash over the full encoded
  point.
- **This library's own domain separation tag.** So its outputs don't
  match RFC 9497's test vectors and aren't meant to.

Using only the x-coordinate is the SEC1 and SP 800-56A convention for
ECDH. Since `Z` and `-Z` share an x-coordinate, it costs the reduction
at most a factor of two.

## Why the point is different for every payload

Each payload's salt gives it its own point, and so its own `Z`. A `Z` that
leaks (from a core dump, swap, a same-user debugger, or the bus of a
discrete TPM) compromises only the one salt it belongs to. With a single fixed
point per service, `Z` would be a per-service constant, and one leak would
open every payload that service ever wrapped or will wrap.

"Compromises" is deliberately stronger than "opens". The wrapping key is
`HKDF(salt, Z, info)`, a public function of `Z`, so whoever holds a leaked
`Z` can also *mint* a payload under that salt that unwraps to a DEK of
their choosing. The leak is still confined to one salt; nobody can reuse
it for another.

## What else is bound

The HKDF `info` and the AEAD's associated data both cover every byte of
the payload except the ciphertext:

- the version
- the provider tag
- the key-id length and the key-id
- the salt
- the nonce
- the ciphertext length
- the KEK fingerprint

The `info` also covers the service name, preceded by its byte length as a
little-endian u16 so the concatenation is unambiguous. So:

- **Another service:** a payload can't be replayed under a different
  service.
- **Another provider:** it can't be relabelled as another provider's.
- **Another KEK:** the derived key commits to the KEK's identity, not just
  a fingerprint that happens to be checked.

Before any ECDH or decryption, unwrap compares the stored fingerprint with
the current KEK's. A mismatch reports `HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH`
(-16), a wrong or rotated KEK, distinct from `HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED`
(-11), a tampered payload.

## The salt's three jobs

Each payload's 32-byte random salt is used in three places. That's
deliberate, and each use is safe for the salt being public, and for it
being attacker-chosen in a forged payload:

1. **The PRF input.** The salt is hashed to `H_salt`, so it selects which
   `Z`, and so which output of `F`, the payload uses. This is the job that
   matters: it is what makes `Z` unique per payload.
2. **The HKDF salt.** `HKDF-Extract(salt, Z)` is where the salt enters
   `H2`, the outer hash of `F(k, salt) = H2(salt, k · H1(salt))`, which
   takes the input as well as the point. An HKDF salt doesn't need to be
   secret (RFC 5869 §3.1). An attacker choosing it gains nothing either:
   the security argument doesn't rest on HKDF extracting randomness with
   the help of an independent salt, but on `Z` being something the
   attacker can't compute for any salt.
3. **Authenticated header data.** The salt is part of the header, and
   every header byte is in both the HKDF `info` and the AES-GCM
   associated data (see "What else is bound"). It isn't singled out. For
   key derivation this repeats job 2. Its own effect is that the AEAD
   authenticates the salt directly, although a changed salt would already
   fail, since it selects a different point and so a different key.

One field doing all three costs nothing. Separate values would add
bytes to every payload and no security, because each job needs only what
one value already gives: 256 bits from the OS random number generator,
unique per payload.

That uniqueness also explains the nonce. If two payloads ever shared a
salt they would share a wrapping key, and the random 96-bit nonce is
what would still keep AES-GCM safe. At 256 bits a repeated salt won't
happen in practice (the birthday bound is around 2^128 wraps), so in
normal operation every payload has its own key and the nonce is a second
line of defence.

## What it costs

- **Every wrap uses the KEK.** On a TPM that's one `TPM2_ECDH_ZGen` per
  wrap as well as per unwrap. Wrapping can't happen while the provider is
  unavailable.
- **No wrapping from elsewhere.** A build server can't pre-wrap a DEK for a
  host; the host wraps it locally. That matches the deployment model:
  DEKs arrive from a pipeline and are wrapped on the host that will use
  them.

## Alternatives considered

| Alternative | Forgery-resistant? | Why not chosen |
|---|---|---|
| ECIES / HPKE base mode | No | Anyone with `KEK_pub` can forge, as above |
| HPKE auth mode, or a signature on each payload | Yes | Needs a second protected key on the wrapping side, so wrapping still needs a protected key. It adds a key and a mechanism to get the same property |
| An SP 800-56A key-agreement scheme | No, or only at the cost of per-payload isolation | See "Decision: no SP 800-56A scheme" below |
| A symmetric PRF (e.g. TPM-held HMAC key) instead of ECDH | Yes | Works on TPMs and HSMs, but the macOS Secure Enclave holds only P-256 keys. ECDH is the one primitive every HKDFGuard platform's hardware offers, and its public key gives a fingerprint and a TPM Name that can be pinned. It is the route to NIST-approved functions throughout, if that is ever required (see below) |
| ECDH against a hashed point, i.e. the 2HashDH PRF (chosen) | Yes | — |

## Standards and FIPS 140

In short: **approved algorithms, in an implementation that is not FIPS 140
validated.** Don't describe a deployment as FIPS-compliant on the strength
of this library.

The algorithms, each used as its standard specifies:

| Step | Algorithm | Standard |
|---|---|---|
| `Z = KEK_priv · H_salt` | The ECC CDH primitive on P-256 | SP 800-56A Rev. 3 §5.7.1.2 |
| Key derivation | HKDF-SHA512: HMAC extract, then expand | RFC 5869; the two-step KDF of SP 800-56C Rev. 2 |
| Encryption | AES-256-GCM, 96-bit random IV, 128-bit tag | SP 800-38D (each key encrypts one DEK) |
| KEK fingerprint | SHA-256 | FIPS 180-4 |
| Salt, IV, generated DEKs | The OS random number generator (`getrandom(2)`) | -- |
| `H_salt` | RFC 9380 hash-to-curve, `P256_XMD:SHA-256_SSWU_RO_` | RFC 9380; not a NIST standard |

What isn't standard:

- **The scheme as a whole.** It is not one of SP 800-56A's key-agreement
  schemes: there is no second party and no ephemeral key, and the point the
  KEK is multiplied by comes from a hash, not from a peer. It uses the CDH
  primitive to build a PRF (see "In standard terms" above), which no NIST
  publication specifies. The argument for it is the PRF argument, not
  conformance to a NIST scheme.
- **Key wrapping.** It is not SP 800-38F key wrap (AES-KW or AES-KWP). The
  DEK is encrypted with AES-GCM, an approved AEAD, under a key used for
  that one DEK.
- **Hash-to-curve.** RFC 9380 is an IETF standard. It only produces a
  public point, from public input; no secret goes through it.

What isn't validated:

- **The software.** Hash-to-curve, HKDF, AES-GCM and SHA-256 run in this
  library, using the RustCrypto crates, which are not a FIPS 140-3
  validated cryptographic module. The external-secret and ephemeral
  providers' ECDH runs there too.
- **The hardware, partly.** On a TPM or HSM, the KEK and its ECDH stay
  inside the device, which may itself hold a FIPS 140 certificate. That
  certificate covers what the device does, not what this library does with
  the shared secret afterwards. On PKCS#11, an HSM in FIPS-approved mode
  may refuse to export the shared secret at all (see
  [configuration.md](configuration.md#pkcs11-hsm-or-smart-card)).

The individual steps are each testable by NIST's algorithm validation
program (CAVP has separate tests for the shared-secret computation,
KAS-ECC-SSC, and for HKDF, KDA), so a validated module could certify every
step even though the whole is not a named SP 800-56A scheme.

### Decision: no SP 800-56A scheme, and no FIPS claim

We looked at making the construction a NIST key-agreement scheme and
decided against it, because every scheme that fits gives up one of the two
properties this design exists for:

| SP 800-56A scheme | What it would take | What it breaks |
|---|---|---|
| C(1e,1s), One-Pass Diffie-Hellman | A fresh ephemeral key per wrap, against the KEK's public key | **Forgery resistance.** It is ECIES: anyone with the KEK's public key can mint a payload (see "Why ECIES-style wrapping is forgeable"). |
| C(0e,2s), static-static with a nonce | A second protected "wrapper" key per service | **Per-payload isolation.** `Z` is the same for every payload; the nonce only enters the KDF, so one leaked `Z` opens every payload the service ever wraps. |
| C(1e,2s), One-Pass Unified Model or MQV | An ephemeral key and a second protected static key | **Forgery resistance after a leak.** The static half of `Z` is constant: leaked once, it lets anyone forge payloads indefinitely, where today a leaked `Z` is confined to its one salt. |

All three also need the hashed point replaced by a key pair someone owns,
which is the very thing that makes forgery impossible here.

**If FIPS conformance is ever required,** the route is not key agreement
but a key-based KDF: a device-held HMAC key (`TPM2_HMAC`, or the HSM's
HMAC mechanism) as the PRF of an SP 800-108 counter-mode KDF over the salt
and header, computed inside the TPM or HSM. That keeps both properties and
uses only NIST-approved functions. It would be a new wire format and a new
KEK type for every provider (an external secret would become a symmetric
key), and the encryption and KDF glue would still have to move into a
validated module, such as OpenSSL 3's FIPS provider, before any FIPS claim.

Until then, the position is: approved algorithms, a documented composition
justified by the PRF argument above, and no claim of FIPS compliance.

## What it does not protect against

- **Someone who can use the KEK.** On a TPM host that's any process that
  can open the device and read the service's key file. Such a process can
  wrap any DEK it likes, legitimately. Against that threat, the protection
  is keeping who may use the KEK small, and `hkdfguard_open_file`'s
  refusal of key files that anyone else could have replaced.
- **Putting back an older genuine payload.** A payload carries no
  counter or epoch, so any payload this KEK ever wrapped for the service
  still unwraps, and a key file replaced with an older one is accepted.
  `hkdfguard_open_file` refuses key files that other accounts could have
  replaced, but not a rollback by the file's own owner (or root). Where it
  matters, record the payload's hash when it's deployed (the audit trail
  already logs `payload_sha256` on every unwrap) and compare it out of
  band.
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
  each step's output, so a change to any step shows up.
- **Binding:** `derive_wrapping_key_binds_every_input`, and the
  `tampered_*` tests, which change one field at a time.

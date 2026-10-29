# ADR-0001: Replace the ECDH wrapping suite with a post-quantum HMAC suite

**Status:** Accepted, implemented (payload format 1, the first release)
**Date:** 2026-10-27
**Deciders:** HKDFGuard maintainers

## Context

Before its first release, HKDFGuard wrapped every payload with the
construction described in [why-ecdh.md](../why-ecdh.md): ECDH between the
service's P-256 KEK and a point hashed from the payload's salt (the 2HashDH
PRF), then HKDF-SHA512 and AES-256-GCM.

The symmetric parts are not at risk from a quantum computer. AES-256 keeps
about 128 bits of strength against Grover's algorithm, and the SHA-2 and
HMAC constructions are unaffected. The ECDH step is. Shor's algorithm
recovers `KEK_priv` from `KEK_pub`, and with it every wrapping key the KEK
ever produced. On a TPM host, `KEK_pub` was not hard to come by: the key
file in `/var/lib/hkdfguard/tpm/` stores the key's `TPM2B_PUBLIC` in the
clear. A copy of that directory plus the stored payloads was enough to
harvest now and decrypt later.

Three further forces shaped the choice:

- **Forgery resistance must stay.** Wrapping needs the protected key, not
  only a public value; that is why ECIES and HPKE base mode were rejected
  in the first place.
- **FIPS.** The ECDH construction used approved algorithms in a
  composition that is not an approved key-establishment scheme.
- **No released payloads exist.** Only test machines held payloads, and a
  payload is only ever opened on the host that wrapped it, so there was no
  format to stay compatible with.

## Decision

1. **Replace the ECDH suite with a symmetric one, released as payload
   format 1.** The service's KEK is an HMAC-SHA-256 key held by the
   provider. The wrapping key is one block of an SP 800-108 counter-mode KDF with that HMAC as its
   PRF, computed by the provider:

   ```text
   K_wrap      = HMAC(KEK, [1]_32 || "hkdfguard-wrap-v1" || 0x00 || Context || [256]_32)
   Context     = u16_le(len(service)) || service || header
   fingerprint = HMAC(KEK, [1]_32 || "hkdfguard-kek-fingerprint-v1" || 0x00 || [256]_32)
   ```

   `header` is every payload field before the ciphertext. `K_wrap` is the
   AES-256-GCM key directly; there is no HKDF step. The associated data is
   the header followed by the fingerprint. The fingerprint is not in
   `Context`, so the provider computes both outputs in one call: one key
   load per wrap or unwrap on a TPM, as before. The wire layout is
   unchanged, so payload sizes and
   `HKDFGUARD_WRAPPED_MAX_LEN` stay the same. The longest input is 352
   bytes, under the 1024 a TPM accepts per `TPM2_HMAC` call.

2. **Remove ECDH entirely.** No suite setting in `policy.toml`, no
   version dispatch, no migration path. Nothing was released, so the new
   construction is the first release's format 1 and its labels end in
   `-v1`. Pre-release ECDH payloads also carry version 1; they fail the
   KEK fingerprint check and are never decrypted (pinned by
   `a_pre_release_ecdh_payload_fails_the_fingerprint_check`). A TPM key
   file holding an ECC key is refused with instructions to provision the
   service again.

3. **Per provider:**

   | Provider | KEK | PRF |
   |---|---|---|
   | TPM 2.0 | Keyed-hash object, `HMAC_SHA_256`, TPM-generated, `fixedTPM`, `fixedParent`, sign-only, `noDA`; the same key file format and storage root key as before. ADR-0002 adds an authValue | One-shot `TPM2_HMAC` per input, in a salted encrypted session; ADR-0002 keys it by the authValue |
   | PKCS#11 | 32-byte `CKK_GENERIC_SECRET`, generated on the token, sensitive, non-extractable, sign-only; imported keys refused via `CKA_ALWAYS_SENSITIVE` / `CKA_NEVER_EXTRACTABLE` | Single-part `C_Sign`, `CKM_SHA256_HMAC` |
   | External secret | Exactly 32 raw bytes in the mounted file | Software HMAC |
   | Ephemeral | 32 random bytes in locked memory | Software HMAC |

4. **The TPM proves itself first.** The connection self-test, already
   checking that the storage root key is reproducible, also runs a
   known-answer `TPM2_HMAC` over the longest input and compares it with
   software HMAC-SHA-256. A TPM that fails is refused.

## Options considered

### Option A: Symmetric PRF only, replacing ECDH (chosen)

| Dimension | Assessment |
|---|---|
| Quantum safety | Full: no public-key step anywhere |
| Forgery resistance | Kept: wrapping needs the HMAC key |
| FIPS path | Approved functions throughout |
| Hardware support | Every TPM 2.0 (`TPM2_HMAC` is in the core library spec), every PKCS#11 v2.20+ token. Tested, see below |
| Complexity | Lower than before: one key type per provider, no hash-to-curve, no HKDF |

**Pros:** one device call per operation; the simplest construction to
justify; fixes the FIPS obstacle and the quantum exposure together; drops
the `p256`, `elliptic-curve` and `hkdf` dependencies.
**Cons:** no public key, so the fingerprint and pinning needed new
definitions. The macOS Secure Enclave holds only P-256 keys, so this
library's construction differs from that platform's; payloads never cross
platforms, so nothing depends on them matching.

### Option B: Keep both suites, chosen by `policy.toml`

A host-wide `suite` setting, with post-quantum as the default and classical
kept for compatibility.

**Rejected** once it was clear no released payloads exist. With nothing to
stay compatible with, a second suite only adds a downgrade surface (a
policy or payload that selects the weaker format), a second key type per
provider, migration tooling, and a second construction for reviewers to
evaluate.

### Option C: Hybrid, HKDF over `Z_ecdh || T_hmac`

**Rejected.** Quantum-safe as long as the HMAC key holds, and allowed by
SP 800-133 Rev. 2 §6.3, but twice the keys and device calls to hedge
against HMAC-SHA-256 failing, which nothing currently suggests.

### Option D: ML-KEM, or another KEM

**Rejected.** Anyone with the public key can encapsulate to it, so it has
the same forgery flaw as ECIES. TPMs that support ML-KEM can't be counted
on, and a PKCS#11 token would need version 3.2.

## Evidence

All on the development host (Intel PTT firmware TPM, SoftHSM2), 2026-10-27.

**Before implementation**, a standalone probe showed both devices can do
what the design needs:

| Device | Result |
|---|---|
| TPM 2.0 | One-shot `TPM2_HMAC` matches software HMAC-SHA-256 on the PRF input shape; a TPM-generated key gives repeatable, salt-dependent output and still works after a reboot. Input limit per call: 1024 bytes |
| SoftHSM2 | `CKM_SHA256_HMAC` matches software HMAC-SHA-256; a generated key is sensitive and non-extractable. Keys must be at least 32 bytes (`CKR_KEY_SIZE_RANGE` below that) |

The same session found one hazard: the multi-command HMAC sequence
(`TPM2_HMAC_Start`, as `tpm2_hmac` uses) put this TPM into failure mode
until a reboot. One-shot `TPM2_HMAC` had no such effect, so the provider
uses only that.

**After implementation:**

- Unit and integration tests pass with default and with all features.
- The known-answer values -- fingerprint, wrapping-key block, wrapping
  key, ciphertext, whole payload -- were reproduced exactly by an
  independent implementation using Python's `hmac` module and
  pyca/cryptography (OpenSSL). The documented OpenSSL command for an
  external secret's fingerprint gives the same value.
- `scripts/native-tpm-test.sh` against the real TPM and SoftHSM2 passes in
  full: 17 TPM conformance tests (known-answer `TPM2_HMAC` at every input
  length, encrypted and plain sessions agreeing, the TPM refusing HMAC with
  the storage root key, pinning, retiring), 15 SoftHSM2 tests (standard
  HMAC-SHA-256, imported and weakly protected keys refused, a key made
  without the PIN never used), C ABI round trips with session encryption
  off and required with both Names pinned, and CLI-to-library unwrap. The
  TPM's self-test still reported success afterwards.
- Across a real reboot (`scripts/native-tpm-test.sh reboot capture`, then
  `reboot verify`), the storage root key's Name was unchanged and a DEK
  wrapped under an HMAC TPM key file before the reboot unwrapped after it.

## Consequences

**Easier:**

- Describing payloads as safe against a quantum computer, including
  payloads harvested today together with the host's key files.
- A FIPS claim: the construction uses only approved functions. The remaining work is
  moving the software crypto into a validated module and running on
  validated devices.
- Review: one construction, built from standard parts, with no
  non-standard composition to argue for.

**Harder:**

- Existing test-machine key files and payloads must be re-provisioned and
  re-wrapped. External secrets change format: 32 raw bytes instead of a
  P-256 key.
- An external secret's fingerprint can't be computed with a plain hash of
  a public key any more; the documented OpenSSL HMAC command replaces it.

**Still classical:** on a discrete TPM, session encryption salts its
sessions by ECDH to the storage root key, as the TPM specification
defines. Someone recording that bus today who can later break P-256 could
recover the wrapping keys that crossed it. Firmware and virtual TPMs have
no bus. *Superseded by [ADR-0002](0002-tpm-sessions-keyed-by-authvalue.md),
which narrows this to the provisioning command.*

## Follow-up

- Run `scripts/native-tpm-test.sh` on an AMD fTPM and on a discrete TPM
  before release.
- A FIPS claim further requires the software crypto (AES-GCM, HMAC for
  software-held keys, random numbers) to come from a validated module such
  as `aws-lc-rs` in FIPS mode or OpenSSL 3's FIPS provider, and deployment
  on FIPS-validated TPMs or HSMs. Intel PTT, AMD fTPM and SoftHSM2 are not
  validated.

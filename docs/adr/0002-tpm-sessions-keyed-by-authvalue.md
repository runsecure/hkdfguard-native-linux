# ADR-0002: Key TPM sessions by a per-service authValue, not a pinned salt key

**Status:** Accepted, implemented
**Date:** 2026-10-29
**Deciders:** HKDFGuard maintainers

## Context

On a discrete TPM, `TPM2_HMAC`'s output crosses the LPC or SPI bus. That
output is a payload's wrapping key. ADR-0001 left its protection to the
pre-existing mechanism: a session salted to the storage root key (SRK) by
one-pass ECDH, with the SRK's Name pinned in policy
(`tpm.pinned_session_salt_key_name`) and an `auto` mode that skipped
encryption for TPMs whose reported manufacturer has no external bus.

A security review on 2026-10-29 found that mechanism no longer fit:

- **The pin was checked against the wrong response.** The provider pinned
  the Name from `TPM2_ReadPublic`. ESAPI encrypts the salt to the public
  area it cached from `TPM2_CreatePrimary`, and `TPM2_ReadPublic` never
  updates that cache (tpm2-tss: `Esys_CreatePrimary_Finish` stores
  `outPublic`; `iesys_compute_encrypted_salt` reads it;
  `Esys_ReadPublic_Finish` only returns values). An interposer could answer
  `TPM2_CreatePrimary` with its own key and pass `TPM2_ReadPublic` through:
  the pin matched, and every salt went to the interposer.
- **Authenticity rested on it too.** An interposer who knows a session's
  key can forge `TPM2_HMAC`'s response during a wrap. The fingerprint
  passes, and the payload is sealed under a key the interposer chose.
- **One quantum break opened everything.** Every salt was encrypted to one
  static P-256 key, whose public half is in policy. Breaking it once
  recovered every recorded session.
- **`auto` decided from a forgeable string.** The manufacturer is read over
  the bus being protected.

## Decision

1. **Every service key gets a random 32-byte authValue**, set by
   `TPM2_Create` and kept beside the key file as `<service>.tpmauth`. Its
   last byte is never zero, because the TPM drops trailing zeros from an
   authValue. The public area, and so the key's Name and pin, don't change.
   The key file omits `emptyAuth`; a file carrying it is refused.
2. **Every `TPM2_HMAC` runs in a session that authorizes the key.** ESAPI
   and the TPM key the session's parameter encryption with
   `sessionKey || authValue`, and its response HMAC with the same value,
   unless the session is bound to that object (TPM 2.0 Part 1 §19.6 and
   §21; tpm2-tss `iesys_compute_session_value`). The session is never bound.
   Without the authValue, nobody can read `outHMAC` or forge it.
3. **The session stays salted to the SRK, as a second layer.** An attacker
   then needs the authValue and also a P-256 break or a man-in-the-middle
   position on the SRK.
4. **`TPM2_Create` always runs in a salted, encrypting session.** It sends
   the authValue, so it can't be protected by it. This is the one point
   where the SRK pin is load-bearing.
5. **The SRK is checked against `TPM2_CreatePrimary`'s own response**: the
   template, the Name ESAPI cached, and the pin.
6. **`tpm.session_encryption` is `"on"` (the default) or `"off"`.** `"auto"`
   and `"required"` are refused. `"off"` uses an unsalted session with no
   encryption attributes; its responses are still authenticated by the
   authValue. It is for test harnesses.
7. **The authValue file is a second access control.** Written
   `root:<key-dir group> 0440`, like the key file. An administrator can
   give it the service's own group, so other services in the key
   directory's group can't use that key.

## Options considered

### Option A: Fix the pin and keep the design

Check the pin against `TPM2_CreatePrimary`'s output. **Rejected as the
whole answer**, though done as part of the chosen option. It closes the
man-in-the-middle, but every session still rests on one static P-256 key,
and `auto` still trusts a forgeable string.

### Option B: A host-side secret mixed into the wrapping key in software

`K_wrap = HMAC(host_secret, TPM_output)`. **Rejected.** The secret file
is exposed exactly as an authValue file would be, and it stops a
recorded or substituted output from yielding a known key. But the TPM's
response stays unauthenticated, so a garbled one silently seals a DEK
that no later unwrap can open. It also changes the wrapping construction
ADR-0001 standardised, adding a software HMAC step after the device.

### Option C: A per-service authValue (chosen)

Symmetric, so quantum-safe; makes responses authenticated; needs no
trusted public key after provisioning; uses only TPM 2.0 core features
every TPM has.

### Option D: A policy session (`TPM2_PolicySecret` or `TPM2_PolicyAuthValue`)

**Rejected.** The same secret is needed, with more commands per call and a
key template whose `authPolicy` would have to be pinned too.

## Consequences

**Easier:**

- Bus protection on every TPM, with nothing to configure and no guess
  about whether the TPM has a bus.
- Responses are authenticated, so a wrapping key can't be substituted.
- Per-service access control without per-service directories.

**Harder:**

- **A second file per service.** Losing it loses the KEK, so it is backed
  up with the key file. A key file without one is an error, never "not
  provisioned".
- **Re-provisioning.** Key files from before this change carry
  `emptyAuth` and are refused. Only test machines hold any.
- **An extra `TPM2_StartAuthSession` per call**, salted, so one ECDH in the
  TPM.

**Still classical:** provisioning's `TPM2_Create`. Someone who records it,
records later sessions, and later breaks P-256 recovers that key's
authValue and the wrapping keys in those sessions. Pinning the SRK before
provisioning defeats an active interposer at that moment. Re-provisioning
issues a new authValue. Firmware and virtual TPMs have no bus.

## Follow-up

- Run `scripts/native-tpm-test.sh` on a discrete TPM.
- Measure the added session's latency on each TPM the library ships for.

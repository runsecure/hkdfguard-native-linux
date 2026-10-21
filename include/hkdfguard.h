/*
 * hkdfguard.h -- Stable C ABI for hkdfguard-native-linux.
 *
 * Wraps and unwraps 32-byte Data Encryption Keys (DEKs) under a persistent,
 * per-service Key Encryption Key (KEK), using the strongest available
 * provider on the host (TPM2 > PKCS#11 > external secret > ephemeral).
 * See the crate's provider/ module docs for the protocol
 * (ECDH P-256 against a per-payload hashed point -> HKDF-SHA512 -> AES-256-GCM) and
 * provider details. A wrapped payload can only be created, and only be
 * opened, on the host holding the KEK: it is not possible to pre-wrap a
 * DEK for a host from elsewhere.
 *
 * The wrapped payload is opaque: size buffers with HKDFGUARD_WRAPPED_MAX_LEN
 * (or a size probe) and never parse it. It opens only on the host whose KEK
 * wrapped it.
 *
 * No Rust type, TPM handle, OpenSSL structure, or PKCS#11 object ever
 * crosses this boundary. No exception/panic ever crosses this boundary --
 * every function below returns a plain status code. (That relies on the
 * library being built with panic = "unwind", as every packaged and
 * released build is. A Rust program that links the crate into a binary
 * built with panic = "abort" gets a process abort instead of
 * HKDFGUARD_ERR_INTERNAL_ERROR: still never undefined behavior, but not a
 * status code either.)
 */

#ifndef HKDFGUARD_H
#define HKDFGUARD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Required length of a DEK, in bytes. */
#define HKDFGUARD_DEK_LEN 32

/* Largest wrapped payload hkdfguard_wrap_dek / hkdfguard_generate_and_wrap_dek
 * can produce, for any provider and any valid service name. A buffer of this
 * size never needs a retry. */
#define HKDFGUARD_WRAPPED_MAX_LEN 276

/*
 * Status codes returned by every hkdfguard_* function.
 *
 * This table is shared by all three platform implementations of this C ABI
 * (Linux, Windows, macOS): a name always has the same number everywhere, and
 * every platform's header defines every code, including ones that platform
 * never returns (marked below). Codes are grouped in bands:
 *
 *      0 ..   -8   general
 *     -9           policy
 *    -10 ..  -15   wrapped payload
 *    -16 ..  -31   KEK
 *    -32 ..  -63   key file (hkdfguard_open_file); -40..-63 reserved
 *    -64 ..  -79   Windows-specific
 *    -80 ..  -95   Linux-specific
 *    -96 .. -111   macOS-specific
 *
 * Every code in a platform band refines one common code, named in its
 * comment: a caller that doesn't care about the detail can treat it as that
 * common code. Numbers not listed are reserved: a number is never reused
 * for a different meaning.
 */

/* General */
#define HKDFGUARD_OK 0
#define HKDFGUARD_ERR_INVALID_ARGUMENT (-1)     /* null pointer, wrong DEK length, negative capacity, etc. -- never a service-string problem, see HKDFGUARD_ERR_INVALID_SERVICE_NAME */
#define HKDFGUARD_ERR_BUFFER_TOO_SMALL (-2)     /* `out` is too small; *out_len says what to retry with */
#define HKDFGUARD_ERR_PROVIDER_UNAVAILABLE (-3) /* no KEK provider could be reached at all */
#define HKDFGUARD_ERR_PROVIDER_ERROR (-4)       /* a provider was reachable but failed to create, load, or use the KEK */
#define HKDFGUARD_ERR_CRYPTO_ERROR (-5)         /* a cryptographic operation failed for a reason other than authentication: RNG, hash-to-curve, HKDF, or encryption */
#define HKDFGUARD_ERR_INTERNAL_ERROR (-6)       /* an unexpected internal failure (a caught panic) */
/* -7 is reserved and never returned. A `service` string that isn't valid
 * UTF-8 is one more way for it to be invalid, reported as
 * HKDFGUARD_ERR_INVALID_SERVICE_NAME below. */
#define HKDFGUARD_ERR_INVALID_SERVICE_NAME (-8) /* service is null, empty, not valid UTF-8, over 128 bytes, contains a character other than an ASCII letter, digit, or '.', starts with '.', or contains ".." */

/* Policy */
#define HKDFGUARD_ERR_POLICY_INVALID (-9)       /* the policy file can't be used: unparsable, an invalid or contradictory setting, insecure ownership/permissions of it or of any directory above it (writable by group/others, sticky /tmp-style included), or it requires a provider this build lacks */

/* Wrapped payload */
#define HKDFGUARD_ERR_PAYLOAD_MALFORMED (-10)   /* structurally invalid: truncated, trailing bytes, unknown provider type, or a field length no wrap produces */
#define HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED (-11) /* AES-GCM authentication failed: tampered, wrong service, or wrong KEK */
#define HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED (-12) /* unknown payload version */
/* -13..-15 reserved. */

/* KEK */
#define HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH (-16) /* the payload was wrapped under a different KEK than `service` resolves to now */
#define HKDFGUARD_ERR_KEK_NOT_FOUND (-17)       /* no KEK exists yet for this service; call hkdfguard_create_kek first */
#define HKDFGUARD_ERR_KEK_ACCESS_DENIED (-18)   /* this process may not do this to the KEK: on Linux, under the production security model, create a KEK that doesn't exist yet (or retire one) without being root */
#define HKDFGUARD_ERR_KEK_INVALID (-19)         /* the KEK exists but is corrupt or has an invalid ACL -- not currently returned on Linux */
#define HKDFGUARD_ERR_PROCESS_HARDENING_FAILED (-20) /* hkdfguard_harden_process could not disable core dumps or ptrace access, or (with HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE) the process can still be debugged by its own user */
/* -21..-31 reserved. */

/* Key file: hkdfguard_open_file's refusals. */
#define HKDFGUARD_ERR_FILE_NOT_FOUND (-32)      /* key file, or a directory in its path, does not exist */
#define HKDFGUARD_ERR_FILE_ACCESS_DENIED (-33)  /* the OS refused to let this process open the key file (e.g. EACCES) */
#define HKDFGUARD_ERR_FILE_IO (-34)             /* key file is not a regular file, or reading it failed */
#define HKDFGUARD_ERR_FILE_TOO_SHORT (-35)      /* key file is shorter than a wrapped DEK, or than its own header declares */
#define HKDFGUARD_ERR_FILE_TOO_LONG (-36)       /* key file is longer than a wrapped DEK, or than its own header declares */
#define HKDFGUARD_ERR_FILE_PLAINTEXT_KEY (-37)  /* key file looks like an UNWRAPPED DEK (32 raw bytes, or its base64 or hex): treat as a key exposure */
#define HKDFGUARD_ERR_FILE_MALFORMED (-38)      /* key file is the right length but not a well-formed wrapped DEK */
#define HKDFGUARD_ERR_FILE_UNTRUSTED (-39)      /* key file, or a directory deciding what its path names, is owned by someone the security model doesn't trust, or writable by someone else (sticky, /tmp-style, included): someone else could have replaced it */
/* -40..-63 reserved for future common codes. */

/* Windows-specific (-64..-79). Not returned on Linux. */
#define HKDFGUARD_ERR_WIN_GROUP_INVALID (-64)   /* refines HKDFGUARD_ERR_POLICY_INVALID; Windows only */

/* Linux-specific (-80..-95). */
#define HKDFGUARD_ERR_LINUX_GROUP_INVALID (-80) /* refines HKDFGUARD_ERR_POLICY_INVALID: a deployer group (policy deployer_groups, or hkdfguard-deployers) doesn't exist, is over-broad, or can't be looked up; Linux only */

/* macOS-specific (-96..-111). Each refines HKDFGUARD_ERR_PROVIDER_ERROR. Not returned on Linux. */
#define HKDFGUARD_ERR_MAC_ACCESS_CONTROL_CREATION_FAILED (-96) /* macOS only */
#define HKDFGUARD_ERR_MAC_KEY_GENERATION_FAILED (-97)          /* macOS only */
#define HKDFGUARD_ERR_MAC_KEYCHAIN_WRITE_FAILED (-98)          /* macOS only */
#define HKDFGUARD_ERR_MAC_KEK_VERIFICATION_FAILED (-99)        /* macOS only */
#define HKDFGUARD_ERR_MAC_KEYCHAIN_READ_FAILED (-100)          /* macOS only */

/*
 * Opt-in hardening of the *calling process* against memory disclosure:
 * disables core dumps (RLIMIT_CORE = 0, soft and hard) and, on Linux,
 * calls prctl(PR_SET_DUMPABLE, 0), which also stops other non-root
 * processes of the same user from ptrace-attaching or reading
 * /proc/<pid>/mem. Keys and DEKs that pass through this library then
 * can't be recovered from a crash dump or a same-user debugger.
 *
 * It changes process-wide state, so debuggers and crash reporters stop
 * working for the process -- hence opt-in. Call once, early in startup,
 * and after any privilege change (the kernel resets the dumpable flag
 * when credentials change). Root and CAP_SYS_PTRACE are unaffected; that
 * is host configuration. Idempotent. The library applies it itself before
 * creating an ephemeral KEK, whose only protection is process memory.
 *
 * Same as hkdfguard_harden_process_with_flags(0).
 *
 * Returns HKDFGUARD_OK, or HKDFGUARD_ERR_PROCESS_HARDENING_FAILED.
 */
int hkdfguard_harden_process(void);

/*
 * Flags for hkdfguard_harden_process_with_flags. Shared by every platform:
 * a flag has the same bit everywhere, and every platform accepts every
 * flag defined here.
 *
 * HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE: fail with
 *     HKDFGUARD_ERR_PROCESS_HARDENING_FAILED unless no other process of the
 *     same user can attach a debugger to, or inject code into, this
 *     process.
 *       macOS: that depends on the host executable's code signature --
 *         Hardened Runtime, without the get-task-allow entitlement (which
 *         Xcode adds to Debug builds) or ones that allow DYLD_* injection.
 *         The library can check the signature but not change it. Without
 *         this flag a weak signature is logged as a warning and the call
 *         still succeeds, so unsigned development hosts (python, dotnet,
 *         Xcode Debug builds) work; pass it in release builds of a signed
 *         app to make a weak signature a startup failure.
 *       Linux: PR_SET_DUMPABLE already guarantees it whatever the binary,
 *         so the flag is accepted and adds no further check.
 */
#define HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE 0x1u

/*
 * hkdfguard_harden_process, with `flags` -- a bitwise OR of
 * HKDFGUARD_HARDEN_* flags, or 0 -- choosing how strict it is.
 *
 * Returns HKDFGUARD_OK; HKDFGUARD_ERR_INVALID_ARGUMENT if `flags` has a
 * bit this library doesn't know (checked before anything is changed, so a
 * newer flag is never silently ignored); or
 * HKDFGUARD_ERR_PROCESS_HARDENING_FAILED.
 */
int hkdfguard_harden_process_with_flags(unsigned int flags);

/*
 * Ensures a persistent KEK exists for `service`, creating one (on the
 * strongest available, policy-allowed provider) if it does not already.
 * Idempotent: safe to call again for a `service` that already has one --
 * this just confirms it's still there, doesn't rotate or recreate it.
 *
 * This is the *only* way a KEK ever gets created: hkdfguard_wrap_dek and
 * hkdfguard_generate_and_wrap_dek both return HKDFGUARD_ERR_KEK_NOT_FOUND
 * if called before this for a given `service`.
 *
 * TPM2 exception: the TPM derives a KEK for any service on demand, so by
 * default every service already "exists" there and this call has nothing
 * to create. With `tpm.require_pinned_names: true` in the policy file, a
 * service exists on the TPM only if policy pins its Name; for an unpinned
 * service this call fails and logs (at error level) the policy entry to
 * add, ready to paste. Provisioning on TPM is that root-owned policy
 * edit.
 *
 * Under the production security model (the default; see
 * hkdfguard_security_model) only root creates a KEK: any other caller gets
 * the existing KEK -- so an application may still call this at startup --
 * or HKDFGUARD_ERR_KEK_ACCESS_DENIED if there is none. An ephemeral KEK is
 * the exception: it exists only in this process, so this process makes it.
 *
 * Audited: creating a KEK, every wrap and unwrap, and the failures an
 * administrator needs to see are written to syslog (facility authpriv,
 * tag hkdfguard) with the Windows build's event IDs - see README.md,
 * "Audit trail".
 *
 * Deliberately slow: this, hkdfguard_kek_exists and hkdfguard_kek_fingerprint
 * are setup calls, meant to run once per application startup, and each takes at least
 * `startup_behavior.setup_min_delay_ms` (policy file; default 1000 ms)
 * of wall-clock time whatever its outcome, and they are serialized with
 * each other across threads. Do not call them per request; call once at
 * startup and then use hkdfguard_wrap_dek / hkdfguard_unwrap_dek.
 * Argument errors (bad pointer or service name) return immediately.
 *
 * service:  see hkdfguard_wrap_dek below.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 */
int hkdfguard_create_kek(const char* service);

/*
 * Reports whether a persistent KEK already exists for `service`, without
 * creating one. Subject to the same startup latency floor and
 * serialization as hkdfguard_create_kek above; "exists" and "doesn't
 * exist" take the same time. On TPM2, always 1 when the TPM is reachable
 * unless policy sets `tpm.require_pinned_names` (see hkdfguard_create_kek).
 *
 * service:  see hkdfguard_wrap_dek below.
 * exists:   out-parameter; on HKDFGUARD_OK, set to 1 if a KEK exists for
 *           `service`, 0 otherwise (including "chain fully walked and
 *           nothing has one yet" -- call hkdfguard_create_kek to
 *           provision one). Untouched on any other return code.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 */
int hkdfguard_kek_exists(const char* service, int* exists);

/*
 * Writes the 32-byte fingerprint of the KEK `service` currently resolves
 * to: SHA-256 of its public key, SEC1-uncompressed (0x04 || X || Y) -- the
 * same value every payload wrapped under it carries, and that
 * hkdfguard_unwrap_dek checks. Public-key material, not a secret. Lets an
 * operator record which KEK a service uses after provisioning (the CLI's
 * `provision` prints it), and confirm it before retiring it (`retire`
 * requires it). Never creates a KEK: HKDFGUARD_ERR_KEK_NOT_FOUND if none
 * exists.
 *
 * A setup call, like hkdfguard_kek_exists: whether it finds a KEK answers
 * the same question, so it is subject to the same startup latency floor
 * and serialization as hkdfguard_create_kek above. Argument errors and the
 * size probe return immediately.
 *
 * service:  see hkdfguard_wrap_dek below.
 * out:      receives the 32 bytes on success. May be NULL only for a size
 *           probe (*out_len == 0).
 * out_len:  on input, the capacity of `out`. Set to 32 on success, and to
 *           32 on HKDFGUARD_ERR_BUFFER_TOO_SMALL (capacity under 32;
 *           nothing written). Untouched on any other return code, as is
 *           `out`.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 */
int hkdfguard_kek_fingerprint(const char* service, uint8_t* out, int* out_len);

/*
 * Wraps a 32-byte DEK under the persistent KEK identified by `service`.
 * The KEK must already exist -- see hkdfguard_create_kek above; this
 * never creates one itself.
 *
 * The wrapped payload embeds a 32-byte SHA-256 fingerprint of this KEK's
 * public key, which hkdfguard_unwrap_dek checks before decrypting -- see
 * its own doc comment below.
 *
 * service:  NUL-terminated UTF-8 string, 1..=128 bytes. The logical,
 *           cross-platform identity of the KEK (e.g. "com.company.orders").
 *           Only ASCII alphanumeric characters and '.' are allowed, and it
 *           may not start with '.' or contain two consecutive dots (".."),
 *           so it can never name ".", "..", or a hidden file. NULL, an
 *           empty string, a string over 128 bytes, non-UTF-8 bytes, a
 *           disallowed character, or a dot rule violation all return
 *           HKDFGUARD_ERR_INVALID_SERVICE_NAME. Case-insensitive: normalized
 *           to lowercase internally, so e.g. "Com.Example.Orders" and
 *           "com.example.orders" always resolve to the same KEK. Distinct
 *           (after normalization) service strings always resolve to
 *           different KEKs.
 * dek:      pointer to exactly `dek_len` bytes to wrap.
 * dek_len:  must be exactly HKDFGUARD_DEK_LEN (32); any other value
 *           returns HKDFGUARD_ERR_INVALID_ARGUMENT.
 * out:      buffer to receive the wrapped payload. May be NULL only if
 *           *out_len is 0 (to probe the required size); a NULL `out` with
 *           a positive *out_len returns HKDFGUARD_ERR_INVALID_ARGUMENT.
 * out_len:  in: capacity of `out` in bytes.
 *           out: on HKDFGUARD_OK, the number of bytes written to `out`.
 *                on HKDFGUARD_ERR_BUFFER_TOO_SMALL, a capacity to retry
 *                with; `out` is left untouched. A capacity too small for
 *                any payload (including the 0 of a size probe) is
 *                answered at once, without reaching a provider, with
 *                HKDFGUARD_WRAPPED_MAX_LEN; otherwise the exact length.
 *                A buffer of HKDFGUARD_WRAPPED_MAX_LEN bytes always fits.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 */
int hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek,
    int dek_len,
    uint8_t* out,
    int* out_len);

/*
 * Unwraps a payload previously produced by hkdfguard_wrap_dek for the same
 * `service`, recovering the original 32-byte DEK.
 *
 * Before attempting any decryption, checks the wrapped payload's embedded
 * KEK fingerprint against the public key of the KEK `service` currently
 * resolves to, failing fast with HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH
 * (-16) if they don't match -- this specifically means "wrong/rotated KEK,"
 * as opposed to HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED, which means "right KEK,
 * but the payload itself is tampered or otherwise unauthenticated." A
 * payload that doesn't parse at all is HKDFGUARD_ERR_PAYLOAD_MALFORMED, and
 * one with a version this library doesn't know is
 * HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED; both are reported before any provider
 * is reached.
 *
 * service:      must match the value used when the payload was wrapped
 *                (case-insensitively -- see hkdfguard_wrap_dek); any other
 *                mismatch is indistinguishable from tampering and returns
 *                HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED. An invalid service string (see
 *                hkdfguard_wrap_dek) returns HKDFGUARD_ERR_INVALID_SERVICE_NAME.
 * wrapped:       pointer to the wrapped payload bytes.
 * wrapped_len:   length of `wrapped` in bytes.
 * out:           buffer to receive the recovered 32-byte DEK. May be the
 *                same buffer as `wrapped` (or overlap it): `wrapped` is
 *                read in full before anything is written to `out`.
 * out_len:       in: capacity of `out` in bytes.
 *                out: on HKDFGUARD_OK, always HKDFGUARD_DEK_LEN (32).
 *                     on HKDFGUARD_ERR_BUFFER_TOO_SMALL, the required
 *                     capacity (HKDFGUARD_DEK_LEN), reported before the
 *                     payload is even parsed -- no provider is reached.
 *
 * On ANY non-OK return -- including HKDFGUARD_ERR_INTERNAL_ERROR -- every
 * byte of the caller's originally-declared `out` capacity is zeroed before
 * returning, so no partial or stale key material is ever left in `out`.
 * The one exception is `out_len == NULL`: with no declared capacity there
 * is nothing that can safely be written, so `out` is left untouched.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 */
int hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped,
    int wrapped_len,
    uint8_t* out,
    int* out_len);

/*
 * Generates a fresh, cryptographically random 32-byte DEK and immediately
 * wraps it under the persistent KEK identified by `service`, in one call --
 * for callers that want a brand new Ephemeral Data Protection Key without
 * having to source their own randomness.
 *
 * The newly generated plaintext DEK never crosses this ABI boundary: it is
 * zeroed internally the instant it has been wrapped, before this function
 * returns. To recover it later, unwrap the resulting payload via
 * hkdfguard_unwrap_dek, passing the same `service`.
 *
 * service:  see hkdfguard_wrap_dek.
 * out:      as for hkdfguard_wrap_dek.
 * out_len:  as for hkdfguard_wrap_dek. A DEK generated by a call that
 *           returns HKDFGUARD_ERR_BUFFER_TOO_SMALL is discarded; the retry
 *           generates a new one. Use a buffer of HKDFGUARD_WRAPPED_MAX_LEN
 *           bytes to never need a retry.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 */
int hkdfguard_generate_and_wrap_dek(
    const char* service,
    uint8_t* out,
    int* out_len);

/* Values of hkdfguard_security_model's *out_model: the Windows build's. */
#define HKDFGUARD_SECURITY_MODEL_PRODUCTION 0
#define HKDFGUARD_SECURITY_MODEL_DEVELOPER  1

/*
 * Reports the security model in force and whether this process may persist
 * key files under it. The Windows build has the same function.
 *
 * The model is the top-level policy setting
 *
 *     security_model = "production"   # or "developer"
 *
 * in /etc/hkdfguard/policy.toml. Absent -- or no policy file at all --
 * means HKDFGUARD_SECURITY_MODEL_PRODUCTION: this is a production install
 * unless an administrator says otherwise. Any other value makes the policy
 * invalid, and every call fails with HKDFGUARD_ERR_POLICY_INVALID. It
 * decides:
 *
 *   Who may create or retire a KEK. Production: root (see
 *     hkdfguard_create_kek). Developer: anyone who can reach the provider.
 *   Whose key files hkdfguard_open_file trusts. Production: root and the
 *     deployers -- direct members of the group hkdfguard-deployers (the
 *     packages create it) and of each group the policy lists in
 *     `deployer_groups = ["..."]` (none of them over-broad) -- and a
 *     deployer group may hold write access to a key file or its folders.
 *     The calling account is trusted only if it is a deployer itself, so an
 *     application that unwraps, and wraps ephemeral keys in memory, cannot
 *     persist a key file its own service would accept. Developer: root and
 *     the calling user, and no group (the rule before security models).
 *
 * Wrapping and unwrapping are the same in both models: any process the
 * provider lets use the KEK may do either, in memory.
 *
 * out_model               - receives HKDFGUARD_SECURITY_MODEL_*.
 * out_may_write_key_files - receives 1 if a key file written by this
 *                           process (owned by its effective uid) would be
 *                           trusted under that model, else 0.
 *
 * Returns HKDFGUARD_OK; HKDFGUARD_ERR_INVALID_ARGUMENT for a NULL pointer;
 * HKDFGUARD_ERR_POLICY_INVALID if the policy can't be used; or
 * HKDFGUARD_ERR_LINUX_GROUP_INVALID for a deployer group that doesn't
 * exist, is over-broad (root, users, wheel, sudo, adm, staff, ...), or
 * can't be looked up. Both outputs are left unchanged on failure.
 */
int hkdfguard_security_model(
    int* out_model,
    int* out_may_write_key_files);

/*
 * Whether hkdfguard_open_file, under the security model in force (see
 * hkdfguard_security_model), trusts `principal` -- "uid:<n>" for a user,
 * "gid:<n>" for a group, <n> in decimal -- to own a key file or a folder
 * above one (a uid), or to hold write access to one through its group (a
 * gid). Lets a tool that prepares or writes key files check a folder
 * against the exact rule the library reads by. The Windows build's
 * function of the same name takes a SID string instead.
 *
 * Returns HKDFGUARD_OK with *out_trusted set to 1 or 0;
 * HKDFGUARD_ERR_INVALID_ARGUMENT for a NULL pointer or a string of any
 * other form; or HKDFGUARD_ERR_POLICY_INVALID /
 * HKDFGUARD_ERR_LINUX_GROUP_INVALID as hkdfguard_security_model.
 * *out_trusted is left unchanged on failure.
 */
int hkdfguard_key_file_principal_trusted(
    const char* principal,
    int* out_trusted);

/*
 * Reads a wrapped-key file -- one written by `hkdfguard wrap`,
 * or the output of hkdfguard_wrap_dek saved as-is -- into `out`, exactly as
 * stored, after checking that it is a complete, well-formed wrapped DEK.
 * Never unwraps: nothing is decrypted, no provider is reached and no KEK is
 * opened, so this needs only read access to the file. Pass the result to
 * hkdfguard_unwrap_dek.
 *
 * path:     NUL-terminated path, at most PATH_MAX (4096) bytes including the
 *           terminator. Symlinks are followed. Must name a regular file:
 *           directories, FIFOs and devices are refused before anything is
 *           read (a FIFO never blocks the call). The file must be owned by
 *           someone the security model trusts -- under the production
 *           model (the default), root or a deployer; under the developer
 *           model, root or the calling user (see hkdfguard_security_model)
 *           -- and must not be writable by anyone else: not by others, and
 *           by its group only if that is a deployer group (production
 *           only). HKDFGUARD_ERR_FILE_UNTRUSTED otherwise: a
 *           wrapped DEK is ciphertext, but someone who can replace the file
 *           and can wrap under the service's KEK could plant a DEK they
 *           know. The same goes for the directories that decide what `path`
 *           names -- the one holding the opened file and the one `path`
 *           names it in (where a symlink lives), each up to `/`: owned by
 *           someone trusted, and not writable by anyone else
 *           -- sticky or not, at any level: a key file anywhere under
 *           /tmp, /var/tmp, /dev/shm or any other sticky, world-writable
 *           directory is refused, however private the directories beneath
 *           it; HKDFGUARD_ERR_FILE_UNTRUSTED otherwise. A directory on a
 *           read-only mount counts as unwritable whatever its mode, so a
 *           Kubernetes Secret or ConfigMap volume (1777, read-only)
 *           passes. The CLI writes key files 0600, and refuses to write
 *           one into a folder this check would refuse -- or at all, under
 *           the production model, unless it runs as root or a deployer.
 * out:      buffer to receive the wrapped payload. May be NULL only if
 *           *out_len is 0 (to probe the size).
 * out_len:  in: capacity of `out` in bytes.
 *           out: on HKDFGUARD_OK, the number of bytes read (the file's
 *                length, 132..=HKDFGUARD_WRAPPED_MAX_LEN).
 *                on HKDFGUARD_ERR_BUFFER_TOO_SMALL, a capacity to retry
 *                with: HKDFGUARD_WRAPPED_MAX_LEN for a capacity too small
 *                for any payload (answered without opening the file),
 *                otherwise the file's exact length.
 *                Left unchanged on every other failure, as with
 *                hkdfguard_wrap_dek and hkdfguard_unwrap_dek.
 *           A buffer of HKDFGUARD_WRAPPED_MAX_LEN bytes always fits.
 *
 * The file's length is checked against the payload's own header (the
 * header declares the payload's exact length):
 *   HKDFGUARD_ERR_FILE_PLAINTEXT_KEY - the file is 32 bytes (the size of an
 *       UNWRAPPED DEK), or is 32 bytes written as text -- base64 (standard
 *       or URL-safe, padded or not; the CLI's DEK input is standard base64)
 *       or hex -- with any surrounding whitespace. Most likely the plaintext key
 *       saved where its wrapped form belongs: treat it as a key exposure. A
 *       32-byte file is refused from its size alone, normally without being
 *       read (one rewritten mid-call is read, then refused on its contents).
 *   HKDFGUARD_ERR_FILE_TOO_SHORT - shorter than the smallest wrapped DEK, or
 *       than its header declares (e.g. a truncated copy). Includes empty.
 *   HKDFGUARD_ERR_FILE_TOO_LONG - longer than HKDFGUARD_WRAPPED_MAX_LEN, or
 *       than its header declares (e.g. data appended).
 *   HKDFGUARD_ERR_FILE_MALFORMED - an unknown version or provider, or a
 *       key-id or ciphertext length no wrap produces.
 * HKDFGUARD_ERR_FILE_NOT_FOUND, HKDFGUARD_ERR_FILE_ACCESS_DENIED (the OS
 * refused the open, e.g. EACCES) and HKDFGUARD_ERR_FILE_IO report why the
 * file couldn't be opened or read; HKDFGUARD_ERR_FILE_UNTRUSTED, that it
 * could be, but failed the ownership/permission checks above.
 * HKDFGUARD_ERR_POLICY_INVALID and HKDFGUARD_ERR_LINUX_GROUP_INVALID, that
 * whose files to trust can't be decided (see hkdfguard_security_model).
 *
 * On any failure, every byte of the caller's declared `out` capacity is
 * zeroed (unless `out_len` is NULL: then nothing is written).
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code --
 * HKDFGUARD_ERR_INVALID_ARGUMENT for a NULL or empty `path`, a `path` with
 * no terminator within PATH_MAX bytes, a NULL `out_len`, a negative
 * capacity, or a NULL `out` with a positive capacity.
 */
int hkdfguard_open_file(
    const char* path,
    uint8_t* out,
    int* out_len);

#ifdef __cplusplus
}
#endif

#endif /* HKDFGUARD_H */

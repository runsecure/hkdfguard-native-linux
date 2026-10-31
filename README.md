# hkdfguard-native-linux

Linux implementation of HKDFGuard: a stable C ABI for wrapping/unwrapping
32-byte Data Encryption Keys (DEKs) under a persistent, per-service Key
Encryption Key (KEK), using the strongest KEK backing available on the
host. A wrapped payload pertains only to the host that wrapped it: it is
only ever opened there, never on another host or by another
implementation.

```
HMAC-SHA-256 KEK  ->  SP 800-108 counter-mode KDF (per payload)  ->  AES-256-GCM
```

A wrapped payload can only be **created** and **opened** on the host that
holds the KEK. Each service's KEK is a 256-bit HMAC-SHA-256 key that never
leaves the TPM, HSM, or root-owned secret file. For each payload the
provider computes one block of the NIST SP 800-108 counter-mode KDF, with
HMAC-SHA-256 as the PRF:

```
K_wrap  = HMAC(KEK, [1]_32 || "hkdfguard-wrap-v1" || 0x00 || Context || [256]_32)
Context = len(service)_16le || service || header
```

where `header` is every payload field before the ciphertext (version,
provider tag, key ID, the random 32-byte salt, the nonce and the
ciphertext length). `K_wrap` is the AES-256-GCM key directly. There is no
public key anywhere in wrapping, so producing a valid payload requires the
KEK itself. Because the salt is in the KDF context, every payload has its
own wrapping key: capturing one `K_wrap` (core dump, swap, a discrete TPM's
bus) opens exactly that one payload, not every payload the service has
ever wrapped.

There is no discrete-log or factoring step for a quantum computer to
attack; Grover's algorithm only halves the strength of a symmetric key, and
256-bit keys keep about 128 bits. Every function is NIST-approved
(HMAC-SHA-256, FIPS 198-1; the KDF, SP 800-108; AES-256-GCM, SP 800-38D),
but the library is **not** FIPS 140 validated: its software crypto is
RustCrypto, not a validated module, and neither Intel PTT, AMD fTPM nor
SoftHSM2 is a validated device. See [docs/why-hmac-prf.md](docs/why-hmac-prf.md)
for the full rationale (and
[docs/adr/0001-post-quantum-wrapping-suite.md](docs/adr/0001-post-quantum-wrapping-suite.md)
for the decision record), and note the consequence: a build server
**cannot** pre-wrap a DEK for a host. DEKs are delivered to the host and
wrapped there.

Wire format version 1. (Payloads from pre-release builds, which used an
ECDH construction under the same version number, fail the KEK fingerprint
check and are never decrypted.) The header is bound into the KDF context, and the AEAD's
associated data is the header plus the KEK fingerprint -- every byte of a
payload except the ciphertext -- so the `provider_type` tag and the
fingerprint are authenticated rather than merely present. The fingerprint,
`HMAC(KEK, [1]_32 || "hkdfguard-kek-fingerprint-v1" || 0x00 || [256]_32)`,
is public, the same for every payload a KEK wraps, and reveals nothing
about the KEK; unwrap checks it before decrypting. The provider computes
the fingerprint and the wrapping key in one call.

Treat a wrapped payload as opaque bytes: size buffers with
`HKDFGUARD_WRAPPED_MAX_LEN` or a size probe, and never parse one.

## Documentation

For installing, configuring and using HKDFGuard on a host:

- [Installation](docs/installation.md): packages, standalone tarball, container overlay, verifying downloads
- [Configuration](docs/configuration.md): `/etc/hkdfguard/policy.toml`, setting up each provider, example policies, permissions
- [Usage](docs/usage.md): the deployment workflow, the CLI, the C API, linking, the application's account
- [Troubleshooting](docs/troubleshooting.md): finding out why a call fails, and what each error means
- [Why an HMAC PRF](docs/why-hmac-prf.md): why keys are wrapped with a per-payload key from an HMAC-SHA-256 KDF, and why the design is post-quantum

The rest of this README covers the design and building from source.

## Quick start

```sh
scripts/build-release.sh
```

Runs `cargo build --release`, which produces
`target/release/libhkdfguard.so` (dynamic) and
`libhkdfguard.a` (static) -- the `[lib] name` in
`Cargo.toml` controls that output name directly, and Cargo has no way to
produce a name containing dots. The library's name on a running system is
its SONAME, `libhkdfguard.so.1` ([`build.rs`](build.rs)): a program linked
against it records that name and looks for it at run time, and it is what
the packages, the release tarballs and the container overlay install. The
script's one additional step creates `target/release/libhkdfguard.so.1` as
a symlink to Cargo's output. A plain `cargo build --release` still works
for local iteration; link against `libhkdfguard` directly and add the
same symlink (or set `LD_LIBRARY_PATH`) to run. Installed from the packages
(see "Packages"), the library is simply `-lhkdfguard`, via
`pkg-config --cflags --libs hkdfguard`. The C header
(`include/hkdfguard.h`) and exported C symbols (`hkdfguard_create_kek`,
`hkdfguard_kek_exists`, `hkdfguard_wrap_dek`, `hkdfguard_unwrap_dek`,
`hkdfguard_generate_and_wrap_dek`, `hkdfguard_open_file`,
`hkdfguard_security_model`, `hkdfguard_key_file_principal_trusted`) are the
same either way.

```c
#include "hkdfguard.h"

/* Once, at startup: make sure the service has a KEK. This is the only
 * call that creates one -- wrap never does -- and it is deliberately
 * slow (see "Setup calls are deliberately slow"). Idempotent. */
hkdfguard_create_kek("com.company.orders");

uint8_t dek[32] = { ... };
uint8_t wrapped[512];
int wrapped_len = sizeof(wrapped);
hkdfguard_wrap_dek("com.company.orders", dek, 32, wrapped, &wrapped_len);

uint8_t recovered[32];
int recovered_len = sizeof(recovered);
hkdfguard_unwrap_dek("com.company.orders", wrapped, wrapped_len, recovered, &recovered_len);
```

`hkdfguard_wrap_dek` and `hkdfguard_generate_and_wrap_dek` return
`HKDFGUARD_ERR_KEK_NOT_FOUND` (`-17`) if `hkdfguard_create_kek` has never
succeeded for that `service`; `hkdfguard_kek_exists` reports whether it
has, without creating anything.

`hkdfguard_generate_and_wrap_dek` generates its own cryptographically random
32-byte DEK (via the OS CSPRNG) and wraps it in one call, for callers minting
a brand new DEK -- the plaintext never crosses back out to the caller; it's
zeroed internally the moment it's wrapped. Recover it later via
`hkdfguard_unwrap_dek` on the resulting payload, with the same `service`:

```c
uint8_t wrapped[512];
int wrapped_len = sizeof(wrapped);
hkdfguard_generate_and_wrap_dek("com.company.orders", wrapped, &wrapped_len);
```

### Hardening the host process (opt-in)

(Automatic once the process holds an ephemeral key: see
[Provider chain](#provider-chain).)

Keys and DEKs pass through your process's memory. `hkdfguard_harden_process`
makes that memory harder to recover: it disables core dumps (`RLIMIT_CORE`
set to 0, hard limit included) and calls `prctl(PR_SET_DUMPABLE, 0)`,
which also stops other non-root processes running as the same user from
attaching a debugger or reading `/proc/<pid>/mem`. Call it once, early,
and after any privilege drop (the kernel resets the flag when a
process's credentials change):

```c
if (hkdfguard_harden_process() != HKDFGUARD_OK) { /* refuse to start */ }
```

It is opt-in because it is process-wide: debuggers and crash reporters
stop working for your application. It does not stop root or a process
with `CAP_SYS_PTRACE`, and it does not keep memory out of swap; those are
host settings -- no swap or encrypted swap, `kernel.yama.ptrace_scope` of
2 or 3, and for a systemd service `LimitCORE=0` and
`ProtectProc=invisible`.

`hkdfguard_harden_process_with_flags(flags)` is the same call with options;
`hkdfguard_harden_process()` is `..._with_flags(0)`. The one flag,
`HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE`, makes the call fail unless no
other process of the same user can debug or inject code into this one. It
exists for macOS, where that depends on the host executable's code signature
and is otherwise only a logged warning. On Linux `PR_SET_DUMPABLE` already
guarantees it, so the flag is accepted and changes nothing -- a
cross-platform caller can pass it everywhere. Unknown flag bits return
`HKDFGUARD_ERR_INVALID_ARGUMENT` before anything is changed.

The `hkdfguard` command always calls it, and refuses to run if it fails.
The CLI also locks its memory out of swap with `mlockall`, but only when
the process has `CAP_IPC_LOCK` or an unlimited `RLIMIT_MEMLOCK` (root, or
`ulimit -l unlimited`). Under a finite limit, locking future
allocations could make one fail and abort the CLI mid-operation. In that
case it locks only the one small buffer that holds its copies of the DEK
(the base64 text it reads and the bytes that decodes to) with `mlock`, which
fits even a 64 KiB limit, and warns that the library's own transient
copies while it wraps are not locked.

See [`examples/wrap_unwrap.c`](examples/wrap_unwrap.c) for a complete,
buildable example, and [`include/hkdfguard.h`](include/hkdfguard.h) for the
full API contract (status codes, buffer sizing, safety requirements). The
status codes are one table shared with the Windows and macOS libraries: a
name always has the same number on every platform, and the header defines
every code, including the few only another platform returns. The table,
with what each code means, is in [docs/usage.md](docs/usage.md#the-c-api).

## Provider chain

`hkdfguard_create_kek` walks the policy-allowed providers in this order and
creates the `service`'s KEK on the first one that is available.
`hkdfguard_wrap_dek` walks the same order but only ever *loads*: it uses
the first provider that already holds a KEK for `service`, and never
creates one. `hkdfguard_unwrap_dek` always uses the exact provider that
wrapped the payload (recorded -- and authenticated -- in the
payload itself, never in `service`). Providers are constructed fresh on
every call; no session, login, or device connection is kept open between
calls. (A PKCS#11 *module* stays loaded and initialized for the life of
the process -- see "Nothing is cached between calls" under "Design
decisions worth knowing".)

The walk moves past a provider only when it is **absent** -- not on this
host, or not set up for use here -- or has **no key for this service**.
A provider that is present but failing ends the call with its error
instead: a secret file with the wrong owner or mode, a TPM that fails its
self-test or whose configured TCTI can't be opened, a PKCS#11 module that
won't load, a token label that matches nothing, a wrong PIN, a configured
secret mount that isn't there. Falling through in those cases would
quietly wrap every new DEK under a weaker KEK -- or, with Ephemeral, one
lost at the next restart -- with nothing reporting a problem.
`hkdfguard_kek_exists` fails the same way rather than answering 0, so a
caller isn't steered into creating a key somewhere weaker.

| Provider | Absent (the walk moves on) | Present but failing (the call fails) |
|---|---|---|
| TPM2 | no TPM device; or the default device exists but this process can't open it (not in `tss`) and the service has no TPM key file | the default device can't be opened but the service *has* a key file (lost `tss` membership, a missing TCTI plugin); leaky `TSS2_LOG`; unusable policy TCTI, or a configured one that can't be opened; a service's key file present but untrusted or unreadable (a missing one is "not provisioned" for that service: the walk moves on); a policy-named owner authorization file that is missing or untrusted, or a wrong owner password; failed or unrunnable self-test |
| PKCS#11 | no module configured; under the developer security model, a configured module whose PIN file doesn't exist | a configured module whose PIN file doesn't exist (production model); untrusted PIN file; module refused or won't load; no matching token; `C_Initialize`/session/login failure; a PIN the token rejected (no further login from this process until the PIN file changes); a token reporting its user PIN locked or on its final attempt |
| External secret | no mount found | configured `external_secret.dir` missing; a service's secret file present but untrusted |
| (any) | -- | policy present but unusable |

| # | Provider | Module | Feature flag | Built by default |
|---|----------|--------|---------------|-------------------|
| 1 | TPM2 | [`src/provider/tpm2.rs`](src/provider/tpm2.rs) | `tpm2` | no |
| 2 | PKCS#11 | [`src/provider/pkcs11.rs`](src/provider/pkcs11.rs) | `pkcs11` | no |
| 3 | External Secret | [`src/provider/external_secret.rs`](src/provider/external_secret.rs) | `external-secret` | yes |
| 4 | Ephemeral | [`src/provider/ephemeral.rs`](src/provider/ephemeral.rs) | `ephemeral` | yes |

There is deliberately no software-backed (locally-generated,
filesystem-encrypted-at-rest) provider: a deployment without TPM2 or
PKCS#11 hardware is expected to provision a KEK via external-secret
instead.

Ephemeral is compiled in by default but **never used unless a policy file
explicitly names it** -- either as the sole provider under `require`, or
by name in `preferred_order` (e.g. `preferred_order: [external-secret,
ephemeral]`). Qualifying by assurance tier under `require-level` is not
enough on its own; it must be named. Its keys live only in process
memory, so every DEK wrapped under one is lost on restart; without a
policy (or a policy that never names it), a missing secret mount or
unavailable TPM makes `hkdfguard_create_kek` fail rather than silently
degrade to it.

An ephemeral key's only protection is the process's memory, so the library
hardens the process (as `hkdfguard_harden_process` does) before it creates
the first one, and refuses to create it if that fails. The keys are kept in
pages excluded from core dumps and, where `RLIMIT_MEMLOCK` allows, locked
into RAM. The `hkdfguard` CLI refuses ephemeral keys outright: one it
created would vanish when it exits.

The policy file (`/etc/hkdfguard/policy.toml`) must be owned by root and
not writable by group or others, and so must `/etc/hkdfguard` and every
directory above it -- sticky directories like `/tmp` included; only a
read-only mount is exempt. The service's own user is deliberately not accepted: any
process running as that user could otherwise rewrite the policy, or
delete it to switch policy off. Only a *missing* file in a trusted
directory means "no policy"; a file that exists but is unreadable, too
broadly writable, wrongly owned, or malformed -- or one in a directory
someone untrusted could change -- makes every operation fail closed with
`HKDFGUARD_ERR_POLICY_INVALID` (`-9`).
(Only test builds -- see "Testing against scratch configuration" -- also accept the process's own user.)

### Security model

The policy's top-level `security_model` decides who may do what, as the
Windows build's `SecurityModel` policy value and the macOS build's
production mode do. **Production is the default**: with no policy file, or
one that doesn't set it, this is a production install.

| Role | Production | May |
|---|---|---|
| Security admin | root | `hkdfguard provision`, `hkdfguard retire` |
| Deployment admin | root, or a deployer | `hkdfguard wrap`: key files `hkdfguard_open_file` will trust |
| Application | anyone else the provider admits | unwrap (and wrap in memory) only |

- Under production, `hkdfguard_create_kek` creates a KEK only for root;
  anyone else gets the existing KEK, or `HKDFGUARD_ERR_KEK_ACCESS_DENIED`
  (`-18`, which Linux now returns). An ephemeral KEK is exempt.
- A **deployer** is a direct member of `hkdfguard-deployers` (the packages
  create it) or of a group in the policy's `deployer_groups`. Only key files
  owned by root or a deployer, in folders owned by root or a deployer and
  group-writable only through a deployer group, are trusted; others are
  `HKDFGUARD_ERR_FILE_UNTRUSTED` (`-39`). So an application cannot persist a
  key file its own service would accept.
- A deployer group that doesn't exist, is over-broad or can't be looked up
  fails every key-file read with `HKDFGUARD_ERR_LINUX_GROUP_INVALID`
  (`-80`), which refines `POLICY_INVALID` (`-9`).
- `security_model = "developer"` restores the earlier rule: anyone who can
  reach the provider creates KEKs, and key files owned by root or the
  calling user are trusted. Audit event 1005 marks it.
- Wrapping and unwrapping are the same in both: the provider's own access
  control decides who may use a KEK.
- `hkdfguard_security_model(int* out_model, int* out_may_write_key_files)`
  reports the model (`HKDFGUARD_SECURITY_MODEL_PRODUCTION` 0,
  `HKDFGUARD_SECURITY_MODEL_DEVELOPER` 1) and whether this process's key
  files would be trusted; `hkdfguard_key_file_principal_trusted(principal,
  out_trusted)` answers for `"uid:<n>"` or `"gid:<n>"`.

Upgrading changes the default: key files owned by an application's own
account become untrusted until redeployed by root or a deployer (or until
the policy says `security_model = "developer"`). Setup, migration and the
deployers' shared folder are in
[docs/configuration.md](docs/configuration.md#security-model-who-may-provision-wrap-and-unwrap);
`scripts/verify-roles.sh` checks the split end to end, as root, against a
release build.

### Audit trail

The library writes one syslog record per security-relevant event, whatever
the host does about logging. The records use facility `authpriv` and tag
`hkdfguard`, sent straight to `/dev/log`. On systemd hosts they land in the
journal (`journalctl -t hkdfguard`); elsewhere in `/var/log/secure` or
`/var/log/auth.log`. These are the Windows build's Event Log events, with the
same IDs, meanings and severities (1004 aside), so one set of alerts covers both:

| ID | Severity | When |
|---|---|---|
| 1000 | info | A KEK was created (not merely found). If whether one already existed couldn't be checked first, the record carries `existed_before=unknown` and says it may have been found instead. |
| 1001 | warning | A KEK was created on a provider other than the policy's first choice, which was unavailable or declined. |
| 1002 | info | A DEK was wrapped (`hkdfguard_wrap_dek` or `hkdfguard_generate_and_wrap_dek`). |
| 1003 | info | A DEK was unwrapped. |
| 1004 | warning | A KEK was retired (`hkdfguard retire`): deleted for good, after its fingerprint was confirmed. Names the fingerprint. Every DEK wrapped under it can no longer be unwrapped. |
| 1005 | warning | A key file was read under the developer security model, which trusts files the calling account owns. Logged once per process; names the file. |
| 2000 | warning | `KEK_ACCESS_DENIED`: under the production security model, a non-root caller tried to create a KEK that doesn't exist, or to retire one. |
| 2002 | error | `KEK_INVALID`. |
| 2003 | warning | Unwrap rejected a tampered, corrupted, misdirected or unknown-version payload: `PAYLOAD_AUTH_FAILED`, `KEK_FINGERPRINT_MISMATCH`, `PAYLOAD_MALFORMED`, `PAYLOAD_UNSUPPORTED`. Or `hkdfguard_open_file` refused a key file someone else could have replaced (`FILE_UNTRUSTED`), or one that isn't a well-formed payload (`FILE_MALFORMED`, `FILE_TOO_SHORT`, `FILE_TOO_LONG`); names the file. |
| 2004 | error | `POLICY_INVALID`: every call fails closed until the policy is fixed. |
| 2005 | error | `PROVIDER_UNAVAILABLE`, `PROVIDER_ERROR`, `CRYPTO_ERROR` or `INTERNAL_ERROR`. |
| 2006 | error | `hkdfguard_open_file` refused a file that looks like an unwrapped DEK; names the file. |
| 2007 | warning | A process made more than 10 setup calls (see above). Logged once per process. |

Each record is `key=value` fields followed by a sentence:

```text
hkdfguard[4242]: event=1002 op=hkdfguard_wrap_dek result=OK service="com.company.orders" provider=TPM2
  kek_fingerprint=3f9c... payload_sha256=a01b... uid=990 euid=990 pid=4242 exe="/usr/bin/orders" msg="DEK wrapped"
```

The fields identify the caller (`uid`, `euid`, `pid`, `exe`) and the service
by name: service names are public identifiers and are never redacted. Wrap
and unwrap records also carry the KEK's fingerprint and a SHA-256 of the
wrapped payload. Both are public, and the same payload hashes the same in its
wrap record and in every unwrap record, which ties each unwrap back to the
wrap that made it. That also makes a substituted older payload visible (see
"Design decisions worth knowing"). To hash a key file for comparison, run
`sha256sum <file>`.

The records never contain DEKs, KEKs, wrapping keys or other derived keys, or
plaintext. Caller mistakes (`INVALID_ARGUMENT`, `BUFFER_TOO_SMALL`,
`INVALID_SERVICE_NAME`) and `KEK_NOT_FOUND` aren't recorded. Delivery is
best effort: non-blocking, and a missing `/dev/log` (as in a minimal
container) never changes or delays a call. `openlog(3)` is never called, so
the host's own syslog tag and facility are left alone. Anything on the host
can write to `/dev/log` under any tag, so these records are an audit aid,
not tamper-proof evidence.

For a caller that legitimately unwraps often, the policy file can turn off
the unwrap-success record (1003) alone:

```toml
[audit]
unwrap_success = false   # default true
```

Only an explicit `false` in a valid policy turns it off. A missing policy,
or one that is present but invalid, keeps it on. Wrap records and every
failure record are always written.

### Setup calls are deliberately slow

`hkdfguard_create_kek`, `hkdfguard_kek_exists` and
`hkdfguard_kek_fingerprint` are meant to run once per application startup, so each takes **at least one second** of
wall-clock time whatever its outcome (found, not found, or error), and
they are serialized with each other across threads. This bounds how fast
a buggy or hot-looping caller can drive the TPM/HSM (every call is a
fresh connection plus a key lookup) and caps Ephemeral key-map growth.
Argument errors (bad pointer, invalid service name) still return
immediately since they never reach a provider. The library logs a warning
once a process has made more than 10 setup calls.

The floor is about load, not secrecy. It does not hide which services
have a key: `hkdfguard_wrap_dek` is not rate-limited — it is the hot path
— and answers `KEK_NOT_FOUND` (`-17`) at once for a service with none, so
anything that can call the library can find out quickly. Treat service
names as public identifiers, never as secrets.

The floor is set by the policy file and can be tuned per host (up to
60 000 ms; `0` disables it):

```toml
[startup_behavior]
setup_min_delay_ms = 1000   # default when absent
```

A policy file that is present but invalid keeps the 1 s default (the
gated call fails closed on that same policy anyway). There is no
environment-variable override.

### The TPM key and its key file

Each service's KEK on the TPM is an ordinary TPM key: a keyedHash
object with the HMAC-SHA-256 scheme (attributes `fixedTPM`, `fixedParent`,
`sensitiveDataOrigin`, `userWithAuth`, `noDA` and `sign`; not `decrypt`,
not `restricted`) that `TPM2_Create` generates under the Owner hierarchy's
storage root key (SRK), the TCG's standard ECC P-256 storage key. The
result is saved as a **key file**, `/var/lib/hkdfguard/tpm/<service>.tpmkey`,
in the TPM 2.0 key file format (`-----BEGIN TSS2 PRIVATE KEY-----`, parent
`0x40000001`) that the OpenSSL tpm2 provider and tpm2-tss-engine also use.
The key has a random 32-byte authValue, kept beside it in
`<service>.tpmauth`. Every wrap and unwrap re-creates the SRK from its
template, loads the key file under it with `TPM2_Load`, runs one one-shot
`TPM2_HMAC` per input in a session keyed by the authValue, and flushes
everything, so nothing stays on the TPM and no persistent handle is
needed. The provider never uses the `TPM2_HMAC_Start`/`TPM2_SequenceUpdate`
sequence commands: on an Intel PTT firmware TPM that sequence put the TPM
into failure mode until the next reboot. When the provider connects, its
self-test checks that the SRK re-derives identically and runs a
known-answer `TPM2_HMAC` test, so a TPM whose HMAC disagrees with
HMAC-SHA-256 is refused before it wraps anything. A key file holding an ECC key
(from the pre-release ECDH format), or an HMAC key with an empty password
(from before authValues), is refused with a message saying to delete it
and provision again.

What the TPM guarantees:

- **The HMAC key never leaves the TPM.** The key file's private half is
  encrypted and integrity-protected under the SRK, whose seed the TPM
  generated and never exports. The file is useless on any other TPM, and
  `TPM2_Load` refuses a file whose halves don't belong together.
- **The TPM generated it.** The library refuses a key file whose key lacks
  `fixedTPM`, `fixedParent` or `sensitiveDataOrigin`, or differs in any
  other attribute or parameter from the keys it creates. The TPM refuses to
  import an object with `fixedTPM` set, so such a key was generated inside
  this TPM and never duplicated out: no key file can hold an HMAC key
  anyone knows.

What it does not: **anyone who can read a key file and its authValue file,
and open the TPM, can use that KEK.** Read access to the two files is the
access control, as the PIN file is for PKCS#11. The packages create the
directory as `root:hkdfguard 0750`, so the members of `hkdfguard` may use
TPM keys; give a service's `.tpmauth` file that service's own group to
keep the others from using its key. Without the packages, create the
directory as root:

```sh
install -d -m 0750 -o root -g hkdfguard /var/lib/hkdfguard/tpm
```

`provision` (root only, under the production security model) creates each
key file there: owned by root, with the directory's group, mode `0440`.
`tpm.key_dir` moves the directory. The library refuses a key file that is
group- or world-writable, readable by others, a symlink, owned by anyone
but root (or, under the developer model, the calling user), or in a
directory chain someone else could change -- never as "not provisioned",
so a damaged or planted key file can't hand the service to a weaker
provider. A service with *no* key file has no KEK on the TPM, and `retire`
deletes the file.

> **Back up the key files.** A lost key file is a lost KEK: every DEK
> wrapped under it is unrecoverable. A copy is useless on any other TPM, so
> backups are low-risk; on this TPM a copy can still be used, so give
> backups the same access control. A backup recovers from losing the
> *file*, not the *TPM*: a replaced motherboard or discrete TPM, or
> `TPM2_Clear` (which a firmware reset or OS reinstall can trigger), resets
> the Owner hierarchy's seed, the SRK changes, and no key file made before
> it loads again. If DEKs must survive the hardware, keep a copy of each
> somewhere other than this host, wrapped under a key that isn't tied to it.

**1. Pinned TPM Names.** Record the Name of each service's key and the
provider will refuse any key file whose key has a different Name. The
library's own check, that the Name the TPM reports for a loaded key matches
the key file's public area, catches a non-conformant stack; a pin, held in
the root-owned policy file, catches a key file someone replaced.

```toml
[tpm.pinned_names]
"com.company.orders" = "000b<64 hex chars>"   # quote service names: unquoted dots make nested tables
```

With `require_pinned_names`, the pins are also the provisioning allowlist:

```toml
[tpm]
require_pinned_names = true            # only services listed below exist on the TPM
```

Under it, a service with no pinned Name has no KEK, whatever key file
exists: `kek_exists` returns 0, and wrap and unwrap fail. `provision` for
such a service creates its key file, then fails and prints the exact entry
to add:

```text
$ hkdfguard provision -sn com.company.orders
error: hkdfguard: create_kek failed for service "com.company.orders": provider error: TPM2:
tpm.require_pinned_names is set and service "com.company.orders" has no pinned TPM Name. Its key file is
created; to provision it, add this to the policy file and run provision again:
  [tpm.pinned_names]
  "com.company.orders" = "000b..."
error: hkdfguard_create_kek failed for service "com.company.orders": the selected KEK provider failed (see the
messages above for the provider's reason)
```

Add the entry as root and run `provision` again; it then reports "already
provisioned". `scripts/native-tpm-test.sh` shows how to read a key file's
Name directly. A policy file that exists but can't be parsed applies the
allowlist rather than dropping it, and pinning errors rather than reporting
"nothing pinned".

This gates the *TPM* provider. Under `mode = "prefer"`, wrap and unwrap
treat an unpinned service like one the TPM has no key for, so a weaker
provider later in the order that *does* hold a key for it can still serve
it; pair the allowlist with `mode = "require"`, `provider = "tpm2"` (or
`mode = "require-level"`, `level = "hardware"`) if that matters.

**2. Session parameter encryption (bus protection).** On a *discrete*
TPM — a separate chip on the LPC/SPI bus — an interposer can read
`TPM2_HMAC`'s response, the payload's wrapping key, or replace it while a
DEK is wrapped, sealing the payload under a key they chose. The service
key's authValue is what stops both. ESAPI and the TPM key a session's
parameter encryption, and its response HMAC, with the session key followed
by the authValue of the entity the session authorizes (TPM 2.0 Part 1
§19.6 and §21; tpm2-tss's `iesys_compute_session_value`). Every
`TPM2_HMAC` runs in such a session for the service key, so without the
`.tpmauth` file nobody can read `outHMAC` off the bus or forge one. It is a
symmetric secret: no public key has to be trusted for it to hold, and a
quantum computer gains nothing against it. Nothing read over the bus can
prove a TPM has no bus, so every TPM is treated alike.

```toml
[tpm]
session_encryption = "on"             # "on" (default) | "off" (test harnesses only)
pinned_session_salt_key_name = "000b<64 hex chars>"   # pin before provisioning on a discrete TPM
```

The session is also salted to the SRK, as a second layer: someone who has
read a `.tpmauth` file but can't man-in-the-middle the SRK still sees
nothing. The salt is one-pass ECDH, the specification's mechanism, and it
stands alone at one moment: `provision`, whose `TPM2_Create` sends the new
key's authValue and so can't be protected by it. `TPM2_Create` therefore
always runs in a salted, encrypting session, whatever `session_encryption`
says, and `pinned_session_salt_key_name` makes it refuse an SRK whose Name
isn't the pinned one. The pin is checked against what `TPM2_CreatePrimary`
returned, because that is the public area ESAPI encrypts the salt to. The
SRK is a *restricted* storage key, so the TPM uses it only for its children
and to unwrap session salts: someone who can send the TPM commands and
recreate it still can't run ECDH with it.

What's left that is classical: someone who records a discrete TPM's bus
at provisioning, and later breaks P-256, recovers that key's authValue,
and with it the wrapping keys in every session they also recorded.
Re-provisioning gives a key a new authValue. Firmware and virtual TPMs
have no bus to record.

**3. Protect the hierarchy the keys live under.** Every key file is loaded
under the SRK, which is re-created on demand from the Owner hierarchy's
seed, and by default the provider authorizes with an empty owner password.
Two TPM commands are therefore dangerous in the hands of anyone who can
open the device, whether or not they can read a key file:

- `TPM2_Clear` regenerates the seed. Every key file on the host becomes
  unloadable and every DEK wrapped on it unrecoverable. With the default
  empty lockout password, `tpm2_clear -c l` from any `tss`-group shell
  does it.
- `TPM2_HierarchyChangeAuth` on the Owner hierarchy sets a password the
  provider does not know. Every `CreatePrimary` then fails, the self-test
  cannot run, and the TPM is refused on every call until the password is
  cleared again.

Set a lockout-hierarchy password and, where the platform allows, disable
`TPM2_Clear`, so neither command is available to an unprivileged device
user:

```sh
LOCKOUT_PW="$(head -c 32 /dev/urandom | base64)"   # keep it with the key files' backup
tpm2_changeauth -c lockout "$LOCKOUT_PW"
tpm2_clearcontrol -C l -P "$LOCKOUT_PW" s          # disableClear; only platform authorization can re-enable it
```

Then, optionally, give the Owner hierarchy a password too, and name a
file holding it in the policy. With a password, re-creating the SRK -- and
so loading any key file -- needs it as well, and `TPM2_HierarchyChangeAuth`
needs the current one. The password is not an input to the SRK, so setting
it changes no KEK and needs no re-wrapping.

```sh
( umask 077; head -c 32 /dev/urandom > /etc/hkdfguard/tpm.owner-auth )
# For a service that doesn't run as root, let its group read it:
chgrp <service-group> /etc/hkdfguard/tpm.owner-auth && chmod 0440 /etc/hkdfguard/tpm.owner-auth
tpm2_changeauth -c o file:/etc/hkdfguard/tpm.owner-auth   # bytes used verbatim, as hkdfguard reads them
```

```toml
[tpm]
owner_auth_file = "/etc/hkdfguard/tpm.owner-auth"
```

Set the policy entry in the same change as the password: with a password
and no entry (or the reverse), every TPM call is refused. Each process
tries a rejected password once, then sends nothing Owner-authorized again
until the file or the policy entry changes: every wrong attempt counts
toward the TPM's dictionary-attack limit, which is TPM-wide (a Hyper-V
vTPM allows 3 per 1000 s), so a service retrying would otherwise lock the
whole TPM within seconds. After fixing the file, the next call tries again;
nothing needs restarting. Back the file up with the key files. The owner
password applies to the whole Owner hierarchy, so anything else on the
host that creates keys under it with an empty password --
`systemd-cryptenroll --tpm2-device`, tpm2-tss FAPI, `tpm2_createprimary -C o`
scripts -- stops working until it is given the password as well; check
before setting it on a shared host. The provider presents it through an
HMAC session, so it never crosses the bus in the clear.

Note also that dictionary-attack lockout is TPM-wide: failed
authorizations by any other local user of the TPM can put it in lockout,
during which commands that need authorization fail with `TPM_RC_LOCKOUT`
until the lockout interval passes or the lockout password resets it. The
SRK and service keys are `noDA`, so their use is never refused for it, and
Owner-hierarchy authorization failures are not counted towards it.

Callers never see which provider is active. Every provider implements the
identical `HMAC-SHA-256 (SP 800-108 block) -> AES-256-GCM` protocol
([`src/crypto.rs`](src/crypto.rs)); the only difference is where the
persistent HMAC-SHA-256 KEK lives and who computes the HMAC.

### Build & verification matrix

All of the below has actually been run, in Docker on Ubuntu 24.04 (glibc
2.39, tpm2-tss 4.0.1; `docker/run-tests.sh` -- see that section below),
not just reasoned about. Because the release binaries are built in that
same image, they need glibc 2.39 or newer: Ubuntu 24.04+, Debian 13, RHEL
10. Debian 12 is not a target -- its tpm2-tss is 3.2.1, even in backports.
The `tpm2` feature itself does build and pass against tpm2-tss 3.2: the
TPM row's RHEL 9.8 run (tpm2-tss 3.2.3) was a source build on that guest,
not the release binaries.

| Feature | Builds on macOS (this repo's dev env) | Builds & links natively on Linux | Hardware/module test |
|---|---|---|---|
| `external-secret`, `ephemeral` (default) | yes | yes -- verified | unit tests pass; full wrap/unwrap round trip through the compiled C ABI (`examples/wrap_unwrap.c`) verified |
| `pkcs11` | yes (build-only; no module to talk to) | yes -- verified, linked against real `cryptoki` 0.12.1 + `libsofthsm2.so` | `#[ignore]`d tests pass against a real SoftHSM2 token: `C_GenerateKey` (`CKM_GENERIC_SECRET_KEY_GEN`) + `C_Sign` with `CKM_SHA256_HMAC` executed for real, the token's output matching software HMAC-SHA-256, the same key reused for a service, and imported or weakly protected keys refused |
| `tpm2` | **no** -- `tss-esapi-sys` ships pregenerated bindings only for specific Linux target tuples and hard-fails on macOS/aarch64 | yes -- verified, linked against real `libtss2-esys` 4.0.1 (Ubuntu 24.04) and 3.2.3 (RHEL 9.8) | The `#[ignore]`d conformance suite -- key files created, reloaded across connections and refused when spliced, the storage root key's determinism, the client-side Name formula matching the TPM's own, `TPM2_HMAC` matching software HMAC-SHA-256 for every input length, retiring, pins, and salted/parameter-encrypted sessions producing the same HMAC output as plain ones -- plus the reboot-persistence check, passes against `swtpm` (`docker/run-tests.sh`) and, via `scripts/native-tpm-test.sh`, against a real firmware TPM, **Intel PTT**, on Ubuntu 24.04 (tpm2-tss 4.0.1); against a **discrete TPM chip**, an **STMicroelectronics** (`STM`, firmware 71.12.17568.4100) in a ThinkPad T470 on Zorin OS 18 (tpm2-tss 4.0.1), via both `scripts/native-tpm-test.sh` and the hardware-test bundle, with session encryption on and both Names pinned (the reboot-persistence check has not been run on it yet); and, via the hardware-test bundle (`scripts/hardware-tests/`), against **Hyper-V's vTPM** (`MSFT`, firmware 8213.275.21.18467) in RHEL 9.8 (tpm2-tss 3.2.3, bundle built on the guest), AlmaLinux 10.2 (tpm2-tss 4.1.3) and Ubuntu 24.04.5 (tpm2-tss 4.0.1) guests -- the last two from the `--docker` bundle -- the C ABI, CLI-to-C and PKCS#11 suites and the reboot-persistence check included (in the last two across a full VM power cycle, `Stop-VM`/`Start-VM`). The earlier derived-key design also passed against **AMD fTPM**; the key-file design has not been run there yet |

The TPM provider's key-file design has been verified against `swtpm`, a
real firmware TPM (Intel PTT), a discrete TPM chip (STMicroelectronics,
not yet across a reboot) and Hyper-V's virtual TPM (in RHEL 9.8,
AlmaLinux 10.2 and Ubuntu 24.04.5 guests, each surviving a reboot); its
earlier derived-key design was also verified against AMD
fTPM. It has **not** been
exercised against other discrete chips (e.g. Infineon
or Nuvoton), against other hypervisors' vTPMs (VMware, Google Cloud,
AWS NitroTPM), or against a hardware HSM/YubiHSM -- the PKCS#11 provider
has only ever been run against SoftHSM2. `scripts/native-tpm-test.sh`
(next section) exists precisely so you can run the same matrix on your
own hardware, including a discrete chip, before depending on it.

On the Hyper-V vTPM the *packages* of the earlier derived-key design were
verified too, not just the test builds: the Ubuntu 24.04 `.deb`s and the EL10 `.rpm`s from
`packaging/build-packages.sh` (see "Packages"), installed and configured
only through a root-owned `/etc/hkdfguard/policy.toml` that requires the
TPM, with a `0440` derivation secret, and run as an unprivileged service
account in the `tss` group. `hkdfguard provision` and
`wrap` followed by an unwrap through the installed library succeeded; a
group-writable policy, a world-readable derivation secret, `TSS2_LOG` at
`debug`, and the service losing access to `/dev/tpmrm0` were each refused
with no fallback to another provider -- the policy as
`HKDFGUARD_ERR_POLICY_INVALID` (`-9`), the other three as
`HKDFGUARD_ERR_PROVIDER_ERROR` (`-4`); an unwrap under the wrong service
was refused as `HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH` (`-16`); and a DEK
wrapped before a guest reboot unwrapped after it.

> **Dictionary-attack lockout on Hyper-V vTPMs.** A new Hyper-V vTPM
> allows only **3** failed authorizations, forgives one every **1000 s**,
> and has no lockout password. One test guest came up already in lockout,
> before any hkdfguard code had run, and every service-key operation, so every
> wrap and unwrap, failed until it was cleared with
> `tpm2_dictionarylockout --clear-lockout`. The most likely cause is
> Hyper-V's **Reset**, used several times on that guest during
> installation: it restarts the vTPM without an orderly shutdown, which a
> TPM counts as a failed authorization. (Not proven; a **Turn Off**, by
> contrast, was tested and left the counter at 0, the vTPM reporting an
> orderly shutdown.) hkdfguard itself left the counter at 0 through the
> whole suite, including its deliberately failing cases. On Hyper-V
> guests, restart from inside the guest rather than with Reset, raise the
> lockout parameters to suit the host
> (`tpm2_dictionarylockout --setup-parameters`), and set a lockout
> password as described under "Protect the hierarchy" -- without one, any
> `tss`-group user can clear the lockout, as was done here.

Run the ignored hardware/module tests yourself once you have the real backend:

```sh
cargo test --features tpm2 -- --ignored     # needs a TPM or swtpm, on Linux
cargo test --features pkcs11 -- --ignored   # needs SoftHSM2 or another PKCS#11 module
```

The tests make their temp directories under `<target>/tmp/hkdfguard-tests`
(mode `0700`), not under `/tmp`: the library refuses key files, policies
and secrets anywhere under a sticky, world-writable directory. Every
directory above it must be
owned by root or you and not group/other-writable; the tests clear group
and other write on what they own inside the target directory, and stop
with a message naming any other offending directory (a checkout in a shared
folder, or one made under a `002` umask). Set `HKDFGUARD_TEST_TMPDIR` to
another private directory to use that instead.

### Testing on a native Linux TPM (Intel PTT / AMD fTPM / discrete)

Docker proves the code against `swtpm`. This repo's maintainers have run
the scripts below to completion, including reboot persistence, on real
**Intel PTT** and **AMD fTPM** firmware TPMs, and on **Hyper-V's vTPM**
in Ubuntu 24.04 and AlmaLinux 10 guests, and the hardware-test bundle
(below), reboot check included, in RHEL 9.8, AlmaLinux 10.2 and Ubuntu
24.04.5 guests. On a **discrete** TPM, an STMicroelectronics chip,
both the full matrix and the hardware-test bundle have passed, with every
`TPM2_HMAC` in the pinned run going through a salted, encrypted session;
its reboot check has not been run yet, and no other vendor's chip (e.g.
Infineon, Nuvoton) has been tested. To prove it against the hardware you
will actually deploy on:

```sh
scripts/native-tpm-preflight.sh   # read-only: device access, tpm2-tools, libtss2-esys, vendor
scripts/native-tpm-test.sh        # the full matrix, on the real TPM
```

The preflight identifies the TPM from `TPM2_PT_MANUFACTURER`, and says
whether it is a discrete chip whose storage root key should be pinned
before provisioning. The full run then does everything
`docker/entrypoint-test.sh` does, against the real device: the
conformance suite (key files, the storage root key's determinism, the
Name formula, `TPM2_HMAC` against software HMAC-SHA-256, encrypted-session correctness),
a C ABI round trip with the KEK on the TPM with session encryption off
and with both Names pinned, and the CLI-to-C-consumer
cross-process check. It learns the Names to pin from the TPM itself via
two operator-helper tests (run them directly to get values for your own
policy):

```sh
cargo test --features tpm2 --lib print_session_salt_key_name_for_pinning -- --ignored --nocapture
HKDFGUARD_PIN_SERVICE=com.company.orders \
cargo test --features tpm2 --lib print_service_key_name_for_pinning -- --ignored --nocapture
```

Nothing under `/etc/hkdfguard` is touched and no state is left on the
TPM. Every conformance test runs on every kind of TPM, discrete chips
included; none is skipped.

The one property `swtpm` can only approximate is survival of a real
reboot. For that:

```sh
scripts/native-tpm-test.sh reboot capture   # provisions a key file, wraps a DEK on the TPM, saves state
# reboot the machine
scripts/native-tpm-test.sh reboot verify    # the same storage root key must come back, and the key file unwrap it
```

To qualify other machines -- another laptop's TPM, a Hyper-V guest's
vTPM -- without a Rust toolchain on each, build the same matrix once as a
bundle and run it there, by hand or over SSH. It first records the host,
its TPM stack and the TPM's capabilities, and checks the TPM has
everything the provider uses ([scripts/hardware-tests/README.md](scripts/hardware-tests/README.md)):

```sh
scripts/hardware-tests/make-bundle.sh --docker
scripts/hardware-tests/run-remote.sh user@guest1 user@guest2   # logs come back to build-hardware-tests/logs/
```

### Testing in Docker (recommended if you're not already on Linux)

```sh
docker/run-tests.sh
```

Builds a real Linux environment with `tpm2-tss`, `swtpm`, and `SoftHSM2`
and runs the full matrix end-to-end, in this order: the default-feature
unit, CLI, and integration tests; a real link against `libtss2-esys` and
the PKCS#11 loader; the `tpm2`-feature unit tests; the `#[ignore]`d TPM
conformance suite against swtpm; the `#[ignore]`d PKCS#11 tests against a
fresh SoftHSM2 token; a C ABI round trip through the release `.so`; and the
CLI flow (`provision`, then `wrap` via stdin and `--dek-file`, with an
unprovisioned `wrap` asserted to be refused)
unwrapped by a separate C consumer. Every change in this repo is expected
to pass it. See [`docker/README.md`](docker/README.md).

```sh
docker/run-distro-tests.sh
```

Runs the PKCS#11 (SoftHSM2) and Ephemeral provider tests, plus release
builds of the library and CLI configured through a root-owned policy, on
AlmaLinux 9 and 10, Debian 12 and 13, Ubuntu 24.04 and 26.04, SLES 15 SP7
and 16.0, Red Hat UBI 9 and 10 Micro, Amazon Linux 2023 and Alpine 3.24
(musl), each in its own container. See "Test across distributions" in
[`docker/README.md`](docker/README.md). `docker/run-all-tests.sh` runs both
suites, which every change is expected to pass before it is merged; see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Packages (.deb / .rpm)

```sh
packaging/build-packages.sh     # needs Docker; DISTROS="debian sles16" ARCHES=amd64 for a subset
```

Builds packages on amd64/x86_64 and arm64/aarch64 for:

| `DISTROS` key | Distribution | Format | Built on |
|---|---|---|---|
| `debian` | Debian 13 | `.deb` | `debian:13` |
| `ubuntu24.04` | Ubuntu 24.04 LTS | `.deb` | `ubuntu:24.04` |
| `el10` | RHEL 10, AlmaLinux 10, Rocky Linux 10 | `.rpm` | `almalinux:10` |
| `al2023` | Amazon Linux 2023 | `.rpm` | `amazonlinux:2023` |
| `sles16` | SUSE Linux Enterprise Server 16, openSUSE Leap 16.0 | `.rpm` | SUSE's `bci/bci-base:16.0` |

Packages land in `dist/packages/<distro>-<arch>/`. Each build runs on its
own distribution, built against that distribution's glibc and tpm2-tss.
It runs the default and all-features test suites, then installs into a
clean container of that distribution, where
[`packaging/smoke-test.sh`](packaging/smoke-test.sh) exercises it. The base
images are pinned by digest in one table in `build-packages.sh`. CI does
the same in the `packages` job of
[`.github/workflows/build.yml`](.github/workflows/build.yml), one job per
distribution and architecture, each on a native runner; tagged releases
publish what it builds (see "Releases and verifying downloads").

Every target ships tpm2-tss 4.x. Debian 12, RHEL 9 and SLES 15 / Leap 15.6
ship tpm2-tss 3.x and Amazon Linux 2 older still, so none of them is a
target.

One `debian/` directory serves both Debian-family targets. Built on
Ubuntu, `packaging/build-deb.sh` adds the customary backport changelog
entry, so the Ubuntu packages are versioned `0.9.1-1~ubuntu24.04.1` for
release `noble`. One spec serves all three RPM targets. On SUSE it follows
SUSE's naming policy and runs `ldconfig` from scriptlets:

| Debian, Ubuntu | EL10, Amazon Linux | SUSE | Contents |
|---|---|---|---|
| `libhkdfguard1` | `hkdfguard-libs` | `libhkdfguard1` | `libhkdfguard.so.1`, an empty `/etc/hkdfguard` (root, `0755`), the example policy `/usr/share/hkdfguard/policy.toml.example`, README, third-party licenses |
| `libhkdfguard-dev` | `hkdfguard-devel` | `hkdfguard-devel` | `hkdfguard.h`, `libhkdfguard.so`, `hkdfguard.pc` |
| (in `libhkdfguard-dev`) | `hkdfguard-static` | `hkdfguard-devel-static` | `libhkdfguard.a` |
| `hkdfguard` | `hkdfguard` | `hkdfguard` | The `hkdfguard` command and its man page |

All are built with every provider enabled, so the library depends on
tpm2-tss's libraries even on hosts without a TPM. The PKCS#11 module is
only ever loaded at run time, from the policy file. The packages install
no policy file or PIN, and an empty TPM key directory
(`/var/lib/hkdfguard/tpm`, `root:hkdfguard 0750`): those are per-host decisions
(see "Configuration"), and with no policy file the library uses its
defaults. To write one, start from the annotated example:

```sh
install -m 0644 -o root -g root /usr/share/hkdfguard/policy.toml.example \
    /etc/hkdfguard/policy.toml
```

Copied unedited, it behaves exactly like no policy file: every setting in
it is commented out at its default, and a unit test
(`shipped_example_policy_behaves_like_no_policy`) keeps it that way. It is
installed under `/usr/share`, not `/usr/share/doc`, so it survives
container base images that drop documentation.

The version lives in three places -- `Cargo.toml`, `debian/changelog` and
`packaging/rpm/hkdfguard.spec` (`Version` and `%changelog`) -- and
[`packaging/check-version.sh`](packaging/check-version.sh) fails every
package build, and any release tag, where they disagree. The library's
SONAME major (`.1`, in `build.rs`) is separate: it changes only with an
incompatible C ABI change, together with the Debian package name
`libhkdfguard1`.

## Continuous integration

[`.github/workflows/build.yml`](.github/workflows/build.yml) runs on every
push to `main` and `develop` and on every pull request:

| Job | What it runs |
|---|---|
| `lint` | `packaging/check-version.sh`; `cargo clippy --all-targets --all-features -- -D warnings` |
| `deny` | `cargo deny check advisories bans sources` ([`deny.toml`](deny.toml)) |
| `test` | `docker/run-tests.sh` -- the full matrix against swtpm and SoftHSM2 -- on amd64 and arm64 |
| `packages` | `packaging/build-packages.sh` for each distribution and architecture: build, both test suites, lintian, clean-container smoke test |
| `binaries` | `docker/build-dist.sh` for each architecture |
| `overlay` | `packaging/build-overlay.sh` for each architecture: both container overlay targets, each tested in a consumer image (see "Container overlay image") |

Each architecture runs on its own native runner (`ubuntu-24.04`,
`ubuntu-24.04-arm`), not under QEMU. Every third-party action is pinned
to a commit SHA, and Dependabot ([`.github/dependabot.yml`](.github/dependabot.yml))
proposes updates to those pins weekly.

## Releases and verifying downloads

Pushing a tag `v<version>` runs
[`.github/workflows/release.yml`](.github/workflows/release.yml): the
whole build workflow above, then a `publish` job that

1. fails unless the tag names the version in `Cargo.toml`,
   `debian/changelog` and the RPM spec (`packaging/check-version.sh`);
2. assembles the release assets
   ([`packaging/release-assets.sh`](packaging/release-assets.sh)):
   - `hkdfguard-<version>-<distro>-<arch>.tar.gz` -- one target's `.deb`
     or `.rpm` packages;
   - `hkdfguard-<version>-linux-<arch>.tar.gz` -- the standalone library
     (`lib/libhkdfguard.so.1`, with the `libhkdfguard.so` link for
     `-lhkdfguard`, and the static `lib/libhkdfguard.a`), CLI (`bin/`),
     header (`include/`), `LICENSE` and `THIRD-PARTY-LICENSES.txt`;
   - `SHA256SUMS`;
3. signs a [SLSA build provenance](https://slsa.dev/spec/v1.0/provenance)
   attestation for every asset, **and for every package and binary inside
   the tarballs**, with a short-lived Sigstore certificate issued to this
   repository's release workflow (the public-good Sigstore instance; the
   signature is recorded in its public transparency log, Rekor);
4. opens a **draft** GitHub release with the assets and the attestation's
   Sigstore bundle (`hkdfguard-<version>.sigstore.json`). A maintainer
   reviews and publishes it.

The `publish` job runs in a GitHub environment named `release`. Before
the first release, create it under Settings -> Environments with required
reviewers and a deployment rule allowing only `v*` tags, and protect `v*`
tags with a tag ruleset so only maintainers can create them.

To verify a download -- a release tarball, or a `.deb`, `.rpm` or binary
taken out of one -- with the [GitHub CLI](https://cli.github.com/):

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify hkdfguard_0.9.1-1_amd64.deb \
    --repo runsecure/hkdfguard-native-linux \
    --signer-workflow runsecure/hkdfguard-native-linux/.github/workflows/release.yml
```

Without network access to GitHub, pass the bundle from the release:
`--bundle hkdfguard-<version>.sigstore.json`. A successful verification
proves the file was built by this repository's release workflow, from the
commit and tag the attestation names; it says nothing about whether that
code is correct.

Or with cosign (2.4+), which needs no GitHub account, naming the exact
workflow and tag:

```sh
cosign verify-blob-attestation --new-bundle-format \
    --bundle hkdfguard-0.9.1.sigstore.json \
    --type https://slsa.dev/provenance/v1 \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity https://github.com/runsecure/hkdfguard-native-linux/.github/workflows/release.yml@refs/tags/v0.9.1 \
    hkdfguard_0.9.1-1_amd64.deb
```

[docs/installation.md](docs/installation.md#download-and-verify) has a
Dockerfile that verifies a release this way before installing it.

The attestations prove provenance; they do not make the packages
installable from a signed apt, dnf or zypper repository. Those check GPG
signatures on repository metadata, which these releases do not provide.

## Container overlay image

For containers, each release also publishes a `FROM scratch` image that
holds only HKDFGuard's binaries, at the paths the Ubuntu 24.04 packages
install them to, for copying into another image
([`packaging/overlay/Dockerfile`](packaging/overlay/Dockerfile)):

```
/usr/lib/<multiarch>/libhkdfguard.so.1
/usr/lib/<multiarch>/libhkdfguard.so.1.sigstore.json
/usr/bin/hkdfguard
```

They are taken from the tested `libhkdfguard1` and `hkdfguard` packages,
not rebuilt; nothing else from the packages is copied. The
`.sigstore.json` file is the release workflow's Sigstore build-provenance
bundle for that exact library file (see below); only released images have
it. `packaging/build-overlay.sh` fails if the image holds anything more. About
6 MB, for `linux/amd64` and `linux/arm64`.

| Tag | Policy |
|---|---|
| `ghcr.io/runsecure/hkdfguard-overlay:<version>` | None: the library's defaults (TPM2, PKCS#11 if configured, external secret; never ephemeral). Add your own `/etc/hkdfguard/policy.toml`. |
| `ghcr.io/runsecure/hkdfguard-overlay:<version>-dev` | Adds `/etc/hkdfguard/policy.toml` from [`packaging/overlay/policy.dev.toml`](packaging/overlay/policy.dev.toml): SoftHSM2 when `/etc/hkdfguard/pkcs11.pin` exists, otherwise **ephemeral** keys that are lost when the process exits. Development and tests only. |

```dockerfile
FROM ubuntu:24.04
# The library's runtime dependencies (libhkdfguard1's Depends).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libtss2-esys-3.0.2-0t64 libtss2-mu-4.0.1-0t64 libtss2-tctildr0t64 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/runsecure/hkdfguard-overlay:0.9.1 / /
```

- **Debian-family images only**, with glibc 2.39 or newer: Ubuntu 24.04+
  or Debian 13. The library sits in Debian's multiarch directory, which
  their dynamic loader searches without `ldconfig`. RPM-family images
  (`/usr/lib64`) and musl-based ones (Alpine) need the packages instead.
- **License notices aren't in the image.** The binaries statically link
  crates under permissive open-source licenses,
  which require their notices to accompany the binaries. An image you
  distribute with the overlay in it should carry `LICENSE` and
  `THIRD-PARTY-LICENSES.txt` from the release's `linux-<arch>` tarball.
- **dpkg doesn't know about these files.** `apt` won't upgrade them, and
  installing the `libhkdfguard1` package later in the same image conflicts
  with them; update by changing the overlay tag.
- **To use SoftHSM2 with the `-dev` tag**, install `softhsm2`, initialize
  a token labelled `hkdfguard`
  (`softhsm2-util --init-token --free --label hkdfguard ...`), and write
  its user PIN to `/etc/hkdfguard/pkcs11.pin` (root-owned, `0400`, or
  `0440` with the service's group). From then on a problem with the module
  or token fails every call rather than falling back to ephemeral. Keep
  the token directory (`/var/lib/softhsm/tokens`) on a volume so its keys
  outlive the container.

The release workflow's `overlay` job builds both architectures from the
packages the build workflow tested, pushes them, attests each image with
Sigstore, and signs each with cosign (keyless, as the release workflow;
the job fails unless the signature then verifies). To verify one:

```sh
gh attestation verify oci://ghcr.io/runsecure/hkdfguard-overlay:0.9.1 \
    --repo runsecure/hkdfguard-native-linux
# or the cosign signature, with cosign 3.0+:
cosign verify ghcr.io/runsecure/hkdfguard-overlay:0.9.1 \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity https://github.com/runsecure/hkdfguard-native-linux/.github/workflows/release.yml@refs/tags/v0.9.1
```

In a build, verify the image's digest and copy from that digest, not the
tag; see [docs/installation.md](docs/installation.md).

Before building the images, the same job attests the library file each
one holds and puts that bundle beside it, failing the release unless the
bundle verifies the file. The deployed library, in your image or after
copying it out, then verifies against its own bundle:

```sh
lib=/usr/lib/x86_64-linux-gnu/libhkdfguard.so.1
gh attestation verify "$lib" --bundle "$lib.sigstore.json" \
    --repo runsecure/hkdfguard-native-linux \
    --signer-workflow runsecure/hkdfguard-native-linux/.github/workflows/release.yml
# or, with cosign 2.4+:
cosign verify-blob-attestation --new-bundle-format --bundle "$lib.sigstore.json" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github\.com/runsecure/hkdfguard-native-linux/\.github/workflows/release\.yml@refs/tags/v' \
    --type slsaprovenance1 "$lib"
```

To build and test locally, from `dist/packages/ubuntu24.04-<arch>/`
(`DISTROS=ubuntu24.04 packaging/build-packages.sh`):

```sh
packaging/build-overlay.sh    # hkdfguard-overlay:local and :local-dev for this architecture
```

## External-secret file requirements

For the external-secret provider the mounted file *is* the KEK, so it is
held to the same standard as the PKCS#11 PIN and the TPM owner password.
`<mount>/<service>` must:

- hold **exactly 32 raw random bytes**, used directly as the HMAC-SHA-256
  key: not base64 or hex text, no trailing newline, not PEM or DER. Any
  other length is refused with an error saying so, and so is an all-zero
  file. Generate one with `head -c 32 /dev/urandom > <file>` or
  `openssl rand -out <file> 32`;

- be **owned by root or by the process's user**, with **no group or other
  access** — `0400` or `0600`. A root-owned file may also be readable by
  its group (`root:<group> 0440`), which is how a non-root service reads
  it; never by others, and never by the group of a file the service owns
  itself;
- be a **regular file** (not a directory, device, or FIFO);
- **resolve to a path inside the mount.** Symlinks are followed —
  Kubernetes Secret volumes present every key as a symlink into `..data/`,
  and refusing that would refuse the most common delivery mechanism — but
  only while the resolution stays within the mount directory. A link
  leading anywhere else is refused;
- sit in a **mount nobody else can write to**: the mount directory and
  every directory above it must be owned by root or the process's user and
  not writable by group or others -- sticky or not, so a mount anywhere
  under `/tmp`, `/var/tmp` or `/dev/shm` is refused, however private the
  directories beneath it; so must the directory the resolved file sits in,
  and every one above it. The one exception is a read-only mount: a
  Kubernetes Secret volume is `1777` but read-only, and is fine. A mount
  another user could write to would let them plant a KEK for a service
  that isn't provisioned yet, which `create_kek` would then adopt.

A file that is present but fails a check is reported as an **error**,
never as "not provisioned": a misconfigured mount must not silently fall
through to a weaker provider. `hkdfguard_kek_exists` surfaces it the same
way.

Every common mechanism meets the mode requirement with one setting:

| Mechanism | Setting |
|---|---|
| Kubernetes `Secret` volume | `defaultMode: 0400` on the volume (files are root-owned); a non-root pod also sets `fsGroup` |
| Vault Agent template/sink | `perms = "0400"` |
| Docker Swarm secret | `mode: 0400` (the default `0444` is refused) |
| CSI Secrets Store | `defaultMode`/file permission in the `SecretProviderClass` |
| systemd `LoadCredential=` | already `0400`, root-owned — works as-is |

> **Non-root pods:** the kubelet always writes Secret files as root, so a
> pod running as another user can only read them through `fsGroup`. With
> `fsGroup` set, the kubelet makes each file `root:<fsGroup> 0440` and
> adds the group to the pod's processes, and the provider accepts it.
> Without `fsGroup`, a non-root pod is refused the file by the kernel.
> Keep the KEK in a Secret of its own, so that only pods meant to hold it
> mount it.

## Wrapping a key with the CLI (`hkdfguard`)

Because a wrapped payload can only be produced on the host that holds the
KEK, a deployment pipeline delivers the *plaintext* DEK to the host and
wraps it there. This CLI is that step, in two deliberately separate
commands. Under the production security model (the default), `provision` of
a new KEK and `retire` need root, and `wrap` needs root or a deployer (a
member of `hkdfguard-deployers`, or of a policy `deployer_groups` group);
anyone else's `wrap` is refused before the DEK is read ("may not persist key
files ... Nothing was written"). See "Security model".

```sh
# 1. Once, at deployment time: ensure the service has a KEK, and print its
#    fingerprint. With `retire`, the only command that makes the
#    (deliberately slow) setup calls.
hkdfguard provision --service-name com.company.orders

# 2. Wrap a DEK under it. Never creates a KEK: if none is provisioned it
#    fails and names the command above. --fingerprint (optional) writes
#    nothing unless the DEK was wrapped under the KEK provision reported.
printf '%s' "$DEK_B64" | hkdfguard wrap \
    --key-file-path /var/lib/app/key.bin \
    --service-name com.company.orders --dek-stdin \
    --fingerprint <fingerprint from provision>

# ...or from a file: a Kubernetes/Vault secret mount, or a systemd credential
hkdfguard wrap \
    --key-file-path /var/lib/app/key.bin \
    --service-name com.company.orders \
    --dek-file "$CREDENTIALS_DIRECTORY/dek"
```

`provision` is idempotent and never changes an existing KEK, but it
always verifies one: it loads the KEK through the provider (on a TPM,
loading its key file into the TPM and checking it against any pinned
Name; on PKCS#11, finding the HMAC key on the token) and reports "already
provisioned ... verified". So a KEK that is missing or wrong on the
provider fails at deployment, not at the first wrap. On a TPM it creates
the service's key file; on PKCS#11, its HMAC secret key; for `external-secret`
the mounted file *is* the provisioning.

`provision` prints the KEK's fingerprint, and `wrap` prints the
fingerprint of the KEK it actually wrapped under, read from the payload it
is about to write. `wrap --fingerprint` checks the two match before
writing: `wrap` is the step that commits a secret to a KEK, and if the
service's KEK had been replaced since provisioning, the DEK would
otherwise be sealed to that key, and the mistake found only at unwrap
(`KEK_FINGERPRINT_MISMATCH`, `-16`). On a mismatch nothing is written, and
with `--force` the existing key file is left as it was. The check reads
the fingerprint from the finished payload rather than asking for the KEK's
fingerprint first, so the KEK can't change between the check and the
wrap.

The DEK is base64 of exactly 32 bytes, read from stdin or a file — never
from a command-line argument or an environment variable, both of which are
readable by any process running as the same user (`/proc/<pid>/cmdline`,
`/proc/<pid>/environ`). `printf` is a shell builtin, so the DEK never
reaches any argv.

`wrap` never writes a key file in place. It completes the wrap in memory,
writes the payload to a hidden temporary file in the same folder, syncs
it, and only then gives it the key file's name. With `--force` that last
step is a `rename(2)` over the existing file, so the path holds the old
key file or the new one at every moment. Whatever fails before then (no
KEK, provider unavailable, bad input, a full disk, a folder that refuses
the write) leaves the existing key file exactly as it was, and no
temporary file behind.

The replaced file is then securely overwritten through a descriptor
opened before the rename. `--force` only ever replaces a regular file at
that exact path: a symlink there is refused rather than followed, as are a
directory, FIFO, or device, any file far larger than a wrapped key, and a
file with more than one hard link (overwriting it would also destroy the
file at its other name). A replaced file that still turns out to have a
name, because something moved it during the wrap, is left alone, with a
warning. The overwrite is best-effort: on copy-on-write or
log-structured filesystems (btrfs, ZFS) and on flash storage, old blocks
can survive it.

The key file's folder must be a real folder at the path spelled: a
`--key-file-path` that goes through a symbolic link anywhere above the file
is refused, with or without `--force`, so a link planted where the operator
writes can't redirect a `wrap --force` into another folder. Spell the real
path (`/run/...`, not `/var/run/...`). This is checked before the DEK is
read, and again on the open file before anything is overwritten or written.

Nor may the key file's folder, or any folder above it up to `/`, be
writable by group or others -- **sticky folders such as `/tmp`, `/var/tmp`
and `/dev/shm` included**, however private the folder inside them. The
library refuses to read a key file under such a folder
(`HKDFGUARD_ERR_FILE_UNTRUSTED`, `-39`), so `wrap` refuses to write one
there, before the DEK is read or a provider is reached, naming the folder
and its mode. Under the developer security model only the folders' modes
are checked, not who owns them: `wrap` often runs as root into a folder the
application's account owns, which the library, running as that account,
accepts. Under production the rule doesn't depend on the reader, so `wrap`
checks it exactly, through `hkdfguard_key_file_principal_trusted`: every
folder must be owned by root or a deployer, and may be group-writable only
through a deployer group. Put key files somewhere like `/var/lib/<app>/`
(`0755`, owned by root), or in a folder the deployers share,
`root:hkdfguard-deployers 2775`.

The key file is written `0600`, owned by whoever runs the command. It is
ciphertext, but anyone who can read it *and* reach the provider — on a TPM
host, any member of `tss` — can unwrap it, so nothing beyond its owner is
granted by default. If the service that reads it runs as a different user,
pass `--group <name|gid>`. The file then goes to that group and becomes `0640`
(owner read/write, the group read-only), the same as the Windows tool's
`--group`. The group is set on the open file before anything is written, so the
payload is never readable by any other group. Only root, or a member of the
group, can give a file to it. Over-broad groups are refused: `root`, `users`,
`nogroup`, `nobody`, `wheel`, `sudo`, `adm`, `staff`, and gids 0 and 65534,
matched by name and by gid. `hkdfguard_open_file` accepts the result, since
group read is never a reason to refuse a key file.

A `--dek-file` must be reached through real folders (no symbolic link anywhere
above it, as for the key file), and must be a regular file, not a symlink, owned by root or by
the invoking user, with no group or other access (e.g. `0400`/`0600`). Its
folder, and every folder above it up to `/`, must be owned by root or the
invoking user and not writable by group or others -- sticky folders such as
`/tmp` included, unless on a read-only mount -- or someone else could put a
DEK of their choosing there. These are the rules the library applies to the
PKCS#11 PIN and the TPM owner password. On both paths the input is strict standard base64 (`+/`, padded), at
most 64 bytes: one trailing newline (LF or CRLF) is ignored, and no other
whitespace is accepted. A leading UTF-8 byte-order mark (some Windows tools
add one) is skipped, and UTF-16 input is refused with a message saying so.
The Windows tool applies the same rules, so the same input works on both.
Decoding uses RustCrypto's `base64ct`, constant time with respect to the DEK
text, and any malformed input gets one fixed message that names no character
or offset, so a mistyped DEK never ends up in a log. `--dek-stdin` refuses
an interactive terminal: pipe the DEK in rather than typing or pasting it,
so it isn't echoed or kept in the scrollback.

> The remaining exposure is upstream of this tool: don't put the DEK in an
> environment variable, and don't pipe it with an `echo` that resolves to
> `/bin/echo` (argv again). `printf` as a shell builtin is safe.

### Retiring a KEK

`retire` permanently deletes a service's KEK, so that nothing wrapped under
it can be unwrapped again. It takes the fingerprint `provision` printed for
that KEK, and deletes nothing unless the service's current KEK has exactly
that fingerprint:

```sh
hkdfguard provision -sn com.company.orders
# KEK provisioned for service "com.company.orders"
# fingerprint: 3f1c...e09a -- record this; retire requires it

hkdfguard retire -sn com.company.orders -fp 3f1c...e09a   # all 64 hex characters
```

The fingerprint is checked twice: against the KEK the service resolves to
(the one every wrap uses), and again on the exact token objects about to be
deleted. A wrong fingerprint, a missing KEK, or a token holding anything
other than the one secret key `provision` made (a duplicate, or a key
without hkdfguard's protections) deletes nothing. On success it writes audit
event 1004, naming the fingerprint. Running `provision` afterwards creates
a new, different KEK.

`retire` exists only in the CLI. It is not part of the C API, so no
application linking the library can delete a KEK. Under the production
security model it also takes root.

What can be retired depends on the provider:

| Provider | `retire` |
|---|---|
| PKCS#11 | Deletes the service's HMAC secret key from the token. |
| TPM | Deletes the service's key file. The TPM keeps no copy, so the KEK is gone -- unless a copy of the key file survives (a backup), which still loads on this TPM: destroy those too. |
| External secret | Refused: the KEK is the mounted secret. Remove it where it is managed (the Kubernetes Secret, Vault entry, systemd credential). |
| Ephemeral | Refused: an ephemeral KEK ends with its process. |

## Configuration

Every setting -- which TPM, which key directory, which secret mount,
which PKCS#11 module, token and PIN file -- comes from one root-owned file,
the policy at `/etc/hkdfguard/policy.toml` (see "Policy file reference"), or
a built-in default. Nothing in the environment can redirect any of it, in
any build that ships -- release or debug. The environment is often set by
lower-trust configuration than `/etc/hkdfguard` (a unit drop-in, a pod
spec), and whoever picks the TPM picks who knows its seed. A build that
finds `HKDFGUARD_POLICY_FILE` set ignores it and logs a warning.

The only environment variable the library acts on:

| Env var | Purpose |
|---|---|
| `TSS2_LOG` | tpm2-tss's own log level. If it sets `debug` or `trace` for any module, the TPM provider **refuses to run**: at those levels tpm2-tss logs raw TPM commands and responses (including `TPM2_HMAC` outputs, i.e. wrapping keys), session keys, and plaintext parameters, and `TSS2_LOGFILE` can send that to any path. `info` and below are fine. |

### Testing against scratch configuration

Tests need their own policies, pointing at simulators, scratch secrets and
SoftHSM2. They get them without anything being redirectable in a real
build:

- **This crate's unit tests** use `policy::test_support::TestPolicy`, which
  exists only under `cfg(test)`. Each test writes its own policy into a
  private temp directory -- layered over the harness's, below -- and the
  library reads it through exactly the production path (ownership,
  location, and parse checks included). It is removed when the test ends.
  With no harness policy, unit tests read *no* policy, so a real
  `/etc/hkdfguard` on the machine never leaks in.
- **Everything run as a separate process** -- the CLI's own tests, the
  integration tests, the C examples -- uses a library built with
  `RUSTFLAGS="--cfg hkdfguard_test_paths"`. Only such a build reads
  `HKDFGUARD_POLICY_FILE` (and accepts config owned by the invoking user
  rather than root), and it says so in its log. No ordinary build setting
  -- a cargo feature, a profile, `--all-features` -- can turn it on, and
  nothing that ships is built with it. Without it, the tests that need it
  are reported as ignored, naming the flag.

`scripts/native-tpm-test.sh`, `docker/entrypoint-test.sh` and CI build these
into `target/test-paths`, write a harness policy naming the TPM, a scratch
key directory and the SoftHSM2 token, and point
`HKDFGUARD_POLICY_FILE` at it. To do the same by hand:

```sh
RUSTFLAGS="--cfg hkdfguard_test_paths" CARGO_TARGET_DIR=target/test-paths \
  HKDFGUARD_POLICY_FILE=/path/to/scratch-policy.toml \
  cargo test --features tpm2 -- --ignored --test-threads=1
```

Secrets are never read from environment variables (`/proc/<pid>/environ`
is readable by same-user processes and inherited by children); every
secret is a file named in the policy, and every such file is checked on the
opened descriptor for ownership, mode, and type before its contents are
trusted.

### Policy file reference

Everything the policy file (`/etc/hkdfguard/policy.toml`) accepts, in one
place. It is [TOML](https://toml.io). Unknown keys are rejected. Every
field is optional except `[selection]`; the values shown are the defaults
where one exists.

Two TOML rules matter here. Top-level keys (`preferred_order`) must come
before the first `[table]` header: written below one, they belong to that
table and the file is rejected. And service names in `[tpm.pinned_names]`
must be quoted: an unquoted `com.company.orders` is a dotted key meaning
nested tables, which is also rejected.

```toml
preferred_order = ["tpm2", "pkcs11", "external-secret"]
                                    # with `prefer`: try in this order; omitted providers are excluded.
                                    # This is also the ONLY way Ephemeral is ever used: it must be named here
                                    # (or be the `require` provider). With no policy file at all, the order is
                                    # tpm2, pkcs11, external-secret -- and never ephemeral.

[key_requirements]
minimum_protection = "external"     # ephemeral | software | external | hardware; providers below this tier are excluded

[selection]
mode = "prefer"                     # require | require-level | prefer
provider = "tpm2"                   # with `require`: exactly this provider (tpm2 | pkcs11 | external-secret | ephemeral)
level = "hardware"                  # with `require-level`: any provider at this tier or above

[startup_behavior]
setup_min_delay_ms = 1000           # floor on create_kek/kek_exists latency; 0 disables, max 60000
fail_if_requirement_unmet = true    # accepted for schema parity; the library always fails closed regardless

[tpm]
key_dir = "/var/lib/hkdfguard/tpm"  # absolute path; a <service>.tpmkey and <service>.tpmauth per service, created by provision
require_pinned_names = false        # true: only services in pinned_names exist on the TPM (provisioning allowlist)
session_encryption = "on"           # on | off (test harnesses only)  (see "Session parameter encryption")
pinned_session_salt_key_name = "000b<64 hex>"   # the storage root key's Name; pin before provisioning on a discrete TPM
tcti = "device:/dev/tpmrm0"         # which TPM: device:<path> | tabrmd:<conf> | mssim:<conf> | swtpm:<conf>
                                    # mssim/swtpm are for testing only: no resource manager, so another client of
                                    # the same simulator can swap a key handle between its Name check and its use
owner_auth_file = "/etc/hkdfguard/tpm.owner-auth"  # unset: empty owner password. Absolute path; root-owned, 0400 (or 0440 with the service's group); see "Protect the hierarchy"

[tpm.pinned_names]                  # per-service expected TPM Name; refuse any other key
"com.company.orders" = "000b<64 hex>"

[external_secret]
dir = "/var/run/secrets/hkdfguard"  # where <service> KEK files live; when set, the only place looked
                                    # (default: first existing of the four conventional mounts)
require_pinned_keys = false         # true: only services in pinned_keys have a KEK here (provisioning allowlist)

[external_secret.pinned_keys]       # per-service expected KEK fingerprint (or a list, while rotating); refuse any other key
"com.company.orders" = "<64 hex>"

[audit]
unwrap_success = true               # false: no audit record (1003) for a successful unwrap; see "Audit trail"

[pkcs11]
module = "/usr/lib/vendor/libhsm-pkcs11.so"   # PKCS#11 is used only when this is set (no default search); root-owned
pin_file = "/etc/hkdfguard/pkcs11.pin"        # root-owned 0400, or 0440 with the service's group; this is the default
token_label = "hkdfguard-prod"      # choose the token by label and/or serial; exactly one must match.
token_serial = "0123456789abcdef"   # with neither, exactly one initialized token must be present
```

The policy file must be owned by root and not writable by group or
others, in directories only root can change. So must the PIN file, which
additionally may be read by nobody but root and, optionally, the
service's group: a PIN file the service could write would let any process
running as that user write a wrong PIN and lock the HSM user out. The
PKCS#11 module, its directory, and every directory above it must be
root-owned and not group/other-writable, so nothing on the module's path
can be swapped before it is `dlopen`ed. "Directories only root can
change" means every one up to `/`, sticky directories such as `/tmp`
included: nothing here may live anywhere under `/tmp`, `/var/tmp` or
`/dev/shm`. Only a read-only mount (a Kubernetes Secret or ConfigMap
volume) is exempt.

Only a *missing* file means "no policy"; a present but
unreadable, too-broadly-writable, or malformed file makes every operation
fail closed with `HKDFGUARD_ERR_POLICY_INVALID` (`-9`) -- and resolves
each hardening knob to its strictest setting
(`session_encryption = "on"`, the pinned-names allowlist on) rather than
its default.

## Design decisions worth knowing

- **Wire format is hand-rolled, not `serde`+`bincode`.** The wrapped
  payload ([`src/payload.rs`](src/payload.rs)) is security-critical: it
  is the AAD input as well as the on-disk layout, so every field width
  and order is pinned explicitly rather than left to a serialization
  library's derive output, which could silently change across a
  dependency bump. 
- **Pure-Rust crypto (`hmac`/`sha2`/`aes-gcm`), not OpenSSL**, for the
  protocol itself. No system OpenSSL version skew across distros, trivial
  static linking (`libhkdfguard.a`), and RustCrypto's HMAC-SHA-256 and
  AES-256-GCM implementations satisfy the mandated algorithm list exactly.
  They are not a FIPS 140 validated module, so the library uses only
  NIST-approved functions but is not itself FIPS validated.
  TPM2 and PKCS#11 still, necessarily, link against their respective
  native libraries.
- **TPM2 KEKs are key files, not persistent handles or derived
  primaries.** Rather than using `EvictControl` to persist a key into the
  TPM's limited persistent-handle range (which needs an owner-auth session
  and a local `service -> handle number` mapping to protect and never
  lose), each service's key is created once with `TPM2_Create` under the
  standard storage root key and saved as a key file the TPM encrypted; each
  use re-creates the storage root key with `TPM2_CreatePrimary` (it is
  deterministic for a fixed hierarchy and template) and loads the key file
  under it. No persistent-handle bookkeeping, no exhaustion risk, and
  provisioning is real: a service has a TPM KEK only once `provision` has
  created its key file. An earlier design derived each service's key as a
  primary, with a host secret folded into the template's `unique` field;
  that secret crossed a discrete TPM's bus in cleartext with every
  re-derivation, which a key file never does. See "The TPM key and its key
  file" and the module doc in [`src/provider/tpm2.rs`](src/provider/tpm2.rs).
- **The external-secret provider never creates keys, only loads them**,
  and declines per-service (not globally) when nothing is provisioned for
  a given `service`. `hkdfguard_create_kek` then continues down the
  policy-allowed chain; if nothing there can create one -- and Ephemeral
  is never a candidate unless the policy names it -- the call fails with
  `HKDFGUARD_ERR_PROVIDER_UNAVAILABLE` rather than quietly producing a key
  that would be lost on restart.
- **Nothing is cached between calls.** Providers are constructed fresh on
  every call and dropped after it; there are no standing TPM or PKCS#11
  sessions, no memoized provider selection, and the policy file is re-read
  from disk each time. The only per-process state is a handful of facts
  about the *hardware* (the TPM conformance verdict)
  that cannot change underneath a
  running process, and the PKCS#11 module's library handle: `C_Initialize`
  and `C_Finalize` act on the whole process, and finalizing while another
  thread is mid-call is undefined behavior, so a module is initialized once
  and never finalized. That handle is not authority -- every PKCS#11
  session and login is still opened per call and closed with it. This is
  deliberate: the most secret parts of the system are re-authenticated on
  every use rather than held open.
- **Unwrap always uses the provider recorded in the payload**, not
  whichever provider is currently strongest -- and that provider tag is
  authenticated, so it cannot be steered. If it differs from what policy
  would pick today, a debug-level migration hint is logged so operators
  know it's time to re-wrap onto the stronger provider.

## Security properties

- **No Rust type, TPM handle, OpenSSL structure, or PKCS#11 object crosses
  the C ABI.** Only `int`/`uint8_t*`/`char*`.
- **No panic ever unwinds across the ABI.** Every exported function is
  wrapped in `catch_unwind`; a caught panic returns `HKDFGUARD_ERR_INTERNAL_ERROR`.
  That needs the panic strategy `unwind` (`Cargo.toml` sets it for release,
  and every package is built that way). A Rust program linking the crate
  into a binary built with `panic = "abort"` aborts on a panic instead --
  never undefined behavior, but not a status code either.
- **DEK plaintext is stack-only, never heap, during wrap/unwrap.**
  `crypto.rs` uses `AeadInOut::{encrypt,decrypt}_inout_detached`, in place, on a
  stack-allocated `[u8; 32]` instead of the more convenient
  `Aead::{encrypt,decrypt}`, which internally allocates a heap `Vec<u8>`
  for exactly this data.
- **Key material never leaves the TPM or the PKCS#11 token.**
  `Pkcs11Handle` holds no key bytes at all -- only the object handle for
  the HMAC key and the open session. `Tpm2Handle` holds the service's key
  file as read once per wrap/unwrap -- its public half, and its private half
  encrypted under the storage root key, which only this TPM can use -- so
  the fingerprint and the wrapping key come from the same key even if the
  file is replaced in between. `prf()` asks the device/token to compute
  HMAC-SHA-256 and only the (non-reversible) outputs cross back.
- **Every secret file is checked on its opened descriptor, never by path.**
  The policy file, the PKCS#11 PIN, TPM key files and the owner password,
  an external-secret KEK, and the CLI's `--dek-file` all go through the same
  discipline (`src/secure_file.rs`): open, then `fstat` the descriptor for
  regular-file type, ownership, and mode, so nothing can be swapped between
  the check and the read. The policy, PIN, and owner password must be
  root-owned (in every build but the test ones), and TPM key files owned by
  whoever may create KEKs, in directories only they can change, so
  the service's own uid can't rewrite (or delete) them. Secret contents are read into a single fixed
  allocation that is never grown (so no partially-filled buffer is ever
  freed un-wiped) and zeroed on every exit path.
- **Nothing the library reads is trusted under a shared directory.**
  The policy file, the PKCS#11 module and PIN file, TPM key files and the
  owner password, external-secret KEKs, and key files opened
  with `hkdfguard_open_file` must each sit in a directory that, with every
  directory above it up to `/`, is owned by root (or, where the file may
  be, the calling user) and not writable by group or others. For the
  policy, PIN, TPM and `hkdfguard_open_file` paths that holds for every
  directory the path is looked up in -- symlinks followed the way the
  kernel follows them, and the directory each link lives in checked like
  the rest. All of it applies with no exception for sticky directories, so nothing under `/tmp`, `/var/tmp` or
  `/dev/shm` is accepted, however private the directory beneath. The one
  exception is a read-only mount: a Kubernetes Secret or ConfigMap volume
  is `1777` but nobody can write to it. The refusal names the directory
  and says when it was a sticky one. The CLI holds its own files to the
  same rule: `wrap` refuses to write a key file where it would be refused,
  and to read a `--dek-file` from such a directory.
- **Service names can never name a file outside their mount.** The C ABI
  rejects a `service` that starts with `.` or contains `..`, and the
  external-secret provider enforces the same rule again where the name
  becomes a path -- plus a containment check that any symlink it follows
  resolves inside the mount directory.
- **Every other point a secret transits a heap buffer is explicitly
  zeroized**, not left to an incidental `Drop`: every HMAC output,
  including the wrapping key (`Zeroizing<[u8; 32]>` throughout), the AES
  key schedule built from it (aes-gcm's `zeroize` feature), the SHA-256
  states keyed with a software KEK (sha2's `zeroize` feature), and the
  external-secret and ephemeral providers' copies of their KEKs. What stays
  out of reach is stack residue inside the RustCrypto crates themselves:
  the HMAC pad blocks `hmac` 0.13 derives from a software-held KEK (it has
  no zeroize support) and compression-function temporaries.
- **On any `hkdfguard_unwrap_dek` failure, the caller's entire declared
  output buffer is zeroed** before returning -- no partial or stale key
  material is ever left behind.
- **KEKs are always cryptographically random**, generated by the provider
  (TPM RNG, PKCS#11 token RNG, or the OS CSPRNG via `getrandom`) -- never derived from hostname,
  machine ID, MAC address, container ID, or any other host fingerprint.
  The one necessary exception is the Ephemeral provider, whose whole
  design requires keeping generated keys in a heap-resident map for the
  life of the process; each call's copy still zeroizes on drop
  (`Zeroizing<[u8; 32]>`), and the keys themselves sit in locked,
  dump-excluded pages, but by definition can't be stack-only across calls.
- **Logging** comes in two kinds. The audit trail (see "Audit trail") is
  syslog `authpriv` records, written whatever the host does. Diagnostics go
  through the `log` crate: provider selection, provider initialization,
  migration events and error reasons, seen only by a host that installs a
  logger (the CLI logs to stderr). Neither ever carries DEKs, KEKs,
  wrapping keys or other HMAC outputs (bar the public fingerprint),
  plaintext or ciphertext. Both name the service.

## Layout

```
src/
  lib.rs                    C ABI: hkdfguard_create_kek / hkdfguard_kek_exists /
                             hkdfguard_wrap_dek / hkdfguard_unwrap_dek /
                             hkdfguard_generate_and_wrap_dek /
                             hkdfguard_harden_process(_with_flags) / hkdfguard_open_file /
                             hkdfguard_security_model / hkdfguard_key_file_principal_trusted;
                             the setup-call gate
  security_model.rs         production/developer: who creates KEKs, whose key files are trusted
  error.rs                  Internal error type <-> C status codes
  payload.rs                Wrapped-payload wire format (version 1)
  crypto.rs                 HMAC-SHA-256 SP 800-108 block -> AES-256-GCM protocol; KEK fingerprint
  policy.rs                 /etc/hkdfguard/policy.toml parsing and evaluation
  secure_file.rs            Descriptor-checked secret-file reads, self-wiping buffer
  provider/
    mod.rs                  KekProvider/KekHandle traits, selection chain
    tpm2.rs                 Provider 1 (feature `tpm2`): key files, Name
                             pinning, session encryption, conformance suite
    tpm_key_file.rs         The TPM key file format (TSS2 PRIVATE KEY), strictly parsed
    pkcs11.rs                Provider 2 (feature `pkcs11`)
    external_secret.rs      Provider 3 (feature `external-secret`, default)
    ephemeral.rs             Provider 4 (feature `ephemeral`, default)
  bin/
    hkdfguard.rs            CLI: `provision`, `wrap` and `retire`
include/hkdfguard.h          C header
examples/
  wrap_unwrap.c              Minimal C consumer (create_kek -> wrap -> unwrap)
  cli_unwrap_check.c         Unwraps a CLI-written key file through the .so
tests/
  cli_round_trip.rs          Drives the CLI as a real subprocess
  harden_process.rs              hkdfguard_harden_process, in its own process
  ephemeral_hardening.rs         Creating an ephemeral key hardens the process, in its own process
scripts/
  build-release.sh           cargo build --release, then links libhkdfguard.so.1
                              (the SONAME) to Cargo's libhkdfguard.so
  native-tpm-preflight.sh    Read-only check of a real Linux TPM host
  native-tpm-test.sh         Full matrix on a real TPM; `reboot capture|verify`
  tpm-reboot-test.sh         swtpm-restart approximation of reboot persistence
  hardware-tests/            The native matrix as a prebuilt bundle, plus a
                              read-only TPM probe, for other machines and
                              Hyper-V guests (run over SSH: run-remote.sh)
docker/                      Dockerfile + entrypoint running the full matrix
                              against swtpm and SoftHSM2 (run-tests.sh)
  distros/                   Per-distribution SoftHSM2 + Ephemeral test images:
                              AlmaLinux, Debian, Ubuntu, SLES, UBI Micro,
                              Amazon Linux, Alpine (run-distro-tests.sh)
  run-all-tests.sh           Every containerized suite (see CONTRIBUTING.md)
build.rs                     Sets the shared library's SONAME (libhkdfguard.so.1)
debian/                      Debian packaging (dpkg-buildpackage)
.github/
  workflows/build.yml        CI: lint, cargo deny, test matrix, packages, binaries
  workflows/release.yml      v* tags: build, attest (Sigstore), draft release, signed overlay images
  dependabot.yml             Weekly updates to the pinned action SHAs
packaging/
  build-packages.sh          Builds and smoke-tests the .deb and .rpm packages
  Dockerfile.debian, .dnf, .suse   Package build images (apt, dnf, zypper targets)
  build-deb.sh, build-rpm.sh In-container package builds
  smoke-test.sh              Installs packages into a clean container and uses them
  release-assets.sh          Release tarballs, SHA256SUMS and attestation subjects from CI artifacts
  build-overlay.sh           Builds the scratch overlay images and tests them in consumer images
  overlay/Dockerfile         FROM scratch overlay: the library and CLI from the packages
  overlay/policy.dev.toml    The -dev overlay's policy: SoftHSM2, else ephemeral
  overlay/consumer-test.sh   Uses the overlay from a consumer image
  check-version.sh           Cargo.toml / debian/changelog / spec version agreement
  rpm/hkdfguard.spec         RPM packaging
  hkdfguard.pc.in            pkg-config template
  policy.toml.example        Annotated policy, installed to /usr/share/hkdfguard
  hkdfguard.1                Man page
  third-party-licenses.py    License notices of the statically linked crates
```

## License

HKDFGuard is licensed under the [Mozilla Public License 2.0](LICENSE)
(`MPL-2.0`).

MPL-2.0 is file-level copyleft: if you distribute modified versions of
this project's source files, those files must stay under MPL-2.0 and
their source must be made available. Programs that only link against
`libhkdfguard` (dynamically or statically) may use any license for their
own code; distributing a binary that includes this library only requires
telling recipients where its source can be obtained (MPL-2.0 §3.2).

The release binaries statically link Rust crates under their own
permissive open-source licenses; their notices ship as
`THIRD-PARTY-LICENSES.txt` (see `packaging/third-party-licenses.py`).

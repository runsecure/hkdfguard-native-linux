# Using HKDFGuard

This page covers the day-to-day workflow: provisioning a service's key,
wrapping a Data Encryption Key (DEK) with the CLI, and unwrapping it from your
application. It assumes HKDFGuard is installed ([installation.md](installation.md))
and the host is configured ([configuration.md](configuration.md)).

- [Concepts](#concepts)
- [The deployment workflow](#the-deployment-workflow)
- [The CLI: `hkdfguard`](#the-cli-hkdfguard)
- [The C API](#the-c-api)
- [Building and linking](#building-and-linking)
- [Running as a service](#running-as-a-service)

## Concepts

| Term | Meaning |
|---|---|
| **DEK** (data encryption key) | Exactly 32 bytes that your application uses to encrypt its own data. HKDFGuard protects it; it doesn't use it. |
| **KEK** (key encryption key) | A per-service P-256 key held by the provider (TPM, HSM or secret file). It never leaves the provider. |
| **Service name** | Names the KEK, e.g. `com.company.orders`. |
| **Wrapped DEK** | The DEK encrypted under the service's KEK: up to 276 bytes, safe to store on disk. |

**Service names** are 1 to 128 bytes of ASCII letters, digits and dots, must
not start with a dot or contain `..`, and are case-insensitive
(`Com.Company.Orders` and `com.company.orders` are the same KEK). Treat them
as public identifiers, not secrets.

**A DEK can only be wrapped on the host that holds the KEK.** You can't
pre-wrap a DEK on a build server for a target host. The plaintext DEK is
delivered to the host, and wrapped there.

## The deployment workflow

```
deployment (once per host and DEK)                application (every start)
---------------------------------------           ---------------------------
1. provision the service's KEK          ──┐
2. wrap the DEK into a key file           ├──>     read the key file
   (the plaintext DEK is then discarded)  │        hkdfguard_unwrap_dek -> DEK
                                          │        use the DEK, wipe it
```

```sh
# 1. Once per host, as root (the security admin): make sure the service has a KEK.
sudo hkdfguard provision -sn com.company.orders

# 2. As root or a deployer (the deployment admin): wrap the DEK, delivered
#    by your secrets pipeline, into a key file the service's group may read.
printf '%s' "$DEK_B64" | sudo hkdfguard wrap \
    -kf /var/lib/orders/dek.wrapped -sn com.company.orders --dek-stdin -g orders

# 3. The service (the application) only reads the key file and unwraps it.
```

These are the production security model's three roles, the default: only
root provisions and retires, only root or a deployer (a member of
`hkdfguard-deployers`) writes key files the library will trust, and the
application unwraps. Under `security_model = "developer"` anyone who can
reach the provider may do all three. See
[configuration.md](configuration.md#security-model-who-may-provision-wrap-and-unwrap).

What `provision` does depends on the provider:

| Provider | What `provision` does |
|---|---|
| TPM | Derives the key on demand, so it reports "already provisioned", after deriving it and checking any pinned Name. With `require_pinned_names`, it fails for an unlisted service and prints the policy line to add. |
| PKCS#11 | Generates the key pair on the token, once; later runs find it there and report "already provisioned". |
| External secret | Checks the delivered file, that it holds a valid key, and that its fingerprint matches any pin: the file itself is the provisioning. With `require_pinned_keys`, it fails for an unpinned service and prints the policy line for the mounted key. |
| Ephemeral | Refused by the CLI, for `provision` and `wrap` alike: an ephemeral key lives only in the process that creates it, so the application must wrap its own DEKs. |

`provision` also prints the KEK's fingerprint. Record it: `retire` asks
for it, and a later `provision` prints it again so you can confirm the
service still has the same KEK.

## The CLI: `hkdfguard`

```
hkdfguard provision --service-name|-sn <name>
hkdfguard wrap --key-file-path|-kf <path> --service-name|-sn <name> \
               (--dek-stdin | --dek-file <path>) [--group|-g <name>]
               [--fingerprint|-fp <64 hex chars>] [--force|-f]
hkdfguard retire --service-name|-sn <name> --fingerprint|-fp <64 hex chars>
```

| Option | Meaning |
|---|---|
| `--service-name`, `-sn` | The service whose KEK is used |
| `--key-file-path`, `-kf` | Where `wrap` writes the wrapped DEK (mode `0600`, owned by whoever runs the command). No symbolic link may be in the path above the file, and no folder above it, up to `/`, may be writable by group or others -- sticky folders such as `/tmp` included, since `hkdfguard_open_file` refuses a key file there (`-39`). Checked before the DEK is read. Under the developer model only the folders' modes are checked, not who owns them; under production each folder must be owned by root or a deployer, and may be group-writable only through a deployer group (a `root:hkdfguard-deployers 2775` folder), exactly as the library will check it. |
| `--dek-stdin` | Read the DEK, base64 of exactly 32 bytes, from standard input |
| `--dek-file <path>` | Read the DEK from a file: a regular file, not a symlink and not reached through one, owned by root or you, mode `0400` or `0600`, in a folder that -- with every folder above it, up to `/` -- is owned by root or you and not writable by group or others, sticky folders such as `/tmp` included (a read-only mount is exempt) |
| `--group`, `-g` | Also let this group read the key file (mode `0640`). For a service running as another user. Over-broad groups (`root`, `users`, `nogroup`, `nobody`, `wheel`, `sudo`, `adm`, `staff`) are refused. |
| `--fingerprint`, `-fp` | The KEK's fingerprint, as `provision` printed it (64 hex characters). For `wrap`: nothing is written unless the DEK was wrapped under that KEK. For `retire`: required; nothing is deleted unless it matches. |
| `--force`, `-f` | Replace an existing key file. The new wrap completes first, so a failed wrap never destroys the old file; the old file is then overwritten and removed. Refused for a symlink, a non-regular file, or a file with more than one hard link. |

Exit status: `0` success, `1` the operation failed, `2` invalid command line.

Each flag may be given once, and a flag's value may not start with `-`:
`wrap -kf --force ...` is an invalid command line, not a key file named
`--force`. Write a path that starts with `-` as `./-name`.

**Keep the DEK out of command lines and environment variables.** Other
processes running as the same user can read both through `/proc`, so the CLI
doesn't accept the DEK either way.
- Pipe it with `printf`, which is a shell builtin and never appears in a
  process list. Don't use an external `echo`.
- Or pass a file, such as a systemd credential:
  `--dek-file "$CREDENTIALS_DIRECTORY/dek"`.

To generate a new random DEK as base64:
`head -c 32 /dev/urandom | base64 -w0`.

`wrap` never creates a KEK. If the service isn't provisioned, it fails and
tells you to run `provision`.

Under the production security model (the default), `provision` of a KEK
that doesn't exist yet, and `retire`, need root: anyone else gets "only root
creates or retires a KEK" (`provision` of an existing KEK only verifies it,
which anyone may). `wrap` needs root or a deployer -- a member of
`hkdfguard-deployers`, or of a group the policy lists in `deployer_groups`
-- since the library trusts only their key files; anyone else is refused
before the DEK is read ("may not persist key files ... Nothing was
written").

`wrap` prints the fingerprint of the KEK it actually wrapped under, read
from the payload it is about to write. Pass `--fingerprint` with the value
`provision` printed and it checks this for you: if the service's KEK is not
that one (replaced, re-provisioned, or on a different provider than you
expected), nothing is written and the DEK is not committed to that key.
With `--force`, the existing key file is left as it was.

`retire` permanently deletes the service's KEK, and with it every DEK
wrapped under it. It deletes nothing unless the KEK's fingerprint is the
one given. Only PKCS#11 keys can be retired; a TPM key isn't stored
anywhere, so there's nothing to delete. See "Retiring a KEK" in the README.

The CLI hardens itself before touching key material (no core dumps, no
debugger attachment) and refuses to run if it can't. It also tries to lock
its memory out of swap: as root, or with `LimitMEMLOCK=infinity`, everything
is locked. Otherwise it locks only its own copy of the DEK and prints a
warning (`memory not locked as a whole`).

## The C API

```c
#include <hkdfguard.h>
```

| Function | Purpose |
|---|---|
| `int hkdfguard_create_kek(const char* service)` | Ensure the service has a KEK (the only call that creates one). Idempotent. Under the production security model only root creates one; anyone else gets the existing KEK, or `HKDFGUARD_ERR_KEK_ACCESS_DENIED` |
| `int hkdfguard_kek_exists(const char* service, int* exists)` | Report whether a KEK exists, without creating one |
| `int hkdfguard_wrap_dek(const char* service, const uint8_t* dek, int dek_len, uint8_t* out, int* out_len)` | Wrap a 32-byte DEK |
| `int hkdfguard_unwrap_dek(const char* service, const uint8_t* wrapped, int wrapped_len, uint8_t* out, int* out_len)` | Recover the DEK from a wrapped payload |
| `int hkdfguard_generate_and_wrap_dek(const char* service, uint8_t* out, int* out_len)` | Generate a random DEK and return only its wrapped form |
| `int hkdfguard_open_file(const char* path, uint8_t* out, int* out_len)` | Read a wrapped-key file, checking its length and form; `*out_len` is the number of bytes read. Doesn't unwrap |
| `int hkdfguard_security_model(int* out_model, int* out_may_write_key_files)` | The security model in force (`HKDFGUARD_SECURITY_MODEL_PRODUCTION` 0, `HKDFGUARD_SECURITY_MODEL_DEVELOPER` 1), and whether a key file this process writes would be trusted |
| `int hkdfguard_key_file_principal_trusted(const char* principal, int* out_trusted)` | Whether `"uid:<n>"` may own, or `"gid:<n>"` write through its group, a key file or a folder above one, under the model in force: for tools that prepare key folders |
| `int hkdfguard_harden_process(void)` | Opt in to process hardening: no core dumps, no same-user debugging |
| `int hkdfguard_harden_process_with_flags(unsigned int flags)` | The same, with options. `HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE` makes a debuggable process a failure on macOS (where it depends on code signing); on Linux it's accepted and changes nothing |

**Rules that matter.**

- **`hkdfguard_create_kek` and `hkdfguard_kek_exists` are deliberately
  slow:** each takes at least one second, and they run one at a time.
  Call one of them once at startup, never per request. Wrap and unwrap
  aren't rate-limited.
- **Wrap never creates a KEK.** Before `hkdfguard_create_kek` has
  succeeded for a service, wrap returns `HKDFGUARD_ERR_KEK_NOT_FOUND`.
- **Buffer sizes:** a buffer of `HKDFGUARD_WRAPPED_MAX_LEN` (276) bytes
  always fits a wrapped DEK, and `HKDFGUARD_DEK_LEN` (32) always fits an
  unwrapped one. On `HKDFGUARD_ERR_BUFFER_TOO_SMALL`, `*out_len` holds a
  size to retry with.
- **Unwrap zeroes your whole output buffer on every failure**, so it never
  leaves partial key material behind.
- **Cache the unwrapped DEK** for as long as you need it, rather than
  unwrapping per request. Every call opens a fresh TPM or HSM session.

**Status codes.** Every function returns `HKDFGUARD_OK` (0) or one of these:

| Code | Name | Meaning |
|---|---|---|
| -1 | `HKDFGUARD_ERR_INVALID_ARGUMENT` | Null pointer, DEK length other than 32, negative capacity |
| -2 | `HKDFGUARD_ERR_BUFFER_TOO_SMALL` | `*out_len` now holds the size needed |
| -3 | `HKDFGUARD_ERR_PROVIDER_UNAVAILABLE` | No allowed provider is available on this host |
| -4 | `HKDFGUARD_ERR_PROVIDER_ERROR` | A provider is present but failing |
| -5 | `HKDFGUARD_ERR_CRYPTO_ERROR` | A cryptographic step failed for a reason other than authentication, such as the OS random number generator failing |
| -6 | `HKDFGUARD_ERR_INTERNAL_ERROR` | An internal failure: a bug in the library (a caught panic) |
| -8 | `HKDFGUARD_ERR_INVALID_SERVICE_NAME` | The service name breaks the naming rules |
| -9 | `HKDFGUARD_ERR_POLICY_INVALID` | The policy file can't be used: it doesn't parse, a setting is invalid, it or its directory has unsafe ownership or permissions, or it requires a provider this build lacks |
| -10 | `HKDFGUARD_ERR_PAYLOAD_MALFORMED` | The wrapped data isn't a well-formed payload: truncated, extra bytes, or a field no wrap produces |
| -11 | `HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED` | The wrapped data failed authentication: tampered with, or for a different service |
| -12 | `HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED` | The wrapped data has a payload version this library doesn't know |
| -16 | `HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH` | The payload was wrapped under a different KEK than the service has now |
| -17 | `HKDFGUARD_ERR_KEK_NOT_FOUND` | The service has no KEK yet: provision it first |
| -18 | `HKDFGUARD_ERR_KEK_ACCESS_DENIED` | Under the production security model, a non-root caller asked `hkdfguard_create_kek` for a KEK that doesn't exist yet (or the CLI's `retire`): only root creates or retires one |
| -20 | `HKDFGUARD_ERR_PROCESS_HARDENING_FAILED` | `hkdfguard_harden_process` couldn't apply its settings |
| -32 | `HKDFGUARD_ERR_FILE_NOT_FOUND` | `hkdfguard_open_file`: the file, or a directory in its path, doesn't exist |
| -33 | `HKDFGUARD_ERR_FILE_ACCESS_DENIED` | `hkdfguard_open_file`: the OS refused to let this process open the file (for example, no read permission) |
| -34 | `HKDFGUARD_ERR_FILE_IO` | `hkdfguard_open_file`: not a regular file, or the read failed |
| -35 | `HKDFGUARD_ERR_FILE_TOO_SHORT` | `hkdfguard_open_file`: the file is shorter than a wrapped DEK, or than its header says (a truncated copy) |
| -36 | `HKDFGUARD_ERR_FILE_TOO_LONG` | `hkdfguard_open_file`: the file is longer than a wrapped DEK, or than its header says (data appended) |
| -37 | `HKDFGUARD_ERR_FILE_PLAINTEXT_KEY` | `hkdfguard_open_file`: the file looks like an **unwrapped** DEK (32 raw bytes, or its base64 or hex). Treat it as a key exposure: delete the file and rotate the DEK |
| -38 | `HKDFGUARD_ERR_FILE_MALFORMED` | `hkdfguard_open_file`: the length is right but the contents aren't a wrapped DEK |
| -39 | `HKDFGUARD_ERR_FILE_UNTRUSTED` | `hkdfguard_open_file`: the file, or a directory above it (or above a symlink to it), is owned by someone the security model doesn't trust, or writable by someone else, so someone else could have replaced it. Under production (the default) key files and their directories must be owned by root or a deployer, and group-writable only through a deployer group: a key file the service's own account owns is refused. Under developer, owned by the service or by root, with no group write. Either way, all the way up to `/`. Sticky directories are **not** trusted -- for key files or anything else the library reads: a key file anywhere under `/tmp`, `/var/tmp`, `/dev/shm` or another sticky, world-writable directory is refused, however private the directories beneath it (a read-only mount, such as a Kubernetes Secret volume, is fine) |

The numbers are the same in the Windows and macOS builds of this library,
which share one status table. `hkdfguard.h` also defines the codes only
those platforms return (`HKDFGUARD_ERR_KEK_INVALID` (-19), and the
platform-specific codes from -64 down, other than Linux's own); Linux never
returns them. Linux's own band starts at -80:

| Code | Name | Meaning |
|---|---|---|
| -80 | `HKDFGUARD_ERR_LINUX_GROUP_INVALID` | Refines -9: a deployer group (`deployer_groups`, or `hkdfguard-deployers`) doesn't exist, is over-broad, or can't be looked up. Every key-file read fails until it is fixed |
 A platform-specific code always refines a
common one (its comment in the header says which), so it is safe to handle
it as that code.

The library doesn't print its reasons for a failure. To see why a call
fails, run the CLI as the same user; see [troubleshooting.md](troubleshooting.md).

**Example: unwrapping a key file at startup.** This reads the file
`hkdfguard wrap` wrote, recovers the DEK, and wipes it after
use:

```c
#include <hkdfguard.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const char* service = "com.company.orders";

    if (hkdfguard_harden_process() != HKDFGUARD_OK) {
        fprintf(stderr, "could not harden the process\n");
        return 1;
    }

    /* Read the wrapped DEK. It is ciphertext: safe to hold in normal memory.
     * hkdfguard_open_file checks it is a complete wrapped DEK, and refuses a
     * file that holds a plaintext key instead. */
    uint8_t wrapped[HKDFGUARD_WRAPPED_MAX_LEN];
    int wrapped_len = sizeof(wrapped);
    int rc = hkdfguard_open_file("/var/lib/orders/dek.wrapped", wrapped, &wrapped_len);
    if (rc == HKDFGUARD_ERR_FILE_PLAINTEXT_KEY) {
        fprintf(stderr, "the key file holds an UNWRAPPED key: delete it and rotate the DEK\n");
        return 1;
    }
    if (rc != HKDFGUARD_OK) {
        fprintf(stderr, "reading the key file failed: %d\n", rc);
        return 1;
    }

    /* Recover the DEK. */
    uint8_t dek[HKDFGUARD_DEK_LEN];
    int dek_len = sizeof(dek);
    rc = hkdfguard_unwrap_dek(service, wrapped, wrapped_len, dek, &dek_len);
    if (rc != HKDFGUARD_OK) {
        fprintf(stderr, "unwrap failed: %d\n", rc);
        return 1;
    }

    /* ... use dek[0..31] to decrypt or encrypt your data ... */
    printf("recovered a %d-byte DEK\n", dek_len);

    explicit_bzero(dek, sizeof(dek)); /* wipe it when you're done */
    return 0;
}
```

To create and wrap a new DEK entirely in your application, call
`hkdfguard_create_kek(service)` once at startup, then
`hkdfguard_generate_and_wrap_dek` (or `hkdfguard_wrap_dek` with a DEK you
generated) and store the result. [`examples/wrap_unwrap.c`](../examples/wrap_unwrap.c)
shows every call; [`include/hkdfguard.h`](../include/hkdfguard.h) documents
each one in full.

## Building and linking

With the development package installed (`libhkdfguard-dev` or
`hkdfguard-devel`), pkg-config provides the flags.

**Dynamic linking** (recommended):

```sh
cc -o myapp myapp.c $(pkg-config --cflags --libs hkdfguard)
```

**Static linking.** Link `libhkdfguard.a` directly, along with the system
libraries it needs:

```sh
cc -o myapp myapp.c $(pkg-config --cflags hkdfguard) \
    "$(pkg-config --variable=libdir hkdfguard)/libhkdfguard.a" \
    $(pkg-config --static --libs hkdfguard | sed 's/-lhkdfguard\b//')
```

**Other languages.** Load the library by its SONAME, `libhkdfguard.so.1`,
which is the name every installation provides:

```csharp
// .NET
[DllImport("libhkdfguard.so.1")]
static extern int hkdfguard_unwrap_dek(string service, byte[] wrapped, int wrappedLen, byte[] dek, ref int dekLen);
```

```python
# Python
import ctypes
lib = ctypes.CDLL("libhkdfguard.so.1")
```

Don't load it as `hkdfguard` or `libhkdfguard.so`: only the development
package provides `libhkdfguard.so`. The `service` string must be UTF-8 and
NUL-terminated.

## Running as a service

The service's account needs the same provider access that `provision` and
`wrap` had -- but under the production security model it is the
application, not a deployer: it never writes its own key files.

| Provider | The service account needs |
|---|---|
| TPM | `/dev/tpmrm0` (the `tss` group), and read access to the derivation secret (its group) |
| PKCS#11 | Access to the token, and read access to the PIN file (its group) |
| External secret | Read access to its own file in the secret mount |

Plus read access to its wrapped key file. A systemd unit for a service using
the TPM, with the derivation secret group-owned by `hkdfguard`
([configuration.md](configuration.md#who-can-use-the-keys)):

```ini
[Service]
User=orders
Group=orders
SupplementaryGroups=tss hkdfguard
ExecStart=/usr/local/bin/orders-service

# Keep key material out of crash dumps, debuggers and other users' view.
LimitCORE=0
ProtectProc=invisible
NoNewPrivileges=yes
ProtectSystem=strict
ReadOnlyPaths=/etc/hkdfguard
# Don't set PrivateDevices=yes: it hides /dev/tpmrm0.
```

Also call `hkdfguard_harden_process()` early in your program; it covers what
the unit file can't, such as debugger attachment by other processes of the
same user.

**A one-shot wrap at deployment**, taking the DEK from a systemd credential so
it never touches the command line (`%d` is the unit's credentials directory).
It runs as root (no `User=`), the deployment admin; a dedicated deployer
account, a member of `hkdfguard-deployers`, would do as well. The service
gets read access through `-g`, and never runs `wrap` itself:

```ini
[Service]
Type=oneshot
LoadCredential=dek:/etc/orders/dek.b64
ExecStart=/usr/bin/hkdfguard wrap -kf /var/lib/orders/dek.wrapped \
    -sn com.company.orders --dek-file %d/dek -g orders --force
LimitMEMLOCK=infinity
```

Delete the plaintext source (`/etc/orders/dek.b64` here) once the wrapped
file exists.

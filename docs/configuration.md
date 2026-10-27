# Configuring HKDFGuard

HKDFGuard protects each service's Data Encryption Keys (DEKs) with a
persistent **Key Encryption Key (KEK)**. Configuration decides where that
KEK lives, and who and what may use it. Everything is set in one root-owned
file, `/etc/hkdfguard/policy.toml`, plus the secret files it names. Nothing
is read from environment variables.

- [How the provider is chosen](#how-the-provider-is-chosen)
- [The policy file](#the-policy-file)
- [Setting up each provider](#setting-up-each-provider): [TPM 2.0](#tpm-20), [PKCS#11](#pkcs11-hsm-or-smart-card), [external secret](#external-secret-file), [ephemeral](#ephemeral-development-only)
- [Example policies](#example-policies)
- [Security model: who may provision, wrap and unwrap](#security-model-who-may-provision-wrap-and-unwrap)
- [Who can use the keys](#who-can-use-the-keys)
- [Policy reference](#policy-reference)

## How the provider is chosen

There are four providers, from strongest to weakest:

| Provider | Policy name | Protection level | Where the KEK lives |
|---|---|---|---|
| TPM 2.0 | `tpm2` | `hardware` | Generated inside the TPM; stored as a key file only this TPM can load |
| PKCS#11 | `pkcs11` | `hardware` | Generated and kept on an HSM or token |
| External secret | `external-secret` | `external` | A root-owned file delivered by your platform (Kubernetes, Vault, systemd credentials, ...) |
| Ephemeral | `ephemeral` | `ephemeral` | Process memory only; **lost when the process exits** |

With **no policy file**, the library tries `tpm2`, then `pkcs11`, then
`external-secret`, and uses the first one that is set up on the host. It
never uses `ephemeral` unless a policy names it.

The library only moves on to the next provider when one is **absent**: not
on this host or not set up, or holding no key for the service. A provider
that is present but **failing** (wrong file permissions, a wrong PIN, a TPM
that fails its self-test) ends the call with an error instead. Falling
through would quietly protect new DEKs with a weaker key.

Each wrapped DEK records which provider wrapped it, and is always unwrapped
by that same provider.

## The policy file

`/etc/hkdfguard/policy.toml` is a [TOML](https://toml.io) file. Start from the
annotated example the packages install:

```sh
sudo install -m 0644 -o root -g root /usr/share/hkdfguard/policy.toml.example \
    /etc/hkdfguard/policy.toml
```

Copied unedited, it behaves exactly like having no policy: every setting is
commented out at its default. Uncomment and change only what you need.

**The file must be trustworthy, or every call fails.**

- It must be **owned by root** and **not writable by group or others**
  (mode `0644` is right; the services using the library must be able to
  read it).
- So must `/etc/hkdfguard` and every directory above it, up to `/`. Sticky
  directories such as `/tmp` are not exempt: nothing the library reads --
  the policy, secrets, the PIN file, the PKCS#11 module, key files -- may
  live anywhere under `/tmp`, `/var/tmp` or `/dev/shm`, however private
  the directory inside them. The one exception is a read-only mount, such
  as a Kubernetes Secret or ConfigMap volume (`1777`, but nobody can write
  to it).
- Only a *missing* file means "no policy". A file that exists but is wrongly
  owned, too broadly writable, unreadable or malformed makes every
  operation fail, rather than falling back to the defaults. Deleting or
  breaking the policy can never switch it off.

**Two TOML rules catch people out.**

- Top-level keys (`preferred_order`) must come **before** the first
  `[section]` header. Written below one, they belong to that section, and
  the file is rejected.
- Service names in `[tpm.pinned_names]` must be **quoted**:
  `"com.company.orders" = ...`. Unquoted dots would mean nested sections,
  which is also rejected.

Unknown keys are rejected too, so a misspelled setting fails loudly instead
of being ignored.

**Changes take effect immediately.** The library re-reads the policy on every
call, so there is nothing to restart.

## Setting up each provider

### TPM 2.0

Each service's KEK is a key the TPM generates and never exports. It is
stored as a **key file**, `/var/lib/hkdfguard/tpm/<service>.tpmkey`, whose
private half is encrypted by the TPM: the file is useless on any other
TPM. Each operation loads the key file into the TPM, uses it, and flushes
it, so nothing stays on the TPM.

**1. Give the service access to the TPM.** The library opens
`/dev/tpmrm0` (the kernel's resource manager). On most distributions it
belongs to the `tss` group:

```sh
ls -l /dev/tpmrm0                      # crw-rw---- tss tss ...
sudo usermod -aG tss <service-user>
```

**2. The key directory.** The key has no password: anyone who can read a
key file *and* open the TPM can use that KEK. So reading the key file is
the access control, and the key directory's group decides who may. The
packages create `/var/lib/hkdfguard/tpm` as `root:hkdfguard 0750`, so add
each service that uses TPM keys to `hkdfguard`. Without the packages,
create it as root:

```sh
sudo install -d -m 0750 -o root -g hkdfguard /var/lib/hkdfguard/tpm
```

On a `.deb` system, record a different owner or mode with
`dpkg-statoverride` or an upgrade puts `root:hkdfguard 0750` back.

`hkdfguard provision` then creates each key file there, owned by root,
with the directory's group, mode `0440`. The library refuses a key file,
or a directory above it, that anyone else could write to, so never put
the directory under `/tmp`. `tpm.key_dir` moves it.

#### Back up the key files

**A lost key file is a lost KEK:** every DEK wrapped under it becomes
unrecoverable. Copy each key file after `provision`, to wherever you keep
other root-of-trust material. A copy is useless on any other TPM, so
backups are low-risk; on this TPM, though, a copy can still be used, so
give backups the same access control as the directory.

A backup protects against losing the *file*, not the *TPM*. A motherboard
or TPM replacement, or a TPM clear (which a firmware reset can trigger),
changes the TPM's seed, and no key file made before it can be loaded
again. If DEKs must survive the hardware, keep a copy of each somewhere
other than this host, protected by a key not tied to it.

**3. Pin each service's key (recommended).** A key file is checked for
the attributes every key this library creates has, but a key file someone
with root put there is otherwise taken as is. With `require_pinned_names`,
only services listed in the policy have a key, and each one's key must
have the exact TPM Name recorded there:

```toml
[tpm]
require_pinned_names = true

[tpm.pinned_names]
"com.company.orders" = "000b<64 hex chars>"
```

You don't need to work out the Name yourself. With `require_pinned_names`
set, provisioning an unlisted service creates its key file, then fails and
prints the exact line to add:

```sh
sudo hkdfguard provision -sn com.company.orders
#   error: ... Its key file is created; to provision it, add this to the
#   policy file and run provision again:
#     [tpm.pinned_names]
#     "com.company.orders" = "000b..."
```

Add the line as printed, then run `provision` again; it reports "already
provisioned".

**4. Encrypt the TPM bus traffic where it matters.** On a *discrete* TPM
(a separate chip), the shared secret each unwrap computes crosses the
motherboard bus. `session_encryption` controls whether it is encrypted:

| Value | Behaviour | Use for |
|---|---|---|
| `"auto"` (default) | Encrypts unless the TPM reports a manufacturer known to have no external bus (Intel PTT, AMD fTPM, virtual TPMs) | Firmware and virtual TPMs |
| `"required"` | Always encrypts, and refuses to run without `pinned_session_salt_key_name` | Discrete TPMs, or a TPM you can't vouch for |
| `"off"` | Never encrypts | Not recommended |

`auto` relies on the manufacturer the TPM reports over that same bus, so
against an attacker who can rewrite bus traffic only `required` holds. The
Name it needs is that of the TPM's storage root key, which every key file
is loaded under and which salts the session. It is learned from the TPM,
and stays the same until the TPM is cleared. From a source checkout on the
host, as a user in the `tss` group:

```sh
cargo test --features tpm2 --lib print_session_salt_key_name_for_pinning \
    -- --ignored --exact --nocapture
#   SALT_KEY_NAME=000b...
```

`scripts/native-tpm-test.sh` runs this, and a full check of your TPM, for you.

**5. Protect the TPM hierarchy (recommended on shared hosts).** Anyone who
can open the TPM can, with the default empty passwords, *clear* it, which
makes every key file unloadable. Set a lockout password and disable
clearing:

```sh
LOCKOUT_PW="$(head -c 32 /dev/urandom | base64)"   # store it with the key files' backup
tpm2_changeauth -c lockout "$LOCKOUT_PW"
tpm2_clearcontrol -C l -P "$LOCKOUT_PW" s
```

Optionally, also set an **owner** password and name a file holding it in
`tpm.owner_auth_file`. Then the storage root key every key file is loaded
under can't be re-created without that password either. It changes no
existing key. But other
software on the host that uses the owner hierarchy with an empty password
(for example `systemd-cryptenroll --tpm2-device`) stops working until it is
given the password. See the README's "Protect the hierarchy the keys
live under" for the steps.

**Other TPM settings.**

- `tcti` chooses the TPM: `device:/dev/tpmrm0` (the default) or
  `tabrmd:...` for the `tpm2-abrmd` daemon. `mssim:` and `swtpm:` are for
  test simulators only.
- If tpm2-tss's own `TSS2_LOG` is set to `debug` or `trace`, the TPM
  provider refuses to run, because at those levels tpm2-tss logs secrets.

### PKCS#11 (HSM or smart card)

PKCS#11 is used only when the policy names a module. There is no automatic
search.

```toml
[pkcs11]
module = "/usr/lib/vendor/libvendor-pkcs11.so"   # your HSM vendor's PKCS#11 library
pin_file = "/etc/hkdfguard/pkcs11.pin"           # the default
token_label = "hkdfguard-prod"                   # and/or token_serial
```

- **The module**, its directory and every directory above it must be owned
  by root and not writable by group or others, sticky or not (so never under
  `/tmp`). Nothing on that path can then be swapped for another library.
- **The PIN file** holds the token's user PIN (one trailing newline is
  ignored). It must be root-owned, mode `0400`, or `0440` with the service's
  group, in directories only root can change, up to `/`. If the PIN file doesn't exist, PKCS#11 counts as absent and the
  next provider is tried. Once it exists, any problem fails the call
  instead.
- **Choose the token** by `token_label` and/or `token_serial`. Exactly one
  token must match. With neither set, exactly one initialized token must be
  present.
- **A rejected PIN stops further logins** from that process until the PIN
  file changes, so a wrong PIN can't run the token's retry counter down to a
  lockout.

`provision` generates the key pair on the token: non-extractable, usable only
for key derivation, and labelled with the service name. Both halves are
private objects (`CKA_PRIVATE`), and only private objects are ever looked up,
so nothing someone creates on the token without the PIN is ever used. A pair
provisioned before this rule existed has a public half that isn't private: it
is reported as a private key whose public key is missing; delete both halves
and run `provision` again (this changes that service's KEK).

**What the HSM must allow.** Each wrap and unwrap runs ECDH on the token
with `CKM_ECDH1_DERIVE` and no token-side KDF (`CKD_NULL`), into a
temporary session object that is *extractable* and *not sensitive*
(`CKA_EXTRACTABLE=true`, `CKA_SENSITIVE=false`). The library reads the
shared secret out of it, destroys it, and runs HKDF-SHA512 itself, since
that is the same key derivation every provider uses. The service's private
key never leaves the token, and each shared secret it exports covers only
one payload (see [Why ECDH](why-ecdh.md)). Some HSMs refuse this in their
FIPS-approved mode: they reject `CKD_NULL`, or any derived key that is
extractable or not sensitive. If yours does, `provision` succeeds (it only
generates the key pair) but the first wrap fails with
`HKDFGUARD_ERR_PROVIDER_ERROR` (-4), and the log names `CKM_ECDH1_DERIVE`.
Check the HSM's policy, and run the PKCS#11 test suite against it before
relying on it: so far it has only been run against SoftHSM2.

### External secret (file)

The KEK is a file your platform delivers: a Kubernetes Secret, a Vault Agent
sink, a Docker Swarm secret, a CSI Secrets Store volume, or a systemd
credential. The library never creates these keys; it only loads them.

**Where it looks.** With `[external_secret] dir` set, only that directory.
Otherwise the first of these that exists:

```
/var/run/secrets/hkdfguard
/run/secrets/hkdfguard
/vault/secrets/hkdfguard
/mnt/secrets-store/hkdfguard
```

Each service's KEK is the file `<dir>/<service-name>`, e.g.
`/run/secrets/hkdfguard/com.company.orders`.

**The key file** holds a P-256 private key. Use DER, generated with
OpenSSL:

```sh
# Generate the key (SEC1 DER), readable only by you:
( umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -outform DER -out com.company.orders )

# Its fingerprint, to pin in policy (see "Pin each key's fingerprint" below):
openssl pkey -inform DER -in com.company.orders -pubout -outform DER \
    | tail -c 65 | sha256sum | cut -d' ' -f1
```

Run both on the machine where you create the key, then load the file into
your secret store (Vault, AWS Secrets Manager, Google Secret Manager, Azure
Key Vault, a Kubernetes Secret) and record the fingerprint in the policy.
A DER file names its curve, so a key for the wrong curve is caught, and
OpenSSL can compute its fingerprint without any other tool.

PKCS#8 DER is accepted too, and so is a bare 32-byte private scalar, but
use DER: OpenSSL can't read a bare scalar, so there is no simple way to
fingerprint one before it is delivered. PEM (text starting `-----BEGIN`)
isn't accepted: convert it with
`openssl pkey -in key.pem -outform DER -out com.company.orders`. A key for
any curve other than P-256 is refused. `provision` reads and checks the
key, so a wrong format is reported when you provision, not later.

**File rules.** The file must:
- be owned by root or by the service's user, with no group or other access
  (`0400` or `0600`), except that a root-owned file may also be readable by
  its group (`root:<group> 0440`), so a non-root service can read it;
- be a regular file;
- resolve to a path inside the mount (symlinks are followed only while they
  stay inside it).

The mount and every directory above it must be owned by root or the
service's user and not writable by anyone else -- sticky directories such as
`/tmp` included, so a mount anywhere under `/tmp`, `/var/tmp` or `/dev/shm`
is refused. A read-only mount is the one exception: a Kubernetes Secret
volume is `1777`, but read-only, and is fine. Platform settings that meet
the mode rule:

| Mechanism | Setting |
|---|---|
| Kubernetes `Secret` volume | `defaultMode: 0400`; for a non-root pod, set `fsGroup` (the kubelet then makes it `root:<fsGroup> 0440`) |
| Vault Agent template or sink | `perms = "0400"` |
| Docker Swarm secret | `mode: 0400` (the default `0444` is refused) |
| CSI Secrets Store | `defaultMode` in the `SecretProviderClass` |
| systemd `LoadCredential=` | Already `0400` and root-owned |

A file that is present but breaks a rule is an **error**, never "not
provisioned".

**Pin each key's fingerprint.** The file rules limit who could have
written the key: root, the service's user, or anything else that mounts
the same volume read-write, such as a secrets sidecar or a shared
`emptyDir`. They can't tell whether the key is the one you generated. Any
of those writers can put a valid key of its own in the mount before the
real one arrives, and the library would use it. Pinning closes that gap:

```toml
[external_secret]
dir = "/vault/secrets/hkdfguard"
require_pinned_keys = true           # a service with no pin has no KEK here

[external_secret.pinned_keys]
"com.company.orders"   = "<64 hex chars>"
"com.company.payments" = ["<old 64 hex>", "<new 64 hex>"]   # a list while rotating
```

A key whose fingerprint isn't pinned for its service is refused, as an
error, so the library never moves on to another provider. Without
`require_pinned_keys`, services you haven't pinned work as before. Service
names must be quoted, as in `[tpm.pinned_names]`.

The fingerprint is the SHA-256 of the key's uncompressed public point. It's
the same value `provision` prints, every wrapped payload carries, and
`retire --fingerprint` takes. It isn't secret, so it can live in the policy
file wherever that's kept. Compute it where you generate the key, before
the key goes into your secret store:

```sh
openssl pkey -inform DER -in com.company.orders -pubout -outform DER \
    | tail -c 65 | sha256sum | cut -d' ' -f1
```

`-pubout` writes the public key as a SubjectPublicKeyInfo structure, which
ends with the 65-byte uncompressed point `04 || X || Y`; `tail -c 65` keeps
just that point, and its SHA-256 is the fingerprint. The output is 64 hex
characters, ready to paste into `pinned_keys`.

With `require_pinned_keys` on, `provision` also refuses an unpinned service
and prints the policy line for the key that is mounted. That tells you
which key is in the mount now, not which key you generated, so use it to
confirm the fingerprint you computed above, never in place of it.

To rotate: add the new fingerprint to the service's list, deliver the new
key, then remove the old fingerprint. DEKs wrapped under the old key need
re-wrapping before the old key is gone, as with any KEK change.

### Ephemeral (development only)

Keys live in process memory and vanish when the process exits, along with
the ability to unwrap anything wrapped under them. Ephemeral is never used
unless a policy names it, in `preferred_order` or as the `require`
provider. Use it only for development and tests.

Because the process's memory is the key's only protection, the library
hardens the process before it creates the first ephemeral key: core dumps
are disabled and the process is marked non-dumpable, as
`hkdfguard_harden_process` does, and creating the key fails if that isn't
possible. Debuggers and crash reporters stop working for that process. The
keys themselves sit in pages excluded from core dumps and locked into RAM
where `RLIMIT_MEMLOCK` allows (a warning is logged once if it doesn't).

The `hkdfguard` CLI refuses ephemeral keys for `provision` and `wrap`: a
key it created would be gone when it exits. Wrap DEKs from the application
itself, for example with `hkdfguard_generate_and_wrap_dek`.

## Example policies

Each example is a complete `policy.toml`. Replace the placeholder Names
(`000b<64 hex chars>`) with the values your TPM gives you (see
[step 3](#tpm-20)).

**Strongest: TPM only, everything pinned.** For a host with a TPM, where no
weaker fallback is acceptable:

```toml
[selection]
mode = "require"                     # the TPM and nothing else
provider = "tpm2"

[key_requirements]
minimum_protection = "hardware"

[tpm]
tcti = "device:/dev/tpmrm0"
key_dir = "/var/lib/hkdfguard/tpm"
require_pinned_names = true          # only the services below have a key
session_encryption = "required"
pinned_session_salt_key_name = "000b<64 hex chars>"

[tpm.pinned_names]
"com.company.orders" = "000b<64 hex chars>"
```

**Any hardware, TPM preferred.** For a fleet where some hosts have a TPM and
others an HSM:

```toml
[selection]
mode = "require-level"
level = "hardware"                   # tpm2 or pkcs11, in the default order

[pkcs11]
module = "/usr/lib/vendor/libvendor-pkcs11.so"
token_label = "hkdfguard-prod"
```

**Containers: external secrets only.** For pods or containers that receive
their KEK as a mounted secret:

```toml
[selection]
mode = "require"
provider = "external-secret"

[external_secret]
dir = "/run/secrets/hkdfguard"
require_pinned_keys = true

[external_secret.pinned_keys]
"com.company.orders" = "<64 hex chars>"
```

**Development: SoftHSM2, else ephemeral.** The policy in the `-dev` container
overlay image. Never use it in production:

```toml
preferred_order = ["pkcs11", "ephemeral"]

[selection]
mode = "prefer"

[pkcs11]
module = "/usr/lib/softhsm/libsofthsm2.so"
pin_file = "/etc/hkdfguard/pkcs11.pin"
token_label = "hkdfguard"
```

## Security model: who may provision, wrap and unwrap

The top-level policy setting `security_model` splits the duties, as the
Windows build's `SecurityModel` policy value and the macOS build's
production mode do:

```toml
security_model = "production"            # the default; or "developer"
deployer_groups = ["payments-deployers"] # optional; besides hkdfguard-deployers
```

Both keys go above the first `[table]`. Production applies when they are
absent, and when there is no policy file at all: a host is a production
install unless an administrator says otherwise. Any other value of
`security_model` (`"development"` included) makes the policy invalid, and
every call fails with `HKDFGUARD_ERR_POLICY_INVALID` (-9).

Under **production**:

| Role | Who | May |
|---|---|---|
| Security admin | root | `hkdfguard provision`, `hkdfguard retire` |
| Deployment admin | root, or a *deployer* | `hkdfguard wrap`: write key files `hkdfguard_open_file` will trust |
| Application | any other account the provider lets use the KEK | unwrap (and wrap in memory); it cannot persist a key file its own service would accept |

- **Creating a KEK takes root.** `hkdfguard_create_kek` from anyone else
  returns the existing KEK -- so an application may still call it at
  startup -- or `HKDFGUARD_ERR_KEK_ACCESS_DENIED` (-18) when there is none
  to return. An ephemeral KEK is the exception: it lives only in the
  process that makes it. Retiring a KEK takes root too. On TPM2 and
  PKCS#11 this is enforced directly (only root creates a key file, or
  generates a key pair on the token); external-secret never creates a KEK
  (the delivered file is the provisioning). With
  `tpm.require_pinned_names = true`, a TPM service also needs its key's
  Name in the root-owned policy: `provision` prints it.
- **A deployer** is a direct member of the group `hkdfguard-deployers`
  (the packages create it) or of a group listed in `deployer_groups`:
  named in the group's member list, or having it as their primary group.
  `deployer_groups` takes names, not gids (an all-digit entry is rejected),
  each once. A group that doesn't exist, can't be looked up, or is
  over-broad -- `root`, `users`, `nogroup`, `nobody`, `wheel`, `sudo`,
  `adm`, `staff`, or gid 0 or 65534 -- fails every key-file read with
  `HKDFGUARD_ERR_LINUX_GROUP_INVALID` (-80), which refines -9.
- **Whose key files are trusted.** `hkdfguard_open_file` accepts a key
  file only if it, and every directory deciding what its path names, is
  owned by root or a deployer, and writable by nobody else: never by
  others, and by its group only if that group is a deployer group.
  Otherwise `HKDFGUARD_ERR_FILE_UNTRUSTED` (-39). The calling account is
  trusted only if it is a deployer, so a key file the application wrote --
  or copied into a folder of its own -- is refused.

Under **developer**, anyone who can reach the provider may create a KEK,
and key files owned by root or by the calling user are trusted, with no
group write allowed: the rule before security models existed. The first
key file read under it in each process is audited as event 1005
(Warning), as a reminder that the host is not running production.

Wrapping and unwrapping are the same in both models. Who may use a KEK at
all is still the provider's own access control (TPM access and the key
file's mode, the PIN file, the secret file's mode): wrap and unwrap
are the same ECDH operation on the KEK, so nothing can grant one without
the other. What the model decides is whose key files are believed.

A deployment, as root:

```sh
# Deployers: the accounts (or CI runner) that run `hkdfguard wrap`.
sudo usermod -aG hkdfguard-deployers alice

# A folder the deployers share; setgid, so new files keep the group.
sudo install -d -o root -g hkdfguard-deployers -m 2775 /etc/orders/keys

# Security admin: provision the KEK, once. Record the fingerprint.
sudo hkdfguard provision -sn com.company.orders

# Deployment admin (alice, or root): wrap, readable by the service's group.
printf '%s' "$DEK_B64" | hkdfguard wrap -kf /etc/orders/keys/orders.key \
    -sn com.company.orders --dek-stdin -g orders -fp <fingerprint>

# The service (user orders, not a deployer) only opens and unwraps it.
```

Things to know:

- **Upgrading changes the default.** On a host with no `security_model`,
  key files owned by the application's own account -- `hkdfguard wrap` run
  as the service user, say -- become `FILE_UNTRUSTED` (-39). Redeploy them
  as root or a deployer, or set `security_model = "developer"` until you
  have.
- **Membership is looked up on every `hkdfguard_open_file` call**, through
  NSS, so LDAP and sssd groups count, and a slow directory slows the call.
  Removing a deployer makes every key file they own untrusted at once:
  redeploy those files first.
- Tools can ask the library the same questions: `hkdfguard_security_model`
  (the model, and whether a key file this process writes would be trusted)
  and `hkdfguard_key_file_principal_trusted("uid:<n>"` or `"gid:<n>")`.
- `scripts/verify-roles.sh` checks the whole split end to end, as root,
  against a release build.

## Who can use the keys

On Linux, anything that can reach a service's provider **and** read its
wrapped key file can recover that DEK. For the TPM, reaching the provider
means TPM access plus read access to the service's TPM key file. Arrange
permissions so that only the service's own account can do both.

| File | Owner and mode | Why |
|---|---|---|
| `/etc/hkdfguard/` | `root:root 0755` | Only root may change what's inside |
| `/etc/hkdfguard/policy.toml` | `root:root 0644` | Readable by services; changeable only by root |
| `/var/lib/hkdfguard/tpm/` | `root:<key-users> 0750` | Only root may add or replace a key; its group is the group of each key file in it |
| `/var/lib/hkdfguard/tpm/<service>.tpmkey` | `root:<key-users> 0440` (`provision` sets it) | Readable by the services allowed to use TPM keys |
| `/etc/hkdfguard/tpm.owner-auth` (if used) | `root:<key-users> 0440` | As above |
| `/etc/hkdfguard/pkcs11.pin` | `root:<key-users> 0440` | As above |
| External secret `<dir>/<service>` | root or the service's user, `0400`; or `root:<group> 0440` | Only that service (or the pod's `fsGroup`) |
| Wrapped key files (CLI output) | root or a deployer, `:<service-group> 0640` | Only that service can read its wrapped DEK; under the production model, only root's and deployers' are trusted |
| Folder holding key files | root or a deployer; `root:hkdfguard-deployers 2775` to share it | Nobody untrusted can replace a key file |

The packages create two groups, from `packaging/hkdfguard.sysusers`
(`/usr/lib/sysusers.d/hkdfguard.conf`), and never remove them, on
uninstall or purge, since a group created again could get another gid:
`hkdfguard`, for the accounts that may use the keys (nothing in the library
names it), and `hkdfguard-deployers` (see
[Security model](#security-model-who-may-provision-wrap-and-unwrap)).

A practical layout for several services on one host:

```sh
# hkdfguard and /var/lib/hkdfguard/tpm exist if the packages are installed; otherwise:
sudo groupadd --system hkdfguard        # may use the keys at all
sudo install -d -m 0750 -o root -g hkdfguard /var/lib/hkdfguard/tpm
# Each service runs as its own user, in the tss and hkdfguard groups,
# and its wrapped key files are group-owned by that service's own group.
```

As provisioned, every member of `hkdfguard` can use every service's TPM
key: each key file takes the directory's group. To give each service its
own, change a key file's group to that service's own group after
`provision` (`sudo chgrp orders /var/lib/hkdfguard/tpm/com.company.orders.tpmkey`);
the services still need the directory's group to reach it. Without that,
what stops one service from recovering
another's DEK is that it can't read the other's wrapped key files. Wrapped
files are meant to be storable openly (in backups, for example), so treat
this as defence in depth, not a hard boundary.

The same holds for any file above that a group can read: every member of
that group holds the key it protects, not just read access to a file. An
external secret *is* the KEK's private key, so whoever can read it can
unwrap the service's payloads and wrap new ones, from any host and
indefinitely. A `root:<group> 0440` external secret makes every account in
that group (or every container in the pod's `fsGroup`) a holder of that
service's KEK. Give each service its own group, or deliver the secret
uid-scoped (`0400`, for example through systemd `LoadCredential=`).

## Policy reference

Every setting, with its default. Only `[selection]` is required.

```toml
security_model = "production"   # production | developer. Must come before any [section].
deployer_groups = []            # production only: groups whose direct members deploy key files,
                                # besides hkdfguard-deployers. Names, not gids.
preferred_order = ["tpm2", "pkcs11", "external-secret"]
                         # with mode = "prefer": the order to try; providers left out are never used.
                         # The only way to allow "ephemeral" (besides `require`). Must come before any [section].

[selection]
mode = "prefer"          # prefer | require | require-level
provider = "tpm2"        # with "require": tpm2 | pkcs11 | external-secret | ephemeral
level = "hardware"       # with "require-level": ephemeral | software | external | hardware

[key_requirements]
minimum_protection = "external"   # exclude providers below this level, whatever the mode (default: no minimum)

[startup_behavior]
setup_min_delay_ms = 1000         # minimum duration of create_kek / kek_exists calls; 0 disables, max 60000

[audit]
unwrap_success = true             # false: no audit record for a successful unwrap (README "Audit trail")

[tpm]
tcti = "device:/dev/tpmrm0"
key_dir = "/var/lib/hkdfguard/tpm"                    # one <service>.tpmkey per service
owner_auth_file = "/etc/hkdfguard/tpm.owner-auth"     # default: unset (empty owner password)
require_pinned_names = false
session_encryption = "auto"                           # auto | required | off
pinned_session_salt_key_name = "000b<64 hex chars>"   # default: unset; required by "required"

[tpm.pinned_names]
"com.company.orders" = "000b<64 hex chars>"

[external_secret]
dir = "/run/secrets/hkdfguard"    # default: the first existing conventional mount
require_pinned_keys = false       # true: only services in pinned_keys have a KEK here

[external_secret.pinned_keys]
"com.company.orders" = "<64 hex chars>"           # or a list of them, while rotating

[pkcs11]
module = "/usr/lib/vendor/libvendor-pkcs11.so"   # default: unset (PKCS#11 not used)
pin_file = "/etc/hkdfguard/pkcs11.pin"
token_label = "hkdfguard-prod"                   # 1 to 32 bytes
token_serial = "0123456789abcdef"                # 1 to 16 bytes
```

Notes:

- Set `provider` only with `mode = "require"`, and `level` only with
  `mode = "require-level"`. Any other combination is rejected.
- All paths must be absolute.
- Settings are checked whenever the policy is read, whichever provider ends
  up being used. For example, `session_encryption = "required"` without
  `pinned_session_salt_key_name` makes every call fail, even on a host
  that never uses its TPM.

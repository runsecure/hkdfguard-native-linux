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
- [Who can use the keys](#who-can-use-the-keys)
- [Policy reference](#policy-reference)

## How the provider is chosen

There are four providers, from strongest to weakest:

| Provider | Policy name | Protection level | Where the KEK lives |
|---|---|---|---|
| TPM 2.0 | `tpm2` | `hardware` | Derived inside the TPM on demand; the private key never leaves it |
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
- So must `/etc/hkdfguard` and every directory above it.
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

The TPM provider derives each service's KEK inside the TPM from the TPM's
own seed. The private key never leaves the chip, and nothing is stored on it.

**1. Give the service access to the TPM.** The library opens
`/dev/tpmrm0` (the kernel's resource manager). On most distributions it
belongs to the `tss` group:

```sh
ls -l /dev/tpmrm0                      # crw-rw---- tss tss ...
sudo usermod -aG tss <service-user>    # or SupplementaryGroups=tss in a systemd unit
```

**2. Create the derivation secret.** Without it, any process that can open
the TPM could derive the same keys, so the TPM provider **requires** it by
default. Create it as root, before wrapping anything:

```sh
sudo sh -c '( umask 077; head -c 32 /dev/urandom > /etc/hkdfguard/tpm.derivation-secret )'
# For a service that doesn't run as root, let its group read it:
sudo chgrp <service-group> /etc/hkdfguard/tpm.derivation-secret
sudo chmod 0440 /etc/hkdfguard/tpm.derivation-secret
```

It must be root-owned and readable by root and, optionally, one group;
never writable by the service. Its bytes are used exactly as stored.

#### Back up the derivation secret

The derivation secret is part of every TPM KEK on the host. **If it is lost
or changed, every DEK wrapped on this host becomes unrecoverable.** Copy it
when you create it, to wherever you keep other root-of-trust material
(offline, or a secrets manager with tighter access than the host).

A backup protects against losing the *file*, not the *TPM*. A motherboard
or TPM replacement, or a TPM clear (which a firmware reset can trigger),
changes the TPM's seed, and every key derived from it is gone. If DEKs must
survive the hardware, keep a copy of each somewhere other than this host,
protected by a key not tied to it.

**3. Make provisioning explicit with pinned names (recommended).** A TPM
derives a key for *any* service name on demand, so by default a typo in a
service name silently gets its own key. With `require_pinned_names`, only
services listed in the policy have a key, and each one's key must have the
exact TPM Name recorded there:

```toml
[tpm]
require_pinned_names = true

[tpm.pinned_names]
"com.company.orders" = "000b<64 hex chars>"
```

You don't need to work out the Name yourself. With `require_pinned_names`
set, provisioning an unlisted service fails and prints the exact line to
add:

```sh
sudo hkdfguard provision -sn com.company.orders
#   error: ... add this to the policy file and run provision again:
#     [tpm.pinned_names]
#     "com.company.orders" = "000b..."
```

Add the line as printed, then run `provision`
again; it reports "already provisioned". **Create the derivation secret
before pinning:** the Name depends on it.

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
salt-key Name it needs is learned from the TPM. It doesn't depend on the
derivation secret, so it can be learned at any time. From a source checkout
on the host, as a user in the `tss` group:

```sh
cargo test --features tpm2 --lib print_session_salt_key_name_for_pinning \
    -- --ignored --exact --nocapture
#   SALT_KEY_NAME=000b...
```

`scripts/native-tpm-test.sh` runs this, and a full check of your TPM, for you.

**5. Protect the TPM hierarchy (recommended on shared hosts).** Anyone who
can open the TPM can, with the default empty passwords, *clear* it, which
destroys every key derived from it. Set a lockout password and disable
clearing:

```sh
LOCKOUT_PW="$(head -c 32 /dev/urandom | base64)"   # store it with the derivation secret's backup
tpm2_changeauth -c lockout "$LOCKOUT_PW"
tpm2_clearcontrol -C l -P "$LOCKOUT_PW" s
```

Optionally, also set an **owner** password and name a file holding it in
`tpm.owner_auth_file`. Then deriving any key under the TPM's owner
hierarchy needs that password too. It changes no existing key. But other
software on the host that uses the owner hierarchy with an empty password
(for example `systemd-cryptenroll --tpm2-device`) stops working until it is
given the password. See the README's "Protect the hierarchy the keys
derive from" for the steps.

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
  by root and not writable by group or others. Nothing on that path can then
  be swapped for another library.
- **The PIN file** holds the token's user PIN (one trailing newline is
  ignored). It must be root-owned, mode `0400`, or `0440` with the service's
  group. If the PIN file doesn't exist, PKCS#11 counts as absent and the
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

**The key file** holds a P-256 private key, as 32 raw bytes, or in DER
form (PKCS#8 or SEC1):

```sh
# A raw 32-byte private scalar:
( umask 077; head -c 32 /dev/urandom > com.company.orders )

# Or DER, straight from OpenSSL (this writes SEC1; PKCS#8 works too):
( umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -outform DER -out com.company.orders )
```

PEM (text starting `-----BEGIN`) isn't accepted: convert it to DER first,
with `openssl pkey -in key.pem -outform DER -out key.der`. A key for any
curve other than P-256 is refused. `provision` reads and checks the key, so
a wrong format is reported when you provision, not later.

**File rules.** The file must:
- be owned by root or by the service's user, with no group or other access
  (`0400` or `0600`), except that a root-owned file may also be readable by
  its group (`root:<group> 0440`), so a non-root service can read it;
- be a regular file;
- resolve to a path inside the mount (symlinks are followed only while they
  stay inside it).

The mount and every directory above it must not be writable by anyone else;
sticky directories such as `/tmp`, and read-only mounts, are fine. Platform
settings that meet the mode rule:

| Mechanism | Setting |
|---|---|
| Kubernetes `Secret` volume | `defaultMode: 0400`; for a non-root pod, set `fsGroup` (the kubelet then makes it `root:<fsGroup> 0440`) |
| Vault Agent template or sink | `perms = "0400"` |
| Docker Swarm secret | `mode: 0400` (the default `0444` is refused) |
| CSI Secrets Store | `defaultMode` in the `SecretProviderClass` |
| systemd `LoadCredential=` | Already `0400` and root-owned |

A file that is present but breaks a rule is an **error**, never "not
provisioned".

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
require_derivation_secret = true
derivation_secret_file = "/etc/hkdfguard/tpm.derivation-secret"
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

## Who can use the keys

On Linux, anything that can reach a service's provider **and** read its
wrapped key file can recover that DEK. For the TPM, reaching the provider
means TPM access plus read access to the derivation secret. Arrange
permissions so that only the service's own account can do both.

| File | Owner and mode | Why |
|---|---|---|
| `/etc/hkdfguard/` | `root:root 0755` | Only root may change what's inside |
| `/etc/hkdfguard/policy.toml` | `root:root 0644` | Readable by services; changeable only by root |
| `/etc/hkdfguard/tpm.derivation-secret` | `root:<key-users> 0440` | Readable by the services allowed to use TPM keys |
| `/etc/hkdfguard/tpm.owner-auth` (if used) | `root:<key-users> 0440` | As above |
| `/etc/hkdfguard/pkcs11.pin` | `root:<key-users> 0440` | As above |
| External secret `<dir>/<service>` | root or the service's user, `0400`; or `root:<group> 0440` | Only that service (or the pod's `fsGroup`) |
| Wrapped key files (CLI output) | `root:<service-group> 0640` | Only that service can read its wrapped DEK |

A practical layout for several services on one host:

```sh
sudo groupadd --system hkdfguard        # may use the keys at all
sudo chgrp hkdfguard /etc/hkdfguard/tpm.derivation-secret
sudo chmod 0440 /etc/hkdfguard/tpm.derivation-secret
# Each service runs as its own user, with SupplementaryGroups=tss hkdfguard,
# and its wrapped key files are group-owned by that service's own group.
```

Every member of `hkdfguard` can derive every service's TPM key: there is one
derivation secret per host. What stops one service from recovering
another's DEK is that it can't read the other's wrapped key files. Wrapped
files are meant to be storable openly (in backups, for example), so treat
this as defence in depth, not a hard boundary.

## Policy reference

Every setting, with its default. Only `[selection]` is required.

```toml
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
require_derivation_secret = true
derivation_secret_file = "/etc/hkdfguard/tpm.derivation-secret"
owner_auth_file = "/etc/hkdfguard/tpm.owner-auth"     # default: unset (empty owner password)
require_pinned_names = false
session_encryption = "auto"                           # auto | required | off
pinned_session_salt_key_name = "000b<64 hex chars>"   # default: unset; required by "required"

[tpm.pinned_names]
"com.company.orders" = "000b<64 hex chars>"

[external_secret]
dir = "/run/secrets/hkdfguard"    # default: the first existing conventional mount

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

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

So does a provider that has gone missing while still holding the service's
key: a TPM key file on a host whose TPM device has disappeared, or a
service with a key pinned in `external_secret.pinned_keys` and no secret
mounted. When a later provider does serve a service, audit event 1006
records it, once per process for each service.

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
  the directory inside them. The one exception is a sticky directory on a
  read-only mount, such as a Kubernetes Secret or projected volume (`1777`:
  nothing in the container can write to it, and the sticky bit stops
  whatever writes it elsewhere from renaming or deleting entries it doesn't
  own). A plain ConfigMap or disk-backed `emptyDir` volume is `0777`, not
  sticky, and is refused even read-only. Ship the policy from a ConfigMap
  through a `projected:` volume:

  ```yaml
  volumes:
    - name: hkdfguard-policy
      projected:
        sources:
          - configMap: { name: hkdfguard-policy }
  ```
- POSIX ACLs count. A named ACL entry that gives someone write access is
  refused like the mode's write bits, and, on a secret, one that gives
  anyone but root read access. With an ACL, `ls -l` shows its mask in the
  group bits, not who it names: check with `getfacl`.
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

Each service's KEK is a 256-bit HMAC-SHA-256 key the TPM generates and
never exports. It is stored as a **key file**, `/var/lib/hkdfguard/tpm/<service>.tpmkey`, whose
private half is encrypted by the TPM: the file is useless on any other
TPM. The key has a random 32-byte password, its **authValue**, kept beside
it in `<service>.tpmauth`. Each operation loads the key file into the TPM,
uses it, and flushes it, so nothing stays on the TPM.

**1. Give the service access to the TPM.** The library opens
`/dev/tpmrm0` (the kernel's resource manager). On most distributions it
belongs to the `tss` group:

```sh
ls -l /dev/tpmrm0                      # crw-rw---- tss tss ...
sudo usermod -aG tss <service-user>
```

**2. The key directory.** Anyone who can read a key file *and* its
authValue file, and open the TPM, can use that KEK. So reading the two
files is the access control, and the key directory's group decides who
may. The packages create `/var/lib/hkdfguard/tpm` as `root:hkdfguard 0750`,
so add each service that uses TPM keys to `hkdfguard`. Without the
packages, create it as root:

```sh
sudo install -d -m 0750 -o root -g hkdfguard /var/lib/hkdfguard/tpm
```

The packages set `root:hkdfguard 0750` only when they create the
directory. An owner or mode you give it afterwards survives upgrades and
reinstalls, `.deb` and `.rpm` alike.

**3. Each service's own group.** The authValue file is what lets an
account use one service's key, so it is never given the directory's group,
which every TPM-using service is in. Name the group of each service that
doesn't run as root:

```toml
[tpm.auth_groups]
"com.company.orders" = "orders"
```

`hkdfguard provision` then creates both files there, owned by root: the key
file with the directory's group, mode `0440`, and the authValue file with
the service's group from `tpm.auth_groups`, mode `0440` -- or, with no
entry, `root:root 0400`, which only a service running as root can use. A
group that covers essentially every account (`users`, `nogroup`, `root`,
`wheel` and the like) is refused. To change a provisioned service's group,
`chgrp` its `.tpmauth` file; the library accepts any group on a root-owned
`0440` file. The library refuses either file, or a directory above it,
that anyone else could write to, so never put the directory under `/tmp`.
`tpm.key_dir` moves it.

Provisioning always creates a new authValue. An authValue file left with
no key file beside it (a retire that couldn't delete it, a key file
deleted by hand) is replaced, never reused.

#### Back up the key files

**A lost key file or authValue file is a lost KEK:** every DEK wrapped
under it becomes unrecoverable. Copy both files after `provision`, to
wherever you keep other root-of-trust material. A copy of the key file is
useless on any other TPM, but the authValue file is a secret; on this TPM
the pair can still be used, so give backups the same access control as
the directory.

A backup protects against losing the *file*, not the *TPM*. A motherboard
or TPM replacement, or a TPM clear (which a firmware reset can trigger),
changes the TPM's seed, and no key file made before it can be loaded
again. If DEKs must survive the hardware, keep a copy of each somewhere
other than this host, protected by a key not tied to it.

**4. Pin each service's key (recommended).** A key file is checked for
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

**5. The TPM bus traffic is encrypted; pin the storage root key for
provisioning.** On a *discrete* TPM (a separate chip), the wrapping key
each wrap and unwrap computes (the output of `TPM2_HMAC`) crosses the
motherboard bus. It is always encrypted, and its response authenticated,
under keys derived from the service key's authValue. Nobody without the
authValue file can read a wrapping key off the bus or replace one. That
needs no trusted public key, and a quantum computer doesn't help against
it. `session_encryption = "off"` turns the encryption off, for test
harnesses only.

The one moment the authValue itself crosses the bus is `provision`, inside
a session salted to the TPM's storage root key. Pinning that key's Name
with `pinned_session_salt_key_name` stops an attacker who can rewrite bus
traffic at provisioning time from substituting their own, so `provision`
refuses to create a TPM key until the Name is pinned. The refusal prints
the Name this TPM reports, as the line to add to the policy:

```sh
sudo hkdfguard provision -sn com.company.orders
#   ... refusing to provision a TPM key: policy pins no storage root key ...
#     pinned_session_salt_key_name = "000b..."
```

Add that line to the `[tpm]` table and run `provision` again. The Name
stays the same until the TPM is cleared, so it is the same for every
service on the host; if it was recorded when the host was set up, check
the printed value against that record. Nothing is created by the refused
run.

On a TPM with no bus to tamper with (a firmware or virtual TPM),
`allow_unpinned_provisioning = true` in the `[tpm]` table provisions
without a pin instead. Each key provisioned that way is recorded as audit
event 1007. Using a key that already exists never needs the pin.

From a source checkout, `scripts/native-tpm-test.sh` also reports the
Name, with a full check of your TPM.

**6. Protect the TPM hierarchy (recommended on shared hosts).** Anyone who
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
given the password. Every service using TPM keys must be able to read the
file, so each of them holds the Owner hierarchy's password, not only its
own key. See the README's "Protect the hierarchy the keys live under" for
the steps.

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
  `/tmp`), and no POSIX ACL entry may give anyone else write access. Nothing
  on that path can then be swapped for another library. A sticky directory
  on a read-only mount passes whatever its write bits, so if the module is
  bind-mounted read-only from somewhere writable, make sure the original
  directories are root-owned and unwritable as well: the module is code
  this process runs.
- **The module's own configuration** is not checked. Most modules find
  their token through an environment variable (`SOFTHSM2_CONF`,
  `YUBIHSM_PKCS11_CONF`, `ChrystokiConfigurationPath`, `OPENSC_CONF`,
  `CKNFAST_*`). For a network HSM that names the host the PIN is sent to:
  whoever controls the service's environment (a unit's `Environment=` or
  `EnvironmentFile=`, a pod spec) can point the module at a token they run
  and receive the root-only PIN. Fix the module's configuration in a
  root-owned file, and don't let lower-trust configuration set those
  variables for the service.
- **The PIN file** holds the token's user PIN (one trailing newline is
  ignored). It must be root-owned, mode `0400`, or `0440` with the service's
  group, in directories only root can change, up to `/`. Setting
  `module` is what turns PKCS#11 on, so with it set, a missing PIN file
  fails the call like any other problem: it is never a reason to try the
  next provider. The one exception is the developer security model, where
  a missing PIN file skips PKCS#11 with a warning (the dev overlay image's
  "SoftHSM2, else ephemeral").
- **Choose the token** by `token_label` and/or `token_serial`. Exactly one
  token must match. With neither set, exactly one initialized token must be
  present.
- **A rejected PIN stops further logins** from that process until the PIN
  file changes, so a wrong PIN can't run the token's retry counter down to a
  lockout.

`provision` generates one secret key on the token (`CKO_SECRET_KEY`,
`CKK_GENERIC_SECRET`, 32 bytes, with `CKM_GENERIC_SECRET_KEY_GEN`),
labelled `hkdfguard:<service>`, with `CKA_ID` set to the SHA-256 of the
service name. It is a token object, private (`CKA_PRIVATE`), sensitive and
non-extractable, usable only to sign (`CKA_SIGN`; no verify, derive,
encrypt, decrypt, wrap or unwrap), and neither modifiable nor copyable, so
none of that can be relaxed later. Only private objects are ever looked up,
so nothing someone creates on the token without the PIN is ever used. A key
found under a service's label is used only if it still has all of these
protections, and also `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE` and
`CKA_LOCAL`, which a token sets only on a key it generated itself: an
imported key, whose value someone may know, or one derived from another
key, is refused. Only secret keys are looked up, so an
EC key pair left under the same label by the pre-release ECDH format is
ignored, not used or refused; delete it from the token by hand.

#### What the PIN decides

A PKCS#11 token has one authority over these keys: its user PIN. Every
service that uses the token must be able to read the PIN file, so every
one of them can do, with `pkcs11-tool` or a few lines of code, whatever
the PIN allows -- whatever this library would have refused:

- delete a service's key, which makes every DEK wrapped under it
  unrecoverable;
- delete it and generate another under the same label. The new key
  passes every check above, being as token-generated as the first;
- use any other service's key on the same token. Services sharing a token
  are kept apart by labels only.

Nobody can learn a key's value this way: the keys never leave the token.

What to do about it:

- **Give each service its own token or HSM partition**, with its own PIN
  file, wherever one service must not be able to affect another's key.
- **Pin each service's key.** `provision` prints the key's fingerprint;
  record it in the policy, which only root writes:

  ```toml
  [pkcs11.pinned_keys]
  "com.company.orders" = "<64 hex chars>"    # or a list of them
  ```

  A key with any other fingerprint is then refused, so a replaced key
  can't be used. A pinned service whose key is gone fails every call,
  instead of being treated as having no key -- which would let the next
  provider in the policy order serve it. To provision a pinned service
  again (after `retire`, say), remove its pin first, then pin the new
  fingerprint.
- **`require_pinned_keys = true`** in `[pkcs11]` makes the pins an
  allowlist: a service with no pin has no KEK on the token. `provision`
  then generates the key and fails with the line to add to the policy;
  run it again once the pin is in place.

Pinning detects a deleted or replaced key; it cannot prevent one. Where
the HSM can make a key undeletable for the user role, do that as well.

**What the HSM must allow.** Each wrap and unwrap is a single-part
`C_Sign` with `CKM_SHA256_HMAC` on that key, which returns only the HMAC:
the key never leaves the token, and each wrapping key it returns covers
only one payload (see [Why an HMAC PRF](why-hmac-prf.md)). Any PKCS#11
v2.20 or later token supports `CKM_GENERIC_SECRET_KEY_GEN` and
`CKM_SHA256_HMAC`; SoftHSM2 needs HMAC keys of at least 32 bytes, which
these are. No token-side KDF and no extractable session object are needed.
Still, run the PKCS#11 test suite against your HSM before relying on it:
so far it has only been run against SoftHSM2.

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

**The key file** holds exactly 32 random bytes, used directly as the
service's HMAC-SHA-256 key. Generate it with either:

```sh
# Generate the key, readable only by you:
( umask 077; head -c 32 /dev/urandom > com.company.orders )
# or
( umask 077; openssl rand -out com.company.orders 32 )

# Its fingerprint, to pin in policy (see "Pin each key's fingerprint" below):
printf '\0\0\0\001hkdfguard-kek-fingerprint-v1\0\0\0\001\0' \
    | openssl dgst -sha256 -mac HMAC \
        -macopt hexkey:$(od -An -v -tx1 com.company.orders | tr -d ' \n')
```

Run both on the machine where you create the key, then load the file into
your secret store (Vault, AWS Secrets Manager, Google Secret Manager, Azure
Key Vault, a Kubernetes Secret) and record the fingerprint in the policy.
Stores that hold text, such as a Kubernetes Secret's `data` or a Vault KV
entry, take the 32 bytes base64-encoded, as they require; the file mounted
on the host must be the 32 raw bytes again, not the base64.

The file is the raw bytes only: not base64 or hex text, no trailing
newline, not PEM or DER. A file of any other length is refused with an
error giving its length, and so is an all-zero file. `provision` reads and
checks the key, so a wrong format is reported when you provision, not
later.

**File rules.** The file must:
- be owned by root, with no group or other access
  (`0400` or `0600`), except that a root-owned file may also be readable by
  its group (`root:<group> 0440`), so a non-root service can read it. A
  file owned by the service's own user is accepted only under the developer
  security model, or when `external_secret.pinned_keys` pins the service's
  key: under the production model only root creates a KEK, and for this
  provider putting a file in the mount is creating one. The pin is root
  saying which key it is, whoever wrote the file;
- be a regular file;
- resolve to a path inside the mount (symlinks are followed only while they
  stay inside it).

The mount and every directory above it must be owned as the file must be
(root; or the service's user under the developer model or with a pinned
key) and not writable by anyone else -- sticky directories such as
`/tmp` included, so a mount anywhere under `/tmp`, `/var/tmp` or `/dev/shm`
is refused. A sticky directory on a read-only mount is the one exception:
a Kubernetes Secret volume, or a memory-backed `emptyDir`, is `1777`, and
mounted read-only is fine. A disk-backed `emptyDir` is `0777`, not sticky,
and is refused even read-only: use `medium: Memory`, or mount a private
subdirectory of it. Platform settings that meet
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

The fingerprint is one HMAC-SHA-256 output of the key over a fixed
input, `HMAC(KEK, [1]_32 || "hkdfguard-kek-fingerprint-v1" || 0x00 || [256]_32)`
(an NIST SP 800-108 counter-mode KDF block). It's the same value
`provision` prints, every wrapped payload carries, and
`retire --fingerprint` takes. It isn't secret and reveals nothing about the
key, so it can live in the policy file wherever that's kept. Compute it
where you generate the key, before the key goes into your secret store:

```sh
printf '\0\0\0\001hkdfguard-kek-fingerprint-v1\0\0\0\001\0' \
    | openssl dgst -sha256 -mac HMAC \
        -macopt hexkey:$(od -An -v -tx1 com.company.orders | tr -d ' \n')
```

`printf` writes that fixed input (the counter `00000001`, the label, a zero
byte and the output length `00000100`, 256 bits); `od` turns the key file
into hex for `-macopt hexkey:`. The 64 hex characters after `= ` are the
fingerprint, ready to paste into `pinned_keys`.

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
[step 4](#tpm-20)).

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
pinned_session_salt_key_name = "000b<64 hex chars>"  # the storage root key provisioning is salted to

[tpm.pinned_names]
"com.company.orders" = "000b<64 hex chars>"

[tpm.auth_groups]
"com.company.orders" = "orders"      # only the orders service's group reads its authValue
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

**Development: SoftHSM2, else ephemeral.** The policy in the `hkdfguard-overlay-dev` container
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
  process that makes it. Retiring a KEK takes root too. On TPM2 the
  filesystem enforces it: only root can create or delete a key file.
  On PKCS#11 it is the library's rule, not the token's: the token's one
  authority is its user PIN, which every service using it can read, and
  a PIN holder can delete or regenerate a key with the token's own
  tools (see [What the PIN decides](#what-the-pin-decides)). Pin each
  service's key with `pkcs11.pinned_keys` so that is detected.
  External-secret never creates a KEK
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
are the same HMAC operation on the KEK, so nothing can grant one without
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
| `/var/lib/hkdfguard/tpm/.lock` | `root:root 0600` (`provision` creates it) | Empty; held while a key is provisioned or retired. Only root can open it, so no service can hold up either |
| `/var/lib/hkdfguard/tpm/<service>.tpmauth` | `root:<service-group> 0440`, the group from `tpm.auth_groups`; `root:root 0400` with none (`provision` sets it) | The key's authValue: only that service may read it |
| `/etc/hkdfguard/tpm.owner-auth` (if used) | `root:<key-users> 0440` | Every TPM-using service must read it, and so holds the Owner hierarchy's password |
| `/etc/hkdfguard/pkcs11.pin` | `root:<key-users> 0440` | As above |
| External secret `<dir>/<service>` | root, `0400`; or `root:<group> 0440`; the service's user only under the developer model or with a pinned key | Only that service (or the pod's `fsGroup`) |
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

Every member of `hkdfguard` can read every service's key file, but only a
service's own group (from `tpm.auth_groups`) its authValue file, and
without its authValue another service's key file is useless. List each
service's group in `tpm.auth_groups` before provisioning it; the services
still need the directory's group to reach their files.

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
allow_unwrap_from_lower_provider = false   # true: unwrap payloads wrapped under a provider later in the order than
                                           # one holding the service's KEK now. Only while those are re-wrapped.

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
session_encryption = "on"                             # on | off (off: test harnesses only)
pinned_session_salt_key_name = "000b<64 hex chars>"   # default: unset; provision refuses until it is set, and prints the Name
allow_unpinned_provisioning = false                   # true: provision without the pin (firmware or virtual TPMs, test harnesses)

[tpm.auth_groups]                                     # default: none (every .tpmauth file root:root 0400)
"com.company.orders" = "orders"                       # its .tpmauth file root:orders 0440

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
require_pinned_keys = false                      # true: only the services below have a key on the token

[pkcs11.pinned_keys]                             # default: none
"com.company.orders" = "<64 hex chars>"          # the fingerprint provision prints; or a list of them
```

Notes:

- Set `provider` only with `mode = "require"`, and `level` only with
  `mode = "require-level"`. Any other combination is rejected.
- All paths must be absolute.
- Settings are checked whenever the policy is read, whichever provider ends
  up being used. For example, a `session_encryption` value other than
  `on` or `off` makes every call fail, even on a host that never uses its
  TPM.

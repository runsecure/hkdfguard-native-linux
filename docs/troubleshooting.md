# Troubleshooting HKDFGuard

- [First: find out why](#first-find-out-why)
- [Every call fails: the policy is refused (-9)](#every-call-fails-the-policy-is-refused--9)
- [No provider is available (-3)](#no-provider-is-available--3)
- [A provider is failing (-4)](#a-provider-is-failing--4)
- [No KEK for the service (-17)](#no-kek-for-the-service--17)
- [Fingerprint mismatch (-16)](#fingerprint-mismatch--16)
- [Unwrap fails authentication (-11)](#unwrap-fails-authentication--11)
- [Unwrap says the payload is malformed or unsupported (-10, -12)](#unwrap-says-the-payload-is-malformed-or-unsupported--10--12)
- [The key file is refused as untrusted (-39)](#the-key-file-is-refused-as-untrusted--39)
- [Other problems](#other-problems)

## First: find out why

The library returns only a status code to your application; it doesn't print
its reasons. The CLI does print them, so run it **as the service's user**, for the
same service name:

```sh
sudo -u orders hkdfguard provision -sn com.company.orders
```

`sudo -u` runs it with the groups that account belongs to, so it sees what
the application sees.

The output names the provider, the service and the exact reason.

Every failure worth an administrator's attention is also in the audit trail,
with the caller and service, whatever process hit it:
`journalctl -t hkdfguard` (or `grep hkdfguard /var/log/secure` or
`/var/log/auth.log`). Event IDs are listed in the README, "Audit trail".

The library re-reads `/etc/hkdfguard/policy.toml` on every call, so after
fixing the policy or a file, just try again. Nothing needs restarting.

## Every call fails: the policy is refused (-9)

`HKDFGUARD_ERR_POLICY_INVALID` means the policy file exists but can't be
trusted or parsed, and then **every** call fails. The library never falls
back to defaults in that case.

| Message contains | Cause | Fix |
|---|---|---|
| `refusing to trust its location (directory ...: writable by group or others (mode 775) ...)` | `/etc/hkdfguard` or a directory above it can be changed by non-root users | `sudo chmod go-w <directory>`; every directory up to `/` must be root-owned and not group- or other-writable |
| `... (mode 1777; sticky, like /tmp, which is not enough) ...` | The file (policy, secret, PIN, module, key file) is somewhere under `/tmp`, `/var/tmp`, `/dev/shm` or another sticky, world-writable directory, even inside a private directory there | Move it to a directory only root (or, where allowed, the service) can write, all the way up to `/`. Sticky directories are never trusted; only a read-only mount, such as a Kubernetes Secret volume, is exempt |
| `owned by uid ..., which is not an allowed owner` | The policy, or a directory above it, isn't owned by root | `sudo chown root:root /etc/hkdfguard/policy.toml` |
| `permissions too broad (mode ...)` | The policy is group- or other-writable | `sudo chmod 0644 /etc/hkdfguard/policy.toml` |
| `TOML parse error` | Invalid TOML. Most often a top-level key (`preferred_order`) below a `[section]`, or an unquoted service name in `[tpm.pinned_names]` | Move `preferred_order` above the first section; quote service names: `"com.company.orders" = ...` |
| `unknown field` | A misspelled or misplaced setting | Check it against the [policy reference](configuration.md#policy-reference) |
| `selection.mode "require" needs a selection.provider` (or similar) | `provider` and `level` don't match the mode | `require` takes `provider`, `require-level` takes `level`, `prefer` takes neither |
| `tpm.session_encryption "required" needs tpm.pinned_session_salt_key_name` | `required` without its pin | Add the salt-key Name ([configuration.md](configuration.md#tpm-20), step 4), or use `auto` |

## No provider is available (-3)

`HKDFGUARD_ERR_PROVIDER_UNAVAILABLE` means no provider that the policy allows is set
up on this host.

**TPM.**
- **No access to the device:** the account can't open `/dev/tpmrm0`. Add
  it to the `tss` group. Check with
  `ls -l /dev/tpmrm0` and `id <user>`.
- **No key file for the service:** a service with no key file in the key
  directory has no KEK on the TPM, so wrap and unwrap move on to the next
  provider, or fail with -17 when there is none. Run `sudo hkdfguard
  provision -sn <service>` ([configuration.md](configuration.md#tpm-20)).
  If this host has a TPM but is meant to use another provider, leave
  `"tpm2"` out of `preferred_order` in the policy (or use
  `selection.mode = "require"`), and the TPM is not opened at all.
- **tpm2-tss noise:** lines such as
  `ERROR:tcti:... Failed to open specified TCTI device file /dev/tpmrm0` come
  from tpm2-tss itself while the library checks for a TPM. On a host with
  no TPM they're expected, and harmless if another provider serves the call.

**PKCS#11.** It counts as absent when the policy names no `pkcs11.module`, or
when the PIN file (default `/etc/hkdfguard/pkcs11.pin`) doesn't exist.

**External secret.** It counts as absent when none of the
[conventional mounts](configuration.md#external-secret-file) exist and
`external_secret.dir` isn't set. A configured `dir` that's missing is an
error instead (-4).

**Ephemeral.** It's never used unless the policy names it.

## A provider is failing (-4)

`HKDFGUARD_ERR_PROVIDER_ERROR` means a provider is set up, but something about it is
wrong. The library stops rather than quietly using a weaker provider.

**TPM**

| Symptom (CLI output) | Fix |
|---|---|
| `TPM key file ... is present but can't be trusted` | Make it `root:<group> 0440` or `root:root 0400`, a regular file (not a symlink), in directories only root can change up to `/` (never under `/tmp`) |
| `TPM key file ... is not a key this library creates`, or holds an unreadable part | The file isn't one `provision` wrote, or is damaged. Restore it from your backup. |
| `TPM key file ... holds an ECC key, from the ECDH format hkdfguard used before its first release` | The key file was made by a pre-release build. Delete it and run `provision` again; anything wrapped under it was in the old payload format, which this version refuses anyway, so deliver those DEKs again and wrap them anew. |
| `TPM key directory ... does not exist` | `provision` needs it: create it as the message says, with the group of the services that use TPM keys. |
| `TPM2_Load of this service's key file failed` | The key file was made by another TPM, or this TPM was cleared since (a firmware reset can do it). The key is gone for good; see [Fingerprint mismatch](#fingerprint-mismatch--16). |
| `TSS2_LOG enables debug/trace logging in tpm2-tss ...` | Unset `TSS2_LOG`, or lower it to `info` or below: at debug levels tpm2-tss logs secrets |
| `tpm.require_pinned_names is set and this service has no pinned TPM Name` | The service isn't in `[tpm.pinned_names]`. Add the line the message prints, then run `provision` again. |
| A pinned Name mismatch | The service's key file holds a different key than the pinned one: it was replaced, or the service was retired and provisioned again. Restore the original key file from your backup, or re-learn the pin only once you're sure which key is right: see [Fingerprint mismatch](#fingerprint-mismatch--16). |
| A failed owner authorization | `owner_auth_file` and the TPM's owner password disagree. Set both in the same change. |
| `could not open the configured TCTI` | The `tcti` the policy names can't be opened. Check the path, or that `tpm2-abrmd` is running for `tabrmd:`. |
| `TPM_RC_LOCKOUT` | The TPM is in dictionary-attack lockout, often from another program's failed authorizations. Wait for the lockout interval, or reset it with the lockout password. |

**PKCS#11**

| Symptom | Fix |
|---|---|
| PIN file refused | Make it `root:<group> 0440` or `root:root 0400`, in directories only root can change up to `/` (never under `/tmp`) |
| Module refused, or won't load | The module and every directory above it must be root-owned and not group- or other-writable, sticky (`/tmp`) included. Check the path. |
| No token matches | Check `token_label` and `token_serial` against `pkcs11-tool --list-token-slots` (from OpenSC). Exactly one token must match. |
| `the PKCS#11 token reports failed user-PIN attempts` | The PIN file is probably wrong. Fix it **before** the token locks. After a rejected PIN, the process makes no further logins until the PIN file changes. |

**External secret**

| Symptom | Fix |
|---|---|
| `permissions too broad (mode ...)` | The key file must be `0400` or `0600` with no group or other access, or `root:<group> 0440`. On Kubernetes, use `defaultMode: 0400` (never `0444`); a non-root pod also needs `fsGroup`. |
| `owned by uid ..., which is not an allowed owner` | The key file must be owned by root or by the service's user |
| `resolves to ..., outside the secret mount` | A symlink points out of the mount. Deliver the file inside it. |
| `directory ...: writable by group or others (mode ...)` | The mount, or a directory above it or above the resolved file, can be changed by others -- a sticky one (`/tmp`) included. Mount the secrets read-only (as Kubernetes does), or somewhere only root or the service can write, up to `/`. |
| `external secret is N bytes; it must be exactly 32 raw random bytes ...` | The file must hold exactly 32 raw bytes. Most often it's base64 or hex text (decode it to raw bytes where it is mounted), has a trailing newline (`echo` adds one), or is an old P-256 key in PEM or DER, which is no longer accepted. Generate a new key with `head -c 32 /dev/urandom` or `openssl rand -out <file> 32` and pin its new fingerprint. |
| `external secret is all zero bytes` | The file was filled from `/dev/zero` or truncated and extended. Provision 32 random bytes. |
| `the external secret for this service has fingerprint ..., which is not the one pinned in policy` | The mounted key isn't the one `external_secret.pinned_keys` names. Either something else wrote the mount (check every container that mounts the volume read-write), or the key was rotated without adding its fingerprint first. Pin the new fingerprint only once you've confirmed where the key came from. |
| `external_secret.require_pinned_keys is set and service ... has no pinned key` | The service isn't in `[external_secret.pinned_keys]`. Compare the printed fingerprint with the one you computed when generating the key, then add the line. |
| A configured `external_secret.dir` is missing | The mount isn't there yet (a volume not attached, a sidecar not ready). Fix the mount; the library won't use another provider in the meantime. |

## No KEK for the service (-17)

`HKDFGUARD_ERR_KEK_NOT_FOUND` means the service hasn't been provisioned on this host.
`wrap` never creates a key. The CLI says:

```
no KEK is provisioned for service "com.company.orders"; run `hkdfguard provision --service-name com.company.orders` first
```

Run `provision`; from code, call `hkdfguard_create_kek` once at startup.
Check the service name for typos too: service names are case-insensitive,
but otherwise must match exactly.

## Fingerprint mismatch (-16)

`HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH` means the payload was wrapped under a **different
KEK** than the one the service resolves to now. Something changed the key:

- **TPM:** the service's key file was replaced, or retired and provisioned
  again. (A TPM cleared by a firmware reset or `tpm2_clear`, or replaced,
  fails earlier: its key files no longer load at all.)
- **External secret:** the key file was replaced or rotated.
- **PKCS#11:** the HMAC secret key was deleted and generated again, or a
  different token is now selected.
- **Any provider:** the payload came from another host. A payload only
  ever opens on the host whose KEK wrapped it.

To recover:
- **The key file or secret was changed:** restore the original from your
  backup, byte for byte. The payload then unwraps again.
- **The TPM was cleared or replaced:** the old key is gone for good, and so
  is every DEK wrapped only under it. Deliver the DEK again from its source
  and wrap it anew.

This is why [backing up the key files](configuration.md#back-up-the-key-files)
matters.

## Unwrap fails authentication (-11)

`HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED` means the KEK is right but the payload
doesn't authenticate. Either:
- the **service name** differs from the one used when wrapping;
- the file is **corrupt**;
- or it was **tampered with**.

HKDFGuard can't tell these apart, by design.

## Unwrap says the payload is malformed or unsupported (-10, -12)

`HKDFGUARD_ERR_PAYLOAD_MALFORMED` means the bytes passed to unwrap aren't a
wrapped DEK at all: most often a **truncated** or **extended** copy (compare
its size with what `wrap` reported, at most 276 bytes), or the wrong file.
`HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED` means the payload's version byte isn't
one this library knows (it accepts version 2 only): a payload from a newer
HKDFGuard, one from a pre-release build in the unreleased version 1 (ECDH)
format, or not a payload.
Read key files with `hkdfguard_open_file`, which reports these problems
before unwrap is called.

`HKDFGUARD_ERR_CRYPTO_ERROR` (-5) is for a cryptographic step
failing for another reason, such as the OS random number generator; it never
means the payload itself is bad.

## The key file is refused as untrusted (-39)

`HKDFGUARD_ERR_FILE_UNTRUSTED` from `hkdfguard_open_file` means someone
the security model doesn't trust could have replaced the key file: the
file, or a directory above it (or above a symlink to it), is owned by
someone untrusted or is writable by someone else. Under the production
model (the default) only root and deployers -- members of
`hkdfguard-deployers` or of a policy `deployer_groups` group -- are
trusted, and a directory may be group-writable only through a deployer
group; under the developer model, root and the reading process's user,
with no group write. Find which with `namei -l <path>` (and
`namei -l "$(readlink -f <path>)"`).

| Cause | Fix |
|---|---|
| Production: the file (or a directory above it) is owned by the service's own account -- for example `hkdfguard wrap` was run as the service user, or the file was written before upgrading to a version with the production default | Redeploy it as root or a deployer (`sudo hkdfguard wrap ... -g <service-group>`), or set `security_model = "developer"` in the policy until you have |
| Production: the file's owner was removed from the deployer group | Redeploy it as a current deployer or root. Membership is looked up on every call |
| The file is group- or other-writable | `chmod 0600` (or `0640`/`0644`: read access is fine, it is ciphertext) |
| The file, or a directory above it, is owned by another non-root user | Own it by root or a deployer (production), or by the service's user or root (developer) |
| A directory above it is group- or other-writable | `chmod go-w <directory>`, or move the key file |
| The key file is under `/tmp`, `/var/tmp`, `/dev/shm` or another **sticky**, world-writable directory, even inside a private `mktemp -d` directory there | Move it to a directory only the service or root can write, all the way up to `/` (for example `/var/lib/<app>/`, `0700` or `0755`). Sticky directories are never trusted, for key files or anything else the library reads. |

`hkdfguard wrap` applies the same mode rule to its `--key-file-path` up
front, before the DEK is read, and stops with
`... is writable by group or others (mode ...); the library would refuse to read a key file at ...`
rather than write a key file the application could never open. Under the
developer model it checks modes only, not owners, since it often runs as
root into a folder the service's account owns. Under production it asks the
library about each folder's owner and group, and stops with
`... is owned by uid ..., whom the library does not trust with key files under the production security model ...`
for a folder owned by someone other than root or a deployer.

## `wrap` says this account "may not persist key files"

`under the production security model this account (uid ...) may not persist
key files ... Nothing was written`: the production model trusts only key
files root or a deployer wrote, so `wrap` refuses anyone else before reading
the DEK. Run it as root, or add the account to `hkdfguard-deployers`
(`sudo usermod -aG hkdfguard-deployers <user>`) or to a group listed in the
policy's `deployer_groups`. On a development machine, `security_model =
"developer"` lifts the rule.

## Creating or retiring a KEK is refused (-18)

`HKDFGUARD_ERR_KEK_ACCESS_DENIED` from `hkdfguard_create_kek` (the CLI:
`only root creates or retires a KEK`) means the production model is in
force, the caller isn't root, and the service has no KEK yet: only root
creates one. Run `sudo hkdfguard provision -sn <service>`; after that, the
application's own `hkdfguard_create_kek` at startup returns the existing
KEK. `hkdfguard retire` as non-root fails the same way. An ephemeral KEK is
not affected.

## A deployer group can't be used (-80)

`HKDFGUARD_ERR_LINUX_GROUP_INVALID` refines `-9`: every key-file read (and
`hkdfguard_security_model`, and `wrap`) fails because a group in the
policy's `deployer_groups` doesn't exist on this host, is over-broad
(`root`, `users`, `nogroup`, `nobody`, `wheel`, `sudo`, `adm`, `staff`, gid
0 or 65534), or can't be looked up -- or `hkdfguard-deployers` itself can't
be. The library's log names the group. Create it, choose a dedicated group,
or fix NSS (LDAP, sssd) if lookups are failing.

## Other problems

**Startup takes about a second per service.** By design:
`hkdfguard_create_kek` and `hkdfguard_kek_exists` take at least
`setup_min_delay_ms` (default 1000 ms) each, and run one at a time. Call
them once at startup, not per request. Wrap and unwrap aren't slowed.

**`warning: memory not locked as a whole ...` from the CLI.** Harmless:
the CLI still locks its own copy of the DEK. To lock everything, run it as
root, or raise the memory-lock limit first (`ulimit -l unlimited`).

**`could not disable core dumps / ptrace access for this process`.** The
CLI (or `hkdfguard_harden_process`) couldn't harden the process, so it
refuses to handle key material. Containers or sandboxes that block `prctl`
or `setrlimit` cause this; allow them.

**`libhkdfguard.so.1: cannot open shared object file`.** The library isn't
installed where the loader looks:
- install the `libhkdfguard1` (or `hkdfguard-libs`) package;
- after a manual install to `/usr/local/lib`, run `sudo ldconfig`;
- load it by the name `libhkdfguard.so.1`. Only the development package
  provides `libhkdfguard.so`.

**`version 'GLIBC_2.39' not found`.** The standalone tarball and container
overlay need glibc 2.39 or newer. Use the package built for your
distribution instead ([installation.md](installation.md#requirements)).

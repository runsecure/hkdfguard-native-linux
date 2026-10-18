# Troubleshooting HKDFGuard

- [First: find out why](#first-find-out-why)
- [Every call fails: the policy is refused (-9)](#every-call-fails-the-policy-is-refused--9)
- [No provider is available (-3)](#no-provider-is-available--3)
- [A provider is failing (-4)](#a-provider-is-failing--4)
- [No KEK for the service (-17)](#no-kek-for-the-service--17)
- [Fingerprint mismatch (-16)](#fingerprint-mismatch--16)
- [Unwrap fails authentication (-11)](#unwrap-fails-authentication--11)
- [Unwrap says the payload is malformed or unsupported (-10, -12)](#unwrap-says-the-payload-is-malformed-or-unsupported--10--12)
- [Other problems](#other-problems)

## First: find out why

The library returns only a status code to your application; it doesn't print
its reasons. The CLI does print them, so run it **as the service's user, with
the service's groups**, for the same service name:

```sh
sudo systemd-run --pty --uid=orders --gid=orders \
    -p SupplementaryGroups="tss hkdfguard" \
    hkdfguard provision -sn com.company.orders
```

(`sudo -u orders ...` works too, but only with the user's permanent groups,
not a systemd unit's `SupplementaryGroups=`.)

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
  it to the `tss` group, or set `SupplementaryGroups=tss`. Check with
  `ls -l /dev/tpmrm0` and `id <user>`.
- **No derivation secret:** a missing secret at the default path makes the
  TPM count as not set up. The CLI shows:

  ```
  hkdfguard: TPM not used: TPM derivation secret /etc/hkdfguard/tpm.derivation-secret does not exist. Create it as root: ...
  ```

  Create it as the message says ([configuration.md](configuration.md#tpm-20)).
  If the policy *names* a derivation secret path, a missing file is an
  error instead (-4).
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
| `TPM derivation secret at ... is present but unusable` | Make it `root:<group> 0440` or `root:root 0400`, a regular file (not a symlink), and not empty |
| `TSS2_LOG enables debug/trace logging in tpm2-tss ...` | Unset `TSS2_LOG`, or lower it to `info` or below: at debug levels tpm2-tss logs secrets |
| `tpm.require_pinned_names is set and this service has no pinned TPM Name` | The service isn't in `[tpm.pinned_names]`. Add the line the message prints, then run `provision` again. |
| A pinned Name mismatch | The TPM derives a different key than the pinned one: the derivation secret changed, the TPM was cleared or replaced, or the pin was learned before the secret was created. Re-learn the pin only once you're sure which key is right: see [Fingerprint mismatch](#fingerprint-mismatch--16). |
| A failed owner authorization | `owner_auth_file` and the TPM's owner password disagree. Set both in the same change. |
| `could not open the configured TCTI` | The `tcti` the policy names can't be opened. Check the path, or that `tpm2-abrmd` is running for `tabrmd:`. |
| `TPM_RC_LOCKOUT` | The TPM is in dictionary-attack lockout, often from another program's failed authorizations. Wait for the lockout interval, or reset it with the lockout password. |

**PKCS#11**

| Symptom | Fix |
|---|---|
| PIN file refused | Make it `root:<group> 0440` or `root:root 0400` |
| Module refused, or won't load | The module and every directory above it must be root-owned and not group- or other-writable. Check the path. |
| No token matches | Check `token_label` and `token_serial` against `pkcs11-tool --list-token-slots` (from OpenSC). Exactly one token must match. |
| `the PKCS#11 token reports failed user-PIN attempts` | The PIN file is probably wrong. Fix it **before** the token locks. After a rejected PIN, the process makes no further logins until the PIN file changes. |

**External secret**

| Symptom | Fix |
|---|---|
| `permissions too broad (mode ...)` | The key file must be `0400` or `0600` with no group or other access, or `root:<group> 0440`. On Kubernetes, use `defaultMode: 0400` (never `0444`); a non-root pod also needs `fsGroup`. |
| `owned by uid ..., which is not an allowed owner` | The key file must be owned by root or by the service's user |
| `resolves to ..., outside the secret mount` | A symlink points out of the mount. Deliver the file inside it. |
| `external secret is not a valid P-256 key (expected 32 raw bytes, PKCS#8 DER or SEC1 DER; PEM must be converted to DER)` | The file isn't one of the accepted forms. Most often it's PEM (text starting `-----BEGIN`): convert it with `openssl pkey -in key.pem -outform DER -out key.der`. Or the key is for another curve: only P-256 is accepted. |
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

- **TPM:** the derivation secret was changed, lost, added or removed; or
  the TPM was cleared (by a firmware reset or `tpm2_clear`) or replaced.
- **External secret:** the key file was replaced or rotated.
- **PKCS#11:** the key pair was deleted and generated again, or a
  different token is now selected.
- **Any provider:** the payload came from another host. A payload only
  ever opens on the host whose KEK wrapped it.

To recover:
- **The key file or secret was changed:** restore the original from your
  backup, byte for byte. The payload then unwraps again.
- **The TPM was cleared or replaced:** the old key is gone for good, and so
  is every DEK wrapped only under it. Deliver the DEK again from its source
  and wrap it anew.

This is why [backing up the derivation secret](configuration.md#back-up-the-derivation-secret)
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
one this library knows: a payload from a newer HKDFGuard, or not a payload.
Read key files with `hkdfguard_open_file`, which reports these problems
before unwrap is called.

`HKDFGUARD_ERR_CRYPTO_ERROR` (-5) is for a cryptographic step
failing for another reason, such as the OS random number generator; it never
means the payload itself is bad.

## Other problems

**`provision` says "already provisioned" for a service you never set up.**
On a TPM without `require_pinned_names`, the TPM derives a key for any name,
so `provision` always reports a key; a typo in a service name then quietly
gets its own key. Enable pinned names to make provisioning explicit
([configuration.md](configuration.md#tpm-20), step 3).

**Startup takes about a second per service.** By design:
`hkdfguard_create_kek` and `hkdfguard_kek_exists` take at least
`setup_min_delay_ms` (default 1000 ms) each, and run one at a time. Call
them once at startup, not per request. Wrap and unwrap aren't slowed.

**`warning: memory not locked as a whole ...` from the CLI.** Harmless:
the CLI still locks its own copy of the DEK. To lock everything, run it as
root, or with `LimitMEMLOCK=infinity` in a systemd unit.

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

//! Provider 3: External Secret Provider.
//!
//! Used when TPM2 and PKCS#11 are both unavailable. Reads a persistent P-256
//! KEK that has been provisioned *outside* this process by the deployment
//! platform -- a Kubernetes Secret, a Docker secret, a Vault Agent
//! sink, a CSI Secret Store volume, a systemd credential, or any other
//! mounted-file secret mechanism -- rather than generating one itself.
//!
//! Lookup pattern: `<dir>/<service>`. `<dir>` is `external_secret.dir` from
//! the root-owned policy when set; otherwise the first of a list of
//! conventional secret mount points that exists.
//!
//! The secret file's contents must be a P-256 private key, as exactly 32
//! raw big-endian scalar bytes, PKCS#8 DER, or SEC1 DER (`ECPrivateKey`,
//! what `openssl genpkey -outform DER` writes).
//!
//! This provider never creates or writes a secret: if no file exists for a
//! given service it declines with [`Error::KeyNotProvisioned`]. A file that
//! exists is only reported as a provisioned KEK once it has been read and
//! parsed, so a malformed secret fails at provisioning, not at first use.
//!
//! ## What the file must satisfy
//!
//! For this provider the file *is* the KEK private key -- not a PIN or a
//! defensive input -- so it is held to the same standard as every other
//! secret this crate reads from disk:
//!
//! - **Owned by root or by this process's user**, with **no group or
//!   other access** (`0400`/`0600`) -- except that a root-owned file may
//!   also be group-readable (`root:<group> 0440`), which is what a
//!   Kubernetes Secret volume becomes when the pod sets `fsGroup`, and how
//!   a non-root service reads a root-owned secret. A world-readable key,
//!   or a group-readable one the service owns itself, is refused, and
//!   refused loudly: it is reported as an error, never as "not
//!   provisioned", so a misconfigured mount can't silently fall through to
//!   a weaker provider.
//! - **In a mount nobody else can write to.** The mount directory and
//!   every directory above it must be owned by root or this process's user
//!   and not writable by group or others -- sticky or not, so a mount
//!   anywhere under `/tmp`, `/var/tmp` or `/dev/shm` is refused, however
//!   private the directories beneath it (see
//!   [`crate::secure_file::check_dir_chain`]); so must the directory the
//!   resolved file sits in and every one above it. The one exception is
//!   a read-only mount: a Kubernetes Secret volume is `1777` but mounted
//!   read-only, so nobody can write to it, and it is fine. Otherwise
//!   another user could plant a KEK for a not-yet-provisioned service.
//! - **A regular file.** Not a directory, device, or FIFO (which would
//!   block the read forever).
//! - **Resolves to a path inside the mount.** Symlinks are followed --
//!   Kubernetes Secret volumes materialize every key as a symlink into a
//!   `..data/` directory, and refusing that would refuse the most common
//!   delivery mechanism outright -- but only while the resolution stays
//!   within the mount directory. A link that leads anywhere else is
//!   refused. That keeps the property a blanket symlink ban would
//!   give (nothing in the mount can redirect a read to an arbitrary host
//!   path) without breaking the platform that needs symlinks.
//!
//! All checks are made on the opened descriptor, and the resolved path is
//! opened with `O_NOFOLLOW` so no link can be swapped in between
//! resolution and open -- see [`open_secret_within_mount`].
//!
//! Every common mechanism can meet the mode requirement with one setting:
//! Kubernetes `defaultMode: 0400` (`0440` with `fsGroup` for a non-root
//! pod), Vault Agent `perms = "0400"`, Docker Swarm `mode: 0400`; systemd
//! `LoadCredential=` is already `0400`.
//!
//! ## Pinning
//!
//! The rules above limit *who* could have written the file: root, this
//! service's user, or whatever else mounts the same volume read-write (a
//! secrets sidecar, a shared `emptyDir`). They say nothing about *which*
//! key it holds, and any of those writers can mount a valid key of its own
//! before the real one arrives. With `external_secret.pinned_keys` naming
//! a service, the key's fingerprint (SHA-256 of its public point, see
//! [`crate::crypto::kek_fingerprint`]) must be one of the pinned values, or
//! the key is refused -- an error, never "not provisioned". With
//! `external_secret.require_pinned_keys`, a service with no pin has no KEK
//! here, whatever is mounted for it; `provision` then reports the mounted
//! key's fingerprint and the policy line that would accept it.

use crate::crypto::kek_fingerprint; // the fingerprint every payload carries, and policy pins
use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::payload::FINGERPRINT_LEN;
use crate::provider::{Backend, KekHandle, KekProvider, ProviderType, SharedSecret}; // traits/types this module implements
use crate::secure_file::{open_checked, FileRequirements, Owner, SecretBuffer, FORBID_GROUP_OTHER_ACCESS}; // descriptor-based trust checks and a self-wiping read buffer
use elliptic_curve::pkcs8::DecodePrivateKey; // lets `SecretKey` parse from PKCS#8 DER (SEC1 DER is an inherent method)
use p256::{PublicKey, SecretKey}; // P-256 key types
use std::fs::File;
use std::path::{Path, PathBuf}; // filesystem path types

// Conventional mount points used by common secret-injection mechanisms,
// checked in order until one actually exists on disk.
const CANDIDATE_MOUNTS: &[&str] = &[
    "/var/run/secrets/hkdfguard",   // generic / Kubernetes-style secret mount
    "/run/secrets/hkdfguard",       // Docker Swarm secrets
    "/vault/secrets/hkdfguard",     // HashiCorp Vault Agent sink
    "/mnt/secrets-store/hkdfguard", // CSI Secret Store driver
];

// Holds the resolved secret directory, or `None` if no mount was found at
// construction time (in which case this provider is simply unavailable).
pub struct ExternalSecretProvider {
    dir: Option<PathBuf>,
    // Set when a mount is configured but can't be used (see
    // `crate::provider::Backend::Refused`); every call then fails with it.
    refused: Option<String>,
}

impl ExternalSecretProvider {
    pub fn new() -> Self {
        // resolve once at construction
        match resolve_dir() {
            Backend::Ready(dir) => ExternalSecretProvider { dir: Some(dir), refused: None },
            Backend::Absent => ExternalSecretProvider { dir: None, refused: None },
            Backend::Refused(reason) => {
                crate::provider::log_once(log::Level::Error, format!("hkdfguard: external-secret provider refused: {reason}"));
                ExternalSecretProvider { dir: None, refused: Some(reason) }
            }
        }
    }

    fn check_not_refused(&self) -> Result<()> {
        match &self.refused {
            Some(reason) => Err(Error::Provider(format!("external secret refused: {reason}"))),
            None => Ok(()),
        }
    }
}

// Whether `service` is safe to use directly as a single file name inside
// the mount directory: non-empty, no path separator, and never able to
// name "." (the mount itself), ".." (its parent), or a hidden dot-file --
// so no leading '.' and no consecutive dots. The C ABI already rejects
// such names before they get here (see cstr_to_service in src/lib.rs);
// this is the same rule enforced again at the point where the name
// actually becomes a path, so an in-crate caller that bypasses the ABI
// can't use it to escape the mount either. (The containment check in
// `open_secret_within_mount` would catch an escape anyway; this just
// refuses the name before touching the filesystem at all.)
fn is_safe_file_name(service: &str) -> bool {
    !service.is_empty() && !service.contains('/') && !service.starts_with('.') && !service.contains("..")
}

impl Default for ExternalSecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

// Handle type returned from `load_kek`; holds the key parsed from the
// mounted secret file.
struct ExternalSecretHandle {
    key_id: Vec<u8>,       // diagnostic-only tag embedded in the wrapped payload
    secret_key: SecretKey, // the key loaded from the externally provisioned file
}

impl KekHandle for ExternalSecretHandle {
    fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    fn ecdh(&self, point: &PublicKey) -> Result<SharedSecret> {
        Ok(crate::provider::software_ecdh(&self.secret_key, point)) // point: the payload's hashed point H_salt (see crypto.rs)
    }

    fn public_key(&self) -> Result<PublicKey> {
        Ok(self.secret_key.public_key()) // trivial: the public half is always derivable from the private key we already hold
    }
}

impl KekProvider for ExternalSecretProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::ExternalSecret
    }

    fn probe(&self) -> bool {
        // a mount directory was found (not that any given service has a file
        // in it), or one was configured and is refused
        self.dir.is_some() || self.refused.is_some()
    }

    // Loads the key exactly as `load_kek` would -- open, trust checks, read,
    // parse -- so "exists" means "exists *and* is a usable key", and a
    // malformed secret is reported when it is provisioned rather than at
    // the first wrap. A file that is present but fails a trust check, or
    // doesn't parse, is an error here, not `false`: reporting it as absent
    // would let the chain move on to a weaker provider and hide the
    // misconfiguration.
    fn kek_exists(&self, service: &str) -> Result<bool> {
        self.check_not_refused()?;
        if !is_safe_file_name(service) {
            return Ok(false); // can never name a provisioned secret file
        }
        let Some(dir) = self.dir.as_ref() else {
            return Ok(false); // no mount at all
        };
        let pins = service_pins(service)?;
        if matches!(pins, Pins::Unpinned) {
            return Ok(false); // the allowlist is on and this service isn't on it
        }
        match read_key(dir, service)? {
            Some(key) => {
                check_pins(&key, &pins)?;
                Ok(true)
            } // the parsed key drops (and zeroizes) here
            None => Ok(false),
        }
    }

    // This provider never creates or writes a secret (see the module-level
    // doc comment), so `create_if_missing` never changes what is loaded.
    // It only decides what an unpinned service under
    // `require_pinned_keys` gets: a caller provisioning the service is told
    // the fingerprint to pin; one only loading gets the decline.
    fn load_kek(&self, service: &str, create_if_missing: bool) -> Result<Box<dyn KekHandle>> {
        self.check_not_refused()?;
        if !is_safe_file_name(service) {
            return Err(Error::Provider(
                "this service name cannot be used as an external secret file name".into(), // never the name itself: service names stay out of the log
            ));
        }
        let dir = self
            .dir
            .as_ref()
            .ok_or(Error::KeyNotProvisioned("no external secret mount found"))?; // no mount at all -> decline immediately

        let pins = service_pins(service)?;
        if matches!(pins, Pins::Unpinned) && !create_if_missing {
            return Err(Error::KeyNotProvisioned(
                "external_secret.require_pinned_keys is set and policy pins no key for this service",
            ));
        }
        let secret_key = read_key(dir, service)?.ok_or(Error::KeyNotProvisioned(
            "no secret file provisioned for this service", // mount exists, but nothing provisioned for this service yet
        ))?;
        if matches!(pins, Pins::Unpinned) {
            // Provisioning here means a root-owned policy edit, which this
            // process can't make itself. Do the part it can: report the
            // fingerprint of the key that is mounted, ready to pin.
            return Err(Error::Provider(unpinned_service_instructions(service, &secret_key)));
        }
        check_pins(&secret_key, &pins)?;
        let key_id = format!("external:{service}").into_bytes();

        Ok(Box::new(ExternalSecretHandle {
            key_id,
            secret_key,
        }))
    }
}

/// Opens, checks, reads and parses `<mount>/<service>`. `Ok(None)` only when
/// no such file exists (nothing provisioned); a file that is untrusted
/// (escapes the mount, wrong owner, too broad a mode, not a regular file),
/// unreadable, or not a valid P-256 key is an error, never "not
/// provisioned".
fn read_key(mount: &Path, service: &str) -> Result<Option<SecretKey>> {
    let mut file = match open_secret_within_mount(mount, service) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Provider(format!("external secret for this service rejected: {e}"))),
    };

    // Raw KEK private-key material read straight off disk into a
    // `SecretBuffer`: one fixed allocation, never grown, zeroed on every
    // exit path below.
    let mut bytes = SecretBuffer::read_from(&mut file, MAX_SECRET_FILE_LEN)
        .map_err(|e| Error::Provider(format!("failed to read external secret: {e}")))?;
    let parsed = parse_secret_key(bytes.as_slice());
    bytes.wipe(); // the raw bytes have served their only purpose -- clear them now, on success *and* failure, before propagating anything
    parsed.map(Some)
}

/// What policy accepts as `service`'s key.
enum Pins {
    /// No pin, and no allowlist: any key the file checks accept.
    Any,
    /// A key with one of these fingerprints, and no other.
    OneOf(Vec<[u8; FINGERPRINT_LEN]>),
    /// No pin, under `require_pinned_keys`: no key at all.
    Unpinned,
}

/// Looks up `service`'s pins. A policy file that exists but is broken
/// fails closed: the pin lookup errors rather than reporting none.
fn service_pins(service: &str) -> Result<Pins> {
    if let Some(fingerprints) = crate::policy::pinned_external_keys(service)? {
        return Ok(Pins::OneOf(fingerprints));
    }
    if crate::policy::require_external_pinned_keys() {
        return Ok(Pins::Unpinned);
    }
    Ok(Pins::Any)
}

/// Refuses `key` unless its fingerprint is one `pins` accepts. A mismatch
/// is an error, not "not provisioned": something put a valid key that
/// isn't the administrator's where the KEK belongs, and the chain must not
/// move on to another provider as if nothing were there.
fn check_pins(key: &SecretKey, pins: &Pins) -> Result<()> {
    let Pins::OneOf(accepted) = pins else {
        return Ok(());
    };
    let fingerprint = kek_fingerprint(&key.public_key());
    if accepted.contains(&fingerprint) {
        return Ok(());
    }
    let accepted: Vec<String> = accepted.iter().map(|f| hex(f)).collect();
    Err(Error::Provider(format!(
        "the external secret for this service has fingerprint {}, which is not the one pinned in policy \
         (external_secret.pinned_keys: {})",
        hex(&fingerprint),
        accepted.join(", ")
    )))
}

/// The message `provision` gets for an unpinned service under
/// `external_secret.require_pinned_keys`: the mounted key's fingerprint, in
/// the form to paste into policy. The fingerprint and service name are both
/// public, so the message carries them as-is.
fn unpinned_service_instructions(service: &str, key: &SecretKey) -> String {
    let fingerprint = hex(&kek_fingerprint(&key.public_key()));
    format!(
        "external_secret.require_pinned_keys is set and service \"{service}\" has no pinned key. The key \
         mounted for it has fingerprint {fingerprint}. If that is the key you generated, add this to the \
         policy file and run provision again:\n  [external_secret.pinned_keys]\n  \"{service}\" = \"{fingerprint}\""
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Largest secret file accepted. A PKCS#8 DER P-256 key is ~138 bytes and
// a raw scalar is 32; this leaves generous headroom (e.g. for a PKCS#8
// encoding that also embeds optional attributes) while bounding the one
// up-front allocation `SecretBuffer` makes.
const MAX_SECRET_FILE_LEN: usize = 4096;

/// What a mounted KEK file must satisfy -- identical to the PKCS#11 PIN
/// and the TPM derivation secret, because it is at least as sensitive.
const SECRET_FILE_REQUIREMENTS: FileRequirements = FileRequirements {
    owner: Some(Owner::RootOrCurrentUser),
    forbidden_mode_bits: FORBID_GROUP_OTHER_ACCESS,
    follow_symlinks: false, // applied to the already-resolved path; see below
    allow_group_read_if_root_owned: true, // root:<fsGroup> 0440, as the kubelet writes it for a non-root pod
};

/// Resolves `<mount>/<service>` to the real file it names, refuses the
/// result unless it lies inside the mount, and opens it under
/// [`SECRET_FILE_REQUIREMENTS`].
///
/// Symlinks are followed during resolution -- that is what makes a
/// Kubernetes Secret volume (`<key>` → `..data/<key>` → `..<ts>/<key>`)
/// work -- but the fully resolved target must still start with the fully
/// resolved mount, so a link out of the mount is refused. Both sides are
/// canonicalized because the mount itself is often reached through a
/// symlink (`/var/run` → `/run` on most distributions).
///
/// The resolved path contains no symlinks, so opening *it* with
/// `O_NOFOLLOW` closes the race between resolution and open: a link
/// swapped in for the final component in that window fails with `ELOOP`
/// instead of being followed. The opened descriptor is then confirmed to be
/// the resolved file (see [`crate::secure_file::verify_opened`]), which also covers an
/// intermediate directory being swapped. (Doing that requires write access
/// to a directory between `/` and the file, which
/// [`crate::secure_file::check_dir_chain`] has already confined to root and
/// the service's own uid -- but the check is cheap, and it turns a race
/// into a detection.)
///
/// Only a missing `<mount>/<service>` is `NotFound`, meaning "nothing
/// provisioned"; every other failure means "something is there and it is
/// not acceptable", or "this couldn't be checked".
fn open_secret_within_mount(mount: &Path, service: &str) -> std::io::Result<File> {
    use std::io::{Error as IoError, ErrorKind};

    // Only a missing `<mount>/<service>` may come back as `NotFound`; that
    // is the one failure the chain reads as "not provisioned here". A mount
    // that vanished, or a check that couldn't be carried out, is not a
    // statement about this service and must not look like one.
    let mount_real = std::fs::canonicalize(mount)
        .map_err(|e| IoError::new(ErrorKind::PermissionDenied, format!("secret mount {}: {e}", mount.display())))?;
    // A mount others can write to would let them plant a KEK for a service
    // not provisioned yet -- which `create_kek` would then adopt, leaving
    // them holding the key to everything wrapped under it. The service's
    // own uid may own it: that uid can read every KEK here anyway.
    crate::secure_file::check_dir_chain(&mount_real, Owner::RootOrCurrentUser)?;
    let target_real = std::fs::canonicalize(mount.join(service))?; // NotFound if nothing is provisioned; follows a symlink chain

    if !target_real.starts_with(&mount_real) {
        // Component-wise comparison, so `<mount>-evil/x` does not pass for `<mount>`.
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            format!("resolves to {}, outside the secret mount", target_real.display()),
        ));
    }
    // And every directory between the mount and the file (Kubernetes'
    // `..<timestamp>/`), so nothing under the mount can be swapped either.
    if let Some(target_dir) = target_real.parent() {
        crate::secure_file::check_dir_chain(target_dir, Owner::RootOrCurrentUser)?;
    }

    let file = open_checked(&target_real, &SECRET_FILE_REQUIREMENTS).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            IoError::new(ErrorKind::PermissionDenied, "changed to a symlink between resolution and open")
        } else {
            e
        }
    })?;

    crate::secure_file::verify_opened(&file, &target_real, &mount_real, Path::new("/proc"))?;
    Ok(file)
}

// Accepts a 32-byte raw scalar, a PKCS#8 DER key, or a SEC1 DER
// (`ECPrivateKey`) key, since different provisioning tools produce
// different formats -- `openssl genpkey -outform DER` writes SEC1. Both DER
// forms must name the P-256 curve when they name one at all; a key for
// any other curve is refused.
fn parse_secret_key(bytes: &[u8]) -> Result<SecretKey> {
    if bytes.len() == 32 {
        // exactly 32 bytes: treat as a raw big-endian P-256 private scalar
        return SecretKey::from_slice(bytes)
            .map_err(|e| Error::Provider(format!("invalid raw external KEK scalar: {e}")));
    }
    // A DER key: PKCS#8 (a PrivateKeyInfo, whose second field is the
    // algorithm SEQUENCE) or SEC1 (an ECPrivateKey, whose second field is
    // the key OCTET STRING). Errors are reported for the format that was
    // tried last, with the accepted formats named, since a PEM file or a
    // key for the wrong curve is the usual cause.
    SecretKey::from_pkcs8_der(bytes)
        .or_else(|_| SecretKey::from_sec1_der(bytes))
        .map_err(|e| {
            Error::Provider(format!(
                "external secret is not a valid P-256 key (expected 32 raw bytes, PKCS#8 DER or SEC1 DER; PEM must be converted to DER): {e}"
            ))
        })
}

// Picks the secret mount directory: `external_secret.dir` from the policy,
// else the first conventional mount that exists.
//
// A policy that can't be trusted, or a policy-configured directory that
// isn't there, is `Refused`: the administrator said KEKs live there, so
// its absence is an outage (a mount not ready yet), not a reason to hand
// the call to a weaker provider. No conventional mount existing is
// `Absent`.
fn resolve_dir() -> Backend<PathBuf> {
    match crate::policy::external_secret_dir() {
        Ok(Some(dir)) if dir.is_dir() => return Backend::Ready(dir),
        Ok(Some(dir)) => return Backend::Refused(format!("external_secret.dir {} is not a directory", dir.display())),
        Ok(None) => {}
        Err(e) => return Backend::Refused(e.to_string()),
    }
    CANDIDATE_MOUNTS
        .iter()
        .map(Path::new)
        .find(|p| p.is_dir()) // first one that actually exists on this host
        .map_or(Backend::Absent, |p| Backend::Ready(p.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*; // bring `ExternalSecretProvider` etc. into scope
    use p256::elliptic_curve::Generate as _; // `SecretKey::generate()`, from the OS CSPRNG
    use elliptic_curve::pkcs8::EncodePrivateKey; // lets the test encode a key to PKCS#8 DER for the "provisioned" fixture
    use serial_test::serial; // these tests mutate a shared env var, so they must not run concurrently
    use std::os::unix::fs::PermissionsExt;

    // Runs `f` against a provider pointed at a fresh temp directory acting
    // as the "mounted secret" location.
    fn with_dir<F: FnOnce(&ExternalSecretProvider, &Path)>(f: F) {
        let dir = crate::secure_file::private_tempdir();
        let _secret_mount = crate::policy::test_support::secret_mount(dir.path());
        let provider = ExternalSecretProvider::new();
        f(&provider, dir.path());
    }

    // Writes a secret file the way a correctly configured platform would:
    // owner-only. `std::fs::write` alone inherits the umask (usually
    // 0644), which the provider refuses.
    fn provision(dir: &Path, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes.as_ref()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[test]
    #[serial]
    fn declines_when_no_secret_provisioned() {
        with_dir(|provider, _dir| {
            // no file has been written into the temp dir, so this must decline, not error or succeed
            match provider.load_kek("com.company.orders", true) {
                Err(Error::KeyNotProvisioned(_)) => {}
                Err(other) => panic!("expected KeyNotProvisioned, got {other:?}"),
                Ok(_) => panic!("expected KeyNotProvisioned, got Ok"),
            }
        });
    }

    #[test]
    #[serial]
    fn kek_exists_reflects_the_mounted_file_and_create_if_missing_is_ignored() {
        with_dir(|provider, dir| {
            assert!(!provider.kek_exists("com.company.orders").unwrap());
            // Even with create_if_missing = true, this provider never
            // creates one -- it can only ever load what's already mounted.
            assert!(matches!(
                provider.load_kek("com.company.orders", true),
                Err(Error::KeyNotProvisioned(_))
            ));

            let secret_key = SecretKey::generate();
            provision(dir, "com.company.orders", secret_key.to_bytes()); // simulate an operator provisioning it externally

            assert!(provider.kek_exists("com.company.orders").unwrap());
            provider.load_kek("com.company.orders", false).unwrap(); // now loads fine
        });
    }

    #[test]
    #[serial]
    fn refuses_dot_names_even_when_a_file_exists_there() {
        with_dir(|provider, dir| {
            // A real, valid key sitting at a hidden-file name in the
            // mount: reachable as a path, but the provider must still
            // refuse the name rather than load it.
            let secret_key = SecretKey::generate();
            provision(dir, ".hidden", secret_key.to_bytes());

            for bad in [".hidden", ".", "..", "...", "com..orders", ""] {
                assert!(!provider.kek_exists(bad).unwrap(), "kek_exists must be false for {bad:?}");
                match provider.load_kek(bad, false) {
                    Err(Error::Provider(msg)) => assert!(msg.contains("cannot be used"), "{bad:?}: {msg}"),
                    Err(other) => panic!("{bad:?}: expected Provider error, got {other:?}"),
                    Ok(_) => panic!("{bad:?}: must not load"),
                }
            }
        });
    }

    #[test]
    #[serial]
    fn follows_kubernetes_style_symlinks_within_the_mount() {
        // A Kubernetes Secret volume lays out every key as
        //   <mount>/<key>  ->  ..data/<key>
        //   <mount>/..data ->  ..<timestamp>/        (a real directory)
        // so that updates can swap `..data` atomically. Both hops stay
        // inside the mount, so they must be followed. (On macOS the temp
        // dir itself lives under a symlink, /var -> /private/var, which
        // also exercises the mount-side canonicalization.)
        with_dir(|provider, dir| {
            let versioned = dir.join("..2026_09_28_00_00_00.000000000");
            std::fs::create_dir(&versioned).unwrap();
            std::fs::set_permissions(&versioned, std::fs::Permissions::from_mode(0o755)).unwrap(); // as kubelet makes it, whatever the umask
            let key = SecretKey::generate();
            provision(&versioned, "com.company.orders", key.to_bytes());
            std::os::unix::fs::symlink(&versioned, dir.join("..data")).unwrap();
            std::os::unix::fs::symlink(
                Path::new("..data").join("com.company.orders"),
                dir.join("com.company.orders"),
            )
            .unwrap();

            assert!(provider.kek_exists("com.company.orders").unwrap());
            let handle = provider.load_kek("com.company.orders", false).unwrap();
            assert_eq!(handle.public_key().unwrap(), key.public_key());
        });
    }

    #[test]
    #[serial]
    fn refuses_a_symlink_that_escapes_the_mount() {
        with_dir(|provider, dir| {
            // A real, correctly-permissioned key file living *outside* the
            // mount directory: it would pass every per-file check, so the
            // containment rule is the only thing standing between a
            // planted link and an attacker-chosen KEK.
            let outside = crate::secure_file::private_tempdir();
            let secret_key = SecretKey::generate();
            let real_path = provision(outside.path(), "real-secret", secret_key.to_bytes());
            std::os::unix::fs::symlink(&real_path, dir.join("com.company.orders")).unwrap();

            match provider.load_kek("com.company.orders", true) {
                Err(Error::Provider(msg)) => assert!(msg.contains("outside"), "unexpected message: {msg}"),
                Err(other) => panic!("expected Provider(..outside..), got {other:?}"),
                Ok(_) => panic!("must not load a key from outside the mount"),
            }
            // And kek_exists reports the misconfiguration, not "absent".
            assert!(provider.kek_exists("com.company.orders").is_err());
        });
    }

    #[test]
    #[serial]
    fn refuses_group_or_world_accessible_files_as_errors_not_absence() {
        with_dir(|provider, dir| {
            let secret_key = SecretKey::generate();
            let path = provision(dir, "com.company.orders", secret_key.to_bytes());

            // Group read is allowed only on a root-owned file, and the
            // fixture is owned by whoever runs the tests.
            // SAFETY: geteuid has no preconditions.
            let root_owned = unsafe { libc::geteuid() } == 0;
            let group_read: &[u32] = if root_owned { &[] } else { &[0o640, 0o440] };
            for &mode in [0o644u32, 0o604, 0o660, 0o444].iter().chain(group_read) {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
                match provider.load_kek("com.company.orders", true) {
                    Err(Error::Provider(msg)) => assert!(msg.contains("permissions"), "mode {mode:o}: {msg}"),
                    Err(other) => panic!("mode {mode:o}: expected Provider(..permissions..), got {other:?}"),
                    Ok(_) => panic!("mode {mode:o}: a group/world-accessible KEK must be refused"),
                }
                assert!(
                    provider.kek_exists("com.company.orders").is_err(),
                    "mode {mode:o}: kek_exists must surface the misconfiguration, not report absence"
                );
            }

            // Owner-only modes are accepted, and root:<group> 0440 / 0640.
            let group_read: &[u32] = if root_owned { &[0o640, 0o440] } else { &[] };
            for &mode in [0o600u32, 0o400].iter().chain(group_read) {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
                assert!(provider.kek_exists("com.company.orders").unwrap(), "mode {mode:o}");
                provider.load_kek("com.company.orders", true).unwrap();
            }
        });
    }

    #[test]
    fn opened_file_is_verified_without_proc() {
        // `/proc` masked or not mounted: the descriptor is still checked,
        // by device and inode, and a failure is never `NotFound` (which
        // the chain would read as "not provisioned").
        let mount = crate::secure_file::private_tempdir();
        let mount_real = std::fs::canonicalize(mount.path()).unwrap();
        let no_proc = mount_real.join("no-proc-here");
        let a = provision(&mount_real, "a", [1u8; 32]);
        let b = provision(&mount_real, "b", [2u8; 32]);

        let file_a = File::open(&a).unwrap();
        crate::secure_file::verify_opened(&file_a, &a, &mount_real, &no_proc).expect("the opened file is the resolved one");

        let err = crate::secure_file::verify_opened(&file_a, &b, &mount_real, &no_proc).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "a mismatch is a refusal");

        std::fs::remove_file(&a).unwrap();
        let err = crate::secure_file::verify_opened(&file_a, &a, &mount_real, &no_proc).unwrap_err();
        assert_ne!(err.kind(), std::io::ErrorKind::NotFound, "must never read as 'not provisioned'");
    }

    #[test]
    #[serial]
    fn refuses_a_writable_directory_inside_the_mount() {
        with_dir(|provider, dir| {
            // Kubernetes-style `..data/<key>`, but with the inner directory
            // writable by others: they could swap the key underneath.
            let inner = dir.join("..2026_10_01");
            std::fs::create_dir(&inner).unwrap();
            provision(&inner, "com.company.orders", SecretKey::generate().to_bytes());
            std::os::unix::fs::symlink("..2026_10_01/com.company.orders", dir.join("com.company.orders")).unwrap();

            std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).unwrap();
            provider.load_kek("com.company.orders", false).unwrap();

            std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o777)).unwrap();
            assert!(matches!(provider.load_kek("com.company.orders", false), Err(Error::Provider(_))));
            assert!(provider.kek_exists("com.company.orders").is_err());
            std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).unwrap();
        });
    }

    #[test]
    #[serial]
    fn refuses_a_mount_others_can_write_to() {
        with_dir(|provider, dir| {
            let secret_key = SecretKey::generate();
            provision(dir, "com.company.orders", secret_key.to_bytes());
            provider.load_kek("com.company.orders", false).unwrap();

            for mode in [0o777u32, 0o770, 0o1777] {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
                match provider.load_kek("com.company.orders", false) {
                    Err(Error::Provider(msg)) => assert!(msg.contains("writable by group or others"), "mode {mode:o}: {msg}"),
                    Err(other) => panic!("mode {mode:o}: expected Provider(..writable..), got {other:?}"),
                    Ok(_) => panic!("mode {mode:o}: a KEK from a mount others can write to must be refused"),
                }
                assert!(provider.kek_exists("com.company.orders").is_err(), "mode {mode:o}: an error, not absence");
            }
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        });
    }

    #[test]
    #[serial]
    fn refuses_a_private_mount_under_a_sticky_ancestor() {
        // A 0700 mount inside a /tmp-style (1777) directory: the layout of
        // `mktemp -d` under /tmp. Refused like any shared directory -- a
        // KEK belongs in a mount nobody else can write to, all the way up.
        let base = crate::secure_file::private_tempdir();
        let mount = base.path().join("secrets");
        std::fs::create_dir(&mount).unwrap();
        std::fs::set_permissions(&mount, std::fs::Permissions::from_mode(0o700)).unwrap();
        provision(&mount, "com.company.orders", SecretKey::generate().to_bytes());
        let _secret_mount = crate::policy::test_support::secret_mount(&mount);
        let provider = ExternalSecretProvider::new();
        provider.load_kek("com.company.orders", false).unwrap();

        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        match provider.load_kek("com.company.orders", false) {
            Err(Error::Provider(msg)) => assert!(msg.contains("sticky"), "says why: {msg}"),
            Err(other) => panic!("expected Provider(..sticky..), got {other:?}"),
            Ok(_) => panic!("a KEK under a sticky, world-writable directory must be refused"),
        }
        assert!(provider.kek_exists("com.company.orders").is_err(), "an error, not absence");
        // Nothing provisioned for this one either: still an error, never "not provisioned".
        assert!(provider.kek_exists("com.company.other").is_err());
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        provider.load_kek("com.company.orders", false).unwrap();
    }

    #[test]
    #[serial]
    fn refuses_a_symlink_target_under_a_sticky_directory_inside_the_mount() {
        with_dir(|provider, dir| {
            // `<key>` -> `..2026_10_02/keys/<key>`, with `..2026_10_02`
            // sticky and world-writable: the directory the file sits in is
            // private, but one above it, inside the mount, is not.
            let shared = dir.join("..2026_10_02");
            let keys = shared.join("keys");
            std::fs::create_dir_all(&keys).unwrap();
            std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700)).unwrap();
            provision(&keys, "com.company.orders", SecretKey::generate().to_bytes());
            std::os::unix::fs::symlink("..2026_10_02/keys/com.company.orders", dir.join("com.company.orders")).unwrap();
            provider.load_kek("com.company.orders", false).unwrap();

            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
            match provider.load_kek("com.company.orders", false) {
                Err(Error::Provider(msg)) => assert!(msg.contains("sticky"), "says why: {msg}"),
                Err(other) => panic!("expected Provider(..sticky..), got {other:?}"),
                Ok(_) => panic!("a KEK under a sticky directory inside the mount must be refused"),
            }
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700)).unwrap();
        });
    }

    #[test]
    #[serial]
    fn refuses_a_directory_at_the_service_name() {
        with_dir(|provider, dir| {
            std::fs::create_dir(dir.join("com.company.orders")).unwrap();
            assert!(provider.kek_exists("com.company.orders").is_err());
            assert!(matches!(provider.load_kek("com.company.orders", true), Err(Error::Provider(_))));
        });
    }

    #[test]
    #[serial]
    fn different_provisioned_keys_produce_different_public_keys() {
        with_dir(|provider, dir| {
            let key_a = SecretKey::generate();
            let key_b = SecretKey::generate();
            provision(dir, "com.company.orders", key_a.to_bytes());
            provision(dir, "com.company.billing", key_b.to_bytes());

            let handle_a = provider.load_kek("com.company.orders", true).unwrap();
            let handle_b = provider.load_kek("com.company.billing", true).unwrap();

            let public_a = handle_a.public_key().unwrap();
            let public_b = handle_b.public_key().unwrap();

            // Each handle's reported public key must match its own
            // provisioned secret, not just differ from the other one --
            // guards against a regression where public_key() returns a
            // stale, cached, or otherwise-mismatched value.
            assert_eq!(public_a, key_a.public_key());
            assert_eq!(public_b, key_b.public_key());
            assert_ne!(public_a, public_b, "different provisioned keys must produce different public keys");
        });
    }

    // An ECPrivateKey (SEC1 DER) exactly as `openssl genpkey -algorithm EC
    // -pkeyopt ec_paramgen_curve:P-256 -outform DER` writes it: version 1,
    // the 32-byte key, the prime256v1 OID, and the public point, which is
    // the last 65 bytes. A throwaway test key.
    const OPENSSL_P256_SEC1_DER: &str = "30770201010420ea598655faab80ea2ed2b41d232b0e2ed6291ec86ee54ea2da6fb704ff2d77f9a00a06082a8648ce3d030107a1440342000418d2afa00d9d7ffb1f6514ff3b303b6c4b2b95f5b150b03e56a086f9f5d021f02d0fc482189427a10597d3a4e0b673d364d9a95915c0c3d05b389adc3ea0ffae";
    // The same, for P-384 (secp384r1). A throwaway test key.
    const OPENSSL_P384_SEC1_DER: &str = "3081a402010104301b8239a974c78597128424d8e0704b918c2191efe564110956c8f536b337de8c3255811434aaee8eed4d1b0cbf1dc1c9a00706052b81040022a16403620004e32b45d36c8cf4ac83aa5d3386fca1291f5892e079c687ac3c00a3b91d399057d308d7272f4eaf709412526ca7a131944e32bcb119dad9b4ca0effd743845860b040018c325b9e4ecda3fca57c502d702115507c25d577c03198e8d0c8c719b3";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    #[serial]
    fn loads_an_openssl_sec1_secret() {
        use elliptic_curve::sec1::ToSec1Point;
        with_dir(|provider, dir| {
            let der = unhex(OPENSSL_P256_SEC1_DER);
            provision(dir, "com.company.orders", &der);

            assert!(provider.kek_exists("com.company.orders").unwrap());
            let handle = provider.load_kek("com.company.orders", false).unwrap();
            // The key loaded is the one in the file: its public point is the
            // one OpenSSL embedded alongside it.
            let public = handle.public_key().unwrap().to_sec1_point(false);
            assert_eq!(public.as_bytes(), &der[der.len() - 65..]);
        });
    }

    #[test]
    #[serial]
    fn refuses_a_sec1_key_for_another_curve() {
        with_dir(|provider, dir| {
            provision(dir, "com.company.orders", unhex(OPENSSL_P384_SEC1_DER));
            let err = provider.kek_exists("com.company.orders").unwrap_err();
            assert!(err.to_string().contains("not a valid P-256 key"), "{err}");
            assert!(matches!(provider.load_kek("com.company.orders", false), Err(Error::Provider(_))));
        });
    }

    #[test]
    #[serial]
    fn an_unparseable_secret_is_an_error_at_provisioning_not_a_kek() {
        // kek_exists is what `provision` asks; it must not report a key
        // the first wrap would then reject.
        with_dir(|provider, dir| {
            provision(dir, "com.company.orders", b"-----BEGIN EC PRIVATE KEY-----\nnot DER\n");
            let err = provider.kek_exists("com.company.orders").unwrap_err();
            assert!(err.to_string().contains("PEM must be converted to DER"), "{err}");
            assert!(matches!(provider.load_kek("com.company.orders", true), Err(Error::Provider(_))));
        });
    }

    #[test]
    #[serial]
    fn loads_provisioned_pkcs8_secret() {
        with_dir(|provider, dir| {
            let secret_key = SecretKey::generate(); // simulate an operator-provisioned key
            let der = secret_key.to_pkcs8_der().unwrap();
            provision(dir, "com.company.orders", der.as_bytes()); // "provision" it as a mounted file

            let handle = provider.load_kek("com.company.orders", true).unwrap();
            let peer_key = SecretKey::generate(); // stand-in peer key
            let expected = p256::ecdh::diffie_hellman(
                secret_key.to_nonzero_scalar(),
                peer_key.public_key().as_affine(),
            ); // compute the expected shared secret directly, independent of the provider
            let actual = handle.ecdh(&peer_key.public_key()).unwrap();
            assert_eq!(actual.as_slice(), expected.raw_secret_bytes().as_slice()); // provider's result must match
        });
    }

    #[test]
    #[serial]
    fn loads_provisioned_raw_scalar_secret() {
        with_dir(|provider, dir| {
            let secret_key = SecretKey::generate();
            provision(dir, "com.company.orders", secret_key.to_bytes()); // provision as raw 32-byte scalar this time

            let handle = provider.load_kek("com.company.orders", true).unwrap();
            let peer_key = SecretKey::generate();
            let expected = p256::ecdh::diffie_hellman(
                secret_key.to_nonzero_scalar(),
                peer_key.public_key().as_affine(),
            );
            let actual = handle.ecdh(&peer_key.public_key()).unwrap();
            assert_eq!(actual.as_slice(), expected.raw_secret_bytes().as_slice());
            // Since we provisioned the file ourselves, we independently
            // know the exact key -- `public_key()` must report that same
            // key, not some other/derived value.
            assert_eq!(handle.public_key().unwrap(), secret_key.public_key());
        });
    }

    #[test]
    #[serial]
    fn the_policy_dir_is_used_with_no_fallback() {
        use crate::policy::test_support::{secret_mount, TestPolicy};
        let mount = crate::secure_file::private_tempdir();
        {
            let _policy = secret_mount(mount.path());
            assert_eq!(resolve_dir(), Backend::Ready(mount.path().to_path_buf()));
        }

        // A configured directory that doesn't exist: refused -- an outage of
        // the provider the administrator chose, never a fallback to the
        // conventional mounts or the next provider.
        {
            let _policy = secret_mount(Path::new("/nonexistent-hkdfguard-mount"));
            assert!(matches!(resolve_dir(), Backend::Refused(_)));
        }

        // A broken policy: refused, not a fallback to the search.
        {
            let _policy = TestPolicy::exact("[selection]\nmode = \"require\"\n");
            assert!(matches!(resolve_dir(), Backend::Refused(_)));
        }

        // Only no mount configured, and none of the conventional ones
        // present, means "not here".
        let _policy = TestPolicy::absent();
        if !CANDIDATE_MOUNTS.iter().any(|m| Path::new(m).is_dir()) {
            assert_eq!(resolve_dir(), Backend::Absent);
        }
    }

    fn fingerprint_hex(key: &SecretKey) -> String {
        hex(&kek_fingerprint(&key.public_key()))
    }

    // Layers `[external_secret.pinned_keys]` / `require_pinned_keys` over
    // the mount `with_dir` configured.
    fn pin_policy(require: bool, pins: &str) -> crate::policy::test_support::TestPolicy {
        crate::policy::test_support::TestPolicy::write(&format!(
            "[external_secret]\nrequire_pinned_keys = {require}\n[external_secret.pinned_keys]\n{pins}\n"
        ))
    }

    #[test]
    #[serial]
    fn a_pinned_key_loads_and_any_other_key_is_refused() {
        with_dir(|provider, dir| {
            let real = SecretKey::generate();
            let _policy = pin_policy(false, &format!("\"com.company.orders\" = \"{}\"", fingerprint_hex(&real)));

            provision(dir, "com.company.orders", real.to_bytes());
            assert!(provider.kek_exists("com.company.orders").unwrap());
            let handle = provider.load_kek("com.company.orders", false).unwrap();
            assert_eq!(handle.public_key().unwrap(), real.public_key());

            // A well-formed key, correctly owned and moded -- what a writer
            // sharing the volume could mount first -- is still refused, and
            // as an error, so the chain doesn't move on to another provider.
            let planted = SecretKey::generate();
            provision(dir, "com.company.orders", planted.to_bytes());
            for create_if_missing in [false, true] {
                match provider.load_kek("com.company.orders", create_if_missing) {
                    Err(Error::Provider(msg)) => {
                        assert!(msg.contains("not the one pinned"), "{msg}");
                        assert!(msg.contains(&fingerprint_hex(&planted)), "names the key it found: {msg}");
                    }
                    Err(other) => panic!("expected Provider(..pinned..), got {other:?}"),
                    Ok(_) => panic!("a key that isn't the pinned one must be refused"),
                }
            }
            assert!(provider.kek_exists("com.company.orders").is_err(), "an error, not absence");

            // Pins are per service: an unpinned one is unaffected without the allowlist.
            provision(dir, "com.company.billing", planted.to_bytes());
            provider.load_kek("com.company.billing", false).unwrap();
        });
    }

    #[test]
    #[serial]
    fn a_list_of_pins_accepts_either_key_during_a_rotation() {
        with_dir(|provider, dir| {
            let old = SecretKey::generate();
            let new = SecretKey::generate();
            let _policy = pin_policy(
                true,
                &format!("\"com.company.orders\" = [\"{}\", \"{}\"]", fingerprint_hex(&old), fingerprint_hex(&new)),
            );
            for key in [&old, &new] {
                provision(dir, "com.company.orders", key.to_bytes());
                assert_eq!(provider.load_kek("com.company.orders", false).unwrap().public_key().unwrap(), key.public_key());
            }
            provision(dir, "com.company.orders", SecretKey::generate().to_bytes());
            assert!(matches!(provider.load_kek("com.company.orders", false), Err(Error::Provider(_))));
        });
    }

    #[test]
    #[serial]
    fn require_pinned_keys_serves_only_pinned_services_and_reports_the_pin_to_add() {
        with_dir(|provider, dir| {
            let pinned = SecretKey::generate();
            let unpinned = SecretKey::generate();
            let _policy = pin_policy(true, &format!("\"com.company.orders\" = \"{}\"", fingerprint_hex(&pinned)));
            provision(dir, "com.company.orders", pinned.to_bytes());
            provision(dir, "com.company.billing", unpinned.to_bytes());

            provider.load_kek("com.company.orders", false).unwrap();

            // Mounted but unpinned: no KEK here, for a load...
            assert!(!provider.kek_exists("com.company.billing").unwrap());
            assert!(matches!(provider.load_kek("com.company.billing", false), Err(Error::KeyNotProvisioned(_))));
            // ...and, for `provision`, the line that would pin the mounted key.
            match provider.load_kek("com.company.billing", true) {
                Err(Error::Provider(msg)) => assert!(
                    msg.contains(&format!("\"com.company.billing\" = \"{}\"", fingerprint_hex(&unpinned))),
                    "paste-ready pin: {msg}"
                ),
                Err(other) => panic!("expected Provider(..instructions..), got {other:?}"),
                Ok(_) => panic!("an unpinned service must not load under require_pinned_keys"),
            }
            // Nothing mounted at all: the ordinary decline, even when provisioning.
            assert!(matches!(provider.load_kek("com.company.other", true), Err(Error::KeyNotProvisioned(_))));
        });
    }

    #[test]
    #[serial]
    fn the_fingerprint_is_sha256_of_the_uncompressed_public_point() {
        // What the documented OpenSSL pipeline computes:
        //   openssl pkey -inform DER -pubout -outform DER | tail -c 65 | sha256sum
        // The SEC1 DER below ends with that same 65-byte point.
        use sha2::{Digest, Sha256};
        with_dir(|provider, dir| {
            let der = unhex(OPENSSL_P256_SEC1_DER);
            let expected = hex(&Sha256::digest(&der[der.len() - 65..]));
            let _policy = pin_policy(true, &format!("\"com.company.orders\" = \"{expected}\""));
            provision(dir, "com.company.orders", &der);
            provider.load_kek("com.company.orders", false).unwrap();
        });
    }

    #[test]
    #[serial]
    fn a_broken_policy_refuses_rather_than_dropping_the_pins() {
        let mount = crate::secure_file::private_tempdir();
        provision(mount.path(), "com.company.orders", SecretKey::generate().to_bytes());
        let _secret_mount = crate::policy::test_support::secret_mount(mount.path());
        let provider = ExternalSecretProvider::new();
        // Read per call, so a policy that breaks after construction must
        // still stop the pin check from being skipped.
        let _broken = crate::policy::test_support::TestPolicy::exact("[selection]\nmode = \"require\"\n");
        assert!(provider.kek_exists("com.company.orders").is_err());
        assert!(matches!(provider.load_kek("com.company.orders", false), Err(Error::Policy(_))));
    }

    #[test]
    #[serial]
    fn probe_and_provider_type() {
        with_dir(|provider, _dir| {
            assert!(provider.probe());
            assert_eq!(provider.provider_type(), ProviderType::ExternalSecret);
        });

        let provider = ExternalSecretProvider::new();
        assert!(!provider.probe());
    }

    #[test]
    #[serial]
    fn key_id_format() {
        with_dir(|provider, dir| {
            let secret_key = SecretKey::generate();
            provision(dir, "com.company.orders", secret_key.to_bytes());

            let handle = provider.load_kek("com.company.orders", true).unwrap();
            assert_eq!(handle.key_id(), b"external:com.company.orders");
        });
    }

    #[test]
    #[serial]
    fn rejects_corrupted_secret_file() {
        with_dir(|provider, dir| {
            // A corrupt 32-byte scalar (all zeros is not a valid P-256 scalar).
            provision(dir, "com.company.orders", [0u8; 32]);
            let res = provider.load_kek("com.company.orders", true);
            assert!(matches!(res, Err(Error::Provider(_))));

            // Garbage of a non-32 length, which fails PKCS#8 parsing.
            provision(dir, "com.company.billing", b"invalid-pkcs8-data");
            let res2 = provider.load_kek("com.company.billing", true);
            assert!(matches!(res2, Err(Error::Provider(_))));
        });
    }
}

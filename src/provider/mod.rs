//! Provider abstraction, the priority-ordered selection chain, and the
//! optional provider allow-list policy.
//!
//! Every provider implements the identical keyed-PRF -> AES-256-GCM
//! protocol (see `crypto.rs`); the only thing that differs between providers
//! is *where the persistent HMAC-SHA-256 KEK lives* and *who computes the
//! HMAC*. PKCS#11/TPM2 providers never hand the key back to this crate --
//! `prf()` returns only HMAC outputs.
//!
//! There is deliberately no software-backed (locally-generated,
//! filesystem-encrypted-at-rest) provider: a deployment without TPM2 or
//! PKCS#11 hardware is expected to provision a KEK via the external-secret
//! provider instead. Ephemeral (in-memory, lost on restart) is never used
//! unless a policy file explicitly allows it -- see [`allowed_chain`].
//!
//! Providers never auto-create a KEK on wrap/unwrap: `wrap` calls
//! [`select_existing`], which only *loads* an already-created KEK and fails
//! with [`crate::error::Error::KekNotFound`] if none exists yet; a KEK is
//! created only via the explicit [`create_kek`] (the `hkdfguard_create_kek`
//! C entry point). [`kek_exists`] answers "would `select_existing` succeed"
//! without creating anything. TPM2 is the one exception -- see its own
//! `kek_exists`/`load_kek` doc comments for why.
//!
//! The "allow-list" is the full administrative policy engine in
//! `crate::policy` (`/etc/hkdfguard/policy.toml`) -- see [`allowed_chain`],
//! the sole point where every provider-selection function below crosses
//! from "what's compiled into this build" to "what policy currently
//! allows, and in what order."

// Each provider module is only compiled in when its feature is enabled, so
// a build with e.g. `tpm2` disabled never even sees TPM-related code.
#[cfg(feature = "ephemeral")]
pub mod ephemeral;
#[cfg(feature = "external-secret")]
pub mod external_secret;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;
#[cfg(feature = "tpm2")]
pub mod tpm2;
// The TPM provider's key file format. Pure Rust, so its tests run in every
// build, not only those with the tpm2 feature.
// Also in the fuzz harnesses' build (`hkdfguard_test_paths`), which fuzzes
// it through `crate::fuzz_support` without linking tpm2-tss.
#[cfg(any(feature = "tpm2", test, hkdfguard_test_paths))]
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) mod tpm_key_file;

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::policy::PolicyEvaluator; // brings `.allowed_providers()` into scope on `crate::policy::Policy`
use std::sync::{Arc, OnceLock}; // `Arc` for shared provider ownership, `OnceLock` for the one-time warning flag
use zeroize::Zeroizing; // wrapper that scrubs its contents from memory when dropped

/// Length of a KEK held in software (the external-secret and ephemeral
/// providers), and of every key a provider generates: 256 bits, the
/// HMAC-SHA-256 output size.
#[cfg_attr(not(any(feature = "tpm2", feature = "pkcs11", feature = "external-secret", feature = "ephemeral")), allow(dead_code))]
pub const KEK_LEN: usize = 32;

/// One HMAC-SHA-256 output under a KEK, zeroized on drop. Never logged,
/// never returned across the FFI boundary.
pub type PrfOutput = Zeroizing<[u8; 32]>;

/// A fresh random key of the size providers use, as an operator would
/// provision an external secret.
#[cfg(test)]
pub(crate) fn random_kek_for_tests() -> [u8; KEK_LEN] {
    let mut key = [0u8; KEK_LEN];
    getrandom::fill(&mut key).unwrap();
    key
}

/// HMAC-SHA-256 with a key this process holds in software (the
/// external-secret and ephemeral providers). The HMAC pad blocks `hmac`
/// derives from the key are beyond this crate's reach (`hmac` 0.13 has no
/// zeroize support); the SHA-256 states keyed with them are wiped on drop
/// by `sha2`'s `zeroize` feature.
// Also the TPM provider's: its self-test checks TPM2_HMAC against it.
#[cfg(any(feature = "external-secret", feature = "ephemeral", feature = "tpm2", test))]
pub(crate) fn software_prf(key: &[u8; KEK_LEN], inputs: &[&[u8]]) -> Vec<PrfOutput> {
    use hmac::{Hmac, KeyInit, Mac};
    collect_outputs(inputs, |input| {
        let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(input);
        let mut out = PrfOutput::new([0u8; 32]);
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(out)
    })
    .expect("software HMAC cannot fail")
}

/// One PRF output per input, from `one`, in a `Vec` allocated once at its
/// final size -- what [`KekHandle::prf`] promises. Collecting an iterator
/// of `Result`s gives no such guarantee: it can't know the length up
/// front, so the `Vec` grows as it goes, and each growth frees a buffer
/// with outputs still in it. Stops at the first error; the outputs so far
/// are zeroed as the `Vec` drops.
#[cfg(any(feature = "external-secret", feature = "ephemeral", feature = "tpm2", feature = "pkcs11", test))]
pub(crate) fn collect_outputs(inputs: &[&[u8]], mut one: impl FnMut(&[u8]) -> Result<PrfOutput>) -> Result<Vec<PrfOutput>> {
    let mut outputs = Vec::with_capacity(inputs.len());
    for input in inputs {
        outputs.push(one(input)?);
    }
    Ok(outputs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] // cheap to copy/compare/hash; needed for logging, matching, and use as a map-ish key
#[repr(u8)] // pins the enum's in-memory representation to a single byte, matching the wire format's provider tag
pub enum ProviderType {
    Tpm2 = 1,           // matches payload byte value 1
    Pkcs11 = 2,          // matches payload byte value 2
    ExternalSecret = 3, // matches payload byte value 3
    // 4 is unassigned and rejected by `from_u8` as an unknown tag. Never
    // assign it or renumber onto it, so a payload carrying tag 4 is
    // rejected outright rather than misinterpreted as some provider 4.
    Ephemeral = 5,       // matches payload byte value 5
}

impl ProviderType {
    // Converts a raw wire-format byte back into the enum, rejecting
    // anything outside the currently defined values (byte 4 included --
    // see the note on tag 4 in `ProviderType`).
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ProviderType::Tpm2),
            2 => Some(ProviderType::Pkcs11),
            3 => Some(ProviderType::ExternalSecret),
            5 => Some(ProviderType::Ephemeral),
            _ => None, // any other byte value (including the unassigned 4) is not a valid provider tag
        }
    }

    // Human-readable name used only in log messages (the administrative
    // policy file has its own, distinct vocabulary -- see `crate::policy`).
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderType::Tpm2 => "TPM2",
            ProviderType::Pkcs11 => "PKCS11",
            ProviderType::ExternalSecret => "EXTERNAL_SECRET",
            ProviderType::Ephemeral => "EPHEMERAL",
        }
    }
}

/// What a provider found when it was constructed. The distinction between
/// the last two is what keeps the chain fail-closed: only an `Absent`
/// provider lets the chain move on to the next (usually weaker) one.
#[cfg_attr(not(any(feature = "tpm2", feature = "pkcs11", feature = "external-secret")), allow(dead_code))]
#[derive(Debug, PartialEq)]
pub(crate) enum Backend<T> {
    /// Connected and usable.
    Ready(T),
    /// Not on this host, or not configured for use here (no TPM device we
    /// can open, no PKCS#11 module or PIN file, no secret mount). The provider takes no part in the chain.
    Absent,
    /// There and configured, but unusable or untrustworthy: a secret with
    /// the wrong owner or mode, a TPM that fails its self-test, a module
    /// that won't load, a token that can't be selected. Every call that
    /// reaches this provider fails with this reason, rather than quietly
    /// falling through to a weaker provider -- a misconfiguration or outage
    /// of the strong provider must not silently turn into new DEKs wrapped
    /// under a weak (or, with Ephemeral, a lost-on-restart) KEK.
    Refused(String),
}

/// A handle to a loaded persistent service KEK. The key never leaves the
/// provider that produced this handle -- only [`KekHandle::prf`]'s
/// *outputs* cross back into `crypto.rs`.
pub trait KekHandle {
    /// Provider-specific opaque identifier for this KEK, recorded (not
    /// secret) in the wrapped payload for diagnostics and provider
    /// migration detection. Never used as the sole lookup key -- the
    /// `service` string is always the logical identity.
    fn key_id(&self) -> &[u8]; // borrowed, non-secret bytes to embed in the payload

    /// HMAC-SHA-256 under this KEK of each of `inputs`, in order, in one
    /// session with the device: a wrap or unwrap needs two outputs (the
    /// KEK fingerprint and the wrapping key, see `crypto.rs`), and on a
    /// TPM each session costs a key load. Each input is one SP 800-108
    /// block, at most [`crate::crypto::MAX_PRF_INPUT_LEN`] bytes. Never
    /// exposes the key itself.
    ///
    /// The `Vec` is allocated once, at its final size, and never grown: a
    /// reallocation would free the old buffer with outputs still in it.
    /// Callers read the outputs in place and let the `Vec` drop, which
    /// zeroes each one where it sits (see `crypto::derive_keys`).
    fn prf(&self, inputs: &[&[u8]]) -> Result<Vec<PrfOutput>>;
}

// `Send + Sync` because providers are shared across calls via `Arc` and
// must be safe to use from whatever thread the FFI caller is on.
pub trait KekProvider: Send + Sync {
    fn provider_type(&self) -> ProviderType; // which of the 5 tags this provider implements

    /// Cheap, side-effect-free check: is this provider present on this
    /// host -- ready, or there but refused ([`Backend::Refused`])? Only a
    /// `false` here lets the chain skip the provider; a refused provider
    /// reports `true` and fails `kek_exists`/`load_kek` with its reason.
    /// Must not create or persist anything.
    fn probe(&self) -> bool;

    /// For a provider that is not present (`probe()` is false): `Err` if
    /// `service` is nonetheless known to keep its KEK here -- a TPM key
    /// file on a host whose TPM device has gone, an external secret that
    /// policy pins but nothing mounts. The chain then stops with that error
    /// instead of skipping the provider: the key's home disappearing is an
    /// outage, and treating it as "never there" would hand every new wrap
    /// to a weaker provider. `Ok` when nothing ties the service to this
    /// provider. Must not create or persist anything.
    fn claims_while_absent(&self, service: &str) -> Result<()> {
        let _ = service;
        Ok(())
    }

    /// Whether a persistent KEK already exists for `service`, without
    /// creating one. Must be side-effect-free.
    fn kek_exists(&self, service: &str) -> Result<bool>;

    /// Loads the persistent KEK for `service`. If `create_if_missing` is
    /// `true`, generates and persists one first when none exists yet
    /// (idempotent if one already does). If `false`, fails with
    /// [`Error::KeyNotProvisioned`] when none exists rather than creating
    /// one.
    fn load_kek(&self, service: &str, create_if_missing: bool) -> Result<Box<dyn KekHandle>>; // `Box<dyn _>` since each provider returns a different concrete handle type

    /// Permanently deletes this provider's KEK for `service` -- only if the
    /// key it would delete has exactly `expected_fingerprint` (see
    /// `crypto::kek_fingerprint`), computed with the very object deleted.
    /// [`Error::KekNotFound`] if it holds none, and
    /// [`Error::KekFingerprintMismatch`] if it holds a different one.
    ///
    /// Only a provider that stores one key per service can do this (TPM2,
    /// PKCS#11); the default refuses. An external secret belongs to the
    /// platform that mounted it, and an ephemeral KEK ends with its process.
    fn retire_kek(&self, service: &str, expected_fingerprint: &[u8; crate::payload::FINGERPRINT_LEN]) -> Result<()> {
        let _ = (service, expected_fingerprint);
        Err(Error::Provider(format!(
            "{} cannot retire a single service's KEK: {}",
            self.provider_type().as_str(),
            match self.provider_type() {
                ProviderType::Tpm2 => "this build's TPM provider does not implement it",
                ProviderType::ExternalSecret => {
                    "the KEK is a secret the platform provides; remove it there (the Kubernetes Secret, Vault \
                     entry, systemd credential, ...)"
                }
                ProviderType::Ephemeral => "an ephemeral KEK exists only in its process's memory and ends with it",
                ProviderType::Pkcs11 => "this build's PKCS#11 provider does not implement it",
            }
        )))
    }
}

/// Every provider type compiled into this build, in the mandated selection
/// priority order (strongest first). A static list -- nothing is
/// constructed, connected, or logged into here -- so policy can be
/// evaluated against it at zero cost before any provider is built.
#[allow(clippy::vec_init_then_push)] // each push is independently feature-gated
fn compiled_provider_types() -> Vec<ProviderType> {
    #[allow(unused_mut)] // `mut` is only needed when at least one push below is compiled in
    let mut types = Vec::new();

    #[cfg(feature = "tpm2")]
    types.push(ProviderType::Tpm2); // priority 1

    #[cfg(feature = "pkcs11")]
    types.push(ProviderType::Pkcs11); // priority 2

    #[cfg(feature = "external-secret")]
    types.push(ProviderType::ExternalSecret); // priority 3

    #[cfg(feature = "ephemeral")]
    types.push(ProviderType::Ephemeral); // priority 4, and only ever when a policy names it

    types // order of pushes above IS the selection priority order
}

/// Constructs exactly one provider, fresh. This is the expensive step --
/// for TPM2 it opens a TCTI connection, for PKCS#11 it opens a session
/// and logs in -- and it's deliberately done per call and torn down when
/// the returned `Arc` drops: no session, login, or device connection is
/// ever kept alive between calls. That's a deliberate posture, not an
/// oversight: a standing logged-in PKCS#11 session (or, once the TPM key
/// carries an authValue, a standing authorized TPM context) is ambient
/// authority that anything running in this process could use without ever
/// presenting the credential again. Re-authenticating per call costs a
/// connection per wrap/unwrap; callers are expected to cache the
/// *unwrapped DEK* for as long as they need it, not to call in here at
/// high frequency. Returns `None` only for a type not compiled into this
/// build.
///
/// The one thing that does outlive a call is the PKCS#11 *module*: it is
/// loaded and `C_Initialize`d once per process and never finalized, because
/// those two calls act on the whole process, and finalizing while another
/// thread is inside the module is undefined behavior (see
/// `pkcs11::MODULES`). That is a library handle, not authority -- every
/// session and login is still per call.
fn construct_provider(provider_type: ProviderType) -> Option<Arc<dyn KekProvider>> {
    match provider_type {
        #[cfg(feature = "tpm2")]
        ProviderType::Tpm2 => Some(Arc::new(tpm2::Tpm2Provider::new())),
        #[cfg(feature = "pkcs11")]
        ProviderType::Pkcs11 => Some(Arc::new(pkcs11::Pkcs11Provider::new())),
        #[cfg(feature = "external-secret")]
        ProviderType::ExternalSecret => Some(Arc::new(external_secret::ExternalSecretProvider::new())),
        #[cfg(feature = "ephemeral")]
        ProviderType::Ephemeral => Some(Arc::new(ephemeral::EphemeralProvider::new())),
        #[allow(unreachable_patterns)] // only reachable for a type whose feature is compiled out
        _ => None,
    }
}

/// The provider types this process is currently allowed to use, in
/// try-order: the compiled-in list ([`compiled_provider_types`]), filtered
/// down to and reordered by the administrative policy in `crate::policy`
/// (`/etc/hkdfguard/policy.toml`; a test build also reads
/// `HKDFGUARD_POLICY_FILE`) if one is configured. Pure policy evaluation over types -- no provider is
/// constructed here -- so a policy of e.g. `require: external-secret`
/// never causes a TPM connection or an HSM login just to be told no.
/// Every selection/creation/existence-check function below goes through
/// this, so the policy applies uniformly to wrap, unwrap, create, and
/// exists.
///
/// Ephemeral is **excluded** unless a policy explicitly names it (as the
/// sole provider under `require`, or by name in `preferred_order`) -- see
/// `crate::policy::Policy::ephemeral_explicitly_listed`.
/// Its keys live only in process memory, so every DEK wrapped under one is
/// permanently lost on restart; silently falling back to it -- because a
/// secret mount wasn't there yet at startup, or a TPM failed its
/// self-test -- would turn a transient provider outage into permanent
/// data loss.
fn allowed_types() -> Result<Vec<ProviderType>> {
    let compiled = compiled_provider_types();
    // A missing, malformed or self-contradictory policy fails every
    // operation, on purpose (fail closed).
    crate::policy::load()?.allowed_providers(&compiled)
}

/// The policy's first choice of provider (the head of the allowed chain),
/// for the audit trail's "created somewhere else" event (1001). `None` if
/// the policy can't be read -- the call it's for then fails closed anyway.
pub(crate) fn preferred_type() -> Option<ProviderType> {
    allowed_types().ok().and_then(|types| types.first().copied())
}

/// Ensures the "no persistent provider available, running on EPHEMERAL"
/// warning is logged once per process rather than on every wrap call.
static EPHEMERAL_WARNED: OnceLock<()> = OnceLock::new(); // `set()` succeeds exactly once per process; later calls fail harmlessly

/// Warnings already logged by [`warn_once`], by their exact text.
static WARNED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Logs `message` at warn level the first time this process sees it, and
/// never again. For events that are worth an operator's attention but
/// would repeat on every call -- a fallback, a migration hint -- so the
/// log shows each distinct one once instead of flooding. The list of
/// messages seen is bounded: at `audit::ONCE_LIST_LIMIT` it starts over,
/// so a message can then be logged once more.
fn warn_once(message: String) {
    log_once(log::Level::Warn, message);
}

/// [`warn_once`] at any level. Also used by the providers for a refusal
/// reason, which they would otherwise log on every construction -- that
/// is, on every C ABI call -- while the provider stays misconfigured. The
/// C ABI's own per-call failure line still carries the reason each time,
/// so logging it once more here adds nothing after the first.
pub(crate) fn log_once(level: log::Level, message: String) {
    let mut warned = WARNED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if !warned.contains(&message) {
        log::log!(level, "{message}");
        if warned.len() >= crate::audit::ONCE_LIST_LIMIT {
            warned.clear(); // bounded: see `ONCE_LIST_LIMIT`
        }
        warned.push(message);
    }
}

/// Test-only: forget which warnings were logged, so a test can see its own.
/// Gated like its one caller.
#[cfg(all(test, feature = "external-secret", feature = "ephemeral"))]
fn reset_warn_once() {
    WARNED.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
}

/// The provider policy pins `service`'s key in, when `provider_type` is not
/// one of them: `provider_type` then takes no part in any call for the
/// service. `None` when nothing is pinned for the service, or
/// `provider_type` itself holds a pin for it.
///
/// A pin -- `pkcs11.pinned_keys`, `external_secret.pinned_keys`,
/// `tpm.pinned_names` -- is the administrator's statement of where a
/// service's KEK lives. Without this, the chain would still take the first
/// provider in the order that holds *a* key for the service, and a key can
/// appear in a provider the service was never given: whoever can read a
/// shared token's PIN file can generate one there under any service's
/// label; a writer of the secret mount can add a file. Every wrap for the
/// service would then go to that key, which its maker can use, and
/// [`for_unwrap`] would refuse everything wrapped under the real one.
/// The pin in the service's own provider can't catch that -- the chain
/// never gets as far -- so it is caught here, before the other provider is
/// even constructed.
///
/// Only pins in providers the policy allows count: one left behind in a
/// provider since taken out of the order binds nothing. The TPM is never
/// passed over: only root writes its key directory, so a TPM key for a
/// service is one an administrator provisioned.
fn bound_elsewhere(service: &str, provider_type: ProviderType, allowed: &[ProviderType]) -> Result<Option<ProviderType>> {
    if provider_type == ProviderType::Tpm2 {
        return Ok(None);
    }
    let mut elsewhere = None;
    for pinned_in in allowed {
        let pinned = match pinned_in {
            ProviderType::Tpm2 => crate::policy::pinned_tpm_name(service)?.is_some(),
            ProviderType::Pkcs11 => crate::policy::pinned_pkcs11_keys(service)?.is_some(),
            ProviderType::ExternalSecret => crate::policy::pinned_external_keys(service)?.is_some(),
            ProviderType::Ephemeral => false, // nothing to pin: its keys end with their process
        };
        if pinned && *pinned_in == provider_type {
            return Ok(None);
        }
        if pinned && elsewhere.is_none() {
            elsewhere = Some(*pinned_in);
        }
    }
    Ok(elsewhere)
}

/// Shared walk behind [`create_kek`] and [`select_existing`]: for each
/// policy-allowed type in priority order, constructs that one provider
/// (see [`construct_provider`]), probes it, and calls
/// `provider.load_kek(service, create_if_missing(type))`; the first to succeed
/// wins and the walk stops -- providers later in the order are never even
/// constructed.
///
/// A provider is left out of the walk altogether when policy pins this
/// service's key in another one (see [`bound_elsewhere`]). Otherwise the
/// walk moves on past a provider in exactly two cases: it isn't
/// present at all (`probe()` is false -- see [`Backend::Absent`]) and
/// nothing says this service's key lives there
/// ([`KekProvider::claims_while_absent`]), or it is
/// present but has no key for this service ([`Error::KeyNotProvisioned`]).
/// Any other error from a present provider ends the walk and is returned:
/// a TPM, token, or secret mount that is there but failing must not quietly
/// hand the call to a weaker provider, because every DEK wrapped meanwhile
/// would land under that weaker KEK -- or, with Ephemeral, under one that
/// is gone at the next restart. `not_found_err` is returned if the walk
/// runs out of providers after at least one present provider declined;
/// [`Error::NoProviderAvailable`] if none was present at all (see
/// [`nothing_present`]).
///
/// The returned error is logged by the caller (the C ABI layer), not here;
/// an `Error::Provider` is prefixed with the provider's name so that one
/// line still says which provider failed.
fn walk_chain(
    service: &str,
    create_if_missing: fn(ProviderType) -> bool,
    not_found_err: Error,
) -> Result<(Arc<dyn KekProvider>, Box<dyn KekHandle>)> {
    // Every provider this call passed over, and why: if a later one serves
    // the call, an operator should know a preferred one didn't.
    let mut passed_over: Vec<String> = Vec::new();
    let mut any_present = false;
    let allowed = allowed_types()?;
    for &provider_type in &allowed {
        // priority order, per the configured policy (or the default compiled-in order)
        if let Some(home) = bound_elsewhere(service, provider_type, &allowed)? {
            log::debug!(
                "hkdfguard: policy pins this service's key in {}; not consulting {}",
                home.as_str(),
                provider_type.as_str()
            );
            continue;
        }
        let Some(provider) = construct_provider(provider_type) else {
            continue; // not compiled into this build (policy can name a type the build lacks)
        };
        let present = provider.probe();
        any_present |= present;
        if !present {
            // Gone, but this service's key lives there: stop, don't skip.
            provider.claims_while_absent(service).map_err(|e| attribute(provider_type, e))?;
            log::debug!("hkdfguard: provider {} not present, trying next", provider_type.as_str());
            passed_over.push(format!("{}: not present", provider_type.as_str()));
            continue;
        }

        match provider.load_kek(service, create_if_missing(provider_type)) {
            Ok(handle) => {
                log::debug!("hkdfguard: using provider {} for this call", provider_type.as_str());
                if !passed_over.is_empty() {
                    // The audit trail too: the `log` line below goes nowhere
                    // in a host that installs no logger.
                    crate::audit::provider_fallback(service, provider_type, &passed_over.join("; "));
                    warn_once(format!(
                        "hkdfguard: {} is serving calls in place of a provider earlier in the policy order ({}); \
                         if that isn't intended, make the earlier provider available, or take it out of \
                         preferred_order (logged once per process)",
                        provider_type.as_str(),
                        passed_over.join("; ")
                    ));
                }
                if matches!(provider_type, ProviderType::Ephemeral) && EPHEMERAL_WARNED.set(()).is_ok() {
                    // `.set()` only returns Ok the first time; subsequent calls see it already set
                    log::warn!(
                        "hkdfguard: no persistent KEK provider is available; falling back to \
                         an EPHEMERAL in-memory KEK. DEKs wrapped in this process cannot be \
                         unwrapped after a process restart."
                    );
                }
                return Ok((provider, handle)); // stop the chain walk; this is the provider+handle to use
            }
            Err(Error::KeyNotProvisioned(msg)) => {
                log::debug!(
                    "hkdfguard: provider {} has no key for this service ({msg}), trying next",
                    provider_type.as_str()
                );
                passed_over.push(format!("{}: {msg}", provider_type.as_str()));
            }
            Err(e) => return Err(attribute(provider_type, e)),
        }
        // `provider` drops here: session logged out / module finalized /
        // TCTI closed before the next candidate is even constructed.
    }
    Err(if any_present { not_found_err } else { nothing_present() })
}

/// The error for a chain walk that found no policy-allowed provider on
/// this host at all. Never "no KEK for this service" (`KEK_NOT_FOUND`): that
/// says provisioning is all that's missing, is deliberately not audited,
/// and would send a caller to `hkdfguard_create_kek` -- when what is
/// missing is the provider itself, such as the TPM a `require` policy names.
/// `PROVIDER_UNAVAILABLE` is audited (event 2005).
fn nothing_present() -> Error {
    Error::NoProviderAvailable
}

// Names the provider in a `Provider` error's message, for the caller's log line.
fn attribute(provider_type: ProviderType, e: Error) -> Error {
    match e {
        Error::Provider(msg) => Error::Provider(format!("{}: {msg}", provider_type.as_str())),
        other => other,
    }
}

/// Walks the policy-allowed priority chain (TPM2 -> PKCS#11 -> External
/// Secret -> Ephemeral, or whatever subset/order the policy configures)
/// and creates (or reuses, if one already exists) a persistent
/// KEK for `service` on the first reachable, allowed provider. This is
/// the *only* path that ever creates a KEK -- `wrap`/`unwrap` (via
/// [`select_existing`]) only ever load one. Backs `hkdfguard_create_kek`.
///
/// Fails with the error of the first provider that is present but failing
/// (see [`walk_chain`]), or [`Error::NoProviderAvailable`] if every allowed
/// provider is absent or declined.
pub fn create_kek(service: &str) -> Result<(Arc<dyn KekProvider>, Box<dyn KekHandle>)> {
    walk_chain(service, |_| true, Error::NoProviderAvailable)
}

/// [`create_kek`] for a process the security model doesn't let create
/// persistent KEKs (production, not root): the same walk, but only the
/// Ephemeral provider -- whose KEK lives and dies in this process, so only
/// this process can make it -- may create one; every other provider only
/// loads an existing KEK. An application calling `hkdfguard_create_kek` at
/// startup for a KEK an administrator provisioned therefore still
/// succeeds. Fails with [`Error::AccessDenied`] if the walk finds none --
/// or, when no allowed provider is present at all, with
/// [`Error::NoProviderAvailable`], as [`create_kek`] would: root couldn't
/// create one either.
pub fn create_kek_unprivileged(service: &str) -> Result<(Arc<dyn KekProvider>, Box<dyn KekHandle>)> {
    match walk_chain(service, |provider_type| provider_type == ProviderType::Ephemeral, Error::KekNotFound) {
        Err(Error::KekNotFound) => Err(Error::AccessDenied(
            "no KEK exists for this service, and under the production security model only root creates one \
             (run `hkdfguard provision` as root)",
        )),
        other => other,
    }
}

/// Walks the policy-allowed priority chain looking for a provider that
/// already has a persistent KEK for `service`, loading (never creating)
/// it. Backs `wrap`. Fails with [`Error::KekNotFound`] if the whole chain
/// is walked without finding one -- the caller must call [`create_kek`]
/// first -- or [`Error::NoProviderAvailable`] if no allowed provider is
/// present to walk.
pub fn select_existing(service: &str) -> Result<(Arc<dyn KekProvider>, Box<dyn KekHandle>)> {
    walk_chain(service, |_| false, Error::KekNotFound)
}

/// Walks the policy-allowed chain checking whether a persistent KEK already
/// exists for `service`, without creating one anywhere. `Ok(false)` (not an
/// error) means the chain was fully walked, every present provider answered,
/// and none has one yet -- call
/// [`create_kek`] to provision one. With no allowed provider present at
/// all, there is nothing to answer, and it fails as [`walk_chain`] does
/// ([`Error::NoProviderAvailable`]). Backs `hkdfguard_kek_exists`. Like
/// [`walk_chain`], constructs providers one at a time and stops at the
/// first that has the key.
pub fn kek_exists(service: &str) -> Result<bool> {
    let mut any_present = false;
    let allowed = allowed_types()?;
    for &provider_type in &allowed {
        if bound_elsewhere(service, provider_type, &allowed)?.is_some() {
            continue; // policy pins this service's key in another provider: a key here is not its KEK
        }
        let Some(provider) = construct_provider(provider_type) else {
            continue;
        };
        if !provider.probe() {
            provider.claims_while_absent(service).map_err(|e| attribute(provider_type, e))?;
            continue;
        }
        any_present = true;
        // An error is returned, not read as "no key": the caller would
        // otherwise go on to `create_kek`, and a strong provider that is
        // failing must not be the reason a key gets created somewhere weaker.
        if provider.kek_exists(service).map_err(|e| attribute(provider_type, e))? {
            return Ok(true);
        }
    }
    if any_present { Ok(false) } else { Err(nothing_present()) }
}

/// Looks up a specific provider by the type recorded in a wrapped payload
/// (used by `unwrap`, which must use whichever provider originally wrapped
/// the DEK, not necessarily the currently-preferred one). Constructs it
/// fresh for this call, like everything else here.
///
/// Enforces the current policy: a provider excluded by policy is treated
/// exactly like one that isn't compiled into this build at all
/// (`Error::NoProviderAvailable`) -- disabling a provider stops it from
/// being used for *both* new wraps and unwrapping payloads it already
/// produced, matching how disabling a TLS cipher suite stops it being used
/// for new and resumed connections alike.
///
/// Also logs a migration hint -- a warning, once per process for each pair
/// of providers -- if `provider_type` isn't the policy's first choice, so
/// operators can see DEKs still held under a provider they no longer
/// prefer. "First choice" here is by policy order,
/// not by probing what's reachable -- probing would mean constructing (and
/// connecting to) every stronger provider on every unwrap purely to decide
/// whether to log a hint.
pub fn get_by_type(provider_type: ProviderType) -> Result<Arc<dyn KekProvider>> {
    let allowed = allowed_types()?;
    if !allowed.contains(&provider_type) {
        return Err(Error::NoProviderAvailable); // not compiled into this build, or excluded by the current policy
    }
    if let Some(&preferred) = allowed.first() {
        if preferred != provider_type {
            // the DEK was wrapped under a different (usually weaker) provider than what policy prefers today
            warn_once(format!(
                "hkdfguard: unwrapping a DEK wrapped under {}, but policy now prefers {}; \
                 DEKs wrapped from now on go to the preferred provider when it is available \
                 (logged once per process)",
                provider_type.as_str(),
                preferred.as_str()
            ));
        }
    }
    construct_provider(provider_type).ok_or(Error::NoProviderAvailable)
}

/// The provider to unwrap a payload for `service` with: the one the
/// payload names ([`get_by_type`]) -- unless a provider earlier in the
/// policy order holds a KEK for the service now.
///
/// The provider byte in a payload is authenticated only under the key of
/// the provider it names. So whoever holds *any* allowed provider's key
/// for a service -- a sidecar that can write the external-secret mount,
/// say -- can make a payload naming that provider which opens, although
/// the service's KEK is on the TPM and every wrap goes there. A wrap
/// always uses the first provider in the order that holds a key
/// ([`select_existing`]), so a payload naming a later one is either left
/// over from before the service moved up, or that forgery; the two can't
/// be told apart, and it is refused as [`Error::KekFingerprintMismatch`]:
/// not wrapped under the KEK the service resolves to now. An administrator
/// re-wrapping what is left over sets
/// `selection.allow_unwrap_from_lower_provider` for as long as that takes.
///
/// A payload naming a provider the service is pinned away from is refused
/// the same way, whatever the order and that setting, and such a provider
/// is not asked whether it holds a key: see [`bound_elsewhere`].
///
/// The earlier providers are asked only when the payload doesn't name the
/// first one, so the usual unwrap constructs nothing extra. One that can't
/// answer -- present but failing, or absent with this service's key known
/// to live there -- fails the unwrap with its own error, as it would fail
/// a wrap ([`walk_chain`]).
pub fn for_unwrap(service: &str, provider_type: ProviderType) -> Result<Arc<dyn KekProvider>> {
    let provider = get_by_type(provider_type)?;
    let allowed = allowed_types()?;
    if let Some(home) = bound_elsewhere(service, provider_type, &allowed)? {
        log::error!(
            "hkdfguard: refusing a payload wrapped under {}: policy pins this service's key in {}, so no wrap for it \
             uses {}. If the service does keep a KEK in {} as well, pin that key too; otherwise the payload was made \
             by someone who could place a key there",
            provider_type.as_str(),
            home.as_str(),
            provider_type.as_str(),
            provider_type.as_str()
        );
        return Err(Error::KekFingerprintMismatch);
    }
    if crate::policy::allow_unwrap_from_lower_provider() {
        return Ok(provider);
    }
    for earlier in allowed.iter().copied().take_while(|t| *t != provider_type) {
        if bound_elsewhere(service, earlier, &allowed)?.is_some() {
            continue; // not this service's provider, whatever key it holds under the name (see `bound_elsewhere`)
        }
        let Some(stronger) = construct_provider(earlier) else {
            continue; // not compiled into this build
        };
        let holds_key = if stronger.probe() {
            stronger.kek_exists(service)
        } else {
            stronger.claims_while_absent(service).map(|()| false)
        };
        if holds_key.map_err(|e| attribute(earlier, e))? {
            log::error!(
                "hkdfguard: refusing a payload wrapped under {}: {} is earlier in the policy order and holds a KEK \
                 for this service, so nothing wrapped for it since then names {}. If the payload is left over from \
                 before the service moved to {}, set selection.allow_unwrap_from_lower_provider = true while it is \
                 re-wrapped; otherwise it was made by someone holding only the {} key",
                provider_type.as_str(),
                earlier.as_str(),
                provider_type.as_str(),
                earlier.as_str(),
                provider_type.as_str()
            );
            return Err(Error::KekFingerprintMismatch);
        }
    }
    Ok(provider)
}

#[cfg(test)]
mod tests {
    use super::*; // bring `ProviderType` etc. into scope
    use serial_test::serial;

    // The shortest valid policy, for tests that don't care about policy
    // behavior: nothing from the harness's policy, and nothing set. In
    // force while the returned guard lives.
    #[must_use]
    fn default_policy() -> crate::policy::test_support::TestPolicy {
        crate::policy::test_support::TestPolicy::minimal()
    }

    // Stand-in for `.unwrap_err()`: the `Ok` type here is
    // `(Arc<dyn KekProvider>, Box<dyn KekHandle>)`, which doesn't (and
    // shouldn't) implement `Debug`, so `.unwrap_err()`'s `T: Debug` bound
    // doesn't apply -- this extracts the error without needing that.
    fn expect_err<T>(r: Result<T>) -> Error {
        match r {
            Err(e) => e,
            Ok(_) => panic!("expected an error, got Ok"),
        }
    }

    // Asserts the invariant "Ephemeral is never selected unless policy
    // names it", for tests that deliberately run with *no* usable
    // external-secret mount and therefore can't pin a provider.
    //
    // Both outcomes are correct and which one occurs is a property of
    // the test host, not of the code under test: on a bare container
    // nothing is left and selection fails, while on a host with a
    // reachable TPM or PKCS#11 token that provider legitimately serves
    // the key. Asserting either one specifically would make the test
    // track hardware presence instead of the invariant.
    #[cfg(feature = "ephemeral")] // as its callers are
    fn assert_never_ephemeral(result: Result<(Arc<dyn KekProvider>, Box<dyn KekHandle>)>) {
        match result {
            Ok((provider, _handle)) => assert_ne!(
                provider.provider_type(),
                ProviderType::Ephemeral,
                "Ephemeral must not be selected unless policy explicitly names it"
            ),
            Err(Error::NoProviderAvailable) | Err(Error::Provider(_)) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn provider_type_round_trips_through_u8() {
        for t in [
            ProviderType::Tpm2,
            ProviderType::Pkcs11,
            ProviderType::ExternalSecret,
            ProviderType::Ephemeral,
        ] {
            // casting to u8 and back through `from_u8` must return the same variant
            assert_eq!(ProviderType::from_u8(t as u8), Some(t));
        }
        // 0, the unassigned 4, and 6 are all outside the
        // currently valid set and must be rejected.
        assert_eq!(ProviderType::from_u8(0), None);
        assert_eq!(ProviderType::from_u8(4), None);
        assert_eq!(ProviderType::from_u8(6), None);
        assert_eq!(ProviderType::from_u8(255), None);
    }

    #[test]
    fn provider_type_as_str() {
        assert_eq!(ProviderType::Tpm2.as_str(), "TPM2");
        assert_eq!(ProviderType::Pkcs11.as_str(), "PKCS11");
        assert_eq!(ProviderType::ExternalSecret.as_str(), "EXTERNAL_SECRET");
        assert_eq!(ProviderType::Ephemeral.as_str(), "EPHEMERAL");
    }

    #[test]
    #[serial]
    fn get_by_type_finds_compiled_providers() {
        let _policy = default_policy();
        #[cfg(feature = "external-secret")]
        {
            let p = get_by_type(ProviderType::ExternalSecret).unwrap();
            assert_eq!(p.provider_type(), ProviderType::ExternalSecret);
        }
        #[cfg(feature = "ephemeral")]
        {
            // Compiled in, but with no policy file it's excluded -- even
            // for unwrap, which is what get_by_type backs.
            assert!(matches!(
                get_by_type(ProviderType::Ephemeral).map(|_| ()),
                Err(Error::NoProviderAvailable)
            ));

            let _policy = crate::policy::allow_ephemeral_policy_for_tests();
            let p = get_by_type(ProviderType::Ephemeral).unwrap();
            assert_eq!(p.provider_type(), ProviderType::Ephemeral);
        }
    }

    #[test]
    #[serial]
    #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
    fn unwrap_refuses_a_payload_from_a_provider_below_the_one_holding_the_services_key() {
        use crate::policy::test_support::TestPolicy;
        const ORDER: &str = "preferred_order = [\"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n";
        let _policy = TestPolicy::write(ORDER);
        let mount = crate::secure_file::private_tempdir();
        let _secret_mount = crate::policy::test_support::secret_mount(mount.path());
        let dek = [7u8; crate::crypto::DEK_LEN];

        // No external secret yet: the wrap lands on Ephemeral, and opens.
        create_kek("com.company.orders").unwrap();
        let below = crate::crypto::wrap("com.company.orders", &dek).unwrap();
        assert_eq!(*crate::crypto::unwrap("com.company.orders", &below).unwrap(), dek);

        // The service's KEK is now an external secret: every wrap goes
        // there, so a payload naming Ephemeral is left over -- or made by
        // someone holding only the Ephemeral key. Refused either way.
        let secret = mount.path().join("com.company.orders");
        std::fs::write(&secret, random_kek_for_tests()).unwrap();
        std::fs::set_permissions(&secret, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600)).unwrap();
        assert!(matches!(crate::crypto::unwrap("com.company.orders", &below), Err(Error::KekFingerprintMismatch)));
        assert!(matches!(for_unwrap("com.company.orders", ProviderType::Ephemeral).map(|_| ()), Err(Error::KekFingerprintMismatch)));
        // What the service wraps now opens as ever, and another service,
        // with no key higher up, is untouched.
        let above = crate::crypto::wrap("com.company.orders", &dek).unwrap();
        assert_eq!(*crate::crypto::unwrap("com.company.orders", &above).unwrap(), dek);
        assert!(for_unwrap("com.company.billing", ProviderType::Ephemeral).is_ok());

        // While what is left over is re-wrapped, policy can allow it.
        {
            let _allowed = TestPolicy::write(&format!("{ORDER}allow_unwrap_from_lower_provider = true\n"));
            assert_eq!(*crate::crypto::unwrap("com.company.orders", &below).unwrap(), dek);
        }

        // A provider higher up that can't answer fails the unwrap with its
        // own error: it is never read as "holds no key".
        std::fs::set_permissions(&secret, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o644)).unwrap();
        assert!(matches!(crate::crypto::unwrap("com.company.orders", &below), Err(Error::Provider(_))));
    }

    #[test]
    #[serial]
    #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
    fn a_pin_binds_a_service_to_its_provider_whatever_comes_earlier_in_the_order() {
        // Ephemeral is ahead of external-secret, and any process may create
        // an Ephemeral key: the stand-in for a provider someone other than
        // the administrator can place a key in (a shared PKCS#11 token).
        const ORDER: &str = "preferred_order = [\"ephemeral\", \"external-secret\"]\n[selection]\nmode = \"prefer\"\n";
        let service = "com.company.pinnedhome";
        let mount = crate::secure_file::private_tempdir();
        let _secret_mount = crate::policy::test_support::secret_mount(mount.path());
        let key = random_kek_for_tests();
        let secret = mount.path().join(service);
        std::fs::write(&secret, key).unwrap();
        std::fs::set_permissions(&secret, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600)).unwrap();
        let dek = [9u8; crate::crypto::DEK_LEN];

        // Unpinned: the first provider holding a key wins, as ever. A key
        // planted on Ephemeral takes the service's wraps.
        let planted = {
            let _unpinned = write_policy(ORDER);
            let (provider, _) = create_kek(service).unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);
            crate::crypto::wrap(service, &dek).unwrap()
        };

        // Pinned to its external secret: the planted key is never used, for
        // a wrap, an existence check, or a creation...
        let fingerprint: String = crate::crypto::software_kek_fingerprint(&key).iter().map(|b| format!("{b:02x}")).collect();
        let _pinned = write_policy(&format!("{ORDER}[external_secret.pinned_keys]\n\"{service}\" = \"{fingerprint}\"\n"));
        for (provider, _) in [select_existing(service).unwrap(), create_kek(service).unwrap()] {
            assert_eq!(provider.provider_type(), ProviderType::ExternalSecret);
        }
        assert!(kek_exists(service).unwrap());
        let genuine = crate::crypto::wrap(service, &dek).unwrap();
        assert_eq!(crate::payload::Payload::from_bytes(&genuine).unwrap().provider_type, ProviderType::ExternalSecret);
        // ...what the real key wrapped still opens, though a provider
        // earlier in the order holds a key under the service's name...
        assert_eq!(*crate::crypto::unwrap(service, &genuine).unwrap(), dek);
        // ...and what the planted key wrapped does not.
        assert!(matches!(crate::crypto::unwrap(service, &planted), Err(Error::KekFingerprintMismatch)));
        assert!(matches!(for_unwrap(service, ProviderType::Ephemeral).map(|_| ()), Err(Error::KekFingerprintMismatch)));

        // A service with no pin is untouched.
        let (provider, _) = create_kek("com.company.nopin").unwrap();
        assert_eq!(provider.provider_type(), ProviderType::Ephemeral);
    }

    #[test]
    #[serial]
    fn create_kek_prefers_external_secret_when_provisioned() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {
            let _policy = crate::policy::allow_ephemeral_policy_for_tests(); // the billing fall-through below needs Ephemeral opted in

            let ext_dir = crate::secure_file::private_tempdir();
            let _secret_mount = crate::policy::test_support::secret_mount(ext_dir.path());

            // Write an external secret for "com.company.orders", owner-only
            // as the provider requires of a KEK file.
            let secret_key = random_kek_for_tests();
            let secret_path = ext_dir.path().join("com.company.orders");
            std::fs::write(&secret_path, secret_key).unwrap();
            std::fs::set_permissions(&secret_path, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600)).unwrap();

            let (provider, handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::ExternalSecret);
            assert_eq!(handle.key_id(), b"external:com.company.orders");

            // For an unprovisioned service, it falls through to Ephemeral
            // (external-secret never creates one itself).
            let (provider2, handle2) = create_kek("com.company.billing").unwrap();
            assert_eq!(provider2.provider_type(), ProviderType::Ephemeral);
            assert_eq!(handle2.key_id(), b"ephemeral:com.company.billing");

        }
    }

    #[test]
    #[serial]
    fn create_kek_does_not_fall_back_to_ephemeral_unless_policy_names_it() {
        #[cfg(feature = "ephemeral")]
        {
            let _policy = default_policy(); // a policy that names nothing

            // External secret unreachable, so on a host with no hardware
            // provider Ephemeral is the only thing left -- and it must
            // NOT be used: a transient outage must not silently become a
            // key that's lost on restart. The subject here is the
            // *default order*, so the policy deliberately isn't
            // pinned; see `assert_never_ephemeral` for why the outcome is
            // asserted as an invariant rather than one fixed result.

            assert_never_ephemeral(create_kek("com.company.orders.nopolicy"));

        }
    }

    #[test]
    #[serial]
    fn create_kek_falls_back_to_ephemeral_only_when_policy_allows_it() {
        #[cfg(feature = "ephemeral")]
        {
            let _policy = crate::policy::allow_ephemeral_policy_for_tests();

            let (provider, handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);
            assert_eq!(handle.key_id(), b"ephemeral:com.company.orders");

        }
    }

    #[test]
    #[serial]
    fn create_kek_constructs_a_fresh_provider_on_every_call() {
        #[cfg(feature = "external-secret")]
        {
            // This test is about external-secret specifically (that a
            // fresh instance of it is constructed per call), so pin the
            // chain to it -- otherwise a reachable TPM or PKCS#11 token
            // wins the chain and the assertions below compare the wrong
            // provider.
            let _policy = crate::policy::require_provider_policy_for_tests("external-secret");
            let ext_dir = crate::secure_file::private_tempdir();
            let _secret_mount = crate::policy::test_support::secret_mount(ext_dir.path());

            // external-secret never creates a key itself, so both
            // services need to be pre-provisioned.
            let key_a = random_kek_for_tests();
            let key_b = random_kek_for_tests();
            for (name, key) in [("com.company.a", &key_a), ("com.company.b", &key_b)] {
                let path = ext_dir.path().join(name);
                std::fs::write(&path, key).unwrap();
                std::fs::set_permissions(&path, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600)).unwrap(); // owner-only, as the provider requires
            }

            let (provider1, _handle1) = create_kek("com.company.a").unwrap();
            assert_eq!(provider1.provider_type(), ProviderType::ExternalSecret);

            let (provider2, _handle2) = create_kek("com.company.b").unwrap();
            assert_eq!(provider2.provider_type(), ProviderType::ExternalSecret);
            // A *different* instance each call: nothing is kept alive
            // between calls -- no standing session, login, or device
            // connection (see `construct_provider`'s doc comment).
            assert!(
                !Arc::ptr_eq(&provider1, &provider2),
                "each call must construct its own provider; no instance may be retained between calls"
            );

        }
    }

    #[test]
    #[serial]
    fn select_existing_fails_until_create_kek_is_called() {
        #[cfg(feature = "ephemeral")]
        {
            // A service name unique to this test: Ephemeral's key map is
            // process-global and never cleared between tests, so reusing
            // a name another test also resolves via Ephemeral could find
            // it already "created" here.
            let service = "com.company.nevercreated.selectexisting";
            let _policy = crate::policy::allow_ephemeral_policy_for_tests();

            let err = expect_err(select_existing(service));
            assert!(matches!(err, Error::KekNotFound));
            assert!(!kek_exists(service).unwrap());

            create_kek(service).unwrap();

            assert!(kek_exists(service).unwrap());
            let (provider, _handle) = select_existing(service).unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);

        }
    }

    // `doc` as the policy while the returned guard lives -- bind it
    // (`let _policy = ...`), or it is gone at the end of the statement.
    fn write_policy(doc: &str) -> crate::policy::test_support::TestPolicy {
        crate::policy::test_support::TestPolicy::write(doc)
    }

    #[test]
    #[serial]
    fn policy_prefer_mode_restricts_to_named_providers_in_order() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {

            // Deliberately excludes external-secret; naming Ephemeral in
            // preferred_order is what makes it reachable at all.
            let _policy_dir = write_policy("preferred_order = [\"ephemeral\"]\n[selection]\nmode = \"prefer\"\n");

            let (provider, _handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(
                provider.provider_type(),
                ProviderType::Ephemeral,
                "policy names only Ephemeral, so it must be used"
            );

        }
    }

    #[test]
    #[serial]
    fn policy_require_provider_fails_closed_when_unreachable() {
        #[cfg(feature = "pkcs11")]
        {
            // Nothing from the harness: no PKCS#11 module or PIN file.
            let _isolated = crate::policy::test_support::TestPolicy::minimal();
            // PKCS#11 is compiled in but not reachable here (the policy
            // names no module), and the policy
            // requires exactly it -- so there must be no fallback to
            // Ephemeral/external-secret, unlike the unrestricted default
            // chain (this is the Linux equivalent of "Require TPM
            // failure" when TPM hardware isn't present).
            let _policy_dir = write_policy("[selection]\nmode = \"require\"\nprovider = \"pkcs11\"\n");

            let err = expect_err(create_kek("com.company.orders"));
            assert!(matches!(err, Error::NoProviderAvailable | Error::Provider(_)));

        }
    }

    #[test]
    #[serial]
    fn policy_prefer_mode_falls_through_unreachable_providers_to_a_reachable_one() {
        #[cfg(all(feature = "pkcs11", feature = "external-secret"))]
        {
            // Nothing from the harness: no PKCS#11 module or PIN file.
            let _isolated = crate::policy::test_support::TestPolicy::minimal();
            let ext_dir = crate::secure_file::private_tempdir();
            let _secret_mount = crate::policy::test_support::secret_mount(ext_dir.path());

            // Pre-provision the external secret so it's actually usable
            // once the chain reaches it (this provider never creates one
            // itself).
            let secret_key = random_kek_for_tests();
            let secret_path = ext_dir.path().join("com.company.orders");
            std::fs::write(&secret_path, secret_key).unwrap();
            std::fs::set_permissions(&secret_path, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600)).unwrap(); // owner-only, as the provider requires

            // PKCS#11 (no PIN configured) is unreachable; policy must
            // fall through to external-secret.
            let _policy_dir = write_policy(
                "preferred_order = [\"pkcs11\", \"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n",
            );

            let (provider, _handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::ExternalSecret);

        }
    }

    #[test]
    #[serial]
    fn policy_ephemeral_disallowed_by_default_end_to_end() {
        #[cfg(feature = "ephemeral")]
        {

            // No preferred_order at all -- ephemeral must default to
            // disallowed (never named), even where it would otherwise be
            // the only reachable provider.
            let _policy_dir = write_policy("[selection]\nmode = \"prefer\"\n");

            assert_never_ephemeral(create_kek("com.company.orders"));

        }
    }

    #[test]
    #[serial]
    fn policy_ephemeral_allowed_end_to_end_when_policy_permits() {
        #[cfg(feature = "ephemeral")]
        {

            let _policy_dir = write_policy("preferred_order = [\"ephemeral\"]\n[selection]\nmode = \"prefer\"\n");

            let (provider, _handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);

        }
    }

    #[test]
    #[serial]
    fn policy_minimum_protection_enforced_end_to_end() {
        #[cfg(feature = "ephemeral")]
        {

            // Ephemeral is explicitly named (clearing that gate), so
            // minimum_protection: external is the *only* thing standing
            // between it and being selected -- isolating exactly the
            // mechanism this test means to exercise.
            let _policy_dir = write_policy(
                "preferred_order = [\"ephemeral\"]\n[key_requirements]\nminimum_protection = \"external\"\n[selection]\nmode = \"prefer\"\n",
            );

            let err = expect_err(create_kek("com.company.orders"));
            assert!(matches!(err, Error::NoProviderAvailable | Error::Provider(_)));

        }
    }

    // ---- each provider failure is logged exactly once ----

    // The log capture below is used only by the external-secret tests.
    #[cfg(feature = "external-secret")]
    struct CapturingLogger(std::sync::Mutex<Vec<String>>);

    #[cfg(feature = "external-secret")]
    impl log::Log for CapturingLogger {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() <= log::Level::Warn
        }
        fn log(&self, record: &log::Record) {
            if self.enabled(record.metadata()) {
                self.0.lock().unwrap().push(format!("{}", record.args()));
            }
        }
        fn flush(&self) {}
    }

    #[cfg(feature = "external-secret")]
    static CAPTURED: CapturingLogger = CapturingLogger(std::sync::Mutex::new(Vec::new()));

    // Runs `f` and returns every warn/error line it logged that contains
    // `marker`. `#[serial]` callers keep other tests' lines out.
    #[cfg(feature = "external-secret")]
    fn logged_lines_containing(marker: &str, f: impl FnOnce()) -> Vec<String> {
        if log::set_logger(&CAPTURED).is_ok() {
            log::set_max_level(log::LevelFilter::Warn);
        }
        CAPTURED.0.lock().unwrap().clear();
        f();
        CAPTURED.0.lock().unwrap().iter().filter(|l| l.contains(marker)).cloned().collect()
    }

    // An external-secret mount holding a group-readable key for `service`:
    // a hard provider failure ("permissions too broad"), not a soft decline.
    // Both halves must stay bound for the test's duration: the mount
    // directory, and the policy layer pointing the provider at it.
    #[cfg(feature = "external-secret")]
    fn mount_with_untrusted_secret(service: &str) -> (tempfile::TempDir, crate::policy::test_support::TestPolicy) {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join(service);
        std::fs::write(&path, random_kek_for_tests()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let mount = crate::policy::test_support::secret_mount(dir.path());
        (dir, mount)
    }

    #[test]
    #[serial]
    fn a_provider_failure_that_fails_the_call_is_logged_once() {
        #[cfg(feature = "external-secret")]
        {
            let service = "com.company.logonce";
            let _mount = mount_with_untrusted_secret(service);
            let _policy = crate::policy::require_provider_policy_for_tests("external-secret");

            let lines = logged_lines_containing("permissions too broad", || {
                let c = std::ffi::CString::new(service).unwrap();
                assert_ne!(crate::hkdfguard_create_kek(c.as_ptr()), crate::status::OK);
            });

            assert_eq!(lines.len(), 1, "the failure must be logged exactly once, got: {lines:#?}");
            assert!(lines[0].contains("EXTERNAL_SECRET"), "the one line must still name the provider: {}", lines[0]);
        }
    }

    #[test]
    #[serial]
    fn serving_from_a_later_provider_is_a_warning_logged_once() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {
            // External-secret is first and present, but has no key for this
            // service, so Ephemeral serves it: the call succeeds, and an
            // operator must still be told -- once, not on every call.
            let empty_mount = crate::secure_file::private_tempdir();
            let _mount = crate::policy::test_support::secret_mount(empty_mount.path());
            let _policy = crate::policy::allow_ephemeral_policy_for_tests(); // external-secret, then ephemeral
            reset_warn_once();

            let lines = logged_lines_containing("in place of a provider earlier", || {
                for _ in 0..3 {
                    let (provider, _handle) = create_kek("com.company.fallbackwarn")
                        .unwrap_or_else(|e| panic!("ephemeral should serve the call: {e}"));
                    assert_eq!(provider.provider_type(), ProviderType::Ephemeral);
                }
            });
            assert_eq!(lines.len(), 1, "logged once per process, not per call: {lines:#?}");
            assert!(lines[0].contains("EPHEMERAL"), "names the provider that served the call: {}", lines[0]);
            assert!(lines[0].contains("EXTERNAL_SECRET: "), "says what was passed over, and why: {}", lines[0]);
            assert!(!lines[0].contains("fallbackwarn"), "never names the service: {}", lines[0]);

            // And in the audit trail, which reaches syslog whether or not
            // the host installed a logger: once too, naming the service.
            let records = crate::audit::captured_containing("\"com.company.fallbackwarn\"");
            let fallbacks: Vec<&String> = records.iter().filter(|r| r.contains("event=1006 ")).collect();
            assert_eq!(fallbacks.len(), 1, "{records:#?}");
            assert!(fallbacks[0].starts_with("<84>"), "a Warning: {}", fallbacks[0]);
            assert!(
                fallbacks[0].contains("provider=EPHEMERAL passed_over=\"EXTERNAL_SECRET: "),
                "says who served it and what was passed over: {}",
                fallbacks[0]
            );
        }
    }

    #[test]
    #[serial]
    fn a_failing_provider_stops_the_chain_instead_of_falling_back_to_a_weaker_one() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {
            // The platform's secret drifted to a group-readable mode. Policy
            // would let Ephemeral serve the service -- but only for a service
            // external-secret doesn't have, not one it has and can't trust:
            // otherwise every DEK from here on is wrapped under a key that is
            // gone at the next restart, and no call ever reports a problem.
            let service = "com.company.nofallback";
            let _mount = mount_with_untrusted_secret(service);
            let _policy = crate::policy::allow_ephemeral_policy_for_tests(); // external-secret, then ephemeral
            let c = std::ffi::CString::new(service).unwrap();

            let lines = logged_lines_containing("permissions too broad", || {
                assert_eq!(crate::hkdfguard_create_kek(c.as_ptr()), crate::status::PROVIDER_ERROR);
            });
            assert_eq!(lines.len(), 1, "the failure must be logged exactly once, got: {lines:#?}");
            assert!(lines[0].contains("EXTERNAL_SECRET"), "the line must name the provider: {}", lines[0]);

            // kek_exists must surface it too, rather than answer "no", which
            // would invite the caller to create a key somewhere weaker.
            let mut exists: std::os::raw::c_int = -1;
            assert_eq!(crate::hkdfguard_kek_exists(c.as_ptr(), &mut exists), crate::status::PROVIDER_ERROR);
            assert_eq!(exists, -1, "untouched on error");
            assert!(kek_exists(service).is_err());

            // And nothing was quietly created on Ephemeral.
            assert!(matches!(
                crate::provider::ephemeral::EphemeralProvider::new().kek_exists(service),
                Ok(false)
            ));

        }
    }

    #[test]
    #[serial]
    fn a_required_provider_that_is_absent_is_unavailable_and_audited_not_kek_not_found() {
        #[cfg(feature = "external-secret")]
        {
            // Policy requires one provider and the host doesn't have it. That
            // is an outage, not "this service isn't provisioned yet":
            // KEK_NOT_FOUND would go unaudited and send the caller off to
            // hkdfguard_create_kek, and kek_exists answering 0 would too.
            let _isolated = crate::policy::test_support::TestPolicy::minimal();
            let _policy = write_policy("[selection]\nmode = \"require\"\nprovider = \"external-secret\"\n");
            if external_secret::ExternalSecretProvider::new().probe() {
                eprintln!("skipping: this host has a conventional secret mount");
                return;
            }
            let service = "com.company.requiredabsent";
            assert!(matches!(expect_err(select_existing(service)), Error::NoProviderAvailable));
            assert!(matches!(kek_exists(service), Err(Error::NoProviderAvailable)));

            let c = std::ffi::CString::new(service).unwrap();
            let dek = [0x11u8; 32];
            let mut out = [0u8; 512];
            let mut out_len: std::os::raw::c_int = 512;
            assert_eq!(
                crate::hkdfguard_wrap_dek(c.as_ptr(), dek.as_ptr(), 32, out.as_mut_ptr(), &mut out_len),
                crate::status::PROVIDER_UNAVAILABLE
            );
            let mut exists: std::os::raw::c_int = -1;
            assert_eq!(crate::hkdfguard_kek_exists(c.as_ptr(), &mut exists), crate::status::PROVIDER_UNAVAILABLE);
            assert_eq!(exists, -1, "untouched on error");

            let records = crate::audit::captured_containing("\"com.company.requiredabsent\"");
            for op in ["hkdfguard_wrap_dek", "hkdfguard_kek_exists"] {
                assert!(
                    records.iter().any(|r| r.contains(&format!("event=2005 op={op} result=PROVIDER_UNAVAILABLE(-3)"))),
                    "{op} must be audited: {records:#?}"
                );
            }
        }
    }

    #[test]
    #[serial]
    fn an_absent_provider_that_holds_the_services_key_stops_the_chain() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {
            // Policy pins an external secret for the service, and no secret
            // mount exists on this host at all: the provider is absent, and
            // would be skipped without a word -- leaving Ephemeral, which
            // policy allows, to take every wrap. The pin says where the key
            // lives, so the chain stops there instead.
            let service = "com.company.pinnedbutgone";
            let _policy = write_policy(&format!(
                "preferred_order = [\"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n\
                 [external_secret.pinned_keys]\n\"{service}\" = \"{}\"\n",
                "ab".repeat(32)
            ));
            if external_secret::ExternalSecretProvider::new().probe() {
                eprintln!("skipping: this host has a conventional secret mount");
                return;
            }
            for result in [create_kek(service).map(|_| ()), select_existing(service).map(|_| ()), kek_exists(service).map(|_| ())] {
                match result {
                    Err(Error::Provider(msg)) => {
                        assert!(msg.starts_with("EXTERNAL_SECRET: ") && msg.contains("none is mounted"), "{msg}")
                    }
                    other => panic!("expected external-secret to stop the chain, got {other:?}"),
                }
            }
            assert!(matches!(ephemeral::EphemeralProvider::new().kek_exists(service), Ok(false)), "nothing created on Ephemeral");

            // A service policy doesn't pin still moves on.
            let (provider, _) = create_kek("com.company.notpinned").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);
        }
    }

    #[test]
    #[serial]
    fn an_absent_provider_or_a_missing_key_still_moves_the_chain_on() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {
            let _policy = crate::policy::allow_ephemeral_policy_for_tests();

            // No mount at all: absent.
            let (provider, _) = create_kek("com.company.absentmount").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);

            // A trusted mount with nothing for this service: declined.
            let mount = crate::secure_file::private_tempdir();
            let _secret_mount = crate::policy::test_support::secret_mount(mount.path());
            let (provider, _) = create_kek("com.company.notinmount").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);

        }
    }

    #[test]
    #[serial]
    fn malformed_policy_fails_closed_even_when_providers_are_available() {

        let _policy_dir = write_policy("[selection]\nmode = \"require\"\nprovider = \"quantum-vault\"\n");

        let err = expect_err(create_kek("com.company.orders"));
        assert!(matches!(err, Error::Policy(_)), "a malformed policy must fail closed, not fall back to the default chain");

    }
}

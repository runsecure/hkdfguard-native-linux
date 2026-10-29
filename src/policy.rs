//! Linux administrative key-selection policy: `/etc/hkdfguard/policy.toml`
//! (overridable with `HKDFGUARD_POLICY_FILE`), giving system administrators
//! control over which KEK providers this crate may use and how the
//! provider chain is selected -- functionally equivalent to HKDFGuard's
//! Windows registry-based policy, extended to Linux-specific providers
//! (TPM2, PKCS#11, an externally provisioned secret, and an in-memory
//! ephemeral key). There is deliberately no software-backed (PKCS#8-file)
//! provider on this platform, so `require: pkcs8` -- the Windows-parity
//! token for that concept -- is not part
//! of this vocabulary; a deployment without TPM2/PKCS#11 hardware should
//! provision a KEK via `external-secret` instead.
//!
//! Design: policy decisions are expressed primarily in terms of a
//! [`KeyProtectionLevel`] (an assurance tier) rather than naming specific
//! provider technologies, so a future provider can slot into an existing
//! level (see [`ProviderType::protection_level`]) and immediately be
//! usable under `require-level`/`minimum_protection` policies without any
//! change to this schema. Only the `require` mode and `preferred_order`
//! name providers directly, since that's their whole point.
//!
//! Separation of concerns: this module owns policy *parsing and
//! evaluation* only -- it has no knowledge of `KekProvider`/`KekHandle`
//! (the actual provider implementations in `crate::provider`) and knows
//! nothing about *how* a provider works -- it only carries the settings
//! each provider reads from the policy (module path, PIN file, TCTI...).
//! Its central question: given the provider types compiled
//! into this build, which of them, in what order, does policy currently
//! allow?

use crate::error::{Error, Result};
use crate::payload::FINGERPRINT_LEN;
use crate::provider::ProviderType;
use crate::security_model::SecurityModel;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// Location of the policy file. Every build that ships reads only this
/// path; every other piece of configuration (TPM and its key directory,
/// secret mount, PKCS#11 module, token and PIN file) is named inside it.
#[cfg_attr(test, allow(dead_code))] // unit tests never read the real policy (see `policy_file_path`)
const DEFAULT_POLICY_FILE: &str = "/etc/hkdfguard/policy.toml";

/// Which policy file to read.
///
/// Builds that ship: always [`DEFAULT_POLICY_FILE`]. Nothing in the
/// environment can redirect it -- the environment is often set by
/// lower-trust configuration than the root-owned file, and whoever picks
/// the policy file picks the TPM, the secrets, and the HSM module loaded
/// into this process.
///
/// Test builds only:
/// - this crate's unit tests (`cfg(test)`): the policy of the innermost
///   live [`test_support::TestPolicy`]; else the harness's
///   `HKDFGUARD_POLICY_FILE`; else *no* policy, so a real
///   `/etc/hkdfguard` on a developer's machine never leaks into a test;
/// - the harnesses' out-of-process builds (`--cfg hkdfguard_test_paths`,
///   which no ordinary build setting can turn on, debug profile
///   included): `HKDFGUARD_POLICY_FILE`, else the default. Such a build
///   says so in its log.
fn policy_file_path() -> PathBuf {
    #[cfg(test)]
    {
        if let Some(path) = test_support::active_path() {
            return path;
        }
        std::env::var_os("HKDFGUARD_POLICY_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/nonexistent-hkdfguard-policy-for-unit-tests"))
    }
    #[cfg(all(not(test), hkdfguard_test_paths))]
    {
        static ANNOUNCED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        ANNOUNCED.get_or_init(|| {
            log::warn!(
                "hkdfguard: TEST BUILD (--cfg hkdfguard_test_paths): HKDFGUARD_POLICY_FILE is honored and \
                 configuration owned by this user is accepted; never deploy this library"
            );
        });
        std::env::var_os("HKDFGUARD_POLICY_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_POLICY_FILE))
    }
    #[cfg(not(any(test, hkdfguard_test_paths)))]
    {
        if std::env::var_os("HKDFGUARD_POLICY_FILE").is_some() {
            static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
            WARNED.get_or_init(|| {
                log::warn!("hkdfguard: HKDFGUARD_POLICY_FILE is set but ignored: the policy is always {DEFAULT_POLICY_FILE}");
            });
        }
        PathBuf::from(DEFAULT_POLICY_FILE)
    }
}

/// Security assurance level a provider offers, independent of the specific
/// technology backing it (see [`ProviderType::protection_level`]). Declared
/// ascending, weakest first, so a derived [`Ord`] makes "at least this
/// strong" a plain `>=` comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyProtectionLevel {
    Ephemeral,
    Software,
    External,
    Hardware,
}

impl KeyProtectionLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyProtectionLevel::Ephemeral => "ephemeral",
            KeyProtectionLevel::Software => "software",
            KeyProtectionLevel::External => "external",
            KeyProtectionLevel::Hardware => "hardware",
        }
    }
}

impl ProviderType {
    /// This provider's assurance tier -- what policy decisions should
    /// generally be made against instead of the specific provider
    /// identity, so adding a new provider later doesn't require touching
    /// every existing `require-level`/`minimum_protection` policy.
    pub fn protection_level(&self) -> KeyProtectionLevel {
        match self {
            ProviderType::Tpm2 | ProviderType::Pkcs11 => KeyProtectionLevel::Hardware,
            ProviderType::ExternalSecret => KeyProtectionLevel::External,
            ProviderType::Ephemeral => KeyProtectionLevel::Ephemeral,
        }
    }

    /// The policy-file vocabulary's name for this provider (distinct from
    /// [`Self::as_str`], which is the log-message/legacy form) -- used in
    /// policy error messages so they read in the same terms the policy file uses.
    fn policy_name(&self) -> &'static str {
        match self {
            ProviderType::Tpm2 => "tpm2",
            ProviderType::Pkcs11 => "pkcs11",
            ProviderType::ExternalSecret => "external-secret",
            ProviderType::Ephemeral => "ephemeral",
        }
    }
}

// Manual (not derived) `Deserialize`: the policy vocabulary's provider
// names (`tpm2`, `pkcs11`, `external-secret`, `ephemeral`) don't match
// `ProviderType`'s own variant names 1:1 (the wire-format log names are
// upper-snake-case), so this is kept independent of that type's definition
// in `provider::mod` -- Rust's orphan rules allow a foreign trait
// (`serde::Deserialize`) to be implemented for a local type from any
// module in this crate.
//
// `pkcs8` is deliberately not a recognized token: this platform has no
// software-backed provider (see this module's own doc comment), so it
// falls through to the `other` arm below like any other unknown name.
impl<'de> Deserialize<'de> for ProviderType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "tpm2" => Ok(ProviderType::Tpm2),
            "pkcs11" => Ok(ProviderType::Pkcs11),
            "external-secret" => Ok(ProviderType::ExternalSecret),
            "ephemeral" => Ok(ProviderType::Ephemeral),
            other => Err(serde::de::Error::custom(format!(
                "unknown provider \"{other}\" (expected one of: tpm2, pkcs11, external-secret, ephemeral)"
            ))),
        }
    }
}

// ---------------------------------------------------------------------
// Raw (as-deserialized, unvalidated) policy-file schema.
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    /// `"production"` (the default) or `"developer"`: see
    /// [`crate::security_model`]. A top-level key, so it goes above the
    /// first `[table]`.
    #[serde(default)]
    security_model: SecurityModel,
    /// Groups whose direct members deploy key files under the production
    /// model, in addition to `hkdfguard-deployers`. Names, not gids.
    #[serde(default)]
    deployer_groups: Vec<String>,
    #[serde(default)]
    key_requirements: KeyRequirements,
    selection: RawSelection,
    #[serde(default)]
    preferred_order: Vec<ProviderType>,
    #[serde(default)]
    startup_behavior: StartupBehavior,
    #[serde(default)]
    tpm: TpmPolicy,
    #[serde(default)]
    external_secret: ExternalSecretPolicy,
    #[serde(default)]
    pkcs11: Pkcs11Policy,
    #[serde(default)]
    audit: AuditPolicy,
}

/// Audit-trail settings (`[audit]`); see `crate::audit`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditPolicy {
    /// Whether a successful unwrap writes audit event 1003. Only an
    /// explicit `false` turns it off -- the counterpart of the Windows
    /// build's AuditUnwrapSuccess = 0 -- for a caller that legitimately
    /// unwraps often. Wrap events and every failure event are written
    /// regardless.
    #[serde(default = "default_true")]
    unwrap_success: bool,
}

impl Default for AuditPolicy {
    fn default() -> Self {
        AuditPolicy { unwrap_success: true }
    }
}

/// External-secret provider settings (`[external_secret]`).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalSecretPolicy {
    /// The directory holding `<service>` KEK files. When set, it is the
    /// only place looked at; when unset, the provider searches the
    /// conventional secret mounts.
    dir: Option<String>,
    /// Expected KEK fingerprint, per service, as hex: the fixed HMAC
    /// output `crypto::kek_fingerprint` defines, the value `provision`
    /// prints and every payload carries. One string, or a list of them while a
    /// rotation is in progress. When a service has an entry here, a
    /// mounted key with any other fingerprint is refused -- see
    /// [`pinned_external_keys`] for why the mount checks alone don't catch
    /// a substituted key.
    #[serde(default)]
    pinned_keys: BTreeMap<String, PinnedKeys>,
    /// Make `pinned_keys` the provider's allowlist: a service with no pin
    /// is treated as having no KEK, whatever is mounted for it. Default
    /// `false`, so existing deployments keep working until they pin.
    #[serde(default)]
    require_pinned_keys: bool,
}

/// One `external_secret.pinned_keys` entry: a single fingerprint, or
/// several (old and new, during a rotation).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PinnedKeys {
    One(String),
    Several(Vec<String>),
}

/// PKCS#11 provider settings (`[pkcs11]`).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pkcs11Policy {
    /// Absolute path of the PKCS#11 module to load. Every build uses
    /// PKCS#11 only when this is set: there is no default module search,
    /// since the commonly installed one (SoftHSM2) is a software token.
    module: Option<String>,
    /// Absolute path of the user-PIN file (default /etc/hkdfguard/pkcs11.pin).
    pin_file: Option<String>,
    /// Select the token by its CKA label (`CK_TOKEN_INFO.label`), and/or
    /// its serial number. Slot numbers aren't stable across reboots or
    /// hot-plugging; these are. Exactly one token must match.
    token_label: Option<String>,
    token_serial: Option<String>,
}

/// The PKCS#11 settings policy supplies, validated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pkcs11Settings {
    pub module: Option<PathBuf>,
    pub pin_file: Option<PathBuf>,
    pub token_label: Option<String>,
    pub token_serial: Option<String>,
}

// A policy-supplied path must be absolute: a relative one would resolve
// against whatever directory the host application happens to run in.
fn absolute_path(field: &str, value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(Error::Policy(format!("hkdfguard policy: {field} \"{value}\" must be an absolute path")));
    }
    Ok(path)
}

// A deployer group is named, never numbered: a gid in the policy would
// silently mean another group on a host that numbers them differently. The
// name can't be one getgrnam could never match, either: nothing a group file
// line uses as a separator, no whitespace or control characters, no `/`.
fn validate_group_name(name: &str) -> Result<()> {
    let bad = name.is_empty()
        || name.len() > 256
        || name.bytes().all(|b| b.is_ascii_digit())
        || name.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, ':' | ',' | '/'));
    if bad {
        return Err(Error::Policy(format!(
            "hkdfguard policy: deployer_groups entry \"{name}\" is not a group name (1..=256 bytes, not all digits, \
             no whitespace, control characters, ':', ',' or '/')"
        )));
    }
    Ok(())
}

// PKCS#11 token fields are fixed-width, blank-padded: label 32 bytes,
// serial 16. A longer value can never match, so reject it as a typo.
fn token_field(field: &str, value: &str, max: usize) -> Result<String> {
    if value.is_empty() || value.len() > max {
        return Err(Error::Policy(format!(
            "hkdfguard policy: {field} must be 1..={max} bytes, got {}",
            value.len()
        )));
    }
    Ok(value.to_string())
}

/// TPM2-provider-specific administrative controls. Parsed and validated
/// on every build (so a policy file is portable across builds with and
/// without the `tpm2` feature) but only consulted by the TPM2 provider.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TpmPolicy {
    /// Expected TPM Name, per service, as lowercase hex. When a service
    /// has an entry here, the Name the TPM reports for its key must match
    /// it exactly or the operation fails -- see
    /// [`pinned_tpm_name`] for why this, and not the
    /// self-consistency check, is the part that resists substitution.
    #[serde(default)]
    pinned_names: BTreeMap<String, String>,
    /// Make `pinned_names` the TPM provider's allowlist: a service with no
    /// pinned Name is treated as having no KEK (`kek_exists` is false,
    /// wrap/unwrap decline), whatever key file it has. Default `false`.
    #[serde(default)]
    require_pinned_names: bool,
    /// Whether `TPM2_HMAC` and `TPM2_Create` run with parameter encryption,
    /// so a payload's wrapping key, and a new key's authValue, don't cross
    /// the TPM bus in cleartext. See [`SessionEncryption`].
    #[serde(default)]
    session_encryption: SessionEncryption,
    /// Expected TPM Name of the storage root key, as lowercase hex: the
    /// key every key file is loaded under and every session is salted to.
    /// Checked against what `TPM2_CreatePrimary` returned, on every call.
    /// It matters most when a service is provisioned: `TPM2_Create` sends
    /// the new key's authValue in a session whose only secret is the salt,
    /// so an interposer who substituted the storage root key there would
    /// learn it. After provisioning the authValue protects every session
    /// on its own (see `crate::provider::tpm2`).
    pinned_session_salt_key_name: Option<String>,
    /// Which TPM to talk to, as a tpm2-tss TCTI string:
    /// `device:/dev/tpmrm0` (the default when unset), `tabrmd:...`,
    /// `mssim:...` or `swtpm:...`. Set here, by root, because it decides
    /// whose TPM derives the keys: a TCTI pointed at an attacker-run
    /// simulator hands them a TPM whose seed they know.
    ///
    /// `mssim` and `swtpm` are accepted for test harnesses only. They talk
    /// to a simulator directly, with no resource manager in between, so
    /// object handles are shared by every client of that simulator: another
    /// client could flush and replace the key between the provider's
    /// `TPM2_ReadPublic` (where its Name is checked) and its `TPM2_HMAC`. `device:/dev/tpmrm0` and `tabrmd` give each
    /// connection its own handles, which closes that window.
    tcti: Option<String>,
    /// Absolute path of the directory holding the TPM key files, one
    /// `<service>.tpmkey` per service (default `/var/lib/hkdfguard/tpm`).
    key_dir: Option<String>,
    /// Absolute path of a file holding the Owner hierarchy's
    /// authorization value, used verbatim. Unset (the default): the Owner
    /// hierarchy is assumed to have an empty password. Setting an owner
    /// password, and this file, stops anyone without it from deriving the
    /// storage primary key every key file is loaded under -- and so from
    /// using this crate's KEKs at all. Adding it changes no KEK.
    owner_auth_file: Option<String>,
}

/// TCTI kinds tss-esapi can open; anything else is rejected at load time.
const TCTI_KINDS: &[&str] = &["device", "tabrmd", "mssim", "swtpm"];

// Checks that a policy TCTI names a supported kind. The rest of the string
// (device path, host/port) is parsed by the TPM provider, which treats a
// value it can't parse as "TPM unavailable", never as "use the default".
fn validate_tcti(tcti: &str) -> Result<()> {
    let kind = tcti.split(':').next().unwrap_or("");
    if TCTI_KINDS.contains(&kind) {
        return Ok(());
    }
    Err(Error::Policy(format!(
        "hkdfguard policy: tpm.tcti \"{tcti}\" must start with one of: {}",
        TCTI_KINDS.join(", ")
    )))
}

/// Policy for TPM session parameter encryption (`tpm.session_encryption`).
///
/// The threat is an interposer on a *discrete* TPM's LPC or SPI bus: one
/// reading `TPM2_HMAC`'s response, a payload's wrapping key, or replacing
/// it with a key of their own while a DEK is wrapped. Every service key
/// has a secret authValue, and the sessions that use the key derive their
/// encryption and response-HMAC keys from it, so encryption needs no
/// trusted public key and no guess about whether the TPM has a bus. It is
/// on unless a test harness turns it off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionEncryption {
    /// Encrypt every `TPM2_HMAC` and `TPM2_Create`: the default.
    #[default]
    On,
    /// Send `TPM2_HMAC`'s input and output in cleartext. Responses are
    /// still authenticated by the key's authValue. For test harnesses;
    /// not for production.
    Off,
}

/// Length of a SHA-256 TPM Name: the two-byte `TPM_ALG_SHA256` prefix
/// followed by the 32-byte digest of the marshalled public area.
const SHA256_TPM_NAME_LEN: usize = 2 + 32;

// Decodes a policy-supplied TPM Name and checks it is a SHA-256 Name.
fn parse_tpm_name(field: &str, hex: &str) -> Result<Vec<u8>> {
    let bytes = parse_hex(hex)
        .ok_or_else(|| Error::Policy(format!("hkdfguard policy: {field} is not valid hex")))?;
    if bytes.len() != SHA256_TPM_NAME_LEN {
        return Err(Error::Policy(format!(
            "hkdfguard policy: {field} is {} bytes, expected {SHA256_TPM_NAME_LEN} (a SHA-256 TPM Name)",
            bytes.len()
        )));
    }
    Ok(bytes)
}

// Decodes a policy-supplied KEK fingerprint (SHA-256, so 32 bytes).
fn parse_kek_fingerprint(field: &str, hex: &str) -> Result<[u8; FINGERPRINT_LEN]> {
    let bytes = parse_hex(hex)
        .ok_or_else(|| Error::Policy(format!("hkdfguard policy: {field} is not valid hex")))?;
    bytes.as_slice().try_into().map_err(|_| {
        Error::Policy(format!(
            "hkdfguard policy: {field} is {} bytes, expected {FINGERPRINT_LEN} (a SHA-256 KEK fingerprint)",
            bytes.len()
        ))
    })
}

// Decodes an even-length hex string. Returns `None` on any non-hex
// character or odd length.
fn parse_hex(s: &str) -> Option<Vec<u8>> {
    // Works on bytes, never on `&str` slices: slicing at an odd byte
    // offset panics if a multi-byte character straddles it, and a policy
    // file is not trusted to be ASCII. Digits are decoded one by one,
    // because `u8::from_str_radix` would also accept a leading `+`.
    let digit = |b: u8| (b as char).to_digit(16);
    let s = s.trim().as_bytes();
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    let (pairs, _) = s.as_chunks::<2>(); // even length, so nothing is left over
    pairs.iter().map(|&[hi, lo]| Some((digit(hi)? << 4 | digit(lo)?) as u8)).collect()
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRequirements {
    minimum_protection: Option<KeyProtectionLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSelection {
    mode: SelectionModeTag,
    provider: Option<ProviderType>,
    level: Option<KeyProtectionLevel>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum SelectionModeTag {
    Require,
    RequireLevel,
    Prefer,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupBehavior {
    // Accepted for schema/Windows-policy-vocabulary compatibility, but
    // currently a no-op either way: this crate always fails closed (design
    // goal #6 -- "no automatic downgrades occur" is unconditional, not an
    // opt-in), so there's no non-fail-closed startup mode to switch off
    // yet. Kept as a real, validated field rather than silently accepted
    // so a future graceful-startup mode has somewhere to land without a
    // schema change.
    #[serde(default = "default_true")]
    #[allow(dead_code)]
    fail_if_requirement_unmet: bool,
    // Minimum wall-clock duration of every `hkdfguard_create_kek` and
    // `hkdfguard_kek_exists` call, in milliseconds (default
    // `DEFAULT_SETUP_MIN_DELAY_MS`; `0` disables the floor). See
    // `setup_min_delay` for what this is for.
    setup_min_delay_ms: Option<u64>,
}

fn default_true() -> bool {
    true
}

impl Default for StartupBehavior {
    fn default() -> Self {
        StartupBehavior {
            fail_if_requirement_unmet: true,
            setup_min_delay_ms: None,
        }
    }
}

/// Default floor on the duration of each setup call (`hkdfguard_create_kek`
/// / `hkdfguard_kek_exists`) when the policy doesn't say otherwise.
pub const DEFAULT_SETUP_MIN_DELAY_MS: u64 = 1_000;

/// Largest `setup_min_delay_ms` a policy may set. A root-controlled policy
/// could legitimately want a long floor, but a typo (one zero too many)
/// shouldn't be able to turn application startup into a multi-hour hang;
/// anything above this is rejected as a validation error rather than
/// honored.
pub const MAX_SETUP_MIN_DELAY_MS: u64 = 60_000;

// ---------------------------------------------------------------------
// Validated policy.
// ---------------------------------------------------------------------

/// A validated selection mode -- the parsed, cross-checked form of
/// [`RawSelection`] (e.g. `require` is guaranteed to carry a `provider`,
/// never a stray `level`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionMode {
    /// Only this exact provider may be used; no fallback.
    Require(ProviderType),
    /// Any provider at or above this assurance tier may be used.
    RequireLevel(KeyProtectionLevel),
    /// Try providers in preference order; first available wins.
    Prefer,
}

/// Trait-based abstraction over policy evaluation, so provider-selection
/// code (`provider::allowed_chain`) depends on this interface rather than
/// [`Policy`]'s concrete fields.
pub trait PolicyEvaluator {
    /// Given every provider type compiled into this build, in the default
    /// priority order, returns the subset policy currently allows, in the
    /// order they should be tried. An empty result (not an error) means
    /// the policy is well-formed but nothing compiled into this build
    /// currently qualifies -- callers should fail closed on that, exactly
    /// as they would on a chain that was merely unreachable at runtime.
    fn allowed_providers(&self, compiled: &[ProviderType]) -> Result<Vec<ProviderType>>;
}

/// A fully parsed and cross-validated policy file.
#[derive(Debug, Clone)]
pub struct Policy {
    security_model: SecurityModel,
    deployer_groups: Vec<String>,
    selection: SelectionMode,
    minimum_protection: Option<KeyProtectionLevel>,
    preferred_order: Vec<ProviderType>,
    setup_min_delay: Duration,
    require_tpm_pinned_names: bool,
    /// Normalized service name -> expected TPM Name bytes.
    pinned_tpm_names: BTreeMap<String, Vec<u8>>,
    tpm_session_encryption: SessionEncryption,
    pinned_session_salt_key_name: Option<Vec<u8>>,
    tpm_tcti: Option<String>,
    tpm_key_dir: Option<PathBuf>,
    tpm_owner_auth_file: Option<PathBuf>,
    external_secret_dir: Option<PathBuf>,
    require_external_pinned_keys: bool,
    /// Normalized service name -> every KEK fingerprint accepted for it.
    pinned_external_keys: BTreeMap<String, Vec<[u8; FINGERPRINT_LEN]>>,
    pkcs11: Pkcs11Settings,
    audit_unwrap_success: bool,
}

impl Policy {
    /// Parses and validates a policy document from a string (the TOML
    /// text itself, not a path) -- kept separate from file I/O so tests
    /// can exercise every schema/validation rule without touching disk or
    /// environment variables.
    ///
    /// TOML rather than YAML: it has one way to write each value (no
    /// implicit `off`/`no` booleans, no anchors or aliases to expand), its
    /// parser is a maintained, Rust-native crate, and a misplaced key is a
    /// hard error here rather than a silent reinterpretation -- every
    /// table is `deny_unknown_fields`, so a top-level key written below a
    /// `[table]` header lands inside that table and is rejected.
    pub fn from_toml_str(doc: &str) -> Result<Policy> {
        let raw: PolicyFile = toml::from_str(doc)
            .map_err(|e| Error::Policy(format!("invalid hkdfguard policy: {e}")))?;
        Self::validate(raw)
    }

    fn validate(raw: PolicyFile) -> Result<Policy> {
        let selection = match raw.selection.mode {
            SelectionModeTag::Require => {
                let provider = raw.selection.provider.ok_or_else(|| {
                    Error::Policy(
                        "hkdfguard policy: selection.mode \"require\" needs a selection.provider"
                            .to_string(),
                    )
                })?;
                if raw.selection.level.is_some() {
                    return Err(Error::Policy(
                        "hkdfguard policy: selection.mode \"require\" must not also set selection.level"
                            .to_string(),
                    ));
                }
                SelectionMode::Require(provider)
            }
            SelectionModeTag::RequireLevel => {
                let level = raw.selection.level.ok_or_else(|| {
                    Error::Policy(
                        "hkdfguard policy: selection.mode \"require-level\" needs a selection.level"
                            .to_string(),
                    )
                })?;
                if raw.selection.provider.is_some() {
                    return Err(Error::Policy(
                        "hkdfguard policy: selection.mode \"require-level\" must not also set selection.provider"
                            .to_string(),
                    ));
                }
                SelectionMode::RequireLevel(level)
            }
            SelectionModeTag::Prefer => {
                if raw.selection.provider.is_some() || raw.selection.level.is_some() {
                    return Err(Error::Policy(
                        "hkdfguard policy: selection.mode \"prefer\" must not set selection.provider or selection.level"
                            .to_string(),
                    ));
                }
                SelectionMode::Prefer
            }
        };

        let minimum_protection = raw.key_requirements.minimum_protection;

        // A "require this exact provider" policy that names a provider
        // below the stated minimum protection is self-contradictory --
        // reject it now rather than let it silently produce an always-
        // empty allowed list at evaluation time.
        if let (SelectionMode::Require(p), Some(min)) = (selection, minimum_protection) {
            if p.protection_level() < min {
                return Err(Error::Policy(format!(
                    "hkdfguard policy: selection requires provider \"{}\" ({}), below key_requirements.minimum_protection ({})",
                    p.policy_name(),
                    p.protection_level().as_str(),
                    min.as_str()
                )));
            }
        }

        let mut seen = Vec::new();
        for p in &raw.preferred_order {
            if seen.contains(p) {
                return Err(Error::Policy(format!(
                    "hkdfguard policy: preferred_order lists \"{}\" more than once",
                    p.policy_name()
                )));
            }
            seen.push(*p);
        }

        for (i, group) in raw.deployer_groups.iter().enumerate() {
            validate_group_name(group)?;
            if raw.deployer_groups[..i].contains(group) {
                return Err(Error::Policy(format!("hkdfguard policy: deployer_groups lists \"{group}\" more than once")));
            }
        }

        let setup_min_delay_ms = raw
            .startup_behavior
            .setup_min_delay_ms
            .unwrap_or(DEFAULT_SETUP_MIN_DELAY_MS);
        if setup_min_delay_ms > MAX_SETUP_MIN_DELAY_MS {
            return Err(Error::Policy(format!(
                "hkdfguard policy: startup_behavior.setup_min_delay_ms is {setup_min_delay_ms}, above the {MAX_SETUP_MIN_DELAY_MS} ms maximum"
            )));
        }

        // Pinned TPM Names: decode and length-check every entry up front,
        // so a typo surfaces as a policy error at load time rather than as
        // a mysterious provider failure on the first wrap. Service keys go
        // through the same normalization the FFI layer applies, so a
        // policy written with a differently-cased name still matches.
        let mut pinned_tpm_names = BTreeMap::new();
        for (service, hex) in &raw.tpm.pinned_names {
            let bytes = parse_tpm_name(&format!("tpm.pinned_names[\"{service}\"]"), hex)?;
            if pinned_tpm_names
                .insert(crate::normalize_service(service), bytes)
                .is_some()
            {
                return Err(Error::Policy(format!(
                    "hkdfguard policy: tpm.pinned_names lists \"{service}\" more than once (names are compared case-insensitively)"
                )));
            }
        }

        let pinned_session_salt_key_name = raw
            .tpm
            .pinned_session_salt_key_name
            .as_deref()
            .map(|hex| parse_tpm_name("tpm.pinned_session_salt_key_name", hex))
            .transpose()?;

        if let Some(tcti) = &raw.tpm.tcti {
            validate_tcti(tcti)?;
        }
        let tpm_key_dir = raw.tpm.key_dir.as_deref().map(|d| absolute_path("tpm.key_dir", d)).transpose()?;
        let tpm_owner_auth_file = raw
            .tpm
            .owner_auth_file
            .as_deref()
            .map(|f| absolute_path("tpm.owner_auth_file", f))
            .transpose()?;

        let external_secret_dir = raw
            .external_secret
            .dir
            .as_deref()
            .map(|d| absolute_path("external_secret.dir", d))
            .transpose()?;
        // Pinned external-secret fingerprints: decoded and checked up front,
        // with service keys normalized, as for the TPM pins above.
        let mut pinned_external_keys = BTreeMap::new();
        for (service, pins) in &raw.external_secret.pinned_keys {
            let field = format!("external_secret.pinned_keys[\"{service}\"]");
            let hexes = match pins {
                PinnedKeys::One(hex) => std::slice::from_ref(hex),
                PinnedKeys::Several(hexes) => hexes.as_slice(),
            };
            if hexes.is_empty() {
                return Err(Error::Policy(format!(
                    "hkdfguard policy: {field} is an empty list; remove the entry to unpin the service"
                )));
            }
            let mut fingerprints = Vec::with_capacity(hexes.len());
            for hex in hexes {
                let fingerprint = parse_kek_fingerprint(&field, hex)?;
                if fingerprints.contains(&fingerprint) {
                    return Err(Error::Policy(format!("hkdfguard policy: {field} lists the same fingerprint more than once")));
                }
                fingerprints.push(fingerprint);
            }
            if pinned_external_keys
                .insert(crate::normalize_service(service), fingerprints)
                .is_some()
            {
                return Err(Error::Policy(format!(
                    "hkdfguard policy: external_secret.pinned_keys lists \"{service}\" more than once (names are compared case-insensitively)"
                )));
            }
        }
        let pkcs11 = Pkcs11Settings {
            module: raw.pkcs11.module.as_deref().map(|m| absolute_path("pkcs11.module", m)).transpose()?,
            pin_file: raw.pkcs11.pin_file.as_deref().map(|f| absolute_path("pkcs11.pin_file", f)).transpose()?,
            token_label: raw.pkcs11.token_label.as_deref().map(|l| token_field("pkcs11.token_label", l, 32)).transpose()?,
            token_serial: raw.pkcs11.token_serial.as_deref().map(|n| token_field("pkcs11.token_serial", n, 16)).transpose()?,
        };

        Ok(Policy {
            security_model: raw.security_model,
            deployer_groups: raw.deployer_groups,
            selection,
            minimum_protection,
            preferred_order: raw.preferred_order,
            setup_min_delay: Duration::from_millis(setup_min_delay_ms),
            require_tpm_pinned_names: raw.tpm.require_pinned_names,
            pinned_tpm_names,
            tpm_session_encryption: raw.tpm.session_encryption,
            pinned_session_salt_key_name,
            tpm_tcti: raw.tpm.tcti,
            tpm_key_dir,
            tpm_owner_auth_file,
            external_secret_dir,
            require_external_pinned_keys: raw.external_secret.require_pinned_keys,
            pinned_external_keys,
            pkcs11,
            audit_unwrap_success: raw.audit.unwrap_success,
        })
    }

    /// The security model (`security_model`); Production unless set.
    pub fn security_model(&self) -> SecurityModel {
        self.security_model
    }

    /// The policy's deployer groups (`deployer_groups`), besides
    /// `hkdfguard-deployers`; consulted under the production model only.
    pub fn deployer_groups(&self) -> &[String] {
        &self.deployer_groups
    }

    /// The Owner-hierarchy authorization file (`tpm.owner_auth_file`), if policy sets one.
    pub fn tpm_owner_auth_file(&self) -> Option<&std::path::Path> {
        self.tpm_owner_auth_file.as_deref()
    }

    /// TPM session parameter-encryption mode (`tpm.session_encryption`).
    pub fn tpm_session_encryption(&self) -> SessionEncryption {
        self.tpm_session_encryption
    }

    /// The external-secret directory (`external_secret.dir`), if policy sets one.
    pub fn external_secret_dir(&self) -> Option<&std::path::Path> {
        self.external_secret_dir.as_deref()
    }

    /// Whether the external-secret provider treats only pinned services as
    /// provisioned (`external_secret.require_pinned_keys`).
    pub fn require_external_pinned_keys(&self) -> bool {
        self.require_external_pinned_keys
    }

    /// The KEK fingerprints policy accepts for `service`'s external secret,
    /// if it pins any.
    pub fn pinned_external_keys(&self, service: &str) -> Option<&[[u8; FINGERPRINT_LEN]]> {
        self.pinned_external_keys
            .get(&crate::normalize_service(service))
            .map(|v| v.as_slice())
    }

    /// The PKCS#11 settings (`[pkcs11]`).
    pub fn pkcs11(&self) -> &Pkcs11Settings {
        &self.pkcs11
    }

    /// The TCTI the TPM provider must use (`tpm.tcti`), if policy sets one.
    pub fn tpm_tcti(&self) -> Option<&str> {
        self.tpm_tcti.as_deref()
    }

    /// The TPM key-file directory (`tpm.key_dir`), if policy sets one.
    pub fn tpm_key_dir(&self) -> Option<&std::path::Path> {
        self.tpm_key_dir.as_deref()
    }

    /// The administrator-pinned Name of the session salt key, if any.
    pub fn pinned_session_salt_key_name(&self) -> Option<&[u8]> {
        self.pinned_session_salt_key_name.as_deref()
    }

    /// The floor on how long each setup call (`hkdfguard_create_kek`,
    /// `hkdfguard_kek_exists`) takes -- see the module-level
    /// [`setup_min_delay`] for why it exists.
    pub fn setup_min_delay(&self) -> Duration {
        self.setup_min_delay
    }

    /// Whether a successful unwrap is audited (`audit.unwrap_success`) --
    /// see the module-level [`audit_unwrap_success`].
    pub fn audit_unwrap_success(&self) -> bool {
        self.audit_unwrap_success
    }

    /// Whether the TPM provider treats only pinned services as provisioned
    /// (`tpm.require_pinned_names`).
    pub fn require_tpm_pinned_names(&self) -> bool {
        self.require_tpm_pinned_names
    }

    /// The administrator-pinned TPM Name for `service`, if policy sets one.
    pub fn pinned_tpm_name(&self, service: &str) -> Option<&[u8]> {
        self.pinned_tpm_names
            .get(&crate::normalize_service(service))
            .map(|v| v.as_slice())
    }

    /// Whether Ephemeral is explicitly named by this policy: either as the
    /// sole provider under `require`, or listed by name in
    /// `preferred_order`. This is the *only* way Ephemeral is ever
    /// reachable -- see [`PolicyEvaluator::allowed_providers`] -- since its
    /// keys live only in process memory and are permanently lost on
    /// restart; assuming it's disallowed unless an operator specifically
    /// named it is the safer default than an opt-out flag someone could
    /// forget to set (or that could default the wrong way in a future
    /// schema change).
    fn ephemeral_explicitly_listed(&self) -> bool {
        self.selection == SelectionMode::Require(ProviderType::Ephemeral)
            || self.preferred_order.contains(&ProviderType::Ephemeral)
    }

    // The order candidates are considered in before the mode/level/
    // minimum-protection/ephemeral filters below are applied: the
    // configured `preferred_order` (restricted to what's actually
    // compiled in, preserving its relative order), or -- if none was
    // given -- the default compiled-in priority order verbatim.
    fn candidate_order(&self, compiled: &[ProviderType]) -> Vec<ProviderType> {
        if self.preferred_order.is_empty() {
            compiled.to_vec()
        } else {
            self.preferred_order
                .iter()
                .copied()
                .filter(|p| compiled.contains(p))
                .collect()
        }
    }
}

impl PolicyEvaluator for Policy {
    fn allowed_providers(&self, compiled: &[ProviderType]) -> Result<Vec<ProviderType>> {
        let mut candidates = match self.selection {
            SelectionMode::Require(provider) => {
                if !compiled.contains(&provider) {
                    return Err(Error::Policy(format!(
                        "hkdfguard policy requires provider \"{}\", but it is not compiled into this build",
                        provider.policy_name()
                    )));
                }
                vec![provider]
            }
            SelectionMode::RequireLevel(level) => self
                .candidate_order(compiled)
                .into_iter()
                .filter(|p| p.protection_level() >= level)
                .collect(),
            SelectionMode::Prefer => self.candidate_order(compiled),
        };

        if let Some(min) = self.minimum_protection {
            candidates.retain(|p| p.protection_level() >= min);
        }

        // Ephemeral is dropped from every result unless the policy
        // explicitly named it -- see `ephemeral_explicitly_listed`'s doc
        // comment. This applies regardless of mode: a `require-level`
        // policy whose level happens to be low enough to admit Ephemeral
        // by tier still doesn't get it unless it's actually named.
        if !self.ephemeral_explicitly_listed() {
            candidates.retain(|p| *p != ProviderType::Ephemeral);
        }

        Ok(candidates)
    }
}

/// Largest policy file accepted. Far above any realistic policy; exists so
/// a huge (or endless) file can't be used to exhaust memory.
const MAX_POLICY_FILE_LEN: usize = 64 * 1024;

/// What the policy file must satisfy before it's trusted: owned by root
/// (see [`crate::secure_file::config_owner`]) and not writable by anyone
/// else -- a policy the service itself could edit wouldn't be a policy.
/// Symlinks are followed (e.g. Kubernetes ConfigMap mounts are symlinks),
/// but the checks apply to the file actually opened, not the link.
const POLICY_FILE_REQUIREMENTS: crate::secure_file::FileRequirements = crate::secure_file::FileRequirements {
    owner: Some(crate::secure_file::config_owner()),
    forbidden_mode_bits: crate::secure_file::FORBID_GROUP_OTHER_WRITE,
    follow_symlinks: true,
    allow_group_read_if_root_owned: false, // already allowed: only write bits are forbidden
};

/// Reads and parses the configured policy file, if one is present.
///
/// Returns:
/// - `None` **only** if no file exists at the configured path. Every
///   compiled-in provider except Ephemeral is then allowed, in the default
///   priority order (see `provider::allowed_chain`).
/// - `Some(Ok(policy))` if a policy file was found, passed its ownership
///   and permission checks, and is valid.
/// - `Some(Err(_))` in every other case -- the file exists but can't be
///   read (permission denied, it's a directory, an I/O error), is owned by
///   someone untrusted or writable by group/others, is too large, isn't
///   UTF-8, or is malformed or self-contradictory; or the directory it
///   lives in (or would live in), or any directory above it, is one
///   someone untrusted could change: owned by someone else, or writable by
///   group or others -- sticky (`/tmp`-style) or not -- unless it is on a
///   read-only mount (see [`crate::secure_file::check_dir_chain`]).
///   This **fails closed**: every wrap/unwrap/create/exists call fails
///   rather than falling back to the unrestricted default. Making the file
///   unreadable, or deleting it, must never be a way to switch policy off.
///
/// Re-read from disk on every C ABI call, so an operator can update the
/// policy without restarting the process -- but only once per call: within
/// a call, every reader gets the snapshot [`snapshot_for_call`] took (see
/// there for why).
pub fn load() -> Option<Result<Policy>> {
    if let Some(snapshot) = SNAPSHOT.with(|s| s.borrow().clone()) {
        return snapshot.map(|r| r.map_err(Error::Policy));
    }
    read_from_disk()
}

/// The policy as one C ABI call sees it: `None` for no file, else the
/// parsed policy or the reason it was refused (every refusal is an
/// `Error::Policy`, so its message is all there is to keep).
type Snapshot = Option<std::result::Result<Policy, String>>;

thread_local! {
    /// The snapshot in force on this thread, while a C ABI call holds a
    /// [`SnapshotGuard`]. Thread-local because a call runs entirely on the
    /// caller's thread, and concurrent calls on other threads must each
    /// get their own read.
    static SNAPSHOT: std::cell::RefCell<Option<Snapshot>> = const { std::cell::RefCell::new(None) };
}

/// Keeps a policy snapshot in force on this thread until dropped.
pub(crate) struct SnapshotGuard {
    /// Whether this guard took the snapshot (and so clears it). A nested
    /// guard -- `hkdfguard_generate_and_wrap_dek` running through the wrap
    /// path -- leaves the outer one's snapshot alone.
    owns: bool,
}

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        if self.owns {
            SNAPSHOT.with(|s| *s.borrow_mut() = None);
        }
    }
}

/// Reads the policy file once and makes that reading the one every
/// [`load`] on this thread returns until the guard drops.
///
/// Without this, a single call would read the file several times -- the
/// provider chain, each provider's settings, the TPM's pins and session
/// mode, the setup floor -- and a root edit landing mid-call (or an editor
/// that writes the file non-atomically) could give one operation two
/// different policies: say, the chain from the old file and the TPM pins
/// from the new one. A snapshot makes every decision in a call come from one
/// version of the file.
pub(crate) fn snapshot_for_call() -> SnapshotGuard {
    SNAPSHOT.with(|s| {
        if s.borrow().is_some() {
            return SnapshotGuard { owns: false };
        }
        let snapshot: Snapshot = read_from_disk().map(|r| {
            r.map_err(|e| match e {
                Error::Policy(msg) => msg,
                other => other.to_string(),
            })
        });
        *s.borrow_mut() = Some(snapshot);
        SnapshotGuard { owns: true }
    })
}

/// Reads and validates the policy file itself; see [`load`] for what each
/// outcome means.
fn read_from_disk() -> Option<Result<Policy>> {
    let path = policy_file_path();
    let fail = |what: String| Some(Err(Error::Policy(format!("hkdfguard policy file {}: {what}", path.display()))));

    if let Err(e) = crate::secure_file::check_location(&path, crate::secure_file::config_owner()) {
        return fail(format!("refusing to trust its location ({e})"));
    }
    let mut file = match crate::secure_file::open_checked(&path, &POLICY_FILE_REQUIREMENTS) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return fail(format!("refusing to use it ({e})")),
    };
    let contents = match crate::secure_file::SecretBuffer::read_from(&mut file, MAX_POLICY_FILE_LEN) {
        Ok(c) => c,
        Err(e) => return fail(format!("could not be read ({e})")),
    };
    let text = match std::str::from_utf8(contents.as_slice()) {
        Ok(t) => t,
        Err(_) => return fail("is not valid UTF-8".to_string()),
    };

    Some(Policy::from_toml_str(text).map_err(|e| match e {
        Error::Policy(msg) => Error::Policy(format!("{} ({})", msg, path.display())),
        other => other,
    }))
}

/// The floor on the wall-clock duration of every `hkdfguard_create_kek` and
/// `hkdfguard_kek_exists` call: [`DEFAULT_SETUP_MIN_DELAY_MS`] unless the
/// policy file sets `startup_behavior.setup_min_delay_ms`.
///
/// Those two calls are meant to run once per application startup, so
/// making each take at least a second costs nothing a caller should
/// notice and buys several things at once: it bounds how fast a buggy or
/// hot-looping caller can drive the TPM/HSM (each call is a fresh
/// connection plus a key derivation -- see `provider::construct_provider`),
/// and bounds Ephemeral key-map growth to one entry per second. It's a
/// floor on *latency*, not just spacing between calls, so "exists" and
/// "doesn't exist" take the same time as well. It is not a secrecy
/// control: `wrap` is ungated (it's the hot path) and reports
/// `KEK_NOT_FOUND` immediately, so whether a service has a key is never
/// hidden from anything that can call the library -- service names are
/// public identifiers.
///
/// A policy file that exists but is invalid still yields the default here
/// -- the call that's being gated is about to fail closed on that same
/// policy anyway, and there's no reason to let a broken policy also remove
/// the floor. Read from disk on every call, like everything else in this
/// module.
pub(crate) fn setup_min_delay() -> Duration {
    match load() {
        Some(Ok(policy)) => policy.setup_min_delay(),
        Some(Err(_)) | None => Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS),
    }
}

/// Whether a successful unwrap writes audit event 1003
/// (`audit.unwrap_success`). `true` unless a valid policy explicitly sets
/// it `false`: no policy file, a policy that doesn't mention it, and one
/// that is present but invalid all keep it on -- a broken policy must
/// never be what silently reduces auditing.
pub(crate) fn audit_unwrap_success() -> bool {
    match load() {
        Some(Ok(policy)) => policy.audit_unwrap_success(),
        Some(Err(_)) | None => true,
    }
}

/// The administrator-pinned TPM Name for `service`, if any.
///
/// This is the part of Name checking that actually resists substitution.
/// A TPM Name is `nameAlg || H(publicArea)` -- a *public* function of the
/// public area -- so verifying that a reported Name matches its own
/// reported public area (which the TPM2 provider also does) only catches
/// a non-conformant stack or corruption, not an active man-in-the-middle,
/// who could simply recompute a matching Name. Comparing against a value
/// an administrator recorded out-of-band, in the root-owned policy file,
/// is what makes substitution detectable.
///
/// `Err` when a policy file exists but can't be trusted -- pinning must
/// fail closed rather than silently degrade to "nothing pinned".
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn pinned_tpm_name(service: &str) -> Result<Option<Vec<u8>>> {
    match load() {
        Some(Ok(policy)) => Ok(policy.pinned_tpm_name(service).map(|n| n.to_vec())),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// Whether the TPM provider only serves services whose Name is pinned
/// (`tpm.require_pinned_names`). No policy file → `false`. A policy file
/// that exists but is invalid → `true`: a broken policy must never be what
/// widens the set of services the TPM will serve.
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn require_tpm_pinned_names() -> bool {
    match load() {
        Some(Ok(policy)) => policy.require_tpm_pinned_names(),
        Some(Err(_)) => true,
        None => false,
    }
}

/// TPM session parameter-encryption mode. `On` unless a valid policy
/// file sets `off`: a broken policy must never be what turns bus
/// protection off.
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn tpm_session_encryption() -> SessionEncryption {
    match load() {
        Some(Ok(policy)) => policy.tpm_session_encryption(),
        Some(Err(_)) | None => SessionEncryption::On,
    }
}

/// The TCTI policy requires (`tpm.tcti`), if any. `Err` on a policy file
/// that exists but can't be trusted: the TPM is then unavailable rather
/// than opened at a default the administrator may have meant to avoid.
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn tpm_tcti() -> Result<Option<String>> {
    match load() {
        Some(Ok(policy)) => Ok(policy.tpm_tcti().map(str::to_owned)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// The TPM key-file directory policy names (`tpm.key_dir`), if any. `Err`
/// on a policy file that exists but can't be trusted: the TPM provider then
/// fails rather than reading or writing keys at the default directory.
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn tpm_key_dir() -> Result<Option<PathBuf>> {
    match load() {
        Some(Ok(policy)) => Ok(policy.tpm_key_dir().map(std::path::Path::to_path_buf)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// The Owner-hierarchy authorization file policy names
/// (`tpm.owner_auth_file`), if any. `Err` on a policy file that exists but
/// can't be trusted: the TPM is then refused rather than tried with an
/// empty owner password the administrator may have replaced.
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn tpm_owner_auth_file() -> Result<Option<PathBuf>> {
    match load() {
        Some(Ok(policy)) => Ok(policy.tpm_owner_auth_file().map(std::path::Path::to_path_buf)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// The external-secret directory policy requires (`external_secret.dir`),
/// if any. `Err` on a policy file that exists but can't be trusted, so the
/// provider is unavailable rather than searching the default mounts.
#[cfg_attr(not(feature = "external-secret"), allow(dead_code))]
pub(crate) fn external_secret_dir() -> Result<Option<PathBuf>> {
    match load() {
        Some(Ok(policy)) => Ok(policy.external_secret_dir().map(std::path::Path::to_path_buf)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// The KEK fingerprints policy accepts for `service`'s external secret
/// (`external_secret.pinned_keys`), if any.
///
/// The mount checks in the external-secret provider establish *who* could
/// have written the file -- root, this service's user, or anything with a
/// read-write mount of the same volume (a sidecar, a shared `emptyDir`) --
/// not *which* key it holds. Any of those writers can put a well-formed
/// key of its own there, in time for the first `provision` or wrap. A
/// fingerprint recorded when the key was generated, in the root-owned
/// policy, is what makes that substitution detectable.
///
/// `Err` when a policy file exists but can't be trusted -- pinning must
/// fail closed rather than silently degrade to "nothing pinned".
#[cfg_attr(not(feature = "external-secret"), allow(dead_code))]
pub(crate) fn pinned_external_keys(service: &str) -> Result<Option<Vec<[u8; FINGERPRINT_LEN]>>> {
    match load() {
        Some(Ok(policy)) => Ok(policy.pinned_external_keys(service).map(<[_]>::to_vec)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// Whether the external-secret provider only serves services whose key is
/// pinned (`external_secret.require_pinned_keys`). No policy file →
/// `false`. A policy file that exists but is invalid → `true`: a broken
/// policy must never be what widens the set of keys the provider accepts.
#[cfg_attr(not(feature = "external-secret"), allow(dead_code))]
pub(crate) fn require_external_pinned_keys() -> bool {
    match load() {
        Some(Ok(policy)) => policy.require_external_pinned_keys(),
        Some(Err(_)) => true,
        None => false,
    }
}

/// The PKCS#11 settings from policy (all unset with no policy file). `Err`
/// on a policy file that exists but can't be trusted.
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
pub(crate) fn pkcs11_settings() -> Result<Pkcs11Settings> {
    match load() {
        Some(Ok(policy)) => Ok(policy.pkcs11().clone()),
        Some(Err(e)) => Err(e),
        None => Ok(Pkcs11Settings::default()),
    }
}

/// The pinned storage-root-key Name (`tpm.pinned_session_salt_key_name`), if policy sets one. `Err` on a
/// policy file that exists but can't be trusted -- pinning fails closed.
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn pinned_session_salt_key_name() -> Result<Option<Vec<u8>>> {
    match load() {
        Some(Ok(policy)) => Ok(policy.pinned_session_salt_key_name().map(|n| n.to_vec())),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// Test-only: a policy that explicitly names Ephemeral in
/// `preferred_order` (alongside `external-secret`, so tests that also need
/// that provider to remain a candidate still get it) -- the same explicit
/// naming a real deployment needs, since with no policy at all (or one that
/// never names it) Ephemeral is excluded (see `provider::allowed_chain` and
/// [`Policy::ephemeral_explicitly_listed`]). In force while the returned
/// guard lives.
#[cfg(test)]
pub(crate) fn allow_ephemeral_policy_for_tests() -> test_support::TestPolicy {
    test_support::TestPolicy::write("preferred_order = [\"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n")
}

/// Test-only: a policy pinning provider selection to `provider` (the policy
/// vocabulary's name, e.g. `external-secret`), in force while the returned
/// guard lives.
///
/// Any test whose subject is one *specific* provider must pin it this
/// way rather than relying on stronger providers being absent. With the
/// `tpm2` or `pkcs11` features compiled in and a real (or simulated)
/// device reachable, the priority chain selects TPM2/PKCS#11 first, and
/// a test that assumed external-secret would win either fails or -- much
/// worse -- silently stops exercising the thing it is named after.
#[cfg(test)]
pub(crate) fn require_provider_policy_for_tests(provider: &str) -> test_support::TestPolicy {
    test_support::TestPolicy::write(&format!("[selection]\nmode = \"require\"\nprovider = \"{provider}\"\n"))
}

/// Per-test policy files. See [`TestPolicy`].
#[cfg(test)]
pub(crate) mod test_support {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// Tables a layered policy merges key by key; every other top-level key
    /// (`[selection]` above all) is replaced whole, so a test's selection is
    /// never a blend of its own and the harness's.
    const MERGED_TABLES: &[&str] = &["tpm", "pkcs11", "external_secret"];

    struct Layer {
        path: PathBuf,
        /// `None`: this layer is "no policy file at all".
        table: Option<toml::Table>,
    }

    /// Live `TestPolicy` layers, innermost last. Tests that touch policy
    /// are `#[serial]`, so one stack serves the whole test binary.
    static LAYERS: Mutex<Vec<Layer>> = Mutex::new(Vec::new());

    fn layers() -> std::sync::MutexGuard<'static, Vec<Layer>> {
        LAYERS.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn active_path() -> Option<PathBuf> {
        layers().last().map(|l| l.path.clone())
    }

    // What a new layer is merged onto: the innermost live layer, or with
    // none, the harness's policy (HKDFGUARD_POLICY_FILE: which TPM and key
    // directory, which PKCS#11 token this machine's test run uses).
    fn base() -> toml::Table {
        if let Some(layer) = layers().last() {
            return layer.table.clone().unwrap_or_default();
        }
        std::env::var_os("HKDFGUARD_POLICY_FILE")
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|text| text.parse::<toml::Table>().expect("the harness policy (HKDFGUARD_POLICY_FILE) is not valid TOML"))
            .unwrap_or_default()
    }

    /// A real policy file for the duration of one test: written into a
    /// private temp directory, read by the library through exactly the
    /// production path (ownership, location, and parse checks included),
    /// and removed -- with the library pointed back at whatever was in
    /// force before -- when the guard drops. Guards nest; drop them in
    /// reverse order of creation, as Rust does for locals.
    pub(crate) struct TestPolicy {
        _dir: tempfile::TempDir, // removed, with the policy file in it, when the guard drops
        depth: usize,
    }

    impl TestPolicy {
        /// `doc` layered over the policy already in force: the tables in
        /// `MERGED_TABLES` merge key by key, `doc` winning; any other
        /// top-level key `doc` sets replaces the old one whole. With no
        /// `[selection]` anywhere, `mode = "prefer"` is added, which selects
        /// exactly as having no policy file does; with no `security_model`,
        /// `"developer"` is.
        pub(crate) fn write(doc: &str) -> Self {
            let mut merged = base();
            let layer: toml::Table = doc.parse().unwrap_or_else(|e| panic!("TestPolicy::write: invalid TOML ({e}); use TestPolicy::exact for a malformed policy:\n{doc}"));
            for (key, value) in layer {
                match (merged.get_mut(&key), value) {
                    (Some(toml::Value::Table(old)), toml::Value::Table(new)) if MERGED_TABLES.contains(&key.as_str()) => old.extend(new),
                    (_, value) => {
                        merged.insert(key, value);
                    }
                }
            }
            if !merged.contains_key("selection") {
                let mut selection = toml::Table::new();
                selection.insert("mode".into(), toml::Value::String("prefer".into()));
                merged.insert("selection".into(), toml::Value::Table(selection));
            }
            // Unit tests run as an ordinary user whose temp files are its
            // own, which only the developer model trusts; a test of the
            // production model says so. `exact` and `absent` add nothing.
            if !merged.contains_key("security_model") {
                merged.insert("security_model".into(), toml::Value::String("developer".into()));
            }
            let text = toml::to_string(&merged).expect("a merged policy serializes");
            Self::push(&text, Some(merged))
        }

        /// Exactly `contents`, merged with nothing -- for malformed,
        /// oversized, or otherwise deliberately broken policies.
        pub(crate) fn exact(contents: impl AsRef<[u8]>) -> Self {
            Self::push(contents, None)
        }

        /// Whatever is at `path` -- for tests of how the loader treats a
        /// directory, an unreadable file, or a file they manage themselves.
        pub(crate) fn at(path: &Path) -> Self {
            Self::stack(crate::secure_file::private_tempdir(), Layer { path: path.to_path_buf(), table: None })
        }

        /// No policy file at all.
        pub(crate) fn absent() -> Self {
            let dir = crate::secure_file::private_tempdir();
            let path = dir.path().join("no-policy.toml");
            Self::stack(dir, Layer { path, table: None })
        }

        fn push(contents: impl AsRef<[u8]>, table: Option<toml::Table>) -> Self {
            let dir = crate::secure_file::private_tempdir();
            let path = dir.path().join("policy.toml");
            crate::secure_file::write_world_readable_for_tests(&path, contents);
            Self::stack(dir, Layer { path, table: table.or(Some(toml::Table::new())) })
        }

        fn stack(dir: tempfile::TempDir, layer: Layer) -> Self {
            let mut layers = layers();
            layers.push(layer);
            TestPolicy { _dir: dir, depth: layers.len() }
        }
    }

    /// Points the external-secret provider at `dir` (`external_secret.dir`),
    /// layered over the policy in force.
    pub(crate) fn secret_mount(dir: &Path) -> TestPolicy {
        TestPolicy::write(&format!("[external_secret]\ndir = \"{}\"\n", dir.display()))
    }

    impl Drop for TestPolicy {
        fn drop(&mut self) {
            let mut layers = layers();
            // Out-of-order drops can only come from a guard kept beyond its
            // scope; unwinding everything above it keeps the stack sane.
            layers.truncate(self.depth - 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::TestPolicy;

    fn compiled(types: &[ProviderType]) -> Vec<ProviderType> {
        types.to_vec()
    }

    // ---- KeyProtectionLevel / ProviderType mapping ----

    #[test]
    fn protection_level_ordering_is_ascending() {
        assert!(KeyProtectionLevel::Ephemeral < KeyProtectionLevel::Software);
        assert!(KeyProtectionLevel::Software < KeyProtectionLevel::External);
        assert!(KeyProtectionLevel::External < KeyProtectionLevel::Hardware);
    }

    #[test]
    fn provider_protection_level_mapping() {
        assert_eq!(ProviderType::Tpm2.protection_level(), KeyProtectionLevel::Hardware);
        assert_eq!(ProviderType::Pkcs11.protection_level(), KeyProtectionLevel::Hardware);
        assert_eq!(ProviderType::ExternalSecret.protection_level(), KeyProtectionLevel::External);
        assert_eq!(ProviderType::Ephemeral.protection_level(), KeyProtectionLevel::Ephemeral);
    }

    #[test]
    fn provider_names_parse_per_policy_vocabulary() {
        let doc = "preferred_order = [\"tpm2\", \"pkcs11\", \"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        assert_eq!(
            policy.preferred_order,
            vec![
                ProviderType::Tpm2,
                ProviderType::Pkcs11,
                ProviderType::ExternalSecret,
                ProviderType::Ephemeral,
            ]
        );
    }

    #[test]
    fn unknown_provider_name_is_rejected() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"quantum-vault\"\n";
        assert!(Policy::from_toml_str(doc).is_err());
    }

    // ---- Require mode ----

    #[test]
    fn require_tpm_success() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::Tpm2, ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::Tpm2]);
    }

    #[test]
    fn require_tpm_failure_when_not_compiled_in() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        // TPM2 simply isn't part of this build -- policy must refuse to
        // silently substitute anything else.
        let err = policy
            .allowed_providers(&compiled(&[ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap_err();
        assert!(matches!(err, Error::Policy(_)));
    }

    // ---- Require-level mode ----

    #[test]
    fn require_hardware_success_via_tpm() {
        let doc = "[selection]\nmode = \"require-level\"\nlevel = \"hardware\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::Tpm2, ProviderType::ExternalSecret]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::Tpm2]);
    }

    #[test]
    fn require_hardware_success_via_pkcs11() {
        let doc = "[selection]\nmode = \"require-level\"\nlevel = \"hardware\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::Pkcs11, ProviderType::ExternalSecret]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::Pkcs11]);
    }

    #[test]
    fn require_hardware_failure_with_only_external_secret() {
        let doc = "[selection]\nmode = \"require-level\"\nlevel = \"hardware\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        // Not an Err here (the policy itself is fine) -- an empty allowed
        // list, which is what makes the actual selection chain fail
        // closed downstream.
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap();
        assert_eq!(allowed, Vec::<ProviderType>::new());
    }

    #[test]
    fn require_level_accepts_both_hardware_providers_together() {
        let doc = "[selection]\nmode = \"require-level\"\nlevel = \"hardware\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[
                ProviderType::Tpm2,
                ProviderType::Pkcs11,
                ProviderType::ExternalSecret,
                ProviderType::Ephemeral,
            ]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::Tpm2, ProviderType::Pkcs11]);
    }

    // ---- Prefer mode ----

    #[test]
    fn prefer_mode_fallback_ordering() {
        let doc = "preferred_order = [\"tpm2\", \"pkcs11\", \"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        // Only ephemeral and external-secret are actually compiled into
        // this build; the allowed order must still reflect
        // preferred_order's relative ordering, not the default
        // all_providers() order.
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::Ephemeral, ProviderType::ExternalSecret]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::ExternalSecret, ProviderType::Ephemeral]);
    }

    #[test]
    fn prefer_mode_without_preferred_order_uses_default_compiled_order() {
        // Deliberately uses two non-Ephemeral providers: this test is
        // about the fallback-to-compiled-order behavior specifically, kept
        // separate from Ephemeral's own always-excluded-unless-named rule
        // (covered by `ephemeral_disallowed_by_default_even_without_preferred_order`).
        let doc = "[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::Tpm2, ProviderType::ExternalSecret]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::Tpm2, ProviderType::ExternalSecret]);
    }

    // ---- Minimum protection ----

    #[test]
    fn minimum_protection_enforcement() {
        let doc = "[key_requirements]\nminimum_protection = \"external\"\n[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[
                ProviderType::ExternalSecret,
                ProviderType::Ephemeral,
            ]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::ExternalSecret]);
    }

    #[test]
    fn minimum_protection_external_rejects_ephemeral_only_build() {
        let doc = "[key_requirements]\nminimum_protection = \"external\"\n[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy.allowed_providers(&compiled(&[ProviderType::Ephemeral])).unwrap();
        assert_eq!(allowed, Vec::<ProviderType>::new());
    }

    // ---- Ephemeral / container policy ----

    #[test]
    fn ephemeral_disallowed_by_default() {
        let doc = "[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::ExternalSecret]);
    }

    #[test]
    fn ephemeral_allowed_when_explicitly_named() {
        let doc = "preferred_order = [\"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::ExternalSecret, ProviderType::Ephemeral]);
    }

    #[test]
    fn container_policy_is_not_a_policy_table() {
        // `[container_policy]` is not part of the schema, so a policy that
        // sets `max_ephemeral_lifetime_seconds` fails to load instead of
        // implying a lifetime limit that nothing enforces.
        // (Ephemeral keys live only as long as the process; its
        // gate is `preferred_order` naming it, see
        // `Policy::ephemeral_explicitly_listed`.)
        for doc in [
            "[selection]\nmode = \"prefer\"\n[container_policy]\nmax_ephemeral_lifetime_seconds = 3600\n",
            "[selection]\nmode = \"prefer\"\n[container_policy]\nallow_ephemeral = true\n",
        ] {
            let err = Policy::from_toml_str(doc).expect_err(doc);
            assert!(err.to_string().contains("container_policy"), "unexpected error: {err}");
        }
    }

    // ---- Invalid configuration rejection ----

    #[test]
    fn invalid_configuration_rejection() {
        let cases = [
            // require without a provider
            "[selection]\nmode = \"require\"\n",
            // require-level without a level
            "[selection]\nmode = \"require-level\"\n",
            // require with a stray level field
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\nlevel = \"hardware\"\n",
            // require-level with a stray provider field
            "[selection]\nmode = \"require-level\"\nlevel = \"hardware\"\nprovider = \"tpm2\"\n",
            // prefer with a stray provider field
            "[selection]\nmode = \"prefer\"\nprovider = \"tpm2\"\n",
            // unknown selection mode
            "[selection]\nmode = \"strongly-suggest\"\n",
            // unknown top-level field (typo)
            "preferred_ordr = [\"tpm2\"]\n[selection]\nmode = \"prefer\"\n",
            // duplicate entries in preferred_order
            "preferred_order = [\"tpm2\", \"tpm2\"]\n[selection]\nmode = \"prefer\"\n",
            // the unsupported [container_policy] table (see
            // container_policy_is_not_a_policy_table)
            "[selection]\nmode = \"prefer\"\n[container_policy]\nmax_ephemeral_lifetime_seconds = 3600\n",
            // require a provider below the stated minimum protection
            "[key_requirements]\nminimum_protection = \"hardware\"\n[selection]\nmode = \"require\"\nprovider = \"external-secret\"\n",
            // not valid TOML at all
            "not = [valid, toml",
            // a top-level key written below a table header belongs to that
            // table in TOML -- here `selection.preferred_order` -- and must
            // be rejected, not silently dropped
            "[selection]\nmode = \"prefer\"\npreferred_order = [\"tpm2\"]\n",
            // a duplicate key
            "[selection]\nmode = \"prefer\"\nmode = \"require\"\n",
            // missing the required `selection` section entirely
            "[key_requirements]\nminimum_protection = \"hardware\"\n",
        ];
        for (i, doc) in cases.iter().enumerate() {
            assert!(Policy::from_toml_str(doc).is_err(), "case {i} should have been rejected: {doc}");
        }
    }

    #[test]
    fn require_ephemeral_succeeds_since_naming_it_under_require_is_itself_explicit() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"ephemeral\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy.allowed_providers(&compiled(&[ProviderType::Ephemeral])).unwrap();
        assert_eq!(allowed, vec![ProviderType::Ephemeral]);
    }

    #[test]
    fn require_level_does_not_admit_ephemeral_even_when_its_tier_qualifies() {
        // require-level: ephemeral means "ephemeral tier or above", i.e.
        // every provider -- but Ephemeral itself is still excluded unless
        // separately named in preferred_order, since qualifying by tier
        // is not the same as being explicitly listed.
        let doc = "[selection]\nmode = \"require-level\"\nlevel = \"ephemeral\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::ExternalSecret]);

        // Naming it in preferred_order admits it, same as `prefer` mode.
        let doc_named = "preferred_order = [\"ephemeral\", \"external-secret\"]\n[selection]\nmode = \"require-level\"\nlevel = \"ephemeral\"\n";
        let policy_named = Policy::from_toml_str(doc_named).unwrap();
        let allowed_named = policy_named
            .allowed_providers(&compiled(&[ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap();
        assert_eq!(allowed_named, vec![ProviderType::Ephemeral, ProviderType::ExternalSecret]);
    }

    // ---- startup_behavior.setup_min_delay_ms ----

    #[test]
    fn setup_min_delay_defaults_to_one_second_when_absent() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        assert_eq!(policy.setup_min_delay(), Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS));

        // Also when startup_behavior is present but doesn't mention it.
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nfail_if_requirement_unmet = true\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        assert_eq!(policy.setup_min_delay(), Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS));
    }

    #[test]
    fn setup_min_delay_is_read_from_the_policy() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = 2500\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        assert_eq!(policy.setup_min_delay(), Duration::from_millis(2500));
    }

    #[test]
    fn setup_min_delay_can_be_disabled_with_zero() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = 0\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        assert_eq!(policy.setup_min_delay(), Duration::ZERO);
    }

    #[test]
    fn setup_min_delay_above_the_cap_is_rejected() {
        let doc = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = {}\n",
            MAX_SETUP_MIN_DELAY_MS + 1
        );
        assert!(Policy::from_toml_str(&doc).is_err());

        // ...and the cap itself is still accepted.
        let doc = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = {MAX_SETUP_MIN_DELAY_MS}\n"
        );
        assert_eq!(
            Policy::from_toml_str(&doc).unwrap().setup_min_delay(),
            Duration::from_millis(MAX_SETUP_MIN_DELAY_MS)
        );
    }

    #[test]
    fn setup_min_delay_rejects_negative_and_non_integer_values() {
        for bad in ["-1", "1.5", "\"1000\"", "fast"] {
            let doc = format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = {bad}\n");
            assert!(Policy::from_toml_str(&doc).is_err(), "{bad} should not parse as a delay");
        }
    }

    #[test]
    #[serial_test::serial]
    fn setup_min_delay_helper_uses_the_default_without_a_policy_file() {
        let _no_policy = TestPolicy::absent();
        let delay = setup_min_delay();
        assert_eq!(delay, Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS));
    }

    #[test]
    #[serial_test::serial]
    fn setup_min_delay_helper_reads_the_configured_file() {
        let _policy = TestPolicy::write("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = 42\n");
        let delay = setup_min_delay();
        assert_eq!(delay, Duration::from_millis(42));
    }

    #[test]
    #[serial_test::serial]
    fn setup_min_delay_helper_keeps_the_default_when_the_policy_is_broken() {
        // A malformed policy must not become a way to remove the floor
        // (the gated call fails closed on the same policy regardless).
        let _policy = TestPolicy::exact("[selection]\nmode = \"require\"\n[startup_behavior]\nsetup_min_delay_ms = 0\n");
        let delay = setup_min_delay();
        assert_eq!(delay, Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS));
    }

    // ---- tpm.key_dir / tpm.pinned_names ----

    const A_NAME: &str = "000b0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    #[test]
    fn tpm_section_defaults_to_the_default_key_dir_and_no_pins() {
        let base = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n";
        let policy = Policy::from_toml_str(base).unwrap();
        assert!(policy.tpm_key_dir().is_none(), "no [tpm] table: the provider's default directory");
        assert!(!policy.require_tpm_pinned_names(), "the allowlist must be opt-in");
        assert_eq!(policy.pinned_tpm_name("com.company.orders"), None);

        let doc = format!("{base}[tpm]\nkey_dir = \"/srv/hkdfguard/tpm\"\n");
        assert_eq!(Policy::from_toml_str(&doc).unwrap().tpm_key_dir(), Some(std::path::Path::new("/srv/hkdfguard/tpm")));
    }

    #[test]
    fn a_relative_tpm_key_dir_is_rejected() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nkey_dir = \"var/lib/hkdfguard/tpm\"\n";
        let err = Policy::from_toml_str(doc).unwrap_err().to_string();
        assert!(err.contains("tpm.key_dir") && err.contains("absolute"), "{err}");
    }

    #[test]
    fn the_removed_derivation_secret_settings_are_rejected() {
        // TPM keys are key files now; a policy still naming the old
        // derivation secret is refused rather than silently ignored.
        for key in ["derivation_secret_file = \"/etc/hkdfguard/tpm.derivation-secret\"", "require_derivation_secret = true"] {
            let doc = format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\n{key}\n");
            assert!(Policy::from_toml_str(&doc).is_err(), "{key}");
        }
    }

    #[test]
    fn tpm_require_pinned_names_is_read() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_pinned_names = true\n";
        assert!(Policy::from_toml_str(doc).unwrap().require_tpm_pinned_names());
    }

    #[test]
    fn require_pinned_names_with_no_pins_is_a_valid_policy() {
        // The first step of rolling the allowlist out: turn it on, then run
        // `provision` for each service to learn the Name to pin. Every TPM
        // service is refused until then, which is the point.
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_pinned_names = true\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        assert!(policy.require_tpm_pinned_names());
        assert_eq!(policy.pinned_tpm_name("com.company.orders"), None);
    }

    #[test]
    fn pinned_name_is_decoded_and_matched_case_insensitively() {
        let doc = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\n\"com.company.Orders\" = \"{A_NAME}\"\n"
        );
        let policy = Policy::from_toml_str(&doc).unwrap();

        let pinned = policy.pinned_tpm_name("com.company.orders").expect("pin should be present");
        assert_eq!(pinned.len(), SHA256_TPM_NAME_LEN);
        assert_eq!(&pinned[..2], &[0x00, 0x0B], "the TPM_ALG_SHA256 prefix must survive decoding");
        assert_eq!(pinned[2], 0x01);
        assert_eq!(pinned[SHA256_TPM_NAME_LEN - 1], 0x20);

        // The policy key was written with a capital O; lookup normalizes.
        assert_eq!(policy.pinned_tpm_name("COM.COMPANY.ORDERS"), Some(pinned));
        // An unpinned service stays unpinned.
        assert_eq!(policy.pinned_tpm_name("com.company.billing"), None);
    }

    #[test]
    fn pinned_name_rejects_bad_hex_and_wrong_length() {
        for bad in [
            "nothex",                    // not hex at all
            "000b01",                    // hex, but far too short
            "000b0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021", // one byte too long
            "000b0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2",    // odd length
        ] {
            let doc = format!(
                "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\n\"com.company.orders\" = \"{bad}\"\n"
            );
            assert!(
                Policy::from_toml_str(&doc).is_err(),
                "{bad} must be rejected as a pinned TPM Name"
            );
        }
    }

    #[test]
    fn pinned_names_reject_an_unquoted_dotted_service_name() {
        // In TOML an unquoted `com.company.orders = ...` is a dotted key --
        // nested tables `com` -> `company` -> `orders` -- not one key
        // containing dots. That must fail to parse rather than quietly pin
        // nothing, which would leave the service unpinned (and, under
        // require_pinned_names, unprovisioned) with no error to say why.
        let doc = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\ncom.company.orders = \"{A_NAME}\"\n"
        );
        assert!(Policy::from_toml_str(&doc).is_err(), "an unquoted dotted key must be rejected");

        let quoted = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\n\"com.company.orders\" = \"{A_NAME}\"\n"
        );
        assert!(Policy::from_toml_str(&quoted).unwrap().pinned_tpm_name("com.company.orders").is_some());
    }

    #[test]
    fn pinned_names_reject_a_duplicate_after_normalization() {
        let doc = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\n\"com.company.orders\" = \"{A_NAME}\"\n\"com.company.ORDERS\" = \"{A_NAME}\"\n"
        );
        assert!(Policy::from_toml_str(&doc).is_err(), "two keys differing only in case must be rejected");
    }

    #[test]
    fn tpm_tcti_is_read_and_validated() {
        let base = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n";
        assert_eq!(Policy::from_toml_str(base).unwrap().tpm_tcti(), None, "unset by default");

        for ok in ["device:/dev/tpmrm0", "device", "tabrmd:bus_type=system", "mssim:host=localhost,port=2321", "swtpm:port=2321"] {
            let doc = format!("{base}[tpm]\ntcti = \"{ok}\"\n");
            assert_eq!(Policy::from_toml_str(&doc).unwrap().tpm_tcti(), Some(ok), "{ok}");
        }
        for bad in ["", "libtss2-tcti-evil.so", "/tmp/evil.so", "cmd:sh", "devices:/dev/tpm0"] {
            let doc = format!("{base}[tpm]\ntcti = \"{bad}\"\n");
            assert!(Policy::from_toml_str(&doc).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn tpm_owner_auth_file_is_read_and_must_be_absolute() {
        let base = "[selection]\nmode = \"prefer\"\n";
        assert_eq!(Policy::from_toml_str(base).unwrap().tpm_owner_auth_file(), None);

        let policy = Policy::from_toml_str(&format!("{base}[tpm]\nowner_auth_file = \"/etc/hkdfguard/tpm.owner-auth\"\n")).unwrap();
        assert_eq!(policy.tpm_owner_auth_file(), Some(std::path::Path::new("/etc/hkdfguard/tpm.owner-auth")));

        assert!(
            Policy::from_toml_str(&format!("{base}[tpm]\nowner_auth_file = \"tpm.owner-auth\"\n")).is_err(),
            "a relative owner_auth_file must be rejected"
        );
    }

    #[test]
    #[serial_test::serial]
    fn a_snapshot_pins_one_reading_of_the_policy_for_the_whole_call() {
        let first = TestPolicy::write("[selection]\nmode = \"prefer\"\n[startup_behavior]\nsetup_min_delay_ms = 10\n");
        let guard = snapshot_for_call();

        // The file changes mid-call (a root edit, or a non-atomic write).
        drop(first);
        let _second = TestPolicy::write("[selection]\nmode = \"prefer\"\n[startup_behavior]\nsetup_min_delay_ms = 20\n");
        assert_eq!(setup_min_delay(), Duration::from_millis(10), "every reader in the call must see the snapshot");

        // A nested guard (generate_and_wrap running the wrap path) neither
        // re-reads nor ends the outer snapshot.
        drop(snapshot_for_call());
        assert_eq!(setup_min_delay(), Duration::from_millis(10), "a nested guard must not clear the outer snapshot");

        // The next call reads the file afresh.
        drop(guard);
        assert_eq!(setup_min_delay(), Duration::from_millis(20), "after the call, the policy is read from disk again");
    }

    #[test]
    #[serial_test::serial]
    fn a_refused_policy_stays_refused_through_the_snapshot() {
        let _bad = TestPolicy::write("[selection]\nmode = \"no-such-mode\"\n");
        let _guard = snapshot_for_call();
        for _ in 0..2 {
            match load() {
                Some(Err(Error::Policy(msg))) => assert!(msg.contains("invalid hkdfguard policy"), "unexpected: {msg}"),
                other => panic!("a malformed policy must stay refused within the call, got {other:?}"),
            }
        }
    }

    #[test]
    fn external_secret_and_pkcs11_sections_are_read_and_validated() {
        let base = "[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(base).unwrap();
        assert_eq!(policy.external_secret_dir(), None);
        assert_eq!(policy.pkcs11(), &Pkcs11Settings::default());

        let doc = format!(
            "{base}[external_secret]\ndir = \"/srv/secrets/hkdfguard\"\n\
             [pkcs11]\nmodule = \"/usr/lib/vendor/libhsm.so\"\npin_file = \"/etc/hkdfguard/hsm.pin\"\n\
             token_label = \"prod-kek\"\ntoken_serial = \"0123456789abcdef\"\n"
        );
        let policy = Policy::from_toml_str(&doc).unwrap();
        assert_eq!(policy.external_secret_dir(), Some(std::path::Path::new("/srv/secrets/hkdfguard")));
        assert_eq!(
            policy.pkcs11(),
            &Pkcs11Settings {
                module: Some(PathBuf::from("/usr/lib/vendor/libhsm.so")),
                pin_file: Some(PathBuf::from("/etc/hkdfguard/hsm.pin")),
                token_label: Some("prod-kek".into()),
                token_serial: Some("0123456789abcdef".into()),
            }
        );

        for bad in [
            "[external_secret]\ndir = \"relative/dir\"\n",
            "[pkcs11]\nmodule = \"libsofthsm2.so\"\n",
            "[pkcs11]\npin_file = \"pkcs11.pin\"\n",
            "[pkcs11]\ntoken_label = \"\"\n",
            "[pkcs11]\ntoken_label = \"this label is far too long for a pkcs11 token\"\n",
            "[pkcs11]\ntoken_serial = \"0123456789abcdef0\"\n",
            "[pkcs11]\nslot = 0\n",
            "[external_secret]\npath = \"/x\"\n",
        ] {
            assert!(Policy::from_toml_str(&format!("{base}{bad}")).is_err(), "{bad:?} must be rejected");
        }
    }

    // ---- external_secret.pinned_keys / external_secret.require_pinned_keys ----

    const A_FINGERPRINT: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const B_FINGERPRINT: &str = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";

    #[test]
    fn external_pins_default_to_none_and_the_allowlist_to_off() {
        let policy = Policy::from_toml_str("[selection]\nmode = \"prefer\"\n[external_secret]\ndir = \"/run/secrets/hkdfguard\"\n").unwrap();
        assert!(!policy.require_external_pinned_keys(), "the allowlist must be opt-in");
        assert_eq!(policy.pinned_external_keys("com.company.orders"), None);

        let policy = Policy::from_toml_str("[selection]\nmode = \"prefer\"\n[external_secret]\nrequire_pinned_keys = true\n").unwrap();
        assert!(policy.require_external_pinned_keys(), "on with no pins yet: the first step of rolling it out");
    }

    #[test]
    fn external_pins_take_one_fingerprint_or_a_list_and_match_case_insensitively() {
        let doc = format!(
            "[selection]\nmode = \"prefer\"\n[external_secret.pinned_keys]\n\"com.company.Orders\" = \"{A_FINGERPRINT}\"\n\
             \"com.company.billing\" = [\"{A_FINGERPRINT}\", \"{}\"]\n",
            B_FINGERPRINT.to_ascii_uppercase()
        );
        let policy = Policy::from_toml_str(&doc).unwrap();

        let orders = policy.pinned_external_keys("COM.COMPANY.ORDERS").expect("pinned");
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0][0], 0x01);
        assert_eq!(orders[0][FINGERPRINT_LEN - 1], 0x20);

        let billing = policy.pinned_external_keys("com.company.billing").expect("pinned");
        assert_eq!(billing.len(), 2, "both halves of a rotation");
        assert_eq!(billing[1][0], 0x21, "upper-case hex decodes too");

        assert_eq!(policy.pinned_external_keys("com.company.other"), None);
    }

    #[test]
    fn external_pins_reject_malformed_entries() {
        for entry in [
            "\"com.company.orders\" = \"nothex\"".to_string(),
            "\"com.company.orders\" = \"0102\"".to_string(), // too short
            format!("\"com.company.orders\" = \"{A_FINGERPRINT}21\""), // one byte too long
            format!("\"com.company.orders\" = \"{A_FINGERPRINT}\"\n\"com.company.ORDERS\" = \"{B_FINGERPRINT}\""), // duplicate after normalization
            format!("\"com.company.orders\" = [\"{A_FINGERPRINT}\", \"{A_FINGERPRINT}\"]"), // same fingerprint twice
            "\"com.company.orders\" = []".to_string(),
            "\"com.company.orders\" = 7".to_string(),
            format!("com.company.orders = \"{A_FINGERPRINT}\""), // unquoted: a dotted key, nested tables
        ] {
            let doc = format!("[selection]\nmode = \"prefer\"\n[external_secret.pinned_keys]\n{entry}\n");
            assert!(Policy::from_toml_str(&doc).is_err(), "{entry:?} must be rejected");
        }
    }

    #[test]
    #[serial_test::serial]
    fn external_pin_helpers_without_a_policy_file_and_with_a_broken_one() {
        {
            let _no_policy = TestPolicy::absent();
            assert!(!require_external_pinned_keys(), "no policy must not make the provider refuse every service");
            assert_eq!(pinned_external_keys("com.company.orders").unwrap(), None);
        }
        let _broken = TestPolicy::exact("[selection]\nmode = \"require\"\n"); // missing `provider`
        assert!(require_external_pinned_keys(), "a broken policy must fail closed to the allowlist");
        assert!(pinned_external_keys("com.company.orders").is_err(), "a broken policy must not report 'nothing pinned'");
    }

    #[test]
    fn unknown_key_in_the_tpm_section_is_rejected() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_drivation_secret = true\n"; // typo
        assert!(Policy::from_toml_str(doc).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn tpm_helpers_without_a_policy_file() {
        let _no_policy = TestPolicy::absent();
        let key_dir = tpm_key_dir();
        let allowlist = require_tpm_pinned_names();
        let pinned = pinned_tpm_name("com.company.orders");
        assert_eq!(key_dir.unwrap(), None, "no policy: the provider's default directory");
        assert!(!allowlist, "no policy must not silently make the TPM refuse every service");
        assert_eq!(pinned.unwrap(), None);
    }

    #[test]
    #[serial_test::serial]
    fn tpm_helpers_fail_closed_on_a_broken_policy() {
        // A policy that can't be parsed must not be the reason a security
        // control is skipped: the allowlist applies, and the key directory
        // and pin lookups error rather than reporting defaults.
        let _policy = TestPolicy::exact("[selection]\nmode = \"require\"\n"); // missing `provider`
        let key_dir = tpm_key_dir();
        let allowlist = require_tpm_pinned_names();
        let pinned = pinned_tpm_name("com.company.orders");
        assert!(key_dir.is_err(), "a broken policy must not mean the default key directory");
        assert!(allowlist, "a broken policy must fail closed to the allowlist");
        assert!(pinned.is_err(), "a broken policy must not report 'nothing pinned'");
    }

    #[test]
    #[serial_test::serial]
    fn tpm_helpers_read_the_configured_file() {
        let _policy = TestPolicy::write(&format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nkey_dir = \"/srv/tpm-keys\"\n[tpm.pinned_names]\n\"com.company.orders\" = \"{A_NAME}\"\n"));
        let key_dir = tpm_key_dir();
        let pinned = pinned_tpm_name("com.company.orders");
        let unpinned = pinned_tpm_name("com.company.billing");

        assert_eq!(key_dir.unwrap(), Some(PathBuf::from("/srv/tpm-keys")));
        assert_eq!(pinned.unwrap().unwrap().len(), SHA256_TPM_NAME_LEN);
        assert_eq!(unpinned.unwrap(), None);
    }

    #[test]
    fn a_non_ascii_pinned_name_is_a_policy_error_not_a_panic() {
        // 68 bytes, even, with a two-byte character straddling the first
        // two-byte step: a `&str`-slicing decoder would panic here.
        let name = format!("a{}0", "é".repeat(33));
        for doc in [
            format!("[selection]\nmode = \"prefer\"\n[tpm]\npinned_session_salt_key_name = \"{name}\"\n"),
            format!("[selection]\nmode = \"prefer\"\n[tpm.pinned_names]\n\"com.company.orders\" = \"{name}\"\n"),
        ] {
            let err = Policy::from_toml_str(&doc).expect_err("a non-hex Name must be refused");
            assert!(err.to_string().contains("not valid hex"), "unexpected error: {err}");
        }
    }

    #[test]
    fn parse_hex_round_trips_and_rejects_malformed_input() {
        assert_eq!(parse_hex("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert_eq!(parse_hex("00FF10").unwrap(), vec![0x00, 0xff, 0x10], "uppercase hex must decode");
        assert_eq!(parse_hex("  00ff10  ").unwrap(), vec![0x00, 0xff, 0x10], "surrounding whitespace is trimmed");
        assert!(parse_hex("").is_none());
        assert!(parse_hex("0").is_none());
        assert!(parse_hex("0g").is_none());
        assert!(parse_hex("00 ff").is_none(), "interior whitespace is not hex");
        assert!(parse_hex("+f").is_none(), "a sign is not a hex digit");
        // Non-ASCII must be refused, not panic: "aé0" is four bytes, and
        // a two-byte step lands inside the "é".
        for non_ascii in ["aé0", "é0", "€0", "00ｆｆ"] {
            assert!(parse_hex(non_ascii).is_none(), "{non_ascii:?}");
        }
    }

    // ---- tpm.session_encryption / tpm.pinned_session_salt_key_name ----

    #[test]
    fn session_encryption_defaults_to_on_with_no_pin() {
        let policy = Policy::from_toml_str("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n").unwrap();
        assert_eq!(policy.tpm_session_encryption(), SessionEncryption::On);
        assert_eq!(policy.pinned_session_salt_key_name(), None);
    }

    #[test]
    fn session_encryption_modes_parse() {
        for (text, expected) in [("on", SessionEncryption::On), ("off", SessionEncryption::Off)] {
            let doc = format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"{text}\"\n");
            assert_eq!(Policy::from_toml_str(&doc).unwrap().tpm_session_encryption(), expected, "{text}");
        }
        // "auto" and "required" were the pre-authValue modes; neither means
        // anything now, so a policy still naming one is refused, not guessed at.
        for removed in ["sometimes", "auto", "required"] {
            let doc = format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"{removed}\"\n");
            assert!(Policy::from_toml_str(&doc).is_err(), "{removed} must be rejected");
        }
    }

    #[test]
    fn a_pinned_salt_key_needs_no_particular_mode() {
        for mode in ["on", "off"] {
            let doc = format!(
                "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"{mode}\"\npinned_session_salt_key_name = \"{A_NAME}\"\n"
            );
            let policy = Policy::from_toml_str(&doc).unwrap();
            assert_eq!(policy.pinned_session_salt_key_name().unwrap().len(), SHA256_TPM_NAME_LEN);
        }
    }

    #[test]
    fn pinned_salt_key_name_is_validated_like_other_names() {
        for bad in ["nothex", "000b01"] {
            let doc = format!(
                "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\npinned_session_salt_key_name = \"{bad}\"\n"
            );
            assert!(Policy::from_toml_str(&doc).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    #[serial_test::serial]
    fn session_encryption_helpers_fail_closed() {
        // No policy: on, nothing pinned.
        let _no_policy = TestPolicy::absent();
        let mode = tpm_session_encryption();
        let pin = pinned_session_salt_key_name();
        assert_eq!(mode, SessionEncryption::On);
        assert_eq!(pin.unwrap(), None);

        // Broken policy: on (never "off"), and pinning errors.
        let _policy = TestPolicy::exact("[selection]\nmode = \"require\"\n[tpm]\nsession_encryption = \"off\"\n");
        let mode = tpm_session_encryption();
        let pin = pinned_session_salt_key_name();
        assert_eq!(mode, SessionEncryption::On, "a broken policy must not turn bus protection off");
        assert!(pin.is_err());
    }

    // ---- load() / file-path behavior ----

    #[test]
    fn security_model_defaults_to_production_and_reads_either_value() {
        let base = "[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(base).unwrap();
        assert_eq!(policy.security_model(), SecurityModel::Production);
        assert!(policy.deployer_groups().is_empty());
        for (text, model) in [("production", SecurityModel::Production), ("developer", SecurityModel::Developer)] {
            let policy = Policy::from_toml_str(&format!("security_model = \"{text}\"\n{base}")).unwrap();
            assert_eq!(policy.security_model(), model, "{text}");
        }
    }

    #[test]
    fn an_unknown_or_misplaced_security_model_is_an_invalid_policy() {
        let base = "[selection]\nmode = \"prefer\"\n";
        for doc in [
            format!("security_model = \"development\"\n{base}"), // the Windows name is "developer"
            format!("security_model = \"Production\"\n{base}"),
            format!("security_model = 1\n{base}"),
            // Below a table header, the key belongs to that table, which rejects it.
            format!("{base}security_model = \"developer\"\n"),
        ] {
            assert!(matches!(Policy::from_toml_str(&doc), Err(Error::Policy(_))), "{doc}");
        }
    }

    #[test]
    fn deployer_groups_must_be_distinct_group_names() {
        let base = "[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(&format!("deployer_groups = [\"payments-deploy\", \"ops_keys\"]\n{base}")).unwrap();
        assert_eq!(policy.deployer_groups(), ["payments-deploy", "ops_keys"]);
        for groups in ["[\"\"]", "[\"1001\"]", "[\"a b\"]", "[\"a:b\"]", "[\"a,b\"]", "[\"../x\"]", "[\"ops\", \"ops\"]", "\"ops\""] {
            let doc = format!("deployer_groups = {groups}\n{base}");
            assert!(matches!(Policy::from_toml_str(&doc), Err(Error::Policy(_))), "{groups}");
        }
    }

    #[test]
    #[serial_test::serial]
    fn load_returns_none_when_no_policy_file_is_configured() {
        let _no_policy = TestPolicy::absent();
        assert!(load().is_none());
    }

    #[test]
    #[serial_test::serial]
    fn load_reads_and_validates_the_configured_file() {
        let _policy = TestPolicy::write("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n");

        match load() {
            Some(Ok(policy)) => {
                assert_eq!(policy.selection, SelectionMode::Require(ProviderType::Tpm2));
            }
            other => panic!("expected Some(Ok(_)), got {other:?}"),
        }

    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_on_a_malformed_file() {
        let _policy = TestPolicy::exact("[selection]\nmode = \"require\"\n"); // missing required `provider`

        match load() {
            Some(Err(Error::Policy(_))) => {}
            other => panic!("expected Some(Err(Error::Policy(_))), got {other:?}"),
        }

    }

    // Points the policy at `path` and asserts load() fails closed
    // (Some(Err)) rather than treating the file as absent (None).
    fn assert_load_fails_closed(path: &std::path::Path, why: &str) {
        let _policy = TestPolicy::at(path);
        let result = load();
        match result {
            Some(Err(Error::Policy(_))) => {}
            other => panic!("{why}: expected Some(Err(Error::Policy(_))) (fail closed), got {other:?}"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_on_an_unreadable_file() {
        if crate::secure_file::skip_as_root() {
            return; // root can read a mode-000 file, so this scenario can't be set up
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert_load_fails_closed(&path, "a present-but-unreadable policy must not disable policy");
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_when_path_is_a_directory() {
        let dir = crate::secure_file::private_tempdir();
        assert_load_fails_closed(dir.path(), "a directory at the policy path must not disable policy");
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_on_a_group_or_world_writable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert_load_fails_closed(&path, "a group-writable policy must be rejected");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o646)).unwrap();
        assert_load_fails_closed(&path, "a world-writable policy must be rejected");
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_when_others_could_replace_or_delete_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(&path, "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_load_fails_closed(&path, "a policy in a world-writable directory could be swapped out");

        // Absent is "no policy" only where nobody untrusted could have deleted it.
        std::fs::remove_file(&path).unwrap();
        assert_load_fails_closed(&path, "deleting the policy must not be a way to switch it off");

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let _policy = TestPolicy::at(&path);
        let absent = load();
        assert!(absent.is_none(), "in a trusted directory, a missing policy is just no policy");
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_under_a_sticky_ancestor_present_or_absent() {
        use std::os::unix::fs::PermissionsExt;
        // A private 0700 directory inside a /tmp-style (1777) one: others
        // can create entries beside it, so neither the policy nor its
        // absence can be trusted there, however private the directory.
        let base = crate::secure_file::private_tempdir();
        let private = base.path().join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = private.join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(&path, "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n");
        {
            let _policy = TestPolicy::at(&path);
            assert!(matches!(load(), Some(Ok(_))), "a private chain is fine");
        }

        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        for present in [true, false] {
            if !present {
                std::fs::remove_file(&path).unwrap();
            }
            let _policy = TestPolicy::at(&path);
            match load() {
                Some(Err(Error::Policy(msg))) => assert!(msg.contains("sticky"), "present={present}: says why: {msg}"),
                other => panic!("present={present}: expected Some(Err(Error::Policy(..sticky..))), got {other:?}"),
            }
        }
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_on_an_oversized_file() {
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(&path, vec![b'#'; MAX_POLICY_FILE_LEN + 1]);
        assert_load_fails_closed(&path, "an oversized policy must be rejected, not truncated");
    }

    // ---- packaging/policy.toml.example ----

    const EXAMPLE_POLICY: &str = include_str!("../packaging/policy.toml.example");

    #[test]
    fn shipped_example_policy_behaves_like_no_policy() {
        // The packages install the example for administrators to copy to
        // /etc/hkdfguard/policy.toml. Copied unedited, it must change
        // nothing: the same chain as `provider::allowed_types` with no
        // policy, and every knob at its default.
        let policy = Policy::from_toml_str(EXAMPLE_POLICY).unwrap();
        let all = [ProviderType::Tpm2, ProviderType::Pkcs11, ProviderType::ExternalSecret, ProviderType::Ephemeral];
        assert_eq!(
            policy.allowed_providers(&all).unwrap(),
            vec![ProviderType::Tpm2, ProviderType::Pkcs11, ProviderType::ExternalSecret]
        );
        assert_eq!(policy.setup_min_delay(), Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS));
        assert!(!policy.require_tpm_pinned_names());
        assert!(policy.pinned_tpm_name("com.company.orders").is_none());
        assert_eq!(policy.tpm_session_encryption(), SessionEncryption::On);
        assert!(policy.pinned_session_salt_key_name().is_none());
        assert!(policy.tpm_tcti().is_none());
        assert!(policy.tpm_key_dir().is_none());
        assert!(policy.tpm_owner_auth_file().is_none());
        assert!(policy.external_secret_dir().is_none());
        assert_eq!(policy.pkcs11(), &Pkcs11Settings::default());
    }

    #[test]
    fn overlay_dev_policy_prefers_softhsm_then_ephemeral() {
        // packaging/overlay/policy.dev.toml, which the overlay-dev image
        // installs as /etc/hkdfguard/policy.toml.
        let policy = Policy::from_toml_str(include_str!("../packaging/overlay/policy.dev.toml")).unwrap();
        let all = [ProviderType::Tpm2, ProviderType::Pkcs11, ProviderType::ExternalSecret, ProviderType::Ephemeral];
        assert_eq!(policy.allowed_providers(&all).unwrap(), vec![ProviderType::Pkcs11, ProviderType::Ephemeral]);
        let pkcs11 = policy.pkcs11();
        assert_eq!(pkcs11.module.as_deref(), Some(std::path::Path::new("/usr/lib/softhsm/libsofthsm2.so")));
        assert_eq!(pkcs11.pin_file.as_deref(), Some(std::path::Path::new("/etc/hkdfguard/pkcs11.pin")));
        assert_eq!(pkcs11.token_label.as_deref(), Some("hkdfguard"));
    }

    #[test]
    fn the_policies_in_docs_configuration_md_are_valid() {
        // docs/configuration.md is what operators copy from. Every complete
        // example policy there must validate as written (placeholder TPM
        // Names and KEK fingerprints swapped for well-formed ones); every other block with a
        // [selection] -- the reference, which lists every key at once --
        // must at least be valid TOML using only known keys.
        let doc = include_str!("../docs/configuration.md");
        let examples_start = doc.find("## Example policies").expect("docs: no \"Example policies\" section");
        let examples_end = doc[examples_start..].find("\n## ").map_or(doc.len(), |i| examples_start + i + 1);
        let dummy_name = format!("000b{}", "00".repeat(32));
        let mut examples = 0;
        let mut pos = 0;
        while let Some(start) = doc[pos..].find("```toml\n") {
            let body_start = pos + start + "```toml\n".len();
            let body_end = body_start + doc[body_start..].find("```").expect("docs: unterminated toml block");
            pos = body_end + 3;
            let body = &doc[body_start..body_end];
            if !body.contains("[selection]") {
                continue; // a fragment, not a policy
            }
            let line = doc[..body_start].lines().count();
            if (examples_start..examples_end).contains(&body_start) {
                let policy = body.replace("000b<64 hex chars>", &dummy_name).replace("<64 hex chars>", &"00".repeat(32));
                if let Err(e) = Policy::from_toml_str(&policy) {
                    panic!("docs/configuration.md line {line}: example policy is invalid: {e}");
                }
                examples += 1;
            } else if let Err(e) = Policy::from_toml_str(body) {
                let e = e.to_string();
                assert!(
                    !e.contains("TOML parse error") && !e.contains("unknown field"),
                    "docs/configuration.md line {line}: {e}"
                );
            }
        }
        assert!(examples >= 4, "found {examples} example policies in docs/configuration.md");
    }

    #[test]
    fn every_commented_setting_in_the_example_is_a_real_one() {
        // Uncommenting any one `#key = value` line must give a key the
        // schema knows, in the table it sits under. Placeholders (TPM
        // Names) and mode-specific keys (provider, level) may still fail
        // validation; an unknown field is the one failure that means the
        // example is wrong.
        let lines: Vec<&str> = EXAMPLE_POLICY.lines().collect();
        let mut checked = 0;
        for (i, line) in lines.iter().enumerate() {
            let Some(setting) = line.strip_prefix('#') else { continue };
            let starts_like_a_key = setting.starts_with(|c: char| c.is_ascii_lowercase() || c == '"');
            if !starts_like_a_key || !setting.contains(" = ") {
                continue;
            }
            let mut edited = lines.clone();
            edited[i] = setting;
            if let Err(e) = Policy::from_toml_str(&edited.join("\n")) {
                assert!(!e.to_string().contains("unknown field"), "example line {}: `{setting}`: {e}", i + 1);
            }
            checked += 1;
        }
        assert!(checked >= 18, "only {checked} commented settings found; did the example's format change?");
    }
}

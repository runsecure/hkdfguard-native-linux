//! The audit trail: one syslog record per security-relevant event, written
//! whatever the host does about logging.
//!
//! The `log` facade the rest of this crate uses is diagnostics, and it is
//! silent unless the host installs a logger -- which a C, Python or .NET
//! host never does. These records are the Linux counterpart of the Windows
//! build's Application Event Log events: the same event IDs, meanings and
//! severities, and the same content, so one set of alerts reads both.
//!
//! - **Where.** Facility `authpriv`, tag `hkdfguard`, sent as a datagram to
//!   `/dev/log` -- journald on systemd hosts, rsyslog/syslog-ng elsewhere
//!   (`/var/log/secure` or `/var/log/auth.log`). The socket is written
//!   directly, not through `openlog(3)`/`syslog(3)`: those set process-wide
//!   state (the tag, the facility) that belongs to the host.
//! - **Best effort.** Non-blocking, and every failure ignored: no
//!   `/dev/log` (a minimal container), a full queue, or anything else never
//!   changes, delays or fails the call being audited.
//! - **What.** `key=value` fields, then a sentence: the event, the C
//!   function, the normalized service name, the result, and who called --
//!   `uid`, `euid`, `pid` and `exe`. Wrap and unwrap records also carry the
//!   KEK's fingerprint and a SHA-256 of the wrapped payload, both public;
//!   the same payload has the same hash in its wrap record and in every
//!   unwrap record, which ties each unwrap back to the wrap that made it.
//! - **Never.** DEKs, KEKs, shared secrets, derived keys or plaintext.
//!   Caller mistakes (`INVALID_ARGUMENT`, `BUFFER_TOO_SMALL`,
//!   `INVALID_SERVICE_NAME`) and `KEK_NOT_FOUND` aren't audited either,
//!   as on Windows.
//!
//! Anyone on the host can write to `/dev/log` under any tag, so these
//! records are an audit aid, not tamper-proof evidence -- as with the
//! Windows Event Log.

use crate::error::status;
use crate::payload::Payload;
use crate::provider::ProviderType;
use sha2::{Digest, Sha256};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

/// The C function an event belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    CreateKek,
    KekExists,
    Wrap,
    GenerateAndWrap,
    Unwrap,
    OpenFile,
    KekFingerprint,
    RetireKek,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::CreateKek => "hkdfguard_create_kek",
            Op::KekExists => "hkdfguard_kek_exists",
            Op::Wrap => "hkdfguard_wrap_dek",
            Op::GenerateAndWrap => "hkdfguard_generate_and_wrap_dek",
            Op::Unwrap => "hkdfguard_unwrap_dek",
            Op::OpenFile => "hkdfguard_open_file",
            Op::KekFingerprint => "hkdfguard_kek_fingerprint",
            // Not a C function: the CLI's `retire`, through the library's
            // Rust-only `admin::retire_kek`.
            Op::RetireKek => "retire_kek",
        }
    }
}

// Event IDs: the Windows build's, number for number (see its
// src/event_messages.mc). 2001 is unused there too.
pub(crate) const KEK_CREATED: u32 = 1000;
pub(crate) const KEK_CREATED_FALLBACK: u32 = 1001;
pub(crate) const DEK_WRAPPED: u32 = 1002;
pub(crate) const DEK_UNWRAPPED: u32 = 1003;
// Not in the Windows table: Linux's own, for `retire`, which permanently
// deletes a KEK. A Warning, as every DEK wrapped under it is now
// unrecoverable.
pub(crate) const KEK_RETIRED: u32 = 1004;
pub(crate) const DEVELOPER_MODEL_KEY_FILE: u32 = 1005;
pub(crate) const ACCESS_DENIED: u32 = 2000;
pub(crate) const KEK_INVALID: u32 = 2002;
pub(crate) const INTEGRITY_FAILURE: u32 = 2003;
pub(crate) const POLICY_INVALID: u32 = 2004;
pub(crate) const OPERATION_FAILED: u32 = 2005;
pub(crate) const PLAINTEXT_KEY_FILE: u32 = 2006;
pub(crate) const SETUP_CALLS_EXCEEDED: u32 = 2007;

/// syslog severities (RFC 5424), mirroring the Windows events' levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Severity {
    Error = 3,
    Warning = 4,
    Info = 6,
}

/// LOG_AUTHPRIV: security/authorization messages, kept out of the
/// world-readable logs on most distributions.
const FACILITY_AUTHPRIV: u8 = 10 << 3;

#[cfg(not(test))]
const SYSLOG_SOCKET: &str = "/dev/log";

/// Whether `hkdfguard_create_kek` knows it created the KEK it returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Creation {
    /// None existed beforehand: this call created it.
    Created,
    /// Whether one existed beforehand couldn't be determined (the check
    /// itself failed), so the call may have found an existing KEK.
    Unconfirmed,
}

/// A KEK was created (not merely found) -- or, `Unconfirmed`, may have
/// been. `preferred` is the policy's first choice of provider: created
/// anywhere else, the event is 1001 (Warning), the counterpart of the
/// Windows build's "created in software because the TPM attempt failed".
pub(crate) fn kek_created(service: &str, provider: ProviderType, preferred: Option<ProviderType>, creation: Creation) {
    let fields = format!("op={} service={} provider={}", Op::CreateKek.name(), quote(service.as_bytes()), provider.as_str());
    let (fields, created) = match creation {
        Creation::Created => (fields, "KEK created"),
        Creation::Unconfirmed => (
            format!("{fields} existed_before=unknown"),
            "KEK created, or an existing one found (whether one existed beforehand could not be checked)",
        ),
    };
    match preferred {
        Some(first) if first != provider => emit(
            Severity::Warning,
            KEK_CREATED_FALLBACK,
            &format!("{fields} preferred={}", first.as_str()),
            &format!(
                "{created} on {}, not on the policy's first choice {}, which was unavailable or declined",
                provider.as_str(),
                first.as_str()
            ),
        ),
        _ => emit(Severity::Info, KEK_CREATED, &fields, &format!("{created} on {}", provider.as_str())),
    }
}

/// A KEK was retired: deleted from `provider` for good, after its
/// fingerprint was confirmed. Records the fingerprint (public), so the
/// record names exactly which key was destroyed.
pub(crate) fn kek_retired(service: &str, provider: ProviderType, fingerprint: &[u8]) {
    emit(
        Severity::Warning,
        KEK_RETIRED,
        &format!(
            "op={} result=OK service={} provider={} kek_fingerprint={}",
            Op::RetireKek.name(),
            quote(service.as_bytes()),
            provider.as_str(),
            hex(fingerprint)
        ),
        &format!(
            "KEK retired: deleted from {}; every DEK wrapped under it can no longer be unwrapped",
            provider.as_str()
        ),
    );
}

/// A DEK was wrapped (`op` is Wrap or GenerateAndWrap) or unwrapped
/// (`Unwrap`). `payload` is the wrapped payload produced or consumed:
/// public bytes, from which the provider and KEK fingerprint are read.
pub(crate) fn dek_operation(op: Op, service: &str, payload: &[u8]) {
    let (provider, fingerprint) = match Payload::from_bytes(payload) {
        Ok(p) => (p.provider_type.as_str(), hex(&p.fingerprint)),
        Err(_) => ("(unknown)", "(unavailable)".to_string()),
    };
    let unwrap = op == Op::Unwrap;
    emit(
        Severity::Info,
        if unwrap { DEK_UNWRAPPED } else { DEK_WRAPPED },
        &format!(
            "op={} result=OK service={} provider={provider} kek_fingerprint={fingerprint} payload_sha256={}",
            op.name(),
            quote(service.as_bytes()),
            hex(&Sha256::digest(payload))
        ),
        if unwrap { "DEK unwrapped" } else { "DEK wrapped" },
    );
}

/// `op` failed with `code`, for `service`. Only the failures worth an
/// administrator's attention are written -- the Windows build's list --
/// plus PROVIDER_UNAVAILABLE, which on Linux means no allowed provider
/// could be reached at all.
pub(crate) fn operation_failed(op: Op, service: &str, code: i32) {
    let (event, severity, meaning) = match code {
        status::KEK_ACCESS_DENIED => (
            ACCESS_DENIED,
            Severity::Warning,
            "the caller is not authorized to do this to the KEK (under the production security model, only root \
             creates or retires one)",
        ),
        status::KEK_INVALID => (
            KEK_INVALID,
            Severity::Error,
            "a KEK exists under this service name but is corrupt or not one this library would create; it was left untouched",
        ),
        status::PAYLOAD_AUTH_FAILED | status::KEK_FINGERPRINT_MISMATCH | status::PAYLOAD_MALFORMED | status::PAYLOAD_UNSUPPORTED => {
            if op != Op::Unwrap {
                return;
            }
            let meaning = match code {
                status::PAYLOAD_AUTH_FAILED => "the payload failed authentication: tampered with, or presented for the wrong service",
                status::KEK_FINGERPRINT_MISMATCH => "the payload was not wrapped under this service's current KEK",
                status::PAYLOAD_UNSUPPORTED => {
                    "the payload's format version is not one this build understands (corrupted, tampered with, or from a newer version)"
                }
                _ => "the payload is not a valid wrapped DEK (truncated, corrupted, or tampered with)",
            };
            (INTEGRITY_FAILURE, Severity::Warning, meaning)
        }
        status::POLICY_INVALID | status::LINUX_GROUP_INVALID => (
            POLICY_INVALID,
            Severity::Error,
            "the policy file can't be trusted or used; every call fails closed until it is fixed",
        ),
        status::PROVIDER_UNAVAILABLE | status::PROVIDER_ERROR | status::CRYPTO_ERROR | status::INTERNAL_ERROR => (
            OPERATION_FAILED,
            Severity::Error,
            "the key provider or a cryptographic operation failed",
        ),
        // Caller mistakes, "not provisioned yet", and everything else.
        _ => return,
    };
    emit(
        severity,
        event,
        &format!("op={} result={}({code}) service={}", op.name(), code_name(code), quote(service.as_bytes())),
        &format!("{} failed: {meaning}", op.name()),
    );
}

/// hkdfguard_open_file refused `path` as FILE_PLAINTEXT_KEY: it looks like
/// an unwrapped DEK, so possibly a plaintext key on disk. Names the file;
/// none of its contents are logged.
pub(crate) fn plaintext_key_file(path: &Path) {
    emit(
        Severity::Error,
        PLAINTEXT_KEY_FILE,
        &format!(
            "op={} result={}({}) path={}",
            Op::OpenFile.name(),
            code_name(status::FILE_PLAINTEXT_KEY),
            status::FILE_PLAINTEXT_KEY,
            quote(path.as_os_str().as_bytes())
        ),
        "the file looks like an unwrapped DEK (32 raw bytes, or its base64 or hex), so it may be a plaintext key \
         written to disk by mistake; none of its contents were returned. Treat that key as exposed: find out how \
         the file was written, remove it, and re-mint the DEK",
    );
}

/// hkdfguard_open_file refused `path` for a reason that points at tampering
/// rather than a setup mistake: `FILE_UNTRUSTED` (someone else could have
/// replaced it -- an untrusted owner, a writable file or directory, a
/// symlink in a directory others control, or a swap mid-open) or a file
/// that isn't a well-formed payload (`FILE_MALFORMED`, `FILE_TOO_SHORT`,
/// `FILE_TOO_LONG`). Event 2003, as for a payload that fails at unwrap.
/// Anything else -- missing, unreadable, not a regular file -- isn't
/// audited, and `FILE_PLAINTEXT_KEY` has its own event
/// ([`plaintext_key_file`]). Names the file; none of its contents are logged.
pub(crate) fn key_file_refused(path: &Path, code: i32) {
    let meaning = match code {
        status::FILE_UNTRUSTED => {
            "the key file, or a directory deciding what its path names, could have been replaced by someone the \
             security model doesn't trust; it was not read"
        }
        status::FILE_MALFORMED | status::FILE_TOO_SHORT | status::FILE_TOO_LONG => {
            "the key file is not a well-formed wrapped DEK (truncated, corrupted, or tampered with)"
        }
        _ => return,
    };
    emit(
        Severity::Warning,
        INTEGRITY_FAILURE,
        &format!("op={} result={}({code}) path={}", Op::OpenFile.name(), code_name(code), quote(path.as_os_str().as_bytes())),
        &format!("{} refused a key file: {meaning}", Op::OpenFile.name()),
    );
}

/// hkdfguard_open_file accepted `path` under the developer security model,
/// which trusts key files the application's own account owns -- so the
/// application could have planted it. Written once per process (the first
/// such file named), as the Windows build's event 1005 is: a reminder that
/// this host is not running the production model, not a per-read record.
pub(crate) fn developer_model_key_file(path: &Path) {
    static WRITTEN: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if WRITTEN.set(()).is_err() {
        return;
    }
    emit(
        Severity::Warning,
        DEVELOPER_MODEL_KEY_FILE,
        &format!("op={} security_model=developer path={}", Op::OpenFile.name(), quote(path.as_os_str().as_bytes())),
        "a key file was read under the developer security model, which trusts key files owned by the calling \
         account: an application could plant a DEK it knows. Set security_model = \"production\" (or remove it) \
         in /etc/hkdfguard/policy.toml on any host that is not a development machine (logged once per process)",
    );
}

/// This process has made more than `calls` setup calls, each held to at
/// least `floor_ms`: the signature of a caller looping on them.
pub(crate) fn setup_calls_exceeded(calls: u32, floor_ms: u128) {
    emit(
        Severity::Warning,
        SETUP_CALLS_EXCEEDED,
        &format!("calls={calls} setup_min_delay_ms={floor_ms}"),
        &format!(
            "more than {calls} hkdfguard_create_kek / hkdfguard_kek_exists / hkdfguard_kek_fingerprint calls in this process; these are meant \
             to run once per application startup, and each costs a fresh provider connection plus at least \
             {floor_ms} ms -- call them once at startup, then use hkdfguard_wrap_dek / hkdfguard_unwrap_dek"
        ),
    );
}

// One record: the event's own fields, who called, then the sentence.
fn emit(severity: Severity, event: u32, fields: &str, message: &str) {
    // SAFETY: getuid/geteuid take no arguments and cannot fail.
    let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    let exe = std::fs::read_link("/proc/self/exe")
        .map(|p| quote(p.as_os_str().as_bytes()))
        .unwrap_or_else(|_| "\"(unknown)\"".to_string());
    let line = format!(
        "event={event} {fields} uid={uid} euid={euid} pid={} exe={exe} msg={}",
        std::process::id(),
        quote(message.as_bytes())
    );
    send(severity, &line);
}

// RFC 3164 framing as the local syslog socket accepts it:
// `<PRI>TAG[PID]: MESSAGE`, the receiver adding the timestamp and host.
fn frame(severity: Severity, line: &str) -> String {
    format!("<{}>hkdfguard[{}]: {line}", FACILITY_AUTHPRIV | severity as u8, std::process::id())
}

#[cfg(not(test))]
fn send(severity: Severity, line: &str) {
    send_to(Path::new(SYSLOG_SOCKET), &frame(severity, line));
}

fn send_to(socket: &Path, record: &str) {
    let Ok(sock) = UnixDatagram::unbound() else { return };
    if sock.set_nonblocking(true).is_err() {
        return; // never risk blocking the call being audited
    }
    let _ = sock.send_to(record.as_bytes(), socket);
}

// Unit tests never write to the host's real syslog: records are captured
// in memory for the tests to inspect, filtered by their own service names
// or paths (tests run in parallel). `send_to` is tested on its own against
// a socket the test binds.
#[cfg(test)]
static CAPTURED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn send(severity: Severity, line: &str) {
    CAPTURED.lock().unwrap_or_else(|p| p.into_inner()).push(frame(severity, line));
}

/// Records captured so far whose text contains `needle` (a test's own
/// service name or path).
#[cfg(test)]
pub(crate) fn captured_containing(needle: &str) -> Vec<String> {
    CAPTURED.lock().unwrap_or_else(|p| p.into_inner()).iter().filter(|r| r.contains(needle)).cloned().collect()
}

fn code_name(code: i32) -> &'static str {
    match code {
        status::OK => "OK",
        status::INVALID_ARGUMENT => "INVALID_ARGUMENT",
        status::BUFFER_TOO_SMALL => "BUFFER_TOO_SMALL",
        status::PROVIDER_UNAVAILABLE => "PROVIDER_UNAVAILABLE",
        status::PROVIDER_ERROR => "PROVIDER_ERROR",
        status::CRYPTO_ERROR => "CRYPTO_ERROR",
        status::INTERNAL_ERROR => "INTERNAL_ERROR",
        status::INVALID_SERVICE_NAME => "INVALID_SERVICE_NAME",
        status::POLICY_INVALID => "POLICY_INVALID",
        status::PAYLOAD_MALFORMED => "PAYLOAD_MALFORMED",
        status::PAYLOAD_AUTH_FAILED => "PAYLOAD_AUTH_FAILED",
        status::PAYLOAD_UNSUPPORTED => "PAYLOAD_UNSUPPORTED",
        status::KEK_FINGERPRINT_MISMATCH => "KEK_FINGERPRINT_MISMATCH",
        status::KEK_NOT_FOUND => "KEK_NOT_FOUND",
        status::KEK_ACCESS_DENIED => "KEK_ACCESS_DENIED",
        status::KEK_INVALID => "KEK_INVALID",
        status::PROCESS_HARDENING_FAILED => "PROCESS_HARDENING_FAILED",
        status::FILE_PLAINTEXT_KEY => "FILE_PLAINTEXT_KEY",
        status::FILE_UNTRUSTED => "FILE_UNTRUSTED",
        status::FILE_MALFORMED => "FILE_MALFORMED",
        status::FILE_TOO_SHORT => "FILE_TOO_SHORT",
        status::FILE_TOO_LONG => "FILE_TOO_LONG",
        status::LINUX_GROUP_INVALID => "LINUX_GROUP_INVALID",
        _ => "UNKNOWN",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// A double-quoted field value. Printable ASCII other than `"` and `\` is
// kept; everything else -- quotes, backslashes, control characters
// (newlines included, so no value can forge a second record), and any
// non-ASCII or non-UTF-8 byte of a path -- is written as \xNN.
fn quote(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for &b in bytes {
        if (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\' {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn last_with(needle: &str) -> String {
        captured_containing(needle).pop().unwrap_or_else(|| panic!("no audit record containing {needle}"))
    }

    #[test]
    fn records_are_authpriv_with_the_windows_severity_and_tag() {
        operation_failed(Op::Unwrap, "audit.test.framing", status::PAYLOAD_AUTH_FAILED);
        let record = last_with("\"audit.test.framing\"");
        assert!(record.starts_with(&format!("<84>hkdfguard[{}]: event=2003 ", std::process::id())), "{record}");
        operation_failed(Op::Wrap, "audit.test.framing.err", status::PROVIDER_ERROR);
        assert!(last_with("audit.test.framing.err").starts_with("<83>"), "error severity");
        kek_created("audit.test.framing.info", ProviderType::Tpm2, Some(ProviderType::Tpm2), Creation::Created);
        assert!(last_with("audit.test.framing.info").starts_with("<86>"), "info severity");
    }

    #[test]
    fn records_name_the_service_and_the_caller() {
        operation_failed(Op::CreateKek, "audit.test.caller", status::POLICY_INVALID);
        let record = last_with("audit.test.caller");
        assert!(
            record.contains("event=2004 op=hkdfguard_create_kek result=POLICY_INVALID(-9) service=\"audit.test.caller\""),
            "{record}"
        );
        // SAFETY: no arguments, cannot fail.
        let uid = unsafe { libc::getuid() };
        assert!(record.contains(&format!(" uid={uid} ")), "{record}");
        assert!(record.contains(&format!(" pid={} ", std::process::id())), "{record}");
        assert!(record.contains(" exe=\"/"), "{record}");
    }

    #[test]
    fn caller_mistakes_and_not_found_are_not_audited() {
        for code in [status::INVALID_ARGUMENT, status::BUFFER_TOO_SMALL, status::INVALID_SERVICE_NAME, status::KEK_NOT_FOUND] {
            operation_failed(Op::Wrap, "audit.test.quiet", code);
        }
        assert!(captured_containing("audit.test.quiet").is_empty());
    }

    #[test]
    fn payload_codes_are_audited_on_unwrap_only() {
        operation_failed(Op::Wrap, "audit.test.wraponly", status::PAYLOAD_MALFORMED);
        assert!(captured_containing("audit.test.wraponly").is_empty());
        for code in [status::PAYLOAD_AUTH_FAILED, status::KEK_FINGERPRINT_MISMATCH, status::PAYLOAD_MALFORMED, status::PAYLOAD_UNSUPPORTED] {
            operation_failed(Op::Unwrap, "audit.test.integrity", code);
        }
        let records = captured_containing("audit.test.integrity");
        assert_eq!(records.len(), 4);
        assert!(records.iter().all(|r| r.contains("event=2003 ")));
    }

    #[test]
    fn each_code_gets_the_windows_event_id() {
        let cases = [
            (status::KEK_ACCESS_DENIED, 2000),
            (status::KEK_INVALID, 2002),
            (status::POLICY_INVALID, 2004),
            (status::PROVIDER_UNAVAILABLE, 2005),
            (status::PROVIDER_ERROR, 2005),
            (status::CRYPTO_ERROR, 2005),
            (status::INTERNAL_ERROR, 2005),
        ];
        for (code, event) in cases {
            let service = format!("audit.test.ids{}", -code);
            operation_failed(Op::KekExists, &service, code);
            assert!(last_with(&format!("\"{service}\"")).contains(&format!("event={event} ")), "code {code}");
        }
    }

    #[test]
    fn a_kek_off_the_first_choice_is_a_fallback_warning() {
        kek_created("audit.test.fallback", ProviderType::ExternalSecret, Some(ProviderType::Tpm2), Creation::Created);
        let record = last_with("audit.test.fallback");
        assert!(record.starts_with("<84>"), "{record}");
        assert!(
            record.contains("event=1001 op=hkdfguard_create_kek service=\"audit.test.fallback\" provider=EXTERNAL_SECRET preferred=TPM2"),
            "{record}"
        );
    }

    #[test]
    fn quoting_keeps_every_value_on_one_line() {
        assert_eq!(quote(b"plain/path.key"), "\"plain/path.key\"");
        assert_eq!(quote(b"a\"b\\c"), "\"a\\x22b\\x5cc\"");
        assert_eq!(quote(b"line\nbreak"), "\"line\\x0abreak\"", "no forged second record");
        assert_eq!(quote(b"caf\xc3\xa9\xff"), "\"caf\\xc3\\xa9\\xff\"");
    }

    #[test]
    fn plaintext_key_file_names_the_path() {
        plaintext_key_file(Path::new("/srv/audit-test/plain\n.key"));
        let record = last_with("audit-test/plain");
        assert!(record.starts_with("<83>"), "{record}");
        assert!(
            record.contains("event=2006 op=hkdfguard_open_file result=FILE_PLAINTEXT_KEY(-37) path=\"/srv/audit-test/plain\\x0a.key\""),
            "{record}"
        );
        assert!(!record.contains('\n'));
    }

    #[test]
    fn key_file_refusals_that_point_at_tampering_are_audited_and_setup_mistakes_are_not() {
        for (code, name, says) in [
            (status::FILE_UNTRUSTED, "FILE_UNTRUSTED", "could have been replaced"),
            (status::FILE_MALFORMED, "FILE_MALFORMED", "not a well-formed wrapped DEK"),
            (status::FILE_TOO_SHORT, "FILE_TOO_SHORT", "not a well-formed wrapped DEK"),
            (status::FILE_TOO_LONG, "FILE_TOO_LONG", "not a well-formed wrapped DEK"),
        ] {
            let path = format!("/srv/audit-test/refused-{name}.key");
            key_file_refused(Path::new(&path), code);
            let record = last_with(&path);
            assert!(record.starts_with("<84>"), "a Warning: {record}");
            assert!(record.contains(&format!("event=2003 op=hkdfguard_open_file result={name}({code})")), "{record}");
            assert!(record.contains(says), "{record}");
        }
        for code in [status::FILE_NOT_FOUND, status::FILE_ACCESS_DENIED, status::FILE_IO, status::FILE_PLAINTEXT_KEY] {
            let path = format!("/srv/audit-test/quiet-{code}.key");
            key_file_refused(Path::new(&path), code);
            assert!(captured_containing(&path).is_empty(), "code {code} is not audited here");
        }
    }

    #[test]
    fn an_unconfirmed_creation_says_so() {
        kek_created("audit.test.unconfirmed", ProviderType::Tpm2, Some(ProviderType::Tpm2), Creation::Unconfirmed);
        let record = last_with("audit.test.unconfirmed");
        assert!(record.contains("event=1000") && record.contains("existed_before=unknown"), "{record}");
        assert!(record.contains("could not be checked"), "{record}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "opens a Unix datagram socket, which Miri can't")]
    fn send_to_delivers_one_datagram_and_never_blocks_or_fails() {
        // Not `private_tempdir`: nothing here goes through the library's
        // trust checks, and a socket path must fit in sun_path (108 bytes),
        // which the test root under a deep build directory (rpmbuild's
        // BUILD/<name>-build/<name>/target/tmp/...) can exceed. The system
        // temp dir is short; `tempdir` makes a 0700 directory in it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.sock");
        let receiver = UnixDatagram::bind(&path).unwrap();
        let record = frame(Severity::Info, "event=1002 op=hkdfguard_wrap_dek msg=\"x\"");
        send_to(&path, &record);
        let mut buf = [0u8; 1024];
        let n = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], record.as_bytes());
        // No receiver at all: silently nothing, at once.
        send_to(&dir.path().join("absent.sock"), &record);
    }
}

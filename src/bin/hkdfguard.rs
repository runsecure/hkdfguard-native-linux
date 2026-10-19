//! CLI tool for setting up a service's persistent KEK and wrapping DEKs
//! under it, and retiring a KEK. Three subcommands, deliberately separate:
//!
//! - `provision` -- ensure a KEK exists for a service, and print its
//!   fingerprint. With `retire`, the only place the setup calls
//!   (`hkdfguard_kek_exists`, `hkdfguard_create_kek`,
//!   `hkdfguard_kek_fingerprint`) are made. They are deliberately slow (see
//!   the library's setup-call latency floor) and meant to run once, at
//!   deployment time.
//! - `retire` -- permanently delete a service's KEK, given the fingerprint
//!   `provision` printed for it. PKCS#11 only (see `admin::retire_kek`); it
//!   goes through the library's Rust-only admin API, the one deliberate
//!   exception to the C-ABI-only rule below, so that no application
//!   linking the library can delete a KEK.
//! - `wrap` -- wrap a caller-supplied Data Encryption Key (DEK) under the
//!   service's KEK and write the wrapped payload to a file. It never
//!   creates a KEK: if none is provisioned, it fails and says to run
//!   `provision`. That keeps the fast, repeatable operation free of the
//!   setup calls, and makes "the KEK is missing" a loud, specific error
//!   instead of something quietly fixed on the fly.
//!
//! `provision` and `wrap` call into the `hkdfguard` library through its stable C ABI, the
//! same interface any other-language caller uses -- this tool takes no
//! shortcut through the library's internal Rust types.
//!
//! The KEK's `service` identity is exactly the caller-supplied
//! `--service-name`; there is no further structure to it.
//!
//! Usage:
//! ```text
//! hkdfguard provision --service-name|-sn <name>
//!
//! hkdfguard retire --service-name|-sn <name> --fingerprint|-fp <64 hex chars>
//!
//! hkdfguard wrap \
//!     --key-file-path|-kf <path> \
//!     --service-name|-sn <name> \
//!     (--dek-stdin | --dek-file <path>) \
//!     [--group|-g <name>] [--fingerprint|-fp <64 hex chars>] [--force|-f]
//! ```
//!
//! ## Supplying the DEK
//!
//! The DEK is base64 (of exactly 32 raw bytes) and is read either from
//! standard input or from a file. It is deliberately **not** accepted as a
//! command-line argument: argv is world-readable through
//! `/proc/<pid>/cmdline` for the life of the process, so every DEK ever
//! deployed would be exposed to any process running as the same user. It
//! is deliberately not read from an environment variable either, for the
//! same reason applied to `/proc/<pid>/environ` -- which is additionally
//! inherited by every child process (this matches the reasoning already
//! applied to the PKCS#11 PIN; see `src/provider/pkcs11.rs`).
//!
//! ```text
//! # stdin -- printf is a shell builtin, so nothing reaches argv
//! printf '%s' "$DEK_B64" | hkdfguard wrap -kf key.bin -sn svc --dek-stdin
//!
//! # file -- e.g. a Kubernetes/Vault secret mount or a systemd credential
//! hkdfguard wrap -kf key.bin -sn svc --dek-file "$CREDENTIALS_DIRECTORY/dek"
//! ```
//!
//! A `--dek-file` must be a regular file, must not be a symlink, must be
//! owned by root or by this process's user, and must grant no access to
//! group or others (e.g. mode `0400`/`0600`). A single trailing newline
//! (optionally CRLF) is ignored on both paths.
//!
//! What this tool cannot fix: if the *caller* puts the DEK in an
//! environment variable, or pipes it with a non-builtin `echo` (argv
//! again), the exposure moves upstream. Whatever drives this tool has to
//! avoid both.
//!
//! ## Overwriting
//!
//! The key file's folder must be a real folder at the path spelled: no
//! symbolic link anywhere above the file (see [`require_real_folder`]),
//! checked before the DEK is read and again on the open descriptor.
//!
//! When `--force` replaces an existing file at `--key-file-path`, the wrap
//! is completed in memory *first*, and only then is the old file securely
//! overwritten in place and removed (see [`secure_delete`]); a file with
//! more than one hard link is refused. A wrap that
//! fails -- no KEK provisioned, provider unavailable, bad DEK input --
//! therefore never destroys the key file that was already there. The
//! secure overwrite is a best-effort measure against a plain read of the
//! disk: it cannot guarantee erasure on copy-on-write or log-structured
//! filesystems (e.g. btrfs, ZFS), or on flash storage doing wear-leveling
//! remaps, where the original blocks may still exist elsewhere.

use base64ct::{Base64, Encoding as _};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::raw::c_int;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroize;
use hkdfguard::{
    admin, harden_flags, hkdfguard_create_kek, hkdfguard_harden_process_with_flags, hkdfguard_kek_exists,
    hkdfguard_kek_fingerprint, hkdfguard_wrap_dek, status,
};

// rw-------: the owning deployment user only. The payload is ciphertext,
// but anyone who can both read it and reach the provider (a `tss` group
// member, on a TPM host) can unwrap it, so group read is not the default.
// A deployment that wants a group to read it grants that deliberately.
const KEY_FILE_MODE: u32 = 0o600;
// With --group: rw-r-----, the owner plus that one group, read-only. The
// Windows tool's --group grants the same (owner read/write, the group read).
const KEY_FILE_GROUP_MODE: u32 = 0o640;

// Groups --group refuses: each covers essentially every account on a
// typical host, or the host's administrators or log readers -- granting one
// read access is no narrower than world-readable for this purpose. Matched
// by resolved gid, so a numeric gid can't dodge the list. gid 0 and the
// overflow gid 65534 are refused whatever their names. The Windows tool
// refuses its own equivalents (Everyone, Users, Authenticated Users, ...).
const OVER_BROAD_GROUPS: &[&str] = &["root", "users", "nogroup", "nobody", "wheel", "sudo", "adm", "staff"];

// Number of (all-zero pass, random pass) rounds `secure_delete` runs before
// removing the file -- 2 passes per round, so this yields 8 total
// overwrites as specified.
const SECURE_DELETE_ROUNDS: usize = 4;

const PROGRAM_NAME: &str = "hkdfguard";
const DEK_LEN: usize = 32;
// Mirrors the library's own cap (see cstr_to_service in src/lib.rs) so this
// tool can give a specific, immediate error instead of relying on the
// library's generic INVALID_ARGUMENT.
const MAX_SERVICE_LEN: usize = 128;
// Generous starting capacity for the wrapped payload -- see
// hkdfguard_wrap_dek's own doc comment ("at most a few hundred bytes").
// Retried once at the library-reported size on BUFFER_TOO_SMALL, so this
// only needs to be a reasonable common case, not an absolute upper bound.
const INITIAL_WRAPPED_CAPACITY: usize = 512;
// Upper bound on the DEK input read from stdin or a file. Base64 of 32
// bytes is 44 characters; this leaves room for a trailing newline (or
// CRLF) and nothing more, so a wrong file fails fast instead of being
// slurped into memory.
const MAX_DEK_INPUT_LEN: usize = 64;
// Room to base64-decode any accepted input: base64 decodes 4 characters
// to at most 3 bytes, and `decode_slice` checks against that estimate.
const MAX_DECODED_LEN: usize = MAX_DEK_INPUT_LEN / 4 * 3;
// Mode bits that must be clear on a --dek-file: no access at all for
// group or others.
const FORBID_GROUP_OTHER_ACCESS: u32 = 0o077;
// Any DEK input that isn't strict, padded, standard base64 -- the Windows
// tool's wording. Deliberately fixed: it names no character, offset or bit
// pattern, so a mistyped DEK never puts part of itself into a log.
const INVALID_BASE64_DEK_MESSAGE: &str =
    "the DEK input is not valid base64 (standard alphabet, padded, at most one trailing newline)";
// Refusing to read the DEK from an interactive terminal -- the Windows
// tool's wording.
const TERMINAL_DEK_MESSAGE: &str = "refusing to read the DEK from an interactive terminal, where it would be \
                                    echoed and kept in the scrollback; pipe it in instead, e.g. \
                                    printf '%s' \"$DEK_B64\" | hkdfguard wrap ... --dek-stdin";
// Refusing UTF-16 DEK input -- the Windows tool's wording.
const UTF16_DEK_MESSAGE: &str = "the DEK input is UTF-16 encoded; send it as ASCII or UTF-8 base64 text \
                                 (in PowerShell, set [Console]::OutputEncoding or $OutputEncoding to UTF-8)";

// Where the base64 DEK is read from. Never argv, never the environment --
// see this file's header comment.
#[derive(Debug, PartialEq, Eq)]
enum DekSource {
    Stdin,
    File(String),
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Provision {
        service_name: String,
    },
    Wrap {
        key_file_path: String,
        service_name: String,
        dek_source: DekSource,
        force: bool,
        // --group: who besides the owner may read the key file. None: no one.
        group: Option<String>,
        // --fingerprint: the KEK the operator recorded at provision time.
        // When set, nothing is written unless the payload was sealed to it.
        expected_fingerprint: Option<[u8; FINGERPRINT_LEN]>,
    },
    Retire {
        service_name: String,
        // --fingerprint: the KEK the operator means to delete, as printed
        // by `provision`. Nothing is deleted unless the KEK matches it.
        fingerprint: [u8; FINGERPRINT_LEN],
    },
}

// A KEK fingerprint: SHA-256 of its public key.
const FINGERPRINT_LEN: usize = 32;

enum ParseOutcome {
    Run(Command),
    Help,
}

fn print_usage() {
    eprintln!(
        "Usage:\n\
         \x20 {PROGRAM_NAME} provision --service-name|-sn <name>\n\
         \x20 {PROGRAM_NAME} wrap --key-file-path|-kf <path> --service-name|-sn <name> (--dek-stdin | --dek-file <path>)\n\
         \x20      [--group|-g <name>] [--fingerprint|-fp <64 hex chars>] [--force|-f]\n\
         \x20 {PROGRAM_NAME} retire --service-name|-sn <name> --fingerprint|-fp <64 hex chars>\n\
         \n\
         provision  ensures a KEK exists for the service, and prints its fingerprint: record\n\
         \x20          it. Run once, at deployment time; with retire, the only commands that\n\
         \x20          make the (deliberately slow) setup calls.\n\
         wrap       wraps a DEK under the service's existing KEK and writes the payload to\n\
         \x20          --key-file-path, readable by its owner only, or also by --group's\n\
         \x20          members (mode 0640). Fails if the KEK has not been provisioned.\n\
         \x20          Prints the fingerprint of the KEK it wrapped under; with --fingerprint,\n\
         \x20          writes nothing unless that is the KEK given.\n\
         retire     permanently deletes the service's KEK, only if its fingerprint is the\n\
         \x20          one given; every DEK wrapped under it becomes unrecoverable. PKCS#11\n\
         \x20          only: a TPM2 KEK is not stored anywhere, so there is nothing to delete.\n\
         \n\
         The DEK is base64 of exactly 32 bytes, read from stdin or a file -- never\n\
         from a command-line argument or an environment variable, both of which are\n\
         readable by other processes of the same user.\n\
         \n\
         Examples:\n\
         \x20 {PROGRAM_NAME} provision -sn svc\n\
         \x20 printf '%s' \"$DEK_B64\" | {PROGRAM_NAME} wrap -kf key.bin -sn svc --dek-stdin\n\
         \x20 {PROGRAM_NAME} wrap -kf key.bin -sn svc --dek-file \"$CREDENTIALS_DIRECTORY/dek\""
    );
}

// The value after a flag that takes one: present, non-empty, and not
// starting with "-". Without that last rule a forgotten value swallows the
// next flag: `wrap -kf --force ...` would write a key file named "--force"
// and silently drop --force. Flags themselves (-sn, -kf, -g, ...) are
// unaffected; only what is consumed as a value is checked. No legitimate
// value starts with "-": service names and groups can't, and a path can be
// written ./-name. `long_name` is the flag's long form, for the messages.
fn take_value(arg: &str, long_name: &str, args: &mut impl Iterator<Item = String>) -> Result<String, String> {
    let value = args.next().ok_or_else(|| format!("{arg} requires a value"))?;
    if value.is_empty() {
        return Err(format!("{long_name} must not be empty"));
    }
    if value.starts_with('-') {
        return Err(format!(
            "{arg} requires a value, but the next argument is {value:?}; a value can't start with \"-\" (write a path like that as ./{value})"
        ));
    }
    Ok(value)
}

// Parses `--service-name|-sn <value>` when `arg` is that flag; the shared
// piece of both subcommands' argument loops.
fn take_service_name(arg: &str, args: &mut impl Iterator<Item = String>) -> Result<String, String> {
    take_value(arg, "--service-name", args)
}

// Stores a flag's value, refusing a second one rather than letting the last
// win: `-kf a.key ... -kf b.key` is ambiguous about which file the operator
// meant, and silently picking one is how the wrong key file gets written or
// the wrong service's KEK gets used. `flag` is the flag's long name.
fn set_once<T>(slot: &mut Option<T>, flag: &str, value: T) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("give {flag} at most once"));
    }
    *slot = Some(value);
    Ok(())
}

// The command line as UTF-8 strings, or the (1-based) position of the
// first argument that isn't valid UTF-8 -- reported as a usage error
// rather than the panic `std::env::args()` raises.
fn utf8_args(args: impl Iterator<Item = std::ffi::OsString>) -> Result<Vec<String>, String> {
    args.enumerate()
        .map(|(i, a)| a.into_string().map_err(|_| format!("argument {i} is not valid UTF-8")))
        .collect()
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<ParseOutcome, String> {
    let mut args = args.skip(1); // skip argv[0]

    let subcommand = match args.next() {
        None => return Err("missing subcommand: expected `provision`, `wrap` or `retire`".to_string()),
        Some(s) if s == "--help" || s == "-h" || s == "help" => return Ok(ParseOutcome::Help),
        Some(s) => s,
    };

    match subcommand.as_str() {
        "provision" => parse_provision(&mut args),
        "wrap" => parse_wrap(&mut args),
        "retire" => parse_retire(&mut args),
        other => Err(format!("unknown subcommand {other:?}: expected `provision`, `wrap` or `retire`")),
    }
}

fn parse_provision(args: &mut impl Iterator<Item = String>) -> Result<ParseOutcome, String> {
    let mut service_name: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(ParseOutcome::Help),
            "--service-name" | "-sn" => set_once(&mut service_name, "--service-name", take_service_name(&arg, args)?)?,
            "--key-file-path" | "-kf" | "--dek-stdin" | "--dek-file" | "--force" | "-f" | "--group" | "-g" => {
                return Err(format!("{arg} is not valid for `provision`; it belongs to `wrap`"))
            }
            other => return Err(format!("unrecognized argument for `provision`: {other}")),
        }
    }

    let service_name = service_name.ok_or("provision: missing required --service-name|-sn")?;
    Ok(ParseOutcome::Run(Command::Provision { service_name }))
}

fn parse_retire(args: &mut impl Iterator<Item = String>) -> Result<ParseOutcome, String> {
    let mut service_name: Option<String> = None;
    let mut fingerprint: Option<[u8; FINGERPRINT_LEN]> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(ParseOutcome::Help),
            "--service-name" | "-sn" => set_once(&mut service_name, "--service-name", take_service_name(&arg, args)?)?,
            "--fingerprint" | "-fp" => {
                let value = take_value(&arg, "--fingerprint", args)?;
                set_once(&mut fingerprint, "--fingerprint", parse_fingerprint_hex(&value)?)?;
            }
            "--key-file-path" | "-kf" | "--dek-stdin" | "--dek-file" | "--force" | "-f" | "--group" | "-g" => {
                return Err(format!("{arg} is not valid for `retire`; it belongs to `wrap`"))
            }
            other => return Err(format!("unrecognized argument for `retire`: {other}")),
        }
    }

    let service_name = service_name.ok_or("retire: missing required --service-name|-sn")?;
    let fingerprint = fingerprint
        .ok_or("retire: missing required --fingerprint|-fp (the 64-hex-character value printed by provision)")?;
    Ok(ParseOutcome::Run(Command::Retire { service_name, fingerprint }))
}

// Exactly 64 hex digits, either case. No separators or prefixes: the value
// is meant to be pasted from provision's output, and a strict format keeps
// a truncated paste from ever looking valid.
fn parse_fingerprint_hex(text: &str) -> Result<[u8; FINGERPRINT_LEN], String> {
    let digits = text.as_bytes();
    if digits.len() != FINGERPRINT_LEN * 2 {
        return Err(format!(
            "--fingerprint must be exactly {} hex characters, got {}",
            FINGERPRINT_LEN * 2,
            digits.len()
        ));
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; FINGERPRINT_LEN];
    for (i, [hi, lo]) in digits.as_chunks::<2>().0.iter().enumerate() {
        match (nibble(*hi), nibble(*lo)) {
            (Some(hi), Some(lo)) => out[i] = hi << 4 | lo,
            _ => return Err("--fingerprint must contain only hex characters (0-9, a-f)".to_string()),
        }
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_wrap(args: &mut impl Iterator<Item = String>) -> Result<ParseOutcome, String> {
    let mut key_file_path: Option<String> = None;
    let mut service_name: Option<String> = None;
    let mut dek_source: Option<DekSource> = None;
    let mut force = false;
    let mut group: Option<String> = None;
    let mut expected_fingerprint: Option<[u8; FINGERPRINT_LEN]> = None;

    // Rejects a second DEK source rather than letting the last one win:
    // silently ignoring one of two explicitly-requested inputs is exactly
    // the kind of ambiguity that leads to wrapping the wrong key.
    fn set_source(slot: &mut Option<DekSource>, source: DekSource) -> Result<(), String> {
        if slot.is_some() {
            return Err("give exactly one of --dek-stdin or --dek-file".to_string());
        }
        *slot = Some(source);
        Ok(())
    }

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(ParseOutcome::Help),
            "--force" | "-f" => {
                if force {
                    return Err("give --force at most once".to_string());
                }
                force = true;
            }
            "--service-name" | "-sn" => set_once(&mut service_name, "--service-name", take_service_name(&arg, args)?)?,
            "--key-file-path" | "-kf" => {
                let value = take_value(&arg, "--key-file-path", args)?;
                set_once(&mut key_file_path, "--key-file-path", value)?;
            }
            "--group" | "-g" => {
                let value = take_value(&arg, "--group", args)?;
                set_once(&mut group, "--group", value)?;
            }
            "--fingerprint" | "-fp" => {
                let value = take_value(&arg, "--fingerprint", args)?;
                set_once(&mut expected_fingerprint, "--fingerprint", parse_fingerprint_hex(&value)?)?;
            }
            "--dek-stdin" => set_source(&mut dek_source, DekSource::Stdin)?,
            "--dek-file" => {
                let value = take_value(&arg, "--dek-file", args)?;
                set_source(&mut dek_source, DekSource::File(value))?;
            }
            other => return Err(format!("unrecognized argument for `wrap`: {other}")),
        }
    }

    let key_file_path = key_file_path.ok_or("wrap: missing required --key-file-path|-kf")?;
    let service_name = service_name.ok_or("wrap: missing required --service-name|-sn")?;
    let dek_source = dek_source.ok_or("wrap: missing required --dek-stdin or --dek-file <path>")?;

    Ok(ParseOutcome::Run(Command::Wrap {
        key_file_path,
        service_name,
        dek_source,
        force,
        group,
        expected_fingerprint,
    }))
}

// Reads at most `MAX_DEK_INPUT_LEN` bytes from `src` into a single
// pre-sized, self-zeroing buffer.
//
// The buffer is allocated at full size up front and never grown, because
// `read_to_end` reallocates as it goes and leaves the intermediate copies
// un-wiped in freed memory -- the same reasoning the library applies to
// its own secret-file reads. Input longer than the limit is rejected
// rather than truncated, so a wrong file can't silently decode to a
// plausible-looking key.
//
// Reads into `buf` (the caller's `DekScratch`) and returns how many bytes
// it filled.
fn read_bounded(src: &mut dyn Read, what: &str, buf: &mut [u8; MAX_DEK_INPUT_LEN + 1]) -> Result<usize, String> {
    let mut filled = 0;
    while filled < buf.len() {
        match src.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("failed to read {what}: {e}")),
        }
    }
    if filled > MAX_DEK_INPUT_LEN {
        // UTF-16 doubles the text, so it is over the limit long before
        // decode_dek could say why: name it here instead.
        if buf.starts_with(b"\xFF\xFE") || buf.starts_with(b"\xFE\xFF") {
            return Err(UTF16_DEK_MESSAGE.to_string());
        }
        return Err(format!(
            "{what} is longer than {MAX_DEK_INPUT_LEN} bytes; expected base64 of a {DEK_LEN}-byte DEK"
        ));
    }
    Ok(filled)
}

// Opens a --dek-file with the same hardening the library applies to its
// own secret files: O_NOFOLLOW so a symlink fails the open outright, and
// ownership/permission checks made against the *opened descriptor* rather
// than the path, so nothing can be swapped between the check and the read.
fn read_dek_file(path: &str, buf: &mut [u8; MAX_DEK_INPUT_LEN + 1]) -> Result<usize, String> {
    // No symbolic link in the folders above it either, as for the key file
    // (and as the Windows tool requires of its --dek-file): a redirected
    // folder could make the deployment wrap a DEK someone else planted.
    // O_NOFOLLOW below covers the file itself; `require_opened_at` confirms
    // the descriptor is the file at the spelled path. Opened through
    // `spelled`, the path that was checked, never `path` as given: the kernel
    // would follow a link before a `..` in it into another folder (see
    // require_real_folder). Messages still show the operator's spelling.
    let spelled = require_real_folder(Path::new(path))?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY) // a FIFO must fail the regular-file check below, not block the open
        .open(&spelled)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                format!("--dek-file {path} is a symlink; refusing to follow it")
            } else {
                format!("failed to open --dek-file {path}: {e}")
            }
        })?;
    require_opened_at(&file, Path::new(path), &spelled)?;

    let meta = file
        .metadata()
        .map_err(|e| format!("failed to stat --dek-file {path}: {e}"))?;
    if !meta.file_type().is_file() {
        // A FIFO here would block the read indefinitely; a directory or
        // device makes no sense as a key source.
        return Err(format!("--dek-file {path} is not a regular file"));
    }
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(format!(
            "--dek-file {path} is owned by uid {}, which is neither root nor this process's user",
            meta.uid()
        ));
    }
    let offending = meta.mode() & FORBID_GROUP_OTHER_ACCESS;
    if offending != 0 {
        return Err(format!(
            "--dek-file {path} permissions are too broad (mode {:o}; bits {offending:o} must be clear)",
            meta.mode() & 0o7777
        ));
    }

    read_bounded(&mut file, "--dek-file", buf)
}

// Decodes the base64 DEK text, tolerating exactly one trailing newline
// (optionally CRLF) so a file written by `printf '%s\n'` or an editor
// still works, and a leading UTF-8 byte-order mark, which some Windows
// tools (PowerShell, .NET) prepend; a UTF-16 byte-order mark is refused as
// such, since the fix is on the sending side. Then strict standard base64
// (the `+/` alphabet, canonical padding, zero unused bits): no other
// whitespace anywhere. Decoded with base64ct, in constant time with respect
// to the secret text, and any failure reported with one fixed message. The Windows tool applies these rules exactly, so the
// same input is accepted or refused on both. Only base64 is accepted: raw
// 32-byte input fails to decode with a clear error rather than being
// silently misinterpreted.
//
// Decodes into `out` (the caller's `DekScratch`), never into a fresh
// allocation, and returns the DEK as a slice of it.
fn decode_dek<'a>(text: &[u8], out: &'a mut [u8; MAX_DECODED_LEN]) -> Result<&'a [u8], String> {
    let text = text.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(text);
    if text.starts_with(b"\xFF\xFE") || text.starts_with(b"\xFE\xFF") {
        return Err(UTF16_DEK_MESSAGE.to_string());
    }
    let trimmed = match text.strip_suffix(b"\n") {
        Some(t) => t.strip_suffix(b"\r").unwrap_or(t),
        None => text,
    };
    if trimmed.is_empty() {
        return Err("the DEK input is empty".to_string());
    }

    // Constant time over the secret text (base64ct: no data-dependent branch
    // or table lookup), and the error carries no input data either way.
    let len = Base64::decode(trimmed, out).map_err(|_| INVALID_BASE64_DEK_MESSAGE.to_string())?.len();
    if len != DEK_LEN {
        return Err(format!("the DEK must decode to exactly {DEK_LEN} bytes, got {len}"));
    }
    Ok(&out[..DEK_LEN])
}

// Every copy of the DEK this program makes -- the base64 text it reads,
// and the bytes that decodes to -- in one fixed allocation, never grown or
// moved, zeroed before it's freed. When the whole process isn't already
// locked into RAM (`lock_memory`), this allocation is, by itself, with
// mlock(2): it is a page or two, well inside even a 64 KiB RLIMIT_MEMLOCK.
// One allocation, not one per buffer, because mlock works on whole pages
// and locks don't nest: unlocking one of two buffers that shared a page
// would unlock the other.
//
// This covers the CLI's own copies. The library's transient copies (on
// its stack, while it wraps) are covered only by `lock_memory`'s
// mlockall.
struct DekScratch {
    text: [u8; MAX_DEK_INPUT_LEN + 1],
    decoded: [u8; MAX_DECODED_LEN],
    locked: bool,
}

impl DekScratch {
    fn new() -> Box<Self> {
        let mut scratch = Box::new(DekScratch {
            text: [0; MAX_DEK_INPUT_LEN + 1],
            decoded: [0; MAX_DECODED_LEN],
            locked: false,
        });
        if !PROCESS_MEMORY_LOCKED.load(std::sync::atomic::Ordering::Relaxed) {
            // SAFETY: the range is this live, heap-pinned allocation.
            let rc = unsafe { libc::mlock((&raw const *scratch).cast(), std::mem::size_of::<DekScratch>()) };
            if rc == 0 {
                scratch.locked = true;
            } else {
                eprintln!(
                    "warning: could not lock the DEK's buffer into memory (mlock: {}); it could be written to swap",
                    std::io::Error::last_os_error()
                );
            }
        }
        scratch
    }
}

impl Drop for DekScratch {
    fn drop(&mut self) {
        self.text.zeroize();
        self.decoded.zeroize();
        if self.locked {
            // SAFETY: the same range `new` locked; still allocated here.
            unsafe { libc::munlock((&raw const *self).cast(), std::mem::size_of::<DekScratch>()) };
        }
    }
}

// Reads and decodes the DEK from wherever the caller pointed us, into
// `scratch`, and returns it as a slice of `scratch.decoded`.
fn load_dek<'a>(source: &DekSource, scratch: &'a mut DekScratch) -> Result<&'a [u8], String> {
    let len = match source {
        DekSource::Stdin => {
            // A DEK typed or pasted at a terminal is echoed and stays in the
            // scrollback: refuse a terminal outright rather than read it.
            // SAFETY: isatty takes a descriptor number and only inspects it.
            if unsafe { libc::isatty(libc::STDIN_FILENO) } == 1 {
                return Err(TERMINAL_DEK_MESSAGE.to_string());
            }
            // Straight from descriptor 0, never through `std::io::stdin()`:
            // that is a BufReader whose 8 KiB heap buffer would receive the
            // DEK first and keep it, unwiped and unlocked, for the life of
            // the process. ManuallyDrop: the File must not close stdin.
            // SAFETY: descriptor 0 stays open for the process's lifetime,
            // and nothing else in this program reads it.
            let mut fd0 = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(libc::STDIN_FILENO) });
            read_bounded(&mut *fd0, "the DEK on stdin", &mut scratch.text)?
        }
        DekSource::File(path) => read_dek_file(path, &mut scratch.text)?,
    };
    let dek = decode_dek(&scratch.text[..len], &mut scratch.decoded);
    scratch.text.zeroize(); // the base64 text has served its only purpose; don't wait for scope exit
    dek
}

// Maps a library status code to a human-readable description, for a
// clearer error message than a bare integer. Covers every code the Linux
// library can return (the shared table's Windows/macOS-only codes, and
// KEK_ACCESS_DENIED/KEK_INVALID, which Linux never returns, fall through
// to "unknown"). Only the message depends on this: the tool's own exit
// codes don't.
fn describe_status(code: c_int) -> String {
    match code {
        status::INVALID_ARGUMENT => "invalid argument (bad DEK length, etc.)".to_string(),
        status::BUFFER_TOO_SMALL => "the output buffer was too small".to_string(),
        status::PROVIDER_UNAVAILABLE => "no KEK provider is available on this host".to_string(),
        status::PROVIDER_ERROR => "the selected KEK provider failed".to_string(),
        status::CRYPTO_ERROR => "a cryptographic operation failed".to_string(),
        status::INTERNAL_ERROR => "an internal error occurred in the hkdfguard library".to_string(),
        status::INVALID_SERVICE_NAME => "the service name is missing, empty, too long, or contains an invalid character".to_string(),
        status::POLICY_INVALID => {
            "the hkdfguard policy file is invalid or can't be trusted (see the library's log for why)".to_string()
        }
        status::PAYLOAD_MALFORMED => "the wrapped payload is malformed".to_string(),
        status::PAYLOAD_AUTH_FAILED => {
            "the wrapped payload failed authentication (tampered, wrong service, or wrong KEK)".to_string()
        }
        status::PAYLOAD_UNSUPPORTED => "the wrapped payload's version is not supported".to_string(),
        status::KEK_FINGERPRINT_MISMATCH => {
            "the wrapped payload's KEK fingerprint does not match the current KEK for this service".to_string()
        }
        status::KEK_NOT_FOUND => "no KEK exists yet for this service".to_string(),
        status::PROCESS_HARDENING_FAILED => {
            "could not disable core dumps / ptrace access for this process".to_string()
        }
        status::FILE_NOT_FOUND => "the key file, or a directory in its path, does not exist".to_string(),
        status::FILE_ACCESS_DENIED => "permission to open the key file was denied".to_string(),
        status::FILE_IO => "the key file is not a regular file, or reading it failed".to_string(),
        status::FILE_TOO_SHORT => "the key file is shorter than a wrapped DEK".to_string(),
        status::FILE_TOO_LONG => "the key file is longer than a wrapped DEK".to_string(),
        status::FILE_PLAINTEXT_KEY => {
            "the key file looks like an UNWRAPPED DEK; treat it as a key exposure".to_string()
        }
        status::FILE_MALFORMED => "the key file is not a well-formed wrapped DEK".to_string(),
        status::FILE_UNTRUSTED => {
            "the key file, or a directory in its path, is owned by another user or writable by group/others".to_string()
        }
        other => format!("unknown status code {other}"),
    }
}

// Wraps `dek` under `service`'s *existing* KEK. Never provisions one: a
// missing KEK is reported with the exact command that fixes it.
fn wrap_dek(service: &CString, service_display: &str, dek: &[u8]) -> Result<Vec<u8>, String> {
    let mut wrapped = vec![0u8; INITIAL_WRAPPED_CAPACITY];
    let mut wrapped_len: c_int = wrapped.len() as c_int;

    let mut rc = hkdfguard_wrap_dek(
        service.as_ptr(),
        dek.as_ptr(),
        dek.len() as c_int,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );

    if rc == status::BUFFER_TOO_SMALL {
        // `wrapped_len` now holds the size the library actually needs; retry once at that size.
        wrapped = vec![0u8; wrapped_len as usize];
        rc = hkdfguard_wrap_dek(
            service.as_ptr(),
            dek.as_ptr(),
            dek.len() as c_int,
            wrapped.as_mut_ptr(),
            &mut wrapped_len,
        );
    }

    if rc == status::KEK_NOT_FOUND {
        return Err(format!(
            "no KEK is provisioned for service \"{service_display}\"; run \
             `{PROGRAM_NAME} provision --service-name {service_display}` first"
        ));
    }
    if rc != status::OK {
        return Err(format!("hkdfguard_wrap_dek failed: {}", describe_status(rc)));
    }

    wrapped.truncate(wrapped_len as usize);
    Ok(wrapped)
}

// Enforces that `--service-name` -- the string actually used as the KEK's
// identity -- contains only ASCII alphanumeric characters or '.', doesn't
// start with '.', and has no two consecutive dots: the same rules the
// library itself applies (see cstr_to_service in src/lib.rs), checked here
// too so the tool can give a specific message instead of a bare status code.
fn validate_service_charset(service: &str) -> Result<(), String> {
    if !service.chars().all(|c| c.is_ascii_alphanumeric() || c == '.') {
        return Err(format!(
            "service name \"{service}\" must contain only alphanumeric characters or '.'"
        ));
    }
    if service.starts_with('.') {
        return Err(format!("service name \"{service}\" must not start with '.'"));
    }
    if service.contains("..") {
        return Err(format!("service name \"{service}\" must not contain consecutive dots"));
    }
    Ok(())
}

// Validates and normalizes `--service-name` in place, returning it as the
// C string both subcommands hand to the library. Lowercased to match the
// library's own normalization (the ABI treats the name case-insensitively),
// so what's printed here always reflects the actual KEK identity used. Not
// secret -- a logical identifier, not key material.
fn prepare_service(service_name: &mut str) -> Result<CString, String> {
    if service_name.len() > MAX_SERVICE_LEN {
        return Err(format!(
            "--service-name must be at most {MAX_SERVICE_LEN} bytes, got {}",
            service_name.len()
        ));
    }
    validate_service_charset(service_name)?;
    service_name.make_ascii_lowercase();
    CString::new(&*service_name).map_err(|_| "the service name must not contain a NUL byte".to_string())
}

// Looks a group up by name, or by gid when `spec` is all digits, returning
// its gid and name. `None` if no such group exists.
fn lookup_group(spec: &str) -> Result<Option<(libc::gid_t, String)>, String> {
    lookup_group_from(spec, GROUP_LOOKUP_INITIAL_BUF)
}

// getgr*_r need room for the whole entry, member list included, and report
// ERANGE when it doesn't fit -- routine for a large directory (LDAP, AD)
// group. Start here and double on ERANGE, up to GROUP_LOOKUP_MAX_BUF.
const GROUP_LOOKUP_INITIAL_BUF: usize = 16 * 1024;
const GROUP_LOOKUP_MAX_BUF: usize = 1024 * 1024;

fn lookup_group_from(spec: &str, initial_buf: usize) -> Result<Option<(libc::gid_t, String)>, String> {
    let by_gid = !spec.is_empty() && spec.bytes().all(|b| b.is_ascii_digit());
    let gid: libc::gid_t = if by_gid { spec.parse().map_err(|_| format!("--group {spec} is not a valid gid"))? } else { 0 };
    let name = if by_gid { None } else { Some(CString::new(spec).map_err(|_| "--group must not contain a NUL byte".to_string())?) };

    let mut size = initial_buf.max(1);
    loop {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        let mut buf = vec![0u8; size];
        let rc = match &name {
            // SAFETY: every pointer is to a live, correctly sized local.
            None => unsafe { libc::getgrgid_r(gid, &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result) },
            // SAFETY: as above; `name` is NUL-terminated.
            Some(name) => unsafe { libc::getgrnam_r(name.as_ptr(), &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result) },
        };
        if rc == libc::ERANGE && size < GROUP_LOOKUP_MAX_BUF {
            size = (size * 2).min(GROUP_LOOKUP_MAX_BUF);
            continue;
        }
        if rc != 0 {
            return Err(format!("could not look up group {spec}: {}", std::io::Error::from_raw_os_error(rc)));
        }
        if result.is_null() {
            return Ok(None);
        }
        // SAFETY: getgr*_r set gr_name to a NUL-terminated string inside `buf`.
        let found = unsafe { std::ffi::CStr::from_ptr(grp.gr_name) }.to_string_lossy().into_owned();
        return Ok(Some((grp.gr_gid, found)));
    }
}

// Resolves --group to the gid the key file is given, refusing a group that
// doesn't exist or is over-broad (see OVER_BROAD_GROUPS). Done before the
// DEK is read or any provider reached, so a bad --group costs nothing.
fn resolve_key_file_group(spec: &str) -> Result<(libc::gid_t, String), String> {
    let (gid, name) = lookup_group(spec)?.ok_or_else(|| format!("--group \"{spec}\" does not name a group on this host"))?;
    // Fails closed: if a listed group can't be looked up, whether it is this
    // gid can't be ruled out, so --group is refused rather than allowed.
    let mut listed = false;
    for broad in OVER_BROAD_GROUPS {
        if *broad == name {
            listed = true;
            break;
        }
        match lookup_group(broad) {
            Ok(Some((g, _))) if g == gid => {
                listed = true;
                break;
            }
            Ok(_) => {}
            Err(e) => {
                return Err(format!(
                    "--group \"{spec}\": can't confirm it isn't the over-broad group \"{broad}\" ({e}); refusing"
                ))
            }
        }
    }
    if gid == 0 || gid == 65534 || listed {
        return Err(format!(
            "--group \"{spec}\" ({name}, gid {gid}) is an over-broad group (it covers essentially every account, or the \
             host's administrators); name a dedicated group for the service that unwraps this key"
        ));
    }
    Ok((gid, name))
}

// Whether anything at all occupies `path` -- including a dangling symlink,
// which `Path::exists` (it follows links) reports as absent, and which the
// `create_new` below would then fail on with a misleading "already exists".
fn path_is_taken(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

// The absolute path `path` spells, relative paths resolved against the
// current directory and `.`/`..` resolved lexically -- no link followed.
// What every check below compares the real location against: anything
// that differs means a link redirected the path.
fn spelled_absolute(path: &Path) -> Result<PathBuf, String> {
    let absolute = std::path::absolute(path).map_err(|e| format!("failed to resolve {}: {e}", path.display()))?;
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => out.push(name),
            Component::Prefix(_) => return Err(format!("{} is not a Unix path", path.display())),
        }
    }
    Ok(out)
}

// The folder the key file is named in must be a real folder at the place
// spelled: no symbolic link anywhere in it. `create_new` and `O_NOFOLLOW`
// only guard the last component, so without this a symlinked folder above
// the key file is followed silently -- and whoever can plant one where the
// operator writes could redirect an (often root) `wrap --force` into
// overwriting and deleting a file in another folder. Refused, not
// tolerated, as the Windows tool refuses junctions and links above the
// path: there is no legitimate reason for a key file to be reached through
// one. Spell the real path instead (`/run`, not `/var/run`).
//
// Returns the checked path, and callers must use *that* for every
// filesystem call that follows -- never `path` itself. The check resolves
// `..` as text, but the kernel follows a symbolic link before applying a
// `..` after it: `keys/link/../k` is checked as `keys/k`, yet handed to the
// kernel it names `k` beside wherever `link` points. The returned path has
// no `..` left, so the kernel reaches exactly the folder that was checked.
fn require_real_folder(path: &Path) -> Result<PathBuf, String> {
    let spelled = spelled_absolute(path)?;
    let folder = spelled.parent().ok_or_else(|| format!("{} has no parent folder", path.display()))?;
    let real = fs::canonicalize(folder).map_err(|e| format!("failed to resolve the folder of {}: {e}", path.display()))?;
    if real != folder {
        return Err(format!(
            "{}'s folder {} resolves through a symbolic link to {}; the path must be a real path with \
             no links in it",
            path.display(),
            folder.display(),
            real.display()
        ));
    }
    Ok(spelled)
}

// After an open: `file` must be the file at `spelled` (see
// `require_real_folder`) -- nothing was swapped between the folder check
// and the open. Judged from the descriptor: where the kernel says it is
// (/proc/self/fd), and its device and inode against what the spelled path
// names now. Without /proc only the second applies.
fn require_opened_at(file: &File, path: &Path, spelled: &Path) -> Result<(), String> {
    if let Ok(actual) = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())) {
        if actual != spelled {
            return Err(format!(
                "{} was opened at {} instead; refusing to use it (a folder in its path changed)",
                path.display(),
                actual.display()
            ));
        }
    }
    let opened = file.metadata().map_err(|e| format!("failed to stat {}: {e}", path.display()))?;
    let named = fs::symlink_metadata(spelled).map_err(|e| format!("failed to stat {}: {e}", path.display()))?;
    if (opened.dev(), opened.ino()) != (named.dev(), named.ino()) {
        return Err(format!("{} was moved or replaced while it was being opened; refusing to use it", path.display()));
    }
    Ok(())
}

// Largest existing file `--force` will overwrite. A wrapped key is a few
// hundred bytes; something far bigger at the key path isn't one, and
// overwriting it would also mean allocating and writing that much eight
// times over.
const MAX_REPLACEABLE_KEY_FILE_LEN: u64 = 64 * 1024;

// Overwrites `path`'s existing content in place for `SECURE_DELETE_ROUNDS`
// rounds -- each round first an all-zero-bit pass, then a pass of fresh
// random bits, fsync'd after every pass -- before unlinking it. Called only
// when `--force` is about to replace a file that already exists.
//
// Only ever a regular file, and only the one at `path` itself: a symlink
// there is refused rather than followed (following it would overwrite
// whatever it points at -- any file this user can write), as are a FIFO
// (which would block the open forever), a directory, and a device. So is a
// file with more than one name (hard links): the overwrite passes write
// the file itself, so they would also destroy the contents at its other
// name -- any file someone could link into the key's folder. The Windows
// tool refuses the same. The descriptor is opened `O_NOFOLLOW|O_NONBLOCK`
// and re-checked against what was examined, and against where `path`
// spells (`require_opened_at`), so nothing swapped in between gets
// overwritten either.
//
// If the file can't be opened for writing (EACCES/EPERM -- this tool
// doesn't own it), the overwrite passes are skipped entirely and this falls
// back to a plain `remove_file`: destroying
// the old bytes first is worth attempting, but not worth failing the whole
// command over when this process isn't even allowed to write to the file
// it's about to replace -- matches this project's macOS/Windows tools.
fn secure_delete(path: &Path) -> Result<(), String> {
    let refuse = |why: &str| format!("{} {why}; refusing to overwrite it", path.display());
    let check = |meta: &fs::Metadata| -> Result<usize, String> {
        if !meta.file_type().is_file() {
            return Err(refuse("is not a regular file (a symlink, directory, FIFO, or device)"));
        }
        if meta.nlink() != 1 {
            return Err(refuse(&format!(
                "has {} hard links; the key file must have exactly one name, so that overwriting it cannot alter a \
                 file at some other path",
                meta.nlink()
            )));
        }
        if meta.len() > MAX_REPLACEABLE_KEY_FILE_LEN {
            return Err(refuse(&format!("is {} bytes, far larger than any wrapped key", meta.len())));
        }
        Ok(meta.len() as usize)
    };

    // Every stat, open and remove below goes through `spelled`, the path
    // require_real_folder checked -- never `path` as given, which the kernel
    // could resolve into another folder (see require_real_folder).
    let spelled = require_real_folder(path)?;
    let examined = fs::symlink_metadata(&spelled).map_err(|e| format!("failed to stat {}: {e}", path.display()))?;
    check(&examined)?;

    let mut file = match OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(&spelled)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            // Checked above: a regular file with one name, in a real folder.
            return fs::remove_file(&spelled).map_err(|e| {
                format!("failed to remove {} after permission-denied secure delete: {e}", path.display())
            });
        }
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(refuse("changed to a symlink")),
        Err(e) => return Err(format!("failed to open {} for secure delete: {e}", path.display())),
    };
    let opened = file.metadata().map_err(|e| format!("failed to stat {}: {e}", path.display()))?;
    if (opened.dev(), opened.ino()) != (examined.dev(), examined.ino()) {
        return Err(refuse("was replaced while it was being examined"));
    }
    require_opened_at(&file, path, &spelled)?;
    let len = check(&opened)?;

    let mut buf = vec![0u8; len];
    for _ in 0..SECURE_DELETE_ROUNDS {
        buf.iter_mut().for_each(|b| *b = 0); // pass: overwrite with bit 0 throughout
        overwrite_pass(&mut file, path, &buf)?;

        getrandom::fill(&mut buf).map_err(|e| format!("random overwrite of {} failed: {e}", path.display()))?; // pass: overwrite with a fresh random bit pattern
        overwrite_pass(&mut file, path, &buf)?;
    }

    drop(file);
    fs::remove_file(&spelled).map_err(|e| format!("failed to remove {} after secure delete: {e}", path.display()))
}

// Rewinds to the start of `file` and writes `buf` (the same length as the
// file, per `secure_delete`), fsync'ing before returning so this pass is
// durable on disk before the next one begins.
fn overwrite_pass(file: &mut File, path: &Path, buf: &[u8]) -> Result<(), String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("secure delete: failed to seek {}: {e}", path.display()))?;
    file.write_all(buf)
        .map_err(|e| format!("secure delete: failed to write {}: {e}", path.display()))?;
    file.sync_all()
        .map_err(|e| format!("secure delete: failed to sync {}: {e}", path.display()))
}

// `provision`: with `retire`, the only place the setup calls are made. Always calls
// hkdfguard_create_kek, whether or not the KEK exists, as the Windows tool
// does: for an existing KEK that call loads it through the provider
// (`load_kek`) -- on TPM2, deriving the key and checking it against the
// pinned Name; on PKCS#11, finding the key pair on the token -- so a key
// that exists in policy but not on the provider, or doesn't match its pin,
// fails here at deployment rather than at the first wrap. kek_exists alone
// can't tell: on TPM2 it only consults the policy. kek_exists is still
// asked first, only to report the outcome precisely -- "provisioned" versus
// "already provisioned". Neither call changes an existing KEK.
fn run_provision(mut service_name: String) -> Result<(), String> {
    let service_c = prepare_service(&mut service_name)?;

    let mut exists: c_int = 0;
    let rc = hkdfguard_kek_exists(service_c.as_ptr(), &mut exists);
    if rc != status::OK {
        return Err(format!("hkdfguard_kek_exists failed: {}", describe_status(rc)));
    }

    let rc = hkdfguard_create_kek(service_c.as_ptr());
    if rc != status::OK {
        return Err(format!(
            "hkdfguard_create_kek failed for service \"{service_name}\": {} (see the messages above for the \
             provider's reason)",
            describe_status(rc)
        ));
    }
    let fingerprint = read_kek_fingerprint(&service_c).map_err(|rc| {
        format!(
            "the KEK for service \"{service_name}\" exists but its fingerprint could not be read: {}",
            describe_status(rc)
        )
    })?;
    if exists == 1 {
        println!("KEK already provisioned for service \"{service_name}\"; verified, nothing to do");
        println!(
            "fingerprint: {} -- confirm it matches the one recorded when this service was provisioned",
            hex(&fingerprint)
        );
    } else {
        println!("KEK provisioned for service \"{service_name}\"");
        println!("fingerprint: {} -- record this; retire requires it", hex(&fingerprint));
    }
    Ok(())
}

// The fingerprint of the KEK `service` resolves to now, through the C ABI;
// the status code when it can't be read.
fn read_kek_fingerprint(service: &CString) -> Result<[u8; FINGERPRINT_LEN], c_int> {
    let mut out = [0u8; FINGERPRINT_LEN];
    let mut out_len = FINGERPRINT_LEN as c_int;
    let rc = hkdfguard_kek_fingerprint(service.as_ptr(), out.as_mut_ptr(), &mut out_len);
    if rc != status::OK {
        return Err(rc);
    }
    if out_len != FINGERPRINT_LEN as c_int {
        return Err(status::INTERNAL_ERROR);
    }
    Ok(out)
}

// `retire`: deletes the service's KEK for good, through the library's
// Rust-only admin API (deliberately not in the C ABI, so no application
// linking the library can call it). The library confirms the fingerprint
// twice -- against the KEK the service resolves to, and on the exact
// objects it deletes -- so nothing is deleted on a mismatch, and a KEK
// that can't be confirmed is never deleted.
fn run_retire(mut service_name: String, fingerprint: [u8; FINGERPRINT_LEN]) -> Result<(), String> {
    let service_c = prepare_service(&mut service_name)?;
    match admin::retire_kek(&service_name, &fingerprint) {
        Ok(provider) => {
            println!(
                "retired KEK for service \"{service_name}\" (fingerprint {}, provider {})",
                hex(&fingerprint),
                provider.as_str()
            );
            println!("every payload wrapped under it is now permanently unrecoverable");
            Ok(())
        }
        Err(e) if e.status == status::KEK_NOT_FOUND => {
            Err(format!("no KEK exists for service \"{service_name}\"; nothing to retire"))
        }
        Err(e) if e.status == status::KEK_FINGERPRINT_MISMATCH => Err(match read_kek_fingerprint(&service_c) {
            Ok(current) => format!(
                "fingerprint mismatch for service \"{service_name}\": the current KEK is {}, not {}; nothing was deleted",
                hex(&current),
                hex(&fingerprint)
            ),
            Err(_) => format!(
                "fingerprint mismatch for service \"{service_name}\": the current KEK is not {}; nothing was deleted",
                hex(&fingerprint)
            ),
        }),
        Err(e) => Err(format!(
            "could not retire the KEK for service \"{service_name}\": {} ({})",
            e.message,
            describe_status(e.status)
        )),
    }
}

// `wrap`: no setup calls. The wrap is completed in memory before the
// existing key file (if any) is touched, so a failure -- most likely "no
// KEK provisioned" -- never costs the caller the key file they had.
fn run_wrap(
    key_file_path: String,
    mut service_name: String,
    dek_source: DekSource,
    force: bool,
    group: Option<String>,
    expected_fingerprint: Option<[u8; FINGERPRINT_LEN]>,
) -> Result<(), String> {
    // Before anything else -- reading the DEK, any provider work -- the key
    // file's folder must be a real folder at its spelled location. Every
    // filesystem call below then uses the path that check returns, never
    // `key_file_path` as given (see require_real_folder); messages still
    // show the operator's spelling. Checked again, with the open
    // descriptor, when the file is replaced and created below.
    let checked = require_real_folder(Path::new(&key_file_path))?;
    let path = checked.as_path();

    // Fast, friendly pre-check: fail before reading the DEK or touching
    // the provider if the output path obviously already exists and --force
    // wasn't passed. The final `create_new` open below is the actual
    // correctness guarantee against the exists-then-create race; this is
    // purely a fail-fast convenience on top of it.
    if path_is_taken(path) && !force {
        return Err(format!("{key_file_path} already exists; pass --force|-f to overwrite"));
    }
    let group = group.as_deref().map(resolve_key_file_group).transpose()?;

    let service_c = prepare_service(&mut service_name)?;

    let wrapped = {
        // The plaintext DEK is scoped as tightly as possible: read and
        // decode it into a locked scratch buffer, wrap it, and let
        // `DekScratch`'s `Drop` scrub it the instant this block ends --
        // immediately after wrap_dek is done with it, rather than at the
        // end of this function, which would leave it sitting in memory,
        // unused but unwiped, through the file write below. `load_dek`
        // wipes the base64 text it read on the way out, so no copy of that
        // survives this line either.
        let mut scratch = DekScratch::new();
        let dek = load_dek(&dek_source, &mut scratch)?;
        wrap_dek(&service_c, &service_name, dek)?
        // `scratch` is zeroed (and unlocked) here, as this block ends --
        // immediately after wrap_dek returns the wrapped (encrypted, no
        // longer secret) form, which is the only thing that survives past
        // this point.
    };

    // The KEK this payload was actually sealed to, as the library embedded
    // it in the payload it just returned -- not from a separate
    // hkdfguard_kek_fingerprint call, so there is no window between "which
    // KEK?" and "wrap under it", and what is checked and printed is exactly
    // what the file will carry. With --fingerprint, this is the operator's
    // assertion of which KEK the secret may be committed to: on a mismatch
    // (the service's KEK replaced, re-provisioned, or on another provider
    // than expected) nothing is written, and with --force the existing key
    // file is left as it was.
    let used_fingerprint = admin::payload_fingerprint(&wrapped)
        .ok_or("hkdfguard_wrap_dek returned a payload with no readable KEK fingerprint; nothing was written")?;
    if let Some(expected) = expected_fingerprint {
        if used_fingerprint != expected {
            return Err(format!(
                "fingerprint mismatch for service \"{service_name}\": the service's KEK is {}, not {}; nothing was \
                 written -- the DEK was NOT committed to that key",
                hex(&used_fingerprint),
                hex(&expected)
            ));
        }
    }

    // Only now, with a complete wrapped payload in hand, replace the old
    // file. Re-evaluated here rather than trusting the pre-check above, in
    // case the file appeared in the meantime.
    if path_is_taken(path) {
        if !force {
            return Err(format!("{key_file_path} already exists; pass --force|-f to overwrite"));
        }
        secure_delete(path)?;
    }

    // `create_new` makes "does this file already exist" and "create it"
    // one indivisible kernel operation (the actual correctness guarantee
    // against the exists-then-create race), and `.mode(KEY_FILE_MODE)`
    // sets the permissions at the moment of creation so there's no window
    // where the file briefly exists with broader (umask-derived)
    // permissions before being locked down after the fact. By the time
    // this runs, `path` is always either brand new or was just deleted by
    // `secure_delete` above, so `set_permissions` below is defense-in-depth
    // against the umask, not strictly required.
    let spelled = require_real_folder(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(KEY_FILE_MODE)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!("{key_file_path} already exists; pass --force|-f to overwrite")
            } else {
                format!("failed to open {key_file_path}: {e}")
            }
        })?;
    // The file just created must be at the spelled path. If a folder was
    // swapped for a link after the check above, nothing is written: the
    // (still empty) file is removed from wherever it actually landed.
    if let Err(e) = require_opened_at(&file, path, &spelled) {
        if let Ok(actual) = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())) {
            remove_created_file(&actual, &file);
        }
        return Err(e);
    }
    // --group: the file goes to that group on the open descriptor before a
    // byte is written, so it never holds the payload under any other group.
    // It is still 0600 here; the mode widens to 0640 only below, after the
    // group is right. A non-root caller can only give groups it belongs to:
    // the kernel's rule, reported plainly, and the empty file removed.
    if let Some((gid, name)) = &group {
        // SAFETY: a valid open descriptor; uid -1 leaves the owner as it is.
        if unsafe { libc::fchown(file.as_raw_fd(), libc::uid_t::MAX, *gid) } != 0 {
            let e = std::io::Error::last_os_error();
            remove_created_file(path, &file);
            return Err(format!(
                "could not give {key_file_path} to group \"{name}\": {e} (only root, or a member of the group, can)"
            ));
        }
    }
    let mode = if group.is_some() { KEY_FILE_GROUP_MODE } else { KEY_FILE_MODE };
    finish_key_file(&mut file, path, &key_file_path, &wrapped, mode)?;

    let access = match &group {
        Some((_, name)) => format!("owner read/write + {name} read-only"),
        None => "owner read/write".to_string(),
    };
    println!(
        "wrapped key written to {key_file_path} ({} bytes, {access}, service \"{service_name}\")",
        wrapped.len()
    );
    println!(
        "fingerprint: {}{}",
        hex(&used_fingerprint),
        if expected_fingerprint.is_some() {
            " (confirmed)"
        } else {
            " -- confirm it matches the one recorded when this service was provisioned"
        }
    );
    Ok(())
}

// Removes the key file this run created -- but only if `path` still names
// that very file: the same device and inode as the open descriptor. Linux
// can't unlink through a descriptor, so this is the nearest thing to it; a
// file someone renamed into place after the fact is left alone. Best
// effort: it only ever runs on a path that is already failing.
fn remove_created_file(path: &Path, file: &File) {
    let (Ok(opened), Ok(named)) = (file.metadata(), fs::symlink_metadata(path)) else {
        return;
    };
    if (opened.dev(), opened.ino()) == (named.dev(), named.ino()) {
        let _ = fs::remove_file(path);
    }
}

// Writes the payload into the key file just created, gives it its final
// mode, and flushes the file and then its folder to storage, so a reported
// success survives a crash. On any failure the file is removed (see
// remove_created_file): a failed wrap never leaves an empty or truncated key
// file behind, for the next `wrap` to call "already exists" or a service to
// read as malformed. `shown` is the path as the operator spelled it, for
// messages.
fn finish_key_file(file: &mut File, path: &Path, shown: &str, wrapped: &[u8], mode: u32) -> Result<(), String> {
    let result = (|| {
        file.write_all(wrapped).map_err(|e| format!("failed to write {shown}: {e}"))?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| format!("failed to set permissions on {shown}: {e}"))?;
        file.sync_all().map_err(|e| format!("failed to flush {shown} to storage: {e}"))?;
        sync_parent_folder(path).map_err(|e| format!("failed to flush the folder of {shown} to storage: {e}"))
    })();
    if result.is_err() {
        remove_created_file(path, file);
    }
    result
}

// fsync on the folder, so the key file's directory entry -- not just its
// contents -- is on storage.
fn sync_parent_folder(path: &Path) -> std::io::Result<()> {
    let folder = path.parent().ok_or_else(|| std::io::Error::other("the key file has no parent folder"))?;
    File::open(folder)?.sync_all()
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Provision { service_name } => run_provision(service_name),
        Command::Wrap {
            key_file_path,
            service_name,
            dek_source,
            force,
            group,
            expected_fingerprint,
        } => run_wrap(key_file_path, service_name, dek_source, force, group, expected_fingerprint),
        Command::Retire { service_name, fingerprint } => run_retire(service_name, fingerprint),
    }
}

// `CAP_IPC_LOCK`'s bit in the capability sets of /proc/self/status.
#[cfg(any(target_os = "linux", test))]
const CAP_IPC_LOCK: u32 = 14;

// Whether `mlockall(MCL_CURRENT | MCL_FUTURE)` is safe to apply: only when
// no RLIMIT_MEMLOCK can ever be hit. With a finite limit the kernel either
// refuses MCL_CURRENT outright (virtual size over the limit -- harmless,
// nothing is applied) or accepts it, after which MCL_FUTURE makes any
// allocation that would cross the limit fail and the process abort
// mid-operation. CAP_IPC_LOCK bypasses the limit; so does an unlimited one.
#[cfg(any(target_os = "linux", test))]
fn memory_lock_is_unbounded(cap_eff: Option<u64>, memlock_soft: u64, memlock_hard: u64, infinity: u64) -> bool {
    let has_ipc_lock = cap_eff.is_some_and(|caps| caps & (1u64 << CAP_IPC_LOCK) != 0);
    has_ipc_lock || (memlock_soft == infinity && memlock_hard == infinity)
}

// The effective capability set, from the `CapEff:` line of a
// /proc/<pid>/status document. `None` if absent or malformed.
#[cfg(any(target_os = "linux", test))]
fn parse_cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

// Set once `lock_memory` has locked the whole process; `DekScratch` then
// doesn't lock (or, worse, later unlock) its own pages.
static PROCESS_MEMORY_LOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// Keeps this process's memory -- the plaintext DEK included -- out of swap.
// Applied only when it can't later abort an allocation (see
// `memory_lock_is_unbounded`); otherwise skipped with a warning, since
// default limits for unprivileged users would make it fail or, worse,
// succeed and then kill the process -- and the DEK's own buffer is locked
// by itself instead (`DekScratch`). If it should work and doesn't, that is
// an error.
#[cfg(target_os = "linux")]
fn lock_memory() -> Result<(), String> {
    let cap_eff = fs::read_to_string("/proc/self/status").ok().as_deref().and_then(parse_cap_eff);
    let mut memlock = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit writes into a valid rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut memlock) } != 0 {
        return Err(format!("could not read RLIMIT_MEMLOCK: {}", std::io::Error::last_os_error()));
    }

    if !memory_lock_is_unbounded(cap_eff, memlock.rlim_cur, memlock.rlim_max, libc::RLIM_INFINITY) {
        eprintln!(
            "warning: memory not locked as a whole: needs CAP_IPC_LOCK or an unlimited \
             RLIMIT_MEMLOCK (e.g. run as root, or LimitMEMLOCK=infinity for a systemd unit); \
             the DEK's own buffer is locked instead, but the library's transient copies \
             could be written to swap"
        );
        return Ok(());
    }

    // SAFETY: mlockall takes only flags.
    if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
        return Err(format!(
            "could not lock memory (mlockall): {}",
            std::io::Error::last_os_error()
        ));
    }
    PROCESS_MEMORY_LOCKED.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn lock_memory() -> Result<(), String> {
    Ok(())
}

// Prints the library's warnings and errors to stderr. The library reports
// through the `log` facade and is silent without a logger installed, which
// would hide exactly the messages an operator running this tool needs --
// e.g. the TPM Name to pin when `provision` is refused under
// `tpm.require_pinned_names`, or why a PIN file or secret was rejected.
struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Warn
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("{}: {}", record.level().as_str().to_ascii_lowercase(), record.args());
        }
    }
    fn flush(&self) {}
}

static LOGGER: StderrLogger = StderrLogger;

fn main() -> ExitCode {
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(log::LevelFilter::Warn);
    }
    // Before anything is read: this process holds a plaintext DEK, so it
    // must not be dumpable or debuggable by other processes of the same
    // user. Refuse to run rather than handle a DEK unprotected. The strict
    // flag, as the Windows tool passes: on Linux it adds no check
    // (PR_SET_DUMPABLE 0 already bars same-user ptrace), but the three
    // tools should ask for the same thing.
    let rc = hkdfguard_harden_process_with_flags(harden_flags::REQUIRE_PROTECTED_SIGNATURE);
    if rc != status::OK {
        eprintln!("error: {}; refusing to handle key material", describe_status(rc));
        return ExitCode::FAILURE;
    }
    if let Err(e) = lock_memory() {
        eprintln!("error: {e}; refusing to handle key material");
        return ExitCode::FAILURE;
    }
    // An ephemeral KEK would exist only in this process: `provision` would
    // create one that vanishes on exit, and `wrap` would produce a payload
    // nothing could ever unwrap. The library refuses it with an explanation.
    hkdfguard::refuse_ephemeral_keys_in_this_process();
    let parsed = utf8_args(std::env::args_os()).and_then(|args| parse_args(args.into_iter()));
    match parsed {
        Ok(ParseOutcome::Help) => {
            print_usage();
            ExitCode::SUCCESS
        }
        Ok(ParseOutcome::Run(command)) => match run(command) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("error: {e}");
            print_usage();
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serial_test::serial;
    use tempfile::NamedTempFile;

    #[test]
    fn every_status_the_linux_library_returns_is_described() {
        for code in [
            status::INVALID_ARGUMENT,
            status::BUFFER_TOO_SMALL,
            status::PROVIDER_UNAVAILABLE,
            status::PROVIDER_ERROR,
            status::CRYPTO_ERROR,
            status::INTERNAL_ERROR,
            status::INVALID_SERVICE_NAME,
            status::POLICY_INVALID,
            status::PAYLOAD_MALFORMED,
            status::PAYLOAD_AUTH_FAILED,
            status::PAYLOAD_UNSUPPORTED,
            status::KEK_FINGERPRINT_MISMATCH,
            status::KEK_NOT_FOUND,
            status::PROCESS_HARDENING_FAILED,
            status::FILE_NOT_FOUND,
            status::FILE_ACCESS_DENIED,
            status::FILE_IO,
            status::FILE_TOO_SHORT,
            status::FILE_TOO_LONG,
            status::FILE_PLAINTEXT_KEY,
            status::FILE_MALFORMED,
            status::FILE_UNTRUSTED,
        ] {
            assert!(!describe_status(code).starts_with("unknown"), "status {code} has no description");
        }
        assert_eq!(describe_status(status::MAC_KEYCHAIN_READ_FAILED), "unknown status code -100");
    }

    // Only this user can write to it, whatever the umask: the library refuses
    // to trust a policy or secret mount in a group-writable directory.
    fn private_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new().permissions(fs::Permissions::from_mode(0o700)).tempdir().unwrap()
    }

    fn argv(parts: &[&str]) -> impl Iterator<Item = String> {
        parts.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
    }

    // `ParseOutcome` has no `Debug` impl, so pull results out by matching.
    fn expect_run(args: impl Iterator<Item = String>) -> Command {
        match parse_args(args) {
            Ok(ParseOutcome::Run(c)) => c,
            Ok(ParseOutcome::Help) => panic!("expected Run, got Help"),
            Err(e) => panic!("expected Run, got error: {e}"),
        }
    }
    fn expect_parse_err(args: impl Iterator<Item = String>) -> String {
        match parse_args(args) {
            Err(e) => e,
            Ok(_) => panic!("expected a parse error"),
        }
    }

    // `secure_delete`'s multi-pass overwrite content isn't observable from
    // outside the function by the time it returns (the file is gone by
    // then) -- what's directly testable here is its documented end state:
    // the file no longer exists. (An inode-number check would not be a
    // reliable stronger signal: some filesystems reuse a just-freed inode
    // immediately for a new file.)
    #[test]
    fn secure_delete_removes_the_file() {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), b"sensitive content to be wiped").unwrap();
        assert!(file.path().exists());

        secure_delete(file.path()).unwrap();

        assert!(!file.path().exists());
    }

    #[test]
    fn secure_delete_handles_an_empty_file() {
        let file = NamedTempFile::new().unwrap(); // created empty
        secure_delete(file.path()).unwrap();
        assert!(!file.path().exists());
    }

    #[test]
    fn secure_delete_refuses_a_symlink_and_leaves_its_target_alone() {
        let dir = private_tempdir();
        let victim = dir.path().join("some-other-file");
        fs::write(&victim, b"not a wrapped key").unwrap();
        let link = dir.path().join("wrapped.key");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let err = secure_delete(&link).unwrap_err();
        assert!(err.contains("not a regular file"), "unexpected: {err}");
        assert_eq!(fs::read(&victim).unwrap(), b"not a wrapped key", "the link's target must be untouched");
        assert!(path_is_taken(&link), "and the link itself is left for the operator to look at");
    }

    #[test]
    fn secure_delete_refuses_a_fifo_without_blocking() {
        let dir = private_tempdir();
        let fifo = dir.path().join("wrapped.key");
        let c = CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: c is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || tx.send(secure_delete(&path)).unwrap());
        let result = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("secure_delete blocked on a FIFO");
        assert!(result.unwrap_err().contains("not a regular file"));
    }

    #[test]
    fn secure_delete_refuses_a_file_far_larger_than_a_wrapped_key() {
        let dir = private_tempdir();
        let big = dir.path().join("wrapped.key");
        let f = File::create(&big).unwrap();
        f.set_len(MAX_REPLACEABLE_KEY_FILE_LEN + 1).unwrap(); // sparse: no real disk use
        let err = secure_delete(&big).unwrap_err();
        assert!(err.contains("far larger"), "unexpected: {err}");
        assert!(big.exists());
    }

    #[test]
    fn a_dangling_symlink_counts_as_taken() {
        let dir = private_tempdir();
        let link = dir.path().join("wrapped.key");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &link).unwrap();
        assert!(!link.exists(), "Path::exists follows the link");
        assert!(path_is_taken(&link));
    }

    #[test]
    fn secure_delete_fails_cleanly_on_a_missing_file() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        drop(file);
        fs::remove_file(&path).ok();
        assert!(secure_delete(&path).is_err());
    }

    #[test]
    fn secure_delete_refuses_a_hard_linked_file_and_leaves_both_names_intact() {
        let dir = private_tempdir();
        let base = fs::canonicalize(dir.path()).unwrap();
        let key = base.join("wrapped.key");
        fs::write(&key, b"payload").unwrap();
        let other = base.join("elsewhere.dat");
        fs::hard_link(&key, &other).unwrap();
        let err = secure_delete(&key).unwrap_err();
        assert!(err.contains("2 hard links"), "{err}");
        assert_eq!(fs::read(&other).unwrap(), b"payload", "the other name's contents are untouched");
        assert!(key.exists(), "the key file itself is left in place");
    }

    #[test]
    fn spelled_absolute_resolves_dots_lexically() {
        assert_eq!(spelled_absolute(Path::new("/a/./b/../c/key")).unwrap(), PathBuf::from("/a/c/key"));
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(spelled_absolute(Path::new("key")).unwrap(), cwd.join("key"));
    }

    #[test]
    fn require_real_folder_refuses_a_symlinked_folder_anywhere_above_the_file() {
        use std::os::unix::fs::symlink;
        let dir = private_tempdir();
        let base = fs::canonicalize(dir.path()).unwrap();
        let real = base.join("real");
        fs::create_dir_all(real.join("sub")).unwrap();
        let link = base.join("link");
        symlink(&real, &link).unwrap();

        assert_eq!(require_real_folder(&real.join("k")).unwrap(), real.join("k"));
        assert!(require_real_folder(&real.join("sub/../k")).is_ok(), "`..` resolved lexically is fine");

        let err = require_real_folder(&link.join("k")).unwrap_err();
        assert!(err.contains("symbolic link") && err.contains(real.to_str().unwrap()), "{err}");
        let err = require_real_folder(&link.join("sub/k")).unwrap_err();
        assert!(err.contains("symbolic link"), "a link further up is refused too: {err}");
    }

    #[test]
    fn secure_delete_refuses_a_file_reached_through_a_symlinked_folder() {
        use std::os::unix::fs::symlink;
        let dir = private_tempdir();
        let base = fs::canonicalize(dir.path()).unwrap();
        let real = base.join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("victim.key"), b"not yours").unwrap();
        symlink(&real, base.join("link")).unwrap();
        let err = secure_delete(&base.join("link/victim.key")).unwrap_err();
        assert!(err.contains("symbolic link"), "{err}");
        assert_eq!(fs::read(real.join("victim.key")).unwrap(), b"not yours");
    }

    #[test]
    fn read_dek_file_refuses_a_file_reached_through_a_symlinked_folder() {
        use std::os::unix::fs::symlink;
        let dir = private_tempdir();
        let base = fs::canonicalize(dir.path()).unwrap();
        let real = base.join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("dek.b64"), valid_b64()).unwrap();
        fs::set_permissions(real.join("dek.b64"), fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&real, base.join("link")).unwrap();
        let mut buf = [0u8; MAX_DEK_INPUT_LEN + 1];
        let err = read_dek_file(base.join("link/dek.b64").to_str().unwrap(), &mut buf).unwrap_err();
        assert!(err.contains("symbolic link"), "{err}");
        // The real path reads.
        assert!(read_dek_file(real.join("dek.b64").to_str().unwrap(), &mut buf).is_ok());
    }

    #[test]
    fn read_dek_file_reads_the_checked_file_not_one_beside_a_link_before_dotdot() {
        // keys/link -> elsewhere/deep, so to the kernel keys/link/.. is
        // `elsewhere`, while the folder check resolves it as text to `keys`.
        // The file read must be the one checked: keys/dek.b64, never
        // elsewhere/dek.b64.
        use std::os::unix::fs::symlink;
        let dir = private_tempdir();
        let base = fs::canonicalize(dir.path()).unwrap();
        let keys = base.join("keys");
        let elsewhere = base.join("elsewhere");
        fs::create_dir_all(elsewhere.join("deep")).unwrap();
        fs::create_dir(&keys).unwrap();
        symlink(elsewhere.join("deep"), keys.join("link")).unwrap();
        let checked = STANDARD.encode([0x11u8; DEK_LEN]);
        let planted = STANDARD.encode([0x22u8; DEK_LEN]);
        for (folder, text) in [(&keys, &checked), (&elsewhere, &planted)] {
            fs::write(folder.join("dek.b64"), text).unwrap();
            fs::set_permissions(folder.join("dek.b64"), fs::Permissions::from_mode(0o600)).unwrap();
        }

        let mut buf = [0u8; MAX_DEK_INPUT_LEN + 1];
        let n = read_dek_file(keys.join("link/../dek.b64").to_str().unwrap(), &mut buf).unwrap();
        assert_eq!(&buf[..n], checked.as_bytes(), "read the file at the checked path, keys/dek.b64");
    }

    #[test]
    fn secure_delete_never_follows_a_link_before_dotdot_into_another_folder() {
        // keys/link -> elsewhere/deep, so to the kernel keys/link/.. is
        // `elsewhere`, while the folder check resolves it as text to `keys`.
        // The file in `elsewhere` is read-only, so opening it for writing
        // fails and secure_delete takes its plain-remove fallback -- which
        // must act on the checked path (keys/victim.key, absent) and leave
        // elsewhere/victim.key alone.
        use std::os::unix::fs::symlink;
        let dir = private_tempdir();
        let base = fs::canonicalize(dir.path()).unwrap();
        let keys = base.join("keys");
        let elsewhere = base.join("elsewhere");
        fs::create_dir_all(elsewhere.join("deep")).unwrap();
        fs::create_dir(&keys).unwrap();
        symlink(elsewhere.join("deep"), keys.join("link")).unwrap();
        let victim = elsewhere.join("victim.key");
        fs::write(&victim, b"someone else's file").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o400)).unwrap();

        let err = secure_delete(&keys.join("link/../victim.key")).unwrap_err();
        assert!(err.contains("failed to stat"), "nothing at the checked path keys/victim.key: {err}");
        assert_eq!(fs::read(&victim).unwrap(), b"someone else's file", "the file in the other folder is untouched");
    }

    #[test]
    fn remove_created_file_removes_only_the_file_it_created() {
        let dir = private_tempdir();
        let base = fs::canonicalize(dir.path()).unwrap();
        let key = base.join("wrapped.key");
        fs::write(&key, b"").unwrap();
        let file = File::open(&key).unwrap();

        // Renamed away and another file put at the name: that one stays.
        fs::rename(&key, base.join("moved.key")).unwrap();
        fs::write(&key, b"someone else's file").unwrap();
        remove_created_file(&key, &file);
        assert_eq!(fs::read(&key).unwrap(), b"someone else's file", "a file renamed into place is left alone");

        // Still the same file at the name: removed.
        let moved = base.join("moved.key");
        remove_created_file(&moved, &file);
        assert!(!moved.exists(), "the created file itself is removed");
    }

    #[test]
    fn finish_key_file_writes_flushes_and_sets_the_mode() {
        let dir = private_tempdir();
        let base = fs::canonicalize(dir.path()).unwrap();
        let key = base.join("wrapped.key");
        let mut file = OpenOptions::new().write(true).create_new(true).mode(KEY_FILE_MODE).open(&key).unwrap();
        finish_key_file(&mut file, &key, "wrapped.key", b"payload", KEY_FILE_GROUP_MODE).unwrap();
        assert_eq!(fs::read(&key).unwrap(), b"payload");
        assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, KEY_FILE_GROUP_MODE);
    }

    #[test]
    fn finish_key_file_removes_the_file_when_writing_fails() {
        // A descriptor opened read-only: write_all fails, as a full disk or
        // an I/O error would make it. No empty key file may be left behind.
        let dir = private_tempdir();
        let base = fs::canonicalize(dir.path()).unwrap();
        let key = base.join("wrapped.key");
        fs::write(&key, b"").unwrap();
        let mut read_only = File::open(&key).unwrap();
        let err = finish_key_file(&mut read_only, &key, "wrapped.key", b"payload", KEY_FILE_MODE).unwrap_err();
        assert!(err.contains("failed to write wrapped.key"), "{err}");
        assert!(!key.exists(), "the failed key file is removed");
    }

    #[test]
    fn lookup_group_grows_its_buffer_until_the_entry_fits() {
        // Starting from a 1-byte buffer forces ERANGE on any real entry; the
        // retry must still find this process's own group, by gid and name.
        // SAFETY: no arguments, cannot fail.
        let gid = unsafe { libc::getegid() };
        let (found_gid, name) = lookup_group_from(&gid.to_string(), 1).unwrap().expect("own group by gid");
        assert_eq!(found_gid, gid);
        assert_eq!(lookup_group_from(&name, 1).unwrap(), Some((gid, name.clone())), "and by name");
        assert_eq!(lookup_group_from(&gid.to_string(), 1).unwrap(), lookup_group(&gid.to_string()).unwrap());
    }

    #[test]
    fn require_opened_at_accepts_the_file_at_its_spelled_path() {
        let dir = private_tempdir();
        let base = fs::canonicalize(dir.path()).unwrap();
        let key = base.join("k");
        fs::write(&key, b"x").unwrap();
        let file = File::open(&key).unwrap();
        assert!(require_opened_at(&file, &key, &key).is_ok());
        let other = base.join("other");
        fs::write(&other, b"y").unwrap();
        assert!(require_opened_at(&file, &key, &other).is_err(), "opened somewhere other than spelled");
    }

    #[test]
    fn validate_service_charset_accepts_alphanumerics_and_dots() {
        assert!(validate_service_charset("com.example.orders").is_ok());
        assert!(validate_service_charset("Service123.42").is_ok());
    }

    #[test]
    fn validate_service_charset_rejects_other_characters() {
        for bad in ["com_example", "com example", "com-example", "com/example"] {
            assert!(validate_service_charset(bad).is_err(), "should reject \"{bad}\"");
        }
    }

    #[test]
    fn validate_service_charset_rejects_leading_and_consecutive_dots() {
        for bad in [".", "..", "...", ".hidden", "..parent", "com..example", "com.example..", "a...b"] {
            assert!(validate_service_charset(bad).is_err(), "should reject \"{bad}\"");
        }
    }

    // ---- subcommand parsing ----

    #[test]
    fn parse_requires_a_subcommand() {
        let err = expect_parse_err(argv(&["prog"]));
        assert!(err.contains("provision") && err.contains("wrap"), "{err}");

        let err = expect_parse_err(argv(&["prog", "frobnicate", "-sn", "svc"]));
        assert!(err.contains("unknown subcommand"), "{err}");
    }

    #[test]
    fn parse_help_in_every_position() {
        for args in [
            vec!["prog", "--help"],
            vec!["prog", "-h"],
            vec!["prog", "help"],
            vec!["prog", "provision", "--help"],
            vec!["prog", "wrap", "-kf", "k", "-h"],
        ] {
            assert!(matches!(parse_args(argv(&args)), Ok(ParseOutcome::Help)), "{args:?}");
        }
    }

    #[test]
    fn parse_provision() {
        assert_eq!(
            expect_run(argv(&["prog", "provision", "--service-name", "svc"])),
            Command::Provision { service_name: "svc".to_string() }
        );
        assert_eq!(
            expect_run(argv(&["prog", "provision", "-sn", "svc"])),
            Command::Provision { service_name: "svc".to_string() }
        );

        let err = expect_parse_err(argv(&["prog", "provision"]));
        assert!(err.contains("--service-name"), "{err}");
        let err = expect_parse_err(argv(&["prog", "provision", "-sn", ""]));
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn provision_refuses_wrap_only_flags() {
        for flag in [
            vec!["--key-file-path", "k"],
            vec!["-kf", "k"],
            vec!["--dek-stdin"],
            vec!["--dek-file", "/x"],
            vec!["--force"],
            vec!["--group", "g"],
            vec!["-g", "g"],
        ] {
            let mut a = vec!["prog", "provision", "-sn", "svc"];
            a.extend(flag.iter());
            let err = expect_parse_err(argv(&a));
            assert!(err.contains("belongs to `wrap`"), "{flag:?}: {err}");
        }
    }

    #[test]
    fn parse_wrap_accepts_stdin_and_file_sources() {
        match expect_run(argv(&["prog", "wrap", "-kf", "key.bin", "-sn", "svc", "--dek-stdin"])) {
            Command::Wrap { key_file_path, service_name, dek_source, force, group, expected_fingerprint } => {
                assert_eq!(key_file_path, "key.bin");
                assert_eq!(service_name, "svc");
                assert_eq!(dek_source, DekSource::Stdin);
                assert!(!force);
                assert_eq!(group, None, "--group is optional: owner-only by default");
                assert_eq!(expected_fingerprint, None, "--fingerprint is optional");
            }
            other => panic!("expected Wrap, got {other:?}"),
        }

        let fp = "Ab".repeat(32);
        match expect_run(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "-fp", &fp])) {
            Command::Wrap { expected_fingerprint, .. } => assert_eq!(expected_fingerprint, Some([0xab; 32])),
            other => panic!("expected Wrap, got {other:?}"),
        }
        for (parts, expected) in [
            (vec!["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "-fp", "abc"], "exactly 64 hex characters, got 3"),
            (vec!["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "-fp", fp.as_str(), "--fingerprint", fp.as_str()], "give --fingerprint at most once"),
            (vec!["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "--fingerprint", "-f"], "requires a value, but the next argument is"),
        ] {
            let err = expect_parse_err(argv(&parts));
            assert!(err.contains(expected), "{parts:?}: {err}");
        }

        match expect_run(argv(&[
            "prog", "wrap", "--key-file-path", "key.bin", "--service-name", "svc", "--dek-file", "/run/secrets/dek", "--force",
        ])) {
            Command::Wrap { dek_source, force, .. } => {
                assert_eq!(dek_source, DekSource::File("/run/secrets/dek".to_string()));
                assert!(force);
            }
            other => panic!("expected Wrap, got {other:?}"),
        }
    }

    #[test]
    fn parse_wrap_requires_key_file_service_and_exactly_one_dek_source() {
        let err = expect_parse_err(argv(&["prog", "wrap", "-sn", "svc", "--dek-stdin"]));
        assert!(err.contains("--key-file-path"), "{err}");

        let err = expect_parse_err(argv(&["prog", "wrap", "-kf", "k", "--dek-stdin"]));
        assert!(err.contains("--service-name"), "{err}");

        let err = expect_parse_err(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc"]));
        assert!(err.contains("--dek-stdin"), "a DEK source is mandatory: {err}");

        // Two sources -- rejected rather than last-one-wins, so an
        // ambiguous invocation can't quietly wrap the wrong key.
        assert!(parse_args(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "--dek-file", "/x"])).is_err());
        assert!(parse_args(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-file", "/x", "--dek-file", "/y"])).is_err());
    }

    #[test]
    fn parse_wrap_takes_an_optional_group_once() {
        match expect_run(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "--group", "orders"])) {
            Command::Wrap { group, .. } => assert_eq!(group.as_deref(), Some("orders")),
            other => panic!("expected Wrap, got {other:?}"),
        }
        match expect_run(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "-g", "orders"])) {
            Command::Wrap { group, .. } => assert_eq!(group.as_deref(), Some("orders")),
            other => panic!("expected Wrap, got {other:?}"),
        }
        let err = expect_parse_err(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "-g", "a", "-g", "b"]));
        assert!(err.contains("at most once"), "{err}");
        let err = expect_parse_err(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "--group", ""]));
        assert!(err.contains("must not be empty"), "{err}");
        assert!(expect_parse_err(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "--group"])).contains("requires a value"));
    }

    #[test]
    fn retire_parses_a_service_and_its_fingerprint() {
        let fp = "ab".repeat(32);
        match expect_run(argv(&["prog", "retire", "-sn", "svc", "-fp", &fp])) {
            Command::Retire { service_name, fingerprint } => {
                assert_eq!(service_name, "svc");
                assert_eq!(fingerprint, [0xab; 32]);
            }
            other => panic!("expected Retire, got {other:?}"),
        }
        match expect_run(argv(&["prog", "retire", "--fingerprint", &"AB".repeat(32), "--service-name", "svc"])) {
            Command::Retire { fingerprint, .. } => assert_eq!(fingerprint, [0xab; 32], "either case, either order"),
            other => panic!("expected Retire, got {other:?}"),
        }

        for (parts, expected) in [
            (vec!["prog", "retire", "-sn", "svc"], "missing required --fingerprint"),
            (vec!["prog", "retire", "-fp", fp.as_str()], "missing required --service-name"),
            (vec!["prog", "retire", "-sn", "svc", "-fp", &fp[..63]], "exactly 64 hex characters, got 63"),
            (vec!["prog", "retire", "-sn", "svc", "-fp", "0x1234"], "exactly 64 hex characters"),
            (vec!["prog", "retire", "-sn", "svc", "-fp", fp.as_str(), "-fp", fp.as_str()], "give --fingerprint at most once"),
            (vec!["prog", "retire", "-sn", "svc", "-fp", fp.as_str(), "-kf", "k"], "it belongs to `wrap`"),
            (vec!["prog", "retire", "-sn", "svc", "-fp", fp.as_str(), "--corrupt"], "unrecognized argument for `retire`"),
            (vec!["prog", "retire", "-sn", "svc", "-fp", "--force"], "requires a value, but the next argument is"),
        ] {
            let err = expect_parse_err(argv(&parts));
            assert!(err.contains(expected), "{parts:?}: {err}");
        }
        let bad = format!("{}zz", "ab".repeat(31));
        assert!(expect_parse_err(argv(&["prog", "retire", "-sn", "svc", "-fp", &bad])).contains("only hex characters"));
        assert!(expect_parse_err(argv(&["prog", "frobnicate"])).contains("expected `provision`, `wrap` or `retire`"));
    }

    #[test]
    fn a_flag_value_starting_with_a_dash_is_refused() {
        // A forgotten value must not swallow the next flag: `-kf --force`
        // would otherwise name a key file "--force" and drop --force.
        for parts in [
            vec!["prog", "wrap", "-kf", "--force", "-sn", "svc", "--dek-stdin"],
            vec!["prog", "wrap", "-kf", "k", "-sn", "-g", "--dek-stdin"],
            vec!["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "-g", "-f"],
            vec!["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-file", "--force"],
            vec!["prog", "wrap", "-kf", "-", "-sn", "svc", "--dek-stdin"],
            vec!["prog", "provision", "--service-name", "-h"],
        ] {
            let err = expect_parse_err(argv(&parts));
            assert!(err.contains("requires a value, but the next argument is"), "{parts:?}: {err}");
        }
        // Flags themselves are unaffected, short or long; ./-name is the way
        // to give a path that starts with "-".
        match expect_run(argv(&["prog", "wrap", "-kf", "./-k", "-sn", "svc", "--dek-stdin", "-f"])) {
            Command::Wrap { key_file_path, force, .. } => {
                assert_eq!(key_file_path, "./-k");
                assert!(force);
            }
            other => panic!("expected Wrap, got {other:?}"),
        }
    }

    #[test]
    fn every_repeated_flag_is_refused_rather_than_the_last_winning() {
        for (parts, flag) in [
            (vec!["prog", "wrap", "-kf", "a", "-kf", "b", "-sn", "svc", "--dek-stdin"], "--key-file-path"),
            (vec!["prog", "wrap", "--key-file-path", "a", "-kf", "a", "-sn", "svc", "--dek-stdin"], "--key-file-path"),
            (vec!["prog", "wrap", "-kf", "k", "-sn", "a", "--service-name", "b", "--dek-stdin"], "--service-name"),
            (vec!["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "-f", "--force"], "--force"),
            (vec!["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "-g", "a", "--group", "a"], "--group"),
            (vec!["prog", "provision", "-sn", "a", "-sn", "a"], "--service-name"),
        ] {
            let err = expect_parse_err(argv(&parts));
            assert_eq!(err, format!("give {flag} at most once"), "{parts:?}");
        }
    }

    #[test]
    fn a_non_utf8_argument_is_a_usage_error_not_a_panic() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let args = vec![
            OsString::from("prog"),
            OsString::from("wrap"),
            OsString::from("-kf"),
            OsString::from_vec(vec![b'k', 0xff, b'y']),
        ];
        assert_eq!(utf8_args(args.into_iter()).unwrap_err(), "argument 3 is not valid UTF-8");
        let ok = utf8_args(["prog", "provision"].into_iter().map(OsString::from)).unwrap();
        assert_eq!(ok, ["prog", "provision"]);
    }

    #[test]
    fn over_broad_and_unknown_groups_are_refused() {
        for spec in ["root", "0", "65534"] {
            let err = resolve_key_file_group(spec).unwrap_err();
            assert!(err.contains("over-broad") || err.contains("does not name a group"), "{spec}: {err}");
        }
        assert!(resolve_key_file_group("root").unwrap_err().contains("over-broad"));
        assert!(resolve_key_file_group("0").unwrap_err().contains("over-broad"), "by gid as well as by name");
        // Any of the listed names that exists on this host is refused, by
        // name and by its gid.
        for broad in OVER_BROAD_GROUPS {
            if let Ok(Some((gid, _))) = lookup_group(broad) {
                assert!(resolve_key_file_group(broad).unwrap_err().contains("over-broad"), "{broad}");
                assert!(resolve_key_file_group(&gid.to_string()).unwrap_err().contains("over-broad"), "{broad} as {gid}");
            }
        }
        let err = resolve_key_file_group("hkdfguard-no-such-group-xyz").unwrap_err();
        assert!(err.contains("does not name a group"), "{err}");
    }

    // ---- provision / wrap against the real library, in-process ----

    // Points the library at a policy that names Ephemeral (the only
    // provider that can *create* a KEK without external state) and at no
    // external-secret mount. Ephemeral keys are per-process, which is
    // exactly right for an in-process test of the provision flow.
    fn with_ephemeral_policy<F: FnOnce()>(f: F) {
        let dir = private_tempdir();
        let policy = dir.path().join("policy.toml");
        fs::write(&policy, "preferred_order = [\"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n").unwrap();
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o644)).unwrap(); // not the umask: some distros default to 002 (group-writable), which the policy loader correctly refuses
        std::env::set_var("HKDFGUARD_POLICY_FILE", &policy);
        f();
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
    }

    #[test]
    #[serial]
    #[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
    fn provision_creates_then_reports_already_provisioned() {
        // Pays the library's real setup-call floor (this binary links the
        // library without cfg(test)): kek_exists + create_kek, then
        // kek_exists again -- a few seconds, once.
        with_ephemeral_policy(|| {
            let service = "com.hkdfguard.clitest.provision".to_string();
            run_provision(service.clone()).expect("first provision must create the KEK");
            run_provision(service).expect("second provision must be a no-op success");
        });
    }

    #[test]
    #[serial]
    #[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
    fn wrap_without_a_provisioned_kek_fails_with_the_provision_hint_and_touches_nothing() {
        with_ephemeral_policy(|| {
            let dir = private_tempdir();
            let key_path = dir.path().join("wrapped.key");
            fs::write(&key_path, b"the key file that was already here").unwrap();

            let dek_path = dir.path().join("dek.b64");
            fs::write(&dek_path, STANDARD.encode([0x5au8; DEK_LEN])).unwrap();
            fs::set_permissions(&dek_path, fs::Permissions::from_mode(0o600)).unwrap();

            // --force is given, and the KEK is missing: the old file must
            // survive, because the wrap fails before it is ever touched.
            let err = run_wrap(
                key_path.to_str().unwrap().to_string(),
                "com.hkdfguard.clitest.neverprovisioned".to_string(),
                DekSource::File(dek_path.to_str().unwrap().to_string()),
                true,
                None,
                None,
            )
            .unwrap_err();
            assert!(err.contains("provision --service-name"), "must point at the fix: {err}");
            assert_eq!(fs::read(&key_path).unwrap(), b"the key file that was already here");
        });
    }

    #[test]
    #[serial]
    #[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
    fn provision_then_wrap_round_trip_in_process() {
        with_ephemeral_policy(|| {
            let service = "com.hkdfguard.clitest.roundtrip".to_string();
            run_provision(service.clone()).unwrap();

            let dir = private_tempdir();
            let key_path = dir.path().join("wrapped.key");
            let dek_path = dir.path().join("dek.b64");
            fs::write(&dek_path, STANDARD.encode([0x5au8; DEK_LEN])).unwrap();
            fs::set_permissions(&dek_path, fs::Permissions::from_mode(0o600)).unwrap();

            run_wrap(
                key_path.to_str().unwrap().to_string(),
                service.clone(),
                DekSource::File(dek_path.to_str().unwrap().to_string()),
                false,
                None,
                None,
            )
            .unwrap();
            assert!(key_path.exists());
            assert_eq!(fs::metadata(&key_path).unwrap().permissions().mode() & 0o777, KEY_FILE_MODE);

            // --fingerprint: the KEK the payload was sealed to must be the
            // one given, or nothing is written -- not even with --force.
            let recorded = read_kek_fingerprint(&CString::new(service.as_str()).unwrap()).unwrap();
            assert_eq!(admin::payload_fingerprint(&fs::read(&key_path).unwrap()), Some(recorded), "the file carries it");
            let wrap_pinned = |path: &Path, force: bool, fingerprint: [u8; FINGERPRINT_LEN]| {
                run_wrap(
                    path.to_str().unwrap().to_string(),
                    service.clone(),
                    DekSource::File(dek_path.to_str().unwrap().to_string()),
                    force,
                    None,
                    Some(fingerprint),
                )
            };
            let pinned = dir.path().join("pinned.key");
            wrap_pinned(&pinned, false, recorded).unwrap();
            assert_eq!(admin::payload_fingerprint(&fs::read(&pinned).unwrap()), Some(recorded));

            let mut wrong = recorded;
            wrong[0] ^= 1;
            let refused = dir.path().join("refused.key");
            let err = wrap_pinned(&refused, false, wrong).unwrap_err();
            assert!(err.contains("fingerprint mismatch") && err.contains("nothing was written"), "{err}");
            assert!(!refused.exists(), "nothing written on a mismatch");
            let before = fs::read(&pinned).unwrap();
            let err = wrap_pinned(&pinned, true, wrong).unwrap_err();
            assert!(err.contains("fingerprint mismatch"), "{err}");
            assert_eq!(fs::read(&pinned).unwrap(), before, "--force must not cost the existing file on a mismatch");

            // --group with a group this process may give (its own), unless
            // that group is itself one --group refuses (running as root).
            // SAFETY: no arguments, cannot fail.
            let gid = unsafe { libc::getegid() };
            if resolve_key_file_group(&gid.to_string()).is_ok() {
                let grouped = dir.path().join("grouped.key");
                run_wrap(
                    grouped.to_str().unwrap().to_string(),
                    "com.hkdfguard.clitest.roundtrip".to_string(),
                    DekSource::File(dek_path.to_str().unwrap().to_string()),
                    false,
                    Some(gid.to_string()),
                    None,
                )
                .unwrap();
                let meta = fs::metadata(&grouped).unwrap();
                assert_eq!(meta.permissions().mode() & 0o777, KEY_FILE_GROUP_MODE, "owner rw, group r");
                assert_eq!(meta.gid(), gid, "given to the --group group");
            } else {
                eprintln!("skipping the --group round trip: this process's own group is one --group refuses");
            }
        });
    }

    // ---- DEK decoding ----

    fn valid_b64() -> String {
        STANDARD.encode([0x5au8; DEK_LEN])
    }

    #[test]
    fn decode_dek_accepts_base64_with_an_optional_trailing_newline() {
        let b64 = valid_b64();
        let mut out = [0u8; MAX_DECODED_LEN];
        assert_eq!(decode_dek(b64.as_bytes(), &mut out).unwrap(), [0x5au8; DEK_LEN]);
        assert_eq!(decode_dek(format!("{b64}\n").as_bytes(), &mut out).unwrap(), [0x5au8; DEK_LEN]);
        assert_eq!(decode_dek(format!("{b64}\r\n").as_bytes(), &mut out).unwrap(), [0x5au8; DEK_LEN]);
    }

    #[test]
    fn decode_dek_rejects_bad_input() {
        let mut out = [0u8; MAX_DECODED_LEN];
        let mut decode_dek = |text: &[u8]| decode_dek(text, &mut out).map(<[u8]>::to_vec);
        assert!(decode_dek(b"").is_err(), "empty");
        assert!(decode_dek(b"\n").is_err(), "newline only");
        assert!(decode_dek(b"not base64!!").is_err(), "not base64");
        // Only one trailing newline is tolerated; a second is not base64.
        assert!(decode_dek(format!("{}\n\n", valid_b64()).as_bytes()).is_err());
        // Right encoding, wrong length.
        assert!(decode_dek(STANDARD.encode([0u8; 16]).as_bytes()).is_err(), "16 bytes");
        assert!(decode_dek(STANDARD.encode([0u8; 33]).as_bytes()).is_err(), "33 bytes");
        // Raw 32 bytes is not accepted as a silent alternative encoding.
        assert!(decode_dek(&[0x5au8; DEK_LEN]).is_err(), "raw bytes must not decode");
        // The Windows tool's rules, case for case (tests/test_cli.ps1 12b2).
        let b64 = valid_b64();
        assert!(decode_dek(format!(" {b64}").as_bytes()).is_err(), "a leading space");
        assert!(decode_dek(format!("{}\n{}", &b64[..20], &b64[20..]).as_bytes()).is_err(), "a line break inside");
        assert!(decode_dek(format!("{} {}", &b64[..20], &b64[20..]).as_bytes()).is_err(), "a space inside");
        assert!(decode_dek(b64.trim_end_matches('=').as_bytes()).is_err(), "missing padding");
        let zeros = STANDARD.encode([0u8; DEK_LEN]);
        assert!(decode_dek(format!("{}B=", &zeros[..42]).as_bytes()).is_err(), "non-zero bits before the padding");
        let mut mixed = vec![0xFBu8, 0xEF, 0xBE, 0xFF, 0xFF, 0xFF];
        mixed.extend(1..=26u8);
        let standard = STANDARD.encode(&mixed);
        assert!(standard.contains('+') && standard.contains('/'));
        assert_eq!(decode_dek(standard.as_bytes()).unwrap(), &mixed[..], "the '+' and '/' characters");
        assert!(decode_dek(standard.replace('+', "-").replace('/', "_").as_bytes()).is_err(), "the URL-safe alphabet");
    }

    #[test]
    fn decode_dek_reports_every_malformed_input_with_one_fixed_message() {
        // No character, offset or bit pattern of the input reaches the
        // message -- a mistyped DEK never puts part of itself into a log.
        let b64 = valid_b64();
        let zeros = STANDARD.encode([0u8; DEK_LEN]);
        let mut mixed = vec![0xFBu8, 0xEF, 0xBE, 0xFF, 0xFF, 0xFF];
        mixed.extend(1..=26u8);
        let url_safe = STANDARD.encode(&mixed).replace('+', "-").replace('/', "_");
        let cases = [
            format!(" {b64}"),
            format!("{} {}", &b64[..20], &b64[20..]),
            b64.trim_end_matches('=').to_string(),
            format!("{}B=", &zeros[..42]),
            format!("{b64}\n\n"),
            url_safe,
            "not base64!!".to_string(),
        ];
        let mut out = [0u8; MAX_DECODED_LEN];
        for case in cases {
            let err = decode_dek(case.as_bytes(), &mut out).unwrap_err();
            assert_eq!(err, INVALID_BASE64_DEK_MESSAGE, "for {case:?}");
        }
    }

    #[test]
    fn decode_dek_skips_a_utf8_bom_and_refuses_utf16() {
        let b64 = valid_b64();
        let mut out = [0u8; MAX_DECODED_LEN];
        let with_bom = [b"\xEF\xBB\xBF".as_slice(), b64.as_bytes(), b"\r\n"].concat();
        assert_eq!(decode_dek(&with_bom, &mut out).unwrap(), [0x5au8; DEK_LEN]);
        for bom in [b"\xFF\xFE".as_slice(), b"\xFE\xFF".as_slice()] {
            let utf16 = [bom, b64.as_bytes()].concat();
            let err = decode_dek(&utf16, &mut out).unwrap_err();
            assert!(err.contains("UTF-16"), "{err}");
        }
    }

    #[test]
    fn read_bounded_rejects_input_over_the_limit() {
        let too_long = vec![b'A'; MAX_DEK_INPUT_LEN + 1];
        let mut buf = [0u8; MAX_DEK_INPUT_LEN + 1];
        assert!(read_bounded(&mut too_long.as_slice(), "test", &mut buf).is_err());

        let at_limit = vec![b'A'; MAX_DEK_INPUT_LEN];
        assert_eq!(read_bounded(&mut at_limit.as_slice(), "test", &mut buf).unwrap(), MAX_DEK_INPUT_LEN);

        // UTF-16 base64 of a DEK is 90 bytes: over the limit, and named as
        // UTF-16 rather than as merely too long.
        let utf16: Vec<u8> = [0xFFu8, 0xFE].into_iter().chain(valid_b64().bytes().flat_map(|b| [b, 0])).collect();
        let err = read_bounded(&mut utf16.as_slice(), "stdin", &mut buf).unwrap_err();
        assert!(err.contains("UTF-16"), "{err}");
    }

    // ---- memory locking decision ----

    const INF: u64 = u64::MAX;

    #[test]
    fn cap_eff_is_parsed_from_proc_status() {
        let status = "Name:\tx\nCapInh:\t0000000000000000\nCapEff:\t000001ffffffffff\nCapBnd:\t0\n";
        assert_eq!(parse_cap_eff(status), Some(0x1ff_ffff_ffff));
        assert_eq!(parse_cap_eff("Name:\tx\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\tnothex\n"), None);
    }

    #[test]
    fn memory_is_locked_only_when_no_limit_can_be_hit() {
        let ipc_lock = Some(1u64 << CAP_IPC_LOCK);
        let other_caps = Some(!(1u64 << CAP_IPC_LOCK));

        assert!(memory_lock_is_unbounded(ipc_lock, 65536, 65536, INF), "CAP_IPC_LOCK bypasses any limit");
        assert!(memory_lock_is_unbounded(Some(0), INF, INF, INF), "an unlimited RLIMIT_MEMLOCK is safe");
        assert!(memory_lock_is_unbounded(None, INF, INF, INF), "unlimited is safe even if caps are unreadable");

        // A finite limit without the capability: MCL_FUTURE could abort a
        // later allocation, so skip.
        assert!(!memory_lock_is_unbounded(other_caps, 8 << 20, 8 << 20, INF));
        assert!(!memory_lock_is_unbounded(Some(0), 1 << 30, INF, INF), "a finite soft limit still binds");
        assert!(!memory_lock_is_unbounded(None, 65536, 65536, INF));
    }

    // ---- --dek-file hardening ----

    fn write_mode(dir: &Path, name: &str, contents: &[u8], mode: u32) -> std::path::PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn dek_file_accepts_an_owner_only_regular_file() {
        let dir = private_tempdir();
        let path = write_mode(dir.path(), "dek", valid_b64().as_bytes(), 0o600);
        let mut scratch = DekScratch::new();
        let len = read_dek_file(path.to_str().unwrap(), &mut scratch.text).unwrap();
        let text = scratch.text[..len].to_vec();
        assert_eq!(decode_dek(&text, &mut scratch.decoded).unwrap(), [0x5au8; DEK_LEN]);
    }

    #[test]
    fn dek_file_rejects_group_or_world_accessible_permissions() {
        let dir = private_tempdir();
        for mode in [0o640, 0o604, 0o644, 0o660] {
            let path = write_mode(dir.path(), &format!("dek{mode:o}"), valid_b64().as_bytes(), mode);
            assert!(
                read_dek_file(path.to_str().unwrap(), &mut [0u8; MAX_DEK_INPUT_LEN + 1]).is_err(),
                "mode {mode:o} must be rejected"
            );
        }
    }

    #[test]
    fn dek_file_rejects_a_symlink() {
        let dir = private_tempdir();
        let target = write_mode(dir.path(), "real-dek", valid_b64().as_bytes(), 0o600);
        let link = dir.path().join("link-dek");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = read_dek_file(link.to_str().unwrap(), &mut [0u8; MAX_DEK_INPUT_LEN + 1]).unwrap_err();
        assert!(err.contains("symlink"), "got: {err}");
    }

    #[test]
    fn dek_file_rejects_a_directory_and_a_missing_path() {
        let dir = private_tempdir();
        assert!(read_dek_file(dir.path().to_str().unwrap(), &mut [0u8; MAX_DEK_INPUT_LEN + 1]).is_err());
        assert!(read_dek_file("/nonexistent-hkdfguard-dek-for-tests", &mut [0u8; MAX_DEK_INPUT_LEN + 1]).is_err());
    }

    #[test]
    fn dek_file_rejects_an_oversized_file() {
        let dir = private_tempdir();
        let path = write_mode(dir.path(), "big", &[b'A'; MAX_DEK_INPUT_LEN + 1], 0o600);
        assert!(read_dek_file(path.to_str().unwrap(), &mut [0u8; MAX_DEK_INPUT_LEN + 1]).is_err());
    }

    #[test]
    fn load_dek_reads_from_a_file_end_to_end() {
        let dir = private_tempdir();
        let path = write_mode(dir.path(), "dek", format!("{}\n", valid_b64()).as_bytes(), 0o400);
        let mut scratch = DekScratch::new();
        let dek = load_dek(&DekSource::File(path.to_str().unwrap().to_string()), &mut scratch).unwrap();
        assert_eq!(dek, [0x5au8; DEK_LEN]);
        assert!(scratch.text.iter().all(|&b| b == 0), "the base64 text must be wiped once decoded");
    }

    #[test]
    fn the_dek_scratch_buffer_is_locked_into_memory() {
        // The default RLIMIT_MEMLOCK (64 KiB on older systems, 8 MiB on
        // current ones) is far more than this one or two pages; only a
        // limit set below that excuses it.
        let mut memlock = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: getrlimit writes into a valid rlimit.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut memlock) }, 0);
        if memlock.rlim_cur < 64 * 1024 {
            eprintln!("skipping: RLIMIT_MEMLOCK is {} bytes", memlock.rlim_cur);
            return;
        }
        let scratch = DekScratch::new();
        assert!(scratch.locked, "mlock of the DEK scratch buffer failed under a {}-byte limit", memlock.rlim_cur);
        let vm_lck_kb = fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("VmLck:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
            .unwrap();
        assert!(vm_lck_kb > 0, "the kernel reports no locked memory while the scratch buffer is held");
    }
}

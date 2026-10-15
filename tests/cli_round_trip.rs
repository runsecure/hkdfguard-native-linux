//! Integration test for the `hkdfguard` CLI tool
//! (`src/bin/hkdfguard.rs`): runs it as a real, separate
//! process -- `provision` and then `wrap` -- then loads this crate as a
//! library (in *this* process) and confirms `hkdfguard_unwrap_dek`
//! recovers exactly the DEK that was fed to it. The DEK goes in on stdin
//! (or via `--dek-file`), never on the command line -- argv is readable by
//! any process of the same user via `/proc/<pid>/cmdline`. Deliberately
//! spans two processes -- the CLI's wrap and this test's unwrap -- rather
//! than calling the library twice in one process, so it also exercises a
//! genuinely persistent (not per-process, in-memory) KEK.
//!
//! There is no software-backed (locally-generated, filesystem-encrypted-
//! at-rest) provider on this platform, so the persistent provider used
//! here is external-secret: each test pre-provisions its own service's
//! secret file into an isolated temp directory, and writes a policy pinning
//! the chain to external-secret at that directory, before invoking the CLI,
//! mimicking how a real deployment platform (Vault Agent, a Kubernetes
//! Secret, ...) would have already dropped the file before the app starts
//! -- external-secret never creates one itself. For that provider,
//! `provision` therefore always reports "already provisioned": the mounted
//! file *is* the provisioning. The create path is covered in-process by
//! the binary's own unit tests against the ephemeral provider.
//!
//! Both the CLI and this process must read the test's own policy, which a
//! library only does when built with `--cfg hkdfguard_test_paths` (never
//! anything that ships). Without it, the tests that need one are ignored.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::SecretKey;
use serial_test::serial;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::raw::c_int;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
// Only this user can write to it, whatever the umask: the library refuses
// to trust a policy or secret mount in a group-writable directory, and
// `tempfile::tempdir()` creates `0777 & !umask`.
fn tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new().permissions(fs::Permissions::from_mode(0o700)).tempdir()
}
use hkdfguard::{hkdfguard_open_file, hkdfguard_unwrap_dek, status};
use p256::elliptic_curve::Generate as _; // `SecretKey::generate()`, from the OS CSPRNG

// Runs `f` with `doc` as the policy -- read by this process's library and,
// through the inherited environment, by every CLI process it spawns --
// then restores whatever policy (if any) the harness had set.
fn with_policy<F: FnOnce()>(doc: &str, f: F) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("policy.toml");
    fs::write(&path, doc).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(); // not the umask: a group-writable policy is refused
    let saved = std::env::var_os("HKDFGUARD_POLICY_FILE");
    std::env::set_var("HKDFGUARD_POLICY_FILE", &path);
    f();
    match saved {
        Some(v) => std::env::set_var("HKDFGUARD_POLICY_FILE", v),
        None => std::env::remove_var("HKDFGUARD_POLICY_FILE"),
    }
}

// A policy pinning the chain to external-secret, at `mount`.
fn external_secret_policy(mount: &Path) -> String {
    format!(
        "[selection]\nmode = \"require\"\nprovider = \"external-secret\"\n[external_secret]\ndir = \"{}\"\n",
        mount.display()
    )
}

// Points the external-secret provider at a fresh temp directory, isolated
// from any real host KEK storage, and pre-provisions a secret file for
// `service` inside it -- external-secret never creates one itself, so
// `wrap` only finds a KEK because this is already here. The policy pins
// the chain to it: with `tpm2` compiled in and a TPM reachable, the TPM
// would otherwise serve the service and this would test the wrong thing.
fn with_provisioned_external_secret<F: FnOnce()>(service: &str, f: F) {
    let dir = tempdir().unwrap();
    let secret_key = SecretKey::generate();
    let secret_path = dir.path().join(service);
    fs::write(&secret_path, secret_key.to_bytes()).unwrap();
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap(); // owner-only, as the provider requires of a KEK file
    with_policy(&external_secret_policy(dir.path()), f);
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hkdfguard"))
}

// `hkdfguard provision --service-name <service>`
fn run_provision(service: &str) -> Output {
    cli()
        .arg("provision")
        .args(["--service-name", service])
        .output()
        .expect("failed to run hkdfguard provision")
}

// `hkdfguard wrap --key-file-path <path> --service-name
// <service> --dek-stdin [extra]`, with the base64 DEK written to the
// subprocess's stdin -- how a deployment pipeline is expected to supply it.
fn run_wrap_stdin(key_path: &Path, service: &str, dek: &[u8; 32], extra_args: &[&str]) -> Output {
    let dek_b64 = STANDARD.encode(dek);
    let mut child = cli()
        .arg("wrap")
        .args(["--key-file-path", key_path.to_str().unwrap()])
        .args(["--service-name", service])
        .arg("--dek-stdin")
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hkdfguard wrap");
    // A CLI that refuses before reading stdin (e.g. an existing key file
    // without --force) may already have exited, closing the pipe: that is
    // a BrokenPipe here, not a test failure. The caller judges the outcome
    // from the exit status and output; any other write error is a failure.
    match child.stdin.as_mut().expect("stdin was piped").write_all(dek_b64.as_bytes()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(e) => panic!("failed to write the DEK to the CLI's stdin: {e}"),
    }
    drop(child.stdin.take()); // close stdin so the child sees EOF
    child.wait_with_output().expect("failed to run hkdfguard wrap")
}

fn unwrap_via_library(service: &str, wrapped: &[u8]) -> (c_int, [u8; 32]) {
    let service = CString::new(service).unwrap();
    let mut recovered = [0u8; 32];
    let mut recovered_len: c_int = recovered.len() as c_int;
    let rc = hkdfguard_unwrap_dek(
        service.as_ptr(),
        wrapped.as_ptr(),
        wrapped.len() as c_int,
        recovered.as_mut_ptr(),
        &mut recovered_len,
    );
    (rc, recovered)
}

fn stderr_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn cli_provision_then_wrap_unwraps_to_original_input() {
    with_provisioned_external_secret("com.example.orders", || {
        let original_dek: [u8; 32] = core::array::from_fn(|i| i as u8);
        let out_dir = tempdir().unwrap();
        let key_path = out_dir.path().join("wrapped.key");

        // provision: for external-secret the mounted file is the
        // provisioning, so this reports "already" and exits 0.
        let provisioned = run_provision("com.example.orders");
        assert!(provisioned.status.success(), "provision failed: {}", stderr_of(&provisioned));
        assert!(
            String::from_utf8_lossy(&provisioned.stdout).contains("already provisioned"),
            "external-secret must report the mounted file as already provisioned"
        );

        let output = run_wrap_stdin(&key_path, "com.example.orders", &original_dek, &[]);
        assert!(
            output.status.success(),
            "wrap failed (status {:?}): stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            stderr_of(&output)
        );

        let wrapped = fs::read(&key_path).expect("wrapped key file should exist");
        let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "wrapped key file must be written owner-only (0600)");

        let (rc, recovered) = unwrap_via_library("com.example.orders", &wrapped);
        assert_eq!(rc, status::OK, "hkdfguard_unwrap_dek failed with status {rc}");
        assert_eq!(recovered, original_dek, "unwrapped DEK must match the DEK fed in on stdin");
    });
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn cli_force_overwrite_secure_deletes_then_rewraps() {
    with_provisioned_external_secret("com.example.rotation", || {
        let out_dir = tempdir().unwrap();
        let key_path = out_dir.path().join("wrapped.key");

        let first_dek: [u8; 32] = core::array::from_fn(|i| i as u8);
        let first = run_wrap_stdin(&key_path, "com.example.rotation", &first_dek, &[]);
        assert!(first.status.success(), "initial write should succeed: {}", stderr_of(&first));

        let second_dek: [u8; 32] = core::array::from_fn(|i| 255 - i as u8);
        let second = run_wrap_stdin(&key_path, "com.example.rotation", &second_dek, &["--force"]);
        assert!(second.status.success(), "forced overwrite should succeed: {}", stderr_of(&second));

        // The file on disk must now unwrap to the *second* DEK, not the first.
        // (Whether the overwrite actually delete-and-recreated the file
        // rather than truncating it in place is covered separately by the
        // secure_delete unit tests in src/bin/hkdfguard.rs --
        // inode number isn't a reliable signal for that here, since some
        // filesystems immediately reuse a just-freed inode for a new file.)
        let wrapped = fs::read(&key_path).unwrap();
        let (rc, recovered) = unwrap_via_library("com.example.rotation", &wrapped);
        assert_eq!(rc, status::OK);
        assert_eq!(recovered, second_dek, "file must contain the second wrap, not the first");
    });
}

#[test]
#[serial]
fn cli_rejects_pre_existing_file_without_force() {
    // This scenario never reaches the KEK provider at all -- `wrap`'s own
    // pre-check refuses an existing output file before reading the DEK or
    // touching the library -- so no external secret needs to be provisioned.
    let out_dir = tempdir().unwrap();
    let key_path = out_dir.path().join("wrapped.key");
    fs::write(&key_path, b"pre-existing content").unwrap();

    let output = run_wrap_stdin(&key_path, "com.example.billing", &[0x42u8; 32], &[]);

    assert!(!output.status.success(), "wrap should refuse to overwrite an existing file");
    assert_eq!(
        fs::read(&key_path).unwrap(),
        b"pre-existing content",
        "existing file must be left untouched without --force"
    );
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn cli_wrap_without_a_provisioned_kek_fails_and_preserves_the_existing_file() {
    // An external-secret mount that exists but holds nothing for this
    // service, and a policy that pins the chain to external-secret. The
    // pin matters: with `tpm2` compiled in and a TPM reachable (the Docker
    // harness runs this against swtpm), the TPM provider derives every
    // service's KEK on demand and would legitimately serve this one --
    // which is correct behavior, but not the scenario under test.
    // Relying on "no provider happens to be available" would make this
    // test track the host's hardware instead of the CLI's behavior.
    let empty_mount = tempdir().unwrap();
    with_policy(&external_secret_policy(empty_mount.path()), || {
    let out_dir = tempdir().unwrap();
    let key_path = out_dir.path().join("wrapped.key");
    fs::write(&key_path, b"the key file that was already here").unwrap();

    // `wrap` never provisions: it must fail, name the fix, and -- even
    // with --force -- leave the existing key file exactly as it was,
    // because the wrap fails before the old file is ever touched.
    let output = run_wrap_stdin(&key_path, "com.example.unprovisioned", &[0x42u8; 32], &["--force"]);
    assert!(!output.status.success(), "wrap must fail without a provisioned KEK");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("provision --service-name com.example.unprovisioned"),
        "error must point at the provision command: {stderr}"
    );
    assert_eq!(
        fs::read(&key_path).unwrap(),
        b"the key file that was already here",
        "a failed wrap must never destroy the existing key file, even with --force"
    );

    // And `provision` for that service fails too: external-secret cannot
    // create a KEK, and nothing else is allowed to.
    let provisioned = run_provision("com.example.unprovisioned");
    assert!(!provisioned.status.success(), "provision must fail when no provider can create a KEK");
    });
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn cli_accepts_the_dek_from_a_file_and_refuses_a_loose_one() {
    with_provisioned_external_secret("com.example.fileinput", || {
        let original_dek = [0x7Bu8; 32];
        let out_dir = tempdir().unwrap();
        let key_path = out_dir.path().join("wrapped.key");

        // A root-or-owner-only file, as a secret mount or a systemd
        // credential would provide. A trailing newline is tolerated, since
        // that is what `printf '%s\n'` and most editors produce.
        let dek_path = out_dir.path().join("dek.b64");
        fs::write(&dek_path, format!("{}\n", STANDARD.encode(original_dek))).unwrap();
        fs::set_permissions(&dek_path, fs::Permissions::from_mode(0o600)).unwrap();

        let output = cli()
            .arg("wrap")
            .args(["--key-file-path", key_path.to_str().unwrap()])
            .args(["--service-name", "com.example.fileinput"])
            .args(["--dek-file", dek_path.to_str().unwrap()])
            .output()
            .expect("failed to run hkdfguard");
        assert!(output.status.success(), "--dek-file should succeed: {}", stderr_of(&output));

        // Round-trips through the library, exactly as the stdin path does.
        let wrapped = fs::read(&key_path).expect("wrapped key file should exist");
        let (rc, recovered) = unwrap_via_library("com.example.fileinput", &wrapped);
        assert_eq!(rc, status::OK);
        assert_eq!(recovered, original_dek);

        // A group-readable DEK file is refused rather than used.
        let loose_path = out_dir.path().join("loose.b64");
        fs::write(&loose_path, STANDARD.encode(original_dek)).unwrap();
        fs::set_permissions(&loose_path, fs::Permissions::from_mode(0o644)).unwrap();
        let loose_key_path = out_dir.path().join("loose.key");
        let output = cli()
            .arg("wrap")
            .args(["--key-file-path", loose_key_path.to_str().unwrap()])
            .args(["--service-name", "com.example.fileinput"])
            .args(["--dek-file", loose_path.to_str().unwrap()])
            .output()
            .expect("failed to run hkdfguard");
        assert!(!output.status.success(), "a group-readable DEK file must be refused");
        assert!(!loose_key_path.exists(), "nothing should have been written");
    });
}

// Reads `path` through the library's own key-file reader, as an
// application would at startup.
fn open_via_library(path: &Path) -> (c_int, Vec<u8>) {
    let path = CString::new(path.to_str().unwrap()).unwrap();
    let mut out = vec![0u8; 276]; // HKDFGUARD_WRAPPED_MAX_LEN
    let mut out_len = out.len() as c_int;
    let rc = hkdfguard_open_file(path.as_ptr(), out.as_mut_ptr(), &mut out_len);
    out.truncate(out_len.max(0) as usize);
    (rc, out)
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn cli_key_file_opens_through_the_library_and_its_dek_input_is_refused() {
    with_provisioned_external_secret("com.example.openfile", || {
        let original_dek = [0x3Cu8; 32];
        let out_dir = tempdir().unwrap();
        let key_path = out_dir.path().join("wrapped.key");
        let output = run_wrap_stdin(&key_path, "com.example.openfile", &original_dek, &[]);
        assert!(output.status.success(), "wrap failed: {}", stderr_of(&output));

        // The file the CLI wrote, read by hkdfguard_open_file: byte for
        // byte what is on disk, and it unwraps to the original DEK.
        let (rc, wrapped) = open_via_library(&key_path);
        assert_eq!(rc, status::OK, "hkdfguard_open_file failed with status {rc}");
        assert_eq!(wrapped, fs::read(&key_path).unwrap());
        let (rc, recovered) = unwrap_via_library("com.example.openfile", &wrapped);
        assert_eq!(rc, status::OK);
        assert_eq!(recovered, original_dek);

        // The likeliest mix-up: pointing the application at the CLI's DEK
        // *input* file instead of its output. That is the plaintext key.
        let dek_path = out_dir.path().join("dek.b64");
        fs::write(&dek_path, format!("{}\n", STANDARD.encode(original_dek))).unwrap();
        fs::set_permissions(&dek_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(open_via_library(&dek_path).0, status::FILE_PLAINTEXT_KEY);

        // A truncated or extended copy of the key file.
        let full = fs::read(&key_path).unwrap();
        let copy = out_dir.path().join("copy.key");
        fs::write(&copy, &full[..full.len() - 1]).unwrap();
        // Owner-only, like the CLI's own key file: under a umask of 002 the
        // copy would be group-writable and refused as FILE_UNTRUSTED before
        // its length is judged. (The rewrite below keeps this mode.)
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(open_via_library(&copy).0, status::FILE_TOO_SHORT);
        fs::write(&copy, [&full[..], b"\n".as_slice()].concat()).unwrap();
        assert_eq!(open_via_library(&copy).0, status::FILE_TOO_LONG);

        // The CLI's 0600 key file, loosened so another group member could
        // replace it: refused, until the mode is restored.
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o660)).unwrap();
        assert_eq!(open_via_library(&key_path).0, status::FILE_UNTRUSTED);
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(open_via_library(&key_path).0, status::OK);
    });
}

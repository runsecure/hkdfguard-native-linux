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
use serial_test::serial;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::raw::c_int;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
// Only this user can write to it, whatever the umask, and not under the
// sticky /tmp: the library refuses a policy, a secret, or a key file in or
// under any directory others can write to, sticky or not -- so `wrap`
// refuses to write a key file there, and --dek-file to read one.
// `tempfile::tempdir()` creates `0777 & !umask` under /tmp. See
// src/test_tmp.rs.
#[path = "../src/test_tmp.rs"]
mod test_tmp;

fn tempdir() -> std::io::Result<tempfile::TempDir> {
    Ok(test_tmp::private_tempdir())
}
use hkdfguard::{hkdfguard_open_file, hkdfguard_unwrap_dek, status};

// Runs `f` with `doc` as the policy -- read by this process's library and,
// through the inherited environment, by every CLI process it spawns --
// then restores whatever policy (if any) the harness had set. A `doc`
// that doesn't set `security_model` gets the developer model.
fn with_policy<F: FnOnce()>(doc: &str, f: F) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("policy.toml");
    // These tests run as an ordinary user, provisioning and writing key
    // files of their own: the developer model, unless `doc` names one.
    let doc = if doc.contains("security_model") { doc.to_string() } else { format!("security_model = \"developer\"\n{doc}") };
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
    let mut secret_key = [0u8; 32]; // a KEK, as an operator provisions one: 32 random bytes
    getrandom::fill(&mut secret_key).unwrap();
    let secret_path = dir.path().join(service);
    fs::write(&secret_path, secret_key).unwrap();
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap(); // owner-only, as the provider requires of a KEK file
    with_policy(&external_secret_policy(dir.path()), f);
}

// HKDFGUARD_TEST_CLI: the CLI to drive instead of the one cargo built
// alongside this test, whose path is compiled in -- for a test executable
// copied to another machine (scripts/hardware-tests/make-bundle.sh).
fn cli() -> Command {
    match std::env::var_os("HKDFGUARD_TEST_CLI") {
        Some(path) => Command::new(path),
        None => Command::new(env!("CARGO_BIN_EXE_hkdfguard")),
    }
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
            String::from_utf8_lossy(&provisioned.stdout).contains("already provisioned")
                && String::from_utf8_lossy(&provisioned.stdout).contains("verified"),
            "external-secret must report the mounted file as already provisioned, and verified"
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
fn cli_refuses_a_key_path_through_a_symlinked_folder() {
    // Refused before the DEK is read or any provider reached, so no
    // external secret is needed.
    let dir = tempdir().unwrap();
    let base = fs::canonicalize(dir.path()).unwrap();
    let real = base.join("real");
    fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, base.join("link")).unwrap();

    let output = run_wrap_stdin(&base.join("link/wrapped.key"), "com.example.linked", &[0x42u8; 32], &[]);
    assert!(!output.status.success(), "a key path through a symlinked folder must be refused");
    assert!(stderr_of(&output).contains("symbolic link"), "says why: {}", stderr_of(&output));
    assert!(!real.join("wrapped.key").exists(), "nothing is created in the folder the link points at");
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn cli_wrap_writes_where_the_path_was_checked_not_where_a_link_before_dotdot_leads() {
    // keys/link -> elsewhere/deep: the kernel would resolve keys/link/.. to
    // `elsewhere`. The folder check resolves `..` as text, to `keys`, and the
    // CLI must then write exactly there.
    with_provisioned_external_secret("com.example.dotdot", || {
        let dir = tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let keys = base.join("keys");
        let elsewhere = base.join("elsewhere");
        // 0700 whatever the umask: a 002 umask would leave these group-writable, and refused.
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).recursive(true).create(elsewhere.join("deep")).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&keys).unwrap();
        std::os::unix::fs::symlink(elsewhere.join("deep"), keys.join("link")).unwrap();

        let output = run_wrap_stdin(&keys.join("link/../wrapped.key"), "com.example.dotdot", &[7u8; 32], &[]);
        assert!(output.status.success(), "{}", stderr_of(&output));
        assert!(keys.join("wrapped.key").exists(), "written in the checked folder");
        assert!(!elsewhere.join("wrapped.key").exists(), "nothing written where the link leads");
    });
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn cli_force_refuses_a_hard_linked_key_file() {
    with_provisioned_external_secret("com.example.hardlink", || {
        let dir = tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let key_path = base.join("wrapped.key");
        let first = run_wrap_stdin(&key_path, "com.example.hardlink", &[1u8; 32], &[]);
        assert!(first.status.success(), "initial wrap: {}", stderr_of(&first));
        let original = fs::read(&key_path).unwrap();

        // A second name for the key file, as someone able to link into the
        // folder could make; overwriting the key would destroy it too.
        let other = base.join("someone-elses.dat");
        fs::hard_link(&key_path, &other).unwrap();
        let forced = run_wrap_stdin(&key_path, "com.example.hardlink", &[2u8; 32], &["--force"]);
        assert!(!forced.status.success(), "--force onto a hard-linked key file must be refused");
        assert!(stderr_of(&forced).contains("hard links"), "says why: {}", stderr_of(&forced));
        assert_eq!(fs::read(&other).unwrap(), original, "the other name's contents are untouched");
        assert_eq!(fs::read(&key_path).unwrap(), original, "the key file is untouched");
    });
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn cli_group_makes_the_key_file_group_readable_and_it_still_opens() {
    use std::os::unix::fs::MetadataExt;
    with_provisioned_external_secret("com.example.grouped", || {
        let dir = tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();

        // Without --group: owner-only.
        let plain = base.join("plain.key");
        let out = run_wrap_stdin(&plain, "com.example.grouped", &[3u8; 32], &[]);
        assert!(out.status.success(), "{}", stderr_of(&out));
        assert_eq!(fs::metadata(&plain).unwrap().mode() & 0o777, 0o600);
        assert!(String::from_utf8_lossy(&out.stdout).contains("owner read/write,"), "{}", String::from_utf8_lossy(&out.stdout));

        // With --group (this process's own group, which it may give):
        // 0640, that group, and the library still opens and unwraps it.
        // SAFETY: no arguments, cannot fail.
        let gid = unsafe { libc::getegid() };
        if gid == 0 {
            eprintln!("skipping: running as root, whose group --group refuses");
            return;
        }
        let grouped = base.join("grouped.key");
        let out = run_wrap_stdin(&grouped, "com.example.grouped", &[4u8; 32], &["--group", &gid.to_string()]);
        assert!(out.status.success(), "{}", stderr_of(&out));
        let meta = fs::metadata(&grouped).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o640, "owner rw, group r");
        assert_eq!(meta.gid(), gid);
        assert!(String::from_utf8_lossy(&out.stdout).contains("read-only"), "{}", String::from_utf8_lossy(&out.stdout));
        let (rc, wrapped) = open_via_library(&grouped);
        assert_eq!(rc, status::OK, "a group-readable key file is trusted (it is ciphertext)");
        let (rc, recovered) = unwrap_via_library("com.example.grouped", &wrapped);
        assert_eq!((rc, recovered), (status::OK, [4u8; 32]));

        // An over-broad group is refused before anything is written.
        let broad = base.join("broad.key");
        let out = run_wrap_stdin(&broad, "com.example.grouped", &[5u8; 32], &["--group", "root"]);
        assert!(!out.status.success());
        assert!(stderr_of(&out).contains("over-broad"), "{}", stderr_of(&out));
        assert!(!broad.exists(), "nothing written");
    });
}

// `wrap -kf <path> --dek-file <dek>`, no stdin.
fn run_wrap_dek_file(key_path: &Path, service: &str, dek_file: &Path) -> Output {
    cli()
        .arg("wrap")
        .args(["--key-file-path", key_path.to_str().unwrap()])
        .args(["--service-name", service])
        .args(["--dek-file", dek_file.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run hkdfguard wrap")
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn cli_refuses_a_shared_key_folder_up_front() {
    // Under the production model (no policy file) an ordinary account is
    // refused before any of this is reached: these are the developer
    // model's checks.
    with_policy("[selection]\nmode = \"prefer\"\n", cli_refuses_a_shared_key_folder_up_front_under_the_developer_model);
}

fn cli_refuses_a_shared_key_folder_up_front_under_the_developer_model() {
    // A key file the library would refuse to open (FILE_UNTRUSTED) is not
    // written in the first place: a folder anyone else can write to --
    // sticky /tmp-style or plain group/other-writable, the folder itself
    // or one above it -- is refused before the DEK is read or a provider
    // reached. The --dek-file does not exist, so reaching it would fail
    // with a DEK error instead, and no KEK is provisioned for the service.
    let dir = tempdir().unwrap();
    let base = fs::canonicalize(dir.path()).unwrap();
    let missing_dek = base.join("no-such-dek.b64");
    let outer = base.join("outer");
    let inner = outer.join("inner");
    fs::create_dir_all(&inner).unwrap();
    let chmod = |p: &Path, mode: u32| fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    chmod(&outer, 0o755);
    chmod(&inner, 0o700);
    let key_path = inner.join("wrapped.key");

    let cases: [(&Path, u32, bool); 4] =
        [(&inner, 0o1777, true), (&inner, 0o770, false), (&outer, 0o1777, true), (&outer, 0o777, false)];
    for (folder, mode, sticky) in cases {
        chmod(folder, mode);
        let output = run_wrap_dek_file(&key_path, "com.example.sharedfolder", &missing_dek);
        let stderr = stderr_of(&output);
        assert_eq!(output.status.code(), Some(1), "{} mode {mode:o} must be refused: {stderr}", folder.display());
        assert!(
            stderr.contains(&format!("{}, is writable by group or others (mode {mode:o})", folder.display()))
                && stderr.contains("the library would refuse to read a key file"),
            "names the folder, its mode and why: {stderr}"
        );
        assert_eq!(stderr.contains("sticky"), sticky, "{stderr}");
        assert!(!stderr.contains("--dek-file") && !stderr.contains("provision"), "refused before the DEK or a provider: {stderr}");
        assert!(!key_path.exists(), "nothing is created");
        chmod(folder, if folder == outer.as_path() { 0o755 } else { 0o700 });
    }

    // The same folder, private again, gets past the check -- to the DEK.
    let output = run_wrap_dek_file(&key_path, "com.example.sharedfolder", &missing_dek);
    assert!(stderr_of(&output).contains("--dek-file"), "{}", stderr_of(&output));
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn cli_checks_the_key_folder_mode_not_its_owner() {
    // Under the production model (no policy file) an ordinary account is
    // refused before any of this is reached: these are the developer
    // model's checks.
    with_policy("[selection]\nmode = \"prefer\"\n", cli_checks_the_key_folder_mode_not_its_owner_under_the_developer_model);
}

fn cli_checks_the_key_folder_mode_not_its_owner_under_the_developer_model() {
    // wrap often runs as root into a folder the application's account
    // owns. Only the mode is checked: a folder owned by someone else that
    // nobody else can write to gets past the check (to the missing DEK
    // file here). As a non-root run, `/` is such a folder (root's, 0755);
    // as root, a 0700 and a 0755 folder owned by `nobody`.
    let dir = tempdir().unwrap();
    let base = fs::canonicalize(dir.path()).unwrap();
    let missing_dek = base.join("no-such-dek.b64");
    let mut folders = vec![];
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        for mode in [0o700, 0o755] {
            let theirs = base.join(format!("app-owned-{mode:o}"));
            fs::create_dir(&theirs).unwrap();
            fs::set_permissions(&theirs, fs::Permissions::from_mode(mode)).unwrap();
            std::os::unix::fs::chown(&theirs, Some(65534), Some(65534)).unwrap();
            folders.push(theirs);
        }
    } else {
        folders.push(Path::new("/").to_path_buf());
    }
    for folder in folders {
        let key_path = folder.join("hkdfguard-test-never-written.key");
        let output = run_wrap_dek_file(&key_path, "com.example.otherowner", &missing_dek);
        let stderr = stderr_of(&output);
        assert!(!output.status.success());
        assert!(stderr.contains("--dek-file") && !stderr.contains("writable by group"), "{}: {stderr}", folder.display());
        assert!(!key_path.exists());
    }
}

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn cli_refuses_to_read_the_dek_from_a_terminal() {
    // Under the production model (no policy file) an ordinary account is
    // refused before any of this is reached: these are the developer
    // model's checks.
    with_policy("[selection]\nmode = \"prefer\"\n", cli_refuses_to_read_the_dek_from_a_terminal_under_the_developer_model);
}

fn cli_refuses_to_read_the_dek_from_a_terminal_under_the_developer_model() {
    // A real pseudo-terminal as stdin: what an operator typing or pasting
    // the DEK would give the CLI. Refused before anything is read, so no
    // provider is needed and nothing is written.
    use std::os::fd::FromRawFd;
    let (mut controller, mut device) = (-1, -1);
    // SAFETY: openpty writes two descriptors into the given ints; the rest are optional (NULL).
    let rc = unsafe {
        libc::openpty(&mut controller, &mut device, std::ptr::null_mut(), std::ptr::null(), std::ptr::null())
    };
    if rc != 0 {
        eprintln!("skipping: no pseudo-terminal available ({})", std::io::Error::last_os_error());
        return;
    }
    // SAFETY: both descriptors were just returned by openpty and are owned here.
    let (controller, device) = unsafe { (std::fs::File::from_raw_fd(controller), std::fs::File::from_raw_fd(device)) };

    let dir = tempdir().unwrap();
    let key_path = fs::canonicalize(dir.path()).unwrap().join("wrapped.key");
    let output = cli()
        .arg("wrap")
        .args(["--key-file-path", key_path.to_str().unwrap()])
        .args(["--service-name", "com.example.terminal"])
        .arg("--dek-stdin")
        .stdin(Stdio::from(device))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run hkdfguard wrap");
    drop(controller);
    assert!(!output.status.success(), "reading the DEK from a terminal must be refused");
    assert!(stderr_of(&output).contains("interactive terminal"), "says why: {}", stderr_of(&output));
    assert!(!key_path.exists(), "nothing written");
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
fn cli_refuses_ephemeral_keys_with_an_explanation() {
    // An ephemeral key would live only inside the CLI process: provision
    // would "succeed" with a key gone on exit, and wrap would write a
    // payload nothing could unwrap. Both must refuse and say why, whether
    // ephemeral is required or reached as a fallback.
    let empty_mount = tempdir().unwrap();
    let policies = [
        "[selection]\nmode = \"require\"\nprovider = \"ephemeral\"\n".to_string(),
        format!(
            "preferred_order = [\"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n[external_secret]\ndir = \"{}\"\n",
            empty_mount.path().display()
        ),
    ];
    for policy in &policies {
        with_policy(policy, || {
            let provisioned = run_provision("com.example.ephemeral");
            assert!(!provisioned.status.success(), "provision must refuse an ephemeral KEK under {policy:?}");
            let stderr = stderr_of(&provisioned);
            assert!(stderr.contains("exist only inside the process"), "provision must explain why: {stderr}");

            let out_dir = tempdir().unwrap();
            let key_path = out_dir.path().join("wrapped.key");
            fs::write(&key_path, b"the key file that was already here").unwrap();
            let wrapped = run_wrap_stdin(&key_path, "com.example.ephemeral", &[0x42u8; 32], &["--force"]);
            assert!(!wrapped.status.success(), "wrap must refuse an ephemeral KEK under {policy:?}");
            let stderr = stderr_of(&wrapped);
            assert!(stderr.contains("exist only inside the process"), "wrap must explain why: {stderr}");
            assert_eq!(fs::read(&key_path).unwrap(), b"the key file that was already here");
        });
    }
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

#[test]
#[serial]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn production_trusts_only_key_files_a_deployer_wrote() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: root holds every role, so there is nothing to refuse");
        return;
    }
    let service = "com.example.production";
    with_provisioned_external_secret(service, || {
        // Under the developer model this account wraps a key file of its
        // own, and the library opens it...
        let out_dir = tempdir().unwrap();
        let key_path = out_dir.path().join("wrapped.key");
        let dek = [0x6Du8; 32];
        let wrapped = run_wrap_stdin(&key_path, service, &dek, &[]);
        assert!(wrapped.status.success(), "{}", stderr_of(&wrapped));
        assert_eq!(open_via_library(&key_path).0, status::OK);

        // ...but under production the same account is just the
        // application: the file it wrote is refused, and the CLI won't
        // write another.
        let mut policy = fs::read_to_string(std::env::var_os("HKDFGUARD_POLICY_FILE").unwrap()).unwrap();
        policy = policy.replace("security_model = \"developer\"", "security_model = \"production\"");
        with_policy(&policy, || {
            let (mut model, mut may_write) = (-1, -1);
            assert_eq!(hkdfguard::hkdfguard_security_model(&mut model, &mut may_write), status::OK);
            assert_eq!(model, 0, "production");
            if may_write == 1 {
                eprintln!("skipping: this account is a deployer on this host");
                return;
            }
            assert_eq!(open_via_library(&key_path).0, status::FILE_UNTRUSTED, "a key file the application could have planted");

            let second = out_dir.path().join("second.key");
            let refused = run_wrap_stdin(&second, service, &dek, &[]);
            assert!(!refused.status.success());
            let stderr = stderr_of(&refused);
            assert!(stderr.contains("may not persist key files") && stderr.contains("Nothing was written"), "{stderr}");
            assert!(!second.exists());

            // Provisioning a KEK that doesn't exist yet is root's; one that
            // does is only verified, which anyone may.
            let provisioned = run_provision("com.example.production.unprovisioned");
            assert!(!provisioned.status.success(), "creating a KEK needs root under production");
            let stderr = stderr_of(&provisioned);
            assert!(stderr.contains("only root creates or retires a KEK"), "{stderr}");
            assert!(run_provision(service).status.success(), "verifying an existing KEK needs no role");

            // Unwrapping is the same in both models: the payload itself
            // still opens, for whoever the provider lets use the KEK.
            let bytes = fs::read(&key_path).unwrap();
            let mut out = [0u8; 32];
            let mut out_len = out.len() as c_int;
            let c_service = std::ffi::CString::new(service).unwrap();
            assert_eq!(
                hkdfguard_unwrap_dek(c_service.as_ptr(), bytes.as_ptr(), bytes.len() as c_int, out.as_mut_ptr(), &mut out_len),
                status::OK
            );
            assert_eq!(out, dek);
        });
    });
}

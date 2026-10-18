//! Creating an ephemeral KEK hardens the process (core dumps off,
//! non-dumpable) and keeps the key in locked memory excluded from core
//! dumps. That is process-wide state, so it gets its own test binary -- its
//! own process -- rather than running inside the shared unit-test process.
//!
//! The library must read this test's own policy, which only a
//! `--cfg hkdfguard_test_paths` build does (the test scripts set it).

#[test]
#[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
fn creating_an_ephemeral_key_hardens_the_process_and_locks_the_key_away() {
    use hkdfguard::{hkdfguard_create_kek, hkdfguard_generate_and_wrap_dek, hkdfguard_unwrap_dek, status};
    use std::ffi::CString;
    use std::os::raw::c_int;
    use std::os::unix::fs::PermissionsExt;

    // SAFETY: PR_GET_DUMPABLE takes no further arguments.
    let dumpable = || unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    if dumpable() != 1 {
        eprintln!("skipping: the process starts non-dumpable ({}), so nothing would be proven", dumpable());
        return;
    }

    let dir = tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
    let policy = dir.path().join("policy.toml");
    std::fs::write(&policy, "[selection]\nmode = \"require\"\nprovider = \"ephemeral\"\n").unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::env::set_var("HKDFGUARD_POLICY_FILE", &policy);

    let service = CString::new("com.company.ephemeral.hardening").unwrap();
    assert_eq!(dumpable(), 1, "nothing may change before a key exists");
    assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);

    assert_eq!(dumpable(), 0, "creating an ephemeral key must make the process non-dumpable");
    let mut limit = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
    // SAFETY: getrlimit writes into a valid rlimit.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
    assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0), "core dumps must be disabled, hard limit included");

    // The key page: excluded from core dumps (`dd`), and locked (`lo`)
    // when RLIMIT_MEMLOCK leaves room for a page.
    let mut memlock = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: as above.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut memlock) }, 0);
    let expect_locked = memlock.rlim_cur >= 64 * 1024;
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let flags: Vec<&str> = smaps.lines().filter_map(|l| l.strip_prefix("VmFlags:")).collect();
    assert!(
        flags.iter().any(|f| {
            let f: Vec<&str> = f.split_whitespace().collect();
            f.contains(&"dd") && (!expect_locked || f.contains(&"lo"))
        }),
        "no mapping is excluded from core dumps{}: {flags:?}",
        if expect_locked { " and locked" } else { "" }
    );

    // And the key still works.
    let mut wrapped = [0u8; 512];
    let mut wrapped_len = wrapped.len() as c_int;
    assert_eq!(hkdfguard_generate_and_wrap_dek(service.as_ptr(), wrapped.as_mut_ptr(), &mut wrapped_len), status::OK);
    let mut dek = [0u8; 32];
    let mut dek_len = dek.len() as c_int;
    assert_eq!(
        hkdfguard_unwrap_dek(service.as_ptr(), wrapped.as_ptr(), wrapped_len, dek.as_mut_ptr(), &mut dek_len),
        status::OK
    );
    assert_eq!(dek_len, 32);
}

// Gives the Linux shared library an ELF SONAME, so programs linked against
// it record `libhkdfguard.so.1` as their dependency rather than whatever
// file name they happened to link (Cargo's libhkdfguard.so).
// The packages install the library under exactly that name, and dpkg/rpm
// derive the library's dependency metadata from it.
//
// The `.1` is the C ABI's major version (include/hkdfguard.h): bump it, and
// the packages' library names (debian/control, packaging/rpm/hkdfguard.spec),
// only for an incompatible ABI change -- a removed or changed function,
// status code, or payload format. Additions don't bump it.
//
// A program linked against target/release directly therefore needs a
// `libhkdfguard.so.1` next to the .so at run time; scripts/build-release.sh
// and the test scripts create that symlink.

//
// It also refuses to build a release with `--cfg hkdfguard_test_paths`.
// That cfg makes the library read its policy from HKDFGUARD_POLICY_FILE
// and trust configuration the calling user owns -- what the test harnesses
// need, and exactly what a shipped build must never do: anyone who can set
// an environment variable would choose the policy. The harnesses build it
// in the debug profile; every way a release is made (the packages,
// scripts/build-release.sh, docker/build-dist.sh, the overlay) builds the
// release profile, so a RUSTFLAGS that leaked into one of them fails here
// instead of shipping. That judges the build asked for; the file that
// ships is checked again, whatever built it, by
// packaging/check-shipped-binary.sh. Fuzzing is the one exception: `cargo fuzz` builds
// the release profile with `--cfg fuzzing`, and its harnesses are never
// shipped.

const SONAME: &str = "libhkdfguard.so.1";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,{SONAME}");
    }

    // Cargo hands a build script every cfg the crate is compiled with,
    // RUSTFLAGS' included, as CARGO_CFG_<NAME>.
    let test_paths = std::env::var_os("CARGO_CFG_HKDFGUARD_TEST_PATHS").is_some();
    let fuzzing = std::env::var_os("CARGO_CFG_FUZZING").is_some();
    let release = std::env::var("PROFILE").as_deref() == Ok("release");
    if test_paths && release && !fuzzing {
        eprintln!(
            "error: refusing to build hkdfguard in the release profile with `--cfg hkdfguard_test_paths`.\n\
             That cfg makes the library read its policy from HKDFGUARD_POLICY_FILE and trust configuration the \
             calling user owns: test harnesses only, never a build that ships. Remove it from RUSTFLAGS (and \
             CARGO_ENCODED_RUSTFLAGS, .cargo/config.toml), or build the test harness in the debug profile."
        );
        std::process::exit(1);
    }
}

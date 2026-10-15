#!/usr/bin/env bash
# Runs the SoftHSM2 (PKCS#11) and Ephemeral provider tests inside one of
# the per-distribution images built from docker/distros/Dockerfile.*, so
# both providers are proven on each distribution's own libc, toolchain
# and SoftHSM2 build. docker/run-distro-tests.sh builds and runs them; see
# docker/README.md.
#
# The TPM2 provider is deliberately not covered here: it needs tpm2-tss
# 4.x and has its own swtpm matrix in docker/entrypoint-test.sh.
#
# As there, the container starts as root only to do what a deployment's
# root would -- install root-owned configuration under /etc/hkdfguard --
# and every build, test, and library/CLI run happens as the unprivileged
# `ci` user.
#
# HKDFGUARD_PREBUILT=1 (images with no toolchain, i.e. UBI Micro): nothing
# is compiled here. The image's builder stage already ran
# build-artifacts.sh, and the same tests run from those executables
# instead of through cargo (doc tests excepted; this crate has none).
set -euo pipefail

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "entrypoint-distro-test.sh starts as root and drops to ci itself"
# Runs a command as `ci`, keeping this script's environment (setpriv
# drops every capability along with root).
as_ci() { setpriv --reuid=ci --regid=ci --init-groups env HOME=/home/ci USER=ci LOGNAME=ci "$@"; }
# Writes stdin into a file `ci` owns, as ci (see docker/entrypoint-test.sh
# on fs.protected_regular).
ci_write() { as_ci sh -c 'cat > "$1"' sh "$1"; }

# BASE_RUSTFLAGS is set only where the target needs it (Alpine/musl:
# -crt-static). A RUSTFLAGS variable replaces configured target flags, so
# every invocation carries it explicitly.
BASE_RUSTFLAGS=${BASE_RUSTFLAGS:-}
ci_cargo() { as_ci env RUSTFLAGS="$BASE_RUSTFLAGS" cargo "$@"; }
# Test-path builds: the only builds that read a policy other than
# /etc/hkdfguard/policy.toml (see docker/entrypoint-test.sh).
test_cargo() {
    as_ci env RUSTFLAGS="$BASE_RUSTFLAGS --cfg hkdfguard_test_paths" CARGO_TARGET_DIR=target/test-paths cargo "$@"
}
PREBUILT=${HKDFGUARD_PREBUILT:-0}
# Prebuilt: runs each test executable build-artifacts.sh listed, from the
# package root and with CARGO_MANIFEST_DIR set, as cargo test would.
run_test_list() {
    local list=target/test-lists/$1 exe; shift
    [ -s "$list" ] || fail "$list is missing or empty"
    while read -r exe; do
        echo "     Running $exe"
        as_ci env CARGO_MANIFEST_DIR=/work "$exe" "$@" || fail "$exe $*"
    done < "$list"
}

. /etc/os-release
DISTRO="$PRETTY_NAME"
section "platform: $DISTRO"
echo "arch:     $(uname -m)"
echo "libc:     $(ldd --version 2>&1 | head -n1)"
if [ "$PREBUILT" = 1 ]; then
    echo "rustc:    none in this image; tests prebuilt in its builder stage"
else
    echo "rustc:    $(as_ci rustc --version)"
fi
echo "softhsm:  $(softhsm2-util --version)"
[ -z "$BASE_RUSTFLAGS" ] || echo "rustflags: $BASE_RUSTFLAGS"

# An image may name the module (UBI Micro has no find). Otherwise search;
# not every distribution has /usr/lib64, which makes find fail (pipefail).
if [ -z "${SOFTHSM_MODULE:-}" ]; then
    SOFTHSM_MODULE=$( (find /usr/lib /usr/lib64 -name libsofthsm2.so 2>/dev/null || true) | head -n1)
fi
[ -f "$SOFTHSM_MODULE" ] || fail "libsofthsm2.so not found"
echo "module:   $SOFTHSM_MODULE"

if [ "$PREBUILT" = 1 ]; then
    section "tests (default features: external-secret, ephemeral; prebuilt)"
    run_test_list default
else
    section "cargo build --features pkcs11"
    ci_cargo build --locked --features pkcs11

    section "cargo test (default features: external-secret, ephemeral)"
    ci_cargo test --locked
fi

section "initializing a SoftHSM2 token"
# Same label and PINs as docker/entrypoint-test.sh: the pkcs11 tests
# select this token by label (SOFTHSM_TEST_TOKEN_LABEL).
as_ci softhsm2-util --init-token --free --label hkdfguard-test --pin 1234 --so-pin 5678

HARNESS=$(as_ci mktemp -d)
( umask 077; printf '1234\n' > "$HARNESS/pkcs11.pin" )
cat > "$HARNESS/policy.toml" <<TOML
[selection]
mode = "prefer"

[pkcs11]
module = "$SOFTHSM_MODULE"
pin_file = "$HARNESS/pkcs11.pin"
token_label = "hkdfguard-test"
TOML
chmod 0644 "$HARNESS/policy.toml"
chown -R ci:ci "$HARNESS"
export HKDFGUARD_POLICY_FILE="$HARNESS/policy.toml"

if [ "$PREBUILT" = 1 ]; then
    section "tests --features pkcs11 (test build: unit, CLI and integration tests, ephemeral policy tests; prebuilt)"
    run_test_list test-paths

    section "tests --features pkcs11 -- --ignored (against SoftHSM2; prebuilt)"
    run_test_list test-paths --ignored --test-threads=1
else
    section "cargo test --features pkcs11 (test build: unit, CLI and integration tests, ephemeral policy tests)"
    test_cargo test --locked --features pkcs11

    section "cargo test --features pkcs11 -- --ignored (against SoftHSM2)"
    test_cargo test --locked --features pkcs11 -- --ignored --test-threads=1
fi

unset HKDFGUARD_POLICY_FILE
rm -rf "$HARNESS"

# Everything below uses release builds -- the shape that ships -- which
# take their configuration only from the root-owned
# /etc/hkdfguard/policy.toml, installed the way a deployment would.
if [ "$PREBUILT" = 1 ]; then
    section "release library and CLI link only what the base image ships"
    # The final image adds openssl-libs and libstdc++ for SoftHSM2 alone:
    # HKDFGuard itself must run on stock UBI Micro, i.e. need nothing
    # beyond glibc and libgcc_s.
    for bin in target/release/libhkdfguard.so target/release/hkdfguard; do
        LDD=$(ldd "$bin")
        echo "$bin:"; echo "$LDD"
        while read -r lib _; do
            case "$lib" in
                linux-vdso.so.*|/lib*/ld-linux*.so.*|libc.so.6|libm.so.6|libdl.so.2|libpthread.so.0|librt.so.1|libgcc_s.so.1) ;;
                *) fail "$bin links $lib, which stock UBI Micro does not ship" ;;
            esac
        done <<<"$LDD"
        [[ "$LDD" != *"not found"* ]] || fail "$bin has unresolved libraries"
    done
else
    section "release build and C consumers"
    ci_cargo build --locked --release --features pkcs11
    # The .so's SONAME is libhkdfguard.so.1 (build.rs).
    as_ci ln -sf libhkdfguard.so target/release/libhkdfguard.so.1
    as_ci mkdir -p target/c
    for prog in examples/wrap_unwrap.c examples/cli_unwrap_check.c docker/distros/ephemeral_cross_process.c; do
        as_ci cc -I include "$prog" -L target/release -lhkdfguard -o "target/c/$(basename "$prog" .c)"
    done
fi
run_c() { as_ci env LD_LIBRARY_PATH=target/release "$@"; }
mkdir -p /etc/hkdfguard

section "ephemeral is never chosen unless policy names it"
# No policy file at all: TPM2 is not built, PKCS#11 has no module and no
# secret is mounted, so nothing is available -- and the library must say
# so rather than fall back to a key that dies with the process.
rm -f /etc/hkdfguard/policy.toml
if OUT=$(run_c target/c/wrap_unwrap 2>&1); then
    fail "with no policy, a KEK was created (ephemeral fallback?): $OUT"
fi
grep -q 'create_kek failed' <<<"$OUT" || fail "unexpected failure without a policy: $OUT"
echo "no policy: no provider available, no silent ephemeral fallback."

section "ephemeral via /etc/hkdfguard/policy.toml (release .so)"
cat > /etc/hkdfguard/policy.toml <<'TOML'
[selection]
mode = "require"
provider = "ephemeral"
TOML
chmod 0644 /etc/hkdfguard/policy.toml
run_c target/c/wrap_unwrap
EPH_PAYLOAD=$(as_ci mktemp)
run_c target/c/ephemeral_cross_process wrap "$EPH_PAYLOAD"
run_c target/c/ephemeral_cross_process unwrap "$EPH_PAYLOAD"
rm -f "$EPH_PAYLOAD"

section "PKCS#11 (SoftHSM2) via /etc/hkdfguard/policy.toml (release .so and CLI)"
# A fresh token, so the release build provisions its own key rather than
# finding one the test suite left behind.
as_ci softhsm2-util --delete-token --token hkdfguard-test >/dev/null
as_ci softhsm2-util --init-token --free --label hkdfguard-test --pin 1234 --so-pin 5678 >/dev/null
# The PIN is root-owned and readable only by the service's group, as a
# deployment installs it for a non-root service.
install -o root -g ci -m 0440 /dev/null /etc/hkdfguard/pkcs11.pin
printf '1234\n' > /etc/hkdfguard/pkcs11.pin
cat > /etc/hkdfguard/policy.toml <<TOML
[selection]
mode = "require"
provider = "pkcs11"

[pkcs11]
module = "$SOFTHSM_MODULE"
pin_file = "/etc/hkdfguard/pkcs11.pin"
token_label = "hkdfguard-test"
TOML
chmod 0644 /etc/hkdfguard/policy.toml

run_c target/c/wrap_unwrap

# Across processes: the CLI provisions and wraps (linking the crate
# statically), then a separate C program unwraps through the .so. Unlike
# the ephemeral case, the KEK lives in the token, so this must succeed.
SERVICE=com.hkdfguard.distrotest.pkcs11
DEK_FILE=$(as_ci mktemp)
head -c 32 /dev/urandom | ci_write "$DEK_FILE"
WRAPPED_FILE=$(as_ci mktemp)
as_ci target/release/hkdfguard provision --service-name "$SERVICE"
base64 -w0 < "$DEK_FILE" | as_ci target/release/hkdfguard wrap \
    --key-file-path "$WRAPPED_FILE" --service-name "$SERVICE" --dek-stdin --force
run_c target/c/cli_unwrap_check "$WRAPPED_FILE" "$SERVICE" "$DEK_FILE"
echo "pkcs11: CLI-wrapped key unwrapped by a separate process through the .so."

# A group- or world-readable PIN file must be refused, not used.
chmod 0444 /etc/hkdfguard/pkcs11.pin
if OUT=$(run_c target/c/cli_unwrap_check "$WRAPPED_FILE" "$SERVICE" "$DEK_FILE" 2>&1); then
    fail "a world-readable PIN file was accepted: $OUT"
fi
echo "pkcs11: world-readable PIN file refused."

rm -f "$DEK_FILE" "$WRAPPED_FILE"
rm -rf /etc/hkdfguard

section "ALL CHECKS PASSED on $DISTRO ($(uname -m))"

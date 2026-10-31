#!/usr/bin/env bash
# Builds the hardware-test bundle: the CLI, the shared library, every test
# executable, the C consumers, tpm-probe.sh and run-hardware-tests.sh, in
# one tarball to copy to a machine being qualified -- a laptop with a
# different TPM, a Hyper-V guest with a vTPM. The target then needs only
# the tpm2-tss runtime libraries (tpm2-tools pulls them in), not Rust.
#
#   scripts/hardware-tests/make-bundle.sh            build on this host
#   scripts/hardware-tests/make-bundle.sh --docker   build in docker/Dockerfile's image
#                                                    (Ubuntu 24.04, glibc 2.39)
#   ... --out DIR                                    where the bundle goes
#                                                    (default build-hardware-tests/)
#
# The binaries link glibc and tpm2-tss dynamically, so a bundle runs on the
# distribution it was built on and newer ones. --docker's runs on Ubuntu
# 24.04+, Debian 13, RHEL 10 and their kin; for an older target (Debian 12,
# RHEL 9, SLES 15) build natively on that distribution, or the oldest one.
# run-hardware-tests.sh says which it is if a binary cannot load.
#
# Built as scripts/native-tpm-test.sh builds: with --cfg hkdfguard_test_paths,
# into target/test-paths, so a library reads the test's policy file and
# never mixes with an ordinary build. Nothing in the bundle is fit to
# deploy. The tpm2 and pkcs11 suites are built separately, as that script
# runs them.
#
# Needs: Linux, cargo, a C compiler, and libtss2-esys development files
# (Debian/Ubuntu: libtss2-dev; Fedora/RHEL: tpm2-tss-devel). With --docker,
# only Docker; run it from Linux or WSL, not a Windows checkout.
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO=$PWD

OUT=build-hardware-tests
DOCKER=0
while [ $# -gt 0 ]; do
    case "$1" in
        --docker) DOCKER=1; shift ;;
        --out) OUT=${2:?--out needs a directory}; shift 2 ;;
        *) echo "usage: $0 [--docker] [--out DIR]" >&2; exit 2 ;;
    esac
done
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
NAME=hkdfguard-hardware-tests

if [ "$DOCKER" -eq 1 ]; then
    export MSYS_NO_PATHCONV=1
    TAG="hkdfguard-bundle-build-$$"
    CONTAINER="hkdfguard-bundle-build-$$"
    trap 'docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; docker rmi -f "$TAG" >/dev/null 2>&1 || true' EXIT
    docker build -t "$TAG" -f docker/Dockerfile .
    # The image's own copy of the source is the build context, already
    # owned by its ci user. Strip CRs in case the context came from a
    # Windows checkout, then build as ci. The tarball comes out by `docker
    # cp`, not a bind mount, so this works with Docker Desktop or a remote
    # daemon too, and the copy is the caller's own.
    docker run --name "$CONTAINER" --entrypoint bash "$TAG" -c '
        set -e
        find /work -name "*.sh" -exec sed -i "s/\r$//" {} +
        setpriv --reuid=ci --regid=ci --init-groups env HOME=/home/ci USER=ci LOGNAME=ci \
            scripts/hardware-tests/make-bundle.sh --out /tmp/bundle-out
'
    tarball="$NAME-$VERSION-$(docker run --rm --entrypoint uname "$TAG" -m).tar.gz"
    docker cp "$CONTAINER:/tmp/bundle-out/$tarball" "$OUT/$tarball"
    echo "-> $OUT/$tarball"
    exit 0
fi

[ "$(uname -s)" = Linux ] || { echo "build the bundle on Linux (or pass --docker)" >&2; exit 1; }

ARCH=$(uname -m)
STAGE="$OUT/$NAME"
TARBALL="$OUT/$NAME-$VERSION-$ARCH.tar.gz"

export RUSTFLAGS="--cfg hkdfguard_test_paths"
export CARGO_TARGET_DIR="$REPO/target/test-paths"

rm -rf "$STAGE"
mkdir -p "$STAGE"/{bin,lib,c,tests/tpm2,tests/pkcs11}

# Copies the test executables cargo reports, named for what they test:
# lib (the library's unit and conformance tests), bin-<name> (a binary's
# own tests), or the integration test's name. Cargo's JSON messages: the
# compiler-artifact lines whose *profile* has "test":true.
collect_tests() { # collect_tests <dest dir>
    grep -E '"profile":\{[^}]*"test":true' \
        | sed -n 's/.*"target":{"kind":\["\([^"]*\)"[^}]*"name":"\([^"]*\)".*"executable":"\([^"]*\)".*/\1 \2 \3/p' \
        | while read -r kind name exe; do
            # The library's kind is its crate types (cdylib, staticlib, rlib).
            case "$kind" in
                bin) label="bin-$name" ;;
                test) label=$name ;;
                *) label=lib ;;
            esac
            cp "$exe" "$1/$label"
            echo "   $1/$label"
        done
}

echo "== pkcs11 test build"
cargo test --locked --features pkcs11 --no-run --message-format=json | collect_tests "$STAGE/tests/pkcs11"
# Only the library's tests talk to a PKCS#11 token; the rest repeat the tpm2 build's.
find "$STAGE/tests/pkcs11" -type f ! -name lib -delete

echo "== tpm2 test build"
cargo test --locked --features tpm2 --no-run --message-format=json | collect_tests "$STAGE/tests/tpm2"
[ -x "$STAGE/tests/tpm2/lib" ] && [ -x "$STAGE/tests/pkcs11/lib" ] || { echo "no library test executable found" >&2; exit 1; }

echo "== tpm2 library and CLI"
cargo build --locked --features tpm2
cp "$CARGO_TARGET_DIR/debug/hkdfguard" "$STAGE/bin/"
cp "$CARGO_TARGET_DIR/debug/libhkdfguard.so" "$STAGE/lib/"
ln -sf libhkdfguard.so "$STAGE/lib/libhkdfguard.so.1" # the SONAME (build.rs)

echo "== C consumers"
for prog in examples/wrap_unwrap.c examples/cli_unwrap_check.c; do
    cc -I include "$prog" -L "$STAGE/lib" -lhkdfguard -Wl,-rpath,'$ORIGIN/../lib' -o "$STAGE/c/$(basename "$prog" .c)"
done

# Scripts: CRs stripped, in case this is a checkout made on Windows.
for f in run-hardware-tests.sh tpm-probe.sh README.md; do
    sed 's/\r$//' "scripts/hardware-tests/$f" > "$STAGE/$f"
done
chmod 755 "$STAGE/run-hardware-tests.sh" "$STAGE/tpm-probe.sh"

# The newest glibc symbol version any binary needs: the oldest glibc the
# bundle runs on.
glibc_needed=
if command -v objdump >/dev/null 2>&1; then
    glibc_needed=$(find "$STAGE/bin" "$STAGE/lib" "$STAGE/c" "$STAGE/tests" -type f -exec objdump -T {} + 2>/dev/null \
        | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -n1)
fi
commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
git diff --quiet HEAD 2>/dev/null || commit="$commit (with uncommitted changes)"
{
    echo "hkdfguard $VERSION, commit $commit"
    echo "built $(date -u +%Y-%m-%dT%H:%M:%SZ) on $( . /etc/os-release && echo "$PRETTY_NAME") ($ARCH)"
    echo "$(rustc --version), tpm2-tss $(pkg-config --modversion tss2-esys 2>/dev/null || echo unknown)"
    echo "needs ${glibc_needed:-glibc of the build host} or newer, and the tpm2-tss runtime libraries"
} > "$STAGE/MANIFEST"
sed 's/^/   /' "$STAGE/MANIFEST"

tar -C "$OUT" -czf "$TARBALL" "$NAME"
echo "-> $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo "Copy it to the target, then: tar xzf $(basename "$TARBALL") && $NAME/run-hardware-tests.sh"
echo "Or over SSH: scripts/hardware-tests/run-remote.sh user@host ..."

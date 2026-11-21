#!/usr/bin/env bash
# Builds and lightly tests HKDFGuard inside the container built from
# docker/Dockerfile (the same image docker/run-tests.sh uses), then copies
# the release library/CLI/header into /dist -- bind-mount that to a host
# directory to collect them (see docker/build-dist.sh, which does this).
#
# Not a substitute for docker/run-tests.sh's full hardware-backed matrix
# (swtpm/SoftHSM2): this just runs the standard test suite plus an
# all-features build/link check as a sanity gate before packaging, so it
# stays fast enough to run on every distribution build.
set -euo pipefail

DIST_DIR=/dist

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

# Builds and tests run as the image's unprivileged `ci` user (see
# docker/Dockerfile); only collecting into the bind-mounted /dist runs as
# root.
as_ci() { setpriv --reuid=ci --regid=ci --init-groups env HOME=/home/ci USER=ci LOGNAME=ci "$@"; }

section "cargo test (default features)"
as_ci cargo test --locked

section "cargo test --all-features (also confirms real link against libtss2-esys + cryptoki)"
as_ci cargo test --locked --all-features

# --locked throughout: what ships is built from exactly the dependency
# versions in Cargo.lock, the ones cargo-deny and the package builds see.
section "cargo build --release --locked --all-features"
as_ci cargo build --release --locked --all-features

section "collecting release artifacts into $DIST_DIR"
mkdir -p "$DIST_DIR"
cp target/release/libhkdfguard.so "$DIST_DIR"/
cp target/release/libhkdfguard.a "$DIST_DIR"/
cp target/release/hkdfguard "$DIST_DIR"/
cp include/hkdfguard.h "$DIST_DIR"/

section "nothing collected is a test build"
packaging/check-shipped-binary.sh "$DIST_DIR"/libhkdfguard.so "$DIST_DIR"/libhkdfguard.a "$DIST_DIR"/hkdfguard

section "dist contents"
ls -la "$DIST_DIR"

section "BUILD COMPLETE"

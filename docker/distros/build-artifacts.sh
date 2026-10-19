#!/bin/sh
# Builds, ahead of time, everything entrypoint-distro-test.sh would
# otherwise compile at run time: for images with no toolchain (UBI Micro),
# whose builder stage runs this in /work and copies the result in.
#
#   target/release/          the release library and CLI (as shipped)
#   target/c/                the C consumers, linked against that library
#   target/test-lists/       the test executables of the plain build
#                            (default) and of the test-path build
#                            (test-paths), one path per line
#
# The entrypoint runs these with HKDFGUARD_PREBUILT=1. Test executables
# keep the absolute paths cargo built them at (the CLI tests find the
# binary through one), so /work must stay /work in the final image.
set -eu
cd /work

BASE_RUSTFLAGS=${BASE_RUSTFLAGS:-}

# The executables of test targets, from cargo's JSON messages: the
# compiler-artifact lines whose *profile* has "test":true. (The target
# object also has a "test" key, true for the CLI binary too.)
test_executables() {
    grep -E '"profile":\{[^}]*"test":true' | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p'
}

RUSTFLAGS="$BASE_RUSTFLAGS" cargo build --locked --release --features pkcs11
ln -sf libhkdfguard.so target/release/libhkdfguard.so.1

mkdir -p target/c target/test-lists
for prog in examples/wrap_unwrap.c examples/cli_unwrap_check.c docker/distros/ephemeral_cross_process.c; do
    cc -I include "$prog" -L target/release -lhkdfguard -o "target/c/$(basename "$prog" .c)"
done

RUSTFLAGS="$BASE_RUSTFLAGS" cargo test --locked --no-run --message-format=json \
    | test_executables > target/test-lists/default
RUSTFLAGS="$BASE_RUSTFLAGS --cfg hkdfguard_test_paths" CARGO_TARGET_DIR=target/test-paths \
    cargo test --locked --features pkcs11 --no-run --message-format=json \
    | test_executables > target/test-lists/test-paths

for list in default test-paths; do
    [ -s "target/test-lists/$list" ] || { echo "no test executables found for $list" >&2; exit 1; }
    echo "$list: $(wc -l < "target/test-lists/$list") test executables"
done

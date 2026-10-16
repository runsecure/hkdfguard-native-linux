#!/usr/bin/env bash
# Builds the release library and CLI, then gives the library its run-time
# name: libhkdfguard.so.1, its SONAME (build.rs).
#
# Cargo can't produce that name: crate names (and therefore [lib] name in
# Cargo.toml) can't contain dots, so `cargo build` always produces
# libhkdfguard.{so,a}. A program linked against target/release records
# the SONAME and looks for libhkdfguard.so.1 at run time, so this script
# adds it as a symlink to Cargo's output. The packages install the library
# under that name directly.
#
# Usage: scripts/build-release.sh
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release

# The SONAME is a Linux (ELF) name; elsewhere Cargo's output is all there is.
[ "$(uname -s)" = Linux ] || exit 0

src=target/release/libhkdfguard.so
if [ ! -f "$src" ]; then
    echo "error: expected build output missing: $src" >&2
    exit 1
fi
ln -sf libhkdfguard.so target/release/libhkdfguard.so.1
echo "-> target/release/libhkdfguard.so.1 (symlink to libhkdfguard.so)"

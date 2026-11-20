#!/usr/bin/env bash
# Refuses a library or CLI built with `--cfg hkdfguard_test_paths`.
#
# That build reads its policy from HKDFGUARD_POLICY_FILE and trusts
# configuration the calling user owns: test harnesses only (see build.rs,
# which refuses it in the release profile). build.rs judges the build it is
# asked for; this judges the file about to ship, whatever profile, flags or
# cache produced it. A test build carries the cfg's name in its own startup
# warning (src/policy.rs); no other build contains the string.
#
# Run on everything that leaves the build: docker/entrypoint-build.sh (the
# standalone binaries), packaging/smoke-test.sh (the installed packages,
# which the overlay images are made from) and packaging/release-assets.sh.
#
# Usage: packaging/check-shipped-binary.sh <file>...
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: $0 <file>..." >&2; exit 2; }
marker=hkdfguard_test_paths
for file in "$@"; do
    [ -f "$file" ] || { echo "error: $file: no such file" >&2; exit 1; }
    # -a: a binary is searched as text. -F: the marker is not a pattern.
    if grep -a -q -F "$marker" "$file"; then
        echo "error: $file was built with --cfg $marker: a test build, which honors HKDFGUARD_POLICY_FILE." >&2
        echo "       It must never ship. Rebuild without that cfg in RUSTFLAGS." >&2
        exit 1
    fi
    echo "ok: $file is not a test build"
done

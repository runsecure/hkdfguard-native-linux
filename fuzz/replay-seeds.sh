#!/usr/bin/env bash
# Runs every seed fuzz/make_seeds.py writes through its target, once, under
# AddressSanitizer: the buffer, NULL-pointer, truncation, length-field and
# string-boundary attacks, as a regression suite that takes a minute or two
# rather than a fuzzing campaign. Fails on the first seed that crashes a
# target or breaks one of its assertions.
#
# Needs what fuzzing needs (README.md): a nightly toolchain
# (HKDFGUARD_FUZZ_TOOLCHAIN, default "nightly"), cargo-fuzz,
# and HKDFGUARD_FUZZ_DIR naming a private directory.
#
# Usage: fuzz/replay-seeds.sh [target...]     (default: every target with seeds)
set -euo pipefail
cd "$(dirname "$0")/.."

: "${HKDFGUARD_FUZZ_DIR:?set HKDFGUARD_FUZZ_DIR to a private directory (see fuzz/README.md)}"
export HKDFGUARD_FUZZ_DIR
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--cfg hkdfguard_test_paths"

python3 fuzz/make_seeds.py
if [ "$#" -eq 0 ]; then
    set -- $(ls fuzz/seeds)
fi
for target in "$@"; do
    [ -d "fuzz/seeds/$target" ] || { echo "replay-seeds: no seeds for target \"$target\"" >&2; exit 2; }
    count=$(find "fuzz/seeds/$target" -type f | wc -l)
    printf '== %s: %s seeds ==\n' "$target" "$count"
    log=$(mktemp)
    # -runs=0: the seeds and nothing else. The seed directory is the only
    # corpus named, so nothing is read from or written to fuzz/corpus.
    if ! cargo "+${HKDFGUARD_FUZZ_TOOLCHAIN:-nightly}" fuzz run "$target" "fuzz/seeds/$target" -- -runs=0 -timeout=60 >"$log" 2>&1; then
        cat "$log" >&2; rm -f "$log"
        echo "replay-seeds: FAIL: $target (the offending input is under fuzz/artifacts/$target/)" >&2
        exit 1
    fi
    # And the run must have been of these seeds, all of them.
    ran=$(sed -n 's/^INFO: seed corpus: files: \([0-9]*\) .*/\1/p' "$log")
    rm -f "$log"
    [ "$ran" = "$count" ] || { echo "replay-seeds: FAIL: $target ran $ran of $count seeds" >&2; exit 1; }
done
echo "replay-seeds: every seed passed."

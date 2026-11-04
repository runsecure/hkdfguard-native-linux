#!/usr/bin/env bash
# Line and region coverage of the test suite, with LLVM's source-based
# instrumentation (`-Cinstrument-coverage`) and the `llvm-tools-preview`
# rustup component -- no third-party cargo plugin.
#
#   scripts/coverage.sh [BASE]
#
# Runs every test under `--cfg hkdfguard_test_paths` (the configuration the
# integration tests need; the `hkdfguard` binary they spawn is instrumented
# too and writes its own profile), then prints:
#   - the per-file summary for src/,
#   - every line added since BASE (default: the merge base with `main`, plus
#     uncommitted changes) that is executable and was never run.
# Exits 1 if any added executable line is uncovered, other than those
# scripts/coverage-exempt.txt lists (each with the test that runs it).
#
# Needs a private temp directory, as the tests do (see src/test_tmp.rs):
# HKDFGUARD_TEST_TMPDIR, default $HOME/.cache/hkdfguard-coverage-tmp.
set -euo pipefail

cd "$(dirname "$0")/.."
root=$PWD
base=${1:-$(git merge-base HEAD origin/main 2>/dev/null || git merge-base HEAD main)}

sysroot=$(rustc --print sysroot)
host=$(rustc -vV | sed -n 's/^host: //p')
bin="$sysroot/lib/rustlib/$host/bin"
[ -x "$bin/llvm-cov" ] || { echo "llvm-cov missing: rustup component add llvm-tools-preview" >&2; exit 2; }

out=$root/target/coverage
export CARGO_TARGET_DIR=$out/build
export RUSTFLAGS="--cfg hkdfguard_test_paths -Cinstrument-coverage"
export LLVM_PROFILE_FILE=$out/profraw/%p-%m.profraw
export HKDFGUARD_TEST_TMPDIR=${HKDFGUARD_TEST_TMPDIR:-$HOME/.cache/hkdfguard-coverage-tmp}
umask 077
mkdir -p "$HKDFGUARD_TEST_TMPDIR"
chmod 700 "$HKDFGUARD_TEST_TMPDIR"
rm -rf "$out/profraw"

cargo test --all-targets --no-fail-fast 2>&1 | grep -E '^(test result|error|failures:|    [a-z_:]+$)' || true

# A test that runs the CLI under RLIMIT_FSIZE leaves a truncated profile
# (the runtime writes it at exit, past the limit): skipped, with a warning.
"$bin/llvm-profdata" merge -sparse --failure-mode=warn "$out"/profraw/*.profraw -o "$out/merged.profdata"

# Every test executable, plus the CLI binary the integration tests spawn.
objects=()
while IFS= read -r f; do objects+=(-object "$f"); done < <(
    cargo test --all-targets --no-run --message-format=json 2>/dev/null |
        python3 -c 'import json,sys
for l in sys.stdin:
    m = json.loads(l)
    if m.get("reason") == "compiler-artifact" and m.get("executable"):
        print(m["executable"])'
    ls "$CARGO_TARGET_DIR"/debug/hkdfguard
)

ignore='(/\.cargo/registry/|/rustc/|/tests/|/fuzz/)'
"$bin/llvm-cov" report --instr-profile="$out/merged.profdata" "${objects[@]}" \
    --ignore-filename-regex="$ignore" --show-region-summary=false
"$bin/llvm-cov" export --format=lcov --instr-profile="$out/merged.profdata" "${objects[@]}" \
    --ignore-filename-regex="$ignore" > "$out/lcov.info"

echo
echo "Added lines (since ${base:0:12}) that are executable and never ran:"
git diff -U0 "$base" -- src | python3 "$root/scripts/coverage_diff.py" "$out/lcov.info" "$root" "$root/scripts/coverage-exempt.txt"

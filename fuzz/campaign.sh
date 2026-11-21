#!/usr/bin/env bash
# One fuzzing campaign: runs <target> for <seconds>, starting from its
# corpus (fuzz/corpus/<target>, kept between runs where the caller keeps
# it) and its seeds (fuzz/make_seeds.py), and reports the result as
# Markdown. Exits 1 on a finding, 2 if the target doesn't build or the
# arguments are wrong.
#
# By hand, the report goes to stdout and says what was found. In CI
# (.github/workflows/fuzz.yml) it goes to the run's summary page, which on
# a public repository anyone can read -- so there it says only that there
# was a finding, and the finding itself goes into
# fuzz/campaign-<target>.sarif (fuzz/finding_sarif.py), which the workflow
# uploads to code scanning: the Security tab, shown to maintainers only.
#
# The fuzzer's own output goes to fuzz/campaign-<target>.log; a finding's
# input is under fuzz/artifacts/<target>/.
#
# Needs what fuzzing needs (README.md): a nightly toolchain
# (HKDFGUARD_FUZZ_TOOLCHAIN, default "nightly"), cargo-fuzz, and
# HKDFGUARD_FUZZ_DIR naming a private directory.
#
# Usage: fuzz/campaign.sh <target> <seconds>
set -euo pipefail
cd "$(dirname "$0")/.."

[[ $# -eq 2 && $2 =~ ^[0-9]+$ ]] || { echo "usage: $0 <target> <seconds>" >&2; exit 2; }
target=$1
seconds=$2
[[ -f "fuzz/fuzz_targets/$target.rs" && $target != common ]] || { echo "campaign: no fuzz target \"$target\"" >&2; exit 2; }
: "${HKDFGUARD_FUZZ_DIR:?set HKDFGUARD_FUZZ_DIR to a private directory (see fuzz/README.md)}"
export HKDFGUARD_FUZZ_DIR
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--cfg hkdfguard_test_paths"
toolchain=${HKDFGUARD_FUZZ_TOOLCHAIN:-nightly}
summary=${GITHUB_STEP_SUMMARY:-/dev/stdout}
# Set where what this prints is public (GitHub Actions): a finding's details
# then go to the SARIF file only.
public=${GITHUB_ACTIONS:-}
log=fuzz/campaign-$target.log

if ! cargo "+$toolchain" fuzz build "$target" >"$log" 2>&1; then
    tail -n 60 "$log" >&2
    printf '### :x: `%s`: did not build\n\nThe harness no longer compiles against the library; see the job log.\n' "$target" >> "$summary"
    exit 2
fi

python3 fuzz/make_seeds.py >/dev/null
corpus=fuzz/corpus/$target
mkdir -p "$corpus"
inputs=("$corpus") # the first directory is the one libFuzzer adds to
[[ -d "fuzz/seeds/$target" ]] && inputs+=("fuzz/seeds/$target")
options=("-max_total_time=$seconds" -timeout=20 -print_final_stats=1)
case $target in
    policy)   options+=(-dict=fuzz/policy.dict) ;;
    cli_args) options+=(-dict=fuzz/cli.dict) ;;
esac
# Findings from an earlier run are not this run's.
rm -rf "fuzz/artifacts/$target" "fuzz/campaign-$target.sarif"

status=0
cargo "+$toolchain" fuzz run "$target" "${inputs[@]}" -- "${options[@]}" >"$log" 2>&1 || status=$?

executions=$(sed -n 's/^stat::number_of_executed_units: //p' "$log" | tail -n 1)
entries=$(find "$corpus" -type f | wc -l)
findings=()
if [[ -d "fuzz/artifacts/$target" ]]; then
    mapfile -t findings < <(find "fuzz/artifacts/$target" -type f -printf '%f\n' | sort)
fi

{
    if [[ $status -eq 0 ]]; then
        printf '### :white_check_mark: `%s`: no findings\n\n' "$target"
    else
        printf '### :x: `%s`: FINDING\n\n' "$target"
    fi
    printf '| executions | time budget | corpus entries | findings |\n|---|---|---|---|\n'
    printf '| %s | %ss | %s | %s |\n' "${executions:-unknown}" "$seconds" "$entries" "${#findings[@]}"
    if [[ $status -ne 0 && -n $public ]]; then
        printf '\nThe details -- what failed, the input, the log -- are in the Security tab, under code scanning (branch `%s`, tool `hkdfguard-fuzz`). They are not in this run.\n' "$(git rev-parse --abbrev-ref HEAD)"
    elif [[ $status -ne 0 ]]; then
        # What kind of failure, in a line: the harness's own panic message,
        # or the sanitizer's summary.
        reason=$(grep -m1 -E '^PANIC \(aborting|^SUMMARY: |ERROR: libFuzzer: timeout' "$log" || true)
        printf '\n%s\n' "${reason:-The fuzzer exited with status $status; see $log.}"
        for name in "${findings[@]}"; do
            printf '\nReplay: `cargo +nightly fuzz run %s fuzz/artifacts/%s/%s`\n' "$target" "$target" "$name"
        done
    fi
    printf '\n'
} >> "$summary"

if [[ $status -ne 0 ]]; then
    sarif=fuzz/campaign-$target.sarif
    category=$(python3 fuzz/finding_sarif.py "$target" "$log" "fuzz/artifacts/$target" "$(git rev-parse HEAD)" "$sarif")
    if [[ -n $public ]]; then
        # For the upload step. Nothing of the finding goes to the job log.
        printf 'sarif=%s\ncategory=%s\n' "$sarif" "$category" >> "${GITHUB_OUTPUT:-/dev/null}"
        echo "campaign: finding in $target; see the Security tab (code scanning)." >&2
    else
        tail -n 80 "$log" >&2
        echo "campaign: finding in $target; SARIF for code scanning written to $sarif." >&2
    fi
    exit 1
fi

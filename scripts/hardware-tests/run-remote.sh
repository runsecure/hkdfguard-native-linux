#!/usr/bin/env bash
# Runs the hardware-test bundle on one or more machines over SSH -- Hyper-V
# guests, lab laptops -- one after another, and brings each one's log and
# raw TPM capabilities back. From Linux, WSL, or Git Bash on the Hyper-V
# host.
#
#   scripts/hardware-tests/run-remote.sh [options] user@host [user@host ...]
#
# Options:
#   --bundle FILE   the tarball to run (default: the newest
#                   build-hardware-tests/hkdfguard-hardware-tests-*.tar.gz)
#   --args "..."    arguments for run-hardware-tests.sh (default: a full run),
#                   e.g. --args "reboot capture", then reboot the target and
#                   --args "reboot verify"
#   --keep          leave the extracted bundle on the target (the reboot
#                   phases do this regardless: verify needs what capture left)
#
# The SSH user should be an ordinary user in the target's 'tss' group (see
# run-hardware-tests.sh). Each target gets ~/hkdfguard-hardware-tests, which
# is replaced on every run. Logs land in build-hardware-tests/logs/<host>/.
# Exits 1 if any target failed or could not be reached.
set -uo pipefail
cd "$(dirname "$0")/../.."

BUNDLE=
RUN_ARGS=
KEEP=0
TARGETS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --bundle) BUNDLE=${2:?--bundle needs a file}; shift 2 ;;
        --args) RUN_ARGS=${2?--args needs a value}; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -*) echo "unknown option $1" >&2; exit 2 ;;
        *) TARGETS+=("$1"); shift ;;
    esac
done
[ "${#TARGETS[@]}" -gt 0 ] || { echo "usage: $0 [--bundle FILE] [--args \"...\"] [--keep] user@host ..." >&2; exit 2; }
case "$RUN_ARGS" in reboot*) KEEP=1 ;; esac
if [ -z "$BUNDLE" ]; then
    BUNDLE=$(ls -1t build-hardware-tests/hkdfguard-hardware-tests-*.tar.gz 2>/dev/null | head -n1)
    [ -n "$BUNDLE" ] || { echo "no bundle in build-hardware-tests/: run scripts/hardware-tests/make-bundle.sh first" >&2; exit 1; }
fi
[ -f "$BUNDLE" ] || { echo "no such bundle: $BUNDLE" >&2; exit 1; }
echo "bundle: $BUNDLE"

REMOTE_DIR=hkdfguard-hardware-tests # the tarball's top-level directory, in the remote home
RESULTS=()
FAILED=0
for t in "${TARGETS[@]}"; do
    host=${t#*@}
    logs="build-hardware-tests/logs/$host"
    echo
    echo "======== $t"
    if ! scp -q "$BUNDLE" "$t:$REMOTE_DIR.tar.gz"; then
        RESULTS+=("$t: unreachable (scp failed)"); FAILED=1; continue
    fi
    # Replace any earlier copy -- except during the reboot phases, whose
    # state lives outside it anyway but whose verify run must find the
    # same bundle. $RUN_ARGS is word-split on purpose.
    ssh "$t" "set -e
        if [ '$KEEP' = 1 ] && [ -d $REMOTE_DIR ]; then :; else rm -rf $REMOTE_DIR; fi
        tar -xzf $REMOTE_DIR.tar.gz && rm -f $REMOTE_DIR.tar.gz
        $REMOTE_DIR/run-hardware-tests.sh $RUN_ARGS"
    code=$?
    mkdir -p "$logs"
    scp -q "$t:$REMOTE_DIR/hardware-tests-*.log" "$t:$REMOTE_DIR/tpm-capabilities-*.txt" "$logs/" 2>/dev/null \
        || echo "(could not fetch every log from $t)"
    [ "$KEEP" = 1 ] || ssh "$t" "rm -rf $REMOTE_DIR" || true
    if [ "$code" -eq 0 ]; then RESULTS+=("$t: passed"); else RESULTS+=("$t: FAILED (exit $code)"); FAILED=1; fi
done

echo
echo "======== Summary (logs in build-hardware-tests/logs/)"
printf '%s\n' "${RESULTS[@]}"
exit "$FAILED"

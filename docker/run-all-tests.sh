#!/usr/bin/env bash
# Runs every containerized test suite this repo has -- the fleet a change
# is expected to pass before it is merged (see CONTRIBUTING.md):
#
#   1. docker/run-tests.sh         the full matrix on Ubuntu 24.04: TPM2
#                                  against swtpm, PKCS#11 against SoftHSM2,
#                                  external-secret, the C ABI and the CLI
#   2. docker/run-distro-tests.sh  the SoftHSM2 + Ephemeral suite on every
#                                  supported distribution
#
# Both run even if the first fails; the exit status is non-zero if either
# did. JOBS, PLATFORM and the other variables docker/run-distro-tests.sh
# reads pass through to it; JOBS=3 runs three distributions at a time.
#
# Usage: docker/run-all-tests.sh
set -uo pipefail
cd "$(dirname "$0")/.."

LOG_DIR=${LOG_DIR:-target/distro-tests}
export LOG_DIR
mkdir -p "$LOG_DIR"

echo "== 1/2: full matrix (docker/run-tests.sh); log: $LOG_DIR/full-matrix.log"
docker/run-tests.sh >"$LOG_DIR/full-matrix.log" 2>&1
full=$?
[ "$full" -eq 0 ] && echo "   PASS" || echo "   FAIL (see $LOG_DIR/full-matrix.log)"

echo
echo "== 2/2: distributions (docker/run-distro-tests.sh)"
docker/run-distro-tests.sh
distros=$?

echo
if [ "$full" -eq 0 ] && [ "$distros" -eq 0 ]; then
    echo "Every containerized suite passed."
    exit 0
fi
[ "$full" -eq 0 ] || echo "FAILED: full matrix (docker/run-tests.sh)" >&2
[ "$distros" -eq 0 ] || echo "FAILED: one or more distributions (summary above)" >&2
exit 1

#!/usr/bin/env bash
# Builds the HKDFGuard test image and runs the full test matrix in it:
#   cargo build/test (default features) -> real link against tpm2-tss and
#   PKCS#11 -> a swtpm-backed TPM2 hardware test -> a SoftHSM2-backed
#   PKCS#11 hardware test -> a C ABI round trip.
#
# The container is already ephemeral (`docker run --rm`, and named so an
# interrupted run's container can be removed too); the trap below
# additionally removes, on exit -- success, failure or Ctrl-C -- the built
# image and the pinned base image if this run is what pulled it (BuildKit
# keeps it in its build cache, the legacy builder in the image store), so
# nothing is left behind on the host beyond this run. A base image that
# was already present is never touched.
#
# Usage: docker/run-tests.sh
set -euo pipefail
cd "$(dirname "$0")/.."

TAG=hkdfguard-test
CONTAINER="hkdfguard-test-$$"
BASE_IMAGE=$(sed -n 's/^FROM[[:space:]]\{1,\}//p' docker/Dockerfile | head -n 1)
NEW_BASE_IMAGE=
docker image inspect "$BASE_IMAGE" >/dev/null 2>&1 || NEW_BASE_IMAGE=$BASE_IMAGE

cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker rmi -f "$TAG" >/dev/null 2>&1 || true
    if [ -n "$NEW_BASE_IMAGE" ]; then
        local id
        id=$(docker image inspect --format '{{.Id}}' "$NEW_BASE_IMAGE" 2>/dev/null) \
            && docker rmi -f "$id" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker build -t "$TAG" -f docker/Dockerfile .
docker run --rm --name "$CONTAINER" --cap-add IPC_LOCK "$TAG"   # IPC_LOCK: lets the CLI take its mlockall path

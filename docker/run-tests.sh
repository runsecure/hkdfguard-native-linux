#!/usr/bin/env bash
# Builds the HKDFGuard test image and runs the full test matrix in it:
#   cargo build/test (default features) -> real link against tpm2-tss and
#   PKCS#11 -> a swtpm-backed TPM2 hardware test -> a SoftHSM2-backed
#   PKCS#11 hardware test -> a C ABI round trip.
#
# It also mounts a read-only volume at /run/hkdfguard-ro-secrets, laid out
# like a Kubernetes Secret volume (a 1777 root holding KEK files), so the
# library's one exception to "nothing under a sticky, world-writable
# directory" -- a read-only mount -- is exercised on a real mount
# (docker/entrypoint-test.sh fails without it).
#
# The container is already ephemeral (`docker run --rm`, and named so an
# interrupted run's container can be removed too); the trap below
# additionally removes, on exit -- success, failure or Ctrl-C -- the built
# image, that volume, and the pinned base image if this run is what pulled it (BuildKit
# keeps it in its build cache, the legacy builder in the image store), so
# nothing is left behind on the host beyond this run. A base image that
# was already present is never touched.
#
# Usage: docker/run-tests.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1 # Git Bash: pass /paths to docker.exe unchanged

TAG=hkdfguard-test
CONTAINER="hkdfguard-test-$$"
RO_VOLUME="hkdfguard-test-ro-secrets-$$"
BASE_IMAGE=$(sed -n 's/^FROM[[:space:]]\{1,\}//p' docker/Dockerfile | head -n 1)
NEW_BASE_IMAGE=
docker image inspect "$BASE_IMAGE" >/dev/null 2>&1 || NEW_BASE_IMAGE=$BASE_IMAGE

cleanup() {
    docker rm -f "$CONTAINER" "$CONTAINER-ro" >/dev/null 2>&1 || true
    docker volume rm -f "$RO_VOLUME" >/dev/null 2>&1 || true
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
# The read-only secret volume: a 1777 root, as the kubelet makes a Secret
# volume, with a KEK for the test service in it and in a 0755
# subdirectory, each ci's own and 0400. Filled here, then mounted
# read-only into the test container.
docker volume create "$RO_VOLUME" >/dev/null
docker run --rm --name "$CONTAINER-ro" --entrypoint sh -v "$RO_VOLUME:/v" "$TAG" -c '
    set -e
    chmod 1777 /v && install -d -m 0755 /v/hkdfguard
    for d in /v /v/hkdfguard; do
        head -c 32 /dev/urandom > "$d/com.hkdfguard.dockertest.romount"
        chown ci:ci "$d/com.hkdfguard.dockertest.romount" && chmod 0400 "$d/com.hkdfguard.dockertest.romount"
    done'
docker run --rm --name "$CONTAINER" --cap-add IPC_LOCK \
    --mount "type=volume,src=$RO_VOLUME,dst=/run/hkdfguard-ro-secrets,readonly" \
    "$TAG"   # IPC_LOCK: lets the CLI take its mlockall path

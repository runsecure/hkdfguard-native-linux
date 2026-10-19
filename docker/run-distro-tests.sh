#!/usr/bin/env bash
# Runs the SoftHSM2 (PKCS#11) and Ephemeral provider tests on each
# supported distribution, each in its own container built from
# docker/distros/Dockerfile.<family> (the tests themselves are
# docker/distros/entrypoint-distro-test.sh). See docker/README.md.
#
# Usage:
#   docker/run-distro-tests.sh                 # every distribution below
#   docker/run-distro-tests.sh alpine-3.24 sles-16.0   # a subset, by name
#   docker/run-distro-tests.sh --list          # print the names
#   docker/distros/test-<name>.sh              # one distribution, streamed
#
# Environment:
#   JOBS=n           run n distributions at once (default 1)
#   PLATFORM=p       e.g. linux/amd64 on an arm64 host (QEMU; much slower).
#                    Default: the Docker host's native platform.
#   KEEP_IMAGES=1    keep the built images (default: removed, see below)
#   LOG_DIR=dir      per-distribution logs (default target/distro-tests)
#
# Exits non-zero if any distribution fails; the others still run, and a
# summary lists each result with its log.
#
# Cleanup: each distribution's test image is removed as soon as its run
# ends, pass or fail. On exit -- including Ctrl-C -- running builds are
# stopped, this run's containers are removed, any pinned base image that
# was not already present before the run is removed (BuildKit keeps base
# images in its build cache, but the legacy builder pulls them into the
# image store), and so are dangling images left by earlier runs (all
# carry the hkdfguard.distro-test label). Images that were already
# present are never touched. BuildKit's build cache is kept, so a rerun
# does not rebuild from scratch; `docker builder prune` reclaims it.
set -euo pipefail
cd "$(dirname "$0")/.."

# name | Dockerfile family | base image, pinned by digest | extra build args
#
# Digests are multi-arch indexes. To take an update, re-resolve
# deliberately:  docker buildx imagetools inspect <image:tag>
# ubuntu-24.04 matches docker/Dockerfile's pin; update both together.
# sles-16.0 installs softhsm from the openSUSE Backports repository (SUSE
# Package Hub's packages) and pins that repository's signing key file;
# sles-15.7 builds softhsm from source (see Dockerfile.zypper).
# ubi*-micro also pin the full UBI image of the same release that builds
# their root filesystem and test binaries (see Dockerfile.ubi-micro);
# update the two together.
BACKPORTS_16=https://download.opensuse.org/repositories/openSUSE:/Backports:/SLE-16.0/standard/
MATRIX="
almalinux-9      | dnf    | almalinux:9@sha256:9819dc675b67b595c2b59e42be7763fca1a8bb217fa5944e04daa22e9a64db16 |
almalinux-10     | dnf    | almalinux:10@sha256:838c2fafefb1a8a0d7f8cdbc3b0551c2a2b1eb0cd87aad6d62aecadb18311f1b |
debian-12        | apt    | debian:12@sha256:2c037a04925515fdd6ea85ea14a682d0e79931f5e9f5d07b6dbfc6ba12f9e858 |
debian-13        | apt    | debian:13@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5 |
ubuntu-24.04     | apt    | ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 |
ubuntu-26.04     | apt    | ubuntu:26.04@sha256:f144425ff09be612d6d9ad965196e9cdc23dae1f42110a8a11a3e9a8198759f7 |
sles-15.7        | zypper | registry.suse.com/bci/bci-base:15.7@sha256:b39dcf02d6ef54bd2cba185060d41435c75d87fff0f94ce0a2b73f2a24e5e66d |
sles-16.0        | zypper | registry.suse.com/bci/bci-base:16.0@sha256:23e3d679d07fe982d1e306bb2536ef7279aa82f7d296ed3f990f5c55c53f1878 | BACKPORTS_REPO=$BACKPORTS_16 BACKPORTS_KEY_SHA256=5604c296fdb82478d27af8dfa3a3feee38f121f32f6a577260b8a13ef0f76a6e
ubi9-micro       | ubi-micro | registry.access.redhat.com/ubi9/ubi-micro@sha256:ff30602252a3e92706585c7c34cd3c74028eaac4ab815e6b19f8b27562bdd7e3 | BUILDER_IMAGE=registry.access.redhat.com/ubi9/ubi@sha256:beba9460df08acc9f2d5a99f61b8544d5367b05e02c945ca726c6f07ca5963a7 RELEASEVER=9
ubi10-micro      | ubi-micro | registry.access.redhat.com/ubi10/ubi-micro@sha256:5b13e670e107509be71c066180032017ff5dddff2b6cd60d16311a5cea309953 | BUILDER_IMAGE=registry.access.redhat.com/ubi10/ubi@sha256:ad0d8e4fcd4c83cf4a2d025de402f010fd068e43f253d0a57b5681d1ad45f044 RELEASEVER=10
amazonlinux-2023 | dnf    | amazonlinux:2023@sha256:8ed3c0a996841537f75607e7d1de2114d8150391f75792e8da9268738547e73f |
alpine-3.24      | apk    | alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 |
"

trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "$s"; }
names() { while IFS='|' read -r name _; do name=$(trim "$name"); if [ -n "$name" ]; then echo "$name"; fi; done <<<"$MATRIX"; }
row() { while IFS='|' read -r name rest; do [ "$(trim "$name")" = "$1" ] && { echo "$rest"; return 0; }; done <<<"$MATRIX"; return 1; }

if [ "${1:-}" = "--list" ]; then names; exit 0; fi

if [ $# -gt 0 ]; then
    SELECTED=("$@")
    for n in "${SELECTED[@]}"; do
        row "$n" >/dev/null || { echo "unknown distribution '$n'; one of:" >&2; names >&2; exit 2; }
    done
else
    SELECTED=($(names))
fi

JOBS=${JOBS:-1}
# A single distribution streams its output as well as logging it.
STREAM=0
[ "${#SELECTED[@]}" -eq 1 ] && STREAM=1
LOG_DIR=${LOG_DIR:-target/distro-tests}
mkdir -p "$LOG_DIR"
PLATFORM_ARGS=()
[ -z "${PLATFORM:-}" ] || PLATFORM_ARGS=(--platform "$PLATFORM")

LABEL=hkdfguard.distro-test=1
CONTAINER_PREFIX="hkdfguard-distro-test-$$"

# The pinned images a distribution builds from: its base image, and the
# builder image of a multi-stage family (BUILDER_IMAGE=...).
base_images() {
    local family image extra kv
    IFS='|' read -r family image extra <<<"$(row "$1")"
    trim "$image"; echo
    for kv in $(trim "$extra"); do
        case "$kv" in BUILDER_IMAGE=*) echo "${kv#BUILDER_IMAGE=}" ;; esac
    done
}

# Recorded before anything is built: only these are removed afterwards.
NEW_BASE_IMAGES=()
for n in "${SELECTED[@]}"; do
    while read -r ref; do
        docker image inspect "$ref" >/dev/null 2>&1 || NEW_BASE_IMAGES+=("$ref")
    done < <(base_images "$n")
done

cleanup() {
    local pids pid n ref id
    # Each distribution runs in its own process group (set -m below), so
    # signalling the group stops its docker build/run too: docker build
    # cancels, and docker run passes the signal on to the container.
    pids=$(jobs -p)
    if [ -n "$pids" ]; then
        for pid in $pids; do kill -TERM -- "-$pid" 2>/dev/null || true; done
        wait 2>/dev/null || true
    fi
    for n in "${SELECTED[@]}"; do docker rm -f "$CONTAINER_PREFIX-$n" >/dev/null 2>&1 || true; done
    [ "${KEEP_IMAGES:-}" = 1 ] && return
    for n in "${SELECTED[@]}"; do docker rmi -f "hkdfguard-distro-test:$n" >/dev/null 2>&1 || true; done
    for ref in ${NEW_BASE_IMAGES[@]+"${NEW_BASE_IMAGES[@]}"}; do
        id=$(docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null) || continue
        docker rmi -f "$id" >/dev/null 2>&1 || true
    done
    docker image prune -f --filter "label=$LABEL" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_one() {
    local name=$1 family image extra tag
    IFS='|' read -r family image extra <<<"$(row "$name")"
    family=$(trim "$family"); image=$(trim "$image"); extra=$(trim "$extra")
    tag="hkdfguard-distro-test:$name"
    local build_args=(--build-arg "BASE_IMAGE=$image")
    local kv
    for kv in $extra; do build_args+=(--build-arg "$kv"); done

    local rc=0
    {
        echo "### $name: $image"
        docker build ${PLATFORM_ARGS[@]+"${PLATFORM_ARGS[@]}"} "${build_args[@]}" \
            --label "$LABEL" -f "docker/distros/Dockerfile.$family" -t "$tag" . &&
        docker run --rm --name "$CONTAINER_PREFIX-$name" \
            ${PLATFORM_ARGS[@]+"${PLATFORM_ARGS[@]}"} "$tag"
    } 2>&1 | if [ "$STREAM" = 1 ]; then tee "$LOG_DIR/$name.log"; else cat >"$LOG_DIR/$name.log"; fi || rc=$?

    # Done with this image whatever the result; the log has the details.
    [ "${KEEP_IMAGES:-}" = 1 ] || docker rmi -f "$tag" >/dev/null 2>&1 || true
    return "$rc"
}

echo "Testing ${#SELECTED[@]} distribution(s), $JOBS at a time; logs in $LOG_DIR/"
set -m   # a process group per distribution, for cleanup to stop as a unit
for n in "${SELECTED[@]}"; do
    rm -f "$LOG_DIR/$n.status"
    while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do sleep 2; done
    (
        start=$(date +%s)
        if run_one "$n"; then status=PASS; else status=FAIL; fi
        echo "$status $(( $(date +%s) - start ))" > "$LOG_DIR/$n.status"
        printf '  %-18s %s\n' "$n" "$status"
    ) &
done
wait

echo
echo "Summary:"
failed=0
for n in "${SELECTED[@]}"; do
    read -r status secs < "$LOG_DIR/$n.status" || { status=FAIL; secs=0; }
    [ "$status" = PASS ] || failed=$((failed + 1))
    printf '  %-18s %-4s %4ss  %s\n' "$n" "$status" "$secs" "$LOG_DIR/$n.log"
done
[ "$failed" -eq 0 ] || { echo "$failed distribution(s) failed" >&2; exit 1; }
echo "All ${#SELECTED[@]} distribution(s) passed."

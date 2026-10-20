#!/usr/bin/env bash
# Builds the FROM-scratch overlay images (packaging/overlay/Dockerfile) from
# the Ubuntu 24.04 packages in dist/packages/ubuntu24.04-<arch>/ -- build
# them first with DISTROS=ubuntu24.04 packaging/build-packages.sh -- then
# copies each into a clean Ubuntu 24.04 consumer image and runs
# packaging/overlay/consumer-test.sh there:
#   overlay      no policy; external-secret KEKs
#   overlay-dev  the dev policy; ephemeral, then SoftHSM2 with a PIN file
#
# Leaves hkdfguard-overlay:local and hkdfguard-overlay:local-dev loaded in
# Docker for that architecture (KEEP=0 removes them too).
#
# Usage: [ARCH=amd64|arm64] packaging/build-overlay.sh
set -euo pipefail
cd "$(dirname "$0")/.."

case "${ARCH:-$(uname -m)}" in
    amd64|x86_64)  arch=amd64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) echo "unsupported ARCH ${ARCH:-$(uname -m)}" >&2; exit 1 ;;
esac
platform=linux/$arch
[ -d "dist/packages/ubuntu24.04-$arch" ] \
    || { echo "dist/packages/ubuntu24.04-$arch missing: run DISTROS=ubuntu24.04 ARCHES=$arch packaging/build-packages.sh" >&2; exit 1; }

# Pinned like packaging/build-packages.sh's ubuntu24.04 target.
ubuntu=ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

TEMP_TAGS=(hkdfguard-overlay-consumer:plain hkdfguard-overlay-consumer:dev)
# No Sigstore bundle locally: only the release workflow has an identity to
# sign with, so the overlay's sigstore context is empty here.
no_bundle=$(mktemp -d)
cleanup() {
    rm -rf "$no_bundle"
    for tag in "${TEMP_TAGS[@]}"; do docker rmi -f "$tag" >/dev/null 2>&1 || true; done
    if [ "${KEEP:-1}" = 0 ]; then docker rmi -f hkdfguard-overlay:local hkdfguard-overlay:local-dev >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

case "$arch" in amd64) multiarch=x86_64-linux-gnu ;; arm64) multiarch=aarch64-linux-gnu ;; esac
expected_overlay="-rw-r--r-- 0/0 usr/lib/$multiarch/libhkdfguard.so.1
-rwxr-xr-x 0/0 usr/bin/hkdfguard"
expected_dev="$expected_overlay
-rw-r--r-- 0/0 etc/hkdfguard/policy.toml"

for target in overlay overlay-dev; do
    tag=hkdfguard-overlay:local${target#overlay}
    echo
    echo "=== Building $target for $platform as $tag ==="
    docker buildx build --platform "$platform" --load -t "$tag" \
        -f packaging/overlay/Dockerfile --build-context packages=dist/packages \
        --build-context sigstore="$no_bundle" \
        --target "$target" packaging/overlay

    # Every file in the image, directories aside: exactly the binaries (and
    # the dev policy), root-owned. Docker adds its own empty /etc/hosts,
    # /etc/hostname, /etc/resolv.conf, /etc/mtab, /.dockerenv, /dev and /proc to the
    # exported container, never to the image.
    expected=$expected_overlay; [ "$target" = overlay-dev ] && expected=$expected_dev
    container=$(docker create --platform "$platform" "$tag" /none)
    actual=$(docker export "$container" | tar -tvf - \
        | awk '$1 !~ /^d/ { $3 = $4 = $5 = ""; print }' | sed 's/  */ /g' \
        | grep -v -E ' (\.dockerenv|etc/(hosts|hostname|resolv\.conf)|etc/mtab -> /proc/mounts|dev/.*|proc/.*)$' | sort)
    docker rm "$container" >/dev/null
    if [ "$actual" != "$(sort <<< "$expected")" ]; then
        printf 'unexpected contents in %s:\n%s\nexpected:\n%s\n' "$tag" "$actual" "$expected" >&2
        exit 1
    fi
    echo "$tag holds only:"; while IFS= read -r line; do echo "  $line"; done <<< "$actual"
done

# The library's runtime dependencies are the libhkdfguard1 package's
# Depends (libc6 and libgcc-s1 are in the base image already); a consumer
# image installs the same. gcc and libc6-dev build the test programs;
# softhsm2 is for the dev policy's PKCS#11 half.
for mode in plain dev; do
    overlay=hkdfguard-overlay:local; [ "$mode" = dev ] && overlay=hkdfguard-overlay:local-dev
    echo
    echo "=== Consumer image: $ubuntu + $overlay ==="
    docker buildx build --platform "$platform" --load -t "hkdfguard-overlay-consumer:$mode" \
        --build-context "overlay=docker-image://$overlay" - <<DOCKERFILE
FROM $ubuntu
RUN apt-get update \\
    && apt-get install -y --no-install-recommends \\
        libtss2-esys-3.0.2-0t64 libtss2-mu-4.0.1-0t64 libtss2-tctildr0t64 \\
        gcc libc6-dev softhsm2 \\
    && rm -rf /var/lib/apt/lists/*
COPY --from=overlay / /
DOCKERFILE
    docker run --rm --platform "$platform" \
        -v "$(pwd)/examples:/examples:ro" \
        -v "$(pwd)/include:/include:ro" \
        -v "$(pwd)/packaging/overlay/consumer-test.sh:/consumer-test.sh:ro" \
        "hkdfguard-overlay-consumer:$mode" bash /consumer-test.sh "$mode"
done

echo
echo "Overlay images for $platform: hkdfguard-overlay:local, hkdfguard-overlay:local-dev"

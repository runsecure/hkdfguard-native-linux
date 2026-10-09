#!/usr/bin/env bash
# Builds the .deb and .rpm packages for every target distribution (table
# below) on linux/amd64 and linux/arm64, each in its own container, then
# installs each set into a clean container of its distribution and runs
# packaging/smoke-test.sh against it. Packages land in
# dist/packages/<distro>-<arch>/.
#
# Each package build runs the default and all-features test suites
# (dh_auto_test / %check) on its own distribution; the hardware-backed
# matrix (swtpm, SoftHSM2) stays in docker/run-tests.sh.
#
# The non-native architecture builds under QEMU emulation, as in
# docker/build-dist.sh, and is much slower. To build a subset:
#   DISTROS="debian sles16" ARCHES=amd64 packaging/build-packages.sh
#
# Usage: packaging/build-packages.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# Target distributions: the build image and the base image, pinned by
# digest. The package build and its smoke test run on the same base. To
# take an update, re-resolve deliberately:
#   docker buildx imagetools inspect <image>:<tag>     (the index digest)
# Every target ships tpm2-tss >= 4.0. Debian 12, EL9 and SLES 15 / Leap
# 15.6 ship 3.x, and Amazon Linux 2 older still: none are targets. The
# Ubuntu pin is the one docker/Dockerfile builds the release binaries on.
target() {
    case "$1" in
        debian)      echo "packaging/Dockerfile.debian debian:13@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c" ;;
        ubuntu24.04) echo "packaging/Dockerfile.debian ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3" ;;
        el10)        echo "packaging/Dockerfile.dnf almalinux:10@sha256:957738702313e6ee452cdb17bc1431542c467be9a4e2f4da3b8e551b0ebb9677" ;;
        al2023)      echo "packaging/Dockerfile.dnf amazonlinux:2023@sha256:8ed3c0a996841537f75607e7d1de2114d8150391f75792e8da9268738547e73f" ;;
        sles16)      echo "packaging/Dockerfile.suse registry.suse.com/bci/bci-base:16.0@sha256:23e3d679d07fe982d1e306bb2536ef7279aa82f7d296ed3f990f5c55c53f1878" ;;
        *) return 1 ;;
    esac
}

DISTROS=${DISTROS:-"debian ubuntu24.04 el10 al2023 sles16"}
ARCHES=${ARCHES:-"amd64 arm64"}

for distro in $DISTROS; do
    target "$distro" >/dev/null || { echo "error: unknown distro '$distro'" >&2; exit 1; }
done

packaging/check-version.sh

BUILT_TAGS=()
cleanup() {
    for tag in "${BUILT_TAGS[@]}"; do
        docker rmi -f "$tag" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

for distro in $DISTROS; do
    read -r dockerfile base_image < <(target "$distro")

    for arch in $ARCHES; do
        platform="linux/$arch"
        tag="hkdfguard-pkg-$distro-$arch"
        out_dir="dist/packages/$distro-$arch"

        echo
        echo "=== Building $distro packages for $platform ==="
        docker build --platform "$platform" --build-arg "BASE_IMAGE=$base_image" \
            -t "$tag" -f "$dockerfile" .
        BUILT_TAGS+=("$tag")

        rm -rf "$out_dir"
        mkdir -p "$out_dir"
        docker run --rm --platform "$platform" -v "$(pwd)/$out_dir:/dist" "$tag"

        echo
        echo "=== Smoke-testing $distro packages for $platform in a clean $base_image ==="
        docker run --rm --platform "$platform" \
            -v "$(pwd)/$out_dir:/packages:ro" \
            -v "$(pwd)/examples:/examples:ro" \
            -v "$(pwd)/packaging/smoke-test.sh:/smoke-test.sh:ro" \
            "$base_image" bash /smoke-test.sh /packages /examples
    done
done

echo
echo "Packages:"
find dist/packages -maxdepth 2 -type f \( -name '*.deb' -o -name '*.rpm' \) | sort

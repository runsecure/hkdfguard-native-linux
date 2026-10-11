#!/usr/bin/env bash
# Assembles a GitHub release from the build workflow's artifacts, as
# .github/workflows/release.yml downloads them:
#   <artifacts-dir>/packages-<distro>-<arch>/   packaging/build-packages.sh output
#   <artifacts-dir>/binaries-<arch>/            docker/build-dist.sh output
#
# Writes to <out-dir>:
#   hkdfguard-<version>-<distro>-<arch>.tar.gz  one target's .deb or .rpm packages
#   hkdfguard-<version>-linux-<arch>.tar.gz     the standalone library
#                                               (libhkdfguard.so.1, .so, .a),
#                                               CLI and header, with LICENSE
#                                               and THIRD-PARTY-LICENSES.txt
#   SHA256SUMS                                  every file above
# and <out-dir>/../attestation-subjects.txt: SHA256SUMS plus the files
# inside each tarball, so a package or binary that has been extracted can
# be verified on its own (`gh attestation verify <file>`). It is not
# published.
#
# The tarballs are reproducible: entries sorted, owned by root, dated to the
# last commit (SOURCE_DATE_EPOCH), and gzip stores no name or time.
# Artifacts lose their file modes in transit, so modes are set here.
#
# Needs cargo and python3 (for THIRD-PARTY-LICENSES.txt), and the
# dependency sources (`cargo fetch --locked`).
#
# Usage: packaging/release-assets.sh <artifacts-dir> <out-dir>
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <artifacts-dir> <out-dir>" >&2; exit 2; }
artifacts=$(realpath "$1")
mkdir -p "$2"
out=$(realpath "$2")
cd "$(dirname "$0")/.."

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
subjects="$out/../attestation-subjects.txt"
: > "$subjects"

# tarball <name> <dir>: writes <out>/<name>.tar.gz holding <dir> as <name>/,
# and records the regular files inside it as attestation subjects.
tarball() {
    local name=$1 dir=$2
    mv "$dir" "$stage/$name"
    tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner \
        --mtime="@$SOURCE_DATE_EPOCH" -cf - "$name" | gzip -9n > "$out/$name.tar.gz"
    (cd "$stage" && find "$name" -type f -print0 | sort -z | xargs -0 sha256sum) >> "$subjects"
}

found=0
for dir in "$artifacts"/packages-*/; do
    [ -d "$dir" ] || continue
    target=$(basename "$dir"); target=${target#packages-}
    pkg="$stage/pkg-$target"
    mkdir -p "$pkg"
    cp "$dir"/* "$pkg"/
    chmod 0644 "$pkg"/*
    tarball "hkdfguard-$version-$target" "$pkg"
    found=$((found + 1))
done

python3 packaging/third-party-licenses.py "$stage/THIRD-PARTY-LICENSES.txt"
for dir in "$artifacts"/binaries-*/; do
    [ -d "$dir" ] || continue
    arch=$(basename "$dir"); arch=${arch#binaries-}
    bin="$stage/bin-$arch"
    mkdir -p "$bin/lib" "$bin/bin" "$bin/include"
    # Named as the packages install them: the library under its SONAME
    # (build.rs), not Cargo's libhkdfguard_v1.
    install -m 0644 "$dir/libhkdfguard_v1.so" "$bin/lib/libhkdfguard.so.1"
    ln -s libhkdfguard.so.1 "$bin/lib/libhkdfguard.so"
    install -m 0644 "$dir/libhkdfguard_v1.a" "$bin/lib/libhkdfguard.a"
    install -m 0755 "$dir/hkdfguard-v1-initialize" "$bin/bin/"
    install -m 0644 "$dir/hkdfguard.h" "$bin/include/"
    install -m 0644 LICENSE "$stage/THIRD-PARTY-LICENSES.txt" "$bin/"
    tarball "hkdfguard-$version-linux-$arch" "$bin"
    found=$((found + 1))
done

[ "$found" -gt 0 ] || { echo "no packages-* or binaries-* directories in $artifacts" >&2; exit 1; }

(cd "$out" && sha256sum -- *.tar.gz > SHA256SUMS)
cat "$out/SHA256SUMS" >> "$subjects"
echo "release assets in $out:"
ls -l "$out"
echo "$(wc -l < "$subjects") attestation subjects in $subjects"

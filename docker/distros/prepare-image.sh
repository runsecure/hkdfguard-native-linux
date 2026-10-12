#!/bin/sh
# Distro-independent half of every docker/distros/Dockerfile.* image: run
# as root, after the distribution's own packages are installed.
#
#   rust  Installs the pinned Rust toolchain through a checksum-verified
#         rustup-init (glibc or musl build, matching the image's libc).
#   user  Creates `ci`, the unprivileged user every build and test runs
#         as, and its own SoftHSM2 token store. With a second argument,
#         does so inside that root filesystem instead of this one (the
#         UBI Micro image's, which has no useradd of its own).
#
# With no argument, does both, here. Mirrors docker/Dockerfile, which
# explains both choices at length.
#
# Usage: prepare-image.sh [rust | user [ROOT]]
set -eu

install_rust() {
    # rustup-init is fetched by exact version and checked against a SHA-256
    # pinned here, not piped from sh.rustup.rs into a shell. To update, take
    # the new version's hashes from
    #   https://static.rust-lang.org/rustup/archive/<version>/<target>/rustup-init.sha256
    # and check them against a download of the binary itself. The gnu
    # hashes are the ones docker/Dockerfile pins; update both together. The
    # toolchain must match rust-toolchain.toml at the repo root.
    RUSTUP_VERSION=1.29.1
    RUST_TOOLCHAIN=1.99.0

    if ldd --version 2>&1 | grep -qi musl; then libc=musl; else libc=gnu; fi
    case "$(uname -m)-$libc" in
        x86_64-gnu)   sha256=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71 ;;
        aarch64-gnu)  sha256=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433 ;;
        x86_64-musl)  sha256=331228566cc931f32cd684f9bebc5956a5e5d7394c8d5de595f196a658ab98e6 ;;
        aarch64-musl) sha256=1ddf36182ac5d1782dbeefcb9bea7f5f9412d88f4a0d5047b1564a223624e8c6 ;;
        *) echo "no pinned rustup-init for $(uname -m)-$libc" >&2; exit 1 ;;
    esac
    target="$(uname -m)-unknown-linux-$libc"

    curl --proto '=https' --tlsv1.2 -sSfo /tmp/rustup-init \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${target}/rustup-init"
    echo "${sha256}  /tmp/rustup-init" | sha256sum -c -
    chmod 0755 /tmp/rustup-init
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "$RUST_TOOLCHAIN"
    rm /tmp/rustup-init
    # rust-toolchain.toml lists clippy; install it now, while root can still
    # write RUSTUP_HOME, or rustup would try (and fail) to add it as `ci`.
    rustup component add clippy
}

# `ci` owns the source tree, the cargo registry cache, /work, and its own
# SoftHSM2 token store. HKDFGUARD_TESTS_MUST_NOT_RUN_AS_ROOT (set by each
# Dockerfile) makes the ownership tests fail rather than skip as root.
create_user() {
    root=${1:-}
    if [ -n "$root" ]; then
        useradd --root "$root" --create-home --user-group ci
    else
        useradd --create-home --user-group ci
    fi
    # Numeric ids: inside another root filesystem, `ci` is not a name this
    # system knows.
    uid=$(awk -F: '$1 == "ci" { print $3 }' "$root/etc/passwd")
    gid=$(awk -F: '$1 == "ci" { print $4 }' "$root/etc/passwd")
    [ -z "${CARGO_HOME:-}" ] || [ -n "$root" ] || chown -R "$uid:$gid" "$CARGO_HOME"
    install -d -o "$uid" -g "$gid" -m 0700 "$root/home/ci/softhsm-tokens"
    install -d -o "$uid" -g "$gid" "$root/work"
    printf 'directories.tokendir = /home/ci/softhsm-tokens\nobjectstore.backend = file\n' > "$root/etc/softhsm2-ci.conf"
    chmod 0644 "$root/etc/softhsm2-ci.conf"
}

case "${1:-}" in
    "")   install_rust; create_user ;;
    rust) install_rust ;;
    user) create_user "${2:-}" ;;
    *)    echo "usage: $0 [rust | user [ROOT]]" >&2; exit 2 ;;
esac

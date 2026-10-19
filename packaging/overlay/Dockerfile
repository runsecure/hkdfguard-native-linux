# A FROM-scratch image holding only HKDFGuard's binaries, at the paths the
# Ubuntu 24.04 packages install them to, for copying into another image:
#
#   COPY --from=ghcr.io/runsecure/hkdfguard-overlay:<version> / /
#
#   /usr/lib/<multiarch>/libhkdfguard.so.1
#   /usr/bin/hkdfguard
#
# They are taken from the libhkdfguard1 and hkdfguard .deb packages that
# packaging/build-packages.sh builds and tests -- the same bytes, not a
# separate build. Nothing else from the packages (documentation, man page,
# license notices, example policy) is copied.
#
# Two targets:
#   overlay      no policy: the library uses its defaults (TPM2, PKCS#11 if
#                configured, external secret; never ephemeral).
#   overlay-dev  adds policy.dev.toml: SoftHSM2 when its PIN file is
#                present, else EPHEMERAL keys that die with the process.
#                For development and tests only.
#
# Build (packaging/build-overlay.sh does this, then tests the result):
#   docker buildx build -f packaging/overlay/Dockerfile \
#       --build-context packages=dist/packages --target overlay packaging/overlay
# The `packages` context must hold ubuntu24.04-<arch>/ for each platform
# built. Unpacking runs on the build host's own platform, so building the
# other architecture needs no emulation.

# Pinned like packaging/build-packages.sh's ubuntu24.04 target.
ARG UBUNTU=ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

FROM --platform=$BUILDPLATFORM ${UBUNTU} AS unpack
ARG TARGETARCH
COPY --from=packages ubuntu24.04-${TARGETARCH}/ /packages/
COPY policy.dev.toml /policy.dev.toml
RUN set -eu; \
    mkdir /unpacked; \
    for pkg in /packages/libhkdfguard1_*_"${TARGETARCH}".deb /packages/hkdfguard_*_"${TARGETARCH}".deb; do \
        [ -f "$pkg" ] || { echo "missing package for ${TARGETARCH}: $pkg" >&2; exit 1; }; \
        dpkg-deb --extract "$pkg" /unpacked; \
    done; \
    lib=$(cd /unpacked && echo usr/lib/*-linux-gnu/libhkdfguard.so.1); \
    for f in "$lib" usr/bin/hkdfguard; do \
        [ -f "/unpacked/$f" ] || { echo "not in the packages: $f" >&2; exit 1; }; \
        install -d -m 0755 "/overlay/$(dirname "$f")"; \
        cp -a "/unpacked/$f" "/overlay/$f"; \
    done; \
    find /overlay -printf '%M %u:%g %p\n' | sort -k3; \
    # The dev policy, in its own tree. Created here rather than with
    # COPY --chmod, which would give /etc/hkdfguard the file's mode too.
    install -D -m 0644 /policy.dev.toml /overlay-dev/etc/hkdfguard/policy.toml

FROM scratch AS overlay
COPY --from=unpack /overlay/ /

FROM overlay AS overlay-dev
COPY --from=unpack /overlay-dev/ /

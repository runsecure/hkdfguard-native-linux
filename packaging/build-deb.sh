#!/usr/bin/env bash
# Builds the .deb packages inside the image from packaging/Dockerfile.debian
# and copies them into /dist -- bind-mount a host directory there (see
# packaging/build-packages.sh, which does this).
#
# The container starts as root only to collect into /dist; fetching,
# building, testing and lintian run as the unprivileged `builder`.
set -euo pipefail

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "build-deb.sh starts as root and drops to builder itself" >&2; exit 1; }
as_builder() { setpriv --reuid=builder --regid=builder --init-groups env HOME=/home/builder USER=builder LOGNAME=builder "$@"; }

section "version consistency"
packaging/check-version.sh

# debian/changelog names one release (Debian's). Building for another --
# Ubuntu 24.04 -- adds the usual backport entry, in this container's copy
# only: version 0.1.0-1~ubuntu24.04.1, distribution noble. The `~` sorts it
# below the unmodified version, and lintian checks the distribution against
# the release it runs on.
# shellcheck disable=SC1091
. /etc/os-release
changelog_dist=$(sed -n '1s/^[^ ]* ([^)]*) \([^;]*\);.*/\1/p' debian/changelog)
if [ "${VERSION_CODENAME:?}" != "$changelog_dist" ]; then
    section "changelog entry for $PRETTY_NAME"
    version=$(sed -n '1s/^[^ ]* (\([^)]*\)).*/\1/p' debian/changelog)
    # The newest entry's maintainer, dated one second after it: lintian
    # requires a newer date, and deriving it (rather than taking the time
    # of the build) keeps SOURCE_DATE_EPOCH, and so the build, reproducible.
    trailer=$(grep -m 1 '^ -- ' debian/changelog)
    entry_date=$(date -u -R -d "@$(( $(date -d "${trailer##*  }" +%s) + 1 ))")
    trailer="${trailer%  *}  $entry_date"
    as_builder sh -c 'printf "%s\n\n%s\n\n%s\n\n" "$1" "$2" "$3" | cat - debian/changelog > debian/changelog.new \
        && mv debian/changelog.new debian/changelog' sh \
        "hkdfguard ($version~$ID$VERSION_ID.1) $VERSION_CODENAME; urgency=medium" \
        "  * Build for $PRETTY_NAME." \
        "$trailer"
    head -n 6 debian/changelog
fi

section "cargo fetch (the package build itself runs offline)"
as_builder cargo fetch --locked

section "dpkg-buildpackage (build, test, package)"
as_builder dpkg-buildpackage --build=binary --no-sign

section "lintian"
as_builder lintian --fail-on error --info --display-info ../hkdfguard_*.changes

section "collecting packages into /dist"
mkdir -p /dist
cp ../*.deb ../*.buildinfo ../*.changes /dist/
ls -la /dist

#!/usr/bin/env bash
# Runs inside a consumer image -- plain Ubuntu 24.04 with the overlay copied
# in (`COPY --from=<overlay> / /`) and the library's runtime dependencies
# installed -- and uses HKDFGuard the way an application there would. No
# ldconfig has run: the library must load from its multiarch directory as
# copied.
#
#   consumer-test.sh plain  the overlay target: no policy, external-secret KEKs
#   consumer-test.sh dev    the overlay-dev target: ephemeral without a PIN
#                           file, then SoftHSM2 once one exists
#
# Expects examples/ at /examples and include/ at /include (read-only
# mounts; the runtime overlay has no header). packaging/build-overlay.sh
# runs it.
set -euo pipefail

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

[ $# -eq 1 ] || { echo "usage: $0 plain|dev" >&2; exit 2; }
mode=$1
work=$(mktemp -d)
multiarch=$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || gcc -print-multiarch)
libdir=/usr/lib/$multiarch

section "overlay layout"
for f in "$libdir/libhkdfguard.so.1" /usr/bin/hkdfguard; do
    [ -e "$f" ] || { echo "missing: $f" >&2; exit 1; }
done
case "$mode" in
    # Not even /etc/hkdfguard: with no policy directory the library still
    # runs on its defaults.
    plain) [ ! -e /etc/hkdfguard ] || { echo "the overlay target must not create /etc/hkdfguard" >&2; exit 1; } ;;
    dev)   [ "$(stat -c '%U:%G %a' /etc/hkdfguard)" = "root:root 755" ] \
               || { echo "/etc/hkdfguard must be root:root 0755" >&2; exit 1; }
           [ "$(stat -c '%U:%G %a' /etc/hkdfguard/policy.toml)" = "root:root 644" ] \
               || { echo "overlay-dev must ship /etc/hkdfguard/policy.toml as root:root 0644" >&2; exit 1; } ;;
    *) echo "usage: $0 plain|dev" >&2; exit 2 ;;
esac
hkdfguard --help >/dev/null
echo "files in place; CLI runs"

# Linked by SONAME: the runtime overlay has no libhkdfguard.so dev symlink.
build() { cc -I /include -o "$work/$1" "/examples/$1.c" -l:libhkdfguard.so.1; }

section "dlopen(\"libhkdfguard.so.1\") without ldconfig"
cat > "$work/dlopen_check.c" <<'C'
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void* lib = dlopen("libhkdfguard.so.1", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    if (!dlsym(lib, "hkdfguard_unwrap_dek")) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    puts("libhkdfguard.so.1 loads and exports hkdfguard_unwrap_dek");
    return 0;
}
C
cc -o "$work/dlopen_check" "$work/dlopen_check.c" -ldl
"$work/dlopen_check"

build wrap_unwrap
build cli_unwrap_check

# CLI provisions and wraps; a separate process unwraps through the library.
# The wrapped payload's second byte names the provider that served it
# (src/payload.rs): 2 PKCS#11, 3 external secret, 5 ephemeral.
cli_round_trip() { # cli_round_trip <service> <expected provider byte>
    install -m 0600 /dev/null "$work/dek.bin"
    head -c 32 /dev/urandom > "$work/dek.bin"
    hkdfguard provision -sn "$1"
    base64 -w0 < "$work/dek.bin" | hkdfguard wrap -kf "$work/wrapped.key" -sn "$1" --dek-stdin --force
    "$work/cli_unwrap_check" "$work/wrapped.key" "$1" "$work/dek.bin"
    local provider
    provider=$(od -An -tu1 -j1 -N1 "$work/wrapped.key" | tr -d ' ')
    [ "$provider" = "$2" ] || { echo "wrapped by provider $provider, expected $2" >&2; exit 1; }
    echo "wrapped and unwrapped by provider $provider"
}

if [ "$mode" = plain ]; then
    section "no policy: external-secret KEKs from /run/secrets/hkdfguard"
    install -d -m 0755 /run/secrets/hkdfguard
    for service in com.company.orders com.company.cli; do
        install -m 0600 /dev/null "/run/secrets/hkdfguard/$service"
        head -c 32 /dev/urandom > "/run/secrets/hkdfguard/$service"
    done
    "$work/wrap_unwrap"
    cli_round_trip com.company.cli 3
else
    section "dev policy, no PIN file: ephemeral"
    # In one process, ephemeral keys work. The CLI logs which provider it
    # fell back to; the library itself installs no logger.
    "$work/wrap_unwrap"
    hkdfguard provision -sn com.company.ephemeral 2> "$work/ephemeral.log" \
        || { cat "$work/ephemeral.log" >&2; exit 1; }
    grep -q 'EPHEMERAL' "$work/ephemeral.log" || { cat "$work/ephemeral.log" >&2; echo "expected the ephemeral fallback warning" >&2; exit 1; }
    echo "the CLI reports the ephemeral fallback"

    section "dev policy, SoftHSM2 token and PIN file: PKCS#11"
    softhsm2-util --init-token --free --label hkdfguard --pin 1234 --so-pin 5678 >/dev/null
    ( umask 077; printf '1234\n' > /etc/hkdfguard/pkcs11.pin )
    "$work/wrap_unwrap"
    # Across processes, and wrapped by PKCS#11 (2), not ephemeral (5).
    cli_round_trip com.company.cli 2
fi

section "CONSUMER TEST PASSED ($mode)"

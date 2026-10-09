#!/usr/bin/env bash
# Installs the built packages into a clean container of their target
# (Debian 13, Ubuntu 24.04, EL10, Amazon Linux 2023, SLES 16) --
# the plain base image, not the build image, so a missing runtime
# dependency can't be masked by build tools -- and uses them as a consumer
# would: dynamic and static linking through pkg-config, dlopen by the
# HkdfGuard.Kms.Linux.v1 name, and the CLI's provision/wrap output
# unwrapped through the installed library.
#
# There is no TPM or PKCS#11 module in the container, so with no policy
# file the external-secret provider serves every call, as it does in
# docker/entrypoint-test.sh.
#
# Usage (as root, in the clean container; packaging/build-packages.sh
# runs it):
#   smoke-test.sh <package-dir> <examples-dir>
set -euo pipefail

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

[ $# -eq 2 ] || { echo "usage: $0 <package-dir> <examples-dir>" >&2; exit 2; }
pkgs=$1
examples=$2
work=$(mktemp -d)

# The RPMs to install, by glob rather than find: Amazon Linux's base image
# has no findutils, and a failed $(find) would silently install nothing.
rpms=()
for f in "$pkgs"/*.rpm; do
    case "$f" in *-debuginfo-*|*-debugsource-*) ;; *) if [ -f "$f" ]; then rpms+=("$f"); fi ;; esac
done

section "installing packages"
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends gcc libc6-dev pkgconf \
        "$pkgs"/hkdfguard_*.deb "$pkgs"/libhkdfguard1_*.deb "$pkgs"/libhkdfguard-dev_*.deb
elif [ "${#rpms[@]}" -eq 0 ]; then
    echo "no .rpm packages in $pkgs" >&2
    exit 1
elif command -v dnf >/dev/null; then
    # EL10's tpm2-tss-devel is in CRB; Amazon Linux has no CRB.
    dnf -y install dnf-plugins-core
    if dnf repolist --all | grep -q '^crb[[:space:]]'; then dnf config-manager --set-enabled crb; fi
    dnf -y install gcc pkgconf-pkg-config "${rpms[@]}"
elif command -v zypper >/dev/null; then
    # The packages are unsigned local files. SUSE's base image has no awk.
    zypper --non-interactive install --no-recommends --allow-unsigned-rpm \
        gcc glibc-devel pkgconf-pkg-config gawk "${rpms[@]}"
else
    echo "none of apt-get, dnf or zypper found" >&2
    exit 1
fi

section "installed layout"
[ "$(stat -c '%U:%G %a' /etc/hkdfguard)" = "root:root 755" ] \
    || { echo "/etc/hkdfguard must be root:root 0755" >&2; exit 1; }
[ ! -e /etc/hkdfguard/policy.toml ] || { echo "packages must not install a policy" >&2; exit 1; }
libdir=$(pkg-config --variable=libdir hkdfguard)
ls -l "$libdir"/libhkdfguard* "$libdir"/HkdfGuard.Kms.Linux.v1.so
hkdfguard-v1-initialize --help

section "external secrets for the test services (root's mount, as a platform's would be)"
install -d -m 0755 /run/secrets/hkdfguard
for service in com.company.orders com.company.cli; do
    install -m 0600 /dev/null "/run/secrets/hkdfguard/$service"
    head -c 32 /dev/urandom > "/run/secrets/hkdfguard/$service"
done

section "dynamic link via pkg-config"
# shellcheck disable=SC2046 # pkg-config output is a list of flags
cc -o "$work/wrap_unwrap" "$examples/wrap_unwrap.c" $(pkg-config --cflags --libs hkdfguard)
# Compared as real paths: EL's linker cache reports /lib64, a symlink to
# /usr/lib64.
resolved=$(ldd "$work/wrap_unwrap" | awk '$1 == "libhkdfguard.so.1" { print $3 }')
if [ -z "$resolved" ] || [ "$(readlink -f "$resolved")" != "$(readlink -f "$libdir/libhkdfguard.so.1")" ]; then
    echo "libhkdfguard.so.1 resolves to '${resolved:-nothing}', not the installed $libdir/libhkdfguard.so.1" >&2
    exit 1
fi
echo "libhkdfguard.so.1 => $resolved"
"$work/wrap_unwrap"

section "static link via pkg-config --static"
# shellcheck disable=SC2046
cc -o "$work/wrap_unwrap_static" "$examples/wrap_unwrap.c" $(pkg-config --cflags hkdfguard) \
    "$libdir/libhkdfguard.a" $(pkg-config --static --libs hkdfguard | sed 's/-lhkdfguard\b//')
if ldd "$work/wrap_unwrap_static" | grep -F libhkdfguard; then
    echo "static build still depends on the shared library" >&2
    exit 1
fi
"$work/wrap_unwrap_static"

section "dlopen(\"HkdfGuard.Kms.Linux.v1.so\")"
cat > "$work/dlopen_check.c" <<'C'
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void* lib = dlopen("HkdfGuard.Kms.Linux.v1.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    if (!dlsym(lib, "hkdfguard_wrap_dek")) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    puts("HkdfGuard.Kms.Linux.v1.so loads and exports hkdfguard_wrap_dek");
    return 0;
}
C
cc -o "$work/dlopen_check" "$work/dlopen_check.c" -ldl
"$work/dlopen_check"

section "CLI provision + wrap, unwrapped through the installed library"
# shellcheck disable=SC2046
cc -o "$work/cli_unwrap_check" "$examples/cli_unwrap_check.c" $(pkg-config --cflags --libs hkdfguard)
install -m 0600 /dev/null "$work/dek.bin"
head -c 32 /dev/urandom > "$work/dek.bin"
hkdfguard-v1-initialize provision -sn com.company.cli
# base64 reads the DEK from stdin and writes it to a pipe: it never
# reaches an argument list.
base64 -w0 < "$work/dek.bin" | hkdfguard-v1-initialize wrap -kf "$work/wrapped.key" -sn com.company.cli --dek-stdin
"$work/cli_unwrap_check" "$work/wrapped.key" com.company.cli "$work/dek.bin"

section "SMOKE TEST PASSED"

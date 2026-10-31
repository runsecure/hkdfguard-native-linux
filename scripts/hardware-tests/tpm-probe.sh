#!/usr/bin/env bash
# Read-only inventory of the machine being qualified and its TPM, through
# tpm2-tools and sysfs only -- never the library -- so a TPM that lacks
# something hkdfguard relies on is named at its source rather than as a
# failed test later. Changes nothing on the TPM or the host; every TPM
# command it sends is a query (TPM2_GetCapability, TPM2_GetTestResult,
# TPM2_GetRandom).
#
# Usage: tpm-probe.sh [--raw FILE]
#
#   --raw FILE   also write every tpm2_getcap capability, verbatim, to
#                FILE: the record to diff one TPM against another.
#
# Environment:
#   HKDFGUARD_TCTI   the TCTI to probe (default: the first of
#                    device:/dev/tpmrm0, device:/dev/tpm0 that exists)
#
# Exits 1 if hkdfguard's TPM provider cannot work on this TPM: no device,
# no access, tpm2-tools missing, or an algorithm, curve, command or limit
# the provider needs is absent. Everything else is reported, not judged.
set -uo pipefail

ok()   { printf '  ok    %s\n' "$*"; }
info() { printf '  info  %s\n' "$*"; }
warn() { printf '  warn  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAILED=1; }
section() { printf '\n-- %s\n' "$1"; }
FAILED=0

RAW=
while [ $# -gt 0 ]; do
    case "$1" in
        --raw) RAW=${2:?--raw needs a file}; shift 2 ;;
        *) echo "usage: $0 [--raw FILE]" >&2; exit 2 ;;
    esac
done

readf() { [ -r "$1" ] && tr -d '\0' < "$1" | head -n1; } # a sysfs/DMI attribute, if readable

# ---------------------------------------------------------------------
section "host"
# ---------------------------------------------------------------------
if [ "$(uname -s)" != Linux ]; then
    fail "this must run on Linux ($(uname -s) detected)"
    exit 1
fi
distro=$( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$ID $VERSION_ID}" )
info "hostname:        $(hostname)"
info "distribution:    ${distro:-unknown}"
info "kernel:          $(uname -r) ($(uname -m))"
info "glibc:           $(getconf GNU_LIBC_VERSION 2>/dev/null || ldd --version 2>/dev/null | head -n1 || echo unknown)"
virt=$(systemd-detect-virt 2>/dev/null) || virt=${virt:-none}
info "virtualization:  ${virt:-unknown}"
info "system:          $(readf /sys/class/dmi/id/sys_vendor) $(readf /sys/class/dmi/id/product_name) $(readf /sys/class/dmi/id/product_version)"
info "firmware:        $(readf /sys/class/dmi/id/bios_vendor) $(readf /sys/class/dmi/id/bios_version) ($(readf /sys/class/dmi/id/bios_date))"
info "cpu:             $(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"
if [ -d /sys/firmware/efi ]; then
    sb=$(od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | tr -d ' ')
    case "$sb" in 1) sb=enabled ;; 0) sb=disabled ;; *) sb=unknown ;; esac
    info "boot:            UEFI, Secure Boot $sb"
else
    info "boot:            legacy BIOS (no /sys/firmware/efi)"
fi
info "user:            $(id -un) (uid $(id -u)), groups: $(id -nG)"

# ---------------------------------------------------------------------
section "installed components"
# ---------------------------------------------------------------------
# Whatever this host's package manager knows of the TPM stack, the
# PKCS#11 token, and any installed hkdfguard -- the bundle carries its own
# library and CLI and uses those, never an installed one.
pkgs=
if command -v dpkg-query >/dev/null 2>&1; then
    pkgs=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' \
        'libtss2-esys*' 'libtss2-tctildr*' 'libtss2-mu*' tpm2-tools tpm2-abrmd softhsm2 'hkdfguard*' 'libhkdfguard*' 2>/dev/null \
        | awk '$1 ~ /^ii/ {print $2" "$3}')
elif command -v rpm >/dev/null 2>&1; then
    pkgs=$(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null \
        | grep -E '^(tpm2-tss|libtss2|tpm2-tools|tpm2-abrmd|softhsm|hkdfguard|libhkdfguard)' | sort)
elif command -v apk >/dev/null 2>&1; then
    pkgs=$(apk info -v 2>/dev/null | grep -E '^(tpm2-tss|tpm2-tools|tpm2-abrmd|softhsm|hkdfguard)' | sort)
fi
if [ -n "$pkgs" ]; then
    printf '%s\n' "$pkgs" | sed 's/^/  info  package: /'
else
    info "no TPM-related packages found by the package manager"
fi
if command -v tpm2_getcap >/dev/null 2>&1; then
    ok "tpm2-tools: $(tpm2_getcap --version 2>/dev/null | head -n1)"
else
    fail "tpm2-tools not found: install 'tpm2-tools' (it also pulls in the tpm2-tss libraries the bundle links against)"
fi
for lib in libtss2-esys.so.0 libtss2-tctildr.so.0 libtss2-mu.so.0; do
    if ldconfig -p 2>/dev/null | grep -q "$lib"; then
        ok "$lib: $(ldconfig -p | awk -v l="$lib" '$1==l {print $NF; exit}')"
    else
        fail "$lib not found by the dynamic linker: install the tpm2-tss runtime libraries (installing tpm2-tools pulls them in)"
    fi
done
if pgrep -x tpm2-abrmd >/dev/null 2>&1; then
    info "tpm2-abrmd is running (the bundle talks to the kernel resource manager, /dev/tpmrm0, unless HKDFGUARD_TCTI says otherwise)"
fi
softhsm=$(find /usr/lib /usr/lib64 /usr/local/lib -iname 'libsofthsm2.so' 2>/dev/null | head -n1 || true)
if [ -n "$softhsm" ]; then
    info "SoftHSM2: $softhsm (the pkcs11 suite will run)"
else
    info "SoftHSM2 not installed (the pkcs11 suite will be skipped; install 'softhsm2' to include it)"
fi
for f in /etc/hkdfguard/policy.toml /var/lib/hkdfguard/tpm; do
    [ -e "$f" ] && info "existing $f: $(stat -c '%U:%G %a' "$f") (not read or changed; the tests use their own)"
done

# ---------------------------------------------------------------------
section "kernel TPM interface"
# ---------------------------------------------------------------------
if [ -d /sys/class/tpm/tpm0 ]; then
    drv=$(basename "$(readlink -f /sys/class/tpm/tpm0/device/driver 2>/dev/null)" 2>/dev/null)
    info "tpm0: TPM $(readf /sys/class/tpm/tpm0/tpm_version_major).x, driver ${drv:-unknown}${drv:+ }$(readf /sys/class/tpm/tpm0/device/firmware_node/hid)"
    desc=$(readf /sys/class/tpm/tpm0/device/description)
    [ -n "$desc" ] && info "description: $desc"
    [ "$(readf /sys/class/tpm/tpm0/tpm_version_major)" = 1 ] && fail "this is a TPM 1.2; hkdfguard needs a TPM 2.0"
else
    info "no /sys/class/tpm/tpm0"
fi
for d in /dev/tpm0 /dev/tpmrm0; do
    [ -e "$d" ] && info "$d: $(stat -c '%U:%G %a' "$d")"
done
klog=$( { journalctl -k -b --no-pager 2>/dev/null || dmesg 2>/dev/null; } | grep -i 'tpm' | head -n 12)
[ -n "$klog" ] && printf '%s\n' "$klog" | sed 's/^/  info  kernel: /'

TCTI="${HKDFGUARD_TCTI:-}"
if [ -z "$TCTI" ]; then
    if [ -e /dev/tpmrm0 ]; then
        TCTI="device:/dev/tpmrm0"
    elif [ -e /dev/tpm0 ]; then
        TCTI="device:/dev/tpm0"
        warn "/dev/tpmrm0 (kernel resource manager) not present; using /dev/tpm0, which nothing else may use at the same time"
    fi
fi
if [ -z "$TCTI" ]; then
    fail "no TPM device (/dev/tpmrm0 or /dev/tpm0). Enable the TPM/fTPM in firmware (on Hyper-V: Enable-HyperVTpm.ps1 on the host)"
    exit 1
fi
ok "TCTI: $TCTI"
dev="${TCTI#device:}"
if [ "$dev" != "$TCTI" ]; then
    if [ -r "$dev" ] && [ -w "$dev" ]; then
        ok "$dev is readable and writable by $(id -un)"
    else
        fail "$dev is not accessible by $(id -un). Run 'sudo usermod -aG tss $(id -un)', then log in again"
        exit 1
    fi
fi
command -v tpm2_getcap >/dev/null 2>&1 || exit 1
export TPM2TOOLS_TCTI="$TCTI"

# ---------------------------------------------------------------------
section "TPM identity"
# ---------------------------------------------------------------------
getcap() { tpm2_getcap "$1" 2>/dev/null; }
if ! FIXED=$(getcap properties-fixed); then
    fail "tpm2_getcap could not talk to the TPM via $TCTI (busy, no access, or disabled in firmware)"
    exit 1
fi
VARIABLE=$(getcap properties-variable)
ALGS=$(getcap algorithms)
CMDS=$(getcap commands)
CURVES=$(getcap ecc-curves)
PCRS=$(getcap pcrs)
PERSISTENT=$(getcap handles-persistent)
NVIDX=$(getcap handles-nv-index)

# field <yaml> <key> <subkey>: `key:` then an indented `subkey: value` under it.
field() {
    printf '%s\n' "$1" | awk -v k="$2:" -v s="$3:" '
        $1 == k { f = 1; next }
        f && /^[^ \t]/ { exit }
        f && $1 == s { $1 = ""; sub(/^ +/, ""); gsub(/"/, ""); print; exit }'
}
# scalar <yaml> <key>: `key: value` on one line.
scalar() { printf '%s\n' "$1" | awk -v k="$2:" '$1 == k { print $2; exit }'; }
dec() { [ -n "$1" ] && printf '%d' "$1" 2>/dev/null; }
# 32-bit raw -> "high.low" 16-bit halves, the usual vendor version display.
halves() { [ -n "$1" ] && printf '%d.%d' $(( $1 >> 16 )) $(( $1 & 0xffff )) 2>/dev/null; }

MANUFACTURER=$(field "$FIXED" TPM2_PT_MANUFACTURER value)
vendor=
for i in 1 2 3 4; do vendor+=$(field "$FIXED" "TPM2_PT_VENDOR_STRING_$i" value); done
fw1=$(field "$FIXED" TPM2_PT_FIRMWARE_VERSION_1 raw)
fw2=$(field "$FIXED" TPM2_PT_FIRMWARE_VERSION_2 raw)
info "manufacturer:    ${MANUFACTURER:-unknown}${vendor:+ ($vendor)}"
info "firmware:        $(halves "$fw1").$(halves "$fw2") (TPM2_PT_FIRMWARE_VERSION_1 $fw1, _2 $fw2)"
info "spec:            family $(field "$FIXED" TPM2_PT_FAMILY_INDICATOR value), level $(dec "$(field "$FIXED" TPM2_PT_LEVEL raw)"), revision $(field "$FIXED" TPM2_PT_REVISION value), $(dec "$(field "$FIXED" TPM2_PT_YEAR raw)") day $(dec "$(field "$FIXED" TPM2_PT_DAY_OF_YEAR raw)")"
modes=$(field "$FIXED" TPM2_PT_MODES value)
[ -n "$modes" ] && info "modes:           $modes"
case "$MANUFACTURER" in
    INTC|AMD|QCOM) info "class:           firmware TPM (inside the SoC)" ;;
    MSFT|IBM|GOOG|VMW) info "class:           virtual/software TPM" ;;
    IFX|STM|NTC|ATML|NSM|NSG|SMSC) info "class:           discrete TPM chip: pin the storage root key's Name before provisioning in production (README)" ;;
    *) warn "unrecognized manufacturer '${MANUFACTURER}': treat it as a discrete chip" ;;
esac
selftest=$(tpm2_gettestresult 2>/dev/null | awk '/status:/{print $2}')
[ -n "$selftest" ] && info "self-test:       $selftest"
if tpm2_getrandom --hex 16 >/dev/null 2>&1; then ok "TPM2_GetRandom answers"; else warn "TPM2_GetRandom failed"; fi

# ---------------------------------------------------------------------
section "what hkdfguard's TPM provider needs"
# ---------------------------------------------------------------------
# src/provider/tpm2.rs: a storage primary key that is ECC NIST P-256 with
# AES-128-CFB, SHA-256 Names, keyed-hash HMAC-SHA-256 service keys, and
# salted sessions (ECDH to that key) encrypting parameters with AES-128-CFB.
for alg in ecc ecdh aes cfb sha256 keyedhash hmac; do
    if printf '%s\n' "$ALGS" | grep -q "^$alg:"; then ok "algorithm $alg"; else fail "algorithm $alg not supported"; fi
done
if printf '%s\n' "$CURVES" | grep -q 'TPM2_ECC_NIST_P256'; then ok "curve NIST P-256"; else fail "curve NIST P-256 not supported"; fi
if [ "$(printf '%s\n' "$CMDS" | grep -c '^TPM2_CC_')" -eq 0 ]; then
    warn "could not parse the command list from this tpm2-tools; the conformance suite checks the commands instead"
else
    for cc in CreatePrimary Create Load HMAC StartAuthSession FlushContext ReadPublic; do
        if printf '%s\n' "$CMDS" | grep -q "^TPM2_CC_$cc:"; then ok "command TPM2_$cc"; else fail "command TPM2_$cc not supported"; fi
    done
fi
# MAX_PRF_INPUT_LEN (src/crypto.rs): the longest input one TPM2_HMAC gets.
inbuf=$(dec "$(field "$FIXED" TPM2_PT_INPUT_BUFFER raw)")
if [ -z "$inbuf" ]; then
    warn "TPM2_PT_INPUT_BUFFER not reported"
elif [ "$inbuf" -ge 352 ]; then
    ok "TPM2_PT_INPUT_BUFFER $inbuf bytes (needs 352: the longest PRF input)"
else
    fail "TPM2_PT_INPUT_BUFFER is $inbuf bytes; a TPM2_HMAC input can be 352"
fi
transient=$(dec "$(field "$FIXED" TPM2_PT_HR_TRANSIENT_MIN raw)")
if [ -n "$transient" ] && [ "$transient" -lt 3 ]; then
    warn "only $transient transient object slots guaranteed (the provider holds the storage key and a service key at once)"
else
    info "transient object slots: ${transient:-?}, sessions: $(dec "$(field "$FIXED" TPM2_PT_ACTIVE_SESSIONS_MAX raw)")"
fi

# ---------------------------------------------------------------------
section "TPM state"
# ---------------------------------------------------------------------
owner_set=$(field "$VARIABLE" TPM2_PT_PERMANENT ownerAuthSet)
in_lockout=$(field "$VARIABLE" TPM2_PT_PERMANENT inLockout)
counter=$(dec "$(scalar "$VARIABLE" TPM2_PT_LOCKOUT_COUNTER)")
maxfail=$(dec "$(scalar "$VARIABLE" TPM2_PT_MAX_AUTH_FAIL)")
info "dictionary attack: $counter of $maxfail failures, lockout interval $(dec "$(scalar "$VARIABLE" TPM2_PT_LOCKOUT_INTERVAL)")s, recovery $(dec "$(scalar "$VARIABLE" TPM2_PT_LOCKOUT_RECOVERY)")s"
if [ "$in_lockout" = 1 ]; then
    fail "the TPM is in dictionary-attack lockout: authorized commands will fail until it recovers (or tpm2_dictionarylockout --clear-lockout)"
fi
if [ "$owner_set" = 1 ]; then
    if [ -n "${HKDFGUARD_TPM_OWNER_AUTH_FILE:-}" ]; then
        ok "Owner hierarchy has a password; the tests will use HKDFGUARD_TPM_OWNER_AUTH_FILE"
    else
        fail "the Owner hierarchy has a password: set HKDFGUARD_TPM_OWNER_AUTH_FILE to a private file holding it, or every TPM test will fail to create the storage key"
    fi
else
    ok "Owner hierarchy has no password"
fi
info "startup: $(field "$VARIABLE" TPM2_PT_STARTUP_CLEAR phEnable | sed 's/^/phEnable /')$(field "$VARIABLE" TPM2_PT_STARTUP_CLEAR shEnable | sed 's/^/, shEnable /')$(field "$VARIABLE" TPM2_PT_STARTUP_CLEAR ehEnable | sed 's/^/, ehEnable /')"
[ "$(field "$VARIABLE" TPM2_PT_STARTUP_CLEAR shEnable)" = 0 ] && fail "the Owner (storage) hierarchy is disabled"
info "PCR banks: $(printf '%s\n' "$PCRS" | sed -n 's/^ *- \([a-z0-9_]*\):.*/\1/p' | paste -sd' ' -)"
info "persistent objects: $(printf '%s\n' "$PERSISTENT" | grep -c '^- ') (the provider uses none)"
ek=
printf '%s\n' "$NVIDX" | grep -qi '0x1c00002' && ek+=" RSA"
printf '%s\n' "$NVIDX" | grep -qi '0x1c0000a' && ek+=" ECC"
info "EK certificates in NV:${ek:- none}"

if [ -n "$RAW" ]; then
    {
        echo "# tpm2_getcap, $(hostname), $(date -u +%Y-%m-%dT%H:%M:%SZ), TCTI $TCTI"
        for cap in properties-fixed properties-variable algorithms commands ecc-curves pcrs handles-persistent handles-nv-index; do
            printf '\n# ---- %s\n' "$cap"
            getcap "$cap"
        done
    } > "$RAW"
    info "raw capabilities written to $RAW"
fi

echo
if [ "$FAILED" -ne 0 ]; then
    echo "probe: this TPM is missing something hkdfguard needs (FAIL lines above)"
    exit 1
fi
echo "probe: ${MANUFACTURER:-unknown} TPM via $TCTI has everything hkdfguard's TPM provider needs"

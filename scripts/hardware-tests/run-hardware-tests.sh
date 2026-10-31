#!/usr/bin/env bash
# Qualifies hkdfguard on the machine it runs on, from the bundle
# make-bundle.sh made: the same suites as scripts/native-tpm-test.sh, from
# prebuilt binaries, so the target needs no Rust toolchain or headers --
# only the tpm2-tss runtime libraries (install tpm2-tools; it pulls them
# in, and tpm-probe.sh needs it).
#
#   run-hardware-tests.sh                  the full run (default)
#   run-hardware-tests.sh reboot capture   provision a key file and wrap a DEK on the TPM, save
#                                          state, then reboot the machine
#   run-hardware-tests.sh reboot verify    after the reboot: the same storage root key must
#                                          re-derive and the key file unwrap the DEK; then delete
#                                          the saved state
#   run-hardware-tests.sh reboot clean     delete the saved state without verifying
#
# A full run records the host, its installed components and its TPM
# (tpm-probe.sh), then runs, continuing past a failure: every test
# executable's own tests with the TPM reachable; the #[ignore]d
# conformance suite against the TPM; provisioning, pinning the Names the
# TPM reports, and the C ABI round trips under both policies; the CLI ->
# separate C consumer; and, if SoftHSM2 is installed, the pkcs11 suite. It
# ends with a summary and every skip line.
#
# Writes the whole run to hardware-tests-<host>.log next to itself, and
# the TPM's raw capabilities to tpm-capabilities-<host>.txt. Exits 1 if
# any suite failed.
#
# Run it as an ordinary user in the 'tss' group, not root: as root every
# file the tests make is root-owned and every owner-only file readable, so
# the tests proving such files are refused have nothing to refuse and skip.
# --allow-root runs anyway (the summary says so). Over SSH is fine.
#
# Nothing under /etc/hkdfguard or /var/lib/hkdfguard is read or written,
# and the TPM is only asked for transient objects, flushed after use.
#
# Environment (read by this script; the library reads none of them):
#   HKDFGUARD_TCTI                 override the TCTI (default /dev/tpmrm0, else /dev/tpm0)
#   HKDFGUARD_TPM_OWNER_AUTH_FILE  a private file holding the Owner hierarchy's password,
#                                  if it has one (tpm.owner_auth_file in every test policy)
#   HKDFGUARD_HARDWARE_TEST_STATE  where `reboot capture` saves its state (default
#                                  ${XDG_STATE_HOME:-~/.local/state}/hkdfguard-hardware-tests)
#   HKDFGUARD_TEST_TMPDIR          where the temp dir goes (default $XDG_RUNTIME_DIR, else
#                                  ~/.cache); never /tmp, see scripts/native-tpm-test.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)

ALLOW_ROOT=0
ARGS=()
for a in "$@"; do
    case "$a" in
        --allow-root) ALLOW_ROOT=1 ;;
        *) ARGS+=("$a") ;;
    esac
done
MODE="${ARGS[0]:-full}"
PHASE="${ARGS[1]:-}"
HOST=$(hostname -s 2>/dev/null || hostname)
case "$MODE" in
    full) LOG="$HERE/hardware-tests-$HOST.log" ;;
    reboot) LOG="$HERE/hardware-tests-$HOST-reboot-${PHASE:-none}.log" ;;
    *) echo "usage: $0 [--allow-root] [full | reboot capture|verify|clean]" >&2; exit 2 ;;
esac
RAW="$HERE/tpm-capabilities-$HOST.txt"

BIN="$HERE/bin"
LIB="$HERE/lib"
TESTS="$HERE/tests"
C="$HERE/c"
export LD_LIBRARY_PATH="$LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

section() { printf '\n== %s\n' "$1"; }
note()    { printf '   %s\n' "$*"; }

# ---------------------------------------------------------------------
# Setup shared by every mode. Called from main, inside the logged pipe.
# ---------------------------------------------------------------------
setup() {
    echo "== hkdfguard hardware tests on $HOST, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    [ -f "$HERE/MANIFEST" ] && sed 's/^/   bundle: /' "$HERE/MANIFEST"

    [ "$(id -u)" = 0 ] && echo "[WARN] running as root (--allow-root): ownership and permission tests will skip"

    # Every binary must load here: a missing tpm2-tss library, or a glibc
    # older than the one the bundle was built against, shows up now
    # rather than as every suite failing.
    local missing
    missing=$(for f in "$BIN/hkdfguard" "$TESTS"/tpm2/* "$C"/*; do ldd "$f" 2>&1; done | grep -E 'not found' | sort -u)
    if [ -n "$missing" ]; then
        echo "The bundle's binaries cannot load on this host:" >&2
        printf '%s\n' "$missing" | sed 's/^/   /' >&2
        echo "A missing libtss2-*: install tpm2-tools, which pulls in the tpm2-tss runtime libraries." >&2
        echo "A GLIBC_x.y 'not found': this bundle was built on a newer distribution than this one;" >&2
        echo "build one on this distribution (make-bundle.sh) or on an older one." >&2
        return 1
    fi

    TCTI="${HKDFGUARD_TCTI:-}"
    if [ -z "$TCTI" ]; then
        if [ -e /dev/tpmrm0 ]; then TCTI="device:/dev/tpmrm0"; elif [ -e /dev/tpm0 ]; then TCTI="device:/dev/tpm0"; fi
    fi
    export TPM2TOOLS_TCTI="$TCTI" # for tpm2-tools only; the library takes its TCTI from policy
    export HKDFGUARD_TEST_TPM_TCTI="$TCTI" # for the integration tests that write a policy of their own

    SOFTHSM_MODULE=$(find /usr/lib /usr/lib64 /usr/local/lib -iname 'libsofthsm2.so' 2>/dev/null | head -n1 || true)

    # Scratch space: private, never under /tmp (see scripts/native-tpm-test.sh).
    WORK_PARENT=${HKDFGUARD_TEST_TMPDIR:-${XDG_RUNTIME_DIR:-$HOME/.cache}}
    ( umask 077; mkdir -p "$WORK_PARENT" )
    require_private_chain "$WORK_PARENT" HKDFGUARD_TEST_TMPDIR || return 1
    WORK=$(mktemp -d "$WORK_PARENT/hkdfguard-hardware-test.XXXXXX")
    trap 'rm -rf "$WORK"' EXIT
    cd "$WORK" # cargo would run the tests from the package root; anything they leave goes here
    export HKDFGUARD_TEST_TMPDIR="$WORK/test-tmp"
    # cli_round_trip drives this CLI, not the build path compiled into it.
    export HKDFGUARD_TEST_CLI="$BIN/hkdfguard"
    KEY_DIR="$WORK/tpm-keys"
    ( umask 077; mkdir -p "$KEY_DIR" )

    if [ -n "$SOFTHSM_MODULE" ]; then
        export SOFTHSM2_CONF="$WORK/softhsm2.conf"
        mkdir -p "$WORK/tokens"
        printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$WORK/tokens" > "$SOFTHSM2_CONF"
        softhsm2-util --init-token --free --label hkdfguard-test --pin 1234 --so-pin 5678 >/dev/null
        ( umask 077; printf '1234\n' > "$WORK/pkcs11.pin" )
    fi
}

# The library's rule for everything it reads: $1 and every directory above
# it owned by root or this user, and writable by nobody else.
require_private_chain() { # require_private_chain <dir> <what to set instead>
    local d=$1 perm owner
    while :; do
        perm=$(stat -Lc '%a' "$d"); owner=$(stat -Lc '%u' "$d")
        if (( 8#$perm & 8#022 )) || { [ "$owner" != 0 ] && [ "$owner" != "$(id -u)" ]; }; then
            echo "$d is $(stat -Lc '%U:%G %a' "$d"): the library refuses policies, secrets and key files under a directory another user could write to." >&2
            echo "Run 'chmod go-w $d', or set $2 to a private directory." >&2
            return 1
        fi
        [ "$d" != / ] || break
        d=$(dirname "$d")
    done
}

# As scripts/native-tpm-test.sh: a complete policy -- $1 top-level, extra
# [tpm] keys in $2, further tables in $3 -- and making it the one every
# test executable reads.
policy() { # policy <selection...> [extra [tpm] keys] [more tables]
    printf 'security_model = "developer"\n%s\n\n[tpm]\ntcti = "%s"\nkey_dir = "%s"\n' "$1" "$TCTI" "$KEY_DIR"
    [ -n "${HKDFGUARD_TPM_OWNER_AUTH_FILE:-}" ] && printf 'owner_auth_file = "%s"\n' "$HKDFGUARD_TPM_OWNER_AUTH_FILE"
    printf '%s\n' "${2:-}"
    if [ -n "$SOFTHSM_MODULE" ]; then
        printf '\n[pkcs11]\nmodule = "%s"\npin_file = "%s"\ntoken_label = "hkdfguard-test"\n' "$SOFTHSM_MODULE" "$WORK/pkcs11.pin"
    fi
    printf '%s\n' "${3:-}"
}
use_policy() {
    ( umask 077; policy "$@" > "$WORK/policy.toml" )
    export HKDFGUARD_POLICY_FILE="$WORK/policy.toml"
}
use_base_policy() { use_policy $'[selection]\nmode = "prefer"'; }

# One #[ignore]d operator-helper test, and the KEY=value line it prints.
learn() { # learn <test-name> <KEY>
    "$TESTS/tpm2/lib" "provider::tpm2::tests::$1" --ignored --exact --nocapture 2>/dev/null \
        | awk -F= -v k="$2" '$1==k && !found {print $2; found=1}'
}

# ---------------------------------------------------------------------
# Suites: each runs in a subshell, so a failure ends that suite only.
# ---------------------------------------------------------------------
NAMES=()
RESULTS=()
FAILED=0
run_suite() { # run_suite <name> <command...>
    local name=$1 code
    shift
    section "$name"
    ( set -e; "$@" )
    code=$?
    NAMES+=("$name")
    if [ "$code" -eq 0 ]; then
        RESULTS+=("passed")
    else
        RESULTS+=("FAILED (exit $code)")
        FAILED=1
    fi
}
skip_suite() { # skip_suite <name> <why>
    section "$1"
    echo "[SKIP] $1: $2"
    NAMES+=("$1")
    RESULTS+=("skipped ($2)")
}

suite_probe() { "$HERE/tpm-probe.sh" --raw "$RAW"; }

suite_tests() { # suite_tests <executable>: its own (non-ignored) tests, the TPM reachable
    use_base_policy
    HKDFGUARD_TEST_TPM=1 "$1"
}

suite_conformance() {
    use_base_policy
    # The two operator helpers only print; they are not pass/fail.
    "$TESTS/tpm2/lib" --ignored --test-threads=1 \
        --skip print_session_salt_key_name_for_pinning --skip print_service_key_name_for_pinning
}

suite_c_abi() {
    use_base_policy
    section "provisioning com.company.orders, then learning Names to pin (storage root key, and its key file)"
    "$BIN"/hkdfguard provision --service-name com.company.orders
    [ -f "$KEY_DIR/com.company.orders.tpmkey" ] || { echo "provision wrote no key file in $KEY_DIR" >&2; return 1; }
    [ -f "$KEY_DIR/com.company.orders.tpmauth" ] || { echo "provision wrote no authValue file in $KEY_DIR" >&2; return 1; }
    note "key file:       $(stat -c '%n %U:%G %a' "$KEY_DIR/com.company.orders.tpmkey")"
    note "authValue file: $(stat -c '%n %U:%G %a %s bytes' "$KEY_DIR/com.company.orders.tpmauth")"
    local salt_name svc_name
    salt_name=$(learn print_session_salt_key_name_for_pinning SALT_KEY_NAME)
    svc_name=$(HKDFGUARD_PIN_SERVICE=com.company.orders learn print_service_key_name_for_pinning SERVICE_KEY_NAME)
    [ -n "$salt_name" ] && [ -n "$svc_name" ] || { echo "could not learn the Names to pin" >&2; return 1; }
    note "storage root key Name: $salt_name"
    note "service key Name:      $svc_name (com.company.orders)"
    local required_selection=$'[selection]\nmode = "require"\nprovider = "tpm2"'
    local required_tpm_keys="session_encryption = \"on\"
pinned_session_salt_key_name = \"$salt_name\""
    local required_pins="[tpm.pinned_names]
\"com.company.orders\" = \"$svc_name\""

    section "C ABI round trip (wrap_unwrap) -- KEK on the TPM, policy: require tpm2, session_encryption off"
    use_policy "$required_selection" 'session_encryption = "off"'
    "$C/wrap_unwrap"

    section "C ABI round trip -- policy: session_encryption on (the default) with both Names pinned"
    use_policy "$required_selection" "$required_tpm_keys" "$required_pins"
    "$C/wrap_unwrap"
}

suite_cli_to_c() {
    use_base_policy
    local service=com.hkdfguard.hardwaretest.cli
    ( umask 077; head -c 32 /dev/urandom > "$WORK/dek.bin" )
    "$BIN"/hkdfguard provision --service-name "$service"
    base64 -w0 < "$WORK/dek.bin" | "$BIN"/hkdfguard wrap \
        --key-file-path "$WORK/wrapped.key" --service-name "$service" --dek-stdin --force
    "$C/cli_unwrap_check" "$WORK/wrapped.key" "$service" "$WORK/dek.bin"
}

suite_pkcs11() {
    use_base_policy
    "$TESTS/pkcs11/lib" --ignored --test-threads=1
}

full() {
    run_suite probe suite_probe
    MANUFACTURER=$(awk '/TPM2_PT_MANUFACTURER/{f=1} f && /value:/{gsub(/"/,"",$2); print $2; exit}' "$RAW" 2>/dev/null)
    local exe
    for exe in "$TESTS"/tpm2/*; do
        run_suite "tests:$(basename "$exe")" suite_tests "$exe"
    done
    run_suite conformance suite_conformance
    run_suite c_abi suite_c_abi
    run_suite cli_to_c suite_cli_to_c
    if [ -n "$SOFTHSM_MODULE" ]; then
        run_suite pkcs11 suite_pkcs11
    else
        skip_suite pkcs11 "SoftHSM2 not installed"
    fi

    section "Summary: ${MANUFACTURER:-unknown} TPM via $TCTI on $HOST"
    local i
    for i in "${!NAMES[@]}"; do printf '%-28s %s\n' "${NAMES[$i]}" "${RESULTS[$i]}"; done
    [ "$(id -u)" = 0 ] && echo "(run as root: ownership and permission tests skipped)"
    return "$FAILED"
}

# ---------------------------------------------------------------------
# Reboot persistence, as scripts/native-tpm-test.sh reboot
# ---------------------------------------------------------------------
reboot_mode() {
    local state="${HKDFGUARD_HARDWARE_TEST_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/hkdfguard-hardware-tests}"
    local service="com.hkdfguard.hardwaretest.reboot"
    # The key file must be the same before and after: keep the key
    # directory with the rest of the captured state.
    KEY_DIR="$state/tpm-keys"
    use_policy $'[selection]\nmode = "require"\nprovider = "tpm2"'
    local state_files=(dek.bin wrapped.key srk-name.hex "tpm-keys/$service.tpmkey" "tpm-keys/$service.tpmauth")

    remove_state() {
        [ -d "$state" ] || { note "no saved state in $state"; return 0; }
        local f
        for f in "${state_files[@]}"; do
            f="$state/$f"
            [ -f "$f" ] && [ ! -L "$f" ] || continue
            chmod u+w "$f" 2>/dev/null || true
            shred --zero "$f" 2>/dev/null || true
            rm -f "$f"
        done
        note "deleted the saved state files in $state"
        rmdir "$KEY_DIR" 2>/dev/null || true
        rmdir "$state" 2>/dev/null || note "left $state itself in place: it holds files this script did not create"
    }

    case "$PHASE" in
        clean)
            section "reboot clean"
            remove_state
            ;;
        capture)
            section "reboot capture -> $state"
            ( umask 077; mkdir -p "$KEY_DIR" )
            require_private_chain "$state" HKDFGUARD_HARDWARE_TEST_STATE || return 1
            chmod 700 "$state"
            ( umask 077; head -c 32 /dev/urandom > "$state/dek.bin" )
            learn print_session_salt_key_name_for_pinning SALT_KEY_NAME > "$state/srk-name.hex"
            [ -s "$state/srk-name.hex" ] || { echo "could not learn the storage root key's Name" >&2; return 1; }
            "$BIN"/hkdfguard provision --service-name "$service" || return 1
            base64 -w0 < "$state/dek.bin" | "$BIN"/hkdfguard wrap \
                --key-file-path "$state/wrapped.key" --service-name "$service" --dek-stdin --force || return 1
            note "storage root key Name: $(cat "$state/srk-name.hex")"
            note "wrapped DEK saved. Now REBOOT this machine (a full power cycle, for a VM: stop and start it),"
            note "then run: $HERE/run-hardware-tests.sh reboot verify"
            ;;
        verify)
            section "reboot verify <- $state"
            [ -f "$state/wrapped.key" ] || { echo "no captured state in $state; run 'reboot capture' first" >&2; return 1; }
            local before after
            before=$(cat "$state/srk-name.hex")
            after=$(learn print_session_salt_key_name_for_pinning SALT_KEY_NAME)
            if [ "$before" != "$after" ]; then
                echo "FAIL: the storage root key's Name changed across the reboot ($before -> $after): no key file made before it can load" >&2
                return 1
            fi
            note "storage root key Name identical across reboot: $after"
            "$C/cli_unwrap_check" "$state/wrapped.key" "$service" "$state/dek.bin" || return 1
            echo "PASS: the DEK wrapped before the reboot unwraps through the key file loaded on this TPM"
            remove_state
            ;;
        *)
            echo "usage: $0 reboot capture|verify|clean" >&2
            return 2
            ;;
    esac
}

main() {
    setup || return 1
    if [ "$MODE" = reboot ]; then reboot_mode; else full; fi
}

# Before the log is opened, so a refused run leaves an earlier log alone.
if [ "$(id -u)" = 0 ] && [ "$ALLOW_ROOT" -ne 1 ]; then
    echo "Running as root: the tests that prove other users' and owner-only files are refused would skip," >&2
    echo "so this run could not qualify anything. Run as an ordinary user in the 'tss' group" >&2
    echo "(sudo usermod -aG tss <user>, then log in again), or pass --allow-root to run anyway." >&2
    exit 1
fi
if [ ! -f "$HERE/MANIFEST" ] || [ ! -x "$BIN/hkdfguard" ]; then
    echo "$HERE is not an extracted bundle: there are no test binaries to run." >&2
    echo "Build one with scripts/hardware-tests/make-bundle.sh, then run run-hardware-tests.sh from" >&2
    echo "the extracted hkdfguard-hardware-tests/ folder, or use scripts/native-tpm-test.sh to build and test from source." >&2
    exit 1
fi

main 2>&1 | tee "$LOG"
status=${PIPESTATUS[0]}
# Every skip line, from the whole log (the tests print SKIP: or skipping:).
# A TPM skip means the TPM path never ran, whatever the summary says.
skips=$(grep -E '\[SKIP\]|^SKIP:|skipping' "$LOG" | sort -u)
if [ -n "$skips" ]; then
    { echo; echo "Skipped checks (any TPM one means the TPM was not qualified):"; printf '%s\n' "$skips" | sed 's/^/  /'; } | tee -a "$LOG"
fi
echo "Log written to $LOG"
exit "$status"

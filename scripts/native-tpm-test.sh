#!/usr/bin/env bash
# Full hkdfguard test matrix on a native Linux machine with a real TPM
# (Intel PTT, AMD fTPM, or a discrete chip) -- the same sections as
# docker/entrypoint-test.sh, but against the hardware you will deploy on
# instead of swtpm, plus the things only real hardware can prove.
#
#   scripts/native-tpm-test.sh                 full matrix (default)
#   scripts/native-tpm-test.sh reboot capture  provision a key file and wrap a DEK on the TPM, save state,
#                                              then reboot the machine
#   scripts/native-tpm-test.sh reboot verify   after the reboot: the same storage root key must re-derive,
#                                              the key file must load and unwrap the DEK; then delete the
#                                              saved state
#   scripts/native-tpm-test.sh reboot clean    delete the saved state without verifying
#
# What it does, in order:
#   1. Preflight (scripts/native-tpm-preflight.sh).
#   2. Build with --features tpm2 (and pkcs11 if SoftHSM2 is installed).
#   3. Unit tests for the tpm2 feature (no device needed).
#   4. The #[ignore]d conformance suite against the REAL TPM: key files
#      created, reloaded and refused when spliced, the storage root key's
#      determinism, the Name formula, TPM2_HMAC known answers,
#      salted/encrypted session correctness, the authValue refusing a wrong
#      or empty value, pins, and retiring. Each test uses its own key directory.
#   5. Provisions com.company.orders with the CLI, then learns the storage
#      root key's and that key file's Names (the operator helpers in
#      src/provider/tpm2.rs) and writes a policy with both Names pinned.
#   6. C ABI round trip (examples/wrap_unwrap.c) against the .so
#      with the KEK on the TPM -- once with session encryption off, once
#      under that pinned policy with it on.
#   7. CLI -> separate C consumer: hkdfguard wraps via stdin,
#      cli_unwrap_check unwraps through the .so. Cross-process persistence
#      on the real TPM.
#   8. If SoftHSM2 is present: the pkcs11 conformance suite.
#
# Everything is configured the way production is -- by a policy file --
# except that the file lives in this script's temp dir. A library only reads
# a policy other than /etc/hkdfguard/policy.toml when built with
# `--cfg hkdfguard_test_paths`, so everything here (tests, the .so, and the
# CLI the C examples use) is built that way, into its own target directory
# (target/test-paths) so it never mixes with an ordinary build. Nothing that
# ships is ever built with that flag.
#
# Nothing under /etc/hkdfguard or /var/lib/hkdfguard is read or written,
# and the TPM is only ever asked for transient objects (flushed after use),
# so nothing is left on the TPM. A full run keeps every policy, key file
# and secret in a temp dir it removes on exit. `reboot` cannot: what it
# captures must survive the reboot, so `reboot capture` saves a TPM key
# file, a plaintext test DEK, and its wrapped copy in the state dir (below)
# -- together enough to use that test service's key on this TPM. `reboot
# verify` deletes them once it passes (it keeps them on failure, so it can
# be rerun), and `reboot clean` deletes them without verifying.
#
# Options (read by this script; the library reads none of them):
#   HKDFGUARD_TCTI               override the TCTI (default from preflight)
#   HKDFGUARD_NATIVE_TEST_STATE  where `reboot capture` saves its state
#                                (default: ${XDG_STATE_HOME:-~/.local/state}/hkdfguard-native-tpm-test)
#   HKDFGUARD_TEST_TMPDIR        where the temp dir goes (default:
#                                $XDG_RUNTIME_DIR, else ~/.cache). Never /tmp:
#                                the library refuses policies, secrets and
#                                key files under a sticky, world-writable
#                                directory, so it and every directory above
#                                it must be private.
set -euo pipefail
cd "$(dirname "$0")/.."

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }
note()    { printf '   \033[2m%s\033[0m\n' "$*"; }

MODE="${1:-full}"
PHASE="${2:-}"

# ---------------------------------------------------------------------
# Preflight, shared setup
# ---------------------------------------------------------------------
section "preflight"
# shellcheck source=scripts/native-tpm-preflight.sh
source scripts/native-tpm-preflight.sh
TCTI="${HKDFGUARD_TCTI:-$HKDFGUARD_PREFLIGHT_TCTI}"
export TPM2TOOLS_TCTI="$TCTI" # for tpm2-tools only; the library takes its TCTI from policy
export HKDFGUARD_TEST_TPM_TCTI="$TCTI" # for the integration tests that write a policy of their own
MANUFACTURER="$HKDFGUARD_PREFLIGHT_MANUFACTURER"

FEATURES="tpm2"
HAVE_SOFTHSM=0
# Tested on the substitution's *output*, not its exit status: under
# pipefail, `head` closing the pipe early makes `find` report failure
# even when it found the module.
SOFTHSM_MODULE=$(find /usr/lib /usr/lib64 /usr/local/lib -iname 'libsofthsm2.so' 2>/dev/null | head -n1 || true)
if [ -n "$SOFTHSM_MODULE" ]; then
    FEATURES="tpm2,pkcs11"
    HAVE_SOFTHSM=1
fi

# Fails, naming the directory, unless $1 and every directory above it is
# owned by root or this user and writable by nobody else -- sticky ones
# (/tmp) included: the rule the library applies to everything it reads --
# policies, derivation secrets, PIN files and key files, which this script
# writes into $WORK and $STATE -- the TPM key directory among them.
require_private_chain() { # require_private_chain <dir> <what to set instead>
    local d=$1 perm owner
    while :; do
        perm=$(stat -Lc '%a' "$d"); owner=$(stat -Lc '%u' "$d")
        if (( 8#$perm & 8#022 )) || { [ "$owner" != 0 ] && [ "$owner" != "$(id -u)" ]; }; then
            echo "$d is $(stat -Lc '%U:%G %a' "$d"): the library refuses policies, secrets and key files under a directory another user could write to (sticky ones like /tmp included)." >&2
            echo "Run 'chmod go-w $d', or set $2 to a private directory." >&2
            exit 1
        fi
        [ "$d" != / ] || break
        d=$(dirname "$d")
    done
}

# Scratch space for policies, secrets and key files: never under /tmp,
# where the library refuses all of them. $XDG_RUNTIME_DIR (/run/user/<uid>,
# 0700) where there is one, else ~/.cache. The cargo tests' own temp root
# goes inside it too (HKDFGUARD_TEST_TMPDIR).
WORK_PARENT=${HKDFGUARD_TEST_TMPDIR:-${XDG_RUNTIME_DIR:-$HOME/.cache}}
( umask 077; mkdir -p "$WORK_PARENT" )
require_private_chain "$WORK_PARENT" HKDFGUARD_TEST_TMPDIR
WORK=$(mktemp -d "$WORK_PARENT/hkdfguard-native-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
export HKDFGUARD_TEST_TMPDIR="$WORK/cargo-tests"

# Test builds only, in their own target dir; see the note at the top.
export RUSTFLAGS="--cfg hkdfguard_test_paths"
export CARGO_TARGET_DIR="$PWD/target/test-paths"
BIN="$CARGO_TARGET_DIR/debug"

# The TPM key directory: a throwaway one for a full run; `reboot` keeps
# its own in the state dir (below) so the key file survives the reboot.
KEY_DIR="$WORK/tpm-keys"
( umask 077; mkdir -p "$KEY_DIR" )

# SoftHSM2, if present: a throwaway token, named in every policy below so
# the pkcs11 tests can reach it. Same label and PINs as
# docker/entrypoint-test.sh; the tests select it by label
# (SOFTHSM_TEST_TOKEN_LABEL in src/provider/pkcs11.rs).
if [ "$HAVE_SOFTHSM" -eq 1 ]; then
    export SOFTHSM2_CONF="$WORK/softhsm2.conf"
    mkdir -p "$WORK/tokens"
    printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$WORK/tokens" > "$SOFTHSM2_CONF"
    softhsm2-util --init-token --free --label hkdfguard-test --pin 1234 --so-pin 5678 >/dev/null
    ( umask 077; printf '1234\n' > "$WORK/pkcs11.pin" )
fi

# Prints a complete policy: the developer security model (this script
# provisions and wraps as whoever runs it), $1 (the [selection] table and
# anything else top-level), this machine's TPM settings plus any extra
# [tpm] keys in $2, the SoftHSM2 token if there is one, then any further
# tables in $3.
policy() { # policy <selection...> [extra [tpm] keys] [more tables]
    printf 'security_model = "developer"\n%s\n\n[tpm]\ntcti = "%s"\nkey_dir = "%s"\n%s\n' "$1" "$TCTI" "$KEY_DIR" "${2:-}"
    if [ "$HAVE_SOFTHSM" -eq 1 ]; then
        printf '\n[pkcs11]\nmodule = "%s"\npin_file = "%s"\ntoken_label = "hkdfguard-test"\n' "$SOFTHSM_MODULE" "$WORK/pkcs11.pin"
    fi
    printf '%s\n' "${3:-}"
}

# Makes `policy "$@"` the policy file every test build reads (tests layer
# their own policies over it). Owner-only, as the library requires.
use_policy() {
    ( umask 077; policy "$@" > "$WORK/policy.toml" )
    export HKDFGUARD_POLICY_FILE="$WORK/policy.toml"
}
# Selects as having no policy file would: the default order, no Ephemeral.
use_base_policy() { use_policy $'[selection]\nmode = "prefer"'; }

# Runs one #[ignore]d operator-helper test and extracts a KEY=value line.
# `--exact` matches the *full* test path, so it is spelled out here.
learn() { # learn <test-name> <KEY>
    # awk reads to the end rather than exiting at the match: the test
    # binary is still writing its summary, a closed pipe makes that write
    # panic (exit 101), and pipefail turns that into a failed run.
    cargo test --features tpm2 --lib "provider::tpm2::tests::$1" -- --ignored --exact --nocapture 2>/dev/null \
        | awk -F= -v k="$2" '$1==k && !found {print $2; found=1}'
}

# Builds a C example against the library.
build_c() { # build_c <source.c> <out>
    # The .so's SONAME (build.rs), which the program looks for at run time.
    ln -sf libhkdfguard.so "$BIN/libhkdfguard.so.1"
    cc -I include "$1" -L "$BIN" -lhkdfguard -o "$2"
}

# ---------------------------------------------------------------------
# Reboot persistence: the one thing swtpm can only approximate
# ---------------------------------------------------------------------
if [ "$MODE" = "reboot" ]; then
    STATE="${HKDFGUARD_NATIVE_TEST_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/hkdfguard-native-tpm-test}"
    SERVICE="com.hkdfguard.nativetest.reboot"
    # The key file must be the same before and after the reboot: keep the
    # key directory with the rest of the captured state.
    KEY_DIR="$STATE/tpm-keys"
    use_policy $'[selection]\nmode = "require"\nprovider = "tpm2"'

    # Deletes exactly the files capture writes -- never anything else in
    # the state dir, which HKDFGUARD_NATIVE_TEST_STATE may point anywhere
    # -- then the dirs themselves if that left them empty.
    STATE_FILES=(dek.bin wrapped.key srk-name.hex "tpm-keys/$SERVICE.tpmkey")
    remove_state() {
        [ -d "$STATE" ] || { note "no saved state in $STATE"; return 0; }
        local f
        for f in "${STATE_FILES[@]}"; do
            f="$STATE/$f"
            [ -f "$f" ] && [ ! -L "$f" ] || continue
            # Best effort: overwriting in place means little on SSDs and
            # copy-on-write filesystems, but costs nothing elsewhere. The
            # key file is read-only, so make it writable first.
            chmod u+w "$f" 2>/dev/null || true
            shred --zero "$f" 2>/dev/null || true
            rm -f "$f"
        done
        note "deleted the saved state files in $STATE"
        rmdir "$KEY_DIR" 2>/dev/null || true
        rmdir "$STATE" 2>/dev/null || note "left $STATE itself in place: it holds files this script did not create"
    }

    if [ "$PHASE" = "clean" ]; then
        section "reboot clean"
        remove_state
        exit 0
    fi

    # The key file and the wrapped key live in $STATE, and the library
    # refuses either under any directory another user could write to, even
    # a sticky one (/tmp). Under a umask of 002 (Ubuntu's default) `mkdir
    # -p` would create such parents itself, so create them private, and
    # name an existing open one instead of letting the run fail obscurely.
    ( umask 077; mkdir -p "$KEY_DIR" )
    require_private_chain "$STATE" HKDFGUARD_NATIVE_TEST_STATE

    section "build (--features tpm2)"
    cargo build --features tpm2
    build_c examples/cli_unwrap_check.c "$WORK/cli_unwrap_check"

    case "$PHASE" in
        capture)
            section "reboot capture -> $STATE"
            chmod 700 "$STATE"
            ( umask 077; head -c 32 /dev/urandom > "$STATE/dek.bin" )
            learn print_session_salt_key_name_for_pinning SALT_KEY_NAME > "$STATE/srk-name.hex"
            [ -s "$STATE/srk-name.hex" ] || { echo "could not learn the storage root key's Name" >&2; exit 1; }
            "$BIN"/hkdfguard provision --service-name "$SERVICE"
            base64 -w0 < "$STATE/dek.bin" | "$BIN"/hkdfguard wrap \
                --key-file-path "$STATE/wrapped.key" --service-name "$SERVICE" --dek-stdin --force
            note "storage root key Name: $(cat "$STATE/srk-name.hex")"
            note "wrapped DEK saved. Now REBOOT this machine, then run: scripts/native-tpm-test.sh reboot verify"
            note "this state stays in $STATE until 'reboot verify' passes or you run 'reboot clean'"
            exit 0
            ;;
        verify)
            section "reboot verify <- $STATE"
            [ -f "$STATE/wrapped.key" ] || { echo "no captured state in $STATE; run 'reboot capture' first" >&2; exit 1; }
            before=$(cat "$STATE/srk-name.hex")
            after=$(learn print_session_salt_key_name_for_pinning SALT_KEY_NAME)
            if [ "$before" != "$after" ]; then
                echo "FAIL: the storage root key's Name changed across the reboot ($before -> $after): no key file made before it can load" >&2
                exit 1
            fi
            note "storage root key Name identical across reboot: $after"
            LD_LIBRARY_PATH="$BIN" "$WORK/cli_unwrap_check" "$STATE/wrapped.key" "$SERVICE" "$STATE/dek.bin"
            echo "PASS: the DEK wrapped before the reboot unwraps through the key file loaded on this TPM"
            remove_state
            exit 0
            ;;
        *)
            echo "usage: $0 reboot capture|verify|clean" >&2; exit 2
            ;;
    esac
fi

[ "$MODE" = "full" ] || { echo "usage: $0 [full | reboot capture|verify|clean]" >&2; exit 2; }

# ---------------------------------------------------------------------
# 2-3. Build + unit tests
# ---------------------------------------------------------------------
use_base_policy

section "cargo build --features $FEATURES (real link against libtss2-esys${HAVE_SOFTHSM:+ + cryptoki})"
cargo build --features "$FEATURES"

section "cargo test --features tpm2 (unit tests: key files, authValue files, templates, Name computation)"
# HKDFGUARD_TEST_TPM: the integration tests that need a reachable TPM run too.
HKDFGUARD_TEST_TPM=1 cargo test --features tpm2

# ---------------------------------------------------------------------
# 4. Conformance suite against the real TPM
# ---------------------------------------------------------------------
# The two operator helpers only print; keep them out of the pass/fail run.
SKIP=(--skip print_session_salt_key_name_for_pinning --skip print_service_key_name_for_pinning)

section "cargo test --features tpm2 -- --ignored (conformance suite against the real TPM: $TCTI)"
cargo test --features tpm2 -- --ignored --test-threads=1 "${SKIP[@]}"

# ---------------------------------------------------------------------
# 5. Provision, learn pins from the TPM, write a `required` policy
# ---------------------------------------------------------------------
section "cargo build --features tpm2 (the .so and CLI the C examples load)"
cargo build --features tpm2
build_c examples/wrap_unwrap.c "$WORK/wrap_unwrap"
build_c examples/cli_unwrap_check.c "$WORK/cli_unwrap_check"

section "provisioning com.company.orders, then learning Names to pin (storage root key, and its key file)"
"$BIN"/hkdfguard provision --service-name com.company.orders
[ -f "$KEY_DIR/com.company.orders.tpmkey" ] || { echo "provision wrote no key file in $KEY_DIR" >&2; exit 1; }
[ -f "$KEY_DIR/com.company.orders.tpmauth" ] || { echo "provision wrote no authValue file in $KEY_DIR" >&2; exit 1; }
note "key file:       $(stat -c '%n %U:%G %a' "$KEY_DIR/com.company.orders.tpmkey")"
note "authValue file: $(stat -c '%n %U:%G %a %s bytes' "$KEY_DIR/com.company.orders.tpmauth")"
SALT_NAME=$(learn print_session_salt_key_name_for_pinning SALT_KEY_NAME)
SVC_NAME=$(HKDFGUARD_PIN_SERVICE=com.company.orders learn print_service_key_name_for_pinning SERVICE_KEY_NAME)
[ -n "$SALT_NAME" ] && [ -n "$SVC_NAME" ] || { echo "could not learn the Names to pin" >&2; exit 1; }
note "storage root key Name: $SALT_NAME"
note "service key Name:      $SVC_NAME (com.company.orders)"
REQUIRED_SELECTION=$'[selection]\nmode = "require"\nprovider = "tpm2"'
REQUIRED_TPM_KEYS="session_encryption = \"on\"
pinned_session_salt_key_name = \"$SALT_NAME\""
REQUIRED_PINS="[tpm.pinned_names]
\"com.company.orders\" = \"$SVC_NAME\""
note "with this machine's real key directory in place of the scratch one, this is what a"
note "hardened deployment on THIS machine would install at /etc/hkdfguard/policy.toml:"
policy "$REQUIRED_SELECTION" "$REQUIRED_TPM_KEYS" "$REQUIRED_PINS" | sed 's/^/     /'

# ---------------------------------------------------------------------
# 6. C ABI round trip on the TPM, under both policies
# ---------------------------------------------------------------------
section "C ABI round trip (examples/wrap_unwrap.c) -- KEK on the TPM, policy: require tpm2, session_encryption off"
use_policy $'[selection]\nmode = "require"\nprovider = "tpm2"' 'session_encryption = "off"'
LD_LIBRARY_PATH="$BIN" "$WORK/wrap_unwrap"

section "C ABI round trip -- policy: session_encryption on (the default) with both Names pinned"
use_policy "$REQUIRED_SELECTION" "$REQUIRED_TPM_KEYS" "$REQUIRED_PINS"
LD_LIBRARY_PATH="$BIN" "$WORK/wrap_unwrap"
note "every TPM2_HMAC in that run went through a salted, AES-128-CFB-encrypted session keyed by the key's authValue, under a pinned storage root key"

# ---------------------------------------------------------------------
# 7. CLI -> separate C consumer, across processes, on the TPM
# ---------------------------------------------------------------------
section "hkdfguard (stdin) -> cli_unwrap_check via the .so, KEK on the TPM"
use_base_policy
CLI_SERVICE=com.hkdfguard.nativetest.cli
( umask 077; head -c 32 /dev/urandom > "$WORK/dek.bin" )
"$BIN"/hkdfguard provision --service-name "$CLI_SERVICE"
base64 -w0 < "$WORK/dek.bin" | "$BIN"/hkdfguard wrap \
    --key-file-path "$WORK/wrapped.key" --service-name "$CLI_SERVICE" --dek-stdin --force
LD_LIBRARY_PATH="$BIN" "$WORK/cli_unwrap_check" "$WORK/wrapped.key" "$CLI_SERVICE" "$WORK/dek.bin"

# ---------------------------------------------------------------------
# 8. Optional PKCS#11
# ---------------------------------------------------------------------
if [ "$HAVE_SOFTHSM" -eq 1 ]; then
    section "cargo test --features pkcs11 -- --ignored (against the SoftHSM2 token in the policy)"
    cargo test --features pkcs11 -- --ignored --test-threads=1
else
    section "pkcs11 suite skipped (SoftHSM2 not installed)"
fi

section "ALL NATIVE CHECKS PASSED on $MANUFACTURER via $TCTI"
echo "To also prove persistence across a real reboot:"
echo "  scripts/native-tpm-test.sh reboot capture   # then reboot"
echo "  scripts/native-tpm-test.sh reboot verify"

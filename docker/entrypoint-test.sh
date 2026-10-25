#!/usr/bin/env bash
# Runs the full HKDFGuard test matrix inside the container built from
# docker/Dockerfile: default-feature unit tests, a real link against
# tpm2-tss + a swtpm-backed TPM2 hardware test, and a real link against
# SoftHSM2 + a PKCS#11 hardware test. See docker/README.md.
#
# The container starts as root, but only to do what a deployment's root
# would: install root-owned configuration under /etc/hkdfguard and start
# swtpm. Every build, test, and library/CLI run happens as `ci`, an
# unprivileged user in the `tss` group (docker/Dockerfile) -- so the
# library's ownership checks really are exercised, and the tests that
# refuse non-root config fail rather than skip if this ever runs them as
# root (HKDFGUARD_TESTS_MUST_NOT_RUN_AS_ROOT).
set -euo pipefail

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "entrypoint-test.sh starts as root and drops to ci itself" >&2; exit 1; }
# Runs a command as `ci`, keeping this script's environment. setpriv
# changes uid, so all capabilities are dropped too.
as_ci() { setpriv --reuid=ci --regid=ci --init-groups env HOME=/home/ci USER=ci LOGNAME=ci "$@"; }
# Creates an empty owner-only file belonging to `ci` (a secret, a DEK);
# writing into it afterwards, as root, keeps that owner and mode.
ci_file() { install -o ci -g ci -m 0600 /dev/null "$1"; }
# Writes stdin into a file `ci` owns, as ci. Root can't if the file is in
# a sticky directory such as /tmp: with fs.protected_regular=2 (a host
# kernel setting, which containers share) even root may not open another
# user's file there.
ci_write() { as_ci sh -c 'cat > "$1"' sh "$1"; }
# Key files (and the DEKs cli_unwrap_check probes with hkdfguard_open_file)
# live here, and so do the harness's policies, secrets and PIN files --
# never under /tmp: the library refuses anything it reads anywhere under a
# sticky, world-writable directory, and the CLI refuses to write a key file
# or read a --dek-file there. /work is ci's own (docker/Dockerfile) and /
# is root's, both 0755, so a 0700 directory in it passes all the way up.
KEYS=$(as_ci mktemp -d /work/keys.XXXXXX)

section "cargo build (default features: external-secret, ephemeral)"
as_ci cargo build

section "cargo test (default features, as ci; tests that need their own policy are ignored without --cfg hkdfguard_test_paths)"
as_ci cargo test

# Everything below that steers the library at scratch files does it the way
# production does -- with a policy file -- in builds made with
# `--cfg hkdfguard_test_paths`, the only builds that read a policy other
# than /etc/hkdfguard/policy.toml. They go in their own target dir, so they
# never mix with the release and plain builds checked further down.
test_cargo() { as_ci env RUSTFLAGS="--cfg hkdfguard_test_paths" CARGO_TARGET_DIR=target/test-paths cargo "$@"; }
TEST_BIN=target/test-paths/debug

section "cargo build --features tpm2,pkcs11 (real link against libtss2-esys + cryptoki)"
as_ci cargo build --features tpm2,pkcs11
echo "Linked successfully against real tpm2-tss and PKCS#11 (loader) libraries."

section "starting swtpm (software TPM2 simulator)"
TPM_STATE_DIR=$(mktemp -d /root/swtpm-state.XXXXXX) # swtpm's own state, root's, not under /tmp either
swtpm socket \
    --tpmstate dir="$TPM_STATE_DIR" \
    --tpm2 \
    --server type=tcp,port=2321 \
    --ctrl type=tcp,port=2322 \
    --flags not-need-init &
SWTPM_PID=$!
trap 'kill "$SWTPM_PID" 2>/dev/null || true' EXIT
sleep 1

SWTPM_TCTI="swtpm:host=127.0.0.1,port=2321"
export TPM2TOOLS_TCTI="$SWTPM_TCTI" # tpm2-tools only; the library takes its TCTI from policy
tpm2_startup -c -T "$SWTPM_TCTI"
echo "swtpm is up and started (TCTI=$SWTPM_TCTI)."

section "initializing a SoftHSM2 token"
SOFTHSM_MODULE=$(find /usr/lib -iname "libsofthsm2.so" 2>/dev/null | head -n1)
if [ -z "$SOFTHSM_MODULE" ]; then
    echo "libsofthsm2.so not found" >&2
    exit 1
fi
# Same label and PINs as scripts/native-tpm-test.sh; the pkcs11 tests select
# this token by label (SOFTHSM_TEST_TOKEN_LABEL in src/provider/pkcs11.rs).
# The token store is ci's own (SOFTHSM2_CONF, docker/Dockerfile).
as_ci softhsm2-util --init-token --free --label hkdfguard-test --pin 1234 --so-pin 5678
echo "SoftHSM2 token ready (module=$SOFTHSM_MODULE)."

# The harness policy every test build reads: the default selection, plus
# this container's machine facts -- swtpm, a scratch derivation secret (the
# TPM provider requires one by default), and the SoftHSM2 token with an
# owner-only PIN file. Tests layer their own policies over it. All of it
# belongs to ci: a test build accepts config owned by the user running it.
HARNESS=$(as_ci mktemp -d /work/harness.XXXXXX)
( umask 077; head -c 32 /dev/urandom > "$HARNESS/tpm.derivation-secret" )
( umask 077; printf '1234\n' > "$HARNESS/pkcs11.pin" )
cat > "$HARNESS/policy.toml" <<TOML
[selection]
mode = "prefer"

[tpm]
tcti = "$SWTPM_TCTI"
derivation_secret_file = "$HARNESS/tpm.derivation-secret"

[pkcs11]
module = "$SOFTHSM_MODULE"
pin_file = "$HARNESS/pkcs11.pin"
token_label = "hkdfguard-test"
TOML
chmod 0644 "$HARNESS/policy.toml"
chown -R ci:ci "$HARNESS"
export HKDFGUARD_POLICY_FILE="$HARNESS/policy.toml"

section "cargo test --features tpm2 (test build: unit tests, plus the CLI and integration tests that need their own policy)"
test_cargo test --features tpm2

section "cargo test --features tpm2 -- --ignored (against swtpm)"
test_cargo test --features tpm2 -- --ignored --test-threads=1

section "cargo test --features pkcs11 -- --ignored (against SoftHSM2)"
test_cargo test --features pkcs11 -- --ignored --test-threads=1

unset HKDFGUARD_POLICY_FILE TPM2TOOLS_TCTI

section "C ABI round trip via examples/wrap_unwrap.c (default providers)"
# With no policy file, Ephemeral is never used, so the example needs a
# real KEK: provision an external secret for its service, as a
# deployment platform would, in a standard secret mount.
# The mount is root's, as a platform's would be; the KEK file belongs to
# the service user, owner-only, as the provider requires.
SECRET_MOUNT=/run/secrets/hkdfguard
mkdir -p "$SECRET_MOUNT"
ci_file "$SECRET_MOUNT/com.company.orders"; head -c 32 /dev/urandom > "$SECRET_MOUNT/com.company.orders"
as_ci cargo build --release
# The .so's SONAME is libhkdfguard.so.1 (build.rs): what programs linked
# against it look for at run time.
as_ci ln -sf libhkdfguard.so target/release/libhkdfguard.so.1
as_ci cc -I include examples/wrap_unwrap.c -L target/release -lhkdfguard -o /tmp/wrap_unwrap
as_ci env LD_LIBRARY_PATH=target/release /tmp/wrap_unwrap

section "hkdfguard CLI output unwraps via libhkdfguard.so"
# The CLI links this crate's Rust code statically (an rlib), so this proves
# the wrapped payload it writes is genuinely consumer-independent -- a
# *different*, dynamically-linked consumer (this C program, against the
# release .so) can unwrap it too, not just the CLI's own process image.
#
# There is no software-backed provider on this platform, so the shared,
# cross-process-persistent KEK both processes need here comes from
# external-secret: a secret file is provisioned into a shared directory
# before either process runs, exactly as a real deployment platform
# (Vault Agent, a Kubernetes Secret, ...) would have already done.
CLISO_SERVICE=com.hkdfguard.dockertest.cliso
ci_file "$SECRET_MOUNT/$CLISO_SERVICE"; head -c 32 /dev/urandom > "$SECRET_MOUNT/$CLISO_SERVICE"

DEK_FILE=$(as_ci mktemp -p "$KEYS")
head -c 32 /dev/urandom | ci_write "$DEK_FILE"
WRAPPED_FILE=$(as_ci mktemp -p "$KEYS")

# `provision` is the only command that makes the (deliberately slow) setup
# calls. For external-secret the mounted file *is* the provisioning, so
# this reports "already provisioned" -- and must still exit 0.
as_ci target/release/hkdfguard provision --service-name "$CLISO_SERVICE"

# The DEK goes in on stdin, never on the command line: argv is readable by
# any process of the same user through /proc/<pid>/cmdline. `printf` is a
# shell builtin, so the base64 never becomes a child process's argv either.
# This is also the invocation a real deployment pipeline should use.
DEK_B64=$(base64 -w0 < "$DEK_FILE")
printf '%s' "$DEK_B64" | as_ci target/release/hkdfguard wrap \
    --key-file-path "$WRAPPED_FILE" \
    --service-name "$CLISO_SERVICE" \
    --dek-stdin \
    --force
unset DEK_B64

as_ci cc -I include examples/cli_unwrap_check.c -L target/release -lhkdfguard -o /tmp/cli_unwrap_check
as_ci env LD_LIBRARY_PATH=target/release /tmp/cli_unwrap_check "$WRAPPED_FILE" "$CLISO_SERVICE" "$DEK_FILE"

# And the --dek-file path, which is what a secret mount or a systemd
# credential provides. Mode 0600 or the CLI refuses it.
WRAPPED_FILE2=$(as_ci mktemp -p "$KEYS")
DEK_B64_FILE=$(as_ci mktemp -p "$KEYS")
base64 -w0 < "$DEK_FILE" | ci_write "$DEK_B64_FILE"
as_ci target/release/hkdfguard wrap \
    --key-file-path "$WRAPPED_FILE2" \
    --service-name "$CLISO_SERVICE" \
    --dek-file "$DEK_B64_FILE" \
    --force
as_ci env LD_LIBRARY_PATH=target/release /tmp/cli_unwrap_check "$WRAPPED_FILE2" "$CLISO_SERVICE" "$DEK_FILE"

# `wrap` never provisions: with nothing mounted for this service it must
# fail and point at `provision`, rather than quietly creating a KEK.
UNPROVISIONED_OUT="$KEYS/unprovisioned.key"
if printf '%s' "$(base64 -w0 < "$DEK_FILE")" | as_ci target/release/hkdfguard wrap \
        --key-file-path "$UNPROVISIONED_OUT" --service-name com.hkdfguard.dockertest.unprovisioned --dek-stdin 2>/tmp/unprov.err; then
    echo "FAIL: wrap succeeded for a service with no provisioned KEK" >&2
    exit 1
fi
grep -q 'provision --service-name com.hkdfguard.dockertest.unprovisioned' /tmp/unprov.err \
    || { echo "FAIL: wrap's error did not point at the provision command:" >&2; cat /tmp/unprov.err >&2; exit 1; }
[ ! -e "$UNPROVISIONED_OUT" ] || { echo "FAIL: a failed wrap wrote an output file" >&2; exit 1; }
echo "--dek correctly rejected; unprovisioned wrap correctly refused; stdin and --dek-file both round-tripped."

# A key file under /tmp -- even in a private mktemp -d directory there --
# is refused: by the CLI before it reads the DEK, and by the library when
# one is put there anyway.
TMP_KEYS=$(as_ci mktemp -d)
if printf '%s' "$(base64 -w0 < "$DEK_FILE")" | as_ci target/release/hkdfguard wrap         --key-file-path "$TMP_KEYS/wrapped.key" --service-name "$CLISO_SERVICE" --dek-stdin 2>"$KEYS/tmp.err"; then
    echo "FAIL: wrap wrote a key file under /tmp" >&2; exit 1
fi
grep -q 'sticky, like /tmp' "$KEYS/tmp.err" && grep -q 'the library would refuse to read a key file' "$KEYS/tmp.err"     || { echo "FAIL: unexpected refusal for a key file under /tmp:" >&2; cat "$KEYS/tmp.err" >&2; exit 1; }
[ ! -e "$TMP_KEYS/wrapped.key" ] || { echo "FAIL: a refused wrap wrote a key file under /tmp" >&2; exit 1; }
as_ci cp "$WRAPPED_FILE" "$TMP_KEYS/wrapped.key"
if as_ci env LD_LIBRARY_PATH=target/release /tmp/cli_unwrap_check "$TMP_KEYS/wrapped.key" "$CLISO_SERVICE" "$DEK_FILE" 2>"$KEYS/tmp.err"; then
    echo "FAIL: hkdfguard_open_file accepted a key file under /tmp" >&2; exit 1
fi
grep -q -- '-39' "$KEYS/tmp.err" || { echo "FAIL: expected HKDFGUARD_ERR_FILE_UNTRUSTED (-39):" >&2; cat "$KEYS/tmp.err" >&2; exit 1; }
rm -rf "$TMP_KEYS"
echo "a key file under /tmp: wrap refuses to write it, hkdfguard_open_file refuses to read it (-39)."

# A --dek-file under /tmp -- owner-only, in ci's own 0700 directory there --
# is refused too, before it is read: the library's rule for what it reads.
TMP_DEK=$(as_ci mktemp -d)
as_ci sh -c "umask 077; base64 -w0 < '$DEK_FILE' > '$TMP_DEK/dek.b64'"
if as_ci target/release/hkdfguard wrap --key-file-path "$KEYS/tmpdek.key" --service-name "$CLISO_SERVICE" \
        --dek-file "$TMP_DEK/dek.b64" 2>"$KEYS/tmp.err"; then
    echo "FAIL: wrap read a --dek-file under /tmp" >&2; exit 1
fi
grep -q -- "--dek-file $TMP_DEK/dek.b64: folder /tmp is writable by group or others (mode 1777) (sticky, like /tmp" "$KEYS/tmp.err" \
    || { echo "FAIL: unexpected refusal for a --dek-file under /tmp:" >&2; cat "$KEYS/tmp.err" >&2; exit 1; }
[ ! -e "$KEYS/tmpdek.key" ] || { echo "FAIL: a refused wrap wrote a key file" >&2; exit 1; }
rm -rf "$TMP_DEK"
echo "a --dek-file under /tmp: wrap refuses to read it."

rm -f "$DEK_FILE" "$WRAPPED_FILE" "$WRAPPED_FILE2" "$DEK_B64_FILE"
rm -rf "$SECRET_MOUNT"

section "builds that ship take configuration only from /etc/hkdfguard/policy.toml"
# Release builds, and plain debug builds -- anything not made with
# `--cfg hkdfguard_test_paths` -- must take every security setting from the
# root-owned policy, never the environment. Install a real policy reaching
# swtpm through `tpm.tcti`, then set HKDFGUARD_POLICY_FILE and environment
# variables naming a TCTI, derivation secret, secret mount and PKCS#11
# module to values that would break anything that read them. Both shipped-style builds must ignore them and work; the
# test build's CLI, as a control, must follow HKDFGUARD_POLICY_FILE to the
# malformed policy and fail -- proving this check would catch a build that
# honored it.
#
# The configuration is installed the way a deployment installs it for a
# non-root service: root-owned, with the derivation secret root:ci 0440.
as_ci cargo build --release --features tpm2,pkcs11
as_ci cargo build --features tpm2,pkcs11      # plain debug: must behave like release here
test_cargo build --features tpm2,pkcs11       # the control
mkdir -p /etc/hkdfguard
install -o root -g ci -m 0440 /dev/null /etc/hkdfguard/tpm.derivation-secret  # required by default
head -c 32 /dev/urandom > /etc/hkdfguard/tpm.derivation-secret
cat > /etc/hkdfguard/policy.toml <<TOML
# ci provisions and retires KEKs here, which the production security
# model leaves to root: scripts/verify-roles.sh tests that split.
security_model = "developer"
[selection]
mode = "require"
provider = "tpm2"

[tpm]
tcti = "$SWTPM_TCTI"
TOML
chmod 0644 /etc/hkdfguard/policy.toml

BAD_DIR=$(as_ci mktemp -d /work/bad.XXXXXX)
printf 'this is not = valid [toml' > "$BAD_DIR/policy.toml"
printf 'group-readable, so refused if read' > "$BAD_DIR/secret"; chmod 0640 "$BAD_DIR/secret"
chown -R ci:ci "$BAD_DIR" # so the control fails on the malformed policy, not on being unable to read it
export HKDFGUARD_POLICY_FILE="$BAD_DIR/policy.toml"
export TCTI="device:/dev/nonexistent-tpm" TPM2TOOLS_TCTI="device:/dev/nonexistent-tpm" TEST_TCTI="device:/dev/nonexistent-tpm"
export HKDFGUARD_TPM_DERIVATION_SECRET_FILE="$BAD_DIR/secret"
export HKDFGUARD_EXTERNAL_SECRET_DIR=/nonexistent-secret-mount
export HKDFGUARD_PKCS11_MODULE="$SOFTHSM_MODULE" HKDFGUARD_PKCS11_PIN_FILE="$HARNESS/pkcs11.pin" HKDFGUARD_PKCS11_SLOT=0

as_ci env LD_LIBRARY_PATH=target/release /tmp/wrap_unwrap
for build in release debug; do
    OUT=$(as_ci target/$build/hkdfguard provision --service-name com.hkdfguard.dockertest.shipped 2>&1) \
        || { echo "FAIL: the $build CLI did not take its configuration from /etc/hkdfguard: $OUT" >&2; exit 1; }
    grep -q "HKDFGUARD_POLICY_FILE is set but ignored" <<<"$OUT" \
        || { echo "FAIL: the $build CLI did not warn that HKDFGUARD_POLICY_FILE was ignored: $OUT" >&2; exit 1; }
    echo "$build: provisioned on the TPM named by /etc/hkdfguard/policy.toml; every override ignored."
done
if as_ci "$TEST_BIN"/hkdfguard provision --service-name com.hkdfguard.dockertest.shipped >/dev/null 2>&1; then
    echo "FAIL: control: the test-build CLI should have read the malformed HKDFGUARD_POLICY_FILE and failed" >&2; exit 1
fi
echo "control: the test-build CLI honored the malformed HKDFGUARD_POLICY_FILE and failed, as designed."

section "a reachable TPM without its derivation secret refuses; it never falls back to a weaker provider"
# The TPM is reachable (swtpm, via tpm.tcti) but the derivation secret at its
# default path is missing, and a weaker provider is ready to serve: an
# external-secret KEK in the standard mount. Before this was a refusal the
# chain moved on, so provision succeeded on the file-backed KEK while the
# operator believed the service was TPM-bound. Both shipped builds must now
# refuse, naming the missing secret; a policy that leaves tpm2 out of
# preferred_order - the documented way to use another provider on a host
# with a TPM - must then use the external secret, as the control.
NOSECRET_SERVICE=com.hkdfguard.dockertest.nosecret
mv /etc/hkdfguard/tpm.derivation-secret /etc/hkdfguard/tpm.derivation-secret.aside
mkdir -p /run/secrets/hkdfguard
ci_file /run/secrets/hkdfguard/$NOSECRET_SERVICE
head -c 32 /dev/urandom > /run/secrets/hkdfguard/$NOSECRET_SERVICE
cat > /etc/hkdfguard/policy.toml <<TOML
security_model = "developer"
preferred_order = ["tpm2", "external-secret"]
[selection]
mode = "prefer"

[tpm]
tcti = "$SWTPM_TCTI"
TOML
for build in release debug; do
    if OUT=$(as_ci target/$build/hkdfguard provision --service-name $NOSECRET_SERVICE 2>&1); then
        echo "FAIL: the $build CLI provisioned without the TPM derivation secret (fell back to a weaker provider): $OUT" >&2; exit 1
    fi
    grep -q 'TPM derivation secret /etc/hkdfguard/tpm.derivation-secret does not exist' <<<"$OUT" \
        || { echo "FAIL: the $build CLI refused, but not for the missing TPM derivation secret: $OUT" >&2; exit 1; }
    echo "$build: refused, naming the missing derivation secret; the external-secret KEK was not used."
done
cat > /etc/hkdfguard/policy.toml <<'TOML'
security_model = "developer"
preferred_order = ["external-secret"]
[selection]
mode = "prefer"
TOML
for build in release debug; do
    OUT=$(as_ci target/$build/hkdfguard provision --service-name $NOSECRET_SERVICE 2>&1) \
        || { echo "FAIL: control: with tpm2 left out of preferred_order the $build CLI should use the external secret: $OUT" >&2; exit 1; }
    grep -q 'already provisioned' <<<"$OUT" \
        || { echo "FAIL: control: the $build CLI should have found the KEK in the standard mount: $OUT" >&2; exit 1; }
done
echo "control: release, debug: with tpm2 left out of preferred_order, the external secret serves the call."
rm -rf /run/secrets/hkdfguard
mv /etc/hkdfguard/tpm.derivation-secret.aside /etc/hkdfguard/tpm.derivation-secret

# External secret: the policy names no directory, so the standard mount is
# used; HKDFGUARD_EXTERNAL_SECRET_DIR pointing nowhere changes nothing.
cat > /etc/hkdfguard/policy.toml <<'TOML'
security_model = "developer"
[selection]
mode = "require"
provider = "external-secret"
TOML
mkdir -p /run/secrets/hkdfguard
ci_file /run/secrets/hkdfguard/com.hkdfguard.dockertest.extsecret
head -c 32 /dev/urandom > /run/secrets/hkdfguard/com.hkdfguard.dockertest.extsecret
for build in release debug; do
    OUT=$(as_ci target/$build/hkdfguard provision --service-name com.hkdfguard.dockertest.extsecret 2>&1) \
        || { echo "FAIL: the $build CLI did not use the standard secret mount: $OUT" >&2; exit 1; }
    grep -q 'already provisioned' <<<"$OUT" \
        || { echo "FAIL: the $build CLI should have found the KEK in the standard mount: $OUT" >&2; exit 1; }
done
echo "release, debug: external-secret used the standard mount; HKDFGUARD_EXTERNAL_SECRET_DIR ignored."
rm -rf /run/secrets/hkdfguard

# PKCS#11: SoftHSM2 is installed, with an initialized token and a valid PIN
# at the default PIN path, and HKDFGUARD_PKCS11_* point at all of it --
# but the policy names no module. Neither build may use PKCS#11 (no default
# module search, variables ignored).
cat > /etc/hkdfguard/policy.toml <<'TOML'
security_model = "developer"
[selection]
mode = "require"
provider = "pkcs11"
TOML
install -o root -g ci -m 0440 /dev/null /etc/hkdfguard/pkcs11.pin
printf '1234\n' > /etc/hkdfguard/pkcs11.pin
for build in release debug; do
    if OUT=$(as_ci target/$build/hkdfguard provision --service-name com.hkdfguard.dockertest.pkcs11 2>&1); then
        echo "FAIL: the $build CLI used PKCS#11 with no pkcs11.module in policy: $OUT" >&2; exit 1
    fi
    grep -q 'no KEK provider is available' <<<"$OUT" \
        || { echo "FAIL: the $build CLI should have found no provider: $OUT" >&2; exit 1; }
done
echo "release, debug: PKCS#11 unused without pkcs11.module (no SoftHSM2 search, variables ignored)."

section "retire deletes a PKCS#11 KEK only given its fingerprint; TPM2 refuses"
# The release CLI against the real SoftHSM2 token, configured the way a
# deployment configures it: root-owned policy naming the module, and the
# root:ci 0440 PIN file above.
cat > /etc/hkdfguard/policy.toml <<TOML
security_model = "developer"
[selection]
mode = "require"
provider = "pkcs11"

[pkcs11]
module = "$SOFTHSM_MODULE"
pin_file = "/etc/hkdfguard/pkcs11.pin"
token_label = "hkdfguard-test"
TOML
chmod 0644 /etc/hkdfguard/policy.toml
RETIRE_SERVICE=com.hkdfguard.dockertest.retire
RETIRE_DIR=$(as_ci mktemp -d -p "$KEYS")
as_ci sh -c "umask 077; head -c 32 /dev/urandom > '$RETIRE_DIR/dek'"
CLI=target/release/hkdfguard
fingerprint_in() { sed -n 's/^fingerprint: \([0-9a-f]\{64\}\) .*/\1/p' <<<"$1"; }

OUT=$(as_ci $CLI provision -sn $RETIRE_SERVICE 2>&1) || { echo "FAIL: provision on PKCS#11: $OUT" >&2; exit 1; }
FP=$(fingerprint_in "$OUT")
[ ${#FP} -eq 64 ] || { echo "FAIL: provision printed no fingerprint: $OUT" >&2; exit 1; }
OUT=$(as_ci $CLI provision -sn $RETIRE_SERVICE 2>&1)
[ "$(fingerprint_in "$OUT")" = "$FP" ] || { echo "FAIL: a second provision reported another fingerprint: $OUT" >&2; exit 1; }
printf '%s' "$(base64 -w0 < "$RETIRE_DIR/dek")" \
    | as_ci $CLI wrap -kf "$RETIRE_DIR/wrapped.key" -sn $RETIRE_SERVICE --dek-stdin >/dev/null
as_ci env LD_LIBRARY_PATH=target/release /tmp/cli_unwrap_check "$RETIRE_DIR/wrapped.key" $RETIRE_SERVICE "$RETIRE_DIR/dek"

# wrap --fingerprint: written only when the payload is sealed to the KEK
# given; a mismatch writes nothing, and with --force leaves the file alone.
WRONG=$(printf '%064d' 0)
OUT=$(printf '%s' "$(base64 -w0 < "$RETIRE_DIR/dek")" \
    | as_ci $CLI wrap -kf "$RETIRE_DIR/pinned.key" -sn $RETIRE_SERVICE --dek-stdin -fp "$FP" 2>&1) \
    || { echo "FAIL: wrap --fingerprint with the right fingerprint: $OUT" >&2; exit 1; }
grep -q "^fingerprint: $FP (confirmed)" <<<"$OUT" || { echo "FAIL: wrap did not confirm the fingerprint: $OUT" >&2; exit 1; }
if OUT=$(printf '%s' "$(base64 -w0 < "$RETIRE_DIR/dek")" \
        | as_ci $CLI wrap -kf "$RETIRE_DIR/refused.key" -sn $RETIRE_SERVICE --dek-stdin -fp "$WRONG" 2>&1); then
    echo "FAIL: wrap --fingerprint with the wrong fingerprint succeeded" >&2; exit 1
fi
grep -q "the service's KEK is $FP, not $WRONG; nothing was written" <<<"$OUT" \
    || { echo "FAIL: unexpected wrap mismatch message: $OUT" >&2; exit 1; }
[ ! -e "$RETIRE_DIR/refused.key" ] || { echo "FAIL: a key file was written despite the mismatch" >&2; exit 1; }
BEFORE=$(sha256sum < "$RETIRE_DIR/pinned.key")
if printf '%s' "$(base64 -w0 < "$RETIRE_DIR/dek")" \
        | as_ci $CLI wrap -kf "$RETIRE_DIR/pinned.key" -sn $RETIRE_SERVICE --dek-stdin -fp "$WRONG" --force >/dev/null 2>&1; then
    echo "FAIL: wrap --force --fingerprint with the wrong fingerprint succeeded" >&2; exit 1
fi
[ "$(sha256sum < "$RETIRE_DIR/pinned.key")" = "$BEFORE" ] \
    || { echo "FAIL: --force replaced the key file despite the fingerprint mismatch" >&2; exit 1; }
echo "wrap --fingerprint: right one written and confirmed; wrong one wrote nothing, and --force left the old file intact."

if OUT=$(as_ci $CLI retire -sn $RETIRE_SERVICE -fp "$WRONG" 2>&1); then
    echo "FAIL: retire with the wrong fingerprint succeeded" >&2; exit 1
fi
grep -q "the current KEK is $FP, not $WRONG; nothing was deleted" <<<"$OUT" \
    || { echo "FAIL: unexpected mismatch message: $OUT" >&2; exit 1; }
as_ci env LD_LIBRARY_PATH=target/release /tmp/cli_unwrap_check "$RETIRE_DIR/wrapped.key" $RETIRE_SERVICE "$RETIRE_DIR/dek" \
    || { echo "FAIL: the KEK stopped working after a refused retire" >&2; exit 1; }

OUT=$(as_ci $CLI retire -sn $RETIRE_SERVICE -fp "$FP" 2>&1) || { echo "FAIL: retire: $OUT" >&2; exit 1; }
grep -q "retired KEK for service \"$RETIRE_SERVICE\" (fingerprint $FP, provider PKCS11)" <<<"$OUT" \
    || { echo "FAIL: unexpected retire output: $OUT" >&2; exit 1; }
if as_ci env LD_LIBRARY_PATH=target/release /tmp/cli_unwrap_check "$RETIRE_DIR/wrapped.key" $RETIRE_SERVICE "$RETIRE_DIR/dek" 2>/dev/null; then
    echo "FAIL: a DEK wrapped under the retired KEK still unwraps" >&2; exit 1
fi
if OUT=$(as_ci $CLI retire -sn $RETIRE_SERVICE -fp "$FP" 2>&1); then
    echo "FAIL: retiring twice succeeded" >&2; exit 1
fi
grep -q 'nothing to retire' <<<"$OUT" || { echo "FAIL: unexpected second-retire message: $OUT" >&2; exit 1; }

OUT=$(as_ci $CLI provision -sn $RETIRE_SERVICE 2>&1) || { echo "FAIL: provision after retire: $OUT" >&2; exit 1; }
FP2=$(fingerprint_in "$OUT")
[ ${#FP2} -eq 64 ] && [ "$FP2" != "$FP" ] || { echo "FAIL: provision after retire did not make a new KEK: $OUT" >&2; exit 1; }
as_ci $CLI retire -sn $RETIRE_SERVICE -fp "$FP2" >/dev/null
echo "PKCS#11: wrong fingerprint refused, nothing deleted; right one deleted the KEK; its DEKs no longer unwrap; re-provision makes a new KEK."

cat > /etc/hkdfguard/policy.toml <<TOML
security_model = "developer"
[selection]
mode = "require"
provider = "tpm2"

[tpm]
tcti = "$SWTPM_TCTI"
TOML
OUT=$(as_ci $CLI provision -sn $RETIRE_SERVICE 2>&1) || { echo "FAIL: provision on TPM2: $OUT" >&2; exit 1; }
FP=$(fingerprint_in "$OUT")
if OUT=$(as_ci $CLI retire -sn $RETIRE_SERVICE -fp "$FP" 2>&1); then
    echo "FAIL: retire succeeded on TPM2, which stores no key to delete" >&2; exit 1
fi
grep -q "TPM2 cannot retire a single service's KEK" <<<"$OUT" || { echo "FAIL: unexpected TPM2 retire message: $OUT" >&2; exit 1; }
echo "TPM2: retire refused, with the reason."
rm -rf "$RETIRE_DIR"

unset HKDFGUARD_POLICY_FILE TCTI TPM2TOOLS_TCTI TEST_TCTI HKDFGUARD_TPM_DERIVATION_SECRET_FILE \
      HKDFGUARD_EXTERNAL_SECRET_DIR HKDFGUARD_PKCS11_MODULE HKDFGUARD_PKCS11_PIN_FILE HKDFGUARD_PKCS11_SLOT
section "nothing the library reads is trusted under /tmp; a read-only 1777 mount is"
# The release CLI, configured through /etc/hkdfguard/policy.toml as a
# deployment is. Each file sits in a private directory (root's or ci's,
# 0700/0755) inside the real /tmp: sticky and world-writable, so refused
# however private the directory beneath it -- and the error says it was
# the sticky directory.
# expect_sticky_refusal <what> <command...>: the command must fail, naming
# a sticky directory.
expect_sticky_refusal() {
    local what=$1 out; shift
    if out=$("$@" 2>&1); then
        echo "FAIL: $what under /tmp was accepted: $out" >&2; exit 1
    fi
    grep -q 'sticky, like /tmp, which is not enough' <<<"$out" \
        || { echo "FAIL: $what under /tmp: refused, but not for the sticky directory: $out" >&2; exit 1; }
    echo "$what under /tmp: refused ($(grep -o 'directory /tmp: [^)]*)' <<<"$out" | head -n1))."
}
STICKY_SERVICE=com.hkdfguard.dockertest.sticky

# The TPM derivation secret (root:ci 0440 in a root-owned 0755 directory).
TMP_ROOT=$(mktemp -d); chmod 0755 "$TMP_ROOT"
install -o root -g ci -m 0440 /dev/null "$TMP_ROOT/tpm.derivation-secret"
head -c 32 /dev/urandom > "$TMP_ROOT/tpm.derivation-secret"
cat > /etc/hkdfguard/policy.toml <<TOML
security_model = "developer"
[selection]
mode = "require"
provider = "tpm2"

[tpm]
tcti = "$SWTPM_TCTI"
derivation_secret_file = "$TMP_ROOT/tpm.derivation-secret"
TOML
expect_sticky_refusal "the TPM derivation secret" as_ci $CLI provision -sn $STICKY_SERVICE

# The PKCS#11 module (a root-owned copy of SoftHSM2's), and separately the
# PIN file (root:ci 0440), each with the other in its trusted place.
cp "$SOFTHSM_MODULE" "$TMP_ROOT/libsofthsm2.so"; chmod 0755 "$TMP_ROOT/libsofthsm2.so"
install -o root -g ci -m 0440 /dev/null "$TMP_ROOT/pkcs11.pin"; printf '1234\n' > "$TMP_ROOT/pkcs11.pin"
# Developer model, as for the TPM above: the control has ci create a new
# KEK in the token, which under production only root may do. The model
# governs who administers KEKs and whose key files are trusted, not where
# the module and PIN may live, so the refusals below are unaffected.
pkcs11_policy() { # pkcs11_policy <module> <pin file>
    printf 'security_model = "developer"\n[selection]\nmode = "require"\nprovider = "pkcs11"\n\n[pkcs11]\nmodule = "%s"\npin_file = "%s"\ntoken_label = "hkdfguard-test"\n' \
        "$1" "$2" > /etc/hkdfguard/policy.toml
}
pkcs11_policy "$SOFTHSM_MODULE" /etc/hkdfguard/pkcs11.pin
as_ci $CLI provision -sn $STICKY_SERVICE >/dev/null || { echo "FAIL: control: PKCS#11 from trusted places" >&2; exit 1; }
pkcs11_policy "$TMP_ROOT/libsofthsm2.so" /etc/hkdfguard/pkcs11.pin
expect_sticky_refusal "the PKCS#11 module" as_ci $CLI provision -sn $STICKY_SERVICE
pkcs11_policy "$SOFTHSM_MODULE" "$TMP_ROOT/pkcs11.pin"
expect_sticky_refusal "the PKCS#11 PIN file" as_ci $CLI provision -sn $STICKY_SERVICE
rm -rf "$TMP_ROOT"

# An external-secret mount: ci's own 0700 directory under /tmp, with the
# service's KEK in it, owner-only.
TMP_MOUNT=$(as_ci mktemp -d)
ci_file "$TMP_MOUNT/$STICKY_SERVICE"; head -c 32 /dev/urandom | ci_write "$TMP_MOUNT/$STICKY_SERVICE"
printf '[selection]\nmode = "require"\nprovider = "external-secret"\n\n[external_secret]\ndir = "%s"\n' "$TMP_MOUNT" \
    > /etc/hkdfguard/policy.toml
expect_sticky_refusal "an external-secret mount" as_ci $CLI provision -sn $STICKY_SERVICE
rm -rf "$TMP_MOUNT"

# The policy itself, read by the test build's CLI (the only kind that reads
# a policy other than /etc/hkdfguard/policy.toml). Its absence is no more
# trusted there than its presence: someone could have deleted it.
TMP_POLICY=$(as_ci mktemp -d)
printf '[selection]\nmode = "require"\nprovider = "pkcs11"\n' | ci_write "$TMP_POLICY/policy.toml"
expect_sticky_refusal "the policy file" as_ci env HKDFGUARD_POLICY_FILE="$TMP_POLICY/policy.toml" \
    "$TEST_BIN"/hkdfguard provision -sn $STICKY_SERVICE
expect_sticky_refusal "a missing policy file" as_ci env HKDFGUARD_POLICY_FILE="$TMP_POLICY/absent.toml" \
    "$TEST_BIN"/hkdfguard provision -sn $STICKY_SERVICE
rm -rf "$TMP_POLICY"

# The read-only exception, which Kubernetes Secret and ConfigMap volumes
# depend on: docker/run-tests.sh mounts a volume read-only at $RO_MOUNT,
# its root 1777 like a Secret volume's, holding a KEK for $RO_SERVICE (ci's,
# 0400) both in the root itself and in a 0755 subdirectory -- a sticky
# directory as the mount and as an ancestor of it. Both must work; the same
# layout writable must not.
RO_MOUNT=/run/hkdfguard-ro-secrets
RO_SERVICE=com.hkdfguard.dockertest.romount
grep -q " $RO_MOUNT " /proc/self/mountinfo \
    || { echo "FAIL: nothing is mounted at $RO_MOUNT; run this image through docker/run-tests.sh, which mounts it" >&2; exit 1; }
[ "$(stat -c %a "$RO_MOUNT")" = 1777 ] && [ ! -w "$RO_MOUNT" ] && ! touch "$RO_MOUNT/probe" 2>/dev/null \
    || { echo "FAIL: $RO_MOUNT should be a read-only 1777 mount: $(stat -c '%a %U:%G' "$RO_MOUNT")" >&2; exit 1; }
RW_MOUNT=$(mktemp -d /run/hkdfguard-rw-secrets.XXXXXX)
chmod 1777 "$RW_MOUNT"; install -d -m 0755 "$RW_MOUNT/hkdfguard"
for d in "$RW_MOUNT" "$RW_MOUNT/hkdfguard"; do
    # Created by root, then handed to ci: with fs.protected_regular, root
    # may not open an existing file of ci's in a sticky directory.
    head -c 32 /dev/urandom > "$d/$RO_SERVICE"; chown ci:ci "$d/$RO_SERVICE"; chmod 0400 "$d/$RO_SERVICE"
done
for sub in "" /hkdfguard; do
    printf '[selection]\nmode = "require"\nprovider = "external-secret"\n\n[external_secret]\ndir = "%s"\n' "$RO_MOUNT$sub" \
        > /etc/hkdfguard/policy.toml
    OUT=$(as_ci $CLI provision -sn $RO_SERVICE 2>&1) \
        || { echo "FAIL: the read-only 1777 mount ($RO_MOUNT$sub) was refused: $OUT" >&2; exit 1; }
    grep -q 'already provisioned' <<<"$OUT" || { echo "FAIL: no KEK found in $RO_MOUNT$sub: $OUT" >&2; exit 1; }
    as_ci sh -c "umask 077; head -c 32 /dev/urandom > '$KEYS/ro.dek'"
    printf '%s' "$(base64 -w0 < "$KEYS/ro.dek")" | as_ci $CLI wrap -kf "$KEYS/ro.key" -sn $RO_SERVICE --dek-stdin --force >/dev/null
    as_ci env LD_LIBRARY_PATH=target/release /tmp/cli_unwrap_check "$KEYS/ro.key" $RO_SERVICE "$KEYS/ro.dek" >/dev/null \
        || { echo "FAIL: a DEK wrapped under the KEK in $RO_MOUNT$sub did not unwrap" >&2; exit 1; }
    echo "external secret in a read-only 1777 mount ($RO_MOUNT$sub): accepted; wrap and unwrap work."

    printf '[selection]\nmode = "require"\nprovider = "external-secret"\n\n[external_secret]\ndir = "%s"\n' "$RW_MOUNT$sub" \
        > /etc/hkdfguard/policy.toml
    if OUT=$(as_ci $CLI provision -sn $RO_SERVICE 2>&1); then
        echo "FAIL: the same layout writable ($RW_MOUNT$sub) was accepted: $OUT" >&2; exit 1
    fi
    grep -q 'sticky, like /tmp, which is not enough' <<<"$OUT" \
        || { echo "FAIL: $RW_MOUNT$sub refused, but not for the sticky directory: $OUT" >&2; exit 1; }
    echo "the same layout writable ($RW_MOUNT$sub): refused."
done
rm -rf "$RW_MOUNT" "$KEYS/ro.dek" "$KEYS/ro.key"

rm -rf /etc/hkdfguard "$BAD_DIR" "$HARNESS" "$KEYS"

section "the production security model: who may provision, wrap and unwrap"
# A release build, with no policy but the script's own (production), and
# throwaway deployer and application accounts.
mkdir -p /etc/hkdfguard
LD_LIBRARY_PATH="$PWD/target/release" scripts/verify-roles.sh target/release/hkdfguard /tmp/cli_unwrap_check
rm -rf /etc/hkdfguard

section "hkdfguard locks its memory when it can"
# docker/run-tests.sh and CI grant CAP_IPC_LOCK, so the CLI must take the
# mlockall path; it exits non-zero if that fails, so a clean exit with no
# skip warning means memory really was locked. Without the capability the
# skip path must warn instead. This one runs as root: dropping to ci
# drops CAP_IPC_LOCK with it.
CAP_EFF=$((16#$(awk '/^CapEff:/{print $2}' /proc/self/status)))
CLI_STDERR=$(target/release/hkdfguard --help 2>&1 >/dev/null) \
    || { echo "FAIL: CLI exited non-zero at startup: $CLI_STDERR" >&2; exit 1; }
if (( (CAP_EFF >> 14) & 1 )); then
    if grep -q 'memory not locked' <<<"$CLI_STDERR"; then
        echo "FAIL: CAP_IPC_LOCK is present but the CLI skipped mlockall" >&2; exit 1
    fi
    echo "CAP_IPC_LOCK present: CLI locked its memory (mlockall succeeded)."
else
    grep -q 'memory not locked' <<<"$CLI_STDERR" \
        || { echo "FAIL: no CAP_IPC_LOCK, yet the CLI gave no skip warning" >&2; exit 1; }
    echo "no CAP_IPC_LOCK: CLI skipped mlockall and warned, as designed."
fi

section "ALL CHECKS PASSED"

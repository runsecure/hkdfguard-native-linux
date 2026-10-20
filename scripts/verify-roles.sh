#!/usr/bin/env bash
# End to end, the production security model's split of duties -- the Linux
# counterpart of the Windows build's tests/test_roles.ps1 and the macOS
# build's scripts/verify-machine-scope.sh:
#
#   security admin    root: provision, retire
#   deployment admin  a member of hkdfguard-deployers: wrap
#   application       anyone else: unwrap only -- it can't persist a key
#                     file its own service would accept
#
# Usage, as root, against a release build (a test build would honor
# HKDFGUARD_POLICY_FILE and trust files the reader owns):
#
#   LD_LIBRARY_PATH=$PWD/target/release \
#       scripts/verify-roles.sh target/release/hkdfguard <cli_unwrap_check>
#
# <cli_unwrap_check> is examples/cli_unwrap_check.c built against that
# release libhkdfguard.so. The script installs its own
# /etc/hkdfguard/policy.toml (external-secret, no security_model: the
# production default), so it refuses to run while one exists; it creates two
# throwaway accounts, and removes them, the policy and everything else it
# made on exit -- the groups too, unless they were already there.
set -euo pipefail

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[ $# -eq 2 ] || { echo "usage: $0 <hkdfguard CLI> <cli_unwrap_check>" >&2; exit 2; }
CLI=$(realpath "$1")
CHECK=$(realpath "$2")
[ "$(id -u)" -eq 0 ] || fail "run as root: the script creates accounts and installs a policy"
POLICY=/etc/hkdfguard/policy.toml
[ ! -e "$POLICY" ] || fail "$POLICY exists; this script installs its own, so run it where there is none"
[ -d /etc/hkdfguard ] || fail "/etc/hkdfguard does not exist (the packages create it)"

DEPLOYER=hkgroles-deployer
APP=hkgroles-app
SERVICE=com.hkdfguard.roles
created_groups=()
BASE=""
cleanup() {
    rm -f "$POLICY"
    for user in "$DEPLOYER" "$APP"; do
        if getent passwd "$user" >/dev/null; then userdel "$user" 2>/dev/null || true; fi
        if getent group "$user" >/dev/null; then groupdel "$user" 2>/dev/null || true; fi
    done
    for group in "${created_groups[@]}"; do groupdel "$group" 2>/dev/null || true; done
    [ -z "$BASE" ] || rm -rf "$BASE"
}
trap cleanup EXIT

# Runs a command as `user`, with that user's groups and nothing else of
# root's environment.
as_user() {
    local user=$1; shift
    setpriv --reuid="$user" --regid="$user" --init-groups \
        env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ ${LD_LIBRARY_PATH:+LD_LIBRARY_PATH="$LD_LIBRARY_PATH"} "$@"
}

section "accounts: a deployer and an application"
# hkdfguard (key users, who may read the secret) and hkdfguard-deployers
# are the packages' groups; a source build has to make them.
for group in hkdfguard hkdfguard-deployers; do
    if ! getent group "$group" >/dev/null; then
        groupadd --system "$group"
        created_groups+=("$group")
    fi
done
for user in "$DEPLOYER" "$APP"; do
    ! getent passwd "$user" >/dev/null || fail "account $user already exists"
done
useradd --system --user-group --no-create-home --shell /usr/sbin/nologin --groups hkdfguard,hkdfguard-deployers "$DEPLOYER"
useradd --system --user-group --no-create-home --shell /usr/sbin/nologin --groups hkdfguard "$APP"
id "$DEPLOYER"; id "$APP"

# Everything lives under a root-owned 0755 directory both accounts can
# reach, all the way up to / -- not /tmp, which the library never trusts.
BASE=$(mktemp -d /var/lib/hkdfguard-roles.XXXXXX)
chmod 0755 "$BASE"
# The KEK: an external secret, root:hkdfguard 0440, as a deployment
# installs one for a non-root service.
install -d -m 0755 "$BASE/secrets"
install -o root -g hkdfguard -m 0440 /dev/null "$BASE/secrets/$SERVICE"
head -c 32 /dev/urandom > "$BASE/secrets/$SERVICE"
# The DEK the deployer wraps, and the check compares against. Root's, so
# the library judges it as the plaintext key it is (-37), not as a file
# someone untrusted owns (-39).
install -o root -g hkdfguard -m 0440 /dev/null "$BASE/dek"
head -c 32 /dev/urandom > "$BASE/dek"
# The deployers' shared folder, and the application's own.
install -d -o root -g hkdfguard-deployers -m 2775 "$BASE/keys"
install -d -o "$APP" -g "$APP" -m 0755 "$BASE/app"

cat > "$POLICY" <<TOML
# No security_model: the production default.
[selection]
mode = "require"
provider = "external-secret"

[external_secret]
dir = "$BASE/secrets"
TOML
chmod 0644 "$POLICY"

section "security admin: only root provisions and retires"
OUT=$(as_user "$APP" "$CLI" provision -sn com.hkdfguard.roles.unprovisioned 2>&1) \
    && fail "the application provisioned a new KEK: $OUT"
grep -q 'only root creates or retires a KEK' <<<"$OUT" || fail "unexpected refusal of the application's provision: $OUT"
OUT=$(as_user "$APP" "$CLI" retire -sn "$SERVICE" -fp "$(printf '0%.0s' $(seq 64))" 2>&1) \
    && fail "the application's retire succeeded: $OUT"
grep -q 'only root retires a KEK' <<<"$OUT" || fail "unexpected refusal of the application's retire: $OUT"
OUT=$("$CLI" provision -sn "$SERVICE" 2>&1) || fail "root's provision failed: $OUT"
FP=$(grep -o '[0-9a-f]\{64\}' <<<"$OUT" | head -n 1)
[ ${#FP} -eq 64 ] || fail "provision printed no fingerprint: $OUT"
echo "the application's provision and retire refused; root's provision verified KEK $FP."

section "deployment admin: the deployer wraps, into the deployers' folder"
base64 -w0 < "$BASE/dek" | as_user "$DEPLOYER" "$CLI" wrap -kf "$BASE/keys/$SERVICE.key" -sn "$SERVICE" \
    --dek-stdin -g hkdfguard -fp "$FP"
[ "$(stat -c '%U:%G %a' "$BASE/keys/$SERVICE.key")" = "$DEPLOYER:hkdfguard 640" ] \
    || fail "unexpected key file ownership: $(stat -c '%U:%G %a' "$BASE/keys/$SERVICE.key")"
as_user "$APP" "$CHECK" "$BASE/keys/$SERVICE.key" "$SERVICE" "$BASE/dek"
echo "the deployer's key file opens and unwraps for the application."

section "application: unwrap only"
OUT=$(base64 -w0 < "$BASE/dek" | as_user "$APP" "$CLI" wrap -kf "$BASE/app/own.key" -sn "$SERVICE" --dek-stdin 2>&1) \
    && fail "the application's wrap succeeded"
grep -q 'may not persist key files' <<<"$OUT" || fail "unexpected refusal of the application's wrap: $OUT"
[ ! -e "$BASE/app/own.key" ] || fail "a refused wrap wrote a key file"
echo "the application's wrap refused; nothing written."

if as_user "$APP" cp "$BASE/keys/$SERVICE.key" "$BASE/keys/planted.key" 2>/dev/null; then
    fail "the application wrote into the deployers' folder"
fi
echo "the OS keeps the application out of the deployers' folder."

as_user "$APP" cp "$BASE/keys/$SERVICE.key" "$BASE/app/planted.key"
OUT=$(as_user "$APP" "$CHECK" "$BASE/app/planted.key" "$SERVICE" "$BASE/dek" 2>&1) \
    && fail "a key file the application wrote was trusted: $OUT"
grep -q 'failed: -39' <<<"$OUT" || fail "expected HKDFGUARD_ERR_FILE_UNTRUSTED (-39): $OUT"
echo "a key file the application wrote itself (a copy of a genuine one): refused, -39."

section "the developer model, as a control: the application's own file is trusted"
sed -i '1i security_model = "developer"' "$POLICY"
as_user "$APP" "$CHECK" "$BASE/app/planted.key" "$SERVICE" "$BASE/dek"
sed -i '1d' "$POLICY"
echo "the same file opens under the developer model: the model is what refused it."

section "a deployer who leaves the group: their key files are refused at once"
gpasswd -d "$DEPLOYER" hkdfguard-deployers >/dev/null
OUT=$(as_user "$APP" "$CHECK" "$BASE/keys/$SERVICE.key" "$SERVICE" "$BASE/dek" 2>&1) \
    && fail "a former deployer's key file was trusted: $OUT"
grep -q 'failed: -39' <<<"$OUT" || fail "expected HKDFGUARD_ERR_FILE_UNTRUSTED (-39): $OUT"
echo "the former deployer's key file: refused, -39 -- redeploy before removing a deployer."

section "ALL ROLE CHECKS PASSED"

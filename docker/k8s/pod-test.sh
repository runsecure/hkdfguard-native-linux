#!/bin/sh
# Runs inside each test pod (see docker/k8s/run-tests.sh and
# run-vault-tests.sh). Reports how the secret directory was laid out -- by
# the kubelet for a Secret volume, or by a Vault Agent sidecar -- then tries
# the deployment flow against it: provision, wrap a fresh DEK, and unwrap it
# in a separate process through the shared library. Prints one `RESULT:`
# line for the runner to compare with what the scenario expects. The
# runner supplies the policy (a ConfigMap at /etc/hkdfguard) and, in MOUNT,
# where it mounted the secret.
#
# MODE=rotate additionally waits for the secret to be rotated (the runner
# updates it after `READY_FOR_ROTATION`), then checks that the payload
# wrapped under the old key is refused and that a new wrap works.
set -u

SERVICE=${SERVICE:-com.k8stest.orders}
MOUNT=${MOUNT:-/var/run/secrets/hkdfguard} # where the scenario mounted the secret
MODE=${MODE:-once}

echo "== identity: $(id)"
echo "== policy (/etc/hkdfguard/policy.toml):"
sed 's/^/   /' /etc/hkdfguard/policy.toml 2>&1
echo "== mount: $(stat -c '%a %U:%G' "$MOUNT")"
grep " $MOUNT " /proc/self/mountinfo | awk '{print "   options: " $6 "  fs: " $(NF-2)}'
ls -la "$MOUNT"
if key=$(readlink -f "$MOUNT/$SERVICE"); then
    echo "== key file: $key $(stat -c '%a %U:%G' "$key" 2>&1)"
fi

# Key files go in this uid's private directory, which the image creates
# (docker/k8s/Dockerfile) -- not under /tmp: the library refuses a key file
# anywhere under a sticky, world-writable directory, and `hkdfguard wrap`
# refuses to write one there.
keys_root=/var/lib/hkdfguard-test/$(id -u)
if [ ! -d "$keys_root" ]; then
    echo "RESULT: no private key directory $keys_root for uid $(id -u) in this image (see docker/k8s/Dockerfile)"
    exit 0
fi
work=$(mktemp -d "$keys_root/hk.XXXXXX")

# wrap_and_check <name>: wrap a fresh DEK into $work/<name>.key and unwrap
# it through the library. Prints the failing step's output on failure.
wrap_and_check() {
    head -c 32 /dev/urandom > "$work/$1.dek"
    if ! out=$(hkdfguard provision -sn "$SERVICE" 2>&1); then
        echo "provision failed: $out"; return 1
    fi
    if ! out=$(base64 -w0 < "$work/$1.dek" | hkdfguard wrap -kf "$work/$1.key" -sn "$SERVICE" --dek-stdin 2>&1); then
        echo "wrap failed: $out"; return 1
    fi
    if ! out=$(cli_unwrap_check "$work/$1.key" "$SERVICE" "$work/$1.dek" 2>&1); then
        echo "unwrap failed: $out"; return 1
    fi
    echo "$out"
}

echo "== deployment flow"
if ! detail=$(wrap_and_check first); then
    echo "$detail"
    echo "RESULT: refused: $(printf '%s\n' "$detail" | tail -n 1)"
    exit 0
fi
echo "$detail"

if [ "$MODE" != rotate ]; then
    echo "RESULT: works"
    exit 0
fi

# A Secret volume rotates by repointing ..data; a Vault Agent replaces the
# file by renaming a new one over it, which gives it a new inode.
marker() {
    if [ -L "$MOUNT/..data" ]; then
        echo "..data -> $(readlink "$MOUNT/..data")"
    else
        echo "inode $(stat -L -c %i "$MOUNT/$SERVICE" 2>/dev/null)"
    fi
}

before=$(marker)
echo "READY_FOR_ROTATION ($before)"
i=0
while [ "$(marker)" = "$before" ]; do
    i=$((i + 1))
    if [ "$i" -gt 180 ]; then
        echo "RESULT: the secret was not rotated within 180 s"
        exit 0
    fi
    sleep 1
done
echo "== rotated after ${i}s: $(marker)"

if old=$(cli_unwrap_check "$work/first.key" "$SERVICE" "$work/first.dek" 2>&1); then
    echo "RESULT: the payload wrapped under the old key still unwrapped: $old"
    exit 0
fi
echo "old payload: $old"
if ! detail=$(wrap_and_check second); then
    echo "RESULT: old payload refused, but a new wrap failed: $(printf '%s\n' "$detail" | tail -n 1)"
    exit 0
fi
echo "RESULT: rotated: old payload refused ($(printf '%s\n' "$old" | grep -o -- '-[0-9]*' | tail -n 1)), new wrap works"

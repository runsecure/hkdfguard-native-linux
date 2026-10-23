#!/usr/bin/env bash
# Runs the external-secret provider against real Kubernetes Secret volumes,
# on whatever cluster kubectl points at (Docker Desktop's built-in
# Kubernetes, or kind). Each scenario is a Job whose pod mounts a Secret
# holding a P-256 KEK (SEC1 DER, made and fingerprinted on this machine
# with the OpenSSL commands docs/configuration.md gives) and a ConfigMap
# holding the policy at /etc/hkdfguard, and runs docker/k8s/pod-test.sh:
# provision, wrap a DEK, and unwrap it in a separate process through the
# library.
#
# Scenarios vary what the kubelet controls -- the pod's user, fsGroup, and
# the Secret's defaultMode -- plus one that rotates the Secret while the
# pod runs. Most pin the key (external_secret.require_pinned_keys, with the
# key's fingerprint in external_secret.pinned_keys), as the docs recommend;
# others pin a different key, pin nothing, or set external_secret.dir.
# Each prints what it observed and whether that matched the expectation
# listed below: the RESULT the pod reports and, for refusals that are the
# point of the scenario, the reason that must appear in its output.
#
# The image is built into the local Docker engine and used with
# imagePullPolicy: Never, which works when the cluster shares that engine's
# images (Docker Desktop's kubeadm cluster does). Everything runs in its own
# namespace, deleted on exit. Needs openssl on this machine.
#
# Usage: docker/k8s/run-tests.sh
set -uo pipefail
cd "$(dirname "$0")/../.."

IMAGE=hkdfguard-k8s-test:local
NS=hkdfguard-k8stest
SERVICE=com.k8stest.orders
DEFAULT_MOUNT=/var/run/secrets/hkdfguard # the provider's first conventional mount
WORK=$(mktemp -d)

# shellcheck source=docker/k8s/keys.sh
. docker/k8s/keys.sh

cleanup() {
    kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    rm -rf "${WORK:?}"
}
trap cleanup EXIT

# A path kubectl can open: on Windows (Git Bash), kubectl.exe needs a
# Windows path.
native_path() { cygpath -w "$1" 2>/dev/null || echo "$1"; }

# put_secret <name> <key file>: creates (or replaces) Secret <name> holding
# that key for $SERVICE.
put_secret() {
    kubectl -n "$NS" create secret generic "$1" \
        --from-file="$SERVICE=$(native_path "$2")" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}

# put_policy <name> <dir or -> <pin> [<key file>...]: ConfigMap <name>-policy
# holding the scenario's policy.toml (see write_policy in keys.sh).
put_policy() {
    local name=$1
    shift
    write_policy "$WORK/$name.policy.toml" "$@"
    kubectl -n "$NS" create configmap "$name-policy" \
        --from-file="policy.toml=$(native_path "$WORK/$name.policy.toml")" >/dev/null
}

# start_job <name> <runAsUser> <fsGroup or -> <defaultMode, decimal> <mode> <mount>
start_job() {
    local fsgroup=""
    [ "$3" != - ] && fsgroup="fsGroup: $3"
    kubectl apply -f - >/dev/null <<YAML
apiVersion: batch/v1
kind: Job
metadata:
  name: $1
  namespace: $NS
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsUser: $2
        runAsGroup: $2
        $fsgroup
      containers:
        - name: test
          image: $IMAGE
          imagePullPolicy: Never
          env:
            - { name: SERVICE, value: "$SERVICE" }
            - { name: MODE, value: "$5" }
            - { name: MOUNT, value: "$6" }
          volumeMounts:
            - { name: kek, mountPath: $6, readOnly: true }
            - $POLICY_MOUNT
      volumes:
        - name: kek
          secret:
            secretName: $1
            defaultMode: $4
        - $(policy_volume "$1-policy")
YAML
}

finish_job() {
    kubectl -n "$NS" wait --for=condition=complete "job/$1" --timeout=300s >/dev/null 2>&1 \
        || echo "   (job $1 did not complete; its pod may not have started -- see below)"
    kubectl -n "$NS" logs "job/$1" 2>&1 || kubectl -n "$NS" describe "job/$1"
}

echo "== cluster"
kubectl config current-context
if ! kubectl get nodes -o wide; then
    echo "kubectl can't reach a cluster; enable Kubernetes in Docker Desktop and wait for it to start" >&2
    exit 1
fi

echo "== building $IMAGE"
docker build -q -t "$IMAGE" -f docker/k8s/Dockerfile . || exit 1

kubectl create namespace "$NS" >/dev/null

# name | runAsUser | fsGroup | defaultMode (decimal; 256 = 0400, 288 = 0440, 292 = 0444) | mode
#      | mount (- for the default) | external_secret.dir (- for unset) | pin | expected RESULT prefix | reason (- for any)
#   pin: match -- pin the delivered key (and, when rotating, the next one too)
#        other -- pin a different key: the delivered one must be refused
#        none  -- require_pinned_keys with no pin for the service
#        off   -- no pinning
SCENARIOS="
root-0400|0|-|256|once|-|-|match|works|-
nonroot-0400|10001|-|256|once|-|-|match|refused|-
nonroot-fsgroup-0400|10001|10001|256|once|-|-|match|works|-
nonroot-fsgroup-0440|10001|10001|288|once|-|-|match|works|-
nonroot-fsgroup-other-0400|10001|20000|256|once|-|-|match|works|-
nonroot-fsgroup-0444|10001|10001|292|once|-|-|match|refused|-
nonroot-0444|10001|-|292|once|-|-|match|refused|-
root-0400-rotate|0|-|256|rotate|-|-|match|rotated|-
root-0400-unpinned|0|-|256|once|-|-|off|works|-
pin-mismatch|10001|10001|256|once|-|-|other|refused|not the one pinned in policy
pin-missing|10001|10001|256|once|-|-|none|refused|has no pinned key
dir-docs-example|10001|10001|256|once|/run/secrets/hkdfguard|/run/secrets/hkdfguard|match|works|-
dir-elsewhere|10001|10001|256|once|-|/srv/hkdfguard|match|refused|is not a directory
"

failures=0
summary=""
while IFS='|' read -r name user fsgroup mode run mount dir pin expected reason; do
    [ -n "$name" ] || continue
    [ "$mount" = - ] && mount=$DEFAULT_MOUNT
    echo
    echo "================ $name (runAsUser $user, fsGroup $fsgroup, defaultMode $(printf '%o' "$mode"), mount $mount, dir $dir, pin $pin)"
    key=$WORK/$name.key next=$WORK/$name.next.key
    new_key "$key" && new_key "$next" || exit 1
    case $pin in
        match) put_policy "$name" "$dir" pin "$key" "$next" ;; # the next key is only ever delivered by rotation
        other) put_policy "$name" "$dir" pin "$next" ;;
        *) put_policy "$name" "$dir" "$pin" ;;
    esac
    echo "   delivered key fingerprint: $(fingerprint "$key")"
    put_secret "$name" "$key"
    start_job "$name" "$user" "$fsgroup" "$mode" "$run" "$mount"

    if [ "$run" = rotate ]; then
        for _ in $(seq 1 120); do
            kubectl -n "$NS" logs "job/$name" 2>/dev/null | grep -q READY_FOR_ROTATION && break
            sleep 1
        done
        echo "   rotating Secret $name to the key fingerprinted $(fingerprint "$next")"
        put_secret "$name" "$next"
    fi

    out=$(finish_job "$name")
    printf '%s\n' "$out" | sed 's/^/   /'
    result=$(printf '%s\n' "$out" | sed -n 's/^RESULT: //p' | tail -n 1)
    v=$(verdict "$out" "$result" "$expected" "$reason")
    [ "$v" = "as expected" ] || failures=$((failures + 1))
    summary+=$(printf '\n  %-26s %-45s %s' "$name" "${result:-no result}" "$v")
done <<<"$SCENARIOS"

echo
echo "Summary:$summary"
[ "$failures" -eq 0 ] && echo "Every scenario behaved as expected." || echo "$failures scenario(s) did not behave as expected."
exit "$failures"

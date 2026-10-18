#!/usr/bin/env bash
# Runs the external-secret provider against real Kubernetes Secret volumes,
# on whatever cluster kubectl points at (Docker Desktop's built-in
# Kubernetes, or kind). Each scenario is a Job whose pod mounts a Secret
# holding a random 32-byte KEK at /var/run/secrets/hkdfguard -- the
# provider's default directory -- and runs docker/k8s/pod-test.sh: provision,
# wrap a DEK, and unwrap it in a separate process through the library.
#
# Scenarios vary what the kubelet controls -- the pod's user, fsGroup, and
# the Secret's defaultMode -- plus one that rotates the Secret while the
# pod runs. Each prints what it observed and whether that matched the
# expectation listed below.
#
# The image is built into the local Docker engine and used with
# imagePullPolicy: Never, which works when the cluster shares that engine's
# images (Docker Desktop's kubeadm cluster does). Everything runs in its own
# namespace, deleted on exit.
#
# Usage: docker/k8s/run-tests.sh
set -uo pipefail
cd "$(dirname "$0")/../.."

IMAGE=hkdfguard-k8s-test:local
NS=hkdfguard-k8stest
SERVICE=com.k8stest.orders
WORK=$(mktemp -d)

cleanup() {
    kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    rm -rf "${WORK:?}"
}
trap cleanup EXIT

# A path kubectl can open: on Windows (Git Bash), kubectl.exe needs a
# Windows path.
native_path() { cygpath -w "$1" 2>/dev/null || echo "$1"; }

# Creates (or replaces) Secret <name> holding a fresh random key for $SERVICE.
put_secret() {
    head -c 32 /dev/urandom > "$WORK/$1.key"
    kubectl -n "$NS" create secret generic "$1" \
        --from-file="$SERVICE=$(native_path "$WORK/$1.key")" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}

# start_job <name> <runAsUser> <fsGroup or -> <defaultMode, decimal> <mode>
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
          volumeMounts:
            - { name: kek, mountPath: /var/run/secrets/hkdfguard, readOnly: true }
      volumes:
        - name: kek
          secret:
            secretName: $1
            defaultMode: $4
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

# name | runAsUser | fsGroup | defaultMode (decimal; 256 = 0400, 292 = 0444) | mode | expected RESULT prefix
SCENARIOS="
root-0400|0|-|256|once|works
nonroot-0400|10001|-|256|once|refused
nonroot-fsgroup-0400|10001|10001|256|once|refused
nonroot-0444|10001|-|292|once|refused
root-0400-rotate|0|-|256|rotate|rotated
"

failures=0
summary=""
while IFS='|' read -r name user fsgroup mode run expected; do
    [ -n "$name" ] || continue
    echo
    echo "================ $name (runAsUser $user, fsGroup $fsgroup, defaultMode $(printf '%o' "$mode"))"
    put_secret "$name"
    start_job "$name" "$user" "$fsgroup" "$mode" "$run"

    if [ "$run" = rotate ]; then
        for _ in $(seq 1 120); do
            kubectl -n "$NS" logs "job/$name" 2>/dev/null | grep -q READY_FOR_ROTATION && break
            sleep 1
        done
        echo "   rotating Secret $name"
        put_secret "$name"
    fi

    out=$(finish_job "$name")
    printf '%s\n' "$out" | sed 's/^/   /'
    result=$(printf '%s\n' "$out" | sed -n 's/^RESULT: //p' | tail -n 1)
    if [ "${result#"$expected"}" != "$result" ]; then
        verdict="as expected"
    else
        verdict="UNEXPECTED (expected: $expected)"
        failures=$((failures + 1))
    fi
    summary+=$(printf '\n  %-22s %-45s %s' "$name" "${result:-no result}" "$verdict")
done <<<"$SCENARIOS"

echo
echo "Summary:$summary"
[ "$failures" -eq 0 ] && echo "Every scenario behaved as expected." || echo "$failures scenario(s) did not behave as expected."
exit "$failures"

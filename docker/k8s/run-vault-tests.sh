#!/usr/bin/env bash
# Runs the external-secret provider against KEKs delivered by a Vault Agent
# sidecar instead of a Kubernetes Secret volume, on whatever cluster kubectl
# points at (see run-tests.sh). A Vault dev server runs in the test
# namespace with Kubernetes auth enabled -- the login the Vault Agent
# Injector sets up -- and each scenario's key (32 random bytes, made and
# fingerprinted on this machine with the OpenSSL commands
# docs/configuration.md gives) is stored there base64-encoded in KV v2.
# Each scenario is a Job whose pod runs Vault Agent as a native sidecar: it
# logs in with the pod's service-account token, renders the key with
# base64Decode into a shared emptyDir, and keeps it current. The test
# container mounts that directory at /vault/secrets/hkdfguard, with the
# policy from a ConfigMap at /etc/hkdfguard -- the documented pinning
# example: external_secret.dir set to that mount, require_pinned_keys, and
# the key's fingerprint pinned -- and runs docker/k8s/pod-test.sh, as for
# the Secret-volume tests.
#
# Unlike a Secret volume, the file is written by the agent: its owner is
# the agent's uid, its mode the template's `perms`, and the emptyDir it
# lands in (a tmpfs, medium: Memory) is 1777, writable by every container
# in the pod. Scenarios vary those:
#   - the agent's user (the image's default, the app's own, or root),
#   - the template's perms,
#   - whether the app mounts the whole emptyDir (tmpfs or disk-backed) or
#     a private subdirectory of it (created 0700 by an init container
#     running as the app's user),
#   - the pod's fsGroup,
# plus one that writes a new key version to Vault while the pod runs, one
# that pins a different key, and two where the key is planted: an init
# container, running as the app's own user, writes a valid key of its own
# into the shared directory while the real one is still undelivered (it is
# never written to Vault). Unpinned, the planted key is used -- the
# control, showing the attack is real; pinned, it is refused.
#
# Everything runs in its own namespace, plus one ClusterRoleBinding that
# lets Vault review service-account tokens; both are deleted on exit.
# Needs openssl on this machine.
#
# Usage: docker/k8s/run-vault-tests.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1 # Git Bash: pass /paths to kubectl.exe unchanged

IMAGE=hkdfguard-k8s-test:local
VAULT_IMAGE=hashicorp/vault:1.19.0
NS=hkdfguard-vaulttest
CRB=hkdfguard-vaulttest-tokenreview
SERVICE=com.k8stest.orders
MOUNT=/vault/secrets/hkdfguard # where the app sees the keys; external_secret.dir names it
WORK=$(mktemp -d)

# shellcheck source=docker/k8s/keys.sh
. docker/k8s/keys.sh

cleanup() {
    kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    kubectl delete clusterrolebinding "$CRB" --ignore-not-found >/dev/null 2>&1 || true
    rm -rf "${WORK:?}"
}
trap cleanup EXIT

# A path kubectl can open: on Windows (Git Bash), kubectl.exe needs a
# Windows path.
native_path() { cygpath -w "$1" 2>/dev/null || echo "$1"; }

vault_cli() {
    kubectl -n "$NS" exec -i deploy/vault -- env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root vault "$@"
}

# put_secret <name> <key file>: stores the key as a new version of
# secret/hkdfguard/<name>. The value goes over stdin, not argv.
put_secret() {
    base64 -w0 < "$2" | vault_cli kv put "secret/hkdfguard/$1" key=- >/dev/null
}

# put_policy <name> <pin> [<key file>...]: ConfigMap <name>-policy holding
# the scenario's policy.toml, with external_secret.dir = $MOUNT (see
# write_policy in keys.sh).
put_policy() {
    local name=$1
    shift
    write_policy "$WORK/$name.policy.toml" "$MOUNT" "$@"
    kubectl -n "$NS" create configmap "$name-policy" \
        --from-file="policy.toml=$(native_path "$WORK/$name.policy.toml")" >/dev/null
}

# put_planted <name> <key file>: Secret <name>-planted holding the key the
# planting init container copies into the shared directory.
put_planted() {
    kubectl -n "$NS" create secret generic "$1-planted" --from-file="key=$(native_path "$2")" >/dev/null
}

# start_job <name> <agentUser> <appUser> <perms> <layout> <fsGroup or -> <mode> <plant>
#   layout: whole (the app mounts the whole tmpfs emptyDir), whole-disk (the
#   same, on a disk-backed emptyDir), or subdir (a private subdirectory).
#   plant: yes to plant Secret <name>-planted's key where the agent would
#   write the real one, before the agent starts.
start_job() {
    local name=$1 agent_uid=$2 app_uid=$3 perms=$4 layout=$5 fsgroup="" mode=$7 plant=$8
    [ "$6" != - ] && fsgroup="fsGroup: $6"
    local dest=/shared/$SERVICE sub_path="" prep="" planter="" planted_volume="" medium="{ medium: Memory }"
    [ "$layout" = whole-disk ] && medium="{}"
    if [ "$layout" = subdir ]; then
        dest=/shared/hkdfguard/$SERVICE
        sub_path="subPath: hkdfguard"
        prep="
        - name: prep
          image: $IMAGE
          imagePullPolicy: Never
          command: [sh, -c, 'mkdir -m 0700 /shared/hkdfguard']
          securityContext: { runAsUser: $app_uid, runAsGroup: $app_uid }
          volumeMounts:
            - { name: shared, mountPath: /shared }"
    fi
    if [ "$plant" = yes ]; then
        # Runs as the app's own user, so the planted file passes every
        # ownership and mode check; only its fingerprint can give it away.
        # The agent's startupProbe passes on it, as it would in a real pod.
        planter="
        - name: plant
          image: $IMAGE
          imagePullPolicy: Never
          command: [sh, -c, 'cp /planted/key $dest && chmod 0400 $dest']
          securityContext: { runAsUser: $app_uid, runAsGroup: $app_uid }
          volumeMounts:
            - { name: shared, mountPath: /shared }
            - { name: planted, mountPath: /planted, readOnly: true }"
        planted_volume="
        - name: planted
          secret: { secretName: $name-planted, defaultMode: 0444 }"
    fi
    kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ConfigMap
metadata:
  name: $name
  namespace: $NS
data:
  agent.hcl: |
    pid_file = "/tmp/agent.pid"
    vault { address = "http://vault.$NS.svc:8200" }
    auto_auth {
      method "kubernetes" {
        mount_path = "auth/kubernetes"
        config = { role = "hkdfguard" }
      }
    }
    template_config { static_secret_render_interval = "5s" }
    template {
      destination = "$dest"
      perms       = "$perms"
      contents    = <<EOT
    {{ with secret "secret/data/hkdfguard/$name" }}{{ base64Decode .Data.data.key }}{{ end -}}
    EOT
    }
---
apiVersion: batch/v1
kind: Job
metadata:
  name: $name
  namespace: $NS
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: app
      automountServiceAccountToken: false # only the agent gets a token, below
      securityContext:
        $fsgroup
      initContainers:$prep$planter
        - name: vault-agent
          image: $VAULT_IMAGE
          imagePullPolicy: IfNotPresent
          restartPolicy: Always # a native sidecar: started first, stopped after the test
          command: [vault, agent, -config=/etc/vault-agent/agent.hcl]
          securityContext: { runAsUser: $agent_uid, runAsGroup: $agent_uid }
          startupProbe:
            exec: { command: [test, -s, "$dest"] }
            periodSeconds: 1
            failureThreshold: 120
          volumeMounts:
            - { name: shared, mountPath: /shared }
            - { name: agent-config, mountPath: /etc/vault-agent, readOnly: true }
            - { name: sa-token, mountPath: /var/run/secrets/kubernetes.io/serviceaccount, readOnly: true }
      containers:
        - name: test
          image: $IMAGE
          imagePullPolicy: Never
          securityContext: { runAsUser: $app_uid, runAsGroup: $app_uid }
          env:
            - { name: SERVICE, value: "$SERVICE" }
            - { name: MODE, value: "$mode" }
            - { name: MOUNT, value: "$MOUNT" }
          volumeMounts:
            - { name: shared, mountPath: $MOUNT, readOnly: true, $sub_path }
            - $POLICY_MOUNT
      volumes:
        - name: shared
          emptyDir: $medium
        - name: agent-config
          configMap: { name: $name }
        - $(policy_volume "$name-policy")$planted_volume
        - name: sa-token
          projected:
            sources:
              - serviceAccountToken: { path: token, expirationSeconds: 3600 }
YAML
}

finish_job() {
    kubectl -n "$NS" wait --for=condition=complete "job/$1" --timeout=300s >/dev/null 2>&1 \
        || echo "   (job $1 did not complete; its pod may not have started -- see below)"
    kubectl -n "$NS" logs "job/$1" -c test 2>&1 || kubectl -n "$NS" describe "job/$1"
    if ! kubectl -n "$NS" logs "job/$1" -c test 2>/dev/null | grep -q '^RESULT: '; then
        echo "   -- vault-agent log:"
        kubectl -n "$NS" logs "job/$1" -c vault-agent 2>&1 | tail -n 15
    fi
}

echo "== cluster"
kubectl config current-context
if ! kubectl get nodes -o wide; then
    echo "kubectl can't reach a cluster; enable Kubernetes in Docker Desktop and wait for it to start" >&2
    exit 1
fi

echo "== building $IMAGE, pulling $VAULT_IMAGE"
docker build -q -t "$IMAGE" -f docker/k8s/Dockerfile . || exit 1
docker pull -q "$VAULT_IMAGE" >/dev/null || exit 1

echo "== starting Vault (dev mode) in $NS"
kubectl create namespace "$NS" >/dev/null
kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ServiceAccount
metadata: { name: vault, namespace: $NS }
---
apiVersion: v1
kind: ServiceAccount
metadata: { name: app, namespace: $NS }
---
# Vault calls the TokenReview API with its own token to check an agent's.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: $CRB }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: "system:auth-delegator" }
subjects:
  - { kind: ServiceAccount, name: vault, namespace: $NS }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: vault, namespace: $NS }
spec:
  replicas: 1
  selector: { matchLabels: { app: vault } }
  template:
    metadata: { labels: { app: vault } }
    spec:
      serviceAccountName: vault
      containers:
        - name: vault
          image: $VAULT_IMAGE
          imagePullPolicy: IfNotPresent
          command: [vault, server, -dev, -dev-root-token-id=root, -dev-listen-address=0.0.0.0:8200]
          ports: [{ containerPort: 8200 }]
          readinessProbe:
            httpGet: { path: /v1/sys/health, port: 8200 }
            periodSeconds: 1
---
apiVersion: v1
kind: Service
metadata: { name: vault, namespace: $NS }
spec:
  selector: { app: vault }
  ports: [{ port: 8200 }]
YAML
kubectl -n "$NS" rollout status deploy/vault --timeout=180s || exit 1

vault_cli auth enable kubernetes >/dev/null || exit 1
vault_cli write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc >/dev/null || exit 1
printf 'path "secret/data/hkdfguard/*" { capabilities = ["read"] }\n' | vault_cli policy write hkdfguard - >/dev/null || exit 1
vault_cli write auth/kubernetes/role/hkdfguard \
    bound_service_account_names=app bound_service_account_namespaces="$NS" \
    policies=hkdfguard ttl=1h >/dev/null || exit 1

# name | agent runAsUser | app runAsUser | perms | layout | fsGroup | mode | pin | plant
#      | expected RESULT prefix | reason (- for any)
#   The vault image's own user is uid 100.
#   pin: match -- pin the delivered key (and, when rotating, the next one too)
#        other -- pin a different key: the delivered one must be refused
#        off   -- no pinning
#   plant: yes -- an init container plants a key of its own, and the real
#          key is never written to Vault (its delivery is still pending);
#          with pin match, the real key is the one pinned
#   whole-disk works: the library checks ownership, modes and whether the
#   mount is read-only, not what backs it, so a disk-backed emptyDir passes
#   as the tmpfs one does. It does leave the key on the node's disk, so
#   medium: Memory remains the better choice.
SCENARIOS="
vault-default-agent-0644|100|10001|0644|whole|-|once|match|-|refused|-
vault-same-user-whole-0400|10001|10001|0400|whole|-|once|match|-|works|-
vault-same-user-whole-disk-0400|10001|10001|0400|whole-disk|-|once|match|-|works|-
vault-same-user-subdir-0400|10001|10001|0400|subdir|-|once|match|-|works|-
vault-same-user-subdir-0444|10001|10001|0444|subdir|-|once|match|-|refused|-
vault-root-agent-fsgroup-0440|0|10001|0440|subdir|10001|once|match|-|works|-
vault-same-user-subdir-rotate|10001|10001|0400|subdir|-|rotate|match|-|rotated|-
vault-pin-mismatch|10001|10001|0400|subdir|-|once|other|-|refused|not the one pinned in policy
vault-planted-unpinned-control|10001|10001|0400|subdir|-|once|off|yes|works|-
vault-planted-pinned|10001|10001|0400|subdir|-|once|match|yes|refused|not the one pinned in policy
"

failures=0
summary=""
while IFS='|' read -r name agent app perms layout fsgroup run pin plant expected reason; do
    [ -n "$name" ] || continue
    echo
    echo "================ $name (agent uid $agent, app uid $app, perms $perms, $layout, fsGroup $fsgroup, pin $pin, plant $plant)"
    key=$WORK/$name.key next=$WORK/$name.next.key
    new_key "$key" && new_key "$next" || exit 1
    case $pin in
        match) put_policy "$name" pin "$key" "$next" ;; # the next key is only ever delivered by rotation
        other) put_policy "$name" pin "$next" ;;
        *) put_policy "$name" "$pin" ;;
    esac
    if [ "$plant" = yes ]; then
        planted=$WORK/$name.planted.key
        new_key "$planted" || exit 1
        put_planted "$name" "$planted"
        echo "   real key $(fingerprint "$key") not delivered; planted key $(fingerprint "$planted")"
    else
        echo "   delivered key fingerprint: $(fingerprint "$key")"
        put_secret "$name" "$key"
    fi
    start_job "$name" "$agent" "$app" "$perms" "$layout" "$fsgroup" "$run" "$plant"

    if [ "$run" = rotate ]; then
        for _ in $(seq 1 180); do
            kubectl -n "$NS" logs "job/$name" -c test 2>/dev/null | grep -q READY_FOR_ROTATION && break
            sleep 1
        done
        echo "   writing a new key version to Vault for $name, fingerprint $(fingerprint "$next")"
        put_secret "$name" "$next"
    fi

    out=$(finish_job "$name")
    printf '%s\n' "$out" | sed 's/^/   /'
    result=$(printf '%s\n' "$out" | sed -n 's/^RESULT: //p' | tail -n 1)
    v=$(verdict "$out" "$result" "$expected" "$reason")
    [ "$v" = "as expected" ] || failures=$((failures + 1))
    summary+=$(printf '\n  %-31s %-45s %s' "$name" "${result:-no result}" "$v")
done <<<"$SCENARIOS"

echo
echo "Summary:$summary"
[ "$failures" -eq 0 ] && echo "Every scenario behaved as expected." || echo "$failures scenario(s) did not behave as expected."
exit "$failures"

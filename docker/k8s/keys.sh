# Shared by run-tests.sh and run-vault-tests.sh (sourced, not run): KEKs
# made the way docs/configuration.md tells operators to make them, and the
# per-scenario policy that pins them.
#
# Keys are SEC1 DER from OpenSSL, and their fingerprints are computed with
# the documented OpenSSL pipeline -- on this machine, before the key is
# delivered -- so the tests exercise exactly the commands the docs give.

if ! command -v openssl >/dev/null 2>&1; then
    echo "these tests need openssl on this machine, to generate and fingerprint KEKs" >&2
    exit 1
fi

# A path openssl can open. Git for Windows' openssl is a native Windows
# program, and run-vault-tests.sh turns off Git Bash's path conversion
# (MSYS_NO_PATHCONV), so convert explicitly; elsewhere, the path as given.
openssl_path() { cygpath -m "$1" 2>/dev/null || echo "$1"; }

# new_key <file>: a fresh P-256 KEK, SEC1 DER, readable only by this user.
new_key() {
    ( umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform DER -out "$(openssl_path "$1")" )
}

# fingerprint <file>: the KEK's fingerprint, as policy pins it.
fingerprint() {
    openssl pkey -inform DER -in "$(openssl_path "$1")" -pubout -outform DER | tail -c 65 | sha256sum | cut -d' ' -f1
}

# write_policy <file> <dir or -> <pin> [<key file>...]
#   pin: off   -- no pinning at all (require_pinned_keys = false, no pins)
#        none  -- require_pinned_keys = true, and no pin for $SERVICE
#        pin   -- require_pinned_keys = true, $SERVICE pinned to the
#                 fingerprints of the key files given
write_policy() {
    local file=$1 dir=$2 pin=$3
    shift 3
    {
        printf 'security_model = "developer"\n[selection]\nmode = "require"\nprovider = "external-secret"\n'
        printf '[external_secret]\n'
        [ "$dir" != - ] && printf 'dir = "%s"\n' "$dir"
        if [ "$pin" = off ]; then
            printf 'require_pinned_keys = false\n'
        else
            printf 'require_pinned_keys = true\n'
        fi
        if [ "$pin" = pin ]; then
            local fps="" key
            for key in "$@"; do
                fps+="${fps:+, }\"$(fingerprint "$key")\""
            done
            printf '[external_secret.pinned_keys]\n"%s" = [%s]\n' "$SERVICE" "$fps"
        fi
    } > "$file"
}

# The ConfigMap volume and mount that put a scenario's policy at
# /etc/hkdfguard/policy.toml. Read-only, as any secret or config volume
# should be: the library accepts the volume's world-writable directory only
# because nothing can write through a read-only mount.
POLICY_MOUNT='{ name: policy, mountPath: /etc/hkdfguard, readOnly: true }'
policy_volume() { printf '{ name: policy, configMap: { name: %s } }' "$1"; }

# verdict <pod output> <RESULT line> <expected RESULT prefix> <reason or ->:
# whether the scenario behaved as expected. A reason must also appear in
# the pod's output, so a refusal only counts when it was refused for the
# reason the scenario is about.
verdict() {
    local out=$1 result=$2 expected=$3 reason=$4
    if [ -z "$result" ] || [ "${result#"$expected"}" = "$result" ]; then
        echo "UNEXPECTED (expected: $expected)"
    elif [ "$reason" != - ] && ! printf '%s\n' "$out" | grep -qF -- "$reason"; then
        echo "UNEXPECTED (expected the reason: $reason)"
    else
        echo "as expected"
    fi
}

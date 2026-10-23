# Running HKDFGuard's tests and builds in Docker

This crate's TPM2 and PKCS#11 providers can't be built or tested on
macOS (`tss-esapi-sys` only ships
pregenerated bindings for specific Linux target tuples, and there's no TPM
or PKCS#11 module to talk to). This directory gives you a real Linux
environment with `tpm2-tss`, `swtpm` (a software TPM2 simulator), and
`SoftHSM2` (a software PKCS#11 token) so every provider can actually be
built, linked, and exercised end-to-end.

## Run everything

```sh
docker/run-tests.sh
```

This builds the image and runs [`entrypoint-test.sh`](entrypoint-test.sh).
The container starts as root only to install root-owned configuration
under `/etc/hkdfguard` and start `swtpm`; every build, test, and run of
the library or CLI happens as `ci`, an unprivileged user in the `tss`
group. That is what makes the ownership checks testable: as root every
file is root-owned, so there would be nothing to refuse. The image sets
`HKDFGUARD_TESTS_MUST_NOT_RUN_AS_ROOT=1`, so those tests fail rather than
skip if they ever run as root. Key files, policies, secrets and PIN files
the script and the tests write go in private directories under `/work`
(owned by `ci`) and `<target>/tmp/hkdfguard-tests`, never under `/tmp`: the
library refuses anything it reads anywhere under a sticky, world-writable
directory, and the CLI refuses to write a key file or read a `--dek-file`
there. [`run-tests.sh`](run-tests.sh) also mounts a read-only volume at
`/run/hkdfguard-ro-secrets` whose root is `1777`, like a Kubernetes Secret
volume, to prove the one exception: a read-only mount is accepted. The
script:

1. `cargo build` / `cargo test` with the default features (external-secret,
   ephemeral) -- unit tests plus the CLI integration tests
   in [`tests/cli_round_trip.rs`](../tests/cli_round_trip.rs),
   which drive the `hkdfguard` binary as a real subprocess.
2. `cargo build --features tpm2,pkcs11` -- confirms this crate actually
   *links* against real `libtss2-esys` and the PKCS#11 loader (only
   type-checking, not linking, can be verified outside Docker).
3. Starts `swtpm`, sends `TPM2_Startup`, and runs the `#[ignore]`d TPM2
   test against it.
4. Initializes a `SoftHSM2` token and runs the `#[ignore]`d PKCS#11 test
   against it.
5. Builds `libhkdfguard.so` in release mode and runs
   [`examples/wrap_unwrap.c`](../examples/wrap_unwrap.c) against it.
6. Runs `hkdfguard` (release build) to wrap a fresh random
   DEK to a file, then runs
   [`examples/cli_unwrap_check.c`](../examples/cli_unwrap_check.c), which
   loads `libhkdfguard.so` dynamically and confirms it
   unwraps that file back to the exact same DEK -- proving the CLI's
   output isn't tied to being read back by the same (statically-linked)
   binary that wrote it.

Exits non-zero (and stops at the failing section) if anything fails.

## Test across distributions (SoftHSM2 + Ephemeral)

```sh
docker/run-distro-tests.sh                        # every distribution
docker/run-distro-tests.sh alpine-3.24 sles-16.0  # a subset
docker/run-distro-tests.sh --list                 # the names
JOBS=3 docker/run-distro-tests.sh                 # three at a time
docker/distros/test-sles-16.0.sh                  # one, output streamed
```

Every distribution has its own `docker/distros/test-<name>.sh`.
`docker/run-all-tests.sh` runs `run-tests.sh` and then this whole matrix:
the fleet [CONTRIBUTING.md](../CONTRIBUTING.md) asks every change to pass.

Proves the PKCS#11 (SoftHSM2) and Ephemeral providers on each
distribution's own libc, toolchain and SoftHSM2 build, one container
each:

| Name | Base image | SoftHSM2 from |
|---|---|---|
| `almalinux-9`, `almalinux-10` | `almalinux` | AppStream |
| `debian-12`, `debian-13` | `debian` | main |
| `ubuntu-24.04`, `ubuntu-26.04` | `ubuntu` | universe |
| `sles-15.7` | `registry.suse.com/bci/bci-base:15.7` | built from pinned upstream source |
| `sles-16.0` | `registry.suse.com/bci/bci-base:16.0` | openSUSE Backports (SUSE Package Hub's packages), signing key pinned |
| `ubi9-micro`, `ubi10-micro` | `registry.access.redhat.com/ubi{9,10}/ubi-micro` | built from pinned upstream source |
| `amazonlinux-2023` | `amazonlinux` | core repository |
| `alpine-3.24` | `alpine` (musl) | community |

SLES runs on SUSE's freely redistributable BCI images, which are real
SLES binaries without a subscription, but carry only part of SLES's
package set; softhsm is not in it (see
[`distros/Dockerfile.zypper`](distros/Dockerfile.zypper)). Alpine builds
with `-C target-feature=-crt-static`: a static musl binary cannot
`dlopen()` a PKCS#11 module, and rustc will not build the cdylib at all.

UBI Micro has no package manager, compiler, `find` or `useradd`, so
[`distros/Dockerfile.ubi-micro`](distros/Dockerfile.ubi-micro) assembles
it the way Red Hat documents: a full UBI image of the same release
installs packages into a copy of Micro's root filesystem
(`dnf --installroot`) and, in the same builder stage, compiles the
release library, the C consumers and every test executable
([`distros/build-artifacts.sh`](distros/build-artifacts.sh)). The final
image runs those prebuilt (`HKDFGUARD_PREBUILT=1`): the same tests, minus
cargo. It adds to stock Micro only SoftHSM2 and its libraries
(`openssl-libs`, `libstdc++`), plus `util-linux` and `grep` for the
harness. An extra check asserts that the release library and CLI link
nothing beyond glibc and `libgcc_s`, so they run on unmodified Micro.

Each base image is pinned by digest in the script's matrix, as is every
download (rustup-init, the SoftHSM2 source, the Backports key). The
images come from one Dockerfile per package-manager family
([`distros/`](distros/)), which installs the distribution's packages and
then runs the shared
[`distros/prepare-image.sh`](distros/prepare-image.sh) (pinned Rust
toolchain, the unprivileged `ci` user).
[`distros/entrypoint-distro-test.sh`](distros/entrypoint-distro-test.sh)
then, as `ci`:

1. Builds with `--features pkcs11` and runs the default-feature tests,
   including the ephemeral provider's unit tests.
2. Initializes a SoftHSM2 token and runs the test build
   (`--cfg hkdfguard_test_paths`) suite, then the `#[ignore]`d PKCS#11
   tests against the token.
3. Builds the release library and CLI, then checks them against a
   root-owned `/etc/hkdfguard/policy.toml`, as a deployment installs it:
   - with no policy, no provider is available: ephemeral is never a
     silent fallback;
   - with `provider = "ephemeral"`, `examples/wrap_unwrap.c` round-trips,
     and [`distros/ephemeral_cross_process.c`](distros/ephemeral_cross_process.c)
     shows a payload wrapped by one process cannot be unwrapped by the
     next (the KEK dies with the process);
   - with `provider = "pkcs11"` and a `root:ci 0440` PIN file, the CLI
     provisions and wraps, a separate process unwraps through the `.so`,
     and a world-readable PIN file is refused.

Nothing is left in Docker afterwards. Each distribution's image is
removed as soon as its run ends, pass or fail. On exit, including Ctrl-C,
running builds and containers are stopped and removed, along with any
pinned base image the run itself pulled; images that were already
present are never touched. `docker/run-tests.sh` cleans up the same way.
Set `KEEP_IMAGES=1` to keep the images for debugging. BuildKit's build
cache is kept so reruns are fast; `docker builder prune` reclaims it,
for every project on the machine, not only this one.

The TPM2 provider is not part of this matrix: it needs tpm2-tss 4.x and
has the swtpm suite above. All distributions run even when one fails;
the summary lists each result and its log under `target/distro-tests/`.
The images run on the Docker host's native architecture; set
`PLATFORM=linux/amd64` (or `linux/arm64`) to test the other one under
QEMU emulation, which is much slower.

## Test the external-secret provider on Kubernetes

```sh
docker/k8s/run-tests.sh         # keys delivered as Kubernetes Secret volumes
docker/k8s/run-vault-tests.sh   # keys delivered by a Vault Agent sidecar
```

These run the external-secret provider against a real cluster, so the
secret files are laid out by the kubelet and by Vault Agent themselves,
not by a simulation. Neither suite is part of `docker/run-all-tests.sh` or
CI: run them yourself before changing how the provider reads its mount, or
how the docs tell operators to deliver and pin keys.

**What you need**

- `kubectl` pointing at a cluster that shares the local Docker engine's
  images. Docker Desktop's built-in Kubernetes does: each script builds
  `hkdfguard-k8s-test:local` from [`k8s/Dockerfile`](k8s/Dockerfile) and
  runs it with `imagePullPolicy: Never`. A cluster with its own image
  store (kind, minikube) won't find the image.
- `openssl` on the machine running the script: keys are made and
  fingerprinted there, with the commands
  [docs/configuration.md](../docs/configuration.md#external-secret-file)
  gives operators.
- For the Vault suite: rights to create a ClusterRoleBinding (Vault needs
  `system:auth-delegator` to check service-account tokens), and the
  `hashicorp/vault:1.19.0` image, which the script pulls.
- Bash. On Windows, Git Bash works; the scripts convert paths for
  `kubectl.exe` and OpenSSL.

**What a scenario does.** Each one is a Job. The script generates a P-256
key (SEC1 DER) and computes its fingerprint, then delivers the key: as a
Secret volume, or by storing it in a Vault dev server for a Vault Agent
native sidecar to render into a shared `emptyDir`. It also creates the
scenario's `policy.toml` as a ConfigMap, mounted read-only over
`/etc/hkdfguard`, which is how a deployment would ship it. In the pod,
[`k8s/pod-test.sh`](k8s/pod-test.sh) prints the policy and the mount's
layout, then runs `hkdfguard provision`, wraps a fresh DEK with
`hkdfguard wrap`, and unwraps it in a separate process through
`libhkdfguard.so`. It ends with one `RESULT:` line.

Most scenarios pin the delivered key (`require_pinned_keys = true`, with
its fingerprint in `pinned_keys`), as the docs recommend. What the others
vary:

| Suite | Scenarios |
|---|---|
| Secret volume | the pod's user and `fsGroup`, and the Secret's `defaultMode` (`0400`, `0440`, `0444`); rotating the Secret while the pod runs; no pinning; pinning a different key; `require_pinned_keys` with no pin; `external_secret.dir` set to the mount, and set to a path that isn't mounted |
| Vault Agent | the agent's user and the template's `perms`; a tmpfs or disk-backed `emptyDir`, mounted whole or as a private subdirectory; a root agent with `fsGroup`; a new key version in Vault mid-run; pinning a different key; a key **planted** in the shared directory, by a container running as the app's user, while the real key is still undelivered |

Every Vault scenario sets `external_secret.dir = "/vault/secrets/hkdfguard"`,
the configuration.md pinning example. The two planted-key scenarios are a
pair: unpinned, the planted key is used, which shows the attack works;
pinned, it is refused.

**Reading the results.** Each scenario lists the `RESULT` it expects. For
refusals that are the point of a scenario, it also lists a reason that must
appear in the pod's output, such as `not the one pinned in policy`. A
refusal for any other reason counts as a failure. The summary marks each
scenario `as expected` or `UNEXPECTED`, and the exit code is the number of
unexpected ones. The full pod output is printed above the summary, along
with the Vault Agent's log when a pod reported no result.

Each suite runs in its own namespace (`hkdfguard-k8stest`,
`hkdfguard-vaulttest`), and the Vault suite also creates the
ClusterRoleBinding `hkdfguard-vaulttest-tokenreview`. All of these are
deleted when the script exits. The test image stays in the local
Docker engine, and the next run rebuilds it.

## Build a distributable release

```sh
docker/build-dist.sh
```

Builds two images -- `linux/amd64` and `linux/arm64` -- from the same
`docker/Dockerfile` `run-tests.sh` uses (the non-native one runs under
QEMU emulation, transparently on a normal Docker Desktop install), and
runs [`entrypoint-build.sh`](entrypoint-build.sh) inside each, which:

1. Runs `cargo test` (default features), then `cargo test --all-features`
   -- a fast sanity gate (unit/integration tests, plus confirming the
   all-features build actually links against `libtss2-esys` and the
   PKCS#11 loader) rather than the full swtpm/SoftHSM2 hardware matrix
   above; run `docker/run-tests.sh` separately before a real release if you
   want that stronger guarantee.
2. Runs `cargo build --release --all-features`, so the distributed library
   supports every KEK provider (TPM2, PKCS#11, external secret, ephemeral),
   not just the ones enabled by default.
3. Copies `libhkdfguard.so`,
   `libhkdfguard.a`, the `hkdfguard` CLI
   binary, and `include/hkdfguard.h` into `/dist` inside the container,
   which `build-dist.sh` bind-mounts to `dist/linux-amd64` or
   `dist/linux-arm64` on the host respectively -- so each architecture's
   four files land in its own subdirectory once the script finishes:

   ```
   dist/
     linux-amd64/
       hkdfguard
       hkdfguard.h
       libhkdfguard.a
       libhkdfguard.so
     linux-arm64/
       hkdfguard
       hkdfguard.h
       libhkdfguard.a
       libhkdfguard.so
   ```

## Interactive use

```sh
docker build -t hkdfguard-test -f docker/Dockerfile .
docker run --rm -it --entrypoint bash hkdfguard-test
```

From there you have a full Linux Rust toolchain plus `tpm2-tools`,
`swtpm`, and `softhsm2-util` to explore manually, e.g.:

```sh
# start swtpm + TPM2_Startup, then:
cargo test --features tpm2 -- --ignored --test-threads=1

# init a SoftHSM2 token, then:
cargo test --features pkcs11 -- --ignored --test-threads=1
```

(see the corresponding sections of `entrypoint-test.sh` for the exact
commands).

## Testing against a real hardware TPM instead of swtpm

If the Docker host has a real TPM2 device, pass it through instead of
relying on the container's `swtpm`:

```sh
docker run --rm --device=/dev/tpmrm0 \
    -e TCTI=device:/dev/tpmrm0 \
    --entrypoint bash hkdfguard-test
```

then run `cargo test --features tpm2 -- --ignored --test-threads=1`
inside. Note this gives the container access to the host's real TPM state
-- keys it creates are real and persist in TPM NV/derivation state exactly
as they would outside Docker.

## TPM conformance suite (multi-container, persistent swtpm)

`src/provider/tpm2.rs`'s `mod tests` includes a `#[ignore]`d conformance
suite that empirically validates the assumptions the TPM2 provider's
whole persistence model depends on (deterministic `TPM2_CreatePrimary`,
distinct keys per service, ECDH repeatability, ...) -- see that module's
doc comments. `docker/run-tests.sh` already runs it against a swtpm
instance that lives and dies with that one container. For a setup where
swtpm keeps running (or gets restarted) independently of the test runner
-- e.g. to test persistence across a TPM restart -- use the multi-container
setup instead:

```sh
docker compose -f docker/docker-compose.yml up --build --abort-on-container-exit
docker compose -f docker/docker-compose.yml down -v   # also drops the persisted TPM state volume
```

`scripts/tpm-reboot-test.sh` approximates reboot-persistence testing more
directly: it starts swtpm with persistent state, captures a primary key's
public area and TPM Name, stops and restarts swtpm against that same
state, and asserts both captures are identical. Run it from a shell that
has `swtpm`/`tpm2-tools` on PATH (the container from `docker/Dockerfile`
qualifies).

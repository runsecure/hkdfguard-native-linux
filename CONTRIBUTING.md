# Contributing to HKDFGuard (Linux)

HKDFGuard protects key material, and it runs on many Linux
distributions with different libcs, toolchains and PKCS#11 builds. A
change that passes on your machine can still break on one of them, so
every change is expected to pass the full fleet of containerized tests
before it is merged.

## Before you open a pull request

Run the whole fleet (needs Docker):

```sh
JOBS=3 docker/run-all-tests.sh
```

This runs, in order:

1. **The full matrix** (`docker/run-tests.sh`) on Ubuntu 24.04: TPM2
   against swtpm, PKCS#11 against SoftHSM2, external-secret, the C ABI
   and the CLI.
2. **The distribution fleet** (`docker/run-distro-tests.sh`): the
   SoftHSM2 (PKCS#11) and Ephemeral suites, plus release builds configured
   through a root-owned policy, on each distribution below.

Each distribution also has its own script, which streams its output.
Use these while iterating on a fix:

| Distribution | Script |
|---|---|
| AlmaLinux 9 | `docker/distros/test-almalinux-9.sh` |
| AlmaLinux 10 | `docker/distros/test-almalinux-10.sh` |
| Debian 12 | `docker/distros/test-debian-12.sh` |
| Debian 13 | `docker/distros/test-debian-13.sh` |
| Ubuntu 24.04 | `docker/distros/test-ubuntu-24.04.sh` |
| Ubuntu 26.04 | `docker/distros/test-ubuntu-26.04.sh` |
| SLES 15 SP7 | `docker/distros/test-sles-15.7.sh` |
| SLES 16.0 | `docker/distros/test-sles-16.0.sh` |
| Red Hat UBI 9 Micro | `docker/distros/test-ubi9-micro.sh` |
| Red Hat UBI 10 Micro | `docker/distros/test-ubi10-micro.sh` |
| Amazon Linux 2023 | `docker/distros/test-amazonlinux-2023.sh` |
| Alpine 3.24 (musl) | `docker/distros/test-alpine-3.24.sh` |

Logs land in `target/distro-tests/`. The scripts remove every image and
container they create, even when interrupted, so the fleet leaves
nothing behind in Docker (`KEEP_IMAGES=1` keeps the images for
debugging). The suites run on your Docker
host's native architecture. If your change touches anything
architecture-specific, also run the fleet with `PLATFORM=linux/amd64` or
`PLATFORM=linux/arm64` for the other one; it runs under QEMU emulation,
so it is much slower.

Say in the pull request what you ran and on which architecture. The pull
request template has a checklist for it.

## Adding a distribution

1. Add a row to the matrix in `docker/run-distro-tests.sh`: a name, the
   Dockerfile family (`apt`, `dnf`, `zypper`, `apk`, `ubi-micro`), and the
   base image pinned by digest (`docker buildx imagetools inspect
   <image:tag>`).
2. Add `docker/distros/test-<name>.sh` (copy an existing one) and a row
   to the table above and to the one in `docker/README.md`.
3. Run `docker/distros/test-<name>.sh` until it passes.

A distribution with a new package manager needs a new
`docker/distros/Dockerfile.<family>`. It installs that distribution's
packages (a C compiler, curl, SoftHSM2, util-linux's `setpriv`,
`useradd`) and then runs `docker/distros/prepare-image.sh`. An image
with no toolchain or package manager follows `Dockerfile.ubi-micro`:
build in a builder stage (`docker/distros/build-artifacts.sh`) and run
the tests prebuilt.

## Updating pinned versions

Base images, rustup-init, the SoftHSM2 source tarball and the openSUSE
Backports signing key are all pinned by checksum or digest. Re-resolve
them deliberately, never by dropping a pin; the comment beside each pin
says how. The Rust toolchain version lives in `rust-toolchain.toml` and
must match `docker/distros/prepare-image.sh`, `docker/Dockerfile` and
`packaging/Dockerfile.*`.

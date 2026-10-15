# Installing HKDFGuard on Linux

HKDFGuard for Linux ships in three forms. Pick one per host:

| Form | Use it when | Gives you |
|---|---|---|
| [Packages](#packages-deb-and-rpm) (`.deb`, `.rpm`) | Installing on a server or VM | The library, the `hkdfguard` CLI, development files, man page, example policy |
| [Standalone tarball](#standalone-tarball) | No package fits (another distribution, a custom layout) | The same library and CLI as plain files |
| [Container overlay image](#container-overlay-image) | Building a container image | Only the library and the CLI, at their installed paths |

After installing, configure the host ([configuration.md](configuration.md)), then
provision a key and wrap a DEK ([usage.md](usage.md)).

## Requirements

- **Architecture:** x86_64 (amd64) or aarch64 (arm64).
- **tpm2-tss 4.x** runtime libraries. Every build links them, even on hosts
  without a TPM. That is why Debian 12, RHEL 9, SLES 15 and Amazon Linux 2
  (all tpm2-tss 3.x or older) are not supported.
- **glibc 2.39 or newer** for the standalone tarball and the container
  overlay. The packages are each built on their own distribution.

Supported distributions: **Debian 13**, **Ubuntu 24.04**, **RHEL 10** and
compatibles (AlmaLinux, Rocky), **Amazon Linux 2023**, **SLES 16** and
**openSUSE Leap 16**.

## Download and verify

Releases are published on the repository's
[Releases page](https://github.com/runsecure/hkdfguard-native-linux/releases).
Each release contains:

| File | Contents |
|---|---|
| `hkdfguard-<version>-<distro>-<arch>.tar.gz` | The packages for one distribution: `<distro>` is `debian`, `ubuntu24.04`, `el10`, `al2023` or `sles16`; `<arch>` is `amd64` or `arm64` |
| `hkdfguard-<version>-linux-<arch>.tar.gz` | The standalone library, CLI and header |
| `SHA256SUMS` | Checksums of every tarball |
| `hkdfguard-<version>.sigstore.json` | The signed build-provenance attestation, for offline verification |

Every file, and every package and binary inside the tarballs, has a
[Sigstore](https://www.sigstore.dev/) build-provenance attestation, signed by
the repository's release workflow. Verify before installing:

```sh
sha256sum --check --ignore-missing SHA256SUMS

# Needs the GitHub CLI (https://cli.github.com). Works on a tarball, or on a
# .deb, .rpm or binary taken out of one.
gh attestation verify hkdfguard-0.1.0-ubuntu24.04-amd64.tar.gz \
    --repo runsecure/hkdfguard-native-linux
```

Without network access to GitHub, add
`--bundle hkdfguard-<version>.sigstore.json`. A successful verification proves
the file was built by this repository's release workflow from the tagged
commit.

## Packages (.deb and .rpm)

The release tarball for your distribution holds these packages:

| Debian, Ubuntu | RHEL 10, Amazon Linux 2023 | SLES 16 | Contents |
|---|---|---|---|
| `libhkdfguard1` | `hkdfguard-libs` | `libhkdfguard1` | The shared library `libhkdfguard.so.1`, an empty `/etc/hkdfguard` (root, `0755`), the example policy |
| `hkdfguard` | `hkdfguard` | `hkdfguard` | The `hkdfguard` CLI and its man page |
| `libhkdfguard-dev` | `hkdfguard-devel` | `hkdfguard-devel` | `hkdfguard.h`, `libhkdfguard.so`, `hkdfguard.pc` (only for building software against the library) |
| (in `libhkdfguard-dev`) | `hkdfguard-static` | `hkdfguard-devel-static` | The static library `libhkdfguard.a` |

`hkdfguard` requires the same version of the library package, so install them
together. Install the development packages only on build machines.

**Debian and Ubuntu**

```sh
tar -xzf hkdfguard-0.1.0-ubuntu24.04-amd64.tar.gz
cd hkdfguard-0.1.0-ubuntu24.04-amd64
sudo apt install ./libhkdfguard1_*.deb ./hkdfguard_*.deb
```

Keep the `./`: without it, apt looks for the names in its repositories
instead of using the local files.

**RHEL 10 and compatibles, Amazon Linux 2023**

```sh
tar -xzf hkdfguard-0.1.0-el10-amd64.tar.gz
cd hkdfguard-0.1.0-el10-amd64
sudo dnf install ./hkdfguard-libs-0*.rpm ./hkdfguard-0*.rpm
```

On RHEL and AlmaLinux, `hkdfguard-devel` also needs `tpm2-tss-devel` from
the CRB repository (`sudo dnf config-manager --set-enabled crb`).

**SLES 16 and openSUSE Leap 16**

```sh
tar -xzf hkdfguard-0.1.0-sles16-amd64.tar.gz
cd hkdfguard-0.1.0-sles16-amd64
sudo zypper install --allow-unsigned-rpm ./libhkdfguard1-*.rpm ./hkdfguard-0*.rpm
```

The packages in a release are not signed individually; their integrity comes
from the attestation and checksums you verified above, so zypper needs
`--allow-unsigned-rpm` for these local files.

**Check the installation**

```sh
hkdfguard --help
ls -l /usr/share/hkdfguard/policy.toml.example
```

The packages install no policy, derivation secret or PIN file: those are
per-host decisions. With no policy the library uses its defaults, described
in [configuration.md](configuration.md).

## Standalone tarball

`hkdfguard-<version>-linux-<arch>.tar.gz` contains:

```
hkdfguard-<version>-linux-<arch>/
  lib/libhkdfguard.so.1          the shared library (its SONAME)
  lib/libhkdfguard.so            link for compiling with -lhkdfguard
  lib/libhkdfguard.a             the static library
  bin/hkdfguard    the CLI
  include/hkdfguard.h            the C header
  LICENSE, THIRD-PARTY-LICENSES.txt
```

It was built on Ubuntu 24.04, so it needs glibc 2.39 or newer and the
tpm2-tss 4.x runtime libraries from your distribution (on Debian and Ubuntu:
`libtss2-esys-3.0.2-0t64`, `libtss2-mu-4.0.1-0t64`, `libtss2-tctildr0t64`).
To install it under `/usr/local`:

```sh
tar -xzf hkdfguard-0.1.0-linux-amd64.tar.gz
cd hkdfguard-0.1.0-linux-amd64
sudo install -m 0644 lib/libhkdfguard.so.1 /usr/local/lib/
sudo ln -sf libhkdfguard.so.1 /usr/local/lib/libhkdfguard.so
sudo install -m 0755 bin/hkdfguard /usr/local/bin/
sudo install -m 0644 include/hkdfguard.h /usr/local/include/
sudo install -d -m 0755 -o root -g root /etc/hkdfguard
sudo ldconfig
```

If you distribute software that includes these binaries, ship `LICENSE` and
`THIRD-PARTY-LICENSES.txt` with it: the binaries statically link Rust crates
whose licenses require their notices to accompany them.

## Container overlay image

Each release publishes a `FROM scratch` image that holds only the binaries,
at the paths the Ubuntu 24.04 packages use, for copying into your own image:

```
/usr/lib/<multiarch>/libhkdfguard.so.1
/usr/bin/hkdfguard
```

| Image | Policy |
|---|---|
| `ghcr.io/runsecure/hkdfguard-overlay:<version>` | None: the library's defaults. Add your own `/etc/hkdfguard/policy.toml`. |
| `ghcr.io/runsecure/hkdfguard-overlay:<version>-dev` | A development policy: SoftHSM2 when `/etc/hkdfguard/pkcs11.pin` exists, otherwise **ephemeral keys, lost when the process exits**. Never use it in production. |

```dockerfile
FROM ubuntu:24.04
# The library's runtime dependencies.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libtss2-esys-3.0.2-0t64 libtss2-mu-4.0.1-0t64 libtss2-tctildr0t64 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/runsecure/hkdfguard-overlay:0.1.0 / /
```

Things to know:

- **Debian-family images only**, with glibc 2.39 or newer (Ubuntu 24.04+,
  Debian 13). RPM-based images and Alpine (musl) should install the packages
  instead.
- **dpkg doesn't know about the copied files**, so installing the
  `libhkdfguard1` package later in the same image conflicts with them.
  Update by changing the image tag.
- **License notices aren't in the image.** If you distribute an image that
  contains it, add `LICENSE` and `THIRD-PARTY-LICENSES.txt` from the
  release's `linux-<arch>` tarball.
- **Verify the image** before using it:

  ```sh
  gh attestation verify oci://ghcr.io/runsecure/hkdfguard-overlay:0.1.0 \
      --repo runsecure/hkdfguard-native-linux
  ```

## Building from source

Building needs Rust (the version pinned in `rust-toolchain.toml`, which
rustup installs automatically), a C compiler, `pkg-config` and the tpm2-tss
development headers (`libtss2-dev` on Debian and Ubuntu).

```sh
git clone https://github.com/runsecure/hkdfguard-native-linux.git
cd hkdfguard-native-linux
cargo build --release --all-features    # tpm2 and pkcs11 are not in the default features
```

The library is `target/release/libhkdfguard_v1.so` (Cargo can't produce the
installed name); `scripts/build-release.sh` builds it and adds the
`libhkdfguard.so.1` name. To build the packages themselves, with tests and a
smoke test in a clean container for each distribution, use Docker:

```sh
packaging/build-packages.sh                                # every distribution, amd64 and arm64
DISTROS=ubuntu24.04 ARCHES=amd64 packaging/build-packages.sh   # just one
```

The packages land in `dist/packages/<distro>-<arch>/`.

## Uninstalling

```sh
sudo apt purge libhkdfguard1 hkdfguard            # Debian, Ubuntu
sudo dnf remove hkdfguard hkdfguard-libs          # RHEL, Amazon Linux
sudo zypper remove hkdfguard libhkdfguard1        # SLES
```

Removing the packages leaves `/etc/hkdfguard/policy.toml`, the derivation
secret and any other files you created there. **Keep the derivation secret
and your key material if you may need to unwrap existing DEKs later**: see
[configuration.md](configuration.md#back-up-the-derivation-secret).

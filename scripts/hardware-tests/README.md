# Hardware tests

Qualifies hkdfguard on a machine other than the development box: a laptop
with a different TPM, or a Hyper-V guest with a virtual TPM. It produces the
evidence behind the TPM entries in the README's build and verification
matrix.

`docker/run-tests.sh` and CI test against `swtpm`.
`scripts/native-tpm-test.sh` runs the same matrix against a real TPM, but
builds from source on that machine. This harness runs that matrix from
prebuilt binaries, so the target needs no Rust toolchain or headers, only the
tpm2-tss runtime libraries. Before testing, it records the host and the TPM,
and it can drive several targets over SSH.

## Steps

1. On a Linux build machine (or WSL), make the bundle:

   ```sh
   scripts/hardware-tests/make-bundle.sh            # builds on this host
   scripts/hardware-tests/make-bundle.sh --docker   # or in docker/Dockerfile's Ubuntu 24.04 image
   ```

   This writes `build-hardware-tests/hkdfguard-hardware-tests-<version>-<arch>.tar.gz`.
   It contains the CLI, `libhkdfguard.so`, every test executable, the C
   consumers, `tpm-probe.sh` and `run-hardware-tests.sh`.

   The bundle runs on the distribution it was built on, and on newer ones,
   because glibc and tpm2-tss are linked dynamically. A `--docker` bundle
   runs on Ubuntu 24.04+, Debian 13, RHEL 10 and their relatives. For Debian
   12, RHEL 9 or SLES 15, build on that distribution (or the oldest one you
   will test). `MANIFEST` in the bundle names the oldest glibc it needs.
   On RHEL 9, `tpm2-tss-devel` is in CodeReady Builder, not BaseOS or
   AppStream: enable it first with `sudo subscription-manager repos
   --enable codeready-builder-for-rhel-9-$(uname -m)-rpms`.

2. Prepare each target:

   - Install `tpm2-tools`. The probe needs it, and it pulls in the tpm2-tss
     libraries the bundle links against. Install SoftHSM2 too (`softhsm2`;
     `softhsm` on RHEL and Fedora) if the PKCS#11 suite should run.
   - Use an ordinary user in the `tss` group: `sudo usermod -aG tss <user>`,
     then log in again. Don't use root, because the tests that prove another
     user's file is refused skip as root. The runner refuses root unless
     given `--allow-root`.
   - Hyper-V guests: on the host, from an elevated PowerShell, run
     `scripts\hardware-tests\Enable-HyperVTpm.ps1 -VMName <vm>,<vm>`. It
     enables a vTPM on each Generation 2 VM, takes a `pre-hkdfguard`
     checkpoint, and prints the guest's address.

3. Run it on the target in one of two ways.

   Over SSH, for one or many targets. Run this from Linux, WSL, or Git Bash
   on the Hyper-V host:

   ```sh
   scripts/hardware-tests/run-remote.sh user@10.0.0.21 user@10.0.0.22
   ```

   Each target's log comes back to `build-hardware-tests/logs/<host>/`.

   By hand: copy the tarball over, then:

   ```sh
   tar xzf hkdfguard-hardware-tests-*.tar.gz
   hkdfguard-hardware-tests/run-hardware-tests.sh
   ```

   Bring back `hardware-tests-<host>.log` and `tpm-capabilities-<host>.txt`
   from the bundle folder.

4. Optionally, check persistence across a real power cycle. For a VM, stop
   and start it rather than rebooting from inside the guest:

   ```sh
   run-remote.sh --args "reboot capture" user@host   # then power-cycle the target
   run-remote.sh --args "reboot verify"  user@host
   ```

   `reboot clean` deletes the saved state without verifying.

Set `HKDFGUARD_TCTI` to test something other than `/dev/tpmrm0`. If the TPM's
Owner hierarchy has a password, set `HKDFGUARD_TPM_OWNER_AUTH_FILE` to a
private file holding it. The probe fails with a pointer to this variable when
the hierarchy has a password and the variable is unset.

## What the run does

| Suite | What it proves |
|---|---|
| `probe` | `tpm-probe.sh`, read-only, using tpm2-tools and sysfs and never the library. It records the distribution, kernel, glibc, hypervisor, DMI system and firmware, Secure Boot state, the installed TPM packages, the kernel's TPM driver, and the TPM's manufacturer, firmware, spec revision and FIPS mode. It checks that everything the provider uses is there: ECC P-256, ECDH, AES-128-CFB, SHA-256 and keyed-hash HMAC; the commands CreatePrimary, Create, Load, HMAC, StartAuthSession, FlushContext and ReadPublic; and a `TPM2_PT_INPUT_BUFFER` of at least 352 bytes, the longest PRF input. It also checks that the TPM is not in dictionary-attack lockout and that the Owner hierarchy is usable. |
| `tests:<executable>` | Each test executable's own tests, with `HKDFGUARD_TEST_TPM` set: the library's unit tests, the CLI's, and the integration tests. |
| `conformance` | The `#[ignore]`d suite against the TPM. Key files are created, reloaded, and refused when spliced. The storage root key is deterministic, and the Name formula matches. `TPM2_HMAC` equals software HMAC-SHA-256 for every input length. Salted, encrypted sessions work, and the authValue is enforced. Pins and retiring work. |
| `c_abi` | Provisions a service, learns the storage root key's and the key file's Names from the TPM, and runs `wrap_unwrap` twice: once with session encryption off, once with it on and both Names pinned. |
| `cli_to_c` | The CLI wraps a DEK, and a separate C process unwraps it through the `.so`. |
| `pkcs11` | The PKCS#11 suite against a throwaway SoftHSM2 token, if SoftHSM2 is installed. |

Nothing under `/etc/hkdfguard` or `/var/lib/hkdfguard` is read or written. The
TPM is only asked for transient objects, which are flushed after use. All
policies, secrets and key files live in a private temp directory that is
removed on exit. The binaries are built with `--cfg hkdfguard_test_paths`, so
they read the test's policy file. Nothing in the bundle is fit to deploy.

## What counts as a pass

- Every suite in the summary says `passed`. `pkcs11` may say
  `skipped (SoftHSM2 not installed)`.
- No skip line mentions the TPM. A TPM skip means the TPM path never ran, so
  the TPM is not qualified, whatever the summary says. The runner lists every
  skip line at the end of the log.
- The run was not done as root.

## What to record

| Item | Where in the log |
|---|---|
| Distribution, kernel, glibc | `probe`, under `host` |
| Hypervisor or hardware model, and firmware | `virtualization`, `system`, `firmware` |
| TPM manufacturer | `manufacturer`. `INTC`, `AMD` and `QCOM` are firmware TPMs; `MSFT` is Hyper-V's vTPM; `IFX`, `NTC`, `STM` and `ATML` are discrete chips. |
| TPM firmware version | `firmware`, under `TPM identity` |
| TPM spec revision | `spec` |
| tpm2-tss and tpm2-tools versions | `installed components` |
| The bundle's commit | the `bundle:` lines at the top |

Fold the result into the README's build and verification matrix, which notes
which TPMs the key-file design has been run on. The logs themselves are not
committed. To compare two TPMs, diff their `tpm-capabilities-<host>.txt`
files.

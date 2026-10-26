# Fuzzing the C ABI and the CLI

Coverage-guided fuzzing (libFuzzer, via `cargo fuzz`, with AddressSanitizer)
of the library's C ABI and the CLI's parsers, in-process, plus a black-box
fuzzer that drives the real `hkdfguard` binary. Nothing here is part of
the build that ships: the harnesses link a library built with
`--cfg hkdfguard_test_paths`, the test-only configuration that honors
`HKDFGUARD_POLICY_FILE` and accepts a policy owned by the current user
(see `policy::policy_file_path` in `src/policy.rs`), and the one hook
they need in the library (`hkdfguard::fuzz_support`) exists only under
that cfg.

## Targets

| Target | What it drives | What it checks beyond "no crash" |
|---|---|---|
| `unwrap_dek` | `hkdfguard_unwrap_dek` on arbitrary bytes and on bit-flipped, truncated and extended copies of a genuine payload; every shape of service string (valid, other case, unknown, arbitrary bytes, NULL) and of output buffer (any capacity, negative included; NULL `out`; NULL `out_len`) | only the genuine payload ever unwraps, and only to its DEK; every failure zeroes the caller's buffer; `BUFFER_TOO_SMALL` reports 32; no caught panic (`INTERNAL_ERROR`) |
| `wrap_round_trip` | `hkdfguard_wrap_dek` (any DEK length), `hkdfguard_generate_and_wrap_dek`, `hkdfguard_kek_exists`, `hkdfguard_kek_fingerprint`, `hkdfguard_security_model`, `hkdfguard_key_file_principal_trusted` | whatever wrap produces unwraps to the same DEK, under either spelling of the service, and parses; `BUFFER_TOO_SMALL` leaves the buffer untouched and asks for more than the capacity; a non-32-byte DEK is `INVALID_ARGUMENT`; the fingerprint matches the one payloads carry; `kek_exists` answers for exactly the created KEK; the calling uid and root are trusted under the developer model |
| `open_file` | `hkdfguard_open_file` on arbitrary file contents under every file mode, and on arbitrary paths | `key_file::check`, the payload parser and `open_file` agree on what a key file is; a refused file's length never comes back through `BUFFER_TOO_SMALL`; a file writable by group or others is refused; `open_file`'s refusal code is `check`'s |
| `policy` | `Policy::from_toml_str` on arbitrary text, and now and then the same text installed as the policy file and read through `hkdfguard_security_model` | whatever the parser refuses fails closed (`POLICY_INVALID`) through the file; whatever it accepts works |
| `cli_args` | the CLI's private functions, with `src/bin/hkdfguard.rs` included into the harness: argument parsing (UTF-8 and raw argv), fingerprint hex, DEK base64 decoding, the bounded stdin read, service-name checks, group resolution, path spelling, status descriptions | no panic |

Every harness aborts on any panic, including one the library would catch
at the ABI boundary and turn into `INTERNAL_ERROR`, so the fuzzer records
it with the input.

`cli_blackbox.py` runs the real binary, built with
`--cfg hkdfguard_test_paths`, under random and mutated command lines
(including non-UTF-8 argv), stdin contents, `--dek-file` contents and
modes, and key-file paths (existing files, symlinks, directories, long and
odd names, `/dev/null`, `/proc/self/mem`, ...), with a policy pinning the
chain to external-secret and a secret pre-provisioned per service, as
`tests/cli_round_trip.rs` does. A finding is a signal, a panic, an
"internal error", an exit code other than 0, 1 or 2, or a hang; each is
saved as JSON (argv, stdin, output) under `<private dir>/findings/`.

## Running

Needs a nightly toolchain and `cargo fuzz` (`cargo +nightly install
cargo-fuzz`). The library refuses files under any directory that others
can write to, sticky `/tmp` included, so the harnesses need a private
directory whose every ancestor is owned by root or you and writable by
nobody else (as the tests do: see `src/test_tmp.rs`):

```sh
export HKDFGUARD_FUZZ_DIR=$HOME/.cache/hkdfguard-fuzz   # 0700, private chain
export RUSTFLAGS="--cfg hkdfguard_test_paths"
cargo +nightly fuzz run unwrap_dek -- -max_total_time=900 -timeout=10
cargo +nightly fuzz run wrap_round_trip -- -max_total_time=900 -timeout=10
cargo +nightly fuzz run open_file -- -max_total_time=900 -timeout=10
cargo +nightly fuzz run policy -- -max_total_time=900 -timeout=10 -dict=fuzz/policy.dict
cargo +nightly fuzz run cli_args -- -max_total_time=900 -timeout=10 -dict=fuzz/cli.dict
```

A crash lands in `fuzz/artifacts/<target>/`; `cargo +nightly fuzz run
<target> <that file>` replays it. The dictionaries come from the policy's
keys and the CLI's flags.

The black-box CLI fuzzer:

```sh
CARGO_TARGET_DIR=target/fuzz-cli RUSTFLAGS="--cfg hkdfguard_test_paths" \
    cargo build --release --bin hkdfguard
python3 fuzz/cli_blackbox.py target/fuzz-cli/release/hkdfguard <private dir> <seconds> <workers>
```

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
| `unwrap_secret` | `hkdfguard_unwrap_secret` on arbitrary bytes, on a genuine DEK payload, and on bit-flipped, truncated and extended copies of a genuine secret payload; every shape of service string, of secret name (the genuine one, another, its uppercase spelling, arbitrary bytes, unterminated past 64 bytes, NULL) and of output buffer | only the genuine payload unwraps, only under its own service and exact name, and only to its secret; an invalid name is `INVALID_ARGUMENT`; every failure zeroes the caller's buffer; `BUFFER_TOO_SMALL` reports 256 and only below it; a DEK payload never unwraps as a secret, and no secret payload (corrupted or not) as a DEK |
| `wrap_secret_round_trip` | `hkdfguard_wrap_secret` on secrets of every length (0 to past 256, NULL, a length shorter than the buffer) under every shape of secret name, service string and output buffer | OK exactly when the name and length are valid and the service has a KEK; every payload is one size whatever the secret's length; it unwraps to the same secret under either spelling of the service, fails authentication under another name, and is a malformed DEK payload; `BUFFER_TOO_SMALL` leaves the buffer untouched and asks for more than the capacity; the library's name rule matches an independent restatement |
| `open_secret_file` | `hkdfguard_open_secret_file` on arbitrary file contents (empty, or after a genuine secret or DEK payload, or a genuine secret payload with bytes flipped in place) under every file mode, and on arbitrary paths | `key_file::check_kind`, the payload parser and `open_secret_file` agree on what a secret file is; no bytes pass both as a DEK file and as a secret file, and what `open_secret_file` accepts `open_file` refuses; a refused file's length never comes back through `BUFFER_TOO_SMALL`; a file writable by group or others is refused |
| `policy` | `Policy::from_toml_str` on arbitrary text, and now and then the same text installed as the policy file and read through `hkdfguard_security_model` | whatever the parser refuses fails closed (`POLICY_INVALID`) through the file; whatever it accepts works |
| `tpm_key_file` | the TPM key file decoder on arbitrary text, on what the encoder writes for arbitrary areas, and on mutated encodings; the `.tpmauth` content rule. No TPM needed: the format module is pure Rust | decode and encode agree (whatever decodes re-encodes and decodes the same; the encoder's output decodes to exactly its input whenever both areas are non-empty); an oversized structure is refused, never a panic; an authValue is accepted exactly when it is 32 bytes ending in a non-zero byte |
| `path_walk` | `secure_file::resolve_trusted` -- the walk behind `hkdfguard_open_file` and the policy, PIN, TPM and external-secret files -- on random trees of directories (every mode from `0700` to `1777`), files and relative or absolute symlinks, and random paths through them, `.`, `..` and empty segments included | the kernel (`canonicalize`) and the walker agree on where a path leads, and on when it leads nowhere; a reference walk in the harness records every directory a lookup happens in, symlinks' own included, and the walker refuses exactly when one of them is writable by group or others |
| `string_bounds` | every C string the ABI takes -- the service (through each of the eight functions that take one), the secret name, a key file path, a principal -- with no terminator at all, at the longest length the rule allows, one byte over, and with a NUL earlier than the bytes that follow it. Each string ends against an inaccessible page | a read one byte past the bounded scan, or past a terminator, is a crash in any build, sanitizer or not; an unterminated or over-long string gets its documented refusal; the longest valid one is not refused for its length; bytes after the first NUL change neither the status nor the output; the genuine string still works |
| `api_threads` | up to four threads at once, each a sequence of `create_kek`, `kek_exists`, `kek_fingerprint`, wrap and unwrap (DEKs and secrets, genuine and corrupted payloads, short buffers) and `open_file` | every thread gets the answer the call gets alone: its own DEK or secret back and never another thread's, a fingerprint that doesn't change, no KEK appearing for a service without one. Under AddressSanitizer, a use after free or stale pointer in the state the calls share is a finding |
| `cli_args` | the CLI's private functions, with `src/bin/hkdfguard.rs` included into the harness: argument parsing (UTF-8 and raw argv, `protect` included), fingerprint hex, DEK and secret decoding (raw and `--base64`), the bounded stdin reads, service- and secret-name checks, group resolution, path spelling, status descriptions | no panic; `--secret-name`'s rule is the library's; a decoded secret is 1 to 256 bytes; a bounded read never returns more than its limit |

Every harness aborts on any panic, including one the library would catch
at the ABI boundary and turn into `INTERNAL_ERROR`, so the fuzzer records
it with the input.

`cli_blackbox.py` runs the real binary, built with
`--cfg hkdfguard_test_paths`, under random and mutated `wrap`, `protect`,
`provision` and `retire` command lines (including non-UTF-8 argv), stdin
contents, `--dek-file` and `--secret-file` contents and modes, and key-file paths (existing files, symlinks, directories, long and
odd names, `/dev/null`, `/proc/self/mem`, ...), with a policy pinning the
chain to external-secret and a secret pre-provisioned per service, as
`tests/cli_round_trip.rs` does. A finding is a signal, a panic, an
"internal error", an exit code other than 0, 1 or 2, a hang, or a
`protect` whose secret appears in its output; each is
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
cargo +nightly fuzz run tpm_key_file -- -max_total_time=900 -timeout=10
cargo +nightly fuzz run path_walk -- -max_total_time=900 -timeout=10
cargo +nightly fuzz run unwrap_secret -- -max_total_time=900 -timeout=10
cargo +nightly fuzz run wrap_secret_round_trip -- -max_total_time=900 -timeout=10
cargo +nightly fuzz run open_secret_file -- -max_total_time=900 -timeout=10
cargo +nightly fuzz run string_bounds -- -max_total_time=900 -timeout=10
cargo +nightly fuzz run api_threads -- -max_total_time=900 -timeout=20
```

A crash lands in `fuzz/artifacts/<target>/`; `cargo +nightly fuzz run
<target> <that file>` replays it. The dictionaries come from the policy's
keys and the CLI's flags.

## Seeds: the memory attacks, written down

`fuzz/make_seeds.py` writes `fuzz/seeds/<target>/` (ignored by git: the
script is the source), about 1,660 inputs for the C ABI targets, each
named for what it tries:

- **output buffers**: a capacity that fits exactly, one byte short, one
  over, zero, one, negative, the most negative and the largest; `out`
  NULL, `out_len` NULL, both;
- **payloads and key files**: cut off at every length through the header;
  each header byte -- version, provider, the key-id and ciphertext length
  fields, the fingerprint -- flipped to its extremes; trailing bytes; raw
  blocks of zeros, `0xFF` and maximal length fields;
- **strings**: an early NUL (before, inside and after the genuine name), no
  terminator, the longest valid length and one more, format strings,
  path traversal, control and non-UTF-8 bytes, a line of policy TOML;
- **lengths that lie**: DEKs and secrets of every length round the limit,
  NULL with a non-zero length, a length shorter than the buffer;
- **paths**: `/proc/self/mem`, devices, directories, components of 255
  and 256 bytes, a path as long as the input allows;
- **threads**: every call on four threads at once, `create_kek` racing
  wrap, distinct DEKs and secrets per thread.

`fuzz/replay-seeds.sh` generates them and runs each through its target
once, under AddressSanitizer -- a regression suite of a minute or two,
not a campaign:

```sh
export HKDFGUARD_FUZZ_DIR=$HOME/.cache/hkdfguard-fuzz
fuzz/replay-seeds.sh                 # every target with seeds
fuzz/replay-seeds.sh string_bounds   # or the ones named
```

To start a campaign from them, name the seed directory after the corpus
(libFuzzer reads both and writes only to the first):

```sh
cargo +nightly fuzz run unwrap_dek fuzz/corpus/unwrap_dek fuzz/seeds/unwrap_dek -- -max_total_time=900
```

A seed is the `arbitrary` encoding of its target's `Input`; when an
`Input` changes shape, its builder in `make_seeds.py` changes with it, and
`cargo +nightly fuzz fmt <target> fuzz/seeds/<target>/<seed>` prints what
a seed decodes to. Add a seed for every finding, named for it.

What none of this reaches -- the TPM2 and PKCS#11 providers, which the
harnesses don't use -- `docker/entrypoint-test.sh` covers by running the
provider tests against swtpm and SoftHSM2 in an AddressSanitizer build.

## Nightly campaigns

`.github/workflows/fuzz.yml` runs every target each night (and on demand,
from the Actions tab, for any branch and time budget): 15 minutes each, on
its own runner, through `fuzz/campaign.sh`, which is the same thing run by
hand:

```sh
fuzz/campaign.sh unwrap_dek 900    # the result, as the workflow reports it
```

Each night starts from the corpus the nights before built up (kept in the
Actions cache, per target) and from the seeds. The results:

- the run's **summary page**: a table per target -- executions, corpus
  size, and whether there was a finding;
- a **failed run** when a target has a finding or no longer builds, which
  GitHub mails to whoever last edited the workflow's schedule;
- for a finding, a **code scanning alert**: Security tab, tool
  `hkdfguard-fuzz`, filtered to the branch that was fuzzed (`develop`,
  which the default view, of the default branch, does not show). It says
  what failed and holds the input (base64, with the commands that replay
  it) and the end of the fuzzer's log (`fuzz/finding_sarif.py`).

The repository is public, and so are a run's log, summary and artifacts;
a finding's input reproduces whatever it found. So in CI those say only
*that* a target failed, no artifact is kept, and the alert -- which only
people with write access can read -- is the only copy of the rest. An
alert is never closed by a later night: replay its input against the fix,
dismiss it by hand, and add the input to `make_seeds.py`. The same failure
found again updates its alert; a different one opens another.

By hand, `campaign.sh` prints the finding itself and leaves the input in
`fuzz/artifacts/<target>/`.

A scheduled workflow runs from the default branch's copy of the file and
fuzzes `develop`.

The black-box CLI fuzzer:

```sh
CARGO_TARGET_DIR=target/fuzz-cli RUSTFLAGS="--cfg hkdfguard_test_paths" \
    cargo build --release --bin hkdfguard
python3 fuzz/cli_blackbox.py target/fuzz-cli/release/hkdfguard <private dir> <seconds> <workers>
```

## Coverage of the tests

`scripts/coverage.sh [BASE]` runs the whole test suite under LLVM's
source-based coverage (`-Cinstrument-coverage`; needs `rustup component
add llvm-tools-preview`, no cargo plugin), prints the per-file summary,
and lists every line added since `BASE` (default: the merge base with
`origin/main`, plus uncommitted changes) that is executable and never ran,
failing if there is one. `scripts/coverage-exempt.txt` names the lines a
test runs in a process that can't record its profile, with that test.

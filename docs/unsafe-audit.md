# Audit of `unsafe` code

**Date:** 2026-10-29 · **Version:** 0.9.1 · **Scope:** every `unsafe` block in `src/` and `src/bin/`

This records what each kind of `unsafe` code relies on, how that was
checked, and what the checks could not reach. Re-run it after any change
to the code listed here.

## Result

No undefined behaviour was found. Every `unsafe` block states the
invariant it relies on, and each invariant was checked against the code
that establishes it. Miri, Rust's undefined-behaviour checker, ran every
test it can execute in the modules that hold pointer or memory logic and
reported nothing.

The audit changed no behaviour. It added four missing safety comments,
corrected one, and added `cfg(miri)` accommodations that exist only when
Miri runs (listed below).

## Method

1. **Inventory.** Every `unsafe` block, `unsafe impl` and `unsafe fn` in
   the crate. There are no `unsafe fn`s and one `unsafe impl`.
2. **Documentation.** `cargo clippy -- -W clippy::undocumented_unsafe_blocks`
   reports no block without a safety comment.
3. **Review.** Each comment's claim checked against the surrounding code:
   who guarantees the pointer, length, alignment or lifetime, and whether
   every path into the block establishes it.
4. **Miri.** `cargo +nightly miri test --lib`, module by module, with
   isolation off so tests can use the filesystem (see "Re-running").

## The `unsafe` code, by kind

### C ABI entry points (`src/lib.rs`)

The ten `extern "C"` functions read and write caller memory through raw
pointers.

| Invariant | Where it is established |
|---|---|
| A pointer is dereferenced only after a null check | The first lines of every `*_impl` function; `out_len` and `out` are checked before any read or write |
| A length is used as `usize` only once known non-negative | `capacity < 0` and `wrapped_len < 0` refused first |
| A C string is read only up to its bound | `cstr_to_service`, `cstr_to_principal` and `cstr_to_path` scan byte by byte and stop at 129, 16 and 4096 bytes |
| `out` is written only within the declared capacity | Every copy follows a `capacity >= len` check; `zero_caller_buffer` writes exactly `capacity` bytes |
| A panic never crosses into C | Every entry point runs its body under `catch_unwind`; `report_caught_panic` is itself wrapped |

**In-place unwrap.** `hkdfguard_unwrap_dek` allows `out` to be the
caller's `wrapped` buffer. The function borrows `wrapped` as a slice, and
the slice's last use comes before the DEK is written through `out`, so no
live shared reference is invalidated. On failure the zeroing likewise
follows the slice's last use. Miri confirmed this:
`unwrap_in_place_recovers_the_dek_and_audits_the_payload_not_the_dek`
passes under it.

### System calls with out-parameters

`getgrnam_r`, `getgrgid_r`, `getpwuid_r` and `getpwnam_r`
(`src/security_model.rs`, `src/bin/hkdfguard.rs`), and `statvfs`
(`src/secure_file.rs`).

- **Out-parameters are zeroed structs.** All-zero is valid for these:
  their fields are integers and null pointers.
- **Results are read only on success.** That means `rc == 0` and, for the
  lookups, a non-null `result`.
- **Pointers returned into the caller's buffer are used before it drops.**
  The group's member list is walked with `read_unaligned`, which doesn't
  rely on the C library aligning pointers inside a byte buffer. Every
  string is copied out before the buffer is freed.
- **Buffer growth is bounded.** `ERANGE` doubles the buffer up to 1 MiB,
  then reports the error.

### Ephemeral key pages (`src/provider/ephemeral.rs`)

The one `unsafe impl` and the only raw-pointer arithmetic.

- **`mmap` result checked against `MAP_FAILED`** before use. The page is
  never unmapped, so a pointer into it can't dangle.
- **`slot(i)` asserts `i < slots()`** before forming `&mut [u8; 32]` at
  `base + i * 32`. The alignment needed is 1, and `&mut self` behind the
  store's mutex makes it the only reference.
- **`unsafe impl Send for KeyPage`.** It holds a raw pointer, but every
  `KeyPage` is reached only through the store's `Mutex`, so it is never
  shared between threads unsynchronised. It is not `Sync`, and nothing
  needs it to be.

### Process state (`src/lib.rs`, `src/bin/hkdfguard.rs`)

- **`prctl` and `setrlimit` in `harden_process_impl`** take only integers
  and a fully initialised struct. The order matters for the contract, not
  for safety: the reversible step first (see `harden_steps`).
- **`mlock` and `munlock` of the CLI's DEK scratch buffer** cover a `Box`
  allocation, whose address doesn't move between the two calls.
- **`File::from_raw_fd(STDIN_FILENO)` in the CLI** needs descriptor 0 to
  be open. Rust's runtime reopens `/dev/null` on any closed standard
  descriptor before `main`, so it can't be a file the program opened. It
  is wrapped in `ManuallyDrop`, so it is never closed.
- **`fchown`, `isatty`, `mlockall`, `getrlimit`** take a descriptor,
  integers, or a valid out-parameter.

### Calls with no preconditions

`geteuid`, `getuid`, `getegid` and `sysconf` take no pointers and can't
fail. 28 of the crate's 85 `unsafe` blocks are only these.

## Miri results

| Module | Under Miri | Notes |
|---|---|---|
| C ABI (`ffi_tests`) | 58 passed | 4 ignored under Miri: 3 assert wall-clock speed, 1 needs the passwd database |
| `payload` | 8 passed | |
| `crypto` | 31 passed | About an hour: AES-GCM and HMAC fully interpreted |
| `provider::ephemeral` | 8 passed | Includes the `mmap` pages and `slot()` |
| `provider::tpm_key_file` | 7 passed | |
| `key_file` | 44 passed | 3 ignored: 2 need the passwd database, 1 makes a FIFO |
| `secure_file` | 23 passed | 1 ignored: makes a FIFO |
| `audit` | 10 passed | 1 ignored: opens a Unix datagram socket |

**What Miri can't reach.** It interprets Rust, so calls into C are
outside it: the NSS lookups, `statvfs`, `prctl`, `setrlimit`, `madvise`,
`mlock`, `mkfifo`, Unix sockets, and the TPM and PKCS#11 libraries. For
those, the review above is the check. The TPM and PKCS#11 providers'
`unsafe` code is only `geteuid` in tests; their foreign calls go through
the `tss-esapi` and `cryptoki` crates, which are outside this audit.

**`cfg(miri)` accommodations.** Present only when Miri runs, so no build
that ships has them:

- `secure_file::open_checked` opens without `O_NONBLOCK | O_NOCTTY`,
  which Miri doesn't support. Neither changes how a regular file opens.
- `harden_process_impl` runs `harden_steps` with no system calls.
- The ephemeral key page skips `madvise` and `mlock`, which are advice.
- `security_model`'s lookups report no such user or group.
- `on_read_only_mount` reports no read-only mount, the answer for every
  test directory.

## Re-running

From the repository root, with a private temporary directory as the tests
require (see `src/test_tmp.rs`):

```sh
rustup component add miri --toolchain nightly
export HKDFGUARD_TEST_TMPDIR=$HOME/.cache/hkdfguard-test-tmp   # 0700, private chain
export MIRIFLAGS=-Zmiri-disable-isolation
for m in ffi_tests payload:: crypto:: provider::ephemeral provider::tpm_key_file key_file:: secure_file:: audit::; do
    cargo +nightly miri test --lib "$m" -- --test-threads=1
done
```

One Miri process per module, because Miri stops the whole test binary at
the first unsupported operation. A full pass takes several hours.

To check documentation:

```sh
cargo clippy --all-features --all-targets -- -W clippy::undocumented_unsafe_blocks
```

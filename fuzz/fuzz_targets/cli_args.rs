//! The CLI's own parsers, in-process: the source of `src/bin/hkdfguard.rs`
//! is included here whole, so its private functions are reachable --
//! argument parsing, the fingerprint and DEK decoders, the bounded stdin
//! read, service-name checks, group resolution, path spelling and the
//! status descriptions. (Its `main` is simply never called.)
#![no_main]
#![allow(dead_code, unused_imports)]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

include!(concat!(env!("OUT_DIR"), "/cli.rs"));

#[derive(Arbitrary, Debug)]
struct Input {
    argv: Vec<String>,
    raw_argv: Vec<Vec<u8>>,
    text: String,
    blob: Vec<u8>,
    code: i32,
}

fuzz_target!(|input: Input| {
    let mut argv = vec!["hkdfguard".to_string()];
    argv.extend(input.argv.iter().cloned());
    let _ = parse_args(argv.into_iter());

    let raw = input.raw_argv.iter().map(|b| {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(b.clone())
    });
    if let Ok(args) = utf8_args(raw) {
        let _ = parse_args(args.into_iter());
    }

    let _ = parse_fingerprint_hex(&input.text);
    let _ = validate_service_charset(&input.text);
    let mut service = input.text.clone();
    let _ = prepare_service(&mut service);
    let _ = parse_cap_eff(&input.text);
    let _ = spelled_absolute(Path::new(&input.text));
    let _ = resolve_key_file_group(&input.text);
    let _ = describe_status(input.code);
    let _ = hex(&input.blob);

    let mut decoded = [0u8; MAX_DECODED_LEN];
    let _ = decode_dek(&input.blob, &mut decoded);
    let mut buf = [0u8; MAX_DEK_INPUT_LEN + 1];
    let mut src = std::io::Cursor::new(&input.blob[..]);
    if let Ok(n) = read_bounded(&mut src, "the DEK", &mut buf) {
        let _ = decode_dek(&buf[..n], &mut decoded);
    }
});

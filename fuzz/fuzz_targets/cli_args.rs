//! The CLI's own parsers, in-process: the source of `src/bin/hkdfguard.rs`
//! is included here whole, so its private functions are reachable --
//! argument parsing (`protect` included), the fingerprint, DEK and secret
//! decoders, the bounded stdin reads, service- and secret-name checks,
//! group resolution, path spelling and the status descriptions. (Its
//! `main` is simply never called.)
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

    // The CLI's secret-name check is the library's rule, not a variant of it.
    assert_eq!(
        validate_secret_name(&input.text).is_ok(),
        hkdfguard::fuzz_support::is_valid_secret_name(&input.text),
        "--secret-name rule differs from the library's for {:?}",
        input.text
    );
    let mut secret = [0u8; MAX_SECRET_DECODED_LEN];
    for base64 in [false, true] {
        if let Ok(s) = decode_secret(&input.blob, base64, &mut secret) {
            assert!((1..=SECRET_MAX_LEN).contains(&s.len()), "decoded a {}-byte secret", s.len());
        }
    }
    let mut text = [0u8; MAX_SECRET_INPUT_LEN + 1];
    let mut src = std::io::Cursor::new(&input.blob[..]);
    if let Ok(n) = read_bounded_into(&mut src, "the secret", &mut text, "expected a secret") {
        assert!(n <= MAX_SECRET_INPUT_LEN, "read {n} bytes, past the limit");
        let _ = decode_secret(&text[..n], false, &mut secret);
    }

    let mut decoded = [0u8; MAX_DECODED_LEN];
    let _ = decode_dek(&input.blob, &mut decoded);
    let mut buf = [0u8; MAX_DEK_INPUT_LEN + 1];
    let mut src = std::io::Cursor::new(&input.blob[..]);
    if let Ok(n) = read_bounded(&mut src, "the DEK", &mut buf) {
        let _ = decode_dek(&buf[..n], &mut decoded);
    }
});

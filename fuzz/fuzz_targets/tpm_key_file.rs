//! The TPM provider's on-disk formats, without a TPM: the key file decoder
//! (`-----BEGIN TSS2 PRIVATE KEY-----`, the strict DER `TPMKey` shape this
//! library writes) and the `.tpmauth` content rule.
//!
//! Beyond "no crash", checks that the decoder and the encoder agree:
//! whatever decodes re-encodes to something that decodes to the same two
//! areas; whatever the encoder writes decodes back to exactly what it was
//! given, whenever both areas are non-empty (the decoder refuses an empty
//! TPM2B, and nothing the TPM returns is empty); and a mutated encoding
//! either is refused or decodes to areas that round-trip in turn. The
//! authValue rule accepts exactly 32 bytes whose last byte isn't zero.
#![no_main]

use arbitrary::Arbitrary;
use hkdfguard::fuzz_support::{tpm_auth_value_check, tpm_key_file_decode, tpm_key_file_encode, TPM_AUTH_VALUE_LEN};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Input {
    /// Arbitrary bytes as a key file.
    Raw(Vec<u8>),
    /// A key file this library would write, for these two areas.
    Areas { public: Vec<u8>, private: Vec<u8> },
    /// That key file, with bytes changed, cut or added.
    Mutated { public: Vec<u8>, private: Vec<u8>, edits: Vec<Edit> },
    /// Arbitrary bytes as a `.tpmauth` file.
    Auth(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum Edit {
    Flip { at: u16, bits: u8 },
    Truncate { to: u16 },
    Insert { at: u16, byte: u8 },
    Remove { at: u16 },
}

fn apply(text: &mut Vec<u8>, edit: &Edit) {
    let len = text.len();
    match *edit {
        Edit::Flip { at, bits } if len > 0 => text[at as usize % len] ^= bits | 1,
        Edit::Truncate { to } => text.truncate(to as usize % (len + 1)),
        Edit::Insert { at, byte } => text.insert(at as usize % (len + 1), byte),
        Edit::Remove { at } if len > 0 => {
            text.remove(at as usize % len);
        }
        _ => {}
    }
}

// Whatever decodes must survive another encode/decode unchanged.
fn decoded_round_trips(text: &[u8]) {
    if let Ok((public, private)) = tpm_key_file_decode(text) {
        assert!(!public.is_empty() && !private.is_empty(), "the decoder accepted an empty area");
        let again = tpm_key_file_encode(&public, &private).expect("a decoded key file must re-encode");
        assert_eq!(tpm_key_file_decode(again.as_bytes()), Ok((public, private)), "decode . encode . decode");
    }
}

fuzz_target!(|input: Input| {
    match input {
        Input::Raw(bytes) => decoded_round_trips(&bytes),
        Input::Areas { public, private } => {
            let Ok(text) = tpm_key_file_encode(&public, &private) else {
                // Only a structure too large for DER's two-byte lengths is refused.
                assert!(public.len() + private.len() > 0xff00, "{} + {} bytes refused", public.len(), private.len());
                return;
            };
            let decoded = tpm_key_file_decode(text.as_bytes());
            if public.is_empty() || private.is_empty() {
                assert!(decoded.is_err(), "an empty area must not decode");
            } else {
                assert_eq!(decoded, Ok((public, private)), "encode then decode must give back the areas");
            }
        }
        Input::Mutated { public, private, edits } => {
            let Ok(text) = tpm_key_file_encode(&public, &private) else { return };
            let mut text = text.into_bytes();
            for edit in edits.iter().take(8) {
                apply(&mut text, edit);
            }
            decoded_round_trips(&text);
        }
        Input::Auth(bytes) => {
            let accepted = tpm_auth_value_check(&bytes).is_ok();
            let expected = bytes.len() == TPM_AUTH_VALUE_LEN && bytes.last() != Some(&0);
            assert_eq!(accepted, expected, "{} bytes, last {:?}", bytes.len(), bytes.last());
        }
    }
});

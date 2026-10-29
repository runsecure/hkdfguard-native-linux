//! The TPM provider's on-disk key file: the TPM 2.0 key file format
//! (`-----BEGIN TSS2 PRIVATE KEY-----`, the ASN.1 `TPMKey` structure the
//! OpenSSL tpm2 provider, tpm2-tss-engine and the Linux kernel's trusted
//! keys use), restricted to exactly the shape this crate writes:
//!
//! ```text
//! TPMKey ::= SEQUENCE {
//!     type        OBJECT IDENTIFIER,     -- id-loadablekey, 2.23.133.10.1.3
//!                                        -- (emptyAuth absent: the key has a password)
//!     parent      INTEGER,               -- 0x40000001: the Owner hierarchy's storage primary
//!     pubkey      OCTET STRING,          -- TPM2B_PUBLIC
//!     privkey     OCTET STRING           -- TPM2B_PRIVATE, encrypted by the parent
//! }
//! ```
//!
//! Every service key has an authValue, kept in its own file beside the
//! key file (see `tpm2.rs`), so `emptyAuth` -- which the format includes
//! only to say a key has *no* password -- is never written. A file that
//! carries it, TRUE or FALSE, is refused: TRUE is a key from before
//! authValues, and FALSE is not how DER spells the default. The format's
//! other optional fields (policies, an imported secret, a description, an
//! RSA parent) describe keys this crate never makes, so a file carrying
//! any of them is refused rather than half-understood. DER
//! is parsed strictly: minimal lengths, no trailing bytes, and the two
//! TPM2B size prefixes must match their contents. Nothing here talks to a
//! TPM; `tpm2.rs` unmarshals the two structures and loads them.

use base64::{engine::general_purpose::STANDARD, Engine as _};

/// `id-loadablekey` (2.23.133.10.1.3), DER-encoded with its tag and length.
const LOADABLE_KEY_OID: &[u8] = &[0x06, 0x06, 0x67, 0x81, 0x05, 0x0a, 0x01, 0x03];

/// `TPM_RH_OWNER`: the parent is the Owner hierarchy's storage primary key,
/// re-derived from its template on each use rather than kept at a
/// persistent handle.
pub(crate) const PARENT_OWNER_HIERARCHY: u32 = 0x4000_0001;

const PEM_BEGIN: &str = "-----BEGIN TSS2 PRIVATE KEY-----";
const PEM_END: &str = "-----END TSS2 PRIVATE KEY-----";

/// Upper bound on a key file's size. An HMAC key's file is about 300
/// bytes; this is a sanity limit, not a format one.
pub(crate) const MAX_KEY_FILE_LEN: usize = 4096;

/// Length of every service key's authValue, the `.tpmauth` file beside its
/// key file: the digest size of its name algorithm (SHA-256), the most a
/// TPM accepts for an object's authValue.
pub(crate) const AUTH_VALUE_LEN: usize = 32;

/// Checks a `.tpmauth` file's contents: exactly [`AUTH_VALUE_LEN`] bytes,
/// the last one not zero. The TPM drops trailing zero bytes from an
/// authValue before using it, and refusing them keeps both ends agreeing
/// without relying on every layer in between doing the same; this library
/// never writes one. The error says what was wrong, never the contents.
pub(crate) fn check_auth_value(bytes: &[u8]) -> Result<(), String> {
    match bytes {
        b if b.len() != AUTH_VALUE_LEN => Err(format!("is {} bytes, not {AUTH_VALUE_LEN}", b.len())),
        [.., 0] => Err("ends in a zero byte, which the TPM would drop; it is not one this library wrote".to_string()),
        _ => Ok(()),
    }
}

const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_BOOLEAN: u8 = 0x01;
const TAG_EMPTY_AUTH: u8 = 0xa0; // [0] EXPLICIT, constructed: recognised only to refuse it

/// The two TPM structures a key file carries, each without its TPM2B size
/// prefix: the marshalled `TPMT_PUBLIC`, and the `TPM2B_PRIVATE` buffer's
/// contents.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct KeyBlob {
    pub(crate) public: Vec<u8>,
    pub(crate) private: Vec<u8>,
}

/// Encodes `blob` as a PEM key file.
pub(crate) fn encode(blob: &KeyBlob) -> Result<String, String> {
    let mut body = Vec::new();
    body.extend_from_slice(LOADABLE_KEY_OID);
    body.extend_from_slice(&[TAG_INTEGER, 0x04]);
    body.extend_from_slice(&PARENT_OWNER_HIERARCHY.to_be_bytes()); // high bit clear: no leading zero needed
    der_push(&mut body, TAG_OCTET_STRING, &tpm2b(&blob.public)?)?;
    der_push(&mut body, TAG_OCTET_STRING, &tpm2b(&blob.private)?)?;
    let mut der = Vec::new();
    der_push(&mut der, TAG_SEQUENCE, &body)?;

    let encoded = STANDARD.encode(&der);
    let mut pem = String::with_capacity(encoded.len() + encoded.len() / 64 + PEM_BEGIN.len() + PEM_END.len() + 4);
    pem.push_str(PEM_BEGIN);
    pem.push('\n');
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str(PEM_END);
    pem.push('\n');
    Ok(pem)
}

/// Decodes a PEM key file of exactly the shape [`encode`] writes. Every
/// error names what was wrong, never the file's contents.
pub(crate) fn decode(text: &[u8]) -> Result<KeyBlob, String> {
    let text = std::str::from_utf8(text).map_err(|_| "not a PEM file (not UTF-8 text)".to_string())?;
    let mut lines = text.lines();
    if lines.next() != Some(PEM_BEGIN) {
        return Err(format!("does not start with \"{PEM_BEGIN}\""));
    }
    let mut base64 = String::new();
    let mut ended = false;
    for line in lines.by_ref() {
        if line == PEM_END {
            ended = true;
            break;
        }
        base64.push_str(line);
    }
    if !ended {
        return Err(format!("has no \"{PEM_END}\" line"));
    }
    if lines.any(|l| !l.is_empty()) {
        return Err("has text after the end line".to_string());
    }
    let der = STANDARD.decode(base64.as_bytes()).map_err(|_| "its PEM body is not valid base64".to_string())?;
    decode_der(&der)
}

fn decode_der(der: &[u8]) -> Result<KeyBlob, String> {
    let mut outer = Reader { buf: der };
    let mut seq = Reader { buf: outer.take(TAG_SEQUENCE, "TPMKey")? };
    if !outer.buf.is_empty() {
        return Err("has trailing bytes after the TPMKey structure".to_string());
    }

    let oid = seq.take_raw(LOADABLE_KEY_OID.len())?;
    if oid != LOADABLE_KEY_OID {
        return Err("is not a loadable TPM key (type is not id-loadablekey)".to_string());
    }
    if seq.peek() == Some(TAG_EMPTY_AUTH) {
        let empty_auth = Reader { buf: seq.take(TAG_EMPTY_AUTH, "emptyAuth")? }.take(TAG_BOOLEAN, "emptyAuth")?;
        return Err(if empty_auth == [0xff] {
            "holds a key with an empty password (emptyAuth), from before hkdfguard gave every TPM key an authValue; \
             delete the file and provision the service again"
                .to_string()
        } else {
            "has an emptyAuth field, which this library never writes".to_string()
        });
    }
    let parent = seq.take(TAG_INTEGER, "parent")?;
    if parent != PARENT_OWNER_HIERARCHY.to_be_bytes() {
        return Err("names a parent other than the Owner hierarchy's storage primary (0x40000001)".to_string());
    }
    let public = from_tpm2b(seq.take(TAG_OCTET_STRING, "pubkey")?, "pubkey")?;
    let private = from_tpm2b(seq.take(TAG_OCTET_STRING, "privkey")?, "privkey")?;
    if !seq.buf.is_empty() {
        return Err("has fields this library does not use (a policy, a secret, or a description)".to_string());
    }
    Ok(KeyBlob { public, private })
}

/// `bytes` as a TPM2B: a big-endian u16 size, then the bytes.
fn tpm2b(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let len = u16::try_from(bytes.len()).map_err(|_| "a TPM structure is too large for a TPM2B".to_string())?;
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

fn from_tpm2b(bytes: &[u8], what: &str) -> Result<Vec<u8>, String> {
    match bytes {
        [hi, lo, rest @ ..] if usize::from(u16::from_be_bytes([*hi, *lo])) == rest.len() && !rest.is_empty() => {
            Ok(rest.to_vec())
        }
        _ => Err(format!("has a {what} whose TPM2B size does not match its contents")),
    }
}

// The decoder reads at most a two-byte DER length, so nothing longer is
// written: a structure of 64 KiB or more is refused, never truncated. A
// TPM's areas are a few hundred bytes, so only a caller passing something
// else reaches this.
fn der_push(out: &mut Vec<u8>, tag: u8, contents: &[u8]) -> Result<(), String> {
    out.push(tag);
    match contents.len() {
        n @ 0..=0x7f => out.push(n as u8),
        n @ 0x80..=0xff => out.extend_from_slice(&[0x81, n as u8]),
        n => {
            let n = u16::try_from(n).map_err(|_| "a key file structure is too large to encode".to_string())?;
            out.push(0x82);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
    out.extend_from_slice(contents);
    Ok(())
}

/// A forward-only DER reader over one level of a structure.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn peek(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    fn take_raw(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.buf.len() < n {
            return Err("is truncated".to_string());
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    /// One element with tag `tag`, returning its contents. Lengths must be
    /// in DER's minimal form.
    fn take(&mut self, tag: u8, what: &str) -> Result<&'a [u8], String> {
        let bad = || format!("has a malformed {what} field");
        let [found, first, ..] = *self.buf else {
            return Err("is truncated".to_string());
        };
        if found != tag {
            return Err(bad());
        }
        let (len, header) = match first {
            n @ 0..=0x7f => (usize::from(n), 2),
            0x81 => match self.buf.get(2) {
                Some(&n) if n >= 0x80 => (usize::from(n), 3),
                _ => return Err(bad()),
            },
            0x82 => match self.buf.get(2..4) {
                Some(&[hi, lo]) if hi != 0 => (usize::from(u16::from_be_bytes([hi, lo])), 4),
                _ => return Err(bad()),
            },
            _ => return Err(bad()),
        };
        self.take_raw(header)?;
        self.take_raw(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> KeyBlob {
        // Sizes like a real key's: an ~88-byte TPMT_PUBLIC and a ~126-byte
        // private buffer, enough to need DER's long length form.
        KeyBlob { public: (0..88u8).collect(), private: (0..126u8).rev().collect() }
    }

    #[test]
    fn round_trips() {
        let pem = encode(&sample()).unwrap();
        assert!(pem.starts_with("-----BEGIN TSS2 PRIVATE KEY-----\n"));
        assert!(pem.ends_with("-----END TSS2 PRIVATE KEY-----\n"));
        assert!(pem.lines().all(|l| l.len() <= 64 || l.starts_with("-----")));
        assert_eq!(decode(pem.as_bytes()).unwrap(), sample());
    }

    #[test]
    fn encodes_the_exact_tpmkey_structure() {
        // Spelled out byte by byte, so a change to the encoding can't pass
        // by agreeing with a matching change to the decoder.
        let blob = KeyBlob { public: vec![0xaa; 3], private: vec![0xbb; 2] };
        let pem = encode(&blob).unwrap();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = STANDARD.decode(body).unwrap();
        let expected: Vec<u8> = [
            &[0x30, 0x1b][..],                                 // SEQUENCE, 27 bytes
            &[0x06, 0x06, 0x67, 0x81, 0x05, 0x0a, 0x01, 0x03], // id-loadablekey; no emptyAuth: the key has a password
            &[0x02, 0x04, 0x40, 0x00, 0x00, 0x01],             // parent 0x40000001
            &[0x04, 0x05, 0x00, 0x03, 0xaa, 0xaa, 0xaa],       // pubkey: TPM2B of 3 bytes
            &[0x04, 0x04, 0x00, 0x02, 0xbb, 0xbb],             // privkey: TPM2B of 2 bytes
        ]
        .concat();
        assert_eq!(der, expected);
    }

    // Re-encodes a hand-built DER body as PEM.
    fn pem_of(der: &[u8]) -> String {
        format!("{PEM_BEGIN}\n{}\n{PEM_END}\n", STANDARD.encode(der))
    }

    fn der_of(blob: &KeyBlob) -> Vec<u8> {
        let pem = encode(blob).unwrap();
        STANDARD.decode(pem.lines().filter(|l| !l.starts_with("-----")).collect::<String>()).unwrap()
    }

    #[test]
    fn refuses_anything_but_the_shape_this_library_writes() {
        let good = der_of(&KeyBlob { public: vec![0xaa; 3], private: vec![0xbb; 2] });
        let with = |at: usize, byte: u8| {
            let mut der = good.clone();
            der[at] = byte;
            pem_of(&der)
        };
        let cases = [
            (with(9, 0x04), "id-loadablekey"), // another key type (importable)
            (with(15, 0x02), "parent"),        // parent 0x40000002
            (with(19, 0x02), "TPM2B size"),    // pubkey's size prefix says 2, holds 3
        ];
        for (pem, expect) in cases {
            let err = decode(pem.as_bytes()).unwrap_err();
            assert!(err.contains(expect), "expected {expect:?}, got {err:?}");
        }

        // An emptyAuth field, as a key file from before authValues has.
        let with_empty_auth = |value: u8| {
            let mut der = good[..10].to_vec();
            der.extend_from_slice(&[0xa0, 0x03, 0x01, 0x01, value]);
            der.extend_from_slice(&good[10..]);
            der[1] += 5;
            pem_of(&der)
        };
        let err = decode(with_empty_auth(0xff).as_bytes()).unwrap_err();
        assert!(err.contains("empty password") && err.contains("provision the service again"), "{err}");
        assert!(decode(with_empty_auth(0x00).as_bytes()).unwrap_err().contains("never writes"));

        // An extra trailing field inside the SEQUENCE (e.g. a description).
        let mut extra = good.clone();
        extra.extend_from_slice(&[0x04, 0x00]);
        extra[1] += 2;
        assert!(decode(pem_of(&extra).as_bytes()).unwrap_err().contains("fields this library does not use"));

        // Bytes after the SEQUENCE.
        let mut trailing = good.clone();
        trailing.push(0x00);
        assert!(decode(pem_of(&trailing).as_bytes()).unwrap_err().contains("trailing bytes"));

        // Truncated anywhere.
        for cut in 1..good.len() {
            assert!(decode(pem_of(&good[..cut]).as_bytes()).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn oversized_areas_are_refused_not_a_panic() {
        // One area at the TPM2B limit fits a two-byte DER length on its own,
        // but the SEQUENCE around both no longer does.
        let big = KeyBlob { public: vec![1; u16::MAX as usize], private: vec![2; 16] };
        assert!(encode(&big).unwrap_err().contains("too large"));
        let too_big = KeyBlob { public: vec![1; u16::MAX as usize + 1], private: vec![2; 16] };
        assert!(encode(&too_big).unwrap_err().contains("TPM2B"));
    }

    #[test]
    fn an_auth_value_is_exactly_32_bytes_not_ending_in_zero() {
        assert!(check_auth_value(&[7u8; AUTH_VALUE_LEN]).is_ok());
        let mut ends_in_zero = [7u8; AUTH_VALUE_LEN];
        ends_in_zero[AUTH_VALUE_LEN - 1] = 0;
        assert!(check_auth_value(&ends_in_zero).unwrap_err().contains("zero byte"));
        let mut zero_inside = [7u8; AUTH_VALUE_LEN];
        zero_inside[0] = 0;
        assert!(check_auth_value(&zero_inside).is_ok(), "only a trailing zero matters");
        for len in [0, 1, 31, 33, 64] {
            assert!(check_auth_value(&vec![7u8; len]).unwrap_err().contains(&format!("is {len} bytes")), "{len}");
        }
    }

    #[test]
    fn refuses_non_minimal_der_lengths() {
        // The SEQUENCE's 32-byte length written in long form (0x81 0x20).
        let good = der_of(&KeyBlob { public: vec![0xaa; 3], private: vec![0xbb; 2] });
        let mut long_form = vec![0x30, 0x81, 0x20];
        long_form.extend_from_slice(&good[2..]);
        assert!(decode(pem_of(&long_form).as_bytes()).unwrap_err().contains("malformed TPMKey"));
    }

    #[test]
    fn refuses_bad_pem_framing() {
        let pem = encode(&sample()).unwrap();
        let body_start = pem.find('\n').unwrap() + 1;
        let corrupt_body = format!("{}*{}", &pem[..body_start], &pem[body_start + 1..]);
        for (bad, expect) in [
            (pem.replace("TSS2 PRIVATE KEY-----\n", "PRIVATE KEY-----\n"), "does not start"),
            (pem.replace(PEM_END, ""), "no \"-----END"),
            (format!("{pem}junk\n"), "text after"),
            (corrupt_body, "base64"),
        ] {
            let err = decode(bad.as_bytes()).unwrap_err();
            assert!(err.contains(expect), "expected {expect:?}, got {err:?}");
        }
        assert!(decode(&[0xff, 0xfe]).unwrap_err().contains("UTF-8"));
    }
}

//! OpenSSL's subject hash of a certificate: the name a certificate directory
//! files an anchor under, as `<hash>.0`, and the only name OpenSSL's directory
//! lookup opens. It is `X509_NAME_hash_ex` — what `openssl x509
//! -subject_hash` prints and `openssl rehash` links by: the first four bytes,
//! little-endian, of the SHA-1 of the subject's canonical encoding.
//!
//! Only as much DER as reaching the subject takes is read, and nothing is
//! verified: the certificate is the host's own anchor, and all that is wanted
//! of it here is the name OpenSSL will look for it under.

use std::io;

use base64::Engine as _;
use sha1::{Digest as _, Sha1};

const INTEGER: u8 = 0x02;
const OID: u8 = 0x06;
const UTF8_STRING: u8 = 0x0c;
const PRINTABLE_STRING: u8 = 0x13;
const T61_STRING: u8 = 0x14;
const IA5_STRING: u8 = 0x16;
const VISIBLE_STRING: u8 = 0x1a;
const UNIVERSAL_STRING: u8 = 0x1c;
const BMP_STRING: u8 = 0x1e;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
/// `[0] EXPLICIT Version`, absent from a v1 certificate.
const VERSION: u8 = 0xa0;

/// The subject hash of the first certificate in `pem`.
pub(super) fn subject_hash(pem: &[u8]) -> io::Result<u32> {
    let der = certificate(pem)?;
    let name = subject(&der).ok_or_else(|| invalid("its DER does not reach a subject name"))?;
    let canonical = canonical_name(name).ok_or_else(|| invalid("its subject name is malformed"))?;
    let digest = Sha1::digest(&canonical);
    Ok(u32::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3],
    ]))
}

fn invalid(why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("the anchor cannot be filed under its subject hash: {why}"),
    )
}

/// The DER of the first `CERTIFICATE` block in `pem`.
fn certificate(pem: &[u8]) -> io::Result<Vec<u8>> {
    let text = String::from_utf8_lossy(pem);
    let body = text
        .split_once("-----BEGIN CERTIFICATE-----")
        .and_then(|(_, rest)| rest.split_once("-----END CERTIFICATE-----"))
        .map(|(body, _)| body)
        .ok_or_else(|| invalid("it holds no PEM certificate"))?;
    let encoded: String = body.split_ascii_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| invalid(&format!("its PEM body is not base64: {error}")))
}

/// Splits one DER element off `input`: its tag, its contents, and what
/// follows it. `None` for what a certificate's subject never needs — a
/// multi-byte tag, an indefinite length — and for a length past the input.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let (octets, rest) = rest.split_at_checked(usize::from(first & 0x7f))?;
        if octets.is_empty() || octets.len() > size_of::<usize>() {
            return None;
        }
        let len = octets
            .iter()
            .fold(0, |len, &octet| (len << 8) | usize::from(octet));
        (len, rest)
    };
    let (contents, rest) = rest.split_at_checked(len)?;
    Some((tag, contents, rest))
}

/// [`element`], when it carries `tag`: its contents and what follows it.
fn expect(tag: u8, input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (found, contents, rest) = element(input)?;
    (found == tag).then_some((contents, rest))
}

/// The contents of a certificate's subject `Name`: its RDNs, encoded.
fn subject(der: &[u8]) -> Option<&[u8]> {
    let (certificate, _) = expect(SEQUENCE, der)?;
    let (tbs, _) = expect(SEQUENCE, certificate)?;
    let tbs = expect(VERSION, tbs).map_or(tbs, |(_, rest)| rest);
    let (_serial, tbs) = expect(INTEGER, tbs)?;
    let (_signature, tbs) = expect(SEQUENCE, tbs)?;
    let (_issuer, tbs) = expect(SEQUENCE, tbs)?;
    let (_validity, tbs) = expect(SEQUENCE, tbs)?;
    let (subject, _) = expect(SEQUENCE, tbs)?;
    Some(subject)
}

/// OpenSSL's canonical encoding of a name (`x509_name_canon`): each RDN
/// re-encoded as the SET of its attributes with every string value made
/// canonical, and the SETs concatenated with no SEQUENCE around them.
fn canonical_name(mut rdns: &[u8]) -> Option<Vec<u8>> {
    let mut canonical = Vec::new();
    while !rdns.is_empty() {
        let (mut rdn, rest) = expect(SET, rdns)?;
        rdns = rest;
        let mut attributes = Vec::new();
        while !rdn.is_empty() {
            let (attribute, rest) = expect(SEQUENCE, rdn)?;
            rdn = rest;
            let (oid, value) = expect(OID, attribute)?;
            let (tag, contents, rest) = element(value)?;
            if !rest.is_empty() {
                return None;
            }
            let mut encoded = der(OID, oid);
            encoded.extend(canonical_value(tag, contents)?);
            attributes.push(der(SEQUENCE, &encoded));
        }
        // DER orders a SET OF by its members' encodings, and OpenSSL's
        // encoder does too; it matters only to a multi-valued RDN.
        attributes.sort();
        canonical.extend(der(SET, &attributes.concat()));
    }
    Some(canonical)
}

/// One attribute value as `asn1_string_canon` leaves it: a string of a type
/// OpenSSL canonicalizes becomes a UTF8String of its canonical text, and any
/// other value is kept as it was encoded. `None` for a string that does not
/// decode, which OpenSSL refuses too.
fn canonical_value(tag: u8, contents: &[u8]) -> Option<Vec<u8>> {
    let text: String = match tag {
        UTF8_STRING => std::str::from_utf8(contents).ok()?.to_owned(),
        // One octet per character, which OpenSSL reads as Latin-1.
        PRINTABLE_STRING | T61_STRING | IA5_STRING | VISIBLE_STRING => {
            contents.iter().map(|&octet| char::from(octet)).collect()
        }
        BMP_STRING => code_points(contents, 2)?,
        UNIVERSAL_STRING => code_points(contents, 4)?,
        _ => return Some(der(tag, contents)),
    };
    Some(der(UTF8_STRING, canonical_text(&text).as_bytes()))
}

/// `contents` as big-endian code points of `width` octets each.
fn code_points(contents: &[u8], width: usize) -> Option<String> {
    if !contents.len().is_multiple_of(width) {
        return None;
    }
    contents
        .chunks_exact(width)
        .map(|unit| {
            char::from_u32(
                unit.iter()
                    .fold(0, |point, &octet| (point << 8) | u32::from(octet)),
            )
        })
        .collect()
}

/// `asn1_string_canon`'s rule for text: whitespace dropped from both ends,
/// each run of it inside collapsed to one space, ASCII letters lowercased,
/// and every other character kept as it is.
fn canonical_text(text: &str) -> String {
    // `ossl_isspace`: the C locale's whitespace, vertical tab included.
    const WHITESPACE: [char; 6] = [' ', '\t', '\n', '\x0b', '\x0c', '\r'];
    text.split(WHITESPACE)
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// One DER element: `tag`, the definite length of `contents`, `contents`.
fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    match u8::try_from(contents.len()) {
        Ok(len) if len < 0x80 => encoded.push(len),
        _ => {
            let len = contents.len().to_be_bytes();
            let octets = &len[len.iter().take_while(|&&octet| octet == 0).count()..];
            // At most `size_of::<usize>()` octets.
            encoded.push(0x80 | octets.len() as u8);
            encoded.extend_from_slice(octets);
        }
    }
    encoded.extend_from_slice(contents);
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test anchor's subject is `C=GB` as a PrintableString, then
    /// `O=  Minimal   Test  Anchors ` and the multi-valued
    /// `CN=Box  Egress<TAB>ANCHOR+OU=Unit Two` as UTF8Strings: every rule of
    /// the canonical form has something to do.
    const ANCHOR: &str = include_str!("test_anchor.pem");

    /// The hash is the one OpenSSL files the certificate under:
    /// `openssl x509 -in test_anchor.pem -noout -subject_hash` prints
    /// `42d333ec` (OpenSSL 3.6.4).
    #[test]
    fn the_hash_is_the_one_openssl_files_the_certificate_under() {
        assert_eq!(
            format!("{:08x}", subject_hash(ANCHOR.as_bytes()).unwrap()),
            "42d333ec"
        );
    }

    #[test]
    fn canonical_text_trims_collapses_and_lowercases_ascii_only() {
        assert_eq!(
            canonical_text("  Box \t\x0b Egress\r\nÄNCHOR  "),
            "box egress Änchor"
        );
    }

    #[test]
    fn a_file_that_is_not_a_certificate_is_refused_as_invalid_data() {
        for pem in [
            &b"not a certificate"[..],
            b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
            b"-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n",
        ] {
            let error = subject_hash(pem).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        }
    }
}

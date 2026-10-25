//! Injection of a store value into a request, in the form its rule
//! registers (BEP-065, BEP-066).
//!
//! A store reference arrives as a sealed value in one header of the
//! request. [`inject`] removes that header, and puts the value in the
//! registered form:
//!
//! - [`Inject::Header`]: one header of the registered name, whose value is
//!   exactly the registered prefix followed by the stored value. Any other
//!   header of that name is removed, so the upstream sees one value only.
//! - [`Inject::BasicAuth`]: one `Authorization: Basic` header, with the
//!   stored value in the registered field. The other field is the one the
//!   box sent beside its sealed value, or empty. Any other `Authorization`
//!   header is removed.
//!
//! A value or prefix that holds a CR, LF or NUL byte is refused as
//! [`INJECTION_INVALID`], and the request is unchanged. So is a value with a
//! `:` in the `user` field, which the upstream reads as the end of the user,
//! and a form that names no valid header or field.
//!
//! No function here logs, copies to a file, or keeps the value. Each copy it
//! makes is zeroized when dropped, except the header [`inject`] writes. That
//! header moves into the request, and the caller zeroizes it once the
//! request is written.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::{Zeroize as _, Zeroizing};

use crate::handle::Inject;
use crate::http::{Header, Request};

/// The audit marker of a refused injection: the value or the prefix holds a
/// line break, or the form cannot carry the value (BEP-066).
pub const INJECTION_INVALID: &str = "injection_invalid";

/// The `basic_auth` field that carries the value as the user.
pub const FIELD_USER: &str = "user";

/// The `basic_auth` field that carries the value as the password.
pub const FIELD_PASSWORD: &str = "password";

/// Whether `bytes` can go in a header value: no CR, LF or NUL.
fn header_safe(bytes: &[u8]) -> bool {
    !bytes.iter().any(|b| matches!(b, b'\r' | b'\n' | 0))
}

/// Whether `name` is a header field name (RFC 9110 `token`).
fn token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Whether `name` is a header that frames the message or is hop-by-hop
/// (RFC 9110 section 7.6.1, RFC 9112). The parser checks these before
/// injection, so an injected value in one of them reaches the upstream
/// unchecked.
fn framing(name: &str) -> bool {
    const NAMES: [&str; 10] = [
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    NAMES.iter().any(|n| name.eq_ignore_ascii_case(n))
}

/// The header that `form` writes for `value`: its lowercase name and its
/// value. `other` is the `basic_auth` field the box sent beside its sealed
/// value, or empty.
///
/// # Errors
///
/// [`INJECTION_INVALID`] when the value, the prefix or `other` holds a CR,
/// LF or NUL byte, when a `user` value holds a `:`, or when the form names
/// no valid header name or field. A framing or hop-by-hop header name, such
/// as `content-length` or `connection`, is not a valid header name here.
pub fn header_for(
    form: &Inject,
    value: &[u8],
    other: &[u8],
) -> Result<(String, Zeroizing<Vec<u8>>), &'static str> {
    if !header_safe(value) {
        return Err(INJECTION_INVALID);
    }
    match form {
        Inject::Header { name, prefix } => {
            let prefix = prefix.as_deref().unwrap_or("");
            if !token(name) || framing(name) || !header_safe(prefix.as_bytes()) {
                return Err(INJECTION_INVALID);
            }
            let mut out = Zeroizing::new(Vec::with_capacity(prefix.len() + value.len()));
            out.extend_from_slice(prefix.as_bytes());
            out.extend_from_slice(value);
            Ok((name.to_ascii_lowercase(), out))
        }
        Inject::BasicAuth { field } => {
            if !header_safe(other) {
                return Err(INJECTION_INVALID);
            }
            let (user, pass) = match field.as_str() {
                FIELD_USER => (value, other),
                FIELD_PASSWORD => (other, value),
                _ => return Err(INJECTION_INVALID),
            };
            // RFC 7617: the user ends at the first colon.
            if user.contains(&b':') {
                return Err(INJECTION_INVALID);
            }
            let mut pair = Zeroizing::new(Vec::with_capacity(user.len() + pass.len() + 1));
            pair.extend_from_slice(user);
            pair.push(b':');
            pair.extend_from_slice(pass);
            // Encode into the zeroizing buffer itself. It is sized once, so
            // no unzeroized copy of the encoded value is left behind.
            const SCHEME: &[u8] = b"Basic ";
            let encoded = base64::encoded_len(pair.len(), true).ok_or(INJECTION_INVALID)?;
            let mut out = Zeroizing::new(vec![0u8; SCHEME.len() + encoded]);
            out[..SCHEME.len()].copy_from_slice(SCHEME);
            let written = STANDARD
                .encode_slice(pair.as_slice(), &mut out[SCHEME.len()..])
                .map_err(|_| INJECTION_INVALID)?;
            debug_assert_eq!(written, encoded);
            Ok(("authorization".to_owned(), out))
        }
    }
}

/// Removes the header at `sealed` from `request`, and puts `value` in its
/// place in `form`. `other` is the `basic_auth` field the box sent beside its
/// sealed value, or empty.
///
/// # Errors
///
/// [`INJECTION_INVALID`], as [`header_for`] gives it. The request is then
/// unchanged.
pub fn inject(
    request: &mut Request,
    sealed: usize,
    form: &Inject,
    value: &[u8],
    other: &[u8],
) -> Result<(), &'static str> {
    if sealed >= request.headers.len() {
        return Err(INJECTION_INVALID);
    }
    let (name, mut header_value) = header_for(form, value, other)?;
    let mut at = 0usize;
    let mut kept = Vec::with_capacity(request.headers.len());
    for (index, mut header) in std::mem::take(&mut request.headers).into_iter().enumerate() {
        if index == sealed {
            at = kept.len();
            header.value.zeroize();
            continue;
        }
        if header.name.eq_ignore_ascii_case(&name) {
            // One value of the registered header reaches the upstream.
            header.value.zeroize();
            continue;
        }
        kept.push(header);
    }
    kept.insert(
        at,
        Header {
            name,
            // Moved, not copied, so no unzeroized copy is left behind.
            value: std::mem::take(&mut *header_value),
        },
    );
    request.headers = kept;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::BodyFraming;

    fn request(headers: &[(&str, &str)]) -> Request {
        Request {
            method: "GET".into(),
            target: "/v1/models".into(),
            headers: headers
                .iter()
                .map(|(n, v)| Header {
                    name: (*n).to_owned(),
                    value: v.as_bytes().to_vec(),
                })
                .collect(),
            body: BodyFraming::None,
        }
    }

    fn values<'a>(request: &'a Request, name: &str) -> Vec<&'a [u8]> {
        request
            .headers
            .iter()
            .filter(|h| h.name == name)
            .map(|h| h.value.as_slice())
            .collect()
    }

    // BEP-065: the header's value is exactly the prefix and the value, with
    // nothing added, trimmed or encoded. With no prefix it is the value.
    #[test]
    fn injected_value_is_exactly_prefix_plus_value() {
        let bearer = Inject::Header {
            name: "Authorization".into(),
            prefix: Some("Bearer ".into()),
        };
        let mut r = request(&[
            ("host", "api.openai.com"),
            ("authorization", "Bearer SEALED"),
        ]);
        inject(&mut r, 1, &bearer, b"sk-the-key", b"").unwrap();
        assert_eq!(
            values(&r, "authorization"),
            vec![b"Bearer sk-the-key".as_slice()]
        );
        assert_eq!(r.headers.len(), 2);
        assert_eq!(
            r.headers[1].name, "authorization",
            "the header keeps its place"
        );

        // No prefix: the value alone, in a header of its own name.
        let api_key = Inject::Header {
            name: "X-Api-Key".into(),
            prefix: None,
        };
        let mut r = request(&[("x-api-key", "SEALED"), ("accept", "*/*")]);
        inject(&mut r, 0, &api_key, b"  key with spaces ", b"").unwrap();
        assert_eq!(
            values(&r, "x-api-key"),
            vec![b"  key with spaces ".as_slice()]
        );

        // A prefix with no space is not given one.
        let token = Inject::Header {
            name: "x-token".into(),
            prefix: Some("tok=".into()),
        };
        let (name, value) = header_for(&token, b"abc", b"").unwrap();
        assert_eq!(name, "x-token");
        assert_eq!(value.as_slice(), b"tok=abc");

        // The sealed value sent in another header goes, and the registered
        // header is the only one of its name.
        let mut r = request(&[("x-api-key", "box-own"), ("authorization", "Bearer SEALED")]);
        inject(&mut r, 1, &api_key, b"stored", b"").unwrap();
        assert_eq!(values(&r, "x-api-key"), vec![b"stored".as_slice()]);
        assert!(values(&r, "authorization").is_empty());

        // basic_auth fills one field, and keeps the box's other field.
        let user = Inject::BasicAuth {
            field: FIELD_USER.into(),
        };
        let (name, value) = header_for(&user, b"the-key", b"").unwrap();
        assert_eq!(name, "authorization");
        assert_eq!(
            value.as_slice(),
            format!("Basic {}", STANDARD.encode("the-key:")).as_bytes()
        );
        let password = Inject::BasicAuth {
            field: FIELD_PASSWORD.into(),
        };
        let (_, value) = header_for(&password, b"pa:ss", b"me").unwrap();
        assert_eq!(
            value.as_slice(),
            format!("Basic {}", STANDARD.encode("me:pa:ss")).as_bytes()
        );
    }

    // BEP-066: a CR or LF in the value or the prefix refuses the injection,
    // and the request is unchanged.
    #[test]
    fn crlf_in_value_or_prefix_refuses_injection() {
        let bearer = Inject::Header {
            name: "authorization".into(),
            prefix: Some("Bearer ".into()),
        };
        let original = request(&[("authorization", "Bearer SEALED")]);
        for bad in [&b"key\r\nx-evil: 1"[..], b"key\n", b"\rkey", b"k\0ey"] {
            let mut r = original.clone();
            assert_eq!(inject(&mut r, 0, &bearer, bad, b""), Err(INJECTION_INVALID));
            assert_eq!(r, original);
        }
        for prefix in ["Bearer\r\n", "\nBearer ", "x\r"] {
            let form = Inject::Header {
                name: "authorization".into(),
                prefix: Some(prefix.into()),
            };
            let mut r = original.clone();
            assert_eq!(
                inject(&mut r, 0, &form, b"key", b""),
                Err(INJECTION_INVALID)
            );
            assert_eq!(r, original);
        }
        let basic = Inject::BasicAuth {
            field: FIELD_PASSWORD.into(),
        };
        assert_eq!(
            header_for(&basic, b"pa\nss", b"me").unwrap_err(),
            INJECTION_INVALID
        );
        assert_eq!(
            header_for(&basic, b"pass", b"m\re").unwrap_err(),
            INJECTION_INVALID
        );
        // A colon in the user field, a field that is not one, and a header
        // name that is not a token are refused the same way.
        let user = Inject::BasicAuth {
            field: FIELD_USER.into(),
        };
        assert_eq!(
            header_for(&user, b"a:b", b"").unwrap_err(),
            INJECTION_INVALID
        );
        let field = Inject::BasicAuth {
            field: "token".into(),
        };
        assert_eq!(
            header_for(&field, b"k", b"").unwrap_err(),
            INJECTION_INVALID
        );
        let name = Inject::Header {
            name: "x key".into(),
            prefix: None,
        };
        assert_eq!(header_for(&name, b"k", b"").unwrap_err(), INJECTION_INVALID);
        // A header that frames the message or is hop-by-hop is refused, so
        // an injected value cannot change what the parser checked.
        for framed in [
            "Content-Length",
            "transfer-encoding",
            "HOST",
            "connection",
            "te",
        ] {
            let form = Inject::Header {
                name: framed.into(),
                prefix: None,
            };
            assert_eq!(header_for(&form, b"1", b"").unwrap_err(), INJECTION_INVALID);
        }
    }
}

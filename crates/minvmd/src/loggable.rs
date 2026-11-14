//! A guest's bytes as a log line names them: bounded and escaped.
//!
//! Some of what this daemon logs is the guest's to choose — a refused
//! request's target, a request line the door could not parse — and a line
//! written with `%` writes it as it is. The file appender's own escaping
//! covers ESC and a few other terminal controls, but not CR, LF, NUL or the
//! rest of C0, and an exporter's attribute is written raw: a guest that
//! spells a newline can forge a line after its own, and one that spells a CR
//! can overwrite the line it is on in a terminal that tails the log.
//!
//! A value of printable ASCII within its bound — everything the daemon's own
//! clients send — is named as it is, so an honest line reads the same as it
//! always has. Anything else is named escaped and quoted, the way `{:?}`
//! writes a string, so it cannot break the line or forge one, and cut to the
//! bound on a char boundary with a marker naming its full length, so it
//! cannot flood the log either.

use std::borrow::Cow;

/// `text` as a log line names it: as it is when it is printable ASCII of at
/// most `max` bytes, otherwise escaped (`{:?}`) and cut to `max` bytes with
/// a `... (N bytes in all)` marker.
pub(crate) fn text_within(text: &str, max: usize) -> Cow<'_, str> {
    if is_plain(text.as_bytes(), max) {
        return Cow::Borrowed(text);
    }
    bounded(format!("{text:?}"), max, text.len())
}

/// `bytes` as a log line names them: as they are when they are printable
/// ASCII of at most `max` bytes, otherwise quoted and escaped byte by byte
/// (`<[u8]>::escape_ascii`, so a byte that is not UTF-8 is named as the
/// byte it is) and cut to `max` bytes with a `... (N bytes in all)` marker.
pub(crate) fn bytes_within(bytes: &[u8], max: usize) -> Cow<'_, str> {
    if is_plain(bytes, max)
        && let Ok(text) = std::str::from_utf8(bytes)
    {
        return Cow::Borrowed(text);
    }
    bounded(format!("\"{}\"", bytes.escape_ascii()), max, bytes.len())
}

/// Whether `bytes` are named as they are: printable ASCII, the space
/// included, within `max`.
fn is_plain(bytes: &[u8], max: usize) -> bool {
    bytes.len() <= max && bytes.iter().all(|b| *b == b' ' || b.is_ascii_graphic())
}

/// `escaped` cut to `max` bytes on a char boundary, marked with `len`, the
/// value's own length, when it ran past the bound.
fn bounded(mut escaped: String, max: usize, len: usize) -> Cow<'static, str> {
    if escaped.len() > max {
        escaped.truncate(escaped.floor_char_boundary(max));
        escaped.push_str(&format!("... ({len} bytes in all)"));
    }
    Cow::Owned(escaped)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{bytes_within, text_within};

    const MAX: usize = 120;

    /// No raw control character — C0, DEL, C1, or a Unicode line or
    /// paragraph separator — survives into what a line names.
    fn has_no_raw_control(named: &str) -> bool {
        !named
            .chars()
            .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}')
    }

    /// An honest value — printable ASCII within the bound — is named as it
    /// is, borrowed, so the lines the daemon's own clients cause read the
    /// same as before.
    #[test]
    fn an_honest_value_is_named_as_it_is() {
        for plain in [
            "",
            "/services/forwarder/all",
            "/tunnel?ip=100.64.0.9&port=22",
            "unknown variant `nope`, expected `register`",
            "name \"web\"",
        ] {
            assert!(
                matches!(text_within(plain, MAX), Cow::Borrowed(named) if named == plain),
                "{plain:?} is named as it is"
            );
            assert!(
                matches!(bytes_within(plain.as_bytes(), MAX), Cow::Borrowed(named) if named == plain),
                "{plain:?} as bytes is named as it is"
            );
        }
    }

    /// CR, LF, ESC, NUL and the rest are named escaped and quoted, so a
    /// guest's value cannot break the line, overwrite it, or forge another.
    #[test]
    fn a_control_byte_is_named_escaped() {
        let forged = "/a\rWARN forged rule_matched=\"none\"\n\u{1b}[2J\u{0}";
        let named = text_within(forged, MAX);
        assert_eq!(
            named,
            format!("{forged:?}"),
            "escaped whole within the bound"
        );
        assert!(has_no_raw_control(&named), "no raw control: {named:?}");

        let named = bytes_within(forged.as_bytes(), MAX);
        assert_eq!(
            named, r#""/a\rWARN forged rule_matched=\"none\"\n\x1b[2J\x00""#,
            "escaped byte by byte, quoted"
        );
        assert!(has_no_raw_control(&named), "no raw control: {named:?}");

        for control in [
            "\r", "\n", "\t", "\u{0}", "\u{7}", "\u{8}", "\u{1b}", "\u{7f}", "\u{85}", "\u{2028}",
            "\u{2029}",
        ] {
            let value = format!("web{control}min.internal.");
            let named = text_within(&value, MAX);
            assert!(
                matches!(named, Cow::Owned(_)) && has_no_raw_control(&named),
                "{value:?} is named escaped: {named:?}"
            );
            let named = bytes_within(value.as_bytes(), MAX);
            assert!(
                matches!(named, Cow::Owned(_)) && has_no_raw_control(&named),
                "{value:?} as bytes is named escaped: {named:?}"
            );
        }
    }

    /// Bytes that are not UTF-8 are named as the bytes they are, not as a
    /// replacement character.
    #[test]
    fn bytes_that_are_not_utf8_are_named_as_bytes() {
        assert_eq!(bytes_within(b"/a\xff\xfe", MAX), r#""/a\xff\xfe""#);
    }

    /// An over-long value is cut to the bound, keeps its head, and is
    /// marked with its full length; printable or not, it cannot flood the
    /// log.
    #[test]
    fn an_over_long_value_is_cut_and_marked() {
        let long = format!("/{}", "x".repeat(7000));
        for named in [text_within(&long, MAX), bytes_within(long.as_bytes(), MAX)] {
            let marker = format!("... ({} bytes in all)", long.len());
            assert!(named.ends_with(&marker), "the cut is marked: {named:?}");
            assert_eq!(named.len(), MAX + marker.len(), "cut to the bound");
            assert!(named.starts_with("\"/xxx"), "keeps the head: {named:?}");
        }

        // An over-long line of control bytes: each escapes to four bytes,
        // and the escaped form is what is cut.
        let shouted = "\r".repeat(MAX);
        let named = bytes_within(shouted.as_bytes(), MAX);
        let marker = format!("... ({MAX} bytes in all)");
        assert!(named.ends_with(&marker), "the cut is marked: {named:?}");
        assert!(
            named.len() <= MAX + marker.len(),
            "within the bound: {named:?}"
        );
        assert!(has_no_raw_control(&named), "no raw control: {named:?}");
    }

    /// A cut inside a multi-byte character lands on its boundary, at every
    /// offset the bound can fall on, and never panics the logging path.
    #[test]
    fn a_cut_lands_on_a_char_boundary() {
        for run in 0..=MAX {
            let value = format!("{}日\r{}", "x".repeat(run), "é".repeat(MAX));
            let named = text_within(&value, MAX);
            let marker = format!("... ({} bytes in all)", value.len());
            assert!(
                named.len() <= MAX + marker.len() && named.ends_with(&marker),
                "a {}-byte value is named within the bound, got {named:?}",
                value.len()
            );
        }
    }
}

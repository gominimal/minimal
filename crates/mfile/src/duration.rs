//! The timeout grammar: a whole number of seconds, or a whole number
//! followed by `s`, `m` or `h`. `min box exec --timeout` reads it through
//! [`parse_timeout_secs`] (BOX-149), and an entry's `timeout` key reads it
//! through [`spec_timeout`] (BOX-049).

/// What an entry's `timeout` key takes, as the refusal names it.
pub(crate) const TIMEOUT_TAKES: &str = "a whole number of seconds, or a string of a whole \
     number followed by s, m or h, such as \"30s\", \"5m\" or \"1h\"";

/// What a bad `timeout` string is, as the refusal names it.
const NOT_A_DURATION: &str = "a string that is not a duration";

/// What a negative `timeout` number is, as the refusal names it.
const NEGATIVE: &str = "a negative number";

/// What a `timeout` string past the largest TOML integer is, as the refusal
/// names it. The spec writes the value as a TOML integer, which is an `i64`.
const TOO_LONG: &str = "a duration that is too long";

/// Reads a timeout as whole seconds: a number of seconds, or a number
/// followed by `s`, `m` or `h`. Zero is refused, as the daemon refuses an
/// exec timeout of zero seconds (BOX-149).
///
/// # Errors
///
/// The refusal text that `min box exec --timeout` prints, for a value that
/// is not in the grammar or is zero.
pub fn parse_timeout_secs(raw: &str) -> Result<u64, String> {
    match duration_secs(raw) {
        Some(secs) if secs > 0 => Ok(secs),
        _ => Err(format!(
            "'{raw}' is not a timeout. Give a whole number of seconds, minutes or hours \
             that is more than zero, such as 30s, 5m or 1h."
        )),
    }
}

/// Reads an entry's `timeout` value as whole seconds. A zero timeout, in
/// any unit, is no timeout: `None`.
///
/// # Errors
///
/// What the value is, as the refusal names it, for a value that is not a
/// whole number of seconds or a string in the grammar, or for a string
/// whose seconds are more than `i64::MAX`, which `execution.timeout` cannot
/// hold as a TOML integer.
pub fn spec_timeout(value: &toml::Value) -> Result<Option<u64>, &'static str> {
    let secs = match value {
        toml::Value::Integer(n) => u64::try_from(*n).map_err(|_| NEGATIVE)?,
        toml::Value::String(raw) => {
            let secs = duration_secs(raw).ok_or(NOT_A_DURATION)?;
            i64::try_from(secs).map_err(|_| TOO_LONG)?;
            secs
        }
        other => return Err(crate::expand::value_words(other)),
    };
    Ok((secs > 0).then_some(secs))
}

/// The grammar's value in seconds, zero included. `None` for text that is
/// not in the grammar, or that overflows.
fn duration_secs(raw: &str) -> Option<u64> {
    let (digits, scale) = match raw.char_indices().last() {
        Some((at, 's')) => (&raw[..at], 1),
        Some((at, 'm')) => (&raw[..at], 60),
        Some((at, 'h')) => (&raw[..at], 3600),
        _ => (raw, 1),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let count: u64 = digits.parse().ok()?;
    count.checked_mul(scale)
}

#[cfg(test)]
mod tests {
    use super::*;

    // BOX-149: the grammar takes seconds, minutes and hours, and refuses
    // anything else, with the text `min box exec --timeout` prints.
    #[test]
    fn duration_takes_seconds_minutes_hours_and_refuses_the_rest() {
        for (raw, secs) in [("45", 45), ("30s", 30), ("5m", 300), ("1h", 3600)] {
            assert_eq!(parse_timeout_secs(raw), Ok(secs), "{raw}");
        }
        for raw in [
            "0",
            "0s",
            "0m",
            "abc",
            "-1",
            "1d",
            "s",
            "",
            "1.5",
            " 5",
            "18446744073709551615h",
        ] {
            assert_eq!(
                parse_timeout_secs(raw),
                Err(format!(
                    "'{raw}' is not a timeout. Give a whole number of seconds, minutes or \
                     hours that is more than zero, such as 30s, 5m or 1h."
                )),
                "{raw:?}"
            );
        }
    }

    // BOX-049: an entry's `timeout` of zero, in any unit, is no timeout.
    // Every other value reads as the CLI's grammar reads it.
    #[test]
    fn spec_timeout_zero_is_none() {
        for zero in [
            toml::Value::Integer(0),
            "0".into(),
            "0s".into(),
            "0m".into(),
            "00h".into(),
        ] {
            assert_eq!(spec_timeout(&zero), Ok(None), "{zero:?}");
        }
        assert_eq!(spec_timeout(&toml::Value::Integer(90)), Ok(Some(90)));
        assert_eq!(spec_timeout(&"2h".into()), Ok(Some(7200)));
        assert_eq!(spec_timeout(&"30".into()), Ok(Some(30)));
        assert_eq!(spec_timeout(&toml::Value::Integer(-5)), Err(NEGATIVE));
        assert_eq!(spec_timeout(&"2 days".into()), Err(NOT_A_DURATION));
        // `execution.timeout` is a TOML integer, so a string past `i64::MAX`
        // seconds is refused, and `i64::MAX` itself is taken.
        assert_eq!(spec_timeout(&"9223372036854775808".into()), Err(TOO_LONG));
        assert_eq!(spec_timeout(&"3000000000000000h".into()), Err(TOO_LONG));
        assert_eq!(
            spec_timeout(&"9223372036854775807".into()),
            Ok(Some(9_223_372_036_854_775_807))
        );
        assert_eq!(
            spec_timeout(&toml::Value::Float(1.5)),
            Err("a decimal number")
        );
        assert_eq!(spec_timeout(&true.into()), Err("a true or false value"));
    }
}

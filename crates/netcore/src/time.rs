//! Points in time and lengths of time, in milliseconds.
//!
//! Layer 0 of the crate, a leaf: a value with one meaning. It uses no other
//! module ([`crate`] lists the layers).
//!
//! Every public function of the crate that is told the time takes an
//! [`Instant`], and the constructors that take a length of time take a
//! [`Span`]. The two cannot be passed for each other, and neither can be
//! passed as a bare number, so a caller says which it means and in which
//! unit where it makes the value.
//!
//! The crate reads no clock. An `Instant` counts milliseconds from an origin
//! the caller fixes, the same origin for every call about one box. The
//! specifications are written in milliseconds and read the `ms` field.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// A point in time: milliseconds since the caller's origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Instant {
    pub ms: u64,
}

/// A length of time, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Span {
    pub ms: u64,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Instant {
    /// The point `ms` milliseconds after the origin.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r.ms == ms,
    ))]
    pub fn from_millis(ms: u64) -> Instant {
        Instant { ms }
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Span {
    /// A length of `ms` milliseconds.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r.ms == ms,
    ))]
    pub fn from_millis(ms: u64) -> Span {
        Span { ms }
    }

    /// A length of `s` seconds; the longest length when that does not fit.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            s as int * 1000 <= u64::MAX as int ==> r.ms as int == s as int * 1000,
            s as int * 1000 > u64::MAX as int ==> r.ms == u64::MAX,
    ))]
    pub fn from_secs(s: u64) -> Span {
        if s > u64::MAX / 1000 {
            Span { ms: u64::MAX }
        } else {
            Span { ms: s * 1000 }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_become_milliseconds_and_never_wrap() {
        assert_eq!(Span::from_secs(300).ms, 300_000);
        assert_eq!(Span::from_secs(u64::MAX).ms, u64::MAX);
        assert_eq!(Span::from_millis(5).ms, 5);
        assert_eq!(Instant::from_millis(7).ms, 7);
    }
}

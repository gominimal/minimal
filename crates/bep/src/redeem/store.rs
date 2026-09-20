//! The checks over a store handle, and the form a store value is injected in.
//!
//! A store handle (BEP-063) is the member inside the same sealed envelope a
//! module's member arrives in, so the checks over the envelope — that it
//! decrypted here, that the connection is attributed to the box it names,
//! that it is neither expired nor revoked — are [`super::member`]'s, run
//! unchanged. Where that module reads a module's host set, a mode and a
//! breadth, a handle has none: its own checks stand there (BEP-064). The
//! handle's `upstream` is the member's bound set, and the four handle checks
//! run before it is read, so a handle that fails any of them is refused as
//! `store_handle_invalid` whatever authority the request named.
//!
//! Every check is a predicate over the owned facts in a [`Redemption`], as in
//! the sibling modules: none reads a clock, a socket, a key or a rule file.
//! The shell parses the handle, verifies its signature under the client keys
//! it holds, finds the rule currently registered for the handle's store and
//! identifier, and interns the two injection forms as [`InjectId`]s that are
//! equal exactly when the forms are.
//!
//! The injection itself is two pure functions over strings ([`header_value`],
//! [`basic_value`]): exactly the registered prefix then the value as the
//! header's value, or the value as one field of a basic-authentication
//! credential (BEP-065), and none at all when the value or the prefix carries
//! a carriage return or a line feed (BEP-066).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::{Check, HostSet, Redemption, SealedMember, member};

/// An injection form, interned by the shell: a handle's form and a rule's
/// carry the same id exactly when they are the same form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct InjectId(pub u8);

/// A store handle as the decision sees it (BEP-064). Its `upstream` is the
/// bound set of the [`SealedMember`] it is carried as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreHandle {
    /// Whether the signature verified under the registered client key the
    /// handle names.
    pub verified: bool,
    /// The handle's own expiry, as seconds since the Unix epoch.
    pub expires_at: u64,
    /// The injection form the handle carries.
    pub inject: InjectId,
    /// The rule currently registered for the handle's store and identifier,
    /// or `None` when none is.
    pub rule: Option<StoreRule>,
}

/// The rule currently registered for a store and an identifier, as the
/// decision sees it: what a handle minted from an earlier form of it is
/// checked against (BEP-064).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreRule {
    /// The authorities the rule registers, interned.
    pub upstream: HostSet,
    /// The injection form the rule registers.
    pub inject: InjectId,
}

/// The field of a basic-authentication credential a store value fills
/// (BEP-065).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicField {
    /// The user field.
    User,
    /// The password field.
    Password,
}

impl BasicField {
    /// The field a rule's `basic_auth` names, or `None` for one that is no
    /// field.
    #[must_use]
    pub fn recognise(field: &str) -> Option<Self> {
        match field {
            "user" => Some(Self::User),
            "password" => Some(Self::Password),
            _ => None,
        }
    }
}

/// One check as a predicate over the facts.
type Predicate = fn(&SealedMember, &StoreHandle, &Redemption) -> bool;

/// The checks over a store handle's envelope and the handle itself, in the
/// order they run; the first to fail names the refusal. The handle checks run
/// before the bound set is read, so a handle the rule no longer covers is
/// refused as such rather than for the authority it was presented at.
const CHECKS: [(Check, Predicate); 8] = [
    (Check::Attributed, attributed),
    (Check::HandleVerified, verified),
    (Check::HandleUnexpired, handle_unexpired),
    (Check::HandleWithinRule, within_rule),
    (Check::HandleInjectRegistered, inject_registered),
    (Check::InBoundSet, in_bound_set),
    (Check::Unexpired, unexpired),
    (Check::Unrevoked, unrevoked),
];

/// The first check `redemption` fails for the store handle it carries, or
/// `None` when it passes them all. A value that did not decrypt fails
/// [`Check::Decrypts`] before any other check is read.
pub(super) fn first_failure(redemption: &Redemption, handle: &StoreHandle) -> Option<Check> {
    let Some(member) = &redemption.member else {
        return Some(Check::Decrypts);
    };
    CHECKS
        .iter()
        .find(|(_, passes)| !passes(member, handle, redemption))
        .map(|(check, _)| *check)
}

/// BEP-020, as the envelope carries it.
fn attributed(member: &SealedMember, _: &StoreHandle, redemption: &Redemption) -> bool {
    member::attributed(member, redemption)
}

/// BEP-064: the signature verified under a registered client key.
fn verified(_: &SealedMember, handle: &StoreHandle, _: &Redemption) -> bool {
    handle.verified
}

/// BEP-064: the clock is before the handle's own expiry.
fn handle_unexpired(_: &SealedMember, handle: &StoreHandle, redemption: &Redemption) -> bool {
    redemption.now < handle.expires_at
}

/// BEP-064: the handle's `upstream` — the bound set — is a subset of the
/// rule currently registered for its store and identifier; no rule, no
/// subset.
fn within_rule(member: &SealedMember, handle: &StoreHandle, _: &Redemption) -> bool {
    handle
        .rule
        .as_ref()
        .is_some_and(|rule| member.bound_set.is_subset_of(&rule.upstream))
}

/// BEP-064: the handle's `inject` is the rule's.
fn inject_registered(_: &SealedMember, handle: &StoreHandle, _: &Redemption) -> bool {
    handle
        .rule
        .as_ref()
        .is_some_and(|rule| rule.inject == handle.inject)
}

/// BEP-021, with the handle's `upstream` as the bound set.
fn in_bound_set(member: &SealedMember, _: &StoreHandle, redemption: &Redemption) -> bool {
    member::in_bound_set(member, redemption)
}

/// BEP-024, as the envelope carries it.
fn unexpired(member: &SealedMember, _: &StoreHandle, redemption: &Redemption) -> bool {
    member::unexpired(member, redemption)
}

/// BEP-024: no revocation in force covers the envelope.
fn unrevoked(member: &SealedMember, _: &StoreHandle, redemption: &Redemption) -> bool {
    member::unrevoked(member, redemption)
}

// ---------------------------------------------------------------------------
// The injection: the registered form, exactly (BEP-065), or nothing at all
// (BEP-066).
// ---------------------------------------------------------------------------

/// Whether `text` carries a carriage return or a line feed: what would end
/// the header the value is written to and start another (BEP-066).
fn breaks_line(text: &str) -> bool {
    text.contains(['\r', '\n'])
}

/// The header value the header form emits: exactly `prefix` followed by
/// `value`, nothing trimmed, nothing added (BEP-065); `None` when either
/// carries a carriage return or a line feed (BEP-066).
#[must_use]
pub fn header_value(prefix: &str, value: &str) -> Option<String> {
    if breaks_line(prefix) || breaks_line(value) {
        return None;
    }
    Some(format!("{prefix}{value}"))
}

/// The `Authorization` value the basic-authentication form emits: `Basic`
/// and the base64 of `user:password` with `value` as `field` and `other` as
/// the other field, as the box sent it (BEP-065); `None` when the value
/// carries a carriage return or a line feed (BEP-066) — the encoding would
/// hide one, and a value that breaks a line is refused in every form.
#[must_use]
pub fn basic_value(field: BasicField, value: &str, other: &str) -> Option<String> {
    if breaks_line(value) {
        return None;
    }
    let credentials = match field {
        BasicField::User => format!("{value}:{other}"),
        BasicField::Password => format!("{other}:{value}"),
    };
    Some(format!("Basic {}", STANDARD.encode(credentials)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BEP-065: the header form emits exactly the registered prefix followed
    /// by the value — no separator added, no whitespace trimmed, an empty
    /// prefix contributing nothing — and the basic form fills exactly the one
    /// field the rule names with the value, the other field as the box sent
    /// it.
    #[test]
    fn injected_value_is_exactly_prefix_plus_value() {
        assert_eq!(
            header_value("Bearer ", "sk-ant-api03-notreal").as_deref(),
            Some("Bearer sk-ant-api03-notreal")
        );
        assert_eq!(
            header_value("", "sk-ant-api03-notreal").as_deref(),
            Some("sk-ant-api03-notreal")
        );
        // Nothing is inserted between the two, and nothing is trimmed from
        // either: a prefix without its trailing space and a value with one
        // both go out as registered and as stored.
        assert_eq!(header_value("Bearer", "tok").as_deref(), Some("Bearertok"));
        assert_eq!(header_value("Key ", " tok ").as_deref(), Some("Key  tok "));
        assert_eq!(header_value("", "").as_deref(), Some(""));

        // The basic form: one field is the value, the other is the box's.
        assert_eq!(
            basic_value(BasicField::Password, "tok", "octocat").as_deref(),
            Some("Basic b2N0b2NhdDp0b2s=")
        );
        assert_eq!(
            basic_value(BasicField::User, "tok", "").as_deref(),
            Some("Basic dG9rOg==")
        );
        assert_eq!(BasicField::recognise("user"), Some(BasicField::User));
        assert_eq!(
            BasicField::recognise("password"),
            Some(BasicField::Password)
        );
        assert_eq!(BasicField::recognise("username"), None);
    }

    /// BEP-066: a carriage return or a line feed in the value or in the
    /// registered prefix is no injection at all, in either form — including
    /// the basic form, whose encoding would otherwise carry it through.
    #[test]
    fn crlf_in_value_or_prefix_refuses_injection() {
        for broken in ["tok\r\nX-Injected: yes", "tok\n", "\rtok", "to\nk"] {
            assert_eq!(header_value("Bearer ", broken), None, "{broken:?}");
            assert_eq!(header_value("", broken), None, "{broken:?}");
            assert_eq!(
                basic_value(BasicField::Password, broken, "octocat"),
                None,
                "{broken:?}"
            );
            assert_eq!(
                basic_value(BasicField::User, broken, ""),
                None,
                "{broken:?}"
            );
        }
        for prefix in ["Bearer\r\n", "Bearer\n ", "\r"] {
            assert_eq!(header_value(prefix, "tok"), None, "{prefix:?}");
        }
        // Whitespace that does not break a line is carried as registered.
        assert_eq!(
            header_value("Bearer\t", "tok").as_deref(),
            Some("Bearer\ttok")
        );
    }
}

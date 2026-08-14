//! Session-scoped bearer tokens: mint, scope, expiry, and revocation.
//!
//! The token is a capability naming which lanes a box may use, not a
//! credential. It is stored only as a digest, so the broker's memory does not
//! hold anything replayable.
//!
//! Expiry is measured against a caller-supplied [`Instant`]. The clock is an
//! argument rather than an ambient read so the broker's own loop decides how
//! often it reads time, and so tests age a token without sleeping. A monotonic
//! instant also survives a wall-clock jump, which an absolute TTL must.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sessions::SessionId;

use crate::lane::Secret;

/// Bytes of entropy behind a token, hex-encoded to twice that many characters.
const TOKEN_BYTES: usize = 32;

/// Bytes behind a registration handle. Unguessable because presenting one
/// revokes the registration it names.
const HANDLE_BYTES: usize = 16;

/// The single refusal the box-facing path ever produces.
///
/// It is a struct, not an enum, on purpose: an unknown token, an expired
/// token, a revoked registration, and a lane outside the token's scope must
/// stay indistinguishable, and there is no variant to add one accidentally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("credential lane request refused")]
pub struct Refused;

/// A bearer token, held by the box and presented on every request. Redacted in
/// `Debug` by [`Secret`].
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Token(Secret);

impl Token {
    fn mint() -> Self {
        Self(Secret::new(hex::encode(random_bytes::<TOKEN_BYTES>())))
    }

    /// The token as the box presents it, for putting on the wire.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// An opaque handle to one registration, returned alongside the token it
/// scopes and used to revoke it.
///
/// Registrations are keyed by this rather than by session id: two sessions may
/// hold the same lane name with different credentials, and a session-keyed
/// store would let one reach the other's. The session id is carried alongside
/// (see [`TokenStore::revoke_session`]) rather than in its place.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RegistrationHandle(String);

impl RegistrationHandle {
    fn mint() -> Self {
        Self(hex::encode(random_bytes::<HANDLE_BYTES>()))
    }
}

impl fmt::Display for RegistrationHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One registration: the digest of a token, the lanes it may reach, the
/// session it was made for, and when it dies.
struct Registration {
    session: SessionId,
    digest: blake3::Hash,
    lanes: BTreeSet<String>,
    expires_at: Instant,
}

/// The broker's live tokens.
#[derive(Default)]
pub struct TokenStore {
    registrations: HashMap<RegistrationHandle, Registration>,
}

impl TokenStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mints a token for `session`, scoped to `lanes` and expiring `ttl` after
    /// `now`.
    ///
    /// The token is returned once and never stored; the store keeps only its
    /// digest. The handle is the caller's primary later reference to it;
    /// `session` is the one a teardown that holds no handle has.
    #[must_use]
    pub fn mint(
        &mut self,
        session: SessionId,
        lanes: impl IntoIterator<Item = String>,
        now: Instant,
        ttl: Duration,
    ) -> (Token, RegistrationHandle) {
        let token = Token::mint();
        let handle = RegistrationHandle::mint();
        self.registrations.insert(
            handle.clone(),
            Registration {
                session,
                digest: blake3::hash(token.expose().as_bytes()),
                lanes: lanes.into_iter().collect(),
                expires_at: now + ttl,
            },
        );
        (token, handle)
    }

    /// Drops a registration, refusing every later use of its token. Returns
    /// whether it was still live — a control-path answer for the client that
    /// owns the handle, never surfaced to a box.
    pub fn revoke(&mut self, handle: &RegistrationHandle) -> bool {
        self.registrations.remove(handle).is_some()
    }

    /// Drops every registration made for `session`, yielding the handles that
    /// were live so the caller can drop whatever it keyed on them.
    ///
    /// The session is found by scanning rather than through a second map keyed
    /// by it: the store holds one entry per live activation, and a
    /// denormalised index would be a second source of truth every
    /// handle-revoke had to remember to update.
    pub fn revoke_session(&mut self, session: SessionId) -> Vec<RegistrationHandle> {
        let doomed: Vec<_> = self
            .registrations
            .iter()
            .filter(|(_, reg)| reg.session == session)
            .map(|(handle, _)| handle.clone())
            .collect();
        self.registrations.retain(|_, reg| reg.session != session);
        doomed
    }

    /// The handles of `session`'s registrations that have not expired.
    ///
    /// The read-only twin of [`Self::revoke_session`]: the same scan, scoped
    /// the same way, dropping nothing. Expiry is applied here because an
    /// expired registration authorises nothing — reporting it live would tell
    /// an operator a lane works when the next request refuses it.
    #[must_use]
    pub fn live_handles(&self, session: SessionId, now: Instant) -> Vec<RegistrationHandle> {
        self.registrations
            .iter()
            .filter(|(_, reg)| reg.session == session && now < reg.expires_at)
            .map(|(handle, _)| handle.clone())
            .collect()
    }

    /// Authorises `presented` for `lane`, yielding the registration it belongs
    /// to so the caller can resolve the lane against its own table.
    ///
    /// # Errors
    ///
    /// [`Refused`] — identically for an unknown token, an expired token, a
    /// revoked registration, and a lane outside the token's scope. Callers must
    /// not narrow it: a refusal that says which of those happened enumerates
    /// what exists.
    pub fn authorize(
        &self,
        presented: &str,
        lane: &str,
        now: Instant,
    ) -> Result<RegistrationHandle, Refused> {
        let digest = blake3::hash(presented.as_bytes());
        self.registrations
            .iter()
            // `blake3::Hash` equality is constant-time; comparing the raw bytes
            // would not be.
            .find(|(_, reg)| reg.digest == digest)
            .filter(|(_, reg)| now < reg.expires_at && reg.lanes.contains(lane))
            .map(|(handle, _)| handle.clone())
            .ok_or(Refused)
    }
}

fn random_bytes<const N: usize>() -> [u8; N] {
    rand::random()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_hours(1);

    fn lanes(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    /// A distinct session id per `n`, so a test can say which session a
    /// registration was made for without writing a UUID out by hand.
    fn session(n: u8) -> SessionId {
        SessionId::parse_str(&format!("00000000-0000-0000-0000-0000000000{n:02}")).unwrap()
    }

    #[test]
    fn a_fresh_token_authorises_a_lane_in_its_scope() {
        let now = Instant::now();
        let mut store = TokenStore::new();
        let (token, handle) = store.mint(session(1), lanes(&["anthropic", "github-mcp"]), now, TTL);

        assert_eq!(
            store.authorize(token.expose(), "github-mcp", now),
            Ok(handle)
        );
    }

    #[test]
    fn a_lane_outside_the_scope_is_refused_exactly_as_an_unknown_token_is() {
        let now = Instant::now();
        let mut store = TokenStore::new();
        let (token, _) = store.mint(session(1), lanes(&["anthropic"]), now, TTL);

        let out_of_scope = store.authorize(token.expose(), "github-mcp", now);
        let unknown = store.authorize("deadbeef", "github-mcp", now);
        assert_eq!(out_of_scope, Err(Refused));
        assert_eq!(out_of_scope, unknown);
    }

    #[test]
    fn an_expired_token_is_refused() {
        let now = Instant::now();
        let mut store = TokenStore::new();
        let (token, _) = store.mint(session(1), lanes(&["anthropic"]), now, TTL);

        assert!(
            store
                .authorize(token.expose(), "anthropic", now + TTL)
                .is_err()
        );
        assert!(
            store
                .authorize(token.expose(), "anthropic", now + TTL / 2)
                .is_ok()
        );
    }

    #[test]
    fn a_revoked_handle_refuses_its_token() {
        let now = Instant::now();
        let mut store = TokenStore::new();
        let (token, handle) = store.mint(session(1), lanes(&["anthropic"]), now, TTL);

        assert!(store.revoke(&handle));
        assert_eq!(
            store.authorize(token.expose(), "anthropic", now),
            Err(Refused)
        );
        assert!(
            !store.revoke(&handle),
            "revoking twice reports nothing live"
        );
    }

    #[test]
    fn revoking_one_registration_leaves_the_others_alone() {
        let now = Instant::now();
        let mut store = TokenStore::new();
        let (kept, _) = store.mint(session(1), lanes(&["anthropic"]), now, TTL);
        let (_, doomed) = store.mint(session(1), lanes(&["anthropic"]), now, TTL);

        store.revoke(&doomed);
        assert!(store.authorize(kept.expose(), "anthropic", now).is_ok());
    }

    #[test]
    fn two_mints_produce_different_tokens_and_handles() {
        let now = Instant::now();
        let mut store = TokenStore::new();
        let (first, first_handle) = store.mint(session(1), lanes(&["anthropic"]), now, TTL);
        let (second, second_handle) = store.mint(session(1), lanes(&["anthropic"]), now, TTL);

        assert_ne!(first.expose(), second.expose());
        assert_ne!(first_handle, second_handle);
        assert_eq!(first.expose().len(), TOKEN_BYTES * 2);
    }

    #[test]
    fn one_token_does_not_authorise_another_registrations_lane() {
        let now = Instant::now();
        let mut store = TokenStore::new();
        let (sink, _) = store.mint(session(1), lanes(&["sink"]), now, TTL);
        let (_, _mcp) = store.mint(session(2), lanes(&["github-mcp"]), now, TTL);

        assert_eq!(
            store.authorize(sink.expose(), "github-mcp", now),
            Err(Refused)
        );
    }

    /// R3.4: `min session destroy` runs in a process that never held the
    /// handle, so the session id is the only name it has for the registration.
    #[test]
    fn revoking_a_session_refuses_its_token_exactly_as_an_unknown_one_is_refused() {
        let now = Instant::now();
        let mut store = TokenStore::new();
        let (token, handle) = store.mint(session(1), lanes(&["anthropic"]), now, TTL);

        assert_eq!(store.revoke_session(session(1)), vec![handle]);
        assert_eq!(
            store.authorize(token.expose(), "anthropic", now),
            store.authorize("deadbeef", "anthropic", now),
        );
        assert_eq!(
            store.authorize(token.expose(), "anthropic", now),
            Err(Refused)
        );
    }

    #[test]
    fn revoking_one_session_leaves_another_sessions_registration_working() {
        let now = Instant::now();
        let mut store = TokenStore::new();
        let (kept, _) = store.mint(session(1), lanes(&["anthropic"]), now, TTL);
        let (doomed, _) = store.mint(session(2), lanes(&["anthropic"]), now, TTL);

        assert_eq!(store.revoke_session(session(2)).len(), 1);
        assert!(store.authorize(kept.expose(), "anthropic", now).is_ok());
        assert!(store.authorize(doomed.expose(), "anthropic", now).is_err());
    }

    /// A session with no lane never registers, and every destroy calls this.
    #[test]
    fn revoking_a_session_that_never_registered_is_a_no_op() {
        let mut store = TokenStore::new();
        assert!(store.revoke_session(session(9)).is_empty());
    }

    /// One session may register more than once — an activation retried, or a
    /// second lane set — and a destroy must leave none of them live.
    #[test]
    fn revoking_a_session_drops_every_registration_it_made() {
        let now = Instant::now();
        let mut store = TokenStore::new();
        let (first, _) = store.mint(session(1), lanes(&["anthropic"]), now, TTL);
        let (second, _) = store.mint(session(1), lanes(&["github-mcp"]), now, TTL);

        assert_eq!(store.revoke_session(session(1)).len(), 2);
        assert!(store.authorize(first.expose(), "anthropic", now).is_err());
        assert!(store.authorize(second.expose(), "github-mcp", now).is_err());
    }

    /// R7.1: an expired registration serves nothing, so it must not be
    /// reported as live either — a token past its TTL is exactly the state
    /// `min session credentials` exists to surface before a box hits a 401.
    #[test]
    fn an_expired_registration_is_no_longer_one_of_its_sessions_live_handles() {
        let now = Instant::now();
        let mut store = TokenStore::new();
        let (_, handle) = store.mint(session(1), lanes(&["anthropic"]), now, TTL);

        assert_eq!(store.live_handles(session(1), now), vec![handle]);
        assert!(store.live_handles(session(1), now + TTL).is_empty());
    }

    #[test]
    fn live_handles_names_only_the_handles_of_the_session_it_was_asked_about() {
        let now = Instant::now();
        let mut store = TokenStore::new();
        let (_, first) = store.mint(session(1), lanes(&["anthropic"]), now, TTL);
        let (_, second) = store.mint(session(1), lanes(&["github-mcp"]), now, TTL);
        let _other = store.mint(session(2), lanes(&["anthropic"]), now, TTL);

        let mut live = store.live_handles(session(1), now);
        live.sort_by_key(ToString::to_string);
        let mut expected = vec![first, second];
        expected.sort_by_key(ToString::to_string);
        assert_eq!(live, expected);
        assert!(store.live_handles(session(9), now).is_empty());
    }

    #[test]
    fn debugging_a_token_does_not_print_it() {
        let (token, _) =
            TokenStore::new().mint(session(1), lanes(&["anthropic"]), Instant::now(), TTL);
        let rendered = format!("{token:?}");
        assert!(!rendered.contains(token.expose()), "{rendered}");
    }
}

//! Minting a GitHub member from the held sign-in on an un-enrolled host
//! (BEP-005), and the identity events the client records for a mint and for
//! `min auth logout` (BEP-067).
//!
//! A locally minted member is the signed-in account's user token, `mode =
//! "user"` and `full` breadth, sealed to this host's key with the box, the
//! host, the module, the host-set version and the expiry bound in the
//! authenticated context (BEP-006). The expiry is the earlier of eight hours
//! from the mint and the token's own expiry: the member is a creation-time
//! snapshot, and a box that outlives it is re-created to re-mint.
//!
//! The mint and the logout each make one [`Event`] for the proxy's log; the
//! client submits it over the control socket ([`crate::control`]) and never
//! opens the log itself.

use crate::audit::{Decision, Event, Kind, Mapping};
use crate::github::SignIn;
use crate::keychain::KeyStore;
use crate::keys::Keys;
use crate::seal::{Member, SealError, SealedContext, SealedValue, seal};

/// The longest a locally minted member lives: eight hours from its mint.
pub const MAX_LIFETIME_SECS: u64 = 8 * 60 * 60;
/// The module identifier the member is sealed under.
pub const MODULE: &str = "github";
/// The mode of a member minted from the held sign-in.
pub const MODE: &str = "user";
/// The breadth of a locally minted member: the account's whole reach.
pub const BREADTH: &str = "full";
/// The member identifier the audit records name.
pub const CREDENTIAL: &str = "github:user-token";
/// The authority a GitHub identity event names.
pub const AUTHORITY: &str = "api.github.com";
/// The subject of a revocation that covers every box on the host.
pub const EVERY_BOX: &str = "*";

/// What a mint is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintRequest<'a> {
    /// The box the member is minted for.
    pub box_id: &'a str,
    /// The host the member is sealed on.
    pub host: &'a str,
    /// The version of the module's host set the member is minted under.
    pub host_set_version: u32,
    /// The clock, as seconds since the Unix epoch.
    pub now: u64,
}

/// A minted member: the sealed value for the box, the context it was sealed
/// with, and the record of the mint for the proxy's log.
#[derive(Debug)]
pub struct Minted {
    /// The sealed value, as delivered into the box.
    pub value: SealedValue,
    /// The authenticated context the value was sealed with.
    pub context: SealedContext,
    /// The `mint` event for the audit log.
    pub event: Event,
}

/// Why a member could not be minted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MintError {
    /// The held sign-in's token has already expired; sign in again.
    #[error("the GitHub sign-in as {account} expired at {expired_at}; run `min auth login`")]
    Expired { account: String, expired_at: u64 },
    /// The envelope could not be sealed.
    #[error(transparent)]
    Seal(#[from] SealError),
}

/// The expiry a member minted at `now` from a token expiring at
/// `token_expires_at` carries: the earlier of eight hours on and the token's
/// own expiry.
#[must_use]
pub fn member_expiry(now: u64, token_expires_at: Option<u64>) -> u64 {
    let ceiling = now.saturating_add(MAX_LIFETIME_SECS);
    token_expires_at.map_or(ceiling, |expiry| expiry.min(ceiling))
}

/// Mints a `user`, `full` member for `request.box_id` from `sign_in`, sealed
/// to `keys`.
///
/// # Errors
///
/// [`MintError::Expired`] when the sign-in's token has expired at
/// `request.now`; [`MintError::Seal`] when the envelope cannot be sealed.
pub fn mint<S: KeyStore>(
    keys: &Keys<S>,
    sign_in: &SignIn,
    request: &MintRequest<'_>,
) -> Result<Minted, MintError> {
    if let Some(expired_at) = sign_in.expires_at.filter(|expiry| *expiry <= request.now) {
        tracing::warn!(
            account = %sign_in.account,
            box_id = request.box_id,
            expired_at,
            "refusing to mint from an expired GitHub sign-in"
        );
        return Err(MintError::Expired {
            account: sign_in.account.clone(),
            expired_at,
        });
    }
    let context = SealedContext {
        box_id: request.box_id.to_owned(),
        host: request.host.to_owned(),
        module: MODULE.to_owned(),
        host_set_version: request.host_set_version,
        mode: MODE.to_owned(),
        breadth: BREADTH.to_owned(),
        expires_at: member_expiry(request.now, sign_in.expires_at),
    };
    let value = seal(keys, &context, &Member::new(sign_in.token.expose()))?;
    tracing::info!(
        account = %sign_in.account,
        box_id = request.box_id,
        expires_at = context.expires_at,
        "minted a GitHub member from the held sign-in"
    );
    Ok(Minted {
        value,
        event: identity_event(Kind::Mint, request.box_id),
        context,
    })
}

/// The `revocation` event `min auth logout` records: every GitHub member on
/// this host is refused from now on (BEP-044).
#[must_use]
pub fn revocation_event() -> Event {
    identity_event(Kind::Revocation, EVERY_BOX)
}

fn identity_event(kind: Kind, box_id: &str) -> Event {
    Event {
        kind,
        box_id: box_id.to_owned(),
        authority: AUTHORITY.to_owned(),
        credential: Some(CREDENTIAL.to_owned()),
        mapping: Mapping::Unmapped,
        decision: Decision::Admit,
        marker: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::Secret;
    use crate::keychain::MemoryStore;
    use crate::seal::unseal;

    const NOW: u64 = 1_800_000_000;

    fn sign_in(expires_at: Option<u64>) -> SignIn {
        SignIn {
            account: "octocat".into(),
            token: Secret::new("ghu_16C7e42F292c6912E7710c838347Ae178B4a"),
            expires_at,
            refresh_token: Some(Secret::new("ghr_refresh")),
            refresh_expires_at: Some(NOW + 15_811_200),
        }
    }

    fn request() -> MintRequest<'static> {
        MintRequest {
            box_id: "box-a1",
            host: "mac-1",
            host_set_version: 3,
            now: NOW,
        }
    }

    /// BEP-005: a member minted from the held sign-in is `user` mode, `full`
    /// breadth, and expires no later than eight hours after its mint —
    /// earlier when the token itself does.
    #[test]
    fn local_mint_expiry_is_at_most_8h() {
        let keys = Keys::open(MemoryStore::new()).unwrap();
        let ceiling = NOW + MAX_LIFETIME_SECS;

        // GitHub's own eight-hour user token, a token that never expires,
        // and one with an hour left: none of the three outlives the ceiling.
        for (token_expiry, expected) in [
            (Some(NOW + 28_800), ceiling),
            (None, ceiling),
            (Some(NOW + 3_600), NOW + 3_600),
            (Some(NOW + 100_000), ceiling),
        ] {
            let minted = mint(&keys, &sign_in(token_expiry), &request()).unwrap();
            assert!(minted.context.expires_at <= ceiling, "{token_expiry:?}");
            assert_eq!(minted.context.expires_at, expected, "{token_expiry:?}");

            let unsealed = unseal(&keys, minted.value.as_str()).unwrap();
            assert_eq!(unsealed.context, minted.context);
            assert_eq!(unsealed.context.mode, "user");
            assert_eq!(unsealed.context.breadth, "full");
            assert_eq!(unsealed.context.module, "github");
            assert_eq!(unsealed.context.box_id, "box-a1");
            assert_eq!(unsealed.context.host, "mac-1");
            assert_eq!(unsealed.context.host_set_version, 3);
            assert_eq!(unsealed.member.expose(), sign_in(None).token.expose());

            // The mint's record names the box and the member, never the token.
            assert_eq!(minted.event.kind, Kind::Mint);
            assert_eq!(minted.event.box_id, "box-a1");
            assert_eq!(minted.event.credential.as_deref(), Some(CREDENTIAL));
            let line = serde_json_lenient::to_string(&minted.event).unwrap();
            assert!(!line.contains("ghu_"), "{line}");
        }

        // An expired sign-in mints nothing.
        assert!(matches!(
            mint(&keys, &sign_in(Some(NOW)), &request()),
            Err(MintError::Expired { expired_at, .. }) if expired_at == NOW
        ));

        // Logout's revocation covers every box on the host.
        let revocation = revocation_event();
        assert_eq!(revocation.kind, Kind::Revocation);
        assert_eq!(revocation.box_id, EVERY_BOX);
    }
}

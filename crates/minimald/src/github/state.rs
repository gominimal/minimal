//! The daemon's single shared [`GithubService`] instance (spec 10) — the
//! composition root the rest of `crates/minimald/src/github/` fans out from.
//!
//! [`GithubService`] wires together every GitHub-domain building block the
//! `github` crate exports behind its `client` feature:
//!
//! - the on-disk [`GrantStore`], rooted at `<minimal_state_dir>/github/grants`
//!   (spec R1.3/R6.4);
//! - exactly **one** [`GrantManager`] over that store — single-flight token
//!   refresh (spec R1.2) only holds if the whole daemon shares one manager,
//!   so this is the only place a `GrantManager` is constructed;
//! - a [`DeviceFlowClient`] for the OAuth device flow (spec R1.1);
//! - a [`RestClient`] factory, built per grant via [`GithubService::rest_client`]
//!   (`RestClient` is generic over its token provider, so it cannot be one
//!   shared value the way the manager is);
//! - `github::gitops` stays deliberately stateless: callers obtain a token
//!   via [`GithubService::grants`]`.token_for(..)` and hand it to
//!   `github::gitops::Repo` themselves (spec R2.7).
//!
//! `minimald::server::ServerState` holds one [`GithubService`] for the
//! daemon's lifetime, and `ServerStateHandle::github` (see `server.rs`) hands
//! out cheap clones of it, so `rpc.rs`'s auth RPCs and `env.rs`'s session
//! facade channel always reach the same manager — a second `GithubService`
//! constructed over the same grants directory would still be *correct*
//! (the store itself is safe to open twice), but it would defeat
//! single-flight refresh (two independent `GrantManager`s, two independent
//! locks), so `ServerState` must own exactly one.
//!
//! # Unconfigured daemons (spec R1.1)
//!
//! No real GitHub App is provisioned yet, so `MINIMALD_GITHUB_CLIENT_ID` is
//! normally unset. [`GithubService::new`] always succeeds regardless —
//! daemon startup must never depend on GitHub being configured. Every
//! GitHub-touching operation this module's siblings add (`rpcs.rs`,
//! `authz.rs`, `prime.rs`, `push_pr.rs`, `facade.rs`) MUST call
//! [`GithubService::ensure_configured`] (or an equivalent `client_id()`
//! check) before doing any I/O, so an unconfigured daemon answers every
//! GitHub op with the actionable [`github::Error::NotConfigured`] instead of
//! a confusing failure further downstream.
//!
//! # Observability span conventions (spec R8.1)
//!
//! Every GitHub-touching daemon operation MUST open one of these `tracing`
//! spans, named exactly as listed (each is owned by the sibling module that
//! implements it):
//!
//! | Span              | Owner        | Covers                                                        |
//! |-------------------|--------------|---------------------------------------------------------------|
//! | `github.auth`     | `rpcs.rs`    | device-flow login/poll, status, list-auths, logout            |
//! | `github.refresh`  | `rpcs.rs`    | token refresh (incl. the `GrantManager`'s own transparent one) |
//! | `github.prime`    | `prime.rs`   | repo pre-priming / branch checkout-or-create                  |
//! | `github.facade`   | `facade.rs`  | `min git` / `min api` mediated operations                     |
//! | `github.push`     | `push_pr.rs` | explicit `min session push`                                   |
//! | `github.pr`       | `push_pr.rs` | PR create/detect, on exit or explicit request                 |
//!
//! Span **fields** are limited to `repo`, `branch`, and `grant_id` — never a
//! token, and never a full URL that could embed one. This mirrors the
//! crate-wide rule already enforced in `github::Error` and `SecretString`:
//! nothing token-shaped may reach a `tracing` event, a `Debug` impl, or an
//! error message (spec R6.2).

use github::{
    DeviceFlowClient, Error, GithubConfig, GrantId, GrantManager, GrantStore, GrantTokenProvider,
    HttpRefreshBackend, RestClient,
};
use url::Url;

/// The concrete [`GrantManager`] the daemon runs: refreshes over HTTP against
/// [`GithubConfig::oauth_base`]. Every daemon-side consumer of a refreshed
/// token goes through this type, via [`GithubService::grants`].
pub type DaemonGrantManager = GrantManager<HttpRefreshBackend>;

/// The registered GitHub App's slug, per the PRD's authentication model ("A
/// GitHub App... named e.g. `minimal`"). No App is provisioned yet — spec
/// R1.1's "unconfigured daemon" state is the normal one for now — so this
/// constant is only used to build the best-effort installation URL surfaced
/// by [`github::Error::AppNotInstalled`] (spec R1.5); it is not read from
/// [`GithubConfig`] because the config carries no App-identity field yet.
pub(super) const APP_SLUG: &str = "minimal";

/// The daemon's single composition root for everything GitHub (spec 10).
///
/// Cheap to clone: every field is either internally `Arc`-backed
/// (`GrantManager`, the `reqwest::Client`s inside `DeviceFlowClient`) or
/// plain data, so cloning shares state rather than duplicating it. See the
/// module docs for why `ServerState` must hold exactly one lineage.
#[derive(Debug, Clone)]
pub struct GithubService {
    config: GithubConfig,
    grants: DaemonGrantManager,
    device_flow: DeviceFlowClient,
}

impl GithubService {
    /// Builds the service from `config`, rooting the on-disk grant store at
    /// `grants_dir` (the daemon passes `<minimal_state_dir>/github/grants`;
    /// see `ServerState::new` in `server.rs`).
    ///
    /// Always succeeds — including when `config.client_id()` is unset — so
    /// daemon startup never depends on a GitHub App being provisioned.
    /// Callers MUST check [`GithubService::ensure_configured`] before
    /// performing any GitHub operation.
    ///
    /// # Errors
    ///
    /// Only if `grants_dir` cannot be created or its permissions asserted
    /// (spec R6.2's `0700`/`0600` file-layout guarantee) — never on account
    /// of `config` being unconfigured.
    pub fn new(
        config: GithubConfig,
        grants_dir: impl Into<std::path::PathBuf>,
    ) -> std::io::Result<Self> {
        let store = GrantStore::open(grants_dir)?;
        // No real client id in the common (unconfigured) case;
        // `HttpRefreshBackend` still needs *some* string to send as
        // `client_id` on a refresh exchange. An empty placeholder is safe:
        // `token_for`/`refresh_now` are the only callers, and both operate
        // only on a grant that was already minted by a real device-flow
        // login — which itself could only have happened while a client id
        // was actually configured. If the client id is unset when a refresh
        // later fires (e.g. the daemon restarted with the env var removed),
        // the exchange simply fails like any other misconfiguration rather
        // than silently authenticating as the wrong app.
        let client_id = config.client_id().unwrap_or_default().to_string();
        let backend = HttpRefreshBackend::new(config.oauth_base().clone(), client_id);
        let device_flow =
            DeviceFlowClient::new(config.oauth_base().clone(), config.api_base().clone());
        Ok(Self {
            grants: GrantManager::new(store, backend),
            device_flow,
            config,
        })
    }

    /// Fails closed with [`github::Error::NotConfigured`] when no GitHub App
    /// client id is set. The mandatory first call of every GitHub-touching
    /// operation this module's siblings implement (spec R1.1).
    ///
    /// # Errors
    ///
    /// [`github::Error::NotConfigured`] when unconfigured.
    pub fn ensure_configured(&self) -> Result<(), Error> {
        self.config.client_id().map(|_| ())
    }

    /// The resolved GitHub configuration (base URLs, and the client id when
    /// set).
    #[must_use]
    pub fn config(&self) -> &GithubConfig {
        &self.config
    }

    /// The one shared token-refresh state machine (spec R1.2). Every
    /// consumer of a refreshed access token — the REST client, `gitops`, the
    /// facade — must go through this, directly or via
    /// [`GithubService::rest_client`].
    #[must_use]
    pub fn grants(&self) -> &DaemonGrantManager {
        &self.grants
    }

    /// The OAuth device-flow client (spec R1.1).
    #[must_use]
    pub fn device_flow(&self) -> &DeviceFlowClient {
        &self.device_flow
    }

    /// Builds a REST client whose token provider transparently refreshes
    /// `grant_id` through the shared [`GithubService::grants`] manager.
    #[must_use]
    pub fn rest_client(
        &self,
        grant_id: GrantId,
    ) -> RestClient<GrantTokenProvider<HttpRefreshBackend>> {
        RestClient::new(
            self.config.api_base().clone(),
            self.install_url(),
            self.grants.token_provider(grant_id),
        )
    }

    /// Best-effort GitHub App installation URL, surfaced by
    /// [`github::Error::AppNotInstalled`] (spec R1.5). Built from
    /// [`APP_SLUG`] since no App is registered yet; falls back to the OAuth
    /// base itself if, somehow, that join fails.
    fn install_url(&self) -> Url {
        self.config
            .oauth_base()
            .join(&format!("apps/{APP_SLUG}/installations/new"))
            .unwrap_or_else(|_| self.config.oauth_base().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a [`GithubService`] over a fresh tempdir from the real process
    /// environment. This intentionally exercises [`GithubConfig::from_env`]
    /// (not a hand-built config) because the property under test — "an
    /// unconfigured daemon still constructs its `GithubService` and every op
    /// fails closed" — is precisely the ambient state of this test
    /// environment: nothing here sets `MINIMALD_GITHUB_CLIENT_ID`.
    fn unconfigured_service() -> (tempfile::TempDir, GithubService) {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let config = GithubConfig::from_env().expect("ambient env has no malformed override");
        assert!(
            !config.is_configured(),
            "this test assumes no MINIMALD_GITHUB_CLIENT_ID is set in the test environment"
        );
        let service = GithubService::new(config, tmp.path().join("github").join("grants"))
            .expect("an unconfigured GithubService must still construct");
        (tmp, service)
    }

    #[test]
    fn unconfigured_service_constructs_and_fails_closed() {
        let (_tmp, service) = unconfigured_service();
        assert!(
            matches!(service.ensure_configured(), Err(Error::NotConfigured)),
            "an unconfigured service must answer NotConfigured, not silently proceed"
        );
    }

    /// Every composed building block must be reachable — and safe to touch —
    /// even before a GitHub App is configured, since callers only learn that
    /// via `ensure_configured`/`client_id`, not via construction failing.
    #[test]
    fn every_composed_building_block_is_reachable_unconfigured() {
        let (_tmp, service) = unconfigured_service();

        let _config = service.config();
        let _grants = service.grants();
        let _device_flow = service.device_flow();
        let _rest = service.rest_client(GrantId::new("does-not-exist").unwrap());
    }

    /// Every `ServerStateHandle::github` caller gets its own clone of the one
    /// `GithubService`; cloning must be cheap and side-effect-free (no new
    /// grant store opened, no panic) so handing it to every RPC/facade call
    /// site is free.
    #[test]
    fn cloning_the_service_is_side_effect_free() {
        let (_tmp, service) = unconfigured_service();
        let clone = service.clone();
        assert!(matches!(
            clone.ensure_configured(),
            Err(Error::NotConfigured)
        ));
        assert_eq!(
            service.config().api_base(),
            clone.config().api_base(),
            "a clone must observe the same resolved configuration"
        );
    }
}

//! Daemon-side GitHub configuration (spec R1.1).
//!
//! The base URLs default to public GitHub (`github.com` / `api.github.com`) and
//! are overridable through environment variables — the override seam is how the
//! test suite (and later, mock-server integration tests) points the daemon at a
//! local fake instead of the real GitHub.
//!
//! `client_id` is `Option`: at launch no real GitHub App is provisioned, so it
//! is normally `None`. Callers that need it must go through
//! [`GithubConfig::client_id`], which fails closed with
//! [`Error::NotConfigured`] rather than proceeding without an App.

use url::Url;

use crate::error::Error;

/// Environment variable naming the GitHub App client id.
pub const ENV_CLIENT_ID: &str = "MINIMALD_GITHUB_CLIENT_ID";
/// Environment variable overriding the OAuth/device-flow base URL.
pub const ENV_OAUTH_BASE: &str = "MINIMALD_GITHUB_OAUTH_BASE_URL";
/// Environment variable overriding the REST API base URL.
pub const ENV_API_BASE: &str = "MINIMALD_GITHUB_API_BASE_URL";
/// Environment variable overriding the git-over-HTTPS base URL.
pub const ENV_GIT_BASE: &str = "MINIMALD_GITHUB_GIT_BASE_URL";

/// Default OAuth/device-flow base (public GitHub).
pub const DEFAULT_OAUTH_BASE: &str = "https://github.com";
/// Default REST API base (public GitHub).
pub const DEFAULT_API_BASE: &str = "https://api.github.com";
/// Default git-over-HTTPS base (public GitHub).
pub const DEFAULT_GIT_BASE: &str = "https://github.com";

/// Resolved GitHub configuration for the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubConfig {
    /// The GitHub App client id, or `None` when no App is configured yet.
    client_id: Option<String>,
    /// Base URL for the OAuth device flow.
    oauth_base: Url,
    /// Base URL for the REST API.
    api_base: Url,
    /// Base URL for git-over-HTTPS operations.
    git_base: Url,
}

impl GithubConfig {
    /// Builds a config from process environment variables, applying the public
    /// GitHub defaults for any base URL that is unset. Returns
    /// [`Error::InvalidConfig`] if an override is not a valid URL.
    pub fn from_env() -> Result<Self, Error> {
        Self::from_source(|key| std::env::var(key).ok())
    }

    /// Core constructor parameterised over an environment lookup, so tests can
    /// exercise override precedence without touching the process environment.
    fn from_source(get: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let client_id = get(ENV_CLIENT_ID).filter(|v| !v.trim().is_empty());
        Ok(Self {
            client_id,
            oauth_base: resolve_url(ENV_OAUTH_BASE, DEFAULT_OAUTH_BASE, &get)?,
            api_base: resolve_url(ENV_API_BASE, DEFAULT_API_BASE, &get)?,
            git_base: resolve_url(ENV_GIT_BASE, DEFAULT_GIT_BASE, &get)?,
        })
    }

    /// The GitHub App client id, or [`Error::NotConfigured`] when unset. This is
    /// the only sanctioned way to reach the client id, so no auth flow can start
    /// without an App.
    pub fn client_id(&self) -> Result<&str, Error> {
        self.client_id.as_deref().ok_or(Error::NotConfigured)
    }

    /// Whether a client id is configured (a non-failing probe for status).
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some()
    }

    /// The OAuth/device-flow base URL.
    #[must_use]
    pub fn oauth_base(&self) -> &Url {
        &self.oauth_base
    }

    /// The REST API base URL.
    #[must_use]
    pub fn api_base(&self) -> &Url {
        &self.api_base
    }

    /// The git-over-HTTPS base URL.
    #[must_use]
    pub fn git_base(&self) -> &Url {
        &self.git_base
    }
}

/// Resolves a base URL from an override env var, falling back to a default that
/// is a known-good constant.
fn resolve_url(
    var: &str,
    default: &str,
    get: &impl Fn(&str) -> Option<String>,
) -> Result<Url, Error> {
    match get(var).filter(|v| !v.trim().is_empty()) {
        Some(value) => Url::parse(&value).map_err(|e| Error::InvalidConfig {
            var: var.to_string(),
            reason: e.to_string(),
        }),
        // The default is a compile-time constant; parsing it cannot fail.
        None => Ok(Url::parse(default).expect("built-in default URL is valid")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn source(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn defaults_when_unset() {
        let cfg = GithubConfig::from_source(source(&[])).unwrap();
        assert_eq!(cfg.oauth_base().as_str(), "https://github.com/");
        assert_eq!(cfg.api_base().as_str(), "https://api.github.com/");
        assert_eq!(cfg.git_base().as_str(), "https://github.com/");
        assert!(!cfg.is_configured());
    }

    #[test]
    fn overrides_take_precedence() {
        let cfg = GithubConfig::from_source(source(&[
            (ENV_CLIENT_ID, "Iv1.abc123"),
            (ENV_API_BASE, "http://localhost:8080/api"),
            (ENV_OAUTH_BASE, "http://localhost:8080/oauth"),
        ]))
        .unwrap();
        assert_eq!(cfg.client_id().unwrap(), "Iv1.abc123");
        assert_eq!(cfg.api_base().as_str(), "http://localhost:8080/api");
        assert_eq!(cfg.oauth_base().as_str(), "http://localhost:8080/oauth");
        // git base was not overridden -> default.
        assert_eq!(cfg.git_base().as_str(), "https://github.com/");
    }

    #[test]
    fn missing_client_id_is_not_configured_error() {
        let cfg = GithubConfig::from_source(source(&[])).unwrap();
        assert!(matches!(cfg.client_id(), Err(Error::NotConfigured)));
    }

    #[test]
    fn blank_client_id_is_treated_as_unset() {
        let cfg = GithubConfig::from_source(source(&[(ENV_CLIENT_ID, "   ")])).unwrap();
        assert!(matches!(cfg.client_id(), Err(Error::NotConfigured)));
    }

    #[test]
    fn invalid_override_url_is_rejected() {
        let err = GithubConfig::from_source(source(&[(ENV_API_BASE, "not a url")])).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig { .. }));
    }
}

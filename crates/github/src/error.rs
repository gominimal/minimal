//! Actionable, non-secret error taxonomy shared across the GitHub session flow
//! (spec R8.1).
//!
//! Every variant is safe to surface to a user and to write to a log or a
//! diagnostic bundle: no token material, no opaque strings. Messages name the
//! concrete thing that is wrong and, where possible, the way to fix it.

/// Errors produced by the GitHub domain layer.
///
/// `#[non_exhaustive]` because the client feature and later units add variants
/// (rate-limit, network, token-refresh); downstream matches must keep a
/// wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The GitHub App is not installed on the target repository or org. Carries
    /// the installation URL to guide the user (spec R1.5, R2.6).
    #[error("GitHub App is not installed on the target; install it at {install_url}")]
    AppNotInstalled {
        /// The `github.com` App-installation URL to open.
        install_url: String,
    },

    /// The stored authentication is no longer usable (refresh token expired or
    /// revoked) and the user must sign in again (spec R1.2).
    #[error("GitHub authentication has expired; run `min github login` to re-authenticate")]
    NeedsReauth,

    /// No GitHub App client id is configured. At launch no real GitHub App
    /// exists yet, so this is the expected state until one is provisioned and
    /// `MINIMALD_GITHUB_CLIENT_ID` is set (spec R1.1).
    #[error(
        "GitHub support is not configured: set MINIMALD_GITHUB_CLIENT_ID to the GitHub App's \
         client id (no GitHub App is provisioned yet)"
    )]
    NotConfigured,

    /// A required permission was not granted by the resolved token (spec R5.4,
    /// R8.1). Names the scope in `contents:write` form.
    #[error("required GitHub permission `{scope}` was not granted")]
    MissingScope {
        /// The missing permission, rendered as `scope:permission`.
        scope: String,
    },

    /// The base branch a working branch should be created from does not exist on
    /// the remote (spec R2.6, R8.1).
    #[error("base branch `{branch}` not found on the remote")]
    BaseBranchNotFound {
        /// The base branch name that could not be resolved.
        branch: String,
    },

    /// A `owner/repo[@branch[:base]]` spec could not be parsed. Repo specs are
    /// not secret, so the offending input is echoed to make the error actionable.
    #[error("invalid repo spec `{input}`: {reason}")]
    InvalidRepoSpec {
        /// The verbatim input that failed to parse.
        input: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A grant id was empty or otherwise malformed (spec R6.4). Grant ids are
    /// not secret, so the offending reason is safe to surface.
    #[error("invalid grant id: {reason}")]
    InvalidGrantId {
        /// Why the grant id was rejected.
        reason: String,
    },

    /// A permission set string could not be parsed. This is also how a request
    /// for the excluded `workflows` permission surfaces (spec NG6): it is not a
    /// known scope, so it is rejected here rather than silently accepted.
    #[error("invalid GitHub scope `{input}`: {reason}")]
    InvalidScope {
        /// The verbatim scope token that failed to parse.
        input: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A configuration override (an `MINIMALD_GITHUB_*_URL` env var) was not a
    /// valid URL. The variable name is named so the fix is obvious.
    #[error("invalid value for {var}: {reason}")]
    InvalidConfig {
        /// The environment variable whose value was rejected.
        var: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A required session-`attrs` key was absent while decoding (spec R7.1).
    #[error("missing required session attribute `{key}`")]
    MissingAttr {
        /// The `attrs` key that was expected but not present.
        key: String,
    },
}

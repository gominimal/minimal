//! A registered lane: the bound upstream, the header to inject, and the secret
//! the broker holds on the box's behalf.
//!
//! Nothing here is derived from anything the box said. The upstream comes from
//! the user's binding, the header from the declaration the user approved, and
//! the secret from a host-side resolver — the box supplies only a selector.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use url::Url;

/// A credential value. Redacted in `Debug`, and deliberately without `Display`,
/// so the only way to a plaintext is [`Secret::expose`] — a grep-able set of
/// call sites.
///
/// Serialization is the one intended escape: the client sends resolved values
/// to the broker over the control UDS.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Wraps a resolved credential value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The plaintext. Callers must not log, store, or return it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// How a lane's credential enters the outbound request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inject {
    header: String,
    prefix: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    also: BTreeMap<String, String>,
}

impl Inject {
    /// Builds an injection rule from an approved declaration. The header token
    /// and the prefix are validated where the declaration is parsed.
    pub fn new(header: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            prefix: prefix.into(),
            also: BTreeMap::new(),
        }
    }

    /// Adds the declaration's static extra headers.
    #[must_use]
    pub fn with_also(
        mut self,
        also: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.also = also
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect();
        self
    }

    /// The header name to strip from the inbound request and then set.
    #[must_use]
    pub fn header(&self) -> &str {
        &self.header
    }

    /// The static headers the broker attaches alongside the credential.
    ///
    /// They are attached host-side because a box can omit a header it was told
    /// to send but cannot remove one the broker adds: the facade this design
    /// replaced pinned `X-MCP-Readonly: true` on every request, and moving that
    /// into the box would have made it advisory.
    #[must_use]
    pub fn also(&self) -> &BTreeMap<String, String> {
        &self.also
    }

    /// The value to set it to, for this lane's secret.
    #[must_use]
    pub fn header_value(&self, secret: &Secret) -> String {
        format!("{}{}", self.prefix, secret.expose())
    }
}

/// One registered lane, as the broker holds it.
#[derive(Debug, Clone)]
pub struct Lane {
    name: String,
    upstream: Url,
    inject: Inject,
    secret: Secret,
    methods: Vec<String>,
}

impl Lane {
    /// Registers a lane bound to `upstream`.
    ///
    /// The scheme is not checked here: production upstreams are constrained to
    /// `https://` where the binding is parsed, and the behavioural tests of the
    /// request path need a plaintext backend.
    pub fn new(name: impl Into<String>, upstream: Url, inject: Inject, secret: Secret) -> Self {
        Self {
            name: name.into(),
            upstream,
            inject,
            secret,
            methods: Vec::new(),
        }
    }

    /// Narrows the lane to `methods`. An empty set is every method, which is
    /// what a binding without the field means.
    #[must_use]
    pub fn with_methods(mut self, methods: impl IntoIterator<Item = String>) -> Self {
        self.methods = methods.into_iter().collect();
        self
    }

    /// Whether this lane covers `method`.
    ///
    /// Compared exactly, as HTTP methods are case-sensitive and a binding's
    /// entries are uppercase by parse-time constraint.
    #[must_use]
    pub fn allows_method(&self, method: &str) -> bool {
        self.methods.is_empty() || self.methods.iter().any(|allowed| allowed == method)
    }

    /// The lane name — the selector a box's URL leads with.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The bound upstream every request on this lane is forwarded to.
    #[must_use]
    pub fn upstream(&self) -> &Url {
        &self.upstream
    }

    /// The injection rule for this lane.
    #[must_use]
    pub fn inject(&self) -> &Inject {
        &self.inject
    }

    /// The credential the broker injects on this lane's behalf.
    #[must_use]
    pub fn secret(&self) -> &Secret {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lane() -> Lane {
        Lane::new(
            "anthropic",
            Url::parse("https://api.anthropic.com/v1/").unwrap(),
            Inject::new("Authorization", "Bearer "),
            Secret::new("sk-live-hunter2"),
        )
    }

    #[test]
    fn debugging_a_secret_does_not_print_it() {
        let rendered = format!("{:?}", Secret::new("sk-live-hunter2"));
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    #[test]
    fn debugging_a_lane_does_not_print_its_secret() {
        let rendered = format!("{:?}", lane());
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("anthropic"), "{rendered}");
    }

    #[test]
    fn the_injected_value_carries_the_prefix_and_the_secret() {
        let lane = lane();
        assert_eq!(lane.inject().header(), "Authorization");
        assert_eq!(
            lane.inject().header_value(lane.secret()),
            "Bearer sk-live-hunter2"
        );
    }

    #[test]
    fn an_empty_prefix_injects_the_secret_alone() {
        let inject = Inject::new("x-api-key", "");
        assert_eq!(inject.header_value(&Secret::new("abc")), "abc");
    }
}

//! The mirror's path grammar: cache origins, repository slugs and the request
//! paths that the mirror daemon and its clients both spell (spec MIR, O1 and
//! O2). One parser serves both sides, so a path parses one way only.
//!
//! A cache origin is the base URL a client reads a cache from, written without
//! its scheme and trailing slash: `host[:port][/segment...]`. Under the mount
//! `/-/c/<origin>/-/` the mirror serves that cache's own keys. A repository
//! slug is a repository URL with scheme, credentials, query, trailing slash
//! and `.git` stripped: a host, then one path segment or more. The literal
//! segment `-` ends an origin and ends a slug.

use std::fmt;

/// The mount under which cache objects of every origin live.
const CACHE_MOUNT: &str = "/-/c/";
/// The mount under which repository copies live.
const GIT_MOUNT: &str = "/-/git/";
/// The one path outside both mounts.
pub const TRUSTED_ROOT_PATH: &str = "/-/sigstore/trusted_root.json";
/// The file name of an origin's root index.
pub const ROOT_INDEX: &str = "index.shisha";
/// The bucket host every `gs://` location maps to.
pub const GCS_HOST: &str = "storage.googleapis.com";

/// Why a string is not a cache origin, a slug or a segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrammarError {
    /// The scheme is not the one the grammar admits.
    Scheme(String),
    /// The URL carries user information.
    UserInfo,
    /// The URL carries a query or a fragment.
    Query,
    /// A port is present where the grammar admits none, or is out of range.
    Port,
    /// The host is empty or holds a character outside the host rule.
    Host(String),
    /// A segment is empty, `.`, `..`, `-`, or holds a character outside the rule.
    Segment(String),
    /// A slug needs a host and at least one segment.
    TooShort,
}

impl fmt::Display for GrammarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrammarError::Scheme(s) => write!(f, "scheme {s:?} is not https"),
            GrammarError::UserInfo => write!(f, "the URL carries user information"),
            GrammarError::Query => write!(f, "the URL carries a query or a fragment"),
            GrammarError::Port => write!(f, "the port is not admitted here"),
            GrammarError::Host(h) => write!(f, "host {h:?} is not a DNS name"),
            GrammarError::Segment(s) => write!(f, "segment {s:?} is outside the segment rule"),
            GrammarError::TooShort => write!(f, "a slug needs a host and one segment or more"),
        }
    }
}

impl std::error::Error for GrammarError {}

/// The segment rule: one or more of `A`-`Z`, `a`-`z`, `0`-`9`, `.`, `_` and
/// `-`, and not `.`, `..` or the terminator `-`.
pub fn segment_ok(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment != "-"
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

fn check_segment(segment: &str) -> Result<(), GrammarError> {
    if segment_ok(segment) {
        Ok(())
    } else {
        Err(GrammarError::Segment(segment.to_string()))
    }
}

/// The host rule: lowercase letters, digits, `-` and `.`, non-empty.
fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

fn check_host(host: &str) -> Result<(), GrammarError> {
    if host_ok(host) {
        Ok(())
    } else {
        Err(GrammarError::Host(host.to_string()))
    }
}

/// Splits `host[:port]` and validates both halves; `allow_port` is false for
/// a slug, whose grammar admits no port.
fn check_authority(authority: &str, allow_port: bool) -> Result<(), GrammarError> {
    match authority.rsplit_once(':') {
        Some((host, port)) if allow_port => {
            check_host(host)?;
            match port.parse::<u16>() {
                Ok(p) if p > 0 && !port.starts_with('0') => Ok(()),
                _ => Err(GrammarError::Port),
            }
        }
        Some(_) => Err(GrammarError::Port),
        None => check_host(authority),
    }
}

/// A cache origin: the base URL a client reads a cache from, without its
/// scheme and trailing slash.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CacheOrigin(String);

impl CacheOrigin {
    /// The origin of an `https://` base URL, or why the base is outside the
    /// grammar. A base ends in `/` by the cache reader's own rule; a base
    /// without one is read as if it had it.
    pub fn from_https_base(base: &str) -> Result<Self, GrammarError> {
        let url = url::Url::parse(base).map_err(|_| GrammarError::Scheme(base.to_string()))?;
        if url.scheme() != "https" {
            return Err(GrammarError::Scheme(url.scheme().to_string()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(GrammarError::UserInfo);
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(GrammarError::Query);
        }
        let host = url
            .host_str()
            .ok_or_else(|| GrammarError::Host(String::new()))?;
        check_host(host)?;
        let mut rendered = host.to_string();
        if let Some(port) = url.port() {
            rendered.push(':');
            rendered.push_str(&port.to_string());
        }
        for segment in url.path().split('/').filter(|s| !s.is_empty()) {
            check_segment(segment)?;
            rendered.push('/');
            rendered.push_str(segment);
        }
        Ok(CacheOrigin(rendered))
    }

    /// The origin a `gs://<bucket>` location maps to.
    pub fn from_gcs_bucket(bucket: &str) -> Result<Self, GrammarError> {
        check_segment(bucket)?;
        Ok(CacheOrigin(format!("{GCS_HOST}/{bucket}")))
    }

    /// Parses the rendered form, as it appears in a request path.
    pub fn parse(origin: &str) -> Result<Self, GrammarError> {
        let mut segments = origin.split('/');
        let authority = segments.next().unwrap_or("");
        check_authority(authority, true)?;
        for segment in segments {
            check_segment(segment)?;
        }
        Ok(CacheOrigin(origin.to_string()))
    }

    /// The rendered form: `host[:port][/segment...]`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `https://` base this origin stands for, with its trailing slash.
    pub fn https_base(&self) -> String {
        format!("https://{}/", self.0)
    }

    /// The mount under which the mirror serves this origin's keys, with its
    /// trailing slash, so a key joins under it as under the base itself.
    pub fn mount(&self) -> String {
        format!("{CACHE_MOUNT}{}/-/", self.0)
    }
}

impl fmt::Display for CacheOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A repository slug: a host, then one path segment or more.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepoSlug(String);

impl RepoSlug {
    /// The slug of a repository URL the mirror copies: `https`, no user
    /// information, no port. Any other URL is outside the copy (MIR-013).
    pub fn from_repo_url(repo_url: &str) -> Result<Self, GrammarError> {
        let url =
            url::Url::parse(repo_url).map_err(|_| GrammarError::Scheme(repo_url.to_string()))?;
        if url.scheme() != "https" {
            return Err(GrammarError::Scheme(url.scheme().to_string()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(GrammarError::UserInfo);
        }
        if url.port().is_some() {
            return Err(GrammarError::Port);
        }
        let host = url
            .host_str()
            .ok_or_else(|| GrammarError::Host(String::new()))?;
        check_host(host)?;
        let path = url.path().trim_end_matches('/');
        let path = path.strip_suffix(".git").unwrap_or(path);
        let mut rendered = host.to_string();
        let mut segments = 0;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            check_segment(segment)?;
            rendered.push('/');
            rendered.push_str(segment);
            segments += 1;
        }
        if segments == 0 {
            return Err(GrammarError::TooShort);
        }
        Ok(RepoSlug(rendered))
    }

    /// Parses the rendered form, as it appears in a request path or a key.
    pub fn parse(slug: &str) -> Result<Self, GrammarError> {
        let mut segments = slug.split('/');
        let host = segments.next().unwrap_or("");
        check_authority(host, false)?;
        let mut count = 0;
        for segment in segments {
            check_segment(segment)?;
            count += 1;
        }
        if count == 0 {
            return Err(GrammarError::TooShort);
        }
        Ok(RepoSlug(slug.to_string()))
    }

    /// The rendered form: `host/segment[/segment...]`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `https://` URL this slug stands for, without `.git`.
    pub fn https_url(&self) -> String {
        format!("https://{}", self.0)
    }
}

impl fmt::Display for RepoSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// One key of a cache origin: what the cache reader fetches under a base.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CacheKey {
    /// `index.shisha`, the one mutable key.
    RootIndex,
    /// `<slug>/<commit>.closure.shisha`.
    Closure { slug: RepoSlug, commit: String },
    /// `<slug>/<commit>.shisha`.
    Snapshot { slug: RepoSlug, commit: String },
    /// `<slug>/<commit>.closure.shisha.sigstore.json`.
    ClosureSignature { slug: RepoSlug, commit: String },
    /// `<slug>/<commit>.map.json`.
    CommitMap { slug: RepoSlug, commit: String },
    /// `<sha256>.zst`.
    Artifact { sha256: String },
}

impl CacheKey {
    /// Parses a key as the cache reader spells it under a base.
    pub fn parse(key: &str) -> Option<Self> {
        if key == ROOT_INDEX {
            return Some(CacheKey::RootIndex);
        }
        if let Some(stem) = key.strip_suffix(".zst") {
            return is_hex(stem, 64).then(|| CacheKey::Artifact {
                sha256: stem.to_string(),
            });
        }
        let (slug, file) = key.rsplit_once('/')?;
        let slug = RepoSlug::parse(slug).ok()?;
        let (commit, kind) = file.split_once('.')?;
        if !is_hex(commit, 40) {
            return None;
        }
        let commit = commit.to_string();
        Some(match kind {
            "closure.shisha" => CacheKey::Closure { slug, commit },
            "shisha" => CacheKey::Snapshot { slug, commit },
            "closure.shisha.sigstore.json" => CacheKey::ClosureSignature { slug, commit },
            "map.json" => CacheKey::CommitMap { slug, commit },
            _ => return None,
        })
    }

    /// Whether the origin may change this key's bytes. Only the root index.
    pub fn is_mutable(&self) -> bool {
        matches!(self, CacheKey::RootIndex)
    }

    /// The keys the mirror fetches beside this one (MIR-005): a closure's
    /// signature bundle and commit map. Empty for every other key.
    pub fn companions(&self) -> Vec<CacheKey> {
        match self {
            CacheKey::Closure { slug, commit } => vec![
                CacheKey::ClosureSignature {
                    slug: slug.clone(),
                    commit: commit.clone(),
                },
                CacheKey::CommitMap {
                    slug: slug.clone(),
                    commit: commit.clone(),
                },
            ],
            _ => Vec::new(),
        }
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheKey::RootIndex => f.write_str(ROOT_INDEX),
            CacheKey::Closure { slug, commit } => write!(f, "{slug}/{commit}.closure.shisha"),
            CacheKey::Snapshot { slug, commit } => write!(f, "{slug}/{commit}.shisha"),
            CacheKey::ClosureSignature { slug, commit } => {
                write!(f, "{slug}/{commit}.closure.shisha.sigstore.json")
            }
            CacheKey::CommitMap { slug, commit } => write!(f, "{slug}/{commit}.map.json"),
            CacheKey::Artifact { sha256 } => write!(f, "{sha256}.zst"),
        }
    }
}

/// One request path the mirror answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MirrorPath {
    /// `/-/c/<origin>/-/<key>`.
    CacheObject { origin: CacheOrigin, key: CacheKey },
    /// `/-/git/<slug>/-/bundle`: a bundle of the repository copy.
    GitBundle { slug: RepoSlug },
    /// `/-/git/<slug>/-/path`: the copy's path in the store, answered on the
    /// host socket alone.
    GitPath { slug: RepoSlug },
    /// `/-/sigstore/trusted_root.json`.
    TrustedRoot,
}

impl MirrorPath {
    /// Parses a request path. A path with a query string, an empty segment
    /// or anything outside the grammar is `None`.
    pub fn parse(path: &str) -> Option<Self> {
        if path.contains('?') || path.contains('#') {
            return None;
        }
        if path == TRUSTED_ROOT_PATH {
            return Some(MirrorPath::TrustedRoot);
        }
        if let Some(rest) = path.strip_prefix(CACHE_MOUNT) {
            let (origin, key) = rest.split_once("/-/")?;
            let origin = CacheOrigin::parse(origin).ok()?;
            let key = CacheKey::parse(key)?;
            return Some(MirrorPath::CacheObject { origin, key });
        }
        if let Some(rest) = path.strip_prefix(GIT_MOUNT) {
            let (slug, verb) = rest.split_once("/-/")?;
            let slug = RepoSlug::parse(slug).ok()?;
            return match verb {
                "bundle" => Some(MirrorPath::GitBundle { slug }),
                "path" => Some(MirrorPath::GitPath { slug }),
                _ => None,
            };
        }
        None
    }

    /// The request path, the inverse of [`MirrorPath::parse`].
    pub fn render(&self) -> String {
        match self {
            MirrorPath::CacheObject { origin, key } => format!("{}{key}", origin.mount()),
            MirrorPath::GitBundle { slug } => format!("{GIT_MOUNT}{slug}/-/bundle"),
            MirrorPath::GitPath { slug } => format!("{GIT_MOUNT}{slug}/-/path"),
            MirrorPath::TrustedRoot => TRUSTED_ROOT_PATH.to_string(),
        }
    }
}

impl fmt::Display for MirrorPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "bd62e6e2bd62e6e2bd62e6e2bd62e6e2bd62e6e2";
    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn origin_from_https_base_strips_scheme_and_slash() {
        let o = CacheOrigin::from_https_base("https://cache.minimal.dev/").unwrap();
        assert_eq!(o.as_str(), "cache.minimal.dev");
        assert_eq!(o.https_base(), "https://cache.minimal.dev/");
        assert_eq!(o.mount(), "/-/c/cache.minimal.dev/-/");
        let o = CacheOrigin::from_https_base("https://cache.acme.internal:8443/pkgs/").unwrap();
        assert_eq!(o.as_str(), "cache.acme.internal:8443/pkgs");
        assert_eq!(CacheOrigin::parse(o.as_str()).unwrap(), o);
    }

    #[test]
    fn origin_refuses_what_the_grammar_excludes() {
        assert_eq!(
            CacheOrigin::from_https_base("http://cache.minimal.dev/").unwrap_err(),
            GrammarError::Scheme("http".into())
        );
        assert_eq!(
            CacheOrigin::from_https_base("https://u:p@cache.minimal.dev/").unwrap_err(),
            GrammarError::UserInfo
        );
        assert_eq!(
            CacheOrigin::from_https_base("https://cache.minimal.dev/?x=1").unwrap_err(),
            GrammarError::Query
        );
        assert!(matches!(
            CacheOrigin::from_https_base("https://cache.minimal.dev/-/x/").unwrap_err(),
            GrammarError::Segment(_)
        ));
        // The URL parser lowercases a host, so a mixed-case base is the same origin.
        assert_eq!(
            CacheOrigin::from_https_base("https://Cache.Minimal.dev/")
                .unwrap()
                .as_str(),
            "cache.minimal.dev"
        );
        assert!(matches!(
            CacheOrigin::parse("Cache.Minimal.dev"),
            Err(GrammarError::Host(_))
        ));
        assert_eq!(CacheOrigin::parse("h:0").unwrap_err(), GrammarError::Port);
        assert_eq!(
            CacheOrigin::parse("h:70000").unwrap_err(),
            GrammarError::Port
        );
    }

    #[test]
    fn gcs_bucket_maps_to_the_storage_host() {
        let o = CacheOrigin::from_gcs_bucket("minimal-staging-cache").unwrap();
        assert_eq!(o.as_str(), "storage.googleapis.com/minimal-staging-cache");
    }

    #[test]
    fn slug_from_repo_url_matches_the_index_keys() {
        let s = RepoSlug::from_repo_url("https://github.com/gominimal/pkgs.git").unwrap();
        assert_eq!(s.as_str(), "github.com/gominimal/pkgs");
        assert_eq!(s.https_url(), "https://github.com/gominimal/pkgs");
        let deep = RepoSlug::from_repo_url("https://gitlab.com/group/sub/repo/").unwrap();
        assert_eq!(deep.as_str(), "gitlab.com/group/sub/repo");
        assert_eq!(RepoSlug::parse(deep.as_str()).unwrap(), deep);
    }

    #[test]
    fn slug_refuses_ssh_userinfo_ports_and_bare_hosts() {
        assert!(matches!(
            RepoSlug::from_repo_url("git@github.com:gominimal/pkgs").unwrap_err(),
            GrammarError::Scheme(_)
        ));
        assert!(matches!(
            RepoSlug::from_repo_url("ssh://git@github.com/gominimal/pkgs").unwrap_err(),
            GrammarError::Scheme(_)
        ));
        assert_eq!(
            RepoSlug::from_repo_url("https://tok@github.com/gominimal/pkgs").unwrap_err(),
            GrammarError::UserInfo
        );
        assert_eq!(
            RepoSlug::from_repo_url("https://git.example:8443/org/repo").unwrap_err(),
            GrammarError::Port
        );
        assert_eq!(
            RepoSlug::from_repo_url("https://github.com/").unwrap_err(),
            GrammarError::TooShort
        );
        assert_eq!(
            RepoSlug::parse("github.com").unwrap_err(),
            GrammarError::TooShort
        );
        assert_eq!(
            RepoSlug::parse("github.com:443/x").unwrap_err(),
            GrammarError::Port
        );
    }

    #[test]
    fn cache_keys_parse_and_render_round_trip() {
        let keys = [
            "index.shisha".to_string(),
            format!("github.com/gominimal/pkgs/{COMMIT}.closure.shisha"),
            format!("github.com/gominimal/pkgs/{COMMIT}.shisha"),
            format!("github.com/gominimal/pkgs/{COMMIT}.closure.shisha.sigstore.json"),
            format!("gitlab.com/g/s/r/{COMMIT}.map.json"),
            format!("{SHA}.zst"),
        ];
        for key in &keys {
            let parsed = CacheKey::parse(key).unwrap_or_else(|| panic!("{key}"));
            assert_eq!(parsed.to_string(), *key);
        }
        assert!(CacheKey::parse(&format!("{COMMIT}.closure.shisha")).is_none());
        assert!(CacheKey::parse("abc.zst").is_none());
        assert!(CacheKey::parse(&format!("github.com/pkgs/{COMMIT}.other")).is_none());
        assert!(CacheKey::parse(&format!("github.com/-/pkgs/{COMMIT}.shisha")).is_none());
        assert!(CacheKey::RootIndex.is_mutable());
        assert!(!CacheKey::parse(&format!("{SHA}.zst")).unwrap().is_mutable());
    }

    #[test]
    fn closure_companions_are_the_signature_and_the_map() {
        let key = CacheKey::parse(&format!(
            "github.com/gominimal/pkgs/{COMMIT}.closure.shisha"
        ))
        .unwrap();
        let companions: Vec<String> = key.companions().iter().map(|k| k.to_string()).collect();
        assert_eq!(
            companions,
            vec![
                format!("github.com/gominimal/pkgs/{COMMIT}.closure.shisha.sigstore.json"),
                format!("github.com/gominimal/pkgs/{COMMIT}.map.json"),
            ]
        );
        assert!(CacheKey::RootIndex.companions().is_empty());
    }

    #[test]
    fn mirror_paths_parse_one_way_only() {
        let paths = [
            "/-/c/cache.minimal.dev/-/index.shisha".to_string(),
            format!(
                "/-/c/cache.acme.internal:8443/pkgs/-/github.com/gominimal/pkgs/{COMMIT}.closure.shisha"
            ),
            format!("/-/c/storage.googleapis.com/bucket/-/{SHA}.zst"),
            "/-/git/github.com/gominimal/pkgs/-/bundle".to_string(),
            "/-/git/gitlab.com/g/s/r/-/path".to_string(),
            TRUSTED_ROOT_PATH.to_string(),
        ];
        for path in &paths {
            let parsed = MirrorPath::parse(path).unwrap_or_else(|| panic!("{path}"));
            assert_eq!(parsed.render(), *path);
        }
        for bad in [
            "/index.shisha",
            "/-/c/cache.minimal.dev/index.shisha",
            "/-/c/cache.minimal.dev/-/index.shisha?x=1",
            "/-/c/cache.minimal.dev/-/../index.shisha",
            "/-/c//-/index.shisha",
            "/-/git/github.com/-/bundle",
            "/-/git/github.com/gominimal/pkgs/-/config",
            "/-/git/github.com/gominimal/pkgs/-/objects/info/alternates",
            "/-/sigstore/other.json",
            "/-/c/cache.minimal.dev/-/",
        ] {
            assert!(MirrorPath::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_key_joined_under_the_mount_is_the_object_path() {
        let origin = CacheOrigin::from_https_base("https://cache.minimal.dev/").unwrap();
        let key = CacheKey::parse(&format!("{SHA}.zst")).unwrap();
        let joined = format!("{}{key}", origin.mount());
        assert_eq!(
            MirrorPath::parse(&joined),
            Some(MirrorPath::CacheObject { origin, key })
        );
    }
}

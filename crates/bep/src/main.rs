//! `bep`: the Box Egress Proxy daemon.
//!
//! It serves the host's box attachments, terminates TLS for the declared
//! credentialed hosts, redeems sealed values, forwards on an upstream leg
//! validated against the host's trust store, and records every decision in
//! the audit log.
//!
//! Three surfaces beyond the redemption listener make the proxy usable by the
//! `min` client on the same host:
//!
//! - the **control socket** (`--control-socket`), which the client submits
//!   mints, client-key registrations and revocations over (BEP-063, BEP-067);
//! - the **published anchor** (`--anchor-pem`), which a box's trust store is
//!   seeded from at creation (BEP-011);
//! - the operator's **store rules** (`--store-rules`), which a store handle is
//!   checked against on every request (BEP-032, BEP-064).
//!
//! Without them the proxy still runs, and still refuses correctly: no control
//! socket means the client's mint is not recorded, no published root means a
//! box declaring a credentialed upstream cannot be created, and no rules mean
//! every store handle is refused. Each is a flag rather than a default so a
//! hand-started proxy stays the simple thing it was.

use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bep::control::{ClientKeys, Submission};
use bep::keychain::SecretItems;
use bep::listener::{Config, Module, Proxy, RegisteredRule, Sender};
use bep::mint::Inject;
use bep::upstream::{self, Trust};
use bep::{Authority, DeclaredUnion, KeyRole, KeyStore, Keys, Log};
use clap::{Parser, ValueEnum};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, UnixListener};
use tracing_subscriber::EnvFilter;

/// The v1 GitHub module's host set.
const GITHUB_HOST_SET: [&str; 4] = [
    "github.com:443",
    "api.github.com:443",
    "uploads.github.com:443",
    "codeload.github.com:443",
];

#[derive(Parser)]
#[command(name = "bep")]
#[command(
    about = "The Box Egress Proxy: terminates TLS for declared hosts, redeems sealed values and forwards on a validated upstream leg"
)]
struct Cli {
    /// The address the redemption listener binds. The default mirrors
    /// `minvmd::net::DEFAULT_BEP_PORT` — the supervisor always passes
    /// `--listen` explicitly, so this only serves a hand-started proxy.
    #[arg(long, default_value = "127.0.0.1:7656")]
    listen: SocketAddr,

    /// The audit log, appended to and never rewritten. Required to serve;
    /// a `--replace-key` run writes no record, because it serves nothing.
    #[arg(long, required_unless_present = "replace_keys")]
    audit_log: Option<PathBuf>,

    /// The box attachments on this host: a JSON list of objects with
    /// `source` (the box's address), `box`, `addressing` (`own_ip` or
    /// `host_ip`) and an optional `egress` host allow-list.
    #[arg(long, required_unless_present = "replace_keys")]
    boxes: Option<PathBuf>,

    /// A `host:port` of the module's host set; repeatable. Defaults to the
    /// v1 GitHub set.
    #[arg(long = "host")]
    hosts: Vec<String>,

    /// The host set's version: the one a member minted now binds to.
    #[arg(long, default_value_t = 1)]
    host_set_version: u32,

    /// A registered store authority, `host:port`; repeatable.
    #[arg(long = "store-authority")]
    store_authorities: Vec<String>,

    /// The control socket the `min` client submits mints, client-key
    /// registrations and revocations over. Omitted, none is served.
    #[arg(long)]
    control_socket: Option<PathBuf>,

    /// Where to publish the interception anchor, PEM: what a box's trust
    /// store is seeded from at creation. The name-constrained signing
    /// certificate, not the root above it, so the anchor a box holds is
    /// bounded by the same names the proxy may issue for. Omitted, none is
    /// published.
    #[arg(long)]
    anchor_pem: Option<PathBuf>,

    /// Where to publish this host's public identity: what a client seals a
    /// member to, since the private halves are the proxy's alone (BEP-059).
    /// Omitted, none is published and no client on this host can seal.
    #[arg(long)]
    public_keys: Option<PathBuf>,

    /// The operator's `[[secret-store-rules]]` file. Omitted, the proxy holds
    /// no rule and refuses every store handle.
    #[arg(long)]
    store_rules: Option<PathBuf>,

    /// Replace these keys and exit, serving nothing: the explicit operator
    /// command BEP-060 requires before a key changes, and the way back from a
    /// store that no longer admits this program. Repeatable.
    ///
    /// Every member sealed to a replaced sealing key, and every leaf under a
    /// replaced root, is refused from then on; a running box holding one is
    /// re-created to re-mint (BEP-060).
    #[arg(long = "replace-key", value_name = "ROLE")]
    replace_keys: Vec<RoleArg>,
}

/// Which key `--replace-key` names, as the command line spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RoleArg {
    Sealing,
    Root,
    Signing,
}

impl From<RoleArg> for KeyRole {
    fn from(arg: RoleArg) -> Self {
        match arg {
            RoleArg::Sealing => Self::Sealing,
            RoleArg::Root => Self::Root,
            RoleArg::Signing => Self::Signing,
        }
    }
}

/// One box attachment: the address the box's connections arrive from, and
/// what the listener knows of the box.
#[derive(Deserialize)]
struct Attachment {
    source: IpAddr,
    #[serde(flatten)]
    sender: Sender,
}

/// The operator's rules file, as `[[secret-store-rules]]` spells them. Read
/// here in the proxy's own terms rather than through `sessions`, which does
/// not depend on this crate and must not come to.
#[derive(Deserialize, Default)]
struct RulesFile {
    #[serde(default, rename = "secret-store-rules")]
    secret_store_rules: Vec<OperatorRule>,
}

/// One `[[secret-store-rules]]` rule.
#[derive(Deserialize)]
struct OperatorRule {
    store: String,
    id: String,
    upstream: Vec<String>,
    inject: InjectSpec,
    /// `allow`, `ask` or `deny`; `allow` when omitted. Only `allow` rules are
    /// held: `ask` has no consent surface in the proxy and `deny` is the same
    /// as holding no rule at all, so both are dropped with a line saying so
    /// rather than silently treated as `allow`.
    #[serde(default = "allow")]
    action: String,
}

fn allow() -> String {
    "allow".to_owned()
}

/// The `inject = { … }` table, in the rule's own field names.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InjectSpec {
    #[serde(default)]
    header: Option<String>,
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    basic_auth: Option<String>,
}

/// The rules the proxy holds, read from `path` and filtered to `allow`.
///
/// A rule whose injection form is neither a header nor a basic-auth field is
/// dropped: the handle check is an equality of the two forms, so a form no
/// rule can spell equals no rule and would refuse anyway — better to say so at
/// startup than per request.
fn read_rules(path: &Path) -> Result<Vec<RegisteredRule>, Box<dyn Error>> {
    let text = std::fs::read_to_string(path)?;
    let file: RulesFile = toml::from_str(&text)?;
    let mut held = Vec::new();
    for rule in file.secret_store_rules {
        if rule.action != "allow" {
            tracing::warn!(
                store = %rule.store,
                id = %rule.id,
                action = %rule.action,
                "the rule is not an allow rule; the proxy holds no rule for it"
            );
            continue;
        }
        if rule.inject.header.is_none() && rule.inject.basic_auth.is_none() {
            tracing::warn!(
                store = %rule.store,
                id = %rule.id,
                "the rule declares no injection form; the proxy holds no rule for it"
            );
            continue;
        }
        tracing::info!(store = %rule.store, id = %rule.id, "holding a store rule");
        held.push(RegisteredRule {
            store: rule.store,
            id: rule.id,
            upstream: rule.upstream,
            inject: Inject {
                header: rule.inject.header,
                prefix: rule.inject.prefix,
                basic_auth: rule.inject.basic_auth,
            },
        });
    }
    Ok(held)
}

/// The store authorities the proxy intercepts for: those named with
/// `--store-authority` and every upstream an `allow` rule registers, each as
/// `host:port`, port 443 when a rule writes none. The rules' upstreams belong
/// here because the anchor's name constraints are drawn from this set, and a
/// rule whose upstream fell outside them would have its leaf refused by every
/// box.
fn store_authorities(named: &[String], rules: &[RegisteredRule]) -> Vec<String> {
    let mut authorities: Vec<String> = named
        .iter()
        .chain(rules.iter().flat_map(|rule| &rule.upstream))
        .map(|authority| {
            if authority.contains(':') {
                authority.clone()
            } else {
                format!("{authority}:443")
            }
        })
        .collect();
    authorities.sort();
    authorities.dedup();
    authorities
}

/// Publishes `der` at `path` as PEM: what a box's trust store is seeded from
/// (BEP-011). Written whole and renamed over, so a box never reads half a
/// certificate.
///
/// `der` is the signing certificate, which carries the permitted-name
/// constraints; the root above it carries none. Anchoring a box on the root
/// would leave those constraints binding only because the proxy happens to
/// present the intermediate in every chain — a certificate the root signed
/// directly would validate in that box unconstrained.
fn publish_anchor(path: &Path, der: &[u8]) -> std::io::Result<()> {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let staged = path.with_extension("pem.new");
    std::fs::write(&staged, pem)?;
    std::fs::rename(&staged, path)
}

/// Publishes `identity` at `path`: the public halves a client on this host
/// seals with, which it cannot read from the store the private halves live in
/// (BEP-059). Staged and renamed over, as the root is, so a client never reads
/// half an identity.
fn publish_identity(path: &Path, identity: &bep::PublicIdentity) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let staged = path.with_extension("json.new");
    std::fs::write(&staged, identity.encode())?;
    std::fs::rename(&staged, path)
}

/// The accept loop behind the control socket: one JSON-line submission per
/// connection, the proxy's answer back on the same line. A registration goes
/// to the keys the proxy verifies handles under; every other submission goes
/// to the proxy's own intake, which appends it to the log it alone writes and
/// puts a revocation it carries in force.
fn serve_control<S>(proxy: Arc<Proxy<S>>, listener: UnixListener)
where
    S: KeyStore + Send + Sync + 'static,
    S::Key: Send + Sync + 'static,
{
    let keys = Arc::new(Mutex::new(ClientKeys::new()));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                tracing::warn!("the control socket stopped accepting");
                return;
            };
            let proxy = Arc::clone(&proxy);
            let keys = Arc::clone(&keys);
            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut line = String::new();
                if BufReader::new(reader).read_line(&mut line).await.is_err() {
                    return;
                }
                let reply = match serde_json_lenient::from_str::<Submission>(&line) {
                    Ok(Submission::RegisterKey(key)) => keys
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .register(&key)
                        .map_err(|e| e.to_string())
                        .and_then(|registered| {
                            serde_json_lenient::to_string(&registered).map_err(|e| e.to_string())
                        }),
                    Ok(submission) => proxy
                        .submit(&submission)
                        .map_err(|e| e.to_string())
                        .and_then(|record| {
                            serde_json_lenient::to_string(&record).map_err(|e| e.to_string())
                        }),
                    Err(error) => Err(error.to_string()),
                };
                let reply = reply.unwrap_or_else(|error| {
                    tracing::warn!(%error, "refused a control submission");
                    serde_json_lenient::to_string(&serde_json_lenient::json!({"error": error}))
                        .unwrap_or_else(|_| r#"{"error":"refused"}"#.to_owned())
                });
                let _ = writer.write_all(format!("{reply}\n").as_bytes()).await;
            });
        }
    });
}

/// Runs the proxy, and on failure prints the error as its message rather than
/// the `Debug` form a `main` returning `Result` would: the message is what
/// names the way back, and the supervisor's log is where an operator reads it.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match start().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bep: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn start() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();

    // The key store is the one the client seals to: a member sealed under the
    // host keychain's key can only be unsealed by a proxy holding that same
    // key, so anything else here refuses every value this host mints.
    #[cfg(target_os = "macos")]
    {
        run(
            bep::keychain::MacosKeychain,
            Arc::new(bep::keychain::KeychainSecrets) as Arc<dyn SecretItems + Send + Sync>,
            cli,
        )
        .await
    }
    #[cfg(not(target_os = "macos"))]
    {
        tracing::warn!(
            "this host has no keychain backend: the proxy holds process-local keys and an \
             in-memory store, so it unseals nothing the client minted"
        );
        run(
            bep::MemoryStore::new(),
            Arc::new(bep::keychain::MemorySecrets::new()) as Arc<dyn SecretItems + Send + Sync>,
            cli,
        )
        .await
    }
}

/// Replaces the named keys and reports the set that results: `store` drops
/// each one, and opening the set generates a new one in its place (BEP-060).
///
/// Dropping first, rather than replacing through an already-open set, is what
/// makes this the way back from a key this program cannot use. Opening the set
/// is precisely what fails then — deriving each key's public half is the first
/// thing it does — so a remedy that needed an open set could never run when it
/// is needed.
///
/// Every member sealed to a replaced sealing key, and every leaf under a
/// replaced root, is refused from here on. Nothing warns twice: the caller
/// asked for this by name.
fn replace_keys<S>(store: S, roles: &[RoleArg]) -> Result<(), Box<dyn Error>>
where
    S: KeyStore,
{
    for role in roles.iter().copied().map(KeyRole::from) {
        match store.delete(role.store_name()) {
            Ok(()) => tracing::info!(role = %role, "dropped the key held for replacement"),
            // A store holding no such key is where a replacement leaves it
            // anyway, so this is the asked-for state, not a failure.
            Err(bep::StoreError::Missing { .. }) => {
                tracing::info!(role = %role, "the store held no key to replace");
            }
            Err(error) => return Err(error.into()),
        }
    }
    let keys = Keys::open(store).map_err(|error| -> Box<dyn Error> {
        // Opening the set touches every key, not just the replaced ones. A
        // program locked out of one of its keys is usually locked out of all
        // of them, so say which one is left rather than report a role the
        // operator did not name and leave them to guess why.
        if let bep::KeysError::Store {
            role,
            source: bep::StoreError::Unusable,
        } = &error
            && !roles.iter().copied().map(KeyRole::from).any(|r| r == *role)
        {
            return format!(
                "the {role} key is one this program cannot use either, and opening the set \
                 touches every key: name it too, with --replace-key {role}"
            )
            .into();
        }
        error.into()
    })?;
    for role in KeyRole::ALL {
        println!("{role} {}", keys.fingerprint(role));
    }
    Ok(())
}

/// The proxy over `store`'s keys, reading referenced values from `secrets`.
async fn run<S>(
    store: S,
    secrets: Arc<dyn SecretItems + Send + Sync>,
    cli: Cli,
) -> Result<(), Box<dyn Error>>
where
    S: KeyStore + Send + Sync + 'static,
    S::Key: Send + Sync + 'static,
{
    // Before anything the proxy needs to serve: a replacement is what an
    // operator runs when the proxy cannot start, so it must not depend on the
    // files, listeners or rules a running proxy does.
    if !cli.replace_keys.is_empty() {
        return replace_keys(store, &cli.replace_keys);
    }

    // Past the replacement branch above, clap has proved both are present.
    let boxes = cli.boxes.as_ref().expect("--boxes is required to serve");
    let attachments: Vec<Attachment> =
        serde_json_lenient::from_str(&std::fs::read_to_string(boxes)?)?;
    let hosts = if cli.hosts.is_empty() {
        GITHUB_HOST_SET.map(str::to_owned).to_vec()
    } else {
        cli.hosts.clone()
    };

    let rules = match &cli.store_rules {
        Some(path) => read_rules(path)?,
        None => Vec::new(),
    };
    if rules.is_empty() {
        tracing::warn!("the proxy holds no store rule; every store handle is refused");
    }
    let store_authorities = store_authorities(&cli.store_authorities, &rules);

    // The keys live as long as the process: the interception authority
    // borrows them for as long as the listener runs.
    let keys: &'static Keys<S> = Box::leak(Box::new(Keys::open(store)?));
    let union = DeclaredUnion::of([hosts.iter().chain(&store_authorities).map(|authority| {
        authority
            .rsplit_once(':')
            .map_or(authority.as_str(), |(host, _)| host)
    })]);
    let authority = Authority::open(keys, union)?;

    // Published before anything is served: a box created while the root is
    // absent has no anchor for the leaves this proxy will present it.
    if let Some(path) = &cli.anchor_pem {
        publish_anchor(path, authority.signing_der())?;
        tracing::info!(path = %path.display(), "published the interception anchor");
    }
    if let Some(path) = &cli.public_keys {
        publish_identity(path, &keys.public_identity())?;
        tracing::info!(path = %path.display(), "published this host's public identity");
    }

    let log = Log::open(
        cli.audit_log
            .as_ref()
            .expect("--audit-log is required to serve"),
    )?;
    let config = Config {
        modules: vec![Module {
            id: "github".to_owned(),
            host_set: hosts,
            version: cli.host_set_version,
        }],
        store_authorities,
        // Read per request rather than cached, so a rule edited since a handle
        // was minted bites the next request that carries it (BEP-064).
        store_rules: Arc::new(move |store: &str, id: &str| {
            rules
                .iter()
                .find(|rule| rule.store == store && rule.id == id)
                .cloned()
        }),
        secrets,
        attachments: Arc::new(move |source: SocketAddr| {
            attachments
                .iter()
                .find(|attachment| attachment.source == source.ip())
                .map(|attachment| attachment.sender.clone())
        }),
        trust: Trust::native()?,
        resolver: upstream::host_resolver(),
    };
    let proxy = Arc::new(Proxy::new(keys, authority, log, config)?);

    if let Some(path) = &cli.control_socket {
        // A socket left behind by a proxy that did not shut down cleanly would
        // make every bind fail; the directory is the operator's own state dir,
        // so the stale file is ours to clear.
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let listener = bep::control::bind(path)?;
        tracing::info!(path = %path.display(), "the control socket is listening");
        serve_control(Arc::clone(&proxy), listener);
    } else {
        tracing::warn!("no control socket: the client's mints and revocations are not recorded");
    }

    let listener = TcpListener::bind(cli.listen).await?;
    tracing::info!(listen = %cli.listen, "the box egress proxy is listening");
    proxy.serve(listener).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use bep::MemoryStore;

    use super::*;

    /// A replacement changes the keys it names and leaves the rest of the set
    /// alone: an operator replacing a compromised sealing key does not also
    /// invalidate every leaf the root has issued (BEP-060).
    #[test]
    fn replacing_one_key_leaves_the_others_where_they_were() {
        let store = MemoryStore::new();
        let before = Keys::open(store.clone()).unwrap();
        let (sealing, root, signing) = (
            before.fingerprint(KeyRole::Sealing),
            before.fingerprint(KeyRole::Root),
            before.fingerprint(KeyRole::Signing),
        );
        drop(before);

        replace_keys(store.clone(), &[RoleArg::Sealing]).unwrap();

        let after = Keys::open(store).unwrap();
        assert_ne!(after.fingerprint(KeyRole::Sealing), sealing);
        assert_eq!(after.fingerprint(KeyRole::Root), root);
        assert_eq!(after.fingerprint(KeyRole::Signing), signing);
    }

    /// Replacing a key the store does not hold is the asked-for state, not a
    /// failure: it is where a replacement leaves the store anyway, and a
    /// store holding nothing is exactly what a first run finds.
    #[test]
    fn replacing_a_key_the_store_never_held_generates_it() {
        let store = MemoryStore::new();
        replace_keys(store.clone(), &[RoleArg::Root]).unwrap();
        assert!(Keys::open(store).is_ok());
    }

    /// A rule's upstreams join the authorities the proxy intercepts for, so
    /// the anchor it publishes admits the leaves it presents for them. A bare
    /// host is port 443, and an authority both named and registered is held
    /// once.
    #[test]
    fn a_rules_upstreams_are_store_authorities() {
        let rule = |upstream: &[&str]| RegisteredRule {
            store: "keychain".to_owned(),
            id: "demo".to_owned(),
            upstream: upstream
                .iter()
                .map(|&authority| authority.to_owned())
                .collect(),
            inject: Inject {
                header: Some("x-api-key".to_owned()),
                prefix: None,
                basic_auth: None,
            },
        };
        assert_eq!(
            store_authorities(
                &["api.anthropic.com:443".to_owned()],
                &[
                    rule(&["api.anthropic.com"]),
                    rule(&["mcp.example.com:8443"])
                ],
            ),
            ["api.anthropic.com:443", "mcp.example.com:8443"]
        );
    }
}

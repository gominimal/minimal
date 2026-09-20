//! `bep`: the Box Egress Proxy daemon.
//!
//! It serves the host's box attachments, terminates TLS for the declared
//! credentialed hosts, redeems sealed values, forwards on an upstream leg
//! validated against the host's trust store, and records every decision in
//! the audit log.

use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use bep::listener::{Config, Module, Proxy, Sender};
use bep::upstream::{self, Trust};
use bep::{Authority, DeclaredUnion, Keys, Log, MemoryStore};
use clap::Parser;
use serde::Deserialize;
use tokio::net::TcpListener;
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
    /// The address the redemption listener binds.
    #[arg(long, default_value = "127.0.0.1:7655")]
    listen: SocketAddr,

    /// The audit log, appended to and never rewritten.
    #[arg(long)]
    audit_log: PathBuf,

    /// The box attachments on this host: a JSON list of objects with
    /// `source` (the box's address), `box`, `addressing` (`own_ip` or
    /// `host_ip`) and an optional `egress` host allow-list.
    #[arg(long)]
    boxes: PathBuf,

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
}

/// One box attachment: the address the box's connections arrive from, and
/// what the listener knows of the box.
#[derive(Deserialize)]
struct Attachment {
    source: IpAddr,
    #[serde(flatten)]
    sender: Sender,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();

    let attachments: Vec<Attachment> =
        serde_json_lenient::from_str(&std::fs::read_to_string(&cli.boxes)?)?;
    let hosts = if cli.hosts.is_empty() {
        GITHUB_HOST_SET.map(str::to_owned).to_vec()
    } else {
        cli.hosts.clone()
    };

    // The keys live as long as the process: the interception authority
    // borrows them for as long as the listener runs.
    let keys: &'static Keys<MemoryStore> = Box::leak(Box::new(Keys::open(MemoryStore::new())?));
    let union = DeclaredUnion::of(
        [hosts.iter().chain(&cli.store_authorities).map(|authority| {
            authority
                .rsplit_once(':')
                .map_or(authority.as_str(), |(host, _)| host)
        })],
    );
    let authority = Authority::open(keys, union)?;
    let log = Log::open(&cli.audit_log)?;

    let config = Config {
        modules: vec![Module {
            id: "github".to_owned(),
            host_set: hosts,
            version: cli.host_set_version,
        }],
        store_authorities: cli.store_authorities.clone(),
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
    let listener = TcpListener::bind(cli.listen).await?;
    tracing::info!(listen = %cli.listen, "the box egress proxy is listening");
    proxy.serve(listener).await?;
    Ok(())
}

//! A box address: the id, the name or the `provider/host/name` that a `min
//! box` verb takes, resolved over every local host (BCLI-002). An address
//! that names no box fails with exit 4 (BCLI-064). A name that boxes on
//! more than one host hold fails with exit 2 and lists them, and a host
//! that does not answer an unqualified lookup fails with exit 7.

use super::*;

/// A box address as the caller wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BoxAddress<'a> {
    /// `provider/host/name`: the box named `name` on that one host. The
    /// last part can also be an id or the start of one.
    Qualified {
        provider: &'a str,
        host: &'a str,
        name: &'a str,
    },
    /// An id, the start of an id, or a name, looked up on every host.
    Unqualified(&'a str),
}

/// Reads `address` as `provider/host/name` when it has three non-empty
/// parts split by `/`, else as an id or a name.
pub(crate) fn parse_box_address(address: &str) -> BoxAddress<'_> {
    let mut parts = address.split('/');
    if let (Some(provider), Some(host), Some(name), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
        && !provider.is_empty()
        && !host.is_empty()
        && !name.is_empty()
    {
        return BoxAddress::Qualified {
            provider,
            host,
            name,
        };
    }
    BoxAddress::Unqualified(address)
}

/// What one local host answered when the resolver asked for its boxes.
#[derive(Debug, Clone)]
pub(crate) struct HostListing {
    /// The host that was asked.
    pub host: crate::cmd::list::LocalHost,
    /// Every box record the host keeps, or why the host did not answer.
    pub boxes: Result<Vec<minimald_rpc::BoxListingEntry>, String>,
}

/// The box an address resolved to, and the host that keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedBox {
    /// The host that keeps the box.
    pub host: crate::cmd::list::LocalHost,
    /// The box's id.
    pub box_id: boxes::SessionId,
}

/// One box that an ambiguous name matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressCandidate {
    /// The provider that serves the box's host.
    pub provider: String,
    /// The host that keeps the box.
    pub host: String,
    /// The box's name as its host keeps it.
    pub name: String,
    /// The box's state, with how a stopped or exited box ended.
    pub state: String,
    /// The box's id.
    pub box_id: boxes::SessionId,
}

/// Why a box address resolved to no single box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoxAddressRefusal {
    /// The name matches boxes on more than one host (BCLI-002). Exit 2.
    Ambiguous {
        /// The name as the caller wrote it.
        name: String,
        /// Each box the name matched.
        candidates: Vec<AddressCandidate>,
    },
    /// The start of an id matches more than one box. Exit 2.
    AmbiguousIdStart {
        /// The start as the caller wrote it.
        start: String,
    },
    /// A host did not answer while an unqualified address resolved, so no
    /// box was chosen (BCLI-002). Exit 7.
    Unreachable {
        /// The address as the caller wrote it.
        address: String,
        /// Each host that did not answer.
        hosts: Vec<String>,
    },
    /// No box on any host matches the address (BCLI-064). Exit 4.
    NotFound {
        /// The address as the caller wrote it.
        address: String,
    },
}

impl BoxAddressRefusal {
    /// The exit code the command ends with, from the architecture's
    /// reserved codes: 2 for a usage error, 4 for not found, 7 for an
    /// unreachable host.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Ambiguous { .. } | Self::AmbiguousIdStart { .. } => 2,
            Self::NotFound { .. } => 4,
            Self::Unreachable { .. } => 7,
        }
    }

    /// The outcome the command's tracing event records.
    fn outcome(&self) -> &'static str {
        match self {
            Self::Ambiguous { .. } | Self::AmbiguousIdStart { .. } => "ambiguous",
            Self::NotFound { .. } => "not found",
            Self::Unreachable { .. } => "host unreachable",
        }
    }
}

impl std::fmt::Display for BoxAddressRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ambiguous { name, candidates } => {
                writeln!(f, "{name} matches boxes on more than one host:")?;
                for c in candidates {
                    writeln!(
                        f,
                        "  {}/{}/{}  {}  {}",
                        c.provider, c.host, c.name, c.state, c.box_id
                    )?;
                }
                write!(f, "Name one as provider/host/name.")
            }
            Self::AmbiguousIdStart { start } => write!(
                f,
                "More than one box has an id that starts with `{start}`. Give more of the id."
            ),
            Self::Unreachable { address, hosts } => {
                if let [host] = hosts.as_slice() {
                    write!(
                        f,
                        "Could not reach host {host}. Box {address} can be on that host, \
                         so no box was chosen."
                    )?;
                } else {
                    write!(
                        f,
                        "Could not reach hosts {}. Box {address} can be on one of them, \
                         so no box was chosen.",
                        hosts.join(", ")
                    )?;
                }
                write!(
                    f,
                    " Run the command again when the host answers, \
                     or name the box as provider/host/name."
                )
            }
            Self::NotFound { address } => write!(
                f,
                "No box named {address}. \
                 Run `min box list --all` to see the boxes on every host."
            ),
        }
    }
}

impl std::error::Error for BoxAddressRefusal {}

/// Resolves `address` over what each local host answered.
///
/// A full id resolves to the host that lists it. A name resolves to the
/// running box that holds it. With none running, it resolves to the most
/// recent box that held it, when all of those are on one host. Else the
/// start of an id resolves to the one box whose id starts with it. An
/// unqualified address that is not a listed full id resolves nothing while
/// any host does not answer, because the box can be on that host.
pub(crate) fn resolve_box_address(
    address: &str,
    listings: &[HostListing],
) -> Result<ResolvedBox, BoxAddressRefusal> {
    let not_found = || BoxAddressRefusal::NotFound {
        address: address.to_owned(),
    };
    let unreachable = |hosts: Vec<String>| BoxAddressRefusal::Unreachable {
        address: address.to_owned(),
        hosts,
    };
    let resolved = |listing: &HostListing, box_id| ResolvedBox {
        host: listing.host.clone(),
        box_id,
    };

    if let BoxAddress::Qualified {
        provider,
        host,
        name,
    } = parse_box_address(address)
    {
        let listing = listings
            .iter()
            .find(|l| l.host.provider == provider && l.host.host == host)
            .ok_or_else(not_found)?;
        let boxes = listing
            .boxes
            .as_ref()
            .map_err(|_| unreachable(vec![listing.host.host.clone()]))?;
        return match match_on_host(boxes, name) {
            HostMatch::One(id) => Ok(resolved(listing, id)),
            HostMatch::SeveralIdStarts => Err(BoxAddressRefusal::AmbiguousIdStart {
                start: name.to_owned(),
            }),
            HostMatch::None => Err(not_found()),
        };
    }

    // A full id names one box wherever it is, so a host that answered and
    // lists it is enough.
    let full_id = boxes::SessionId::parse_str(address).ok();
    if let Some(id) = full_id
        && let Some(listing) = listings.iter().find(|l| {
            l.boxes
                .as_ref()
                .is_ok_and(|boxes| boxes.iter().any(|e| e.box_id == id))
        })
    {
        return Ok(resolved(listing, id));
    }
    let silent: Vec<String> = listings
        .iter()
        .filter(|l| l.boxes.is_err())
        .map(|l| l.host.host.clone())
        .collect();
    if !silent.is_empty() {
        return Err(unreachable(silent));
    }
    if full_id.is_some() {
        return Err(not_found());
    }
    let answered = || {
        listings
            .iter()
            .filter_map(|l| l.boxes.as_ref().ok().map(|boxes| (l, boxes)))
    };

    // Each host's boxes that hold the name, running first.
    let named: Vec<(&HostListing, Vec<&minimald_rpc::BoxListingEntry>)> = answered()
        .map(|(l, boxes)| {
            let matches: Vec<_> = boxes.iter().filter(|e| holds_name(e, address)).collect();
            (l, matches)
        })
        .filter(|(_, matches)| !matches.is_empty())
        .collect();
    let running: Vec<_> = named
        .iter()
        .filter(|(_, matches)| matches.iter().any(|e| e.state == "running"))
        .collect();
    let candidates = |hosts: &[&(&HostListing, Vec<&minimald_rpc::BoxListingEntry>)],
                      only_running: bool| {
        hosts
            .iter()
            .flat_map(|(l, matches)| {
                matches
                    .iter()
                    .filter(move |e| !only_running || e.state == "running")
                    .map(|e| AddressCandidate {
                        provider: l.host.provider.to_owned(),
                        host: l.host.host.clone(),
                        name: e.name.clone().unwrap_or_default(),
                        state: box_state_label(e),
                        box_id: e.box_id,
                    })
            })
            .collect::<Vec<_>>()
    };
    let chosen = match running.as_slice() {
        [one] => Some(*one),
        [] => match named.as_slice() {
            [one] => Some(one),
            [] => None,
            several => {
                let all: Vec<_> = several.iter().collect();
                return Err(BoxAddressRefusal::Ambiguous {
                    name: address.to_owned(),
                    candidates: candidates(&all, false),
                });
            }
        },
        several => {
            return Err(BoxAddressRefusal::Ambiguous {
                name: address.to_owned(),
                candidates: candidates(several, true),
            });
        }
    };
    if let Some((listing, matches)) = chosen
        && let Some(id) = newest_named(matches.iter().copied())
    {
        return Ok(resolved(listing, id));
    }

    if is_id_prefix(address) {
        let start = id_start(address);
        let mut matches = answered().flat_map(|(l, boxes)| {
            boxes
                .iter()
                .filter(|e| id_starts_with(e, &start))
                .map(move |e| (l, e.box_id))
        });
        if let Some((listing, id)) = matches.next() {
            if matches.next().is_some() {
                return Err(BoxAddressRefusal::AmbiguousIdStart {
                    start: address.to_owned(),
                });
            }
            return Ok(resolved(listing, id));
        }
    }
    Err(not_found())
}

/// What one host's listing holds for an id, a name or the start of an id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostMatch {
    /// One box matches.
    One(boxes::SessionId),
    /// The start of an id matches more than one box.
    SeveralIdStarts,
    /// No box matches.
    None,
}

/// The box `target` names in one host's `listing`: a listed full id, else
/// the box that holds the name, else the one box whose id starts with it.
pub(crate) fn match_on_host(listing: &[minimald_rpc::BoxListingEntry], target: &str) -> HostMatch {
    if let Ok(id) = boxes::SessionId::parse_str(target) {
        return if listing.iter().any(|e| e.box_id == id) {
            HostMatch::One(id)
        } else {
            HostMatch::None
        };
    }
    if let Some(id) = newest_named(listing.iter().filter(|e| holds_name(e, target))) {
        return HostMatch::One(id);
    }
    if is_id_prefix(target) {
        let start = id_start(target);
        let mut matches = listing.iter().filter(|e| id_starts_with(e, &start));
        if let Some(first) = matches.next() {
            if matches.next().is_some() {
                return HostMatch::SeveralIdStarts;
            }
            return HostMatch::One(first.box_id);
        }
    }
    HostMatch::None
}

/// Whether the box holds `name`, compared without ASCII case, as the daemon
/// compares names.
fn holds_name(entry: &minimald_rpc::BoxListingEntry, name: &str) -> bool {
    entry
        .name
        .as_deref()
        .is_some_and(|held| held.eq_ignore_ascii_case(name))
}

/// The start of an id as the comparison reads it: no dashes, lower case,
/// as `min session attach` compares it.
fn id_start(target: &str) -> String {
    target.replace('-', "").to_ascii_lowercase()
}

/// Whether the box's id, without dashes, starts with `start`.
fn id_starts_with(entry: &minimald_rpc::BoxListingEntry, start: &str) -> bool {
    entry
        .box_id
        .as_ref()
        .simple()
        .to_string()
        .starts_with(start)
}

/// Of the boxes that hold one name, the running one, else the one with the
/// greatest id. Box ids are UUIDv7, so the greatest id is the latest
/// creation.
pub(crate) fn newest_named<'a>(
    named: impl Iterator<Item = &'a minimald_rpc::BoxListingEntry>,
) -> Option<boxes::SessionId> {
    named
        .max_by_key(|entry| (entry.state == "running", *entry.box_id.as_ref()))
        .map(|entry| entry.box_id)
}

/// Resolves `address` over the local hosts for `verb`, and records the
/// verb, the box id and the outcome. A qualified address asks only its own
/// host. A version skew on the selected host ends the command, as it does
/// for `min box list`. A host that does not answer is named in the refusal.
pub(crate) async fn resolve_box_on_local_hosts(
    global: &GlobalArgs,
    address: &str,
    verb: &'static str,
) -> Result<ResolvedBox, anyhow::Error> {
    let mut hosts = crate::cmd::list::local_hosts(global)?;
    if let BoxAddress::Qualified { provider, host, .. } = parse_box_address(address) {
        hosts.retain(|h| h.provider == provider && h.host == host);
    }
    let mut listings = Vec::with_capacity(hosts.len());
    for host in hosts {
        let boxes = read_host_boxes(&host).await.inspect_err(|err| {
            tracing::info!(verb, outcome = "error", host = %host.host, "{err:#}");
        })?;
        listings.push(HostListing { host, boxes });
    }
    match resolve_box_address(address, &listings) {
        Ok(resolved) => {
            tracing::info!(
                verb,
                box_id = %resolved.box_id,
                host = %resolved.host.host,
                outcome = "resolved"
            );
            Ok(resolved)
        }
        Err(refusal) => {
            for listing in &listings {
                if let Err(why) = &listing.boxes {
                    tracing::info!(verb, host = %listing.host.host, "host did not answer: {why}");
                }
            }
            tracing::info!(verb, address, outcome = refusal.outcome(), "{refusal}");
            Err(refusal.into())
        }
    }
}

/// Every box record one host keeps. The selected host is reached with the
/// retry window and its build checked. A version skew there is the outer
/// error. A connect or listing failure on any host is the inner error, so
/// the resolver names that host. Another host is probed, and gives no
/// records when it is not running.
pub(crate) async fn read_host_boxes(
    host: &crate::cmd::list::LocalHost,
) -> Result<Result<Vec<minimald_rpc::BoxListingEntry>, String>, anyhow::Error> {
    if host.selected {
        let mut client = match connect_box_host(host).await {
            Ok(client) => client,
            Err(BoxHostConnect::Unreachable(e)) => return Ok(Err(format!("{e:#}"))),
            Err(BoxHostConnect::Skew(e)) => return Err(e),
        };
        return Ok(list_box_records(&mut client, None)
            .await
            .map_err(|e| format!("{e:#}")));
    }
    let read = tokio::time::timeout(client::PROBE_TIMEOUT, async {
        let mut client = match client::Client::probe(&host.sock).await {
            Ok(client) => client,
            Err(client::ProbeRefusal::NotRunning) => return Ok(Vec::new()),
            Err(client::ProbeRefusal::Unreachable(e)) => return Err(format!("{e:#}")),
        };
        list_box_records(&mut client, None)
            .await
            .map_err(|e| format!("{e:#}"))
    })
    .await;
    Ok(read.unwrap_or_else(|elapsed| {
        Err(format!(
            "daemon at {} did not answer within {:?}: {elapsed}",
            host.sock.display(),
            client::PROBE_TIMEOUT
        ))
    }))
}

/// Why the selected host gave no client.
pub(crate) enum BoxHostConnect {
    /// The daemon did not connect.
    Unreachable(anyhow::Error),
    /// The daemon connected, and its build is outside the supported window.
    Skew(anyhow::Error),
}

/// A client on the daemon of `host`: the selected host with the retry
/// window and its build checked, another host probed.
pub(crate) async fn box_host_client(
    host: &crate::cmd::list::LocalHost,
) -> Result<client::Client, anyhow::Error> {
    if host.selected {
        return connect_box_host(host).await.map_err(|failure| match failure {
            BoxHostConnect::Unreachable(e) | BoxHostConnect::Skew(e) => e,
        });
    }
    match probe_other_host(host).await? {
        Some(client) => Ok(client),
        None => bail!("Host {} is not running.", host.host),
    }
}

/// A client on the selected host's daemon, gated as `min box list` gates
/// the selected host: connect with the retry window, then assert the
/// daemon's build.
async fn connect_box_host(
    host: &crate::cmd::list::LocalHost,
) -> Result<client::Client, BoxHostConnect> {
    let mut client = client::Client::connect(&host.sock)
        .await
        .with_context(|| format!("Failed to connect to the daemon at {}", host.sock.display()))
        .map_err(BoxHostConnect::Unreachable)?;
    client::ensure_version_match(&mut client)
        .await
        .map_err(BoxHostConnect::Skew)?;
    Ok(client)
}

/// A client on a host this process did not select, probed ungated as
/// `min box list` probes its other hosts. A host that is not running gives
/// no client.
async fn probe_other_host(
    host: &crate::cmd::list::LocalHost,
) -> Result<Option<client::Client>, anyhow::Error> {
    match client::Client::probe(&host.sock).await {
        Ok(client) => Ok(Some(client)),
        Err(client::ProbeRefusal::NotRunning) => Ok(None),
        Err(client::ProbeRefusal::Unreachable(e)) => {
            Err(e.context(format!("Could not reach host {}.", host.host)))
        }
    }
}

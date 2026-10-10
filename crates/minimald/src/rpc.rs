use futures::StreamExt as _;
use minimald_rpc::{
    AbortSession, AbortSessionResponse, BoxControlReply, BoxControlRequest, CleanCacheRequest,
    CleanCacheUpdate, CreateSession, DestroySession, DestroySessionResponse, Errorable,
    FinalizeSession, GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest, GetMeshStatus,
    GetSessionPolicy, GetSessionPolicyRequest, GetSessionRecord, GetSessionRecordRequest,
    GetSessionRecordResponse, GetSessionScreen, GetVersion, GetVersionResponse, ListSessions,
    ListSessionsEntry, ListSessionsResponse, OneshotSshRpc, RPC_SUBSYSTEM_PREFIX, RenameSession,
    RenameSessionResponse, ResourcePool, SessionDelta, SessionDeltaRequest, SessionDeltaResponse,
    Shutdown, ShutdownRequest, ShutdownResponse, SubmitVerdict,
};
use russh::{
    Channel as RuChannel, ChannelId,
    server::{Msg, Session},
};
use sessions::SessionId;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::task::spawn;

use crate::{
    ChannelConfig,
    connection::{ConnectionError, ConnectionHandle},
    net::classifier,
    server::ServerStateHandle,
    sessions::SessionKeyPredicate,
};

/// This daemon's build, reported on every reply a version-gated client path
/// piggybacks its check on. One name for it so the assertion in
/// `serve_create_session` and the versions echoed to clients cannot drift.
const OWN_VERSION: &str = version::VERSION;

/// Server-side serving glue for [`OneshotSshRpc`]s.
///
/// The wire contract (names, request/response schemas) lives in the
/// `minimald-rpc` crate so clients can share it; this extension trait keeps
/// the transport-bound half — reading the request and writing the response
/// over an SSH channel — local to the server, where `russh` and
/// [`ConnectionError`] are available.
trait ServeOneshot: OneshotSshRpc {
    /// Helper to deserialize the request and serialize the response
    /// down the given SSH channel, calling the provided async handler
    /// function to compute the response.
    ///
    /// On a handler error the message is written to SSH extended data
    /// (stream 1) before the channel is closed, so the client sees a
    /// legible error instead of an opaque EOF (#901).
    async fn handle_channel<F>(
        &self,
        mut c: RuChannel<Msg>,
        handler: F,
    ) -> Result<(), ConnectionError>
    where
        F: for<'a> AsyncFnOnce(Self::Request<'a>) -> Result<Self::Response, ConnectionError>,
    {
        // Read the request by draining Data messages until Eof or the
        // channel closes. Using wait() directly (rather than into_stream)
        // so the channel remains available for extended_data_bytes() and
        // close() on the error path (#901).
        let mut buf = Vec::with_capacity(1024);
        while let Some(msg) = c.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => buf.extend_from_slice(&data),
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        // All error paths — JSON parse, handler, serialization — are funneled
        // through the same match so the client always sees a legible message
        // on extended data instead of an opaque EOF (#901).
        let result: Result<Vec<u8>, ConnectionError> = async {
            let request: Self::Request<'_> = serde_json_lenient::from_slice(&buf)?;
            let response = handler(request).await?;
            Ok(serde_json_lenient::to_vec(&response)?)
        }
        .await;

        match result {
            Ok(response_bytes) => {
                c.data_bytes(response_bytes).await?;
                c.eof().await?;
                c.close().await?;
                Ok(())
            }
            Err(e) => {
                let _ = c.extended_data_bytes(1, e.to_string()).await;
                let _ = c.close().await;
                Err(e)
            }
        }
    }
}

impl<T: OneshotSshRpc> ServeOneshot for T {}

async fn serve_get_version(c: RuChannel<Msg>) -> Result<(), ConnectionError> {
    GetVersion
        .handle_channel(c, async |_req| {
            Ok(GetVersionResponse {
                version: version::VERSION.to_string(),
                long_version: version::LONG_VERSION.to_string(),
                stdlib_version: stdlib::VERSION.to_string(),
            })
        })
        .await
}

async fn serve_list_sessions(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    ListSessions
        .handle_channel(c, async |_req| {
            let resource_pool = tokio::task::spawn_blocking(detect_resource_pool)
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            let mngr = s.sessions_manager().await;
            let infos = mngr
                .list()
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            // NET-018: the answerer's half of the report, and nothing else —
            // the one fact this daemon can know (see the field's doc on the
            // reply for why the daemon probes nothing beyond itself for it).
            // The observability line that names the surface is the answerer's
            // own startup line, not this reply's: a daemon whose answerer
            // has not come up pays nothing per list.
            let hostname_proxy_port = s.hostname_proxy_port().await;
            let zone_answerer_port = s.zone_answerer_port().await;
            // NET-079: the per-box egress enforcement each entry shows — the
            // box's own launch record, what the launch that produced this
            // box decided about it, lowered by the daemon's one classifier
            // fact and never raised above it. A box launched unenforced
            // stays `none` here for its life, whatever a later launch of
            // another box decided; only a host-address box that has not
            // launched yet shows the fact alone. [`displayed_host_ip_enforcement`]
            // shares the launch's own refusal gate, so a box the classifier
            // refuses shows nothing here exactly as its launch refused it.
            // A record that fails to read degrades to `None`: nothing said
            // is the same silence the other surfaces read as "not a
            // host-address session", so one unreadable record fails no
            // listing.
            let in_microvm = s.in_microvm().await;
            let fact = crate::session_host::host_ip_enforcement_fact();
            let enforcement = futures::future::join_all(infos.iter().map(|i| async {
                let record = mngr
                    .get_record(SessionKeyPredicate::Id(i.id))
                    .await
                    .ok()
                    .flatten();
                record.map(|record| {
                    crate::session_host::displayed_host_ip_enforcement(
                        in_microvm,
                        record.network,
                        classifier::verdict_of(record.policy.egress.as_ref()),
                        &fact,
                        record.host_ip_enforcement,
                    )
                })
            }))
            .await;
            Ok(ListSessionsResponse {
                daemon_version: Some(OWN_VERSION.to_string()),
                hostname_routing_unavailable: s.proxy_unavailable().await,
                hostname_proxy_port,
                zone_answerer_port,
                answerer_bound: zone_answerer_port.is_some(),
                resource_pool,
                // `git` is left `None`: the daemon cannot probe it — on
                // macOS it runs in the minvmd guest, where the host's
                // project paths do not exist and git is not on PATH. The
                // client fills it host-side after the reply.
                sessions: infos
                    .into_iter()
                    .zip(enforcement)
                    .map(|(i, host_ip_enforcement)| ListSessionsEntry {
                        // NET-129: the listing names the ports this box
                        // yields, from the same read the runtime facts use.
                        shared_port_collisions: shared_port_collisions_of(&mngr, i.id),
                        id: i.id,
                        name: i.name,
                        project_path: Some(i.project_path),
                        status: i.status,
                        git: None,
                        host_ip_enforcement: host_ip_enforcement.flatten(),
                        attrs: i.attrs.map(|a| minimald_rpc::RunningSessionAttrs {
                            last_stdout: a.stdout_last.map(|i| i.into()),
                            last_stdin: a.stdin_last.map(|i| i.into()),
                            title: a.title.map(|(value, set_at)| minimald_rpc::Title {
                                value,
                                updated_at: set_at.into(),
                            }),
                            visual_bell: a.visual_bell.1.map(|t| minimald_rpc::Bell {
                                count: a.visual_bell.0,
                                last: t.into(),
                            }),
                            audible_bell: a.audible_bell.1.map(|t| minimald_rpc::Bell {
                                count: a.audible_bell.0,
                                last: t.into(),
                            }),
                        }),
                    })
                    .collect(),
            })
        })
        .await
}

/// The ports a box's attach yields because a sibling at the same shared
/// loopback address holds them (NET-129, first-come), as the wire names
/// them: the one registry read both the runtime facts and the listing answer
/// from, so `min session policy` and `min session list` cannot disagree.
/// Empty for every mode but a shared-address own-ip box; a plain map lookup
/// behind the registry's lock, so it never holds up a reply.
fn shared_port_collisions_of(
    mngr: &crate::sessions::ManagerHandle,
    id: SessionId,
) -> Vec<minimald_rpc::SharedPortCollision> {
    let registry = mngr.hostnames();
    let routes = registry.read().expect("hostname registry lock poisoned");
    routes
        .shared_port_collisions(id)
        .into_iter()
        .map(|c| minimald_rpc::SharedPortCollision {
            port: c.port,
            held_by: c.other,
        })
        .collect()
}

fn detect_resource_pool() -> Option<ResourcePool> {
    let cpu_cores = std::thread::available_parallelism()
        .ok()?
        .get()
        .try_into()
        .ok()?;
    let mut system = sysinfo::System::new();
    system.refresh_memory();
    let memory_bytes = system.total_memory();

    (memory_bytes > 0).then_some(ResourcePool {
        cpu_cores,
        memory_bytes,
    })
}

async fn serve_get_session_record(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    use crate::sessions::SessionKeyPredicate;
    GetSessionRecord
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;
            Ok(GetSessionRecordResponse {
                daemon_version: Some(OWN_VERSION.to_string()),
                record: mngr
                    .get_record(match req {
                        GetSessionRecordRequest::Id(id) => SessionKeyPredicate::Id(id),
                        GetSessionRecordRequest::Name(name) => SessionKeyPredicate::Name(name),
                    })
                    .await
                    .map_err(|e| ConnectionError::Internal(e.to_string()))?,
            })
        })
        .await
}

/// Stand-in for `session_name` on the lifecycle records when the session
/// carries no user-assigned name. `SessionConfig::name` is `None` for an
/// anonymous session, and an absent field reads like a logging bug.
const ANONYMOUS_SESSION: &str = "<anonymous>";

/// The egress rule counts a session config parses to, one per egress field.
/// Logged beside the record the daemon stores at session start, they are the
/// diagnostic for what a session actually activated with: a count of `0`
/// means the field — or the whole `egress` section — carries no rules.
#[derive(Debug, Clone, Copy)]
struct EgressRuleCounts {
    allow_subnets: usize,
    allow_protocols: usize,
    allow_dns_hosts: usize,
    deny_subnets: usize,
}

impl EgressRuleCounts {
    fn of(policy: &minimald_rpc::SessionPolicy) -> Self {
        let egress = policy.egress.as_ref();
        Self {
            allow_subnets: egress
                .and_then(|e| e.allow_subnets.as_ref())
                .map_or(0, Vec::len),
            allow_protocols: egress
                .and_then(|e| e.allow_protocols.as_ref())
                .map_or(0, Vec::len),
            allow_dns_hosts: egress
                .and_then(|e| e.allow_dns_hosts.as_ref())
                .map_or(0, Vec::len),
            deny_subnets: egress
                .and_then(|e| e.deny_subnets.as_ref())
                .map_or(0, Vec::len),
        }
    }
}

/// `CreateSession`: allocates the session's record and brings its actor
/// up, replying with the assigned id. The loadout is composed separately,
/// by the `ConfigureLoadout` that follows.
async fn serve_create_session(
    s: ServerStateHandle,
    conn: ConnectionHandle,
    c: RuChannel<Msg>,
    ssh_username: Option<String>,
) -> Result<(), ConnectionError> {
    CreateSession
        .handle_channel(c, async |mut req| {
            // The version gate, made by the RPC the activation path was
            // already sending rather than by a `GetVersion` ahead of it
            // (#1251). Checked here, before the manager allocates anything,
            // because the failure this closes is precisely a session that
            // exists and then gets torn down by its own caller's cleanup:
            // refusing after `create_session` would reproduce it.
            if let Some(asserted) = req.must_match_version.as_deref()
                && let Some(message) = minimald_rpc::version_skew_message(asserted, OWN_VERSION)
            {
                return Ok(Errorable::Err { error: message });
            }

            // The user-namespace gate (NET-141): a host that refuses the
            // unprivileged user namespace every session sandbox starts by
            // unsharing would otherwise mint a session whose first attach
            // dies writing /proc/self/uid_map, with the cause in this log
            // alone. Refused here, before the manager allocates anything,
            // so the activation fails on a reply that names the cause and
            // the remedy, and nothing is left behind for its caller to tear
            // down.
            if let Some(restriction) = s.user_namespace_verdict().await {
                tracing::warn!(
                    reason = %restriction,
                    "session create refused: this host refuses the unprivileged user \
                     namespace every session sandbox needs"
                );
                return Ok(Errorable::Err {
                    error: user_namespace_refusal(restriction),
                });
            }

            let mngr = s.sessions_manager().await;
            // Read the name off the config before it is handed to the
            // manager: the success record below needs it, and the reply
            // carries only the assigned id.
            let session_name = req.config.name.clone();
            // Read the network mode off the config for the same reason: the
            // manager consumes it, and the mode the session activated with is
            // what the field below reports beside the "session created" line.
            let network = req.config.network;
            // Read the egress rule counts off the config for the same reason:
            // the manager consumes it, and the stored record's egress is what
            // the counts below report beside the "session created" line.
            let egress_counts = EgressRuleCounts::of(&req.config.policy);
            // NET-079: this host's verdict on whether it can decide a
            // host-address box's egress per box — the daemon's one node
            // fact, seeded by the start-up read and refreshed by each
            // host-address launch's re-read, read here rather than re-probed,
            // because a create is not a place that decides a box: the launch
            // that follows reads the host again, over the same tree and the
            // same table, before it places anything, and records its own
            // outcome on the session record this create is minting. The
            // advisory the fact yields rides the reply to the start that is
            // about to rely on the host's decision, and the enforcement is
            // the same derivation every read surface answers through — over
            // the declaration the config carries and with no launch record
            // to show yet, so the fact is the best either half of the daemon
            // knows about the box that is coming, and the launch's own
            // refusal gate holds here too: a create under a probe cause
            // refuses the box the same way its launch would, and carries
            // no enforcement value anywhere.
            //
            // Nothing is recorded at create: only a launch writes the
            // outcome, on the daemon-owned record field. The one key a
            // client might assert — the daemon's own `host_ip_enforcement`
            // — is stripped here, unconditionally and for every network
            // mode, because the reads answer over what the launch recorded
            // and must not be handed one by whoever activated.
            let in_microvm = s.in_microvm().await;
            // NET-081's host-table rule: on a VM-backed node a box's
            // addresses are allocated host-side and handed in, so an
            // own-address create that carries none is refused here, before
            // any record exists, rather than started as a box whose every
            // frame the host gate drops.
            if let Err(refused) = refuse_unhanded_vm_box(
                in_microvm,
                req.config.network,
                req.config.box_addresses.as_ref(),
            ) {
                return Ok(Errorable::Err {
                    error: refused.to_string(),
                });
            }
            let fact = crate::session_host::host_ip_enforcement_fact();
            let classifier_cause = fact.cause;
            let classifier_advisory = create_classifier_advisory(
                in_microvm,
                req.config.network,
                classifier_cause,
                req.config.policy.egress.as_ref(),
            );
            let host_ip_enforcement = crate::session_host::displayed_host_ip_enforcement(
                in_microvm,
                req.config.network,
                classifier::verdict_of(req.config.policy.egress.as_ref()),
                &fact,
                None,
            );
            req.config.attrs.remove(HOST_IP_ENFORCEMENT_ATTR);

            Ok(match mngr.create_session(req.config, ssh_username).await {
                Ok(id) => {
                    // Tag the session to this connection so it is reaped if
                    // the client drops before finalizing it (e.g. Ctrl-C at
                    // the gating prompt) — see [`ConnectionHandle`] and the
                    // teardown reap in `server.rs`.
                    conn.record_created_session(id).await;
                    tracing::info!(
                        session_id = %id,
                        session_name = session_name.as_deref().unwrap_or(ANONYMOUS_SESSION),
                        network_mode = %network.word(),
                        egress_allow_subnets = egress_counts.allow_subnets,
                        egress_allow_protocols = egress_counts.allow_protocols,
                        egress_allow_dns_hosts = egress_counts.allow_dns_hosts,
                        egress_deny_subnets = egress_counts.deny_subnets,
                        "session created"
                    );
                    // NET-079's observability: one info line per create
                    // response that carries the advisory, naming the cause
                    // it names and the per-box enforcement this create stated
                    // for a host-address box — so the daemon's log,
                    // the bundle's tail, carries what this reply told the
                    // person in the terminal, beside the start line and each
                    // launch's own record. The advisory rides as a field,
                    // Debug-escaped, because the line a person copies their
                    // command from must stay one line: the terminal gets the
                    // two-line spelling, the log gets the same text whole.
                    if let Some(advisory) = &classifier_advisory {
                        tracing::info!(
                            session_id = %id,
                            classifier_cause = classifier_cause
                                .map_or_else(|| "", classifier::Cause::detail),
                            classifier_install = ?classifier_cause
                                .and_then(classifier::Cause::install_command),
                            host_ip_enforcement =
                                ?host_ip_enforcement.map(|enforcement| enforcement.machine_str()),
                            advisory = ?advisory,
                            "session create carried the classifier advisory"
                        );
                    }
                    // NET-123: the session-start loopback probe, before any
                    // of this session's names publish. Its interim flag on
                    // the reply is what tells the client to surface the
                    // naming advisory again (NET-122). NET-018 reads the
                    // answerer's half straight off the state, not off this
                    // probe: the range the probe covers is the guest's on a
                    // VM-backed host, so it is not the reply's fact to read.
                    let interim_loopback = session_start_loopback_probe(&id).await.interim();
                    let hostname_proxy_port = s.hostname_proxy_port().await;
                    let zone_answerer_port = s.zone_answerer_port().await;
                    Errorable::Ok(minimald_rpc::CreateSessionResponse {
                        id,
                        daemon_version: Some(OWN_VERSION.to_string()),
                        hostname_routing_unavailable: s.proxy_unavailable().await,
                        hostname_proxy_port,
                        zone_answerer_port,
                        interim_loopback,
                        // The rollout's one fact the client cannot know from
                        // its own build (NET-077), carried on the reply the
                        // activation path already holds so the coming-change
                        // notice (NET-076) can stay off a deployment that has
                        // already chosen to keep the shipped default.
                        deny_all_opt_out: Some(s.deny_all_opt_out().await),
                        answerer_bound: zone_answerer_port.is_some(),
                        // NET-079's half: the advisory the start prints, and
                        // the enforcement the same derivation the reads
                        // answer through states over this create's
                        // declaration — the one message the activation path
                        // spends on it.
                        classifier_advisory,
                        host_ip_enforcement: host_ip_enforcement
                            .map(|enforcement| enforcement.machine_str().to_string()),
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Errorable::Err {
                    error: "A session with that name already exists".to_string(),
                },
                // R2.1: a policy/network-mode mismatch is rejected at
                // declaration time and surfaced as a clean typed error rather
                // than a transport failure. NET-079's refusal rides the same
                // arm — a host-address declaration whose rules this host's
                // classifier cannot enforce is refused at create while the
                // host decides per box, and its typed error names each
                // unenforced rule and ends with what to do about them, so
                // the person who typed the declaration is told which parts
                // could not be honoured — and what to type instead — rather
                // than reading a transport failure off the activate.
                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Errorable::Err {
                    error: e.to_string(),
                },
                Err(e) => return Err(ConnectionError::Internal(e.to_string())),
            })
        })
        .await
}

/// The record-attr key a create strips unconditionally (NET-079): the key
/// the state was once recorded under, so the one a client might assert to
/// hand the reads a state of its own choosing. The per-box enforcement is a
/// daemon-owned launch record — written only by the box's own launch, on
/// the record's `host_ip_enforcement` field, never an attr — and displayed
/// as that record lowered by the host's current fact, so the key is
/// removed whatever the session's network mode, and whatever value it
/// carries.
const HOST_IP_ENFORCEMENT_ATTR: &str = "host_ip_enforcement";

/// The refusal a host's user-namespace restriction yields (NET-141): the
/// wire crate's lead — what the client recognises the refusal by — around
/// the cause in the words the person reads, then that cause's own remedy
/// for the daemon on its own line: the install step and the restart it
/// needs for the AppArmor restriction, the persistent sysctl (or a kernel
/// with the namespace) when it is switched off.
fn user_namespace_refusal(restriction: crate::server::UsernsRestriction) -> String {
    format!(
        "{}{}), so no box can start here yet.\n{}",
        minimald_rpc::USER_NAMESPACE_REFUSAL_LEAD,
        restriction.cause(),
        restriction.remedy(sandbox2::RemedyTarget::Daemon {
            bin: &crate::server::this_daemon_path(),
        })
    )
}

/// The refusal an own-address create gets on a VM-backed node when it
/// carries no handed addresses (NET-081): the VM host allocates every
/// box-plane address and hands it in through the registration its control
/// socket serves, so the guest never mints one — a box created without a
/// row would start with every frame dropped at the host gate as an
/// unregistered source (NET-085), a box that is silently dark. `in_microvm`
/// is the daemon's own [`crate::server::Config::in_microvm`]. A native node
/// keeps NET-010's own allocator, and a box that is not own-address has no
/// box-plane address to hand. Pure over its inputs, so the gate is pinned
/// where it is written.
fn refuse_unhanded_vm_box(
    in_microvm: bool,
    network: minimald_rpc::NetworkMode,
    box_addresses: Option<&sessions::BoxAddresses>,
) -> std::io::Result<()> {
    if in_microvm && network == minimald_rpc::NetworkMode::OwnIp && box_addresses.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "box not registered with the VM host (no handed addresses); register \
             through minvmd's control socket first",
        ));
    }
    Ok(())
}

/// The advisory a create owes the start it answers (NET-079): only when
/// every half it is about is true — the daemon is not running inside a
/// microVM, the session is a host-address box, whose verdict is the one the
/// host's cgroup tree decides, and the box declares egress at all. In the
/// guest the start-up line and each launch's own record already say the
/// interim's state, and a guest's causes name its image's builder rather
/// than anything the person starting a session could run; an own-address
/// box's verdict is decided on address leases, so there is no per-box state
/// to advise about; and a box that declared nothing asked for no enforcement,
/// so there is nothing to tell it the host cannot enforce — the host fact
/// is still recorded on the reply, for `min session policy` to show. Over a
/// declaring host-address box on a native host, the advisory is
/// [`classifier::advisory_text`]'s — the same text the daemon's log line for
/// an advisory-carrying create carries. Pure over its inputs, so the gate is
/// pinned where it is written.
fn create_classifier_advisory(
    in_microvm: bool,
    network: minimald_rpc::NetworkMode,
    cause: Option<classifier::Cause>,
    egress: Option<&sessions::EgressPolicy>,
) -> Option<String> {
    if in_microvm || network != minimald_rpc::NetworkMode::HostNet {
        return None;
    }
    let egress = egress?;
    cause.map(|cause| classifier::advisory_text(cause, egress))
}

/// The bind probe over the reserved local range, on the blocking pool —
/// [`session_start_loopback_probe`]'s mechanism half, so the session-start
/// semantics and their log line stay on the wrapper. Cost and failure read
/// are the session-start one's: 254 binds with port 0, milliseconds for the
/// whole range, and a probe task that panics or is lost reads as absent,
/// because without a verdict the daemon may not report the range present.
///
/// The probe measures the daemon's own host and nothing else — whose
/// loopback that is on each platform, and why there is no per-target arm
/// here, is `net::loopback`'s module doc.
async fn run_loopback_probe() -> crate::net::loopback::RangeProbe {
    // The probe to run: the test stand-in when one is installed (a Linux
    // host's real bind can never produce the absent arm), else the real
    // bind probe.
    #[cfg(any(test, feature = "test-support"))]
    let probe_fn = crate::net::loopback::session_start_probe;
    #[cfg(not(any(test, feature = "test-support")))]
    let probe_fn = crate::net::loopback::probe;
    tokio::task::spawn_blocking(probe_fn)
        .await
        .unwrap_or_else(|join| {
            tracing::warn!(
                error = %join,
                "the session-start loopback probe did not run; treating \
                 the reserved local range as absent"
            );
            crate::net::loopback::RangeProbe::failed_to_run()
        })
}

/// The session-start loopback probe (NET-123): bind-probe the reserved local
/// range before this session publishes, log the one session-start line with
/// the probe result and the publish surface it picked, and return the
/// verdict the reply carries — the interim flag is its `interim()`. The
/// range's presence is no part of the name-surface verdict (NET-018): the
/// loopback it covers is the guest's on a VM-backed host, where it always
/// reads present, so the answerer-bound fact the replies do carry is the
/// daemon's only honest one — see
/// [`minimald_rpc::ListSessionsResponse::answerer_bound`].
async fn session_start_loopback_probe(session_id: &SessionId) -> crate::net::loopback::RangeProbe {
    let probe = run_loopback_probe().await;
    tracing::info!(
        session_id = %session_id,
        probe = %probe.summary(),
        surface = %probe.surface(),
        interim_loopback = probe.interim(),
        "session-start loopback probe picked the publish surface"
    );
    probe
}

/// How long [`log_live_name_surface`] lets the proxy's driver finish
/// recording its port before the line names the proxy's state: the two
/// listeners start together and normally land within milliseconds of one
/// another, so this is a settle, not a wait. A proxy still unrecorded past
/// it is one that is genuinely still coming up — a startup retry backing
/// off over a port some other process holds (NET-021) — and the surface
/// line must not sit behind it; the proxy's own startup line corrects the
/// record the moment it lands.
const PROXY_PORT_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);

/// NET-018's observability line, and NET-019's half said with it: the
/// answerer this daemon holds bound — its half of the native condition —
/// and that the hostname proxy keeps serving beside it, with the port a
/// client that captured `HTTP(S)_PROXY` keeps routing through.
///
/// Emitted once, from the answerer driver's serving tail (`server.rs`), at
/// the moment the fact it names comes to be: the answerer's bind is the
/// daemon's half of the native verdict, so that driver's success is the one
/// point in this daemon's own log that can record it. And it is the
/// daemon's moment, not a request's — a daemon no client has ever asked
/// still logs it, where the first-RPC emission round 1 shipped needed a
/// client to come and ask before the bundle had a line to tail.
///
/// The wording stops at what this daemon can see, and claims no more: the
/// answerer is bound on a port. Native DNS becomes the live name surface on
/// the *host* only once the host's own resolver routes the zone to that
/// answerer — the host's half of the condition (the resolver hook and the
/// published range), which no line this daemon writes can read — so the
/// line says exactly that and points at `min ls`, where the host's verdict
/// is reported from the one three-fact function both verbs print from
/// (and the session start logs its verdict beside its advisory, on the
/// host that read it).
///
/// The proxy's port may still be recording when the answerer binds — the
/// two listeners are started together on detached drivers and neither waits
/// for the other — so the proxy half is read after [`PROXY_PORT_SETTLE`]
/// rather than at the instant of the bind; a proxy that has not landed by
/// then is named as not serving, and its own startup line corrects the
/// record when it does.
pub(crate) async fn log_live_name_surface(state: &ServerStateHandle, zone_answerer_port: u16) {
    let hostname_proxy_port = settled_proxy_port(state).await;
    let proxy_half = match hostname_proxy_port {
        Some(port) => format!("the hostname proxy keeps serving on 127.0.0.1:{port}"),
        None => "the hostname proxy is not serving (yet)".to_string(),
    };
    tracing::info!(
        answerer_bound = true,
        zone_answerer_port,
        proxy_serves = hostname_proxy_port.is_some(),
        hostname_proxy_port = ?hostname_proxy_port,
        "this daemon's box-zone answerer is bound on 127.0.0.1:{zone_answerer_port}; \
         native DNS is the live name surface on the host once its resolver routes \
         the zone to it; `min ls` reports the host's surface; {proxy_half}"
    );
}

/// [`log_live_name_surface`]'s read of the proxy's port: the recorded port
/// when it is already there, else polled until it lands or
/// [`PROXY_PORT_SETTLE`] runs out.
async fn settled_proxy_port(state: &ServerStateHandle) -> Option<u16> {
    const POLL: std::time::Duration = std::time::Duration::from_millis(25);
    let deadline = tokio::time::Instant::now() + PROXY_PORT_SETTLE;
    loop {
        if let Some(port) = state.hostname_proxy_port().await {
            return Some(port);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(POLL).await;
    }
}

/// The answerer control socket's file name, beside the daemon's identity
/// dir (its provider instance dir) — the native door the answerer's
/// handover verbs knock on, the counterpart of the VM host daemon's
/// `control.sock` (its `minvmd` control module's socket of the same
/// name): one door per daemon, in a dir only this operator (and root)
/// can reach.
pub const ANSWERER_CONTROL_SOCK_FILE: &str = "control.sock";

/// The largest request line the answerer control socket will read: a
/// request is one small verb, so anything past this bound is not one.
const ANSWER_CONTROL_MAX_LINE: usize = 64 * 1024;

/// How long the answerer control socket waits for one request line: the
/// door answers one ask per connect, so a connection that parks without
/// asking is released at the bound rather than held for the daemon's
/// life.
const CONTROL_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Binds and serves the daemon's answerer control socket (NET-122's
/// native half of the same door the VM host daemon serves): the socket
/// answers the answerer's status and handover verbs —
/// `answerer_status`, `release_answerer`, `release_answerer_cancel` —
/// from the acquisition's status cell ([`AnswererStatus`]), and nothing
/// else: this daemon's boxes register over RPC channels, not over this
/// door, so every box verb is refused as a wrong-door ask.
///
/// The socket lives in the daemon's identity dir (its provider instance
/// dir, the dir its node id is), at [`ANSWERER_CONTROL_SOCK_FILE`], bound
/// before the answerer's acquisition starts so a control surface is
/// there whatever the acquisition decides; a daemon with no identity dir
/// configured (a harness server) serves from its state dir. Bound on the
/// calling task so a failure to bind surfaces to the caller, and the
/// accept loop runs detached for the daemon's life.
///
/// Access is the file's: owner-only (0600), in a dir only this operator
/// and root can reach. The peer check is belt to that braces: a request
/// is served when its peer is this daemon's own uid, or — for the two
/// handover verbs alone — root, whose install step (the answerer
/// service's) is the only asker that runs as root.
pub(crate) async fn spawn_answerer_control(
    state: &ServerStateHandle,
    status: crate::net::answerer::AnswererStatus,
) -> std::io::Result<()> {
    let dir = match state.daemon_identity_dir().await {
        Some(dir) => dir,
        None => state.minimal_state_dir().await,
    };
    let sock_path = std::path::PathBuf::from(dir.as_str()).join(ANSWERER_CONTROL_SOCK_FILE);
    // A socket left by a previous run of this same daemon instance is
    // stale the moment this one binds; a live one is another daemon's
    // door, not this one's to remove, so the bind is refused in its name
    // rather than taking the file out from under a daemon still serving
    // it. The probe is the connect the door's own askers make: a corpse
    // refuses it, a live listener takes it.
    use std::os::unix::fs::FileTypeExt as _;

    match std::fs::symlink_metadata(&sock_path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if tokio::net::UnixStream::connect(&sock_path).await.is_ok() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!(
                        "another daemon is already serving the answerer control socket at {}",
                        sock_path.display()
                    ),
                ));
            }
            let _ = std::fs::remove_file(&sock_path);
        }
        _ => {}
    }
    let listener = tokio::net::UnixListener::bind(&sock_path)?;
    std::fs::set_permissions(
        &sock_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;
    let shutdown = state.shutdown_token().await;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { return };
                    let status = status.clone();
                    tokio::spawn(serve_answerer_control(stream, status));
                }
            }
        }
    });
    tracing::info!(
        component = "zone-answerer",
        socket = %sock_path.display(),
        "the answerer control socket is listening; it answers the answerer's status and \
         handover verbs"
    );
    Ok(())
}

/// Serves one answerer control connection: one request line, one reply
/// line, the same shape every control socket of this system speaks (a
/// [`BoxControlRequest`] in, a [`BoxControlReply`] out), with this
/// daemon's bounds on both.
async fn serve_answerer_control(
    mut stream: tokio::net::UnixStream,
    status: crate::net::answerer::AnswererStatus,
) {
    use tokio::io::AsyncWriteExt as _;

    // The peer check comes at accept, before a byte is read, as on the VM
    // host daemon's door: this daemon's own uid may ask every verb, root
    // only the handover's two, and any other uid is closed on with a
    // debug line. The 0600 socket mode is the primary gate; this is
    // defence in depth against a mis-moded file or dir.
    let own_uid = current_uid();
    let peer_uid = match stream.peer_cred() {
        Ok(cred) => cred.uid(),
        Err(error) => {
            tracing::debug!(
                component = "zone-answerer",
                %error,
                "answerer control-socket peer check failed"
            );
            return;
        }
    };
    let root_peer = peer_uid == 0 && own_uid != 0;
    if peer_uid != own_uid && !root_peer {
        tracing::debug!(
            component = "zone-answerer",
            peer_uid,
            "refused an answerer control-socket connection from a uid that is neither this \
             daemon's nor root"
        );
        return;
    }
    let reply = match read_control_request(&mut stream).await {
        // A connect-and-close probe sent no line: nothing to answer.
        Ok(None) => return,
        Ok(Some(line)) => {
            // An unparseable line is a status ask, not an error reply: the
            // status ask is the read this door always answers, so a
            // probe's garbage gets the status and closes, rather than a
            // parse-failure no client of this door ever sends.
            let request: BoxControlRequest =
                serde_json_lenient::from_str(&line).unwrap_or(BoxControlRequest::AnswererStatus);
            if !answerer_control_admits(peer_uid, own_uid, &request) {
                tracing::warn!(
                    component = "zone-answerer",
                    peer_uid,
                    "refused an answerer control-socket request from root: root may only \
                     release the answerer or cancel a release"
                );
                return;
            }
            match request {
                BoxControlRequest::AnswererStatus => {
                    BoxControlReply::Status(minimald_rpc::AnswererStatusReply {
                        answerer: status.get(),
                        proxy_down: None,
                    })
                }
                BoxControlRequest::ReleaseAnswerer => {
                    let reply = status.release().await;
                    tracing::info!(
                        acted = reply.acted,
                        component = "zone-answerer",
                        "answer to a release request: {}",
                        reply.detail
                    );
                    BoxControlReply::AnswererRelease {
                        acted: reply.acted,
                        detail: reply.detail,
                    }
                }
                BoxControlRequest::ReleaseAnswererCancel => {
                    let reply = status.release_cancel().await;
                    tracing::info!(
                        acted = reply.acted,
                        component = "zone-answerer",
                        "answer to a release-cancel request: {}",
                        reply.detail
                    );
                    BoxControlReply::AnswererRelease {
                        acted: reply.acted,
                        detail: reply.detail,
                    }
                }
                BoxControlRequest::Register(_)
                | BoxControlRequest::Withdraw(_)
                | BoxControlRequest::HoldBoxName(_)
                | BoxControlRequest::ReleaseBoxName(_)
                | BoxControlRequest::AdmitPort(_)
                | BoxControlRequest::WithdrawPort(_)
                | BoxControlRequest::ReadRow(_)
                | BoxControlRequest::AdmitAsk(_)
                | BoxControlRequest::RecordAskAnswer(_)
                | BoxControlRequest::SubscribeAsks(_)
                | BoxControlRequest::ResumeBox(_)
                | BoxControlRequest::RowStanding(_) => BoxControlReply::Error {
                    error: "the native daemon's control socket answers only the answerer \
                            verbs; boxes register over the daemon's RPC channels"
                        .to_string(),
                },
            }
        }
        Err(error) => BoxControlReply::Error {
            error: format!("could not read the request line: {error}"),
        },
    };
    let line = match serde_json_lenient::to_string(&reply) {
        Ok(mut line) => {
            line.push('\n');
            line
        }
        Err(_) => "{\"error\":\"the reply did not serialize\"}\n".to_string(),
    };
    let _ = stream.write_all(line.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Reads one request line off a control connection, bounded by
/// [`ANSWER_CONTROL_MAX_LINE`] and by
/// [`CONTROL_REQUEST_TIMEOUT`]: a request is one small verb one connect
/// sends whole, so a connection that sends none — or half of one — is
/// released after the bound instead of being held for the daemon's life.
/// `Ok(None)` is a connection that said nothing — a probe's
/// connect-and-close, answered with nothing.
async fn read_control_request(
    stream: &mut tokio::net::UnixStream,
) -> std::io::Result<Option<String>> {
    use tokio::io::AsyncReadExt as _;

    let mut line = Vec::new();
    let mut buf = [0u8; 1024];
    let read = async {
        loop {
            let read = stream.read(&mut buf).await?;
            if read == 0 {
                return if line.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(String::from_utf8_lossy(&line).into_owned()))
                };
            }
            if let Some(newline) = buf[..read].iter().position(|byte| *byte == b'\n') {
                line.extend_from_slice(&buf[..newline]);
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
            line.extend_from_slice(&buf[..read]);
            if line.len() > ANSWER_CONTROL_MAX_LINE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the control request exceeded the line bound",
                ));
            }
        }
    };
    match tokio::time::timeout(CONTROL_REQUEST_TIMEOUT, read).await {
        Ok(result) => result,
        Err(_elapsed) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the control request did not arrive in time",
        )),
    }
}

/// This daemon's own uid — the peer check's own half.
/// Whether the answerer control socket serves `request` from `peer_uid`,
/// the gate the VM host daemon's door applies: this daemon's own uid asks
/// every verb, and root — the answerer service's install step, connecting
/// to a daemon that is not root's — only the handover's release and its
/// cancel. Any other uid was closed on at accept.
fn answerer_control_admits(peer_uid: u32, own_uid: u32, request: &BoxControlRequest) -> bool {
    if peer_uid == own_uid {
        return true;
    }
    peer_uid == 0
        && matches!(
            request,
            BoxControlRequest::ReleaseAnswerer | BoxControlRequest::ReleaseAnswererCancel
        )
}

fn current_uid() -> u32 {
    // SAFETY: getuid takes no arguments and cannot fault.
    unsafe { libc::getuid() }
}

/// `ConfigureLoadout`: composes a created session's loadout from the
/// project config in its workspace plus the client's contribution.
/// Resolves the session's live actor and routes the contribution to it;
/// the actor composes and either promotes its record `Pending → Active`
/// (`Ready`) or parks awaiting a verdict (`Pending`).
///
/// A compose failure leaves the session alive and unconfigured, so it
/// surfaces as an `Errorable::Err` the client can act on (fix the project
/// and retry, or abort) rather than a transport failure. An unknown id —
/// including an actor that died between resolve and delivery — is a
/// `NotFound`-flavoured `Errorable::Err`.
///
/// The actor refuses a re-`ConfigureLoadout` when it already holds a
/// pending contribution awaiting `SubmitVerdict`; the client has to
/// `AbortSession` and create a new session to retry. Without that guard
/// a second call would clobber the stashed `PendingComposeState` and
/// invalidate every `PendingId` the first caller received.
async fn serve_configure_loadout(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    minimald_rpc::ConfigureLoadout
        .handle_channel(c, async |req: minimald_rpc::ConfigureLoadoutRequest| {
            let mngr = s.sessions_manager().await;
            let handle = mngr
                .get_session(SessionKeyPredicate::Id(req.session_id))
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            let Some(h) = handle else {
                return Ok(Errorable::Err {
                    error: format!("no session with ID `{}`", req.session_id.as_ref()),
                });
            };
            Ok(match h.configure_loadout(req.contribution).await {
                Ok(None) => Errorable::Ok(minimald_rpc::ConfigureLoadoutResponse::Materialized),
                Ok(Some(response)) => {
                    Errorable::Ok(minimald_rpc::ConfigureLoadoutResponse::Pending { response })
                }
                Err(e) => Errorable::Err {
                    error: e.to_string(),
                },
            })
        })
        .await
}

/// `SubmitVerdict`: the client's per-item decisions for a `Pending`
/// session. Resolves the session's live actor and routes the verdict
/// to it; the actor runs `resume_from_verdict` and promotes its
/// record `Pending → Active`. Replies with `Errorable::Ok(SessionStep)`
/// where the `SessionStep` is `Active { id }` on success or
/// `Fault { error }` for a structured failure. A verdict for an id
/// with no live session — including an actor that died between
/// resolve and delivery — maps to `Fault { UnknownSessionId }` here;
/// other `io::Error`s bubble up as `ConnectionError::Internal`.
async fn serve_submit_verdict(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    SubmitVerdict
        .handle_channel(
            c,
            async |req: sessions::wire::request::ContributionVerdict| {
                let mngr = s.sessions_manager().await;
                let unknown = || {
                    Errorable::Ok(sessions::wire::request::SessionStep::Fault {
                        error: sessions::wire::errors::WireError::UnknownSessionId,
                    })
                };
                let handle = mngr
                    .get_session(SessionKeyPredicate::Id(req.session_id))
                    .await
                    .map_err(|e| ConnectionError::Internal(e.to_string()))?;
                match handle {
                    None => Ok(unknown()),
                    Some(h) => match h.submit_verdict(req).await {
                        Ok(step) => Ok(Errorable::Ok(step)),
                        Err(e) if e.kind() == std::io::ErrorKind::NotConnected => Ok(unknown()),
                        Err(e) => Err(ConnectionError::Internal(e.to_string())),
                    },
                }
            },
        )
        .await
}

/// `FinalizeSession`: promotes a `Materializing` session to
/// `Active`. Gated on the patches-ready marker being present
/// under `<workspace>/patches/`; a missing marker (client crashed
/// mid-upload, or skipped the patches upload entirely) surfaces
/// as `Errorable::Err`. Idempotent on already-Active sessions.
async fn serve_finalize_session(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    FinalizeSession
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;
            let handle = mngr
                .get_session(SessionKeyPredicate::Id(req.session_id))
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            let Some(h) = handle else {
                return Ok(Errorable::Err {
                    error: format!("no session with ID `{}`", req.session_id.as_ref()),
                });
            };
            Ok(match h.finalize().await {
                Ok(mut response) => {
                    // The reply is `deny_unknown_fields`, so a client that
                    // did not ask for the yielded ports would refuse a reply
                    // naming them and abort its activation: only a client
                    // that asked gets the list (the yield itself stands).
                    if !req.report_shared_port_collisions {
                        response.shared_port_collisions.clear();
                    }
                    Errorable::Ok(response)
                }
                Err(e) => Errorable::Err {
                    error: e.to_string(),
                },
            })
        })
        .await
}

/// `RenameSession`: resolves the session's actor (spinning it up from
/// disk if needed) and lets it persist the new name and relink its
/// PTask hostname. A name collision surfaces as the store's
/// `AlreadyExists` in the `Errorable::Err` text.
async fn serve_rename_session(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    RenameSession
        .handle_channel(c, async |req| {
            let res = async {
                match s
                    .sessions_manager()
                    .await
                    .get_session(SessionKeyPredicate::Id(req.id))
                    .await?
                {
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("no session with ID `{}`", req.id.as_ref()),
                    )),
                    Some(h) => h.rename(req.new_name).await,
                }
            }
            .await;
            match res {
                Ok(()) => Ok(Errorable::Ok(RenameSessionResponse)),
                Err(e) => Ok(Errorable::Err {
                    error: e.to_string(),
                }),
            }
        })
        .await
}

async fn serve_destroy_session(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    DestroySession
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;
            // Resolve the name before the delete — the request carries only
            // the id, and once the record is gone there is nothing left to
            // resolve it against. Purely for the record below, so a failed
            // lookup degrades to the anonymous stand-in rather than failing
            // a destroy that would otherwise succeed.
            let session_name = mngr
                .get_record(SessionKeyPredicate::Id(req.id))
                .await
                .ok()
                .flatten()
                .and_then(|record| record.name);
            match mngr.delete_session(req.id).await {
                Ok(hook_failures) => {
                    tracing::info!(
                        session_id = %req.id,
                        session_name = session_name.as_deref().unwrap_or(ANONYMOUS_SESSION),
                        "session destroyed"
                    );
                    Ok(Errorable::Ok(DestroySessionResponse { hook_failures }))
                }
                Err(e) => Ok(Errorable::Err {
                    error: e.to_string(),
                }),
            }
        })
        .await
}

async fn serve_shutdown(s: ServerStateHandle, c: RuChannel<Msg>) -> Result<(), ConnectionError> {
    Shutdown
        .handle_channel(c, async |req: ShutdownRequest| {
            let mngr = s.sessions_manager().await;
            Ok(match mngr.shutdown(req.force).await {
                Ok(()) => {
                    // Close the file log first (both the native daemon and the
                    // microVM): it flushes buffered records, and in the
                    // microVM its write-open fd under the mountpoint would
                    // otherwise defeat the clean unmount below. Records still
                    // reach the console. A no-op for a foreground run.
                    s.release_log().await;
                    // R2.1/R2.2: with the sessions drained, quiesce the state
                    // volume (syncfs + detach) before acknowledging, so a
                    // caller-driven VMM teardown right after the ack leaves a
                    // clean ext4 journal. Best-effort with a bounded wait; the
                    // journal replay backstop covers every failure arm.
                    quiesce_state_volume_if_mounted(&s).await;
                    // Manager is down; tell the accept loop to stop and drain
                    // so the process can exit. Firing before the response is
                    // written is safe: the drain waits out the grace period,
                    // so this reply still flushes to the client.
                    s.trigger_shutdown().await;
                    ShutdownResponse::ShuttingDown
                }
                Err(()) => ShutdownResponse::SessionsLive,
            })
        })
        .await
}

/// Quiesce the guest state volume during shutdown (R2.2). No-op unless the
/// boot path actually mounted the data volume at the state dir — a native
/// daemon's host directory, or a microVM running without a volume, must
/// never be synced-and-unmounted out from under the host. `syncfs` is
/// blocking, so it runs on the blocking pool with a 10 s ceiling; the
/// handler proceeds regardless of the outcome. Note the ceiling's residual
/// risk: a timed-out `syncfs` keeps running detached while the handler acks,
/// so a very large dirty set can still be mid-flush when the caller tears
/// the VM down — bounded, as ever, by the ext4 journal replay backstop.
#[cfg(target_os = "linux")]
async fn quiesce_state_volume_if_mounted(s: &ServerStateHandle) {
    const QUIESCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    if !s.state_volume_mounted().await {
        return;
    }
    // The file log was already released by the shutdown handler, so its fd no
    // longer holds the mountpoint busy.
    let mountpoint = s.minimal_state_dir().await;
    let quiesce = tokio::task::spawn_blocking(move || {
        crate::guest::quiesce_state_volume(mountpoint.as_utf8_path().as_str())
    });
    match tokio::time::timeout(QUIESCE_TIMEOUT, quiesce).await {
        Ok(Ok(Ok(()))) => tracing::info!("state volume quiesced for shutdown"),
        Ok(Ok(Err(e))) => {
            tracing::warn!(error = %e, "state volume quiesce failed; ext4 journal replay will recover")
        }
        Ok(Err(join)) => tracing::warn!(error = %join, "state volume quiesce task panicked"),
        Err(_) => tracing::warn!("state volume quiesce timed out after 10s; proceeding"),
    }
}

#[cfg(not(target_os = "linux"))]
async fn quiesce_state_volume_if_mounted(_s: &ServerStateHandle) {}

/// `AbortSession`: routes to the session actor, whose state machine
/// deletes a `Draft` session's record and stops, or refuses an
/// `Active` session with `InvalidInput` (use `DestroySession`).
/// Unknown ids are `NotFound`.
async fn serve_abort_session(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    AbortSession
        .handle_channel(c, async |req| {
            let res = async {
                match s
                    .sessions_manager()
                    .await
                    .get_session(SessionKeyPredicate::Id(req.id))
                    .await?
                {
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("no session with ID `{}`", req.id.as_ref()),
                    )),
                    Some(h) => h.abort().await,
                }
            }
            .await;
            match res {
                Ok(()) => Ok(Errorable::Ok(AbortSessionResponse)),
                Err(e) => Ok(Errorable::Err {
                    error: e.to_string(),
                }),
            }
        })
        .await
}

async fn serve_get_session_policy(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    GetSessionPolicy
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;
            let predicate = match req {
                GetSessionPolicyRequest::Id(id) => SessionKeyPredicate::Id(id),
                GetSessionPolicyRequest::Name(name) => SessionKeyPredicate::Name(name),
            };
            let record = mngr
                .get_record(predicate)
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            match record {
                None => Ok(Errorable::Err {
                    error: "no session found".to_string(),
                }),
                // R2.6: return the policy configured at launch from the live
                // session record, not a hardcoded default.
                Some(record) => Ok(Errorable::Ok(record.policy)),
            }
        })
        .await
}

/// The `GetEffectiveSessionPolicy` reply for one record's policy and network
/// mode: the egress half resolved to what the gate enforces, the ingress half
/// verbatim, and the credentialed-upstream lane (NET-134) verbatim.
///
/// The reply rule: the policy struct is `deny_unknown_fields`, so an older
/// `min` rejects a key it has no field for. A field that changes what the
/// box can reach goes in this strict reply, so an older `min` fails visibly
/// instead of under-reporting the box's reach — the lane is such a field,
/// and `min session policy` reads no other reply that carries it.
/// Descriptive state — NET-079's enforcement state among it — never rides
/// here: it answers beside this reply, over `GetSessionRuntimeFacts`, so an
/// older client keeps reading the rules.
///
/// `phase` is the rollout phase to resolve under — the handler serves
/// [`sessions::EGRESS_DEFAULT_PHASE`], the phase this build ships, and the
/// tests name [`sessions::EgressDefaultPhase::InForce`] so the deny-all
/// posture they prove does not hang on that constant.
pub(crate) fn effective_policy_reply(
    policy: &sessions::SessionPolicy,
    network: sessions::NetworkMode,
    phase: sessions::EgressDefaultPhase,
    opt_out: bool,
) -> minimald_rpc::EffectiveSessionPolicy {
    minimald_rpc::EffectiveSessionPolicy {
        egress: sessions::effective_egress(policy.egress.as_ref(), network, phase, opt_out),
        ingress: policy.ingress.clone(),
        credentialed_upstream: policy.credentialed_upstream.clone(),
    }
}

/// `GetEffectiveSessionPolicy`: the same record
/// [`serve_get_session_policy`] serves, with the egress half resolved to what
/// the gate enforces — the answer `min session policy` renders (NET-075).
///
/// Resolved here rather than in the client because the inputs are this
/// daemon's own facts: the rollout phase its build ships
/// ([`sessions::EGRESS_DEFAULT_PHASE`]) and its opt-out flag (NET-077). An
/// own-address box with no `egress` section answers `deny_all` with the
/// default in force (NET-074) and `allow_all` behind the opt-out; a declared
/// section answers verbatim; the
/// strict declaration the record holds is never rewritten to say any of
/// this.
async fn serve_get_effective_session_policy(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    GetEffectiveSessionPolicy
        .handle_channel(c, async |req| {
            let opt_out = s.deny_all_opt_out().await;
            let mngr = s.sessions_manager().await;
            let predicate = match req {
                GetEffectiveSessionPolicyRequest::Id(id) => SessionKeyPredicate::Id(id),
                GetEffectiveSessionPolicyRequest::Name(name) => SessionKeyPredicate::Name(name),
            };
            let record = mngr
                .get_record(predicate)
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            match record {
                None => Ok(Errorable::Err {
                    error: "no session found".to_string(),
                }),
                Some(record) => {
                    // NET-079's enforcement state no longer rides this
                    // reply: the policy struct is `deny_unknown_fields`, so
                    // an older `min` would reject the whole reply over the
                    // key it has no field for. It answers over
                    // `GetSessionRuntimeFacts` (see
                    // [`serve_get_session_runtime_facts`]), beside the
                    // rules rather than inside them.
                    Ok(Errorable::Ok(effective_policy_reply(
                        &record.policy,
                        record.network,
                        sessions::EGRESS_DEFAULT_PHASE,
                        opt_out,
                    )))
                }
            }
        })
        .await
}

/// `GetLiveIngress`: the live dynamic-ingress mappings a session's box
/// published at runtime (NET-044) — the rows `min session policy` lists beside
/// the declaration, which is what makes a publish visible rather than only
/// permitted.
///
/// The live actor's own state, so this resolves the session where the policy
/// RPCs read the record: [`Manager::get_session`] brings a known session's
/// actor up if it has none running, and an actor holding no host answers an
/// empty list — the honest answer for a box that is not running, since a
/// publish lives only while its box does.
///
/// Every row reads not pending: a runtime publish admits its port at the
/// box's relay gate in the same turn it records the mapping (NET-044), so a
/// listed publish is reachable. The `pending` field stays on the wire so a
/// client can still tell this daemon's rows from an older daemon's. The
/// listen watcher's rows — the in-range listens the box's `allow` stance
/// published — follow the exposes' rows, reachable too: the watcher admits
/// each port at the gate as its publish's last step.
async fn serve_get_live_ingress(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    minimald_rpc::GetLiveIngress
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;
            let predicate = match req {
                minimald_rpc::GetLiveIngressRequest::Id(id) => SessionKeyPredicate::Id(id),
                minimald_rpc::GetLiveIngressRequest::Name(name) => SessionKeyPredicate::Name(name),
            };
            let session = mngr
                .get_session(predicate)
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            match session {
                None => Ok(Errorable::Err {
                    error: "no session found".to_string(),
                }),
                Some(session) => match session.live_ingress().await {
                    // The actor's own rows, `pending: Some(false)` each: the
                    // publish admitted the port when it recorded the row. The
                    // listen watcher's rows follow the exposes' as they
                    // stand: the gate admitted each one as its publish's
                    // last step.
                    Ok(live) => Ok(Errorable::Ok(
                        live.exposed.into_iter().chain(live.listened).collect(),
                    )),
                    Err(e) => Ok(Errorable::Err {
                        error: e.to_string(),
                    }),
                },
            }
        })
        .await
}

/// `GetSessionRuntimeFacts`: NET-079's per-box enforcement state for one
/// session — the box's own launch record, lowered by the daemon's one
/// classifier fact over the record's own declaration and network mode — the
/// same read the listing answers over, so `min session policy` and a listing
/// cannot disagree, and never re-probed here. The record is the box's own
/// launch outcome, so a box launched unenforced says `none` for its life
/// beside the rules it runs under, never the host's later state.
///
/// Served over this reply rather than a field on the effective policy
/// because the policy struct is `deny_unknown_fields`: an older `min` has no
/// field for the key and would refuse the whole reply, rules included. A
/// client that cannot ask for the facts — an older `min`, against this
/// daemon, or a newer one against an older daemon — simply gets no row,
/// which is the same silence the field's own absence reads as.
async fn serve_get_session_runtime_facts(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    use minimald_rpc::GetSessionRuntimeFactsRequest;
    minimald_rpc::GetSessionRuntimeFacts
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;
            let predicate = match req {
                GetSessionRuntimeFactsRequest::Id(id) => SessionKeyPredicate::Id(id),
                GetSessionRuntimeFactsRequest::Name(name) => SessionKeyPredicate::Name(name),
            };
            let record = mngr
                .get_record(predicate)
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            match record {
                None => Ok(Errorable::Err {
                    error: "no session found".to_string(),
                }),
                Some(record) => {
                    let host_ip_enforcement = crate::session_host::displayed_host_ip_enforcement(
                        s.in_microvm().await,
                        record.network,
                        classifier::verdict_of(record.policy.egress.as_ref()),
                        &crate::session_host::host_ip_enforcement_fact(),
                        record.host_ip_enforcement,
                    );
                    // The listen publishes the audit log refused (NET-046):
                    // a watcher-driven publish has no caller to answer, so
                    // the live actor's set is read here and `min session
                    // policy` warns per port. A session whose actor cannot
                    // answer has no watcher running, and nothing to warn
                    // about.
                    let unaudited_listen_ports =
                        match mngr.get_session(SessionKeyPredicate::Id(record.id)).await {
                            Ok(Some(session)) => session
                                .live_ingress()
                                .await
                                .map(|live| live.unaudited_listen_ports)
                                .unwrap_or_default(),
                            Ok(None) | Err(_) => Vec::new(),
                        };
                    let audit_log = if unaudited_listen_ports.is_empty() {
                        None
                    } else {
                        let state_dir = s.minimal_state_dir().await;
                        Some(
                            crate::audit::log_path(state_dir.as_utf8_path().as_std_path())
                                .display()
                                .to_string(),
                        )
                    };
                    // The ports this box's attach yields because a sibling at
                    // the same shared loopback address holds them (first-come):
                    // the same registry record the attach path reads to skip
                    // those forwards, surfaced so the policy view can mark the
                    // declared rows that are served elsewhere. Empty for every
                    // mode but a shared-address own-ip box — and read behind
                    // the registry's lock, a plain map lookup, so it never
                    // holds up the reply.
                    let shared_port_collisions = shared_port_collisions_of(&mngr, record.id);
                    Ok(Errorable::Ok(minimald_rpc::SessionRuntimeFacts {
                        id: record.id,
                        host_ip_enforcement,
                        unaudited_listen_ports,
                        audit_log,
                        shared_port_collisions,
                    }))
                }
            }
        })
        .await
}

/// `GetSessionHooks`: the lifecycle hooks composed into a session, each
/// with the loadout or project that declared it.
///
/// Read from the persisted composition snapshot, so it answers for a
/// session with no running host and survives a daemon restart. A session
/// whose snapshot is missing (activated before snapshots existed, or
/// reaped mid-write) reports an empty list rather than failing: "no
/// hooks recorded" is the honest answer, and there is nothing to run.
async fn serve_get_session_hooks(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    minimald_rpc::GetSessionHooks
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;
            let predicate = match req {
                minimald_rpc::GetSessionHooksRequest::Id(id) => SessionKeyPredicate::Id(id),
                minimald_rpc::GetSessionHooksRequest::Name(name) => SessionKeyPredicate::Name(name),
            };
            // The record first, only to tell "no such session" from "a
            // session with nothing recorded" — both of which the
            // composition read answers with `None`.
            if mngr
                .get_record(predicate.clone())
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?
                .is_none()
            {
                return Ok(Errorable::Err {
                    error: "no session found".to_string(),
                });
            }
            // Read-only: `get_composition` goes to the store rather than
            // the actor, so listing a stopped session's hooks does not
            // start it. Reporting on a session is not a reason to run one.
            let composition = mngr
                .get_composition(predicate)
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            let hooks = composition
                .map(|c| {
                    c.lifecycle_hooks()
                        .iter()
                        .cloned()
                        .map(Into::into)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Ok(Errorable::Ok(hooks))
        })
        .await
}

/// `SessionDelta`: the session workspace's at-risk report — VCS-exact
/// (uncommitted files, unpushed commits) when the tree is a git repository,
/// the changed-since-activation rows otherwise. Best-effort by contract: an
/// unknown session, a session without a running host, and a failed
/// computation all answer `Unavailable` rather than an error — the client's
/// destroy confirm renders with or without the listing.
async fn serve_session_delta(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    SessionDelta
        .handle_channel(c, async |req: SessionDeltaRequest| {
            let predicate = SessionKeyPredicate::Id(req.id);
            Ok(
                match s.sessions_manager().await.get_session(predicate).await {
                    Ok(Some(h)) => h.workspace_at_risk().await,
                    Ok(None) | Err(_) => SessionDeltaResponse::Unavailable,
                },
            )
        })
        .await
}

/// `GetSessionScreen` (`min dash` Preview section): a read-only snapshot of the
/// session's terminal screen. Unlike attach, this mints nothing and resizes
/// nothing — a session with no live host answers with an error the TUI
/// renders as "session not active".
async fn serve_get_session_screen(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    GetSessionScreen
        .handle_channel(c, async |id| {
            let mngr = s.sessions_manager().await;
            let snapshot = mngr
                .get_screen(SessionKeyPredicate::Id(id))
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            Ok(match snapshot {
                Some(snap) => Errorable::Ok(snap),
                None => Errorable::Err {
                    error: "session is not active".to_string(),
                },
            })
        })
        .await
}

async fn serve_get_mesh_status(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    GetMeshStatus
        .handle_channel(c, async |_req| Ok(s.mesh_status().await))
        .await
}

/// Serves [`CLEAN_CACHE_SUBSYSTEM`]: runs a cache clean and streams its
/// progress back as newline-delimited [`CleanCacheUpdate`]s.
///
/// The split between the two error surfaces is the wire contract: anything that
/// goes wrong before the clean starts leaves the payload stream empty and says
/// why on extended data, so a client that read no lines knows to look there.
/// Once the clean is running, its own failure is a terminal `Failed` line. (A
/// channel that breaks mid-stream also lands on the extended-data arm, where
/// the write is best-effort — by then the client is already gone.)
async fn serve_clean_cache(
    s: ServerStateHandle,
    mut c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    match clean_cache_stream(&s, &mut c).await {
        Ok(()) => {
            c.eof().await?;
            c.close().await?;
            Ok(())
        }
        Err(e) => {
            let _ = c.extended_data_bytes(1, e.to_string()).await;
            let _ = c.close().await;
            Err(e)
        }
    }
}

/// Reads the request, then runs the clean, writing each event out as it
/// happens. The `Err` arm is for failures that precede the clean; a clean that
/// runs reports its own outcome on the payload stream.
async fn clean_cache_stream(
    s: &ServerStateHandle,
    c: &mut RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    let req: CleanCacheRequest = read_channel_request(c).await?;
    let older_than = match req.older_than_secs {
        0 => None,
        secs => Some(std::time::Duration::from_secs(secs)),
    };
    // Every clean goes through the one actor. No actor means no daemon
    // housekeeping to ask (a state built outside `Server::run`), and a clean
    // started here instead would be exactly the unsynchronized second cleaner
    // the actor exists to prevent.
    let maintenance = s.maintenance().await.ok_or_else(|| {
        ConnectionError::Internal("daemon housekeeping is not running".to_string())
    })?;

    let (events, mut rx) = futures::channel::mpsc::unbounded();
    let clean = maintenance.clean_now(older_than, Some(events));
    let mut clean = std::pin::pin!(clean);

    // Drain events as they arrive, until the clean itself resolves. Once the
    // sender is dropped `rx` yields `None`, which disables that branch for the
    // rest of this `select!` — the clean's own branch is irrefutable and never
    // disabled, so the loop parks on it rather than spinning.
    let report = loop {
        tokio::select! {
            Some(event) = rx.next() => write_update(c, &removed(event)).await?,
            report = &mut clean => break report,
        }
    };
    // The clean is done, so its sender is dropped: whatever is still queued is
    // the tail, and the loop below ends on its own.
    while let Some(event) = rx.next().await {
        write_update(c, &removed(event)).await?;
    }

    let terminal = match report {
        Ok(report) => CleanCacheUpdate::Done {
            entries: report.entries,
            dirs: report.dirs,
        },
        Err(e) => CleanCacheUpdate::Failed {
            error: e.to_string(),
        },
    };
    write_update(c, &terminal).await
}

/// The wire form of one reclaimed thing. `render` is the daemon's own
/// rendering, so the RPC and the daemon log say the same words.
fn removed(event: op::CleanEvent) -> CleanCacheUpdate {
    CleanCacheUpdate::Removed {
        detail: event.render(),
    }
}

/// Writes one newline-delimited JSON update.
async fn write_update(
    c: &mut RuChannel<Msg>,
    update: &CleanCacheUpdate,
) -> Result<(), ConnectionError> {
    let mut line = serde_json_lenient::to_vec(update)?;
    line.push(b'\n');
    c.data_bytes(line).await?;
    Ok(())
}

/// Reads a JSON request body off `c`, draining until the client half-closes.
/// The streaming handlers' equivalent of what
/// [`ServeOneshot::handle_channel`] does inline.
async fn read_channel_request<T: serde::de::DeserializeOwned>(
    c: &mut RuChannel<Msg>,
) -> Result<T, ConnectionError> {
    let mut buf = Vec::with_capacity(1024);
    while let Some(msg) = c.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => buf.extend_from_slice(&data),
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    Ok(serde_json_lenient::from_slice(&buf)?)
}

pub(crate) const STREAM_WORKSPACE_FILES: &str =
    constcat::concat!(RPC_SUBSYSTEM_PREFIX, "WorkspaceFilesTarZst");

pub(crate) const STREAM_WORKSPACE_PATCHES: &str =
    constcat::concat!(RPC_SUBSYSTEM_PREFIX, "WorkspacePatchesTarZst");

/// Marker file the patches unpacker drops after a successful
/// atomic swap. `FinalizeSession` checks for its presence before
/// promoting a session from `Materializing` to `Active`, so a
/// client-side crash between upload and finalize can't leave the
/// session `Active` without patches on disk. See the "why the
/// marker exists" note in `finalize_session_handler`.
pub(crate) const PATCHES_READY_MARKER: &str = ".patches_ready";

pub(crate) const STREAM_WORKSPACE_HOOK_SCRIPTS: &str =
    constcat::concat!(RPC_SUBSYSTEM_PREFIX, "WorkspaceHookScriptsTarZst");

/// Marker file the hook-script unpacker drops after a successful
/// atomic swap. `FinalizeSession` requires it before promoting a
/// session whose composition declares external hook scripts, so a
/// client that skipped the upload can't leave an `Active` session
/// whose hooks reference files that were never staged.
pub(crate) const HOOKS_READY_MARKER: &str = ".hooks_ready";

/// Per-entry size cap on incoming hook scripts. A lifecycle hook is a
/// shell script; a megabyte is already far past anything reasonable,
/// and the cap exists to stop a forged tar header from driving
/// `Vec::with_capacity` into an allocation failure, not to constrain
/// legitimate use.
const MAX_HOOK_SCRIPT_BYTES: u64 = 1024 * 1024;

/// Per-entry size cap on incoming patch archives. Legitimate patch files are
/// dotfiles (KB to a few MB); this ceiling is generous but bounded so a peer
/// forging a tar header can't push `Vec::with_capacity` into an allocation
/// error (panic → task abort) or trigger the allocator's OOM handler
/// (aborts the whole daemon).
const MAX_PATCH_ENTRY_BYTES: u64 = 1024 * 1024 * 1024;

/// Total bytes held in memory across every in-flight patch write in a single
/// `WorkspacePatchesTarZst` unpack. The per-entry cap alone isn't a memory
/// bound — the concurrency knob multiplies through it, so on a many-core
/// host without this the ceiling would be tens of GiB. Fixed at 1 GiB
/// regardless of core count: legitimate patch payloads are small dotfile
/// trees; the ceiling exists as an adversarial-input backstop, not as a
/// throughput knob.
const MAX_UNPACK_INFLIGHT_BYTES: usize = 1024 * 1024 * 1024;

/// Tallies the bytes pulled through an [`AsyncRead`] into a shared counter.
///
/// The counter is shared rather than returned because the reader is
/// swallowed by the decompressor and then by the tar unpacker: when the
/// transfer dies mid-stream those layers surface an error and drop the
/// reader, and the tally is the only surviving evidence of how far the
/// upload got.
struct CountingReader<R> {
    inner: R,
    count: Arc<AtomicU64>,
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        // Only a successful read grows `filled`; a pending or failed poll
        // leaves it untouched, so the delta is exactly what this poll
        // delivered regardless of which arm we are in.
        let read = buf.filled().len().saturating_sub(before);
        self.count.fetch_add(read as u64, Ordering::Relaxed);
        polled
    }
}

async fn serve_stream_workspace_files(
    s: ServerStateHandle,
    config: ChannelConfig,
    mut c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    // Shared with the counting reader so the tally outlives the unpack on
    // both arms. Bytes-at-failure is the number that separates "the upload
    // never started" from "the upload died three-quarters of the way in".
    let received = Arc::new(AtomicU64::new(0));
    let unpacked = unpack_workspace_files(&s, &config, &mut c, &received).await;
    // Compressed bytes off the wire, not the unpacked tree: it is the
    // figure a client-side upload size can be compared against directly.
    let bytes_received = received.load(Ordering::Relaxed);

    let outcome = match unpacked {
        Ok(()) => {
            tracing::info!(bytes_received, "workspace upload complete");
            Ok(())
        }
        Err(msg) => {
            tracing::warn!(bytes_received, error = %msg, "workspace upload failed");
            let _ = c.extended_data_bytes(1, msg.clone()).await;
            Err(ConnectionError::Internal(msg))
        }
    };
    let _ = c.close().await;
    outcome
}

async fn serve_stream_workspace_patches(
    s: ServerStateHandle,
    config: ChannelConfig,
    mut c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    let outcome = match unpack_workspace_patches(&s, &config, &mut c).await {
        Ok(()) => Ok(()),
        Err(msg) => {
            let _ = c.extended_data_bytes(1, msg.clone()).await;
            Err(ConnectionError::Internal(msg))
        }
    };
    let _ = c.close().await;
    outcome
}

/// Look up the session for an upload channel: pulls the session id
/// out of the channel env, resolves the live actor via the manager,
/// and returns its paths. Shared by both `WorkspaceFilesTarZst` and
/// `WorkspacePatchesTarZst`.
async fn upload_session_paths(
    s: &ServerStateHandle,
    config: &ChannelConfig,
) -> Result<crate::session::SessionPaths, String> {
    Ok(upload_session_handle(s, config).await?.1)
}

/// Same lookup as [`upload_session_paths`] but returns the session
/// handle too, so callers that need per-session serialization can
/// grab a lock without a second manager round-trip.
async fn upload_session_handle(
    s: &ServerStateHandle,
    config: &ChannelConfig,
) -> Result<(crate::session::SessionHandle, crate::session::SessionPaths), String> {
    let session_id_str = config
        .env_vars
        .get(crate::MINIMAL_SESSION_ID_ENV)
        .ok_or("missing env-var MINIMAL_SESSION_ID")?;
    let session_id =
        SessionId::parse_str(session_id_str).map_err(|e| format!("parsing session UUID: {e}"))?;

    let mngr = s.sessions_manager().await;
    let session_handle = mngr
        .get_session(SessionKeyPredicate::Id(session_id))
        .await
        .map_err(|e| format!("session UUID lookup failed: {e}"))?
        .ok_or("unknown session UUID")?;
    let paths = session_handle
        .paths()
        .await
        .map_err(|e| format!("session is gone: {e}"))?;
    Ok((session_handle, paths))
}

/// Unpacks the zstd-compressed tarball streamed over `c` into the
/// workspace directory of the session named by the channel environment,
/// tallying the wire bytes it consumes into `received`.
///
/// On failure, returns the human-readable message to relay back to the
/// client over the channel's extended-data stream.
async fn unpack_workspace_files(
    s: &ServerStateHandle,
    config: &ChannelConfig,
    c: &mut RuChannel<Msg>,
    received: &Arc<AtomicU64>,
) -> Result<(), String> {
    let paths = upload_session_paths(s, config).await?;
    // Emitted once the upload has a destination and before a single byte is
    // pulled, so a transfer that wedges mid-stream still leaves a record
    // saying which session it was for. Its pair is the complete/failed
    // record in the caller.
    tracing::info!("workspace upload started");

    let reader = async_compression::tokio::bufread::ZstdDecoder::new(tokio::io::BufReader::new(
        CountingReader {
            inner: c.make_reader(),
            count: Arc::clone(received),
        },
    ));
    async_tar::Archive::new(reader)
        .unpack(paths.working.as_utf8_path())
        .await
        .map_err(|e| format!("unpack failed: {e}"))?;

    Ok(())
}

/// Runs one dispatched RPC to completion, bracketing it with the pair of
/// records that let a reader reconstruct what the daemon did on a
/// connection from the log alone.
///
/// Start-and-finish rather than finish-only. Finish-only halves the volume
/// but cannot distinguish an RPC still in flight from one that was never
/// dispatched, and "started, never finished" is precisely the shape of a
/// hang — the case this logging exists to catch. Both records are emitted
/// inside the caller's `rpc` span, so each carries `rpc`, `trace_id` and
/// `span_id` from that span plus `conn`/`transport` from the enclosing
/// connection span, without repeating any of them as event fields.
async fn served(fut: impl Future<Output = Result<(), ConnectionError>>) {
    tracing::info!("rpc dispatched");
    let started = std::time::Instant::now();
    let outcome = fut.await;
    let duration_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Ok(()) => tracing::info!(outcome = "ok", duration_ms, "rpc served"),
        Err(e) => tracing::warn!(outcome = "err", duration_ms, error = %e, "rpc failed"),
    }
}

/// What distinguishes one tar-upload stream from another.
///
/// Everything else about unpacking — validation, staging, the atomic
/// swap, the marker — is identical across streams and lives in
/// [`unpack_tar_zst_into`]. Adding a stream means describing it here,
/// not writing a second unpacker: the entry guards are security
/// checks, and a second copy is a second place for a fix to miss.
struct UnpackTarget {
    /// Live directory the staged tree is swapped into.
    dir: std::path::PathBuf,
    /// Marker filename dropped after a successful swap. Preconditions
    /// in `FinalizeSession` read it, so it is written last.
    marker: &'static str,
    /// Ceiling on a single entry's *declared* size. Guards against a
    /// forged header driving `Vec::with_capacity` into an allocation
    /// failure, not against legitimate volume.
    max_entry_bytes: u64,
    /// Serializes the swap against another upload on the same stream
    /// and session.
    lock: Arc<tokio::sync::Mutex<()>>,
    /// Noun for error messages — "patch", "hook script".
    label: &'static str,
}

/// Unpack a zstd-compressed tarball streamed over `c` into
/// `target.dir`.
///
/// The unpack is **atomic**: entries land in a per-upload staging dir
/// first, then swap into place once the stream ends cleanly. A
/// mid-stream failure leaves the staging tree behind (removed on the
/// next run) but never pollutes the live directory.
///
/// Every entry is validated before a byte reaches disk. The client
/// already rejects absolute and `..` paths at the wire-schema level,
/// but the client is untrusted, so the same checks run again here —
/// a peer writing raw tar bytes bypasses every client-side layer.
///
/// Each entry's **permission bits** are reproduced on disk, masked to
/// the standard nine. That is what carries a patched script's exec bit
/// and a patched secret's `0600` into the session; ownership is not
/// carried at all — every file here belongs to the daemon, and the
/// sandbox's user namespace maps that to the session user.
///
/// On success, drops `target.marker` under `target.dir`. The write
/// order matters: the marker only appears once every entry is on disk,
/// which is what lets `FinalizeSession` treat its presence as proof
/// the upload completed.
#[tracing::instrument(level = "debug", skip_all, fields(stream = target.label))]
async fn unpack_tar_zst_into(target: UnpackTarget, c: &mut RuChannel<Msg>) -> Result<(), String> {
    use std::path::Path as StdPath;

    let UnpackTarget {
        dir,
        marker,
        max_entry_bytes,
        lock,
        label,
    } = target;

    // Per-upload unique staging path so two concurrent uploads for
    // the same session never share a staging tree. The nanosecond
    // clock is fine as a discriminator — the swap lock below
    // serializes the install, so we don't need a strong guarantee
    // against collisions, only against name reuse across the two
    // in-flight tasks.
    let staging_dir = {
        let mut d = dir.clone();
        let suffix = format!(
            ".upload.{}.tmp",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        let name = d
            .file_name()
            .map(|n| {
                let mut n = n.to_os_string();
                n.push(&suffix);
                n
            })
            .unwrap_or_else(|| format!("upload{suffix}").into());
        d.set_file_name(name);
        d
    };

    // Fresh directory. `remove_dir_all` first is defensive against
    // an earlier `SystemTime` collision — extremely unlikely, but
    // cheap to guard against.
    let _ = tokio::fs::remove_dir_all(&staging_dir).await;
    tokio::fs::create_dir_all(&staging_dir)
        .await
        .map_err(|e| format!("creating {label} staging dir: {e}"))?;

    // Zstd decode + tar walk + per-entry unpack. Tar itself is a
    // stream format so decoding entries is sequential, but writing
    // the entry bodies to disk is where the cost actually is (a
    // serial loop over `fs::write` capped at ~190 MB/s per entry).
    // We buffer each body in memory and hand the write off to a
    // spawned task, so up to N files land on disk in parallel. The
    // concurrency cap keeps memory bounded (bodies live only until
    // the write completes) and prevents saturating the runtime's
    // blocking pool.
    let reader = async_compression::tokio::bufread::ZstdDecoder::new(tokio::io::BufReader::new(
        c.make_reader(),
    ));
    let archive = async_tar::Archive::new(reader);
    // Manual iteration so we can reject `..` per-entry before any
    // bytes hit disk. `Archive::unpack` walks entries itself but
    // has no per-entry validation hook.
    use futures::StreamExt as _;
    use tokio::io::AsyncReadExt as _;
    let mut entries = archive
        .entries()
        .map_err(|e| format!("reading {label} tar entries: {e}"))?;
    let write_concurrency = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    // Byte-budget semaphore: each in-flight body reserves permits
    // proportional to its size, and can't reserve if the total
    // in-flight bytes would exceed `MAX_UNPACK_INFLIGHT_BYTES`. This
    // is *the* backpressure — reserved *before* the body read, so a
    // slow disk pumps back into the tar decoder (into the pipe,
    // into the SSH channel) instead of into RAM. The concurrency
    // count guard below is a secondary limit to keep the blocking
    // pool from getting saturated by many small entries. `Arc`ed so
    // the spawned write tasks own their permits.
    let byte_budget = Arc::new(tokio::sync::Semaphore::new(MAX_UNPACK_INFLIGHT_BYTES));
    // `JoinSet` (not `FuturesUnordered<JoinHandle>`) so we can
    // `abort_all` in-flight writes on any error return. Dropping a
    // `JoinHandle` only detaches the task — writes queued when we
    // fail would otherwise keep running under `staging_dir`,
    // racing the next upload's `remove_dir_all` at the top of this
    // function and burning blocking-pool slots for results nobody
    // reads.
    let mut inflight: tokio::task::JoinSet<Result<(), String>> = tokio::task::JoinSet::new();
    let loop_result: Result<(), String> = async {
        while let Some(entry) = entries.next().await {
            let mut entry = entry.map_err(|e| format!("reading {label} tar entry: {e}"))?;
            let entry_path = entry
                .path()
                .map_err(|e| format!("decoding entry path: {e}"))?
                .into_owned();
            if !safe_relative_path(&entry_path) {
                return Err(format!(
                    "{label} archive entry rejected: `{}` contains an absolute path or a \
                     `..` component",
                    entry_path.display()
                ));
            }
            // Reject an entry that would clobber the ready marker.
            // Marker + uploaded file would otherwise race, and for
            // patches `materialize_patches_into_home` would silently
            // copy the emptied marker into the sandbox home, zeroing
            // whatever the user had there.
            if entry_path == StdPath::new(marker) {
                return Err(format!(
                    "{label} archive entry rejected: `{}` collides with the daemon's \
                     ready-marker filename",
                    entry_path.display()
                ));
            }
            // Only regular files are unpacked. The client's uploader
            // (`TarZstArchive::add_file`) only ever emits
            // `EntryType::Regular` — symlink sources are read through
            // (their target's bytes get archived as a regular file,
            // dropping the link relation on purpose) and directory
            // sources fan out into per-file Regular entries. Every
            // other entry type is out of scope: we do not create
            // directories, symlinks, hardlinks, or device nodes from
            // an uploaded archive. Blindly running `tokio::fs::write`
            // for any of those would silently land an empty file at
            // that path — a directory entry would then break
            // `create_dir_all(parent)` for its children, and a
            // symlink entry would drop the link target on the floor.
            // Fail loudly instead.
            let entry_type = entry.header().entry_type();
            if !matches!(
                entry_type,
                async_tar::EntryType::Regular | async_tar::EntryType::Continuous
            ) {
                return Err(format!(
                    "{label} archive entry rejected: `{}` is {entry_type:?}; only regular \
                     files are supported",
                    entry_path.display(),
                ));
            }
            let entry_size = entry.header().size().unwrap_or(0);
            // The entry's permission bits, which the write below
            // reproduces on disk: a patched script has to stay
            // executable and a patched secret has to stay unreadable
            // to anyone else, and neither survives a hardcoded mode.
            //
            // Masked to the standard nine. setuid/setgid/sticky are
            // dropped rather than honoured — this header came off the
            // wire, so the daemon is not in a position to trust it with
            // a privilege bit, and `async_tar::Archive::unpack` (which
            // unpacks the workspace tree a few functions up) applies
            // exactly the same `& 0o777` for the same reason. A header
            // whose mode field doesn't parse falls back to 0o644, the
            // mode every entry landed as before this was read at all.
            let mode = entry.header().mode().unwrap_or(0o644) & 0o777;
            // Per-entry cap: refuses forged headers that would push
            // `Vec::with_capacity` into an allocation panic or OOM
            // (allocator abort → whole daemon down) before we ever
            // reserve budget.
            if entry_size > max_entry_bytes {
                return Err(format!(
                    "{label} archive entry rejected: `{}` declares {entry_size} bytes, \
                     exceeds the {max_entry_bytes}-byte per-entry cap",
                    entry_path.display()
                ));
            }

            // Concurrency backpressure: bound the number of writes
            // in flight before we spawn the next one. Kept alongside
            // the byte budget below so a batch of tiny entries can't
            // saturate the blocking pool.
            while inflight.len() >= write_concurrency {
                match inflight.join_next().await {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(e))) => return Err(e),
                    Some(Err(join_err)) => {
                        return Err(format!("write task panicked: {join_err}"));
                    }
                    None => break,
                }
            }

            // Byte-budget backpressure: reserve permits equal to
            // the entry size *before* the body read, so a stalled
            // fs::write can't let bodies pile up in RAM ahead of
            // it. Zero-byte entries take one permit — semaphores
            // can't acquire zero, but the practical peak is still
            // dominated by real-body permits.
            let permit_bytes = std::cmp::max(entry_size as usize, 1);
            let permit = Arc::clone(&byte_budget)
                .acquire_many_owned(permit_bytes as u32)
                .await
                .map_err(|e| format!("byte-budget semaphore closed: {e}"))?;

            let mut body = Vec::with_capacity(entry_size as usize);
            entry
                .read_to_end(&mut body)
                .await
                .map_err(|e| format!("reading body of `{}`: {e}", entry_path.display()))?;

            let dest = staging_dir.join(&entry_path);
            let path_display = entry_path.display().to_string();
            inflight.spawn(async move {
                // `tokio::fs::OpenOptions::mode` is inherent on unix,
                // so no `OpenOptionsExt` import is needed for it.
                use std::os::unix::fs::PermissionsExt as _;
                use tokio::io::AsyncWriteExt as _;

                if let Some(parent) = dest.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .map_err(|e| format!("creating parent dir for `{path_display}`: {e}"))?;
                }
                // Create *with* the mode rather than writing and then
                // widening: `.mode()` is masked by the daemon's umask,
                // so the file is never briefly more permissive than the
                // entry asked for. The explicit `set_permissions` below
                // then takes it the rest of the way, since that same
                // umask would otherwise quietly clear bits the entry
                // does ask for.
                let mut file = tokio::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(mode)
                    .open(&dest)
                    .await
                    .map_err(|e| format!("creating `{path_display}`: {e}"))?;
                file.write_all(&body)
                    .await
                    .map_err(|e| format!("writing `{path_display}`: {e}"))?;
                // A `tokio::fs::File` completes its writes in the
                // background; dropping one unflushed truncates it
                // silently.
                file.flush()
                    .await
                    .map_err(|e| format!("flushing `{path_display}`: {e}"))?;
                // Through the handle, not the path: the mode lands on
                // the file we just wrote rather than on whatever a
                // concurrent unpack may have swapped in at that path.
                file.set_permissions(std::fs::Permissions::from_mode(mode))
                    .await
                    .map_err(|e| format!("setting mode on `{path_display}`: {e}"))?;
                // Explicit drop keeps the permit alive across the
                // write so the byte budget only frees up after the
                // buffer is genuinely gone.
                drop(body);
                drop(permit);
                Ok::<_, String>(())
            });
        }
        // Drain any tasks still in flight.
        while let Some(res) = inflight.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(join_err) if join_err.is_cancelled() => {}
                Err(join_err) => return Err(format!("write task panicked: {join_err}")),
            }
        }
        Ok(())
    }
    .await;

    if loop_result.is_err() {
        // Cancel and drain every straggler write before returning.
        // `abort_all` only marks tasks; the drain awaits each
        // cancellation so no fs::write outlives this function and
        // races the next upload's `remove_dir_all`.
        inflight.abort_all();
        while inflight.join_next().await.is_some() {}
    }
    loop_result?;

    // Serialize the swap + marker-write against any other in-flight
    // upload on this stream for this session. Two concurrent uploads
    // would otherwise race on the live dir — one's `RENAME_EXCHANGE`
    // could observe an unexpected mid-swap state, or the marker could
    // get written pointing at the wrong upload's contents. The staging
    // phase above ran without the lock (all writes went to a per-upload
    // unique dir), so we only pay the serialization cost across the
    // seconds-of-work install step, not the minutes-of-work unpack.
    let _swap_guard = lock.lock_owned().await;

    // Install the new tree. Two shapes depending on whether a
    // prior tree exists:
    //
    // 1. **Prior tree present** — `renameat2(RENAME_EXCHANGE)` swaps
    //    the staging tree and the live tree atomically. At every
    //    instant an on-disk lookup sees exactly one of the two
    //    trees, and each carries a valid marker (the old one from
    //    the prior successful unpack, the new one written below).
    //    A `FinalizeSession` racing the swap can't observe a gap
    //    where the dir doesn't exist or where the marker is absent,
    //    only "old contents + old marker" or "new contents + new
    //    marker." We swap the trees first (contents on disk), then
    //    delete the old contents that ended up under `staging_dir`
    //    after the swap, then write the new marker over the old one.
    // 2. **First install** — no prior tree, so `RENAME_EXCHANGE`
    //    fails with `ENOENT`. Plain `rename` is atomic in this
    //    case (nothing to displace), so we fall through to it.
    //
    // Go through `common::renameat2` (a direct `renameat2(2)`
    // syscall wrapper) rather than `nix::fcntl::renameat2`: nix
    // gates that wrapper behind `target_env = "gnu"`, but `minimald`
    // is also cross-compiled for static musl (the guest initramfs),
    // where the nix item is configured out.
    let swap_result = tokio::task::spawn_blocking({
        let staging_dir = staging_dir.clone();
        let dir = dir.clone();
        move || {
            common::renameat2::renameat2_cwd(&staging_dir, &dir, common::renameat2::RENAME_EXCHANGE)
        }
    })
    .await
    .map_err(|e| format!("atomic-swap task panicked: {e}"))?;
    match swap_result {
        Ok(()) => {
            // `staging_dir` now holds the previous tree
            // (post-exchange). Drop it — a partial cleanup here is
            // fine; the next unpack's leading `remove_dir_all`
            // covers it.
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            // No prior tree — the `RENAME_EXCHANGE` requires both
            // sides to exist. Plain rename is atomic when the
            // destination doesn't exist yet.
            tokio::fs::rename(&staging_dir, &dir)
                .await
                .map_err(|e| format!("swapping {label} dir into place: {e}"))?;
        }
        Err(e) => {
            return Err(format!("atomic-swap of {label} dir failed: {e}"));
        }
    }

    // Marker last, so the newly-swapped contents can never coexist
    // with a stale marker. If we crash between the swap and this
    // write, the next upload's swap replaces the whole tree and
    // rewrites the marker — FinalizeSession is what fails safe, not
    // this handler.
    let marker_path = dir.join(StdPath::new(marker));
    tokio::fs::write(&marker_path, b"")
        .await
        .map_err(|e| format!("writing {label}-ready marker: {e}"))?;

    Ok(())
}

/// Unpacks the composition-patches tarball streamed over `c` into
/// `<workspace>/patches/`, keyed by each patch's sandbox-home-relative
/// destination. See [`unpack_tar_zst_into`] for the mechanics.
async fn unpack_workspace_patches(
    s: &ServerStateHandle,
    config: &ChannelConfig,
    c: &mut RuChannel<Msg>,
) -> Result<(), String> {
    let (session_handle, paths) = upload_session_handle(s, config).await?;
    let lock = session_handle
        .patches_upload_lock()
        .await
        .map_err(|e| format!("session is gone: {e}"))?;
    unpack_tar_zst_into(
        UnpackTarget {
            dir: paths.patches.as_utf8_path().as_std_path().to_path_buf(),
            marker: PATCHES_READY_MARKER,
            max_entry_bytes: MAX_PATCH_ENTRY_BYTES,
            lock,
            label: "patch",
        },
        c,
    )
    .await
}

/// Unpacks the external-hook-scripts tarball streamed over `c` into
/// `<workspace>/hooks/`.
///
/// Entry paths are the staged paths
/// [`staged_script_path`](sessions::core::lifecyclehook::staged_script_path)
/// produced on the client; the daemon re-derives the same paths from
/// the composition when it goes looking for a script, so nothing here
/// needs a manifest.
async fn unpack_workspace_hook_scripts(
    s: &ServerStateHandle,
    config: &ChannelConfig,
    c: &mut RuChannel<Msg>,
) -> Result<(), String> {
    let (session_handle, paths) = upload_session_handle(s, config).await?;
    let lock = session_handle
        .hook_scripts_upload_lock()
        .await
        .map_err(|e| format!("session is gone: {e}"))?;
    unpack_tar_zst_into(
        UnpackTarget {
            dir: paths.hooks.as_utf8_path().as_std_path().to_path_buf(),
            marker: HOOKS_READY_MARKER,
            max_entry_bytes: MAX_HOOK_SCRIPT_BYTES,
            lock,
            label: "hook script",
        },
        c,
    )
    .await
}
async fn serve_stream_workspace_hook_scripts(
    s: ServerStateHandle,
    config: ChannelConfig,
    mut c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    let outcome = match unpack_workspace_hook_scripts(&s, &config, &mut c).await {
        Ok(()) => Ok(()),
        Err(msg) => {
            let _ = c.extended_data_bytes(1, msg.clone()).await;
            Err(ConnectionError::Internal(msg))
        }
    };
    let _ = c.close().await;
    outcome
}

/// Returns true if `p` is a relative path with no `..` components.
/// Enforced on every wire-supplied archive entry name.
fn safe_relative_path(p: &std::path::Path) -> bool {
    if p.is_absolute() {
        return false;
    }
    !p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

/// Handles an RPC going over an SSH subsystem channel.
///
/// This method takes ownership of the ssh channel, including
/// reading and writing the request/response respectively, as well
/// as indicating if the subsystem request was successful (RPC known)
/// or not (RPC not known, channel request fails).
///
/// The caller should not hold any locks, neither to the Connection nor
/// the Server.
pub async fn handle_ssh_rpc(
    s: ServerStateHandle,
    c: ConnectionHandle,
    name: &str,
    id: ChannelId,
    session: &mut Session,
) -> Result<(), ConnectionError> {
    // Take the channel from connection state if its a known RPC.
    // `ssh_username` is read out under the same lock so `serve_*`
    // handlers that need the authenticated user (CreateSession) don't
    // have to re-lock.
    let res = match name {
        GetVersion::NAME
        | ListSessions::NAME
        | GetSessionRecord::NAME
        | CreateSession::NAME
        | minimald_rpc::ConfigureLoadout::NAME
        | SubmitVerdict::NAME
        | FinalizeSession::NAME
        | RenameSession::NAME
        | DestroySession::NAME
        | Shutdown::NAME
        | AbortSession::NAME
        | GetSessionPolicy::NAME
        | GetEffectiveSessionPolicy::NAME
        | minimald_rpc::GetLiveIngress::NAME
        | minimald_rpc::GetSessionRuntimeFacts::NAME
        | minimald_rpc::GetSessionHooks::NAME
        | SessionDelta::NAME
        | GetSessionScreen::NAME
        | GetMeshStatus::NAME
        | STREAM_WORKSPACE_FILES
        | STREAM_WORKSPACE_PATCHES
        | STREAM_WORKSPACE_HOOK_SCRIPTS
        | minimald_rpc::DIAG_BUNDLE_SUBSYSTEM
        | minimald_rpc::CLEAN_CACHE_SUBSYSTEM => {
            let mut conn_lock = c.lock().await;
            let c_hnd = match conn_lock.take(id) {
                None => {
                    session.channel_failure(id)?;
                    return Ok(());
                }
                Some((channel, config)) => (channel, config),
            };
            let ssh_username = conn_lock.ssh_username.clone();
            drop(conn_lock);
            session.channel_success(id)?;
            Some((c_hnd, ssh_username))
        }
        _ => {
            session.channel_failure(id)?;
            None
        }
    };
    let ((channel, config), ssh_username) = match res {
        Some(v) => v,
        None => return Ok(()),
    };

    // Adopt the client's propagated trace context into this dispatch's span:
    // same trace id, fresh span id, the client's span as parent. Absent or
    // malformed values mint fresh — propagation is a diagnostic aid and must
    // never fail a request. Every record the handler emits carries the ids,
    // so one trace_id grep joins the CLI's log with this daemon's.
    use minimald_rpc::trace::{TRACEPARENT_ENV, TraceContext};
    use tracing::Instrument as _;
    let client_ctx = config
        .env_vars
        .get(TRACEPARENT_ENV)
        .and_then(|v| TraceContext::parse_traceparent(v));
    let ctx = client_ctx
        .as_ref()
        .map(TraceContext::child)
        .unwrap_or_else(TraceContext::mint);
    let span = tracing::info_span!(
        "rpc",
        rpc = name,
        trace_id = %ctx.trace_id_hex(),
        span_id = %ctx.span_id_hex(),
        parent_span_id = tracing::field::Empty,
    );
    if let Some(client_ctx) = &client_ctx {
        span.record(
            "parent_span_id",
            tracing::field::display(client_ctx.span_id_hex()),
        );
    }

    // Handle the named RPC (fire-and-forget; join handles are discarded).
    // `served` brackets each handler with its dispatch/outcome records —
    // the span alone emits nothing, so without them the ids minted above
    // never reach the log.
    macro_rules! serve {
        ($fut:expr) => {
            drop(spawn(served($fut).instrument(span.clone())))
        };
    }
    match name {
        GetVersion::NAME => serve!(serve_get_version(channel)),
        ListSessions::NAME => serve!(serve_list_sessions(s, channel)),
        GetSessionRecord::NAME => serve!(serve_get_session_record(s, channel)),
        CreateSession::NAME => serve!(serve_create_session(s, c.clone(), channel, ssh_username)),
        minimald_rpc::ConfigureLoadout::NAME => serve!(serve_configure_loadout(s, channel)),
        SubmitVerdict::NAME => serve!(serve_submit_verdict(s, channel)),
        FinalizeSession::NAME => serve!(serve_finalize_session(s, channel)),
        RenameSession::NAME => serve!(serve_rename_session(s, channel)),
        DestroySession::NAME => serve!(serve_destroy_session(s, channel)),
        Shutdown::NAME => serve!(serve_shutdown(s, channel)),
        AbortSession::NAME => serve!(serve_abort_session(s, channel)),
        GetSessionPolicy::NAME => serve!(serve_get_session_policy(s, channel)),
        GetEffectiveSessionPolicy::NAME => {
            serve!(serve_get_effective_session_policy(s, channel))
        }
        minimald_rpc::GetLiveIngress::NAME => {
            serve!(serve_get_live_ingress(s, channel))
        }
        minimald_rpc::GetSessionRuntimeFacts::NAME => {
            serve!(serve_get_session_runtime_facts(s, channel))
        }
        minimald_rpc::GetSessionHooks::NAME => serve!(serve_get_session_hooks(s, channel)),
        SessionDelta::NAME => serve!(serve_session_delta(s, channel)),
        GetSessionScreen::NAME => serve!(serve_get_session_screen(s, channel)),
        GetMeshStatus::NAME => serve!(serve_get_mesh_status(s, channel)),
        STREAM_WORKSPACE_FILES => serve!(serve_stream_workspace_files(s, config, channel)),
        STREAM_WORKSPACE_PATCHES => serve!(serve_stream_workspace_patches(s, config, channel)),
        STREAM_WORKSPACE_HOOK_SCRIPTS => {
            serve!(serve_stream_workspace_hook_scripts(s, config, channel))
        }
        minimald_rpc::DIAG_BUNDLE_SUBSYSTEM => {
            serve!(crate::diag::serve_stream_diag_bundle(s, config, channel))
        }
        minimald_rpc::CLEAN_CACHE_SUBSYSTEM => serve!(serve_clean_cache(s, channel)),
        _ => unreachable!(),
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use minimald_rpc::{
        CreateSession, CreateSessionRequest, DestroySessionRequest, EffectiveEgress,
        EffectiveSessionPolicy, EgressPolicy, GetEffectiveSessionPolicy,
        GetEffectiveSessionPolicyRequest, GetSessionPolicy, GetSessionPolicyRequest, IngressPolicy,
        IpProto, PortMapping, RenameSessionRequest, SessionPolicy, Shutdown, ShutdownRequest,
        ShutdownResponse,
    };
    use paths::HostAbsPath;
    use sessions::{NetworkMode, SessionId};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::MINIMAL_SESSION_ID_ENV;
    use crate::session_host::PROBE_TEST_MUTEX;
    use crate::sessions::SessionKeyPredicate;
    use crate::test_harness::{TestClient, TestServer};

    /// Serializes `(path, contents)` entries into a tar archive and
    /// zstd-compresses it, producing exactly the wire format that
    /// [`serve_stream_workspace_files`] decodes.
    async fn tar_zst(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = async_tar::Builder::new(Vec::new());
        for (path, contents) in entries {
            let mut header = async_tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            tar.append_data(&mut header, path, *contents).await.unwrap();
        }
        let tar_bytes = tar.into_inner().await.unwrap();

        let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
        encoder.write_all(&tar_bytes).await.unwrap();
        encoder.shutdown().await.unwrap();
        encoder.into_inner()
    }

    use crate::test_harness::create_session_req as req;

    /// Creates a session through the public RPCs and returns its id, ready
    /// to attach.
    async fn fresh_session(client: &mut TestClient) -> SessionId {
        crate::test_harness::create_configured_session(client, "stream-test", "/tmp").await
    }

    #[tokio::test]
    async fn stream_workspace_files_unpacks_tarball_into_workspace() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst(&[
            ("hello.txt", b"hello world\n"),
            ("dir/nested.txt", b"nested contents"),
        ])
        .await;

        let channel = client
            .open_subsystem(
                STREAM_WORKSPACE_FILES,
                &[(MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
            )
            .await;
        let mut stream = channel.into_stream();
        stream.write_all(&payload).await.unwrap();
        // Half-close so the server's decoder sees EOF; then read to the
        // server's channel close so the unpack has completed on-disk
        // before we assert.
        stream.shutdown().await.unwrap();
        let mut trailing = Vec::new();
        stream.read_to_end(&mut trailing).await.unwrap();

        let mngr = server.state.sessions_manager().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("freshly-created session should be retrievable");
        let paths = handle.paths().await.unwrap();

        assert_eq!(
            tokio::fs::read(paths.working.as_utf8_path().join("hello.txt"))
                .await
                .unwrap(),
            b"hello world\n",
        );
        assert_eq!(
            tokio::fs::read(paths.working.as_utf8_path().join("dir/nested.txt"))
                .await
                .unwrap(),
            b"nested contents",
        );
    }

    /// Drives the `CleanCache` subsystem to completion, returning every update
    /// it streamed back in order.
    async fn clean_cache(client: &mut TestClient, req: CleanCacheRequest) -> Vec<CleanCacheUpdate> {
        let channel = client
            .open_subsystem(minimald_rpc::CLEAN_CACHE_SUBSYSTEM, &[])
            .await;
        let mut stream = channel.into_stream();
        stream
            .write_all(&serde_json_lenient::to_vec(&req).unwrap())
            .await
            .unwrap();
        // Half-close: the handler reads the request until the client is done.
        stream.shutdown().await.unwrap();

        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        String::from_utf8(body)
            .unwrap()
            .lines()
            .map(|line| serde_json_lenient::from_str(line).expect("each line is an update"))
            .collect()
    }

    /// The clean runs through the daemon's actor and reports back: a line per
    /// thing reclaimed, then exactly one terminal `Done` carrying the totals.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clean_cache_streams_progress_then_a_terminal_done() {
        use lcache::{EntryMeta, FileSystem, MetaInner};
        use std::io::Write as _;

        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // Two cold entries — nothing has read them, and no session needs them.
        let cache = server.state.daemon_context().await.local_cache();
        for byte in [1u8, 2] {
            let w = cache
                .write_dir(&common::SpecHash::from_bytes([byte; 32]))
                .unwrap();
            w.open_write("f").unwrap().write_all(b"x").unwrap();
            w.finalize(EntryMeta {
                inner: MetaInner::Spec(format!("pkg-{byte}")),
                fetched: false,
                ..Default::default()
            })
            .unwrap();
        }

        // `older_than_secs` of 1 rather than the daemon default, so entries
        // written a moment ago are in scope.
        let updates = clean_cache(
            &mut client,
            CleanCacheRequest::default().with_older_than_secs(1),
        )
        .await;

        let (terminal, progress) = updates.split_last().expect("at least a terminal update");
        assert_eq!(
            *terminal,
            CleanCacheUpdate::Done {
                entries: 2,
                dirs: 0
            }
        );
        assert_eq!(
            progress.len(),
            2,
            "one line per reclaimed entry: {progress:?}"
        );
        assert!(
            progress.iter().all(|u| matches!(u, CleanCacheUpdate::Removed { detail } if detail.starts_with("Deleting package pkg-"))),
            "progress should name what went: {progress:?}",
        );
        assert_eq!(cache.iter_entries().count(), 0);
    }

    /// An empty cache still terminates the stream properly — a client can
    /// always read to a terminal update.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clean_cache_with_nothing_to_do_still_terminates() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let updates = clean_cache(&mut client, CleanCacheRequest::default()).await;

        assert_eq!(
            updates,
            vec![CleanCacheUpdate::Done {
                entries: 0,
                dirs: 0
            }]
        );
    }

    #[tokio::test]
    async fn stream_workspace_files_rejects_unknown_session() {
        use russh::ChannelMsg;

        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // A well-formed but unknown session id: the handler should report
        // an error on stderr (ssh extended data) rather than unpacking.
        let mut channel = client
            .open_subsystem(
                STREAM_WORKSPACE_FILES,
                &[(MINIMAL_SESSION_ID_ENV, &SessionId::nil().to_string())],
            )
            .await;
        channel.eof().await.unwrap();

        let mut stderr = Vec::new();
        while let Some(msg) = channel.wait().await {
            if let ChannelMsg::ExtendedData { data, ext: 1 } = msg {
                stderr.extend_from_slice(&data);
            }
        }

        assert!(
            String::from_utf8_lossy(&stderr).contains("unknown session"),
            "expected an unknown-session error on stderr, got {:?}",
            String::from_utf8_lossy(&stderr),
        );
    }

    /// The upload's `bytes_received` field is only worth logging if it is
    /// exact, so pull a payload through in many small polls and check the
    /// tally accumulates across them rather than recording the last read.
    #[tokio::test]
    async fn counting_reader_tallies_every_byte_pulled_through() {
        let payload: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
        let count = Arc::new(AtomicU64::new(0));
        let mut sunk = Vec::new();

        let read = tokio::io::copy(
            &mut CountingReader {
                inner: payload.as_slice(),
                count: Arc::clone(&count),
            },
            &mut sunk,
        )
        .await
        .unwrap();

        assert_eq!(sunk, payload);
        assert_eq!(read, payload.len() as u64);
        assert_eq!(count.load(Ordering::Relaxed), payload.len() as u64);
    }

    /// `WorkspacePatchesTarZst` unpacks each entry under
    /// `<workspace>/patches/<archive-path>` and drops the ready
    /// marker on success. Guards the write ordering
    /// (staging-dir → atomic rename → marker) that FinalizeSession
    /// depends on.
    #[tokio::test]
    async fn stream_workspace_patches_unpacks_and_writes_marker() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst(&[
            (".config/helix/config.toml", b"theme = 'nord'\n"),
            (".config/other.toml", b"key = 'value'\n"),
        ])
        .await;

        let channel = client
            .open_subsystem(
                STREAM_WORKSPACE_PATCHES,
                &[(MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
            )
            .await;
        let mut stream = channel.into_stream();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut trailing = Vec::new();
        stream.read_to_end(&mut trailing).await.unwrap();

        let mngr = server.state.sessions_manager().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("session should be retrievable");
        let paths = handle.paths().await.unwrap();
        let patches = paths.patches.as_utf8_path();

        assert_eq!(
            tokio::fs::read(patches.join(".config/helix/config.toml"))
                .await
                .unwrap(),
            b"theme = 'nord'\n",
        );
        assert_eq!(
            tokio::fs::read(patches.join(".config/other.toml"))
                .await
                .unwrap(),
            b"key = 'value'\n",
        );
        assert!(
            tokio::fs::try_exists(patches.join(PATCHES_READY_MARKER))
                .await
                .unwrap(),
            "patches-ready marker must be written on successful unpack",
        );
    }

    /// Build a tar+zstd archive whose entries carry the modes given,
    /// rather than `tar_zst`'s uniform `0o644` — the shape the patches
    /// uploader produces once it stopped flattening the source's mode.
    async fn tar_zst_with_modes(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut tar = async_tar::Builder::new(Vec::new());
        for (path, contents, mode) in entries {
            let mut header = async_tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(*mode);
            tar.append_data(&mut header, path, *contents).await.unwrap();
        }
        let tar_bytes = tar.into_inner().await.unwrap();
        let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
        encoder.write_all(&tar_bytes).await.unwrap();
        encoder.shutdown().await.unwrap();
        encoder.into_inner()
    }

    /// An entry's permission bits reach the staged file, so a patched
    /// script stays executable and a patched secret stays private. The
    /// `0o600` case is the one that proves the mode is applied
    /// explicitly rather than left to the daemon's umask, which would
    /// have produced `0o644` from the same header.
    ///
    /// setuid is masked off: the header arrives over the wire, so a
    /// peer must not be able to ask the daemon to create a setuid file
    /// in a session's tree. (`async_tar::Archive::unpack`, which
    /// handles the workspace stream, drops it for the same reason.)
    #[tokio::test]
    async fn stream_workspace_patches_preserves_entry_modes() {
        use std::os::unix::fs::PermissionsExt as _;

        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst_with_modes(&[
            (".local/bin/tool", b"#!/bin/sh\necho hi\n", 0o755),
            (".config/secret.toml", b"token = 'hunter2'\n", 0o600),
            (".local/bin/suid", b"#!/bin/sh\n", 0o4755),
        ])
        .await;

        let channel = client
            .open_subsystem(
                STREAM_WORKSPACE_PATCHES,
                &[(MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
            )
            .await;
        let mut stream = channel.into_stream();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut trailing = Vec::new();
        stream.read_to_end(&mut trailing).await.unwrap();

        let mngr = server.state.sessions_manager().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("session should be retrievable");
        let paths = handle.paths().await.unwrap();
        let patches = paths.patches.as_utf8_path();

        let mode_of = async |rel: &str| {
            tokio::fs::metadata(patches.join(rel))
                .await
                .unwrap_or_else(|e| panic!("staged patch `{rel}` should exist: {e}"))
                .permissions()
                .mode()
                & 0o7777
        };

        assert_eq!(mode_of(".local/bin/tool").await, 0o755, "exec bit survives");
        assert_eq!(
            mode_of(".config/secret.toml").await,
            0o600,
            "a private mode is applied exactly, not widened by the umask",
        );
        assert_eq!(
            mode_of(".local/bin/suid").await,
            0o755,
            "setuid is masked off, the rest of the mode is kept",
        );
    }

    /// Build a tar+zstd archive with full control over each entry's
    /// type and declared size, so tests can produce the malformed
    /// shapes a hostile peer would hand-craft — `tar_zst` can only
    /// build well-formed regular-file entries.
    ///
    /// `declared_size` overrides the header's size field without
    /// changing the body, which is how the forged-header case is
    /// reproduced.
    async fn tar_zst_raw(entries: &[(&str, &[u8], async_tar::EntryType, Option<u64>)]) -> Vec<u8> {
        let mut tar = async_tar::Builder::new(Vec::new());
        for (path, contents, entry_type, declared_size) in entries {
            let mut header = async_tar::Header::new_gnu();
            header.set_size(declared_size.unwrap_or(contents.len() as u64));
            header.set_mode(0o644);
            header.set_entry_type(*entry_type);
            tar.append_data(&mut header, path, *contents).await.unwrap();
        }
        let tar_bytes = tar.into_inner().await.unwrap();
        let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
        encoder.write_all(&tar_bytes).await.unwrap();
        encoder.shutdown().await.unwrap();
        encoder.into_inner()
    }

    /// Build a tar+zstd archive whose entry name is written straight
    /// into the header's raw name field, bypassing the path validation
    /// `Builder::append_data` performs.
    ///
    /// This is the only way to produce the archive shape the daemon's
    /// traversal guard exists for: `async_tar`'s builder refuses to
    /// *construct* a `..` entry, so a well-behaved client cannot make
    /// one — but a hostile peer writing tar bytes by hand can, and that
    /// is the case the guard has to catch.
    async fn tar_zst_forged_name(name: &[u8], contents: &[u8]) -> Vec<u8> {
        let mut header = async_tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(async_tar::EntryType::Regular);
        // Raw name write: `set_path` would reject or normalize this.
        {
            let gnu = header.as_gnu_mut().expect("new_gnu produces a GNU header");
            gnu.name[..name.len()].copy_from_slice(name);
        }
        header.set_cksum();

        let mut tar = async_tar::Builder::new(Vec::new());
        tar.append(&header, contents).await.unwrap();
        let tar_bytes = tar.into_inner().await.unwrap();

        let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
        encoder.write_all(&tar_bytes).await.unwrap();
        encoder.shutdown().await.unwrap();
        encoder.into_inner()
    }

    /// Push `payload` through `subsystem` for `session_id` and return
    /// whatever the daemon relayed on stderr — empty on success. Keeps
    /// the channel (rather than `into_stream`) so extended data stays
    /// readable, which is how a rejection is signalled.
    async fn upload_and_collect_stderr(
        client: &mut TestClient,
        subsystem: &str,
        session_id: SessionId,
        payload: &[u8],
    ) -> String {
        use russh::ChannelMsg;
        let mut channel = client
            .open_subsystem(
                subsystem,
                &[(MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
            )
            .await;
        channel.data(payload).await.unwrap();
        channel.eof().await.unwrap();
        let mut stderr = Vec::new();
        while let Some(msg) = channel.wait().await {
            if let ChannelMsg::ExtendedData { data, ext: 1 } = msg {
                stderr.extend_from_slice(&data);
            }
        }
        String::from_utf8_lossy(&stderr).into_owned()
    }

    /// Resolve a session's staged-patches and staged-hooks dirs.
    async fn staged_dirs(
        server: &TestServer,
        session_id: SessionId,
    ) -> (camino::Utf8PathBuf, camino::Utf8PathBuf) {
        let mngr = server.state.sessions_manager().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("session should be retrievable");
        let paths = handle.paths().await.unwrap();
        (
            paths.patches.as_utf8_path().to_owned(),
            paths.hooks.as_utf8_path().to_owned(),
        )
    }

    /// A `..` entry is refused end-to-end, not merely by the
    /// `safe_relative_path` unit above: the guard has to actually be
    /// wired into the unpack loop, before any byte reaches disk.
    #[tokio::test]
    async fn stream_workspace_patches_rejects_traversal_end_to_end() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst_forged_name(b"../escape.toml", b"pwned\n").await;
        let stderr =
            upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &payload)
                .await;

        assert!(
            stderr.contains("`..`") || stderr.contains("absolute path"),
            "expected a traversal rejection, got: {stderr:?}",
        );
        let (patches, _) = staged_dirs(&server, session_id).await;
        assert!(
            !tokio::fs::try_exists(patches.join(PATCHES_READY_MARKER))
                .await
                .unwrap_or(false),
            "a rejected upload must not leave a ready marker",
        );
    }

    /// An entry named exactly like the ready marker is refused: it
    /// would otherwise be copied into the sandbox home by
    /// `materialize_patches_into_home`, zeroing whatever the user had
    /// at that path.
    #[tokio::test]
    async fn stream_workspace_patches_rejects_marker_collision() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst(&[(PATCHES_READY_MARKER, b"")]).await;
        let stderr =
            upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &payload)
                .await;

        assert!(
            stderr.contains("ready-marker"),
            "expected a marker-collision rejection, got: {stderr:?}",
        );
    }

    /// Only regular files are unpacked. A directory entry would
    /// otherwise be written as an empty *file*, which then breaks
    /// `create_dir_all` for anything nested beneath it.
    #[tokio::test]
    async fn stream_workspace_patches_rejects_non_regular_entry() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst_raw(&[("adir", b"", async_tar::EntryType::Directory, None)]).await;
        let stderr =
            upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &payload)
                .await;

        assert!(
            stderr.contains("only regular files"),
            "expected a non-regular-entry rejection, got: {stderr:?}",
        );
    }

    /// A forged header declaring more bytes than the per-entry cap is
    /// refused on the header alone, before the body is read — the
    /// check that stops `Vec::with_capacity` being driven into an
    /// allocation failure.
    #[tokio::test]
    async fn stream_workspace_patches_rejects_oversize_declared_entry() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst_raw(&[(
            "big.toml",
            b"small body",
            async_tar::EntryType::Regular,
            Some(MAX_PATCH_ENTRY_BYTES + 1),
        )])
        .await;
        let stderr =
            upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &payload)
                .await;

        assert!(
            stderr.contains("per-entry cap"),
            "expected an oversize rejection, got: {stderr:?}",
        );
    }

    /// A second upload replaces the first tree wholesale rather than
    /// merging into it, and the marker survives. Exercises both swap
    /// branches: the first upload takes the plain-rename path (no
    /// prior tree), the second takes `RENAME_EXCHANGE`.
    #[tokio::test]
    async fn stream_workspace_patches_second_upload_replaces_the_tree() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let first = tar_zst(&[("only-in-first.toml", b"a\n")]).await;
        assert_eq!(
            upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &first)
                .await,
            "",
        );
        let second = tar_zst(&[("only-in-second.toml", b"b\n")]).await;
        assert_eq!(
            upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &second)
                .await,
            "",
        );

        let (patches, _) = staged_dirs(&server, session_id).await;
        assert!(
            tokio::fs::try_exists(patches.join("only-in-second.toml"))
                .await
                .unwrap(),
            "the second upload's contents must be present",
        );
        assert!(
            !tokio::fs::try_exists(patches.join("only-in-first.toml"))
                .await
                .unwrap(),
            "the first upload's contents must be gone, not merged",
        );
        assert!(
            tokio::fs::try_exists(patches.join(PATCHES_READY_MARKER))
                .await
                .unwrap(),
            "the marker must survive the swap",
        );
    }

    // -- hook scripts ---------------------------------------------------

    /// The hook-script stream unpacks under `<workspace>/hooks/` at the
    /// staged path the client derived, and drops its own ready marker.
    #[tokio::test]
    async fn stream_workspace_hook_scripts_unpacks_and_writes_marker() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst(&[
            ("loadout/dev/activate.sh", b"echo hi\n"),
            ("project/scripts/setup.sh", b"echo setup\n"),
        ])
        .await;
        let stderr = upload_and_collect_stderr(
            &mut client,
            STREAM_WORKSPACE_HOOK_SCRIPTS,
            session_id,
            &payload,
        )
        .await;
        assert_eq!(stderr, "", "upload should succeed");

        let (_, hooks) = staged_dirs(&server, session_id).await;
        assert_eq!(
            tokio::fs::read(hooks.join("loadout/dev/activate.sh"))
                .await
                .unwrap(),
            b"echo hi\n",
        );
        assert_eq!(
            tokio::fs::read(hooks.join("project/scripts/setup.sh"))
                .await
                .unwrap(),
            b"echo setup\n",
        );
        assert!(
            tokio::fs::try_exists(hooks.join(HOOKS_READY_MARKER))
                .await
                .unwrap(),
            "hooks-ready marker must be written on successful unpack",
        );
    }

    /// The hook-script stream enforces the same entry guards as the
    /// patch stream. Parameterized over the malformed shapes so the two
    /// paths can't drift in what they refuse.
    #[tokio::test]
    async fn stream_workspace_hook_scripts_rejects_malformed_entries() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "`..`",
                tar_zst_forged_name(b"../escape.sh", b"pwned\n").await,
            ),
            ("ready-marker", tar_zst(&[(HOOKS_READY_MARKER, b"")]).await),
            (
                "only regular files",
                tar_zst_raw(&[("adir", b"", async_tar::EntryType::Directory, None)]).await,
            ),
            (
                "per-entry cap",
                tar_zst_raw(&[(
                    "big.sh",
                    b"small",
                    async_tar::EntryType::Regular,
                    Some(MAX_HOOK_SCRIPT_BYTES + 1),
                )])
                .await,
            ),
        ];
        for (needle, payload) in cases {
            let stderr = upload_and_collect_stderr(
                &mut client,
                STREAM_WORKSPACE_HOOK_SCRIPTS,
                session_id,
                &payload,
            )
            .await;
            assert!(
                stderr.contains(needle),
                "expected a rejection mentioning {needle:?}, got: {stderr:?}",
            );
        }

        let (_, hooks) = staged_dirs(&server, session_id).await;
        assert!(
            !tokio::fs::try_exists(hooks.join(HOOKS_READY_MARKER))
                .await
                .unwrap_or(false),
            "no rejected upload may leave a ready marker",
        );
    }

    /// Unit test on the daemon-side traversal guard — the piece
    /// covering a malicious peer that hand-crafts a raw tar with
    /// `..` entries (the client's own `async_tar` builder refuses
    /// to construct one, and `SandboxRelPath::try_new` already
    /// rejects them at the wire-schema level, so this is a
    /// defense-in-depth check for the "hand-crafted bytes"
    /// scenario the earlier layers don't cover).
    #[test]
    fn safe_relative_path_rejects_absolute_and_traversal() {
        use std::path::Path as StdPath;
        // Absolute — must reject.
        assert!(!super::safe_relative_path(StdPath::new("/etc/foo")));
        // `..` at any position — must reject.
        assert!(!super::safe_relative_path(StdPath::new("../evil")));
        assert!(!super::safe_relative_path(StdPath::new("a/../b")));
        assert!(!super::safe_relative_path(StdPath::new("a/b/..")));
        // Ordinary relative paths — must accept.
        assert!(super::safe_relative_path(StdPath::new("a")));
        assert!(super::safe_relative_path(StdPath::new("a/b/c")));
        assert!(super::safe_relative_path(StdPath::new(
            ".config/helix/config.toml"
        )));
    }

    /// When the daemon fails to parse a request (or the handler errors),
    /// the error message must reach the client on extended data instead
    /// of the client seeing an opaque EOF on the response stream (#901).
    #[tokio::test]
    async fn oneshot_rpc_surfaces_handler_errors_as_extended_data() {
        use russh::ChannelMsg;

        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // Send invalid JSON to a known subsystem: handle_channel will fail
        // at serde_json_lenient::from_slice, which now writes the error to extended
        // data before closing the channel.
        let mut channel = client.open_subsystem(GetVersion::NAME, &[]).await;
        channel
            .data_bytes(b"not valid json".to_vec())
            .await
            .unwrap();
        channel.eof().await.unwrap();

        let mut err_buf = Vec::new();
        let mut data_buf = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::ExtendedData { data, ext: 1 } => err_buf.extend_from_slice(&data),
                ChannelMsg::Data { data } => data_buf.extend_from_slice(&data),
                _ => {}
            }
        }

        assert!(
            !err_buf.is_empty(),
            "expected an error on extended data, got data={:?}, err=empty",
            String::from_utf8_lossy(&data_buf),
        );
        assert!(
            data_buf.is_empty(),
            "expected no response data on error, got {:?}",
            String::from_utf8_lossy(&data_buf),
        );
    }

    #[tokio::test]
    async fn get_version_returns_compiled_in_versions() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client.call::<GetVersion>(&()).await;

        assert_eq!(resp.version, version::VERSION);
        assert_eq!(resp.long_version, version::LONG_VERSION);
        assert_eq!(resp.stdlib_version, stdlib::VERSION);
    }

    #[tokio::test]
    async fn list_sessions_is_empty_on_a_fresh_state_dir() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client.call::<ListSessions>(&()).await;

        assert!(
            resp.sessions.is_empty(),
            "fresh tempdir should yield no sessions, got {:?}",
            resp.sessions,
        );
    }

    #[tokio::test]
    async fn get_session_record_returns_none_for_unknown_name() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Name("does-not-exist".to_string()))
            .await;

        assert!(resp.record.is_none());
    }

    #[tokio::test]
    async fn get_session_record_returns_none_for_unknown_id() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(SessionId::nil()))
            .await;

        assert!(resp.record.is_none());
    }

    #[tokio::test]
    async fn one_server_serves_multiple_back_to_back_clients() {
        // Each connect() spawns its own server-side task; this proves
        // the harness reuses a single ServerStateHandle across them.
        let server = TestServer::new().await;

        for _ in 0..3 {
            let mut client = server.connect().await;
            let resp = client.call::<GetVersion>(&()).await;
            assert_eq!(resp.version, version::VERSION);
        }
    }

    /// NET-079's per-box enforcement is a daemon-owned launch record, never
    /// a client attr, displayed as the record lowered by the current fact.
    /// A box no launch has recorded yet shows the daemon's one classifier
    /// fact: a listing shows the same state the create response said for a
    /// host-address box (this test's default create is one, never
    /// launched), and the fact a test that set its own wrote. The guard is taken
    /// before the server is built and held across the awaited creates on
    /// purpose: the fact is process-global, so under libtest — where the
    /// tests of one binary share a process — a listing driven by another
    /// test would answer over a fact that test set.
    #[expect(
        clippy::await_holding_lock,
        reason = "the fact is process-global, so the guard must span the awaited \
                  reads it is held for"
    )]
    #[tokio::test]
    async fn create_session_shows_in_get_and_list() {
        let _fact_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let created = client
            .call::<CreateSession>(&req("my-session", "/uwu"))
            .await
            .unwrap();
        let id = created.id;
        assert!(id != SessionId::nil());

        let get_session = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(id))
            .await;
        assert_eq!(get_session.record.as_ref().unwrap().id, id);
        assert_eq!(
            get_session.record.as_ref().unwrap().name,
            Some("my-session".to_string())
        );
        assert_eq!(
            get_session.record.as_ref().unwrap().project_path,
            HostAbsPath::try_new("/uwu").unwrap()
        );
        assert!(
            !get_session
                .record
                .as_ref()
                .unwrap()
                .attrs
                .contains_key(super::HOST_IP_ENFORCEMENT_ATTR),
            "the per-box enforcement is a daemon-owned launch record, never \
             an attr: the record's own field carries it, written only by a \
             launch, and displayed as that record lowered by the host's \
             current fact, got: {:?}",
            get_session.record.as_ref().unwrap().attrs
        );

        // The create reply's state is the one node fact's, spelled for the
        // wire — the derivation this test's default (host-address) create
        // reads it from, pinned here so the listing below is proven to
        // answer over the same fact the create did, whatever this host
        // actually decides.
        let fact = crate::session_host::host_ip_enforcement_fact();
        assert_eq!(
            created.host_ip_enforcement.as_deref(),
            Some(fact.enforcement.machine_str()),
            "a host-address create states the fact the daemon holds, got: {:?}",
            created.host_ip_enforcement
        );

        let list_sessions = client.call::<ListSessions>(&()).await;
        assert!(list_sessions.resource_pool.is_some());
        assert_eq!(
            list_sessions.sessions,
            vec![ListSessionsEntry {
                id,
                name: Some("my-session".to_string()),
                project_path: Some(HostAbsPath::try_new("/uwu").unwrap()),
                // A freshly-created session that hasn't been configured yet
                // sits in `Pending` until `ConfigureLoadout` promotes it.
                status: sessions::SessionStatus::Pending,
                // /uwu is not a git repository, so the probe yields nothing.
                git: None,
                // The same state the create response above carried
                // (NET-079) — derived, with the rest of the surfaces, from
                // the fact this process holds, not read off the record the
                // create wrote nothing on. This box declares an allow
                // verdict, so no host's gate refuses it and the fact is what
                // shows, on any host this test runs on.
                host_ip_enforcement: Some(fact.enforcement),
                shared_port_collisions: Vec::new(),
                attrs: None,
            }]
        );
    }

    /// The classifier facts a test builds as the step's whole half (NET-079):
    /// both subtrees with the kernel's delegation-contract files, the loaded
    /// table's presence marker, and the ct-mark mask recorded beside it — the
    /// facts that gate the probe, so an injected reading (the session host's
    /// reading stand-in) is the only input the decision still needs. The
    /// mount table the test spells beside the tree stands in for the daemon's
    /// own. Returns the tree guard, which the caller keeps alive for as long
    /// as the stand-in answers, and the root and mount table to hand a
    /// launch's re-read ([`crate::session_host::re_read_classifier_fact`]).
    fn installed_cohort_tree() -> (tempfile::TempDir, std::path::PathBuf, String) {
        let tree = tempfile::tempdir().expect("a temp dir standing in for the classifier tree");
        let root = tree.path().to_path_buf();
        for verdict in [
            sandbox2::config::Verdict::Deny,
            sandbox2::config::Verdict::Allow,
        ] {
            let subtree = root
                .join(sandbox2::classifier::BOXES_DIR)
                .join(verdict.dir_name());
            std::fs::create_dir_all(&subtree).expect("the step makes the subtree");
            for file in ["cgroup.procs", "cgroup.threads", "cgroup.subtree_control"] {
                std::fs::write(subtree.join(file), "")
                    .unwrap_or_else(|e| panic!("modeling {file} in {}: {e}", subtree.display()));
            }
        }
        std::fs::create_dir_all(root.join(sandbox2::classifier::TABLE_MARKER))
            .expect("the step writes the table's marker");
        std::fs::create_dir_all(root.join("ct-mark-mask-0x30000000"))
            .expect("the step records the ct-mark mask beside the marker");
        let mountinfo = format!(
            "35 30 0:26 / {} rw,relatime shared:2 - cgroup2 cgroup2 rw,nsdelegate\n",
            root.display()
        );
        (tree, root, mountinfo)
    }

    /// The classifier-advisory lines this session's create produced (the
    /// NET-079 observability contract). Attributed by session id, because
    /// under libtest the capture buffer is shared by every test in the
    /// binary — assertions on it say `contains`, never `equals`.
    fn classifier_lines(log: &str, session_id: &SessionId) -> Vec<String> {
        let message = "session create carried the classifier advisory";
        let id = format!("session_id={session_id}");
        log.lines()
            .filter(|line| line.contains(message) && line.contains(&id))
            .map(str::to_string)
            .collect()
    }

    /// NET-079: a native create of a box that declares egress, on a host
    /// that cannot decide per box, answers with the advisory the requirement
    /// spells — what the box asked for, that this machine cannot enforce it
    /// yet, and the two ways to enforce it, naming `min finalize-install`
    /// only when the cause is one the install ends. Both causes a test has
    /// to set as the fact, because the daemon's own host decides them for
    /// real: the step never having run, and a mount that cannot confine a
    /// box at all — so the advisory a person reads is never handed an
    /// install that cannot help. The advisory is spelled without a question,
    /// because it names what a person may run and never asks them to run it,
    /// and the daemon logs one line per advisory-carrying create naming the
    /// cause, the command when one applies, and the per-box enforcement the
    /// reply states — the bundle's tail then says what every create said.
    // The guard is taken before the server is even built and held across
    // both awaited creates on purpose: the fact is process-global, so under
    // libtest another test's create in the window would answer over it too.
    #[expect(
        clippy::await_holding_lock,
        reason = "the fact is process-global, so the guard must span the awaited \
                  creates it is set for"
    )]
    #[tokio::test]
    async fn native_host_advises_classifier_install_without_prompt() {
        let _fact_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let capture = crate::test_harness::captured_log();
        let deny_all = |name: &str| {
            let mut request = req(name, "/uwu");
            request.config.policy.egress = Some(sessions::EgressPolicy::deny_all());
            request
        };

        // The fact a start-up read over a step-missing host leaves: state
        // `none`, cause the step's — the state the daemon's own start-up
        // line would spell with the same words the advisory below carries.
        crate::session_host::set_host_ip_enforcement_fact(&classifier::Decision::undecidable(
            classifier::Cause::StepNotInstalled,
        ));
        let step_missing = client
            .call::<CreateSession>(&deny_all("step-missing"))
            .await
            .unwrap();
        let advisory = step_missing
            .classifier_advisory
            .expect("a create on a step-missing host carries the advisory");
        assert_eq!(
            advisory,
            "note: you asked this box for no network access, but this machine can't \
             enforce it yet, so the box can still reach the network.\n  Enforce it: min \
             finalize-install   (or start the box with --network own_ip, which enforces \
             it now)",
            "the advisory is the requirement's two lines, verbatim"
        );
        // The command's spelling is the install hint's own, pinned in the
        // classifier crate; the pin here is that the advisory carries it
        // whole, whatever the hint currently says.
        let install = sandbox2::classifier::install_hint();
        assert!(
            advisory.contains(&install),
            "a missing step is the cause the install command ends, so the \
             advisory must carry it, got: {advisory}"
        );
        assert!(
            !advisory.contains('?'),
            "the advisory names what a person may run; it never asks: {advisory}"
        );

        // The cannot-confine fact over the same box: the cause is the
        // mount's, so the advisory names the own-address start alone and
        // says why the install cannot help.
        crate::session_host::set_host_ip_enforcement_fact(&classifier::Decision::undecidable(
            classifier::Cause::CannotConfine,
        ));
        let cannot_confine = client
            .call::<CreateSession>(&deny_all("cannot-confine"))
            .await
            .unwrap();
        crate::session_host::clear_host_ip_enforcement_fact();
        let advisory = cannot_confine
            .classifier_advisory
            .expect("a host that cannot confine still gets the advisory");
        assert!(
            advisory.contains(
                "min finalize-install can't fix this: no cgroup2 mount with nsdelegate \
                 covers the classifier tree, so a box could migrate out of its leaf"
            ),
            "the advisory must name this cause in words too, got: {advisory}"
        );
        assert!(
            !advisory.contains("Enforce it: min finalize-install"),
            "no install ends this cause, so the advisory must not hand it out: {advisory}"
        );
        assert!(
            advisory.contains("Enforce it: start the box with --network own_ip"),
            "the own-address start is the one remedy left: {advisory}"
        );
        assert!(
            !advisory.contains('?'),
            "the advisory names what a person may run; it never asks: {advisory}"
        );

        // One line per advisory-carrying create, attributed by the session
        // it carried — the cause, the command when one applies, and the
        // enforcement the reply states for the host-address box.
        let tail = capture.contents();
        let step_line = classifier_lines(&tail, &step_missing.id);
        assert_eq!(
            step_line.len(),
            1,
            "each advisory-carrying create must log exactly one line naming \
             it, got: {tail}"
        );
        let step_line = &step_line[0];
        assert!(
            step_line.contains("advisory=\"note: you asked this box"),
            "the logged line must carry the advisory's own text, not only \
             its facts, got: {step_line}"
        );
        assert!(
            step_line.contains("the classifier's privileged step is not installed"),
            "the logged line must name the cause, got: {step_line}"
        );
        assert!(
            step_line.contains(&install),
            "the logged line must carry the command when one applies, got: {step_line}"
        );
        let confine_line = classifier_lines(&tail, &cannot_confine.id);
        assert_eq!(
            confine_line.len(),
            1,
            "each advisory-carrying create must log exactly one line naming \
             it, got: {tail}"
        );
        let confine_line = &confine_line[0];
        assert!(
            confine_line.contains("no cgroup2 mount with nsdelegate covers the classifier tree"),
            "the logged line must name this cause too, got: {confine_line}"
        );
        assert!(
            confine_line.contains("host_ip_enforcement=Some(\"none\")"),
            "the logged line must carry the enforcement stated for the host-address box, got: {confine_line}"
        );
    }

    /// NET-079: while the host cannot decide per box, a host-address box's
    /// create reply and every surface that reads the session after the
    /// create all say its egress is not enforced per box — the reply so a
    /// client can say it at once, the listing a picker reads without a
    /// round trip per session, and the runtime-facts reply
    /// `min session policy` renders beside the rules it qualifies: a
    /// deny-all declaration with an enforcement of `none` is the state the
    /// box actually runs in, not a verdict that looks decided and is not.
    /// A deny-all box running unenforced is the requirement's own case. The
    /// enforcement is a daemon-owned launch record — never an attr a
    /// client can assert, and nothing the create writes — displayed as
    /// that record lowered by the host's current fact; none of these
    /// sessions launches, so the reads answer over the fact alone. A box
    /// whose verdict is decided on address leases instead of the host's
    /// cgroup tree carries nothing: `None`, not `none`, on every surface —
    /// the same nothing a daemon that predates the field says. A box the
    /// classifier refuses — the deny-all box over a probe cause — shows
    /// nothing on the create reply or the read surfaces, exactly as its
    /// launch refuses it, while the host-address boxes that are not
    /// refused keep showing the fact.
    // The guard is taken before the server is even built and held across
    // the awaited creates on purpose: the fact is process-global, so under
    // libtest another test's read in the window would answer over it too.
    #[expect(
        clippy::await_holding_lock,
        reason = "the fact is process-global, so the guard must span the awaited \
                  reads it is set for"
    )]
    #[tokio::test]
    async fn create_response_shows_enforcement_none_while_the_host_cannot_decide() {
        let _fact_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // The fact a start-up read over a step-missing host leaves.
        crate::session_host::set_host_ip_enforcement_fact(&classifier::Decision::undecidable(
            classifier::Cause::StepNotInstalled,
        ));
        let mut deny_all = req("deny-all", "/uwu");
        deny_all.config.policy = SessionPolicy::new(Some(EgressPolicy::deny_all()), None);
        let created = client.call::<CreateSession>(&deny_all).await.unwrap();

        assert_eq!(
            created.host_ip_enforcement.as_deref(),
            Some("none"),
            "a deny-all box running unenforced on a host that cannot decide \
             per box must show egress enforcement none, got: {:?}",
            created.host_ip_enforcement
        );
        assert!(
            created
                .classifier_advisory
                .as_deref()
                .is_some_and(|advisory| advisory.contains("so the box can still reach the network")),
            "the reply must carry the advisory that says the same state in \
             words, got: {:?}",
            created.classifier_advisory
        );

        // Nothing is recorded by the create: the state the reply named is
        // the daemon's one classifier fact, and the launch record the reads
        // answer over — the record's own `host_ip_enforcement` field, which
        // only a launch writes — is still empty, so the record's attrs
        // carry no enforcement key at all.
        let record = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(created.id))
            .await;
        let attrs = &record
            .record
            .expect("the created session has a record")
            .attrs;
        assert!(
            !attrs.contains_key(super::HOST_IP_ENFORCEMENT_ATTR),
            "the per-box enforcement is a daemon-owned launch record, never \
             an attr: no create records it, and the reads show the record a \
             launch wrote, lowered by the host's current fact, got: {attrs:?}"
        );

        // The surfaces that read a session after the create derive their
        // answer from the same fact the reply stated: the listing a picker
        // reads without a round trip per session, and the runtime-facts
        // reply `min session policy` renders. All of them agree by
        // construction here — they read one fact, the daemon's own.
        let listed = client.call::<ListSessions>(&()).await;
        let entry = listed
            .sessions
            .iter()
            .find(|e| e.id == created.id)
            .expect("the created session is in the listing");
        assert_eq!(
            entry.host_ip_enforcement,
            Some(minimald_rpc::HostIpEnforcement::None),
            "the listing must carry the same state the create reply did, \
             got: {:?}",
            entry.host_ip_enforcement
        );
        let policy = client
            .call::<GetEffectiveSessionPolicy>(&GetEffectiveSessionPolicyRequest::Id(created.id))
            .await
            .unwrap();
        assert_eq!(
            policy.egress,
            EffectiveEgress::Declared(EgressPolicy::deny_all()),
            "the policy reply keeps the declaration the box launched with"
        );
        assert_eq!(
            facts_enforcement(&mut client, created.id).await,
            Some(minimald_rpc::HostIpEnforcement::None),
            "the runtime-facts reply carries the state beside the rules it \
             qualifies: a deny-all declaration that is not decided per box \
             is the state the box runs in"
        );

        // A box whose verdict is decided on address leases carries nothing:
        // `None`, not `none`, over the same host that cannot decide.
        let own_address = own_ip_session(
            &mut client,
            "own-address",
            SessionPolicy::new(Some(EgressPolicy::deny_all()), None),
        )
        .await;
        assert!(own_address != SessionId::nil());
        let reply = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(own_address))
            .await;
        let attrs = &reply
            .record
            .expect("the own-address session has a record")
            .attrs;
        assert!(
            !attrs.contains_key(super::HOST_IP_ENFORCEMENT_ATTR),
            "an own-address box's verdict is decided on address leases, so \
             its record carries no per-box enforcement, got: {attrs:?}"
        );
        let listed = client.call::<ListSessions>(&()).await;
        let own_entry = listed
            .sessions
            .iter()
            .find(|e| e.id == own_address)
            .expect("the own-address session is in the listing");
        assert!(
            own_entry.host_ip_enforcement.is_none(),
            "an own-address box shows nothing on the listing either — its \
             verdict was decided on address leases, got: {:?}",
            own_entry.host_ip_enforcement
        );
        assert!(
            facts_enforcement(&mut client, own_address).await.is_none(),
            "an own-address box shows nothing on the runtime-facts reply \
             either — there is no per-box state to qualify rules that are \
             decided on leases"
        );

        // A box the classifier refuses shows nothing on any surface: the
        // same fact, over the probe cause that refuses a placed deny-all
        // box natively, and the same launch gate the derivation shares —
        // the deny-all box's launch is refused on this ground, so the
        // create that mints it says no enforcement value, and its listing
        // entry and its runtime-facts reply say nothing rather than `none`. The
        // host-address boxes that are not refused keep showing the fact:
        // the one carrying an egress section still runs unenforced and
        // still says so, at its create and after.
        let mut sectioned = req("sectioned", "/uwu");
        sectioned.config.policy = SessionPolicy::new(
            Some(EgressPolicy {
                allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                ..EgressPolicy::deny_all()
            }),
            None,
        );
        let sectioned_id = client.call::<CreateSession>(&sectioned).await.unwrap().id;
        crate::session_host::set_host_ip_enforcement_fact(&classifier::Decision::undecidable(
            classifier::Cause::TableNotEffective,
        ));
        let mut refused_create = req("refused-create", "/uwu");
        refused_create.config.policy = SessionPolicy::new(Some(EgressPolicy::deny_all()), None);
        let refused_create = client.call::<CreateSession>(&refused_create).await.unwrap();
        assert!(
            refused_create.host_ip_enforcement.is_none(),
            "a create over the probe cause that refuses the deny-all box \
             carries no enforcement value on its reply either — the box's \
             own launch would refuse it, got: {:?}",
            refused_create.host_ip_enforcement
        );
        let mut unrefused_create = req("unrefused-create", "/uwu");
        unrefused_create.config.policy = SessionPolicy::new(
            Some(EgressPolicy {
                allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                ..EgressPolicy::deny_all()
            }),
            None,
        );
        let unrefused_create = client
            .call::<CreateSession>(&unrefused_create)
            .await
            .unwrap();
        assert_eq!(
            unrefused_create.host_ip_enforcement.as_deref(),
            Some("none"),
            "the sectioned box the fact does not refuse keeps getting the \
             state it runs in on its create reply too, got: {:?}",
            unrefused_create.host_ip_enforcement
        );
        let listed = client.call::<ListSessions>(&()).await;
        let refused = listed
            .sessions
            .iter()
            .find(|e| e.id == created.id)
            .expect("the deny-all session is in the listing");
        assert!(
            refused.host_ip_enforcement.is_none(),
            "a deny-all box the classifier refuses shows nothing on the \
             listing — the refusal is what its launch said, got: {:?}",
            refused.host_ip_enforcement
        );
        assert!(
            facts_enforcement(&mut client, created.id).await.is_none(),
            "a refused box shows nothing on the runtime-facts reply either"
        );
        let unrefused = listed
            .sessions
            .iter()
            .find(|e| e.id == sectioned_id)
            .expect("the sectioned session is in the listing");
        assert_eq!(
            unrefused.host_ip_enforcement,
            Some(minimald_rpc::HostIpEnforcement::None),
            "the host-address boxes the fact does not refuse keep showing \
             the state they run in, got: {:?}",
            unrefused.host_ip_enforcement
        );

        // The decided host, pinned pure over the derivation every read
        // surface answers through: a decided fact shows `per_box` for the
        // box its host places, the probe cause shows nothing for the box it
        // refuses and the state for the box it does not, and no host shows
        // a per-box state for a box whose verdict is decided on leases. A
        // box with no launch record yet — these pins' `None` — shows the
        // fact; a box with one shows that record, lowered by the fact and
        // never raised above it.
        let decided = fact_of(&classifier::Decision::decided());
        let ineffective = fact_of(&classifier::Decision::undecidable(
            classifier::Cause::TableNotEffective,
        ));
        let step_missing = fact_of(&classifier::Decision::undecidable(
            classifier::Cause::StepNotInstalled,
        ));
        assert_eq!(
            crate::session_host::displayed_host_ip_enforcement(
                false,
                NetworkMode::HostNet,
                sandbox2::config::Verdict::Deny,
                &decided,
                None,
            ),
            Some(minimald_rpc::HostIpEnforcement::PerBox),
            "a host that can decide per box shows its host-address boxes as \
             enforced"
        );
        assert_eq!(
            crate::session_host::displayed_host_ip_enforcement(
                false,
                NetworkMode::HostNet,
                sandbox2::config::Verdict::Allow,
                &decided,
                None,
            ),
            Some(minimald_rpc::HostIpEnforcement::PerBox),
            "the decided fact shows for the box that declared an egress \
             section too"
        );
        assert_eq!(
            crate::session_host::displayed_host_ip_enforcement(
                false,
                NetworkMode::OwnIp,
                sandbox2::config::Verdict::Deny,
                &decided,
                None,
            ),
            None,
            "a decided host still decides an own-address box's verdict on \
             address leases, not on the cgroup tree"
        );
        assert_eq!(
            crate::session_host::displayed_host_ip_enforcement(
                false,
                NetworkMode::HostNet,
                sandbox2::config::Verdict::Deny,
                &ineffective,
                None,
            ),
            None,
            "the probe cause's refusal is the launch's own gate: the box it \
             refuses shows nothing, exactly as its launch refuses it"
        );
        assert_eq!(
            crate::session_host::displayed_host_ip_enforcement(
                false,
                NetworkMode::HostNet,
                sandbox2::config::Verdict::Allow,
                &ineffective,
                None,
            ),
            Some(minimald_rpc::HostIpEnforcement::None),
            "the probe cause refuses only the deny-all box: the others run \
             unenforced and show that state"
        );
        assert_eq!(
            crate::session_host::displayed_host_ip_enforcement(
                false,
                NetworkMode::HostNet,
                sandbox2::config::Verdict::Deny,
                &step_missing,
                None,
            ),
            Some(minimald_rpc::HostIpEnforcement::None),
            "the step's causes keep the exception: even the deny-all box \
             runs unenforced and says so"
        );
        // The box's own launch record, pinned over the same facts: a box
        // its launch placed shows `per_box` while the host can still decide,
        // and `none` the moment it cannot; a box its launch left unenforced
        // shows `none` whatever the host has since decided, because the
        // record is the launch's outcome and never the host's current
        // state's to raise.
        assert_eq!(
            crate::session_host::displayed_host_ip_enforcement(
                false,
                NetworkMode::HostNet,
                sandbox2::config::Verdict::Allow,
                &decided,
                Some(minimald_rpc::HostIpEnforcement::PerBox),
            ),
            Some(minimald_rpc::HostIpEnforcement::PerBox),
            "a box its launch placed shows the per-box state its placement \
             gave it, while this host can still decide per box"
        );
        assert_eq!(
            crate::session_host::displayed_host_ip_enforcement(
                false,
                NetworkMode::HostNet,
                sandbox2::config::Verdict::Allow,
                &ineffective,
                Some(minimald_rpc::HostIpEnforcement::PerBox),
            ),
            Some(minimald_rpc::HostIpEnforcement::None),
            "a placed box on a host that has since stopped deciding shows \
             the undecidable state, never the per-box one its record holds"
        );
        assert_eq!(
            crate::session_host::displayed_host_ip_enforcement(
                false,
                NetworkMode::HostNet,
                sandbox2::config::Verdict::Allow,
                &decided,
                Some(minimald_rpc::HostIpEnforcement::None),
            ),
            Some(minimald_rpc::HostIpEnforcement::None),
            "a box its own launch left unenforced stays `none` — the record \
             is never raised to the per-box state a later launch reached"
        );

        crate::session_host::clear_host_ip_enforcement_fact();
    }

    /// The fact a decision leaves, as the reads see it — set and copied back
    /// through the daemon's own accessors, so a pure pin answers over the
    /// pairing a real read produced, never a pairing a test invented.
    fn fact_of(decision: &classifier::Decision) -> crate::session_host::HostIpEnforcementFact {
        crate::session_host::set_host_ip_enforcement_fact(decision);
        crate::session_host::host_ip_enforcement_fact()
    }

    /// The listing entry's enforcement for one session: the read surface the
    /// re-read proof asserts on, so each leg of it says only what changed.
    async fn listed_enforcement(
        client: &mut TestClient,
        id: SessionId,
    ) -> Option<minimald_rpc::HostIpEnforcement> {
        client
            .call::<ListSessions>(&())
            .await
            .sessions
            .into_iter()
            .find(|e| e.id == id)
            .expect("the created session is in the listing")
            .host_ip_enforcement
    }

    /// The enforcement the runtime-facts reply carries for one session
    /// (NET-079): the read surface `min session policy` renders beside the
    /// rules, so the proofs assert on what that command actually prints —
    /// the same derivation the listing answers over, over the reply the
    /// CLI reads.
    async fn facts_enforcement(
        client: &mut TestClient,
        id: SessionId,
    ) -> Option<minimald_rpc::HostIpEnforcement> {
        use minimald_rpc::{GetSessionRuntimeFacts, GetSessionRuntimeFactsRequest};
        client
            .call::<GetSessionRuntimeFacts>(&GetSessionRuntimeFactsRequest::Id(id))
            .await
            .unwrap()
            .host_ip_enforcement
    }

    /// NET-079's fact follows the launch re-read: the start-up read seeds it
    /// and every host-address launch's re-read refreshes it, so the read
    /// surfaces show the state the *last* read reached, never one a re-read
    /// has replaced. Driven here over the facts a test lays out — the
    /// installed step's cohort, a spelled mount table, and the probe's
    /// reading injected the way a test injects every other classifier fact —
    /// so the table can read as refusing (a host that decides per box), as
    /// removed (the marker standing over a table whose refusal is gone), and
    /// as reinstalled, with the listing answering after each read the
    /// daemon's own launches answer through. The session is a host-address
    /// box created over the start-up default fact — nothing read, nothing
    /// decided — so the create gate that refuses a declaration's
    /// unenforceable rules refuses nothing here, and the listing's answer is
    /// the fact's alone, on any host.
    // The guard is taken before the server is even built and held across
    // the awaited re-reads on purpose: the fact is process-global, so under
    // libtest another test's read in the window would answer over it too.
    #[expect(
        clippy::await_holding_lock,
        reason = "the fact is process-global, so the guard must span the awaited \
                  re-reads it is held for"
    )]
    #[tokio::test]
    async fn host_ip_enforcement_follows_the_launch_reread() {
        let _fact_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // A host-address box created over the start-up default fact — nothing
        // read, nothing decided — so the create gate refuses nothing here; the
        // section it declares is what keeps the listing entry the fact's.
        let mut session = req("reread-proof", "/uwu");
        session.config.policy = SessionPolicy::new(
            Some(EgressPolicy {
                allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                ..EgressPolicy::deny_all()
            }),
            None,
        );
        let created = client.call::<CreateSession>(&session).await.unwrap();

        // The tree the re-read answers over: the step's whole half, with
        // the mount table spelled to cover it — the same facts a launch's
        // knobs stand in, so the decision logic itself runs over them.
        let (tree, root, mountinfo) = installed_cohort_tree();

        // The re-read over a table that is refusing: `per_box`, the state
        // the proof starts from. A test's stand-in tree cannot model a
        // table whose refusal the probe reads — the kernel behind it is not
        // there — so the reading is injected, the one classifier fact a
        // stand-in tree cannot vouch for.
        crate::session_host::install_classifier_reading_standin(classifier::Reading::Refused(
            Vec::new(),
        ));
        let (_, decision) = crate::session_host::re_read_classifier_fact(
            root.clone(),
            Some(mountinfo.clone()),
            false,
        )
        .await
        .expect("the re-read runs");
        assert!(
            decision.can_decide_per_box(),
            "a table whose refusal the probe read decides per box, got: {decision:?}"
        );
        assert_eq!(
            listed_enforcement(&mut client, created.id).await,
            Some(minimald_rpc::HostIpEnforcement::PerBox),
            "the listing shows the fact the re-read wrote: a host that \
             decides per box"
        );

        // The table read as removed: the marker still stands over a refusal
        // that is gone, so the same launch re-reads `none` — and the
        // listing shows it, not the state the earlier read reached.
        crate::session_host::install_classifier_reading_standin(classifier::Reading::NotRefused {
            because: "the injected reading stands in for a probe whose \
                          every leg completed"
                .to_string(),
            families: Vec::new(),
        });
        let (_, decision) = crate::session_host::re_read_classifier_fact(
            root.clone(),
            Some(mountinfo.clone()),
            false,
        )
        .await
        .expect("the re-read runs");
        assert_eq!(
            decision.cause(),
            Some(classifier::Cause::TableNotEffective),
            "a marker standing over a table that is not refusing is its own \
             cause, got: {decision:?}"
        );
        assert_eq!(
            listed_enforcement(&mut client, created.id).await,
            Some(minimald_rpc::HostIpEnforcement::None),
            "the listing follows the re-read: a host whose table read as \
             removed shows `none`"
        );

        // The table read as reinstalled: the next launch re-reads `per_box`,
        // and the listing shows the fact the re-read refreshed.
        crate::session_host::install_classifier_reading_standin(classifier::Reading::Refused(
            Vec::new(),
        ));
        let (_, decision) = crate::session_host::re_read_classifier_fact(
            root.clone(),
            Some(mountinfo.clone()),
            false,
        )
        .await
        .expect("the re-read runs");
        assert!(
            decision.can_decide_per_box(),
            "a table whose refusal the probe read again decides per box, \
             got: {decision:?}"
        );
        assert_eq!(
            listed_enforcement(&mut client, created.id).await,
            Some(minimald_rpc::HostIpEnforcement::PerBox),
            "the listing follows the re-read back: a host whose table read \
             as reinstalled shows `per_box` again"
        );

        crate::session_host::clear_classifier_reading_standin();
        crate::session_host::clear_host_ip_enforcement_fact();
        drop(tree);
    }

    /// NET-079: on a host that decides per box, a host-address box whose
    /// declaration names rules the classifier cannot enforce is refused at
    /// create — before anything is allocated, so no record, no held name,
    /// no actor survives the refusal — and the typed error the client reads
    /// off the activate names each unenforced rule, says own-address boxes
    /// enforce them, and ends with what to do about the rules it named. The
    /// refusal rides this RPC's `InvalidInput` arm — the arm a kind other
    /// than the typed one never reaches, answering as an internal error
    /// instead — so the create's refusal is the same machine-mode code the
    /// launch's identically-typed error carries. The daemon logs one info
    /// line per refused create naming the box, the host's per-box value in
    /// the machine spelling, and each unenforced rule; the refusal counter
    /// counts each one. An own-address box's declaration is enforced on the
    /// address the box holds, so it is never refused on this ground,
    /// whatever the host decides.
    // The guard is taken before the server is even built and held across the
    // awaited creates on purpose: the fact is process-global, so under
    // libtest another test's create in the window would answer over it too.
    #[expect(
        clippy::await_holding_lock,
        reason = "the fact is process-global, so the guard must span the awaited \
                  creates it is set for"
    )]
    #[tokio::test]
    async fn per_box_host_refuses_unenforceable_host_ip_declaration() {
        let _fact_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let capture = crate::test_harness::captured_log();
        let refused_before = crate::sessions::refused_unenforceable_creates();

        // The host decides per box: the state a loaded, refusing table reads,
        // and the one the create gate answers over — the same bit the launch
        // that follows re-reads for its own gate.
        crate::session_host::set_host_ip_enforcement_fact(&classifier::Decision::decided());

        // The CLI's own spellings of a narrowing, each refused with the rule
        // it names: `--deny-subnets` subtracts a range from an allow-all —
        // a partial refusal the deny subtree does not spell — and
        // `--allow-subnets` narrows what the box may reach — a narrowing the
        // allow subtree refuses nothing to enforce.
        let mut deny_a_range = req("refused-deny-range", "/uwu");
        deny_a_range.config.policy = SessionPolicy::new(
            Some(EgressPolicy {
                deny_subnets: Some(vec!["0.0.0.0/0".to_string()]),
                ..Default::default()
            }),
            None,
        );
        // The refusal arrives over the RPC's `InvalidInput` arm — the arm
        // the typed error keys on, where any other kind answers as an
        // internal error and the call never yields an `Errorable::Err` —
        // so what the create reads here is the machine-mode code the
        // launch's identically-typed refusal carries too.
        let error = match client.call::<CreateSession>(&deny_a_range).await {
            Errorable::Err { error } => error,
            other => panic!("a per-box host refuses the denied range, got: {other:?}"),
        };
        assert!(
            error.contains("deny_subnets 0.0.0.0/0"),
            "the refusal names the rule it refused over, by field and entry: {error}"
        );
        assert!(
            error.contains("host_ip boxes on this host enforce only deny-all egress"),
            "the refusal says whose verdict it is that cannot enforce the rule: {error}"
        );
        assert!(
            error.contains("which enforces them"),
            "the refusal says own-address boxes enforce these rules, so the \
             person who typed the declaration is told where they do work: {error}"
        );
        // The refusal ends with what to do: remove the rules, declare the
        // one shape this host's classifier enforces, or take the mode that
        // enforces them — the words a person reads last are the ones they
        // can act on.
        assert!(
            error.contains("Remove them")
                && error.contains("--deny-all-egress")
                && error.contains("all three allow lists present and empty"),
            "the refusal names the remedy for the rules it refused: {error}"
        );

        let mut allow_a_subnet = req("refused-allow-list", "/uwu");
        allow_a_subnet.config.policy = SessionPolicy::new(
            Some(EgressPolicy {
                allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                ..Default::default()
            }),
            None,
        );
        let error = match client.call::<CreateSession>(&allow_a_subnet).await {
            Errorable::Err { error } => error,
            other => panic!("a per-box host refuses the narrowing allow list, got: {other:?}"),
        };
        assert!(
            error.contains("allow_subnets"),
            "the narrowing allow list is refused over the rule it names: {error}"
        );

        // The refusal is before anything is allocated: the store holds
        // neither refused box.
        let mngr = server.state.sessions_manager().await;
        assert!(
            mngr.list().await.unwrap().is_empty(),
            "the refused creates allocated nothing — no record, no held name, \
             no actor survived them"
        );

        // The counter counted each refusal, and each refusal logged one info
        // line: the box, the host's per-box value, and each unenforced rule.
        let refused_after = crate::sessions::refused_unenforceable_creates();
        assert_eq!(
            refused_after,
            refused_before + 2,
            "each refused create counted once, got {refused_after} after \
             {refused_before} before"
        );
        let logged = capture.contents();
        for (name, rule) in [
            ("refused-deny-range", "deny_subnets 0.0.0.0/0"),
            ("refused-allow-list", "allow_subnets"),
        ] {
            assert!(
                logged.lines().any(|line| {
                    line.contains("refused a create whose host-address declaration names rules")
                        && line.contains(&format!("session_name=Some(\"{name}\")"))
                        && line.contains("network_mode=host_ip")
                        && line.contains("host_ip_enforcement=per_box")
                        && line.contains(rule)
                }),
                "the refused create of {name} logged the box, the per-box value, \
                 and the rule it refused over, got: {logged}"
            );
        }

        // The refusal is the host-address mode's alone: an own-address box
        // carrying the same narrowing is created, its verdict decided on the
        // address it holds.
        let own_address = own_ip_session(
            &mut client,
            "own-address-narrowed",
            SessionPolicy::new(
                Some(EgressPolicy {
                    deny_subnets: Some(vec!["0.0.0.0/0".to_string()]),
                    ..Default::default()
                }),
                None,
            ),
        )
        .await;
        assert!(
            own_address != SessionId::nil(),
            "an own-address box's narrowing is enforced, not refused"
        );

        crate::session_host::clear_host_ip_enforcement_fact();
    }

    /// NET-079: a host that decides per box refuses only the declarations
    /// that ask for a verdict its table cannot make. A host-address box
    /// with no egress section — the allow-all it is, every verdict the
    /// classifier could decide for it enforced by its leaf — and a deny-all
    /// box — the one shape the deny subtree enforces — are both created on
    /// that host, their replies stating the per-box state the fact says,
    /// and nothing is counted as refused.
    // The guard is taken before the server is even built and held across the
    // awaited creates on purpose: the fact is process-global, so under
    // libtest another test's create in the window would answer over it too.
    #[expect(
        clippy::await_holding_lock,
        reason = "the fact is process-global, so the guard must span the awaited \
                  creates it is set for"
    )]
    #[tokio::test]
    async fn per_box_host_creates_host_ip_box_with_no_section_or_deny_all() {
        let _fact_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let refused_before = crate::sessions::refused_unenforceable_creates();

        crate::session_host::set_host_ip_enforcement_fact(&classifier::Decision::decided());

        let plain = client
            .call::<CreateSession>(&req("plain-host-address", "/uwu"))
            .await
            .unwrap();
        assert_eq!(
            plain.host_ip_enforcement.as_deref(),
            Some("per_box"),
            "a host-address box with no egress section is created on a \
             per-box host, its reply stating the enforcement the fact says, \
             got: {:?}",
            plain.host_ip_enforcement
        );

        let mut deny_all = req("deny-all-host-address", "/uwu");
        deny_all.config.policy = SessionPolicy::new(Some(EgressPolicy::deny_all()), None);
        let deny_all = client.call::<CreateSession>(&deny_all).await.unwrap();
        assert_eq!(
            deny_all.host_ip_enforcement.as_deref(),
            Some("per_box"),
            "a deny-all host-address box is created on a per-box host — its \
             shape is the deny subtree's own verdict, got: {:?}",
            deny_all.host_ip_enforcement
        );

        // Both in the store, and neither counted as refused: the gate refused
        // nothing a per-box verdict can enforce.
        let mngr = server.state.sessions_manager().await;
        let listed = mngr.list().await.unwrap();
        assert_eq!(
            listed.len(),
            2,
            "both boxes the per-box host can enforce are in the store: {listed:?}"
        );
        for name in ["plain-host-address", "deny-all-host-address"] {
            assert!(
                listed.iter().any(|s| s.name.as_deref() == Some(name)),
                "{name} is in the store, got: {listed:?}"
            );
        }
        assert_eq!(
            crate::sessions::refused_unenforceable_creates(),
            refused_before,
            "an enforceable declaration is never counted as refused"
        );

        crate::session_host::clear_host_ip_enforcement_fact();
    }

    /// NET-079's exception, at the create: a host that cannot decide per
    /// box creates every host-address box it is handed, whatever its
    /// declaration names — the narrowing shapes a decided host refuses, the
    /// deny-all shape, a box with no section, and the narrowed own-address
    /// box — because the box will run unenforced on it and be recorded as
    /// such, never refused on that ground. The probe cause that comes
    /// closest to deciding — the step installed, the table's refusal gone —
    /// creates them too: its own refusal is the *launch's*, for the box
    /// whose declaration promises the verdict, and never the create's.
    // The guard is taken before the server is even built and held across the
    // awaited creates on purpose: the fact is process-global, so under
    // libtest another test's create in the window would answer over it too.
    #[expect(
        clippy::await_holding_lock,
        reason = "the fact is process-global, so the guard must span the awaited \
                  creates it is set for"
    )]
    #[tokio::test]
    async fn unenforcing_host_still_creates_host_ip_box_with_any_declaration() {
        let _fact_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let refused_before = crate::sessions::refused_unenforceable_creates();

        // A host that cannot decide per box: the step never having run, the
        // plainest cause — its boxes run unenforced and say so.
        crate::session_host::set_host_ip_enforcement_fact(&classifier::Decision::undecidable(
            classifier::Cause::StepNotInstalled,
        ));

        // Every declaration shape, created: the two narrowings a per-box
        // host refuses, the deny-all shape, and no section at all.
        let narrowing = SessionPolicy::new(
            Some(EgressPolicy {
                deny_subnets: Some(vec!["0.0.0.0/0".to_string()]),
                ..Default::default()
            }),
            None,
        );
        let mut denied_range = req("unenforcing-deny-range", "/uwu");
        denied_range.config.policy = narrowing.clone();
        let denied_range = client.call::<CreateSession>(&denied_range).await.unwrap();
        let mut narrowed = req("unenforcing-allow-list", "/uwu");
        narrowed.config.policy = SessionPolicy::new(
            Some(EgressPolicy {
                allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                ..Default::default()
            }),
            None,
        );
        let narrowed = client.call::<CreateSession>(&narrowed).await.unwrap();
        let mut deny_all = req("unenforcing-deny-all", "/uwu");
        deny_all.config.policy = SessionPolicy::new(Some(EgressPolicy::deny_all()), None);
        let deny_all = client.call::<CreateSession>(&deny_all).await.unwrap();
        let plain = client
            .call::<CreateSession>(&req("unenforcing-plain", "/uwu"))
            .await
            .unwrap();
        for (id, why) in [
            (denied_range.id, "a denied range over an allow-all"),
            (narrowed.id, "a narrowing allow list"),
            (deny_all.id, "the deny-all shape"),
            (plain.id, "no egress section at all"),
        ] {
            assert!(
                id != SessionId::nil(),
                "a host that cannot decide per box creates {why}, runs it \
                 unenforced and records that, never refusing it on this ground"
            );
        }

        // The narrowed own-address box too: its verdict is its own, on the
        // address it holds.
        let own_address = own_ip_session(&mut client, "unenforcing-own-address", narrowing).await;
        assert!(
            own_address != SessionId::nil(),
            "an own-address box's declaration is its own to enforce, whatever \
             the host can decide"
        );

        // The probe cause nearest deciding — the tree installed, the table's
        // refusal gone — creates the narrowing a decided host refuses: the
        // create answers over the host's `can_decide_per_box` alone, and the
        // launch's own refusal for the promised verdict is never a reason to
        // hold the name or the record hostage here.
        crate::session_host::set_host_ip_enforcement_fact(&classifier::Decision::undecidable(
            classifier::Cause::TableNotEffective,
        ));
        let mut nearly_decided = req("unenforcing-nearly-decided", "/uwu");
        nearly_decided.config.policy = SessionPolicy::new(
            Some(EgressPolicy {
                deny_subnets: Some(vec!["0.0.0.0/0".to_string()]),
                ..Default::default()
            }),
            None,
        );
        let nearly_decided = client.call::<CreateSession>(&nearly_decided).await.unwrap();
        assert!(
            nearly_decided.id != SessionId::nil(),
            "the probe cause that refuses a promised verdict at launch still \
             creates the box whose declaration names it"
        );

        // Nothing was counted as refused: the exception keeps the creates.
        let mngr = server.state.sessions_manager().await;
        let listed = mngr.list().await.unwrap();
        assert_eq!(
            listed.len(),
            6,
            "every host-address box the undeciding hosts were handed was \
             created: {listed:?}"
        );
        assert_eq!(
            crate::sessions::refused_unenforceable_creates(),
            refused_before,
            "a host that cannot decide per box refuses no create on this ground"
        );

        crate::session_host::clear_host_ip_enforcement_fact();
    }

    /// Waits for the mock host's echo of `line`, which proves this session's
    /// attach minted its host — and with it that the launch's own record
    /// write, which runs before the host is handed back, has landed. The
    /// shell channel is confirmed before the attach runs, so the echo is the
    /// earliest a test can know the launch it drove is done.
    async fn await_launch_echo(channel: &mut russh::Channel<russh::client::Msg>, line: &str) {
        use russh::ChannelMsg;

        let expected = format!("got:{line}");
        channel
            .data_bytes(format!("{line}\n").as_bytes().to_vec())
            .await
            .expect("the probe line reaches the shell");
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let mut stdout = Vec::new();
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Data { data }) => {
                        stdout.extend_from_slice(&data);
                        if String::from_utf8_lossy(&stdout).contains(&expected) {
                            return;
                        }
                    }
                    Some(_) => {}
                    None => panic!(
                        "the launch's shell never echoed {expected:?}, got: {:?}",
                        String::from_utf8_lossy(&stdout)
                    ),
                }
            }
        })
        .await
        .expect("the attach mints its host within its timeout");
    }

    /// NET-079's "recorded as such" belongs to the box, not the node: each
    /// host-address box's own launch records its placement outcome on the
    /// session record, and every read surface shows that record — lowered to
    /// `none` when the host cannot decide per box, never raised above the
    /// placement the launch made. Driven end to end over the daemon's own
    /// attach path, the launches a session's start takes: boxes A and B
    /// placed — A while the injected classifier reads undecided, B once it
    /// reads per_box — and box C left unplaced by the step's absence. A
    /// records the placement its launch made over a table that was not
    /// refusing, and shows `none` while the host cannot decide, `per_box`
    /// the moment the table refuses again — the box is in the leaf its
    /// launch placed it in. C records `none` and shows `none` beside its
    /// siblings' `per_box` on the same host, whatever the host has since
    /// decided — which is what proves the reads answer over the box's own
    /// record and not the host's state — and when the fact reads `none`
    /// again, every box on it is lowered beside it.
    // The guard is taken before the server is even built and held across
    // every launch and read on purpose: the fact the launches record over
    // and the reads lower by is process-global, so under libtest another
    // test's launch or read in the window would answer over it too.
    #[expect(
        clippy::await_holding_lock,
        reason = "the fact is process-global, so the guard must span the \
                  awaited launches and reads it is held for"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unplaced_launch_stays_none_after_the_host_decides() {
        let _fact_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let capture = crate::test_harness::captured_log();

        // The tree the launches' re-reads answer over: the step's whole
        // half, with the mount table spelled to cover it, so the only thing
        // injected is the table's effect — the one fact a stand-in tree
        // cannot vouch for.
        let (tree, root, mountinfo) = installed_cohort_tree();

        // Box A's host reads undecided: the marker stands over a table whose
        // refusal is gone, so this host cannot decide per box — but the step's
        // tree is still there for a launch to place a box in, and the
        // placement is the outcome A's launch records; the table's state is
        // the reads' to lower it by, never the launch's to record.
        crate::session_host::install_classifier_reading_standin(classifier::Reading::NotRefused {
            because: "the injected reading stands in for a probe whose \
                          every leg completed"
                .to_string(),
            families: Vec::new(),
        });
        let (_, decision) = crate::session_host::re_read_classifier_fact(
            root.clone(),
            Some(mountinfo.clone()),
            false,
        )
        .await
        .expect("the re-read runs");
        assert_eq!(
            decision.cause(),
            Some(classifier::Cause::TableNotEffective),
            "the undecided reading the proof launches A under, got: {decision:?}"
        );

        // Box A: created, then launched by the attach its start takes.
        let created_a = client
            .call::<CreateSession>(&req("launch-proof-a", "/uwu"))
            .await
            .unwrap();
        let mut channel_a = client.open_shell(created_a.id).await;
        await_launch_echo(&mut channel_a, "probe-a").await;

        // Box A's own record, read back while its host still cannot decide:
        // the placement its launch made, not the table's state — and every
        // read surface lowers it to `none` over the fact, never shows a
        // `per_box` nothing is enforcing.
        let record_a = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(created_a.id))
            .await
            .record
            .expect("box A's record is readable");
        assert_eq!(
            record_a.host_ip_enforcement,
            Some(minimald_rpc::HostIpEnforcement::PerBox),
            "box A's own launch recorded the placement it made over the \
             table that was not refusing, got: {:?}",
            record_a.host_ip_enforcement
        );
        assert_eq!(
            listed_enforcement(&mut client, created_a.id).await,
            Some(minimald_rpc::HostIpEnforcement::None),
            "the listing lowers box A's record to the state its host is in \
             now — a leaf over a table that is not refusing decides nothing"
        );
        assert_eq!(
            facts_enforcement(&mut client, created_a.id).await,
            Some(minimald_rpc::HostIpEnforcement::None),
            "the runtime-facts reply lowers box A's record beside the rules \
             it runs under"
        );

        // Box B's host reads per_box: the table's refusal is in force, so
        // this host can decide a box's verdict on a leaf of its own.
        crate::session_host::install_classifier_reading_standin(classifier::Reading::Refused(
            Vec::new(),
        ));
        let (_, decision) = crate::session_host::re_read_classifier_fact(
            root.clone(),
            Some(mountinfo.clone()),
            false,
        )
        .await
        .expect("the re-read runs");
        assert!(
            decision.can_decide_per_box(),
            "the per-box reading the proof launches B under, got: {decision:?}"
        );

        // Box B: the same create-and-attach, on the host that just decided.
        let created_b = client
            .call::<CreateSession>(&req("launch-proof-b", "/uwu"))
            .await
            .unwrap();
        let mut channel_b = client.open_shell(created_b.id).await;
        await_launch_echo(&mut channel_b, "probe-b").await;

        // The boxes' own records: each launch's outcome, each on the box it
        // launched — the daemon-owned field a create left empty and only a
        // launch wrote.
        let record_b = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(created_b.id))
            .await
            .record
            .expect("box B's record is readable");
        assert_eq!(
            record_b.host_ip_enforcement,
            Some(minimald_rpc::HostIpEnforcement::PerBox),
            "box B's own launch recorded the placement its host decided, \
             got: {:?}",
            record_b.host_ip_enforcement
        );

        // The reads while the host decides: A's recorded placement is one
        // this host can honour again — the table refuses per the leaf A's
        // launch placed it in, so A shows `per_box` beside B, without a
        // relaunch — on the listing and the runtime-facts reply both.
        assert_eq!(
            listed_enforcement(&mut client, created_a.id).await,
            Some(minimald_rpc::HostIpEnforcement::PerBox),
            "the listing shows box A's record as it stands while the table \
             refuses again — the box is in the leaf its launch placed it in"
        );
        assert_eq!(
            listed_enforcement(&mut client, created_b.id).await,
            Some(minimald_rpc::HostIpEnforcement::PerBox),
            "the listing shows box B's own launch record while its host can \
             still decide per box"
        );
        assert_eq!(
            facts_enforcement(&mut client, created_a.id).await,
            Some(minimald_rpc::HostIpEnforcement::PerBox),
            "the runtime-facts reply shows box A's placement beside the \
             rules it runs under, once the table enforces it again"
        );
        assert_eq!(
            facts_enforcement(&mut client, created_b.id).await,
            Some(minimald_rpc::HostIpEnforcement::PerBox),
            "the runtime-facts reply shows box B's own launch record while \
             its host can still decide per box"
        );

        // Box C's host reads the step's absence: a cause the cohort tree
        // cannot produce — it has the step's whole half — so the fact is
        // set the way a host without it reads, which is the only half the
        // test launcher's placement consults. Nothing places a leaf for C:
        // its launch records the outcome of a placement that did not
        // happen.
        crate::session_host::set_host_ip_enforcement_fact(&classifier::Decision::undecidable(
            classifier::Cause::StepNotInstalled,
        ));

        // Box C: the same create-and-attach, on the host whose tree is not
        // there to place it.
        let created_c = client
            .call::<CreateSession>(&req("launch-proof-c", "/uwu"))
            .await
            .unwrap();
        let mut channel_c = client.open_shell(created_c.id).await;
        await_launch_echo(&mut channel_c, "probe-c").await;

        let record_c = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(created_c.id))
            .await
            .record
            .expect("box C's record is readable");
        assert_eq!(
            record_c.host_ip_enforcement,
            Some(minimald_rpc::HostIpEnforcement::None),
            "box C's own launch recorded the placement it could not make, \
             got: {:?}",
            record_c.host_ip_enforcement
        );
        assert_eq!(
            listed_enforcement(&mut client, created_c.id).await,
            Some(minimald_rpc::HostIpEnforcement::None),
            "the listing shows box C's own record — the outcome of a launch \
             that placed nothing"
        );
        assert_eq!(
            facts_enforcement(&mut client, created_c.id).await,
            Some(minimald_rpc::HostIpEnforcement::None),
            "the runtime-facts reply shows box C's own record beside the \
             rules it runs under"
        );

        // The observability half: one info line per host-address box launch,
        // each carrying the outcome its own launch recorded, attributed to
        // the session it belongs to — the placement for A and B, the
        // placement that did not happen for C.
        let logged = capture.contents();
        for (id, expected, label) in [
            (
                created_a.id,
                "host_ip_enforcement=per_box",
                "the launch that placed its box over a table that was not \
                 refusing",
            ),
            (
                created_b.id,
                "host_ip_enforcement=per_box",
                "the launch whose host decided per box",
            ),
            (
                created_c.id,
                "host_ip_enforcement=none",
                "the launch that placed nothing",
            ),
        ] {
            assert!(
                logged.lines().any(|line| {
                    line.contains("recorded its host-address box's egress enforcement")
                        && line.contains(&format!("session_id={id}"))
                        && line.contains(expected)
                }),
                "{label} records its outcome on the daemon's log, got: {logged}"
            );
        }

        // The fact reads `none` again: the host can no longer decide per
        // box, so every box on it shows the state its own record is lowered
        // to — B falls from `per_box` to `none`, and A stays where its
        // launch left it.
        crate::session_host::install_classifier_reading_standin(classifier::Reading::NotRefused {
            because: "the injected reading stands in for a probe whose \
                          every leg completed"
                .to_string(),
            families: Vec::new(),
        });
        let (_, decision) = crate::session_host::re_read_classifier_fact(
            root.clone(),
            Some(mountinfo.clone()),
            false,
        )
        .await
        .expect("the re-read runs");
        assert_eq!(
            decision.cause(),
            Some(classifier::Cause::TableNotEffective),
            "the undecidable reading the proof lowers both boxes under, got: \
             {decision:?}"
        );
        assert_eq!(
            listed_enforcement(&mut client, created_b.id).await,
            Some(minimald_rpc::HostIpEnforcement::None),
            "the listing lowers box B's own record to the state its host is \
             in now — never raised above it, never left standing above it"
        );
        assert_eq!(
            listed_enforcement(&mut client, created_a.id).await,
            Some(minimald_rpc::HostIpEnforcement::None),
            "box A stays `none` — the state its own launch left it in"
        );
        assert_eq!(
            facts_enforcement(&mut client, created_b.id).await,
            Some(minimald_rpc::HostIpEnforcement::None),
            "the runtime-facts reply lowers box B's own record too, beside \
             the rules it qualifies"
        );

        drop(channel_a);
        drop(channel_b);
        crate::session_host::clear_classifier_reading_standin();
        crate::session_host::clear_host_ip_enforcement_fact();
        drop(tree);
    }

    /// NET-079's state is the host's verdict, so no client may assert it:
    /// the daemon strips its own `host_ip_enforcement` key from a create's
    /// attrs unconditionally — whatever the session's network mode, whatever
    /// the value — and every read surface answers from the daemon's own
    /// fact. An own-address box carrying the assertion shows no enforcement
    /// anywhere (its verdict is decided on leases, so there is no per-box
    /// state to say), and a host-address box over a host that cannot decide
    /// still shows the state it runs in, never the `per_box` the activation
    /// tried to hand the reads.
    // The guard is taken before the server is even built: the fact the
    // assertions answer over is process-global, so under libtest another
    // test's read in the window would answer over it too.
    #[expect(
        clippy::await_holding_lock,
        reason = "the fact is process-global, so the guard must span the awaited \
                  reads it is held for"
    )]
    #[tokio::test]
    async fn client_cannot_assert_host_ip_enforcement() {
        let _fact_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // The fact the reads answer from: a host that cannot decide.
        crate::session_host::set_host_ip_enforcement_fact(&classifier::Decision::undecidable(
            classifier::Cause::StepNotInstalled,
        ));

        let mut asserting = req("asserting", "/uwu");
        asserting.config.network = NetworkMode::OwnIp;
        asserting.config.attrs.insert(
            super::HOST_IP_ENFORCEMENT_ATTR.to_string(),
            "per_box".to_string(),
        );
        let own_address = client.call::<CreateSession>(&asserting).await.unwrap();

        // The assertion is stripped, not honoured: the record carries no
        // enforcement key, and the read surfaces show nothing — their own
        // derivation for a box whose verdict is decided on leases.
        let reply = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(own_address.id))
            .await;
        let attrs = &reply
            .record
            .expect("the created session has a record")
            .attrs;
        assert!(
            !attrs.contains_key(super::HOST_IP_ENFORCEMENT_ATTR),
            "a client-supplied enforcement key is stripped, never recorded, \
             got: {attrs:?}"
        );
        assert_eq!(
            listed_enforcement(&mut client, own_address.id).await,
            None,
            "an own-address box shows no enforcement on the listing, \
             assertion or not: its verdict is decided on address leases"
        );
        assert!(
            facts_enforcement(&mut client, own_address.id)
                .await
                .is_none(),
            "an own-address box shows no enforcement on the runtime-facts \
             reply either, assertion or not"
        );

        // The strip is for every network mode: a host-address box carrying
        // the same assertion records nothing either, and its listing shows
        // the daemon's fact — the state the host actually runs in — never
        // the `per_box` the activation tried to assert.
        let mut host_address = req("host-address", "/uwu");
        host_address.config.attrs.insert(
            super::HOST_IP_ENFORCEMENT_ATTR.to_string(),
            "per_box".to_string(),
        );
        let host_address = client.call::<CreateSession>(&host_address).await.unwrap();
        let reply = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(host_address.id))
            .await;
        let attrs = &reply
            .record
            .expect("the created session has a record")
            .attrs;
        assert!(
            !attrs.contains_key(super::HOST_IP_ENFORCEMENT_ATTR),
            "the strip is unconditional — the mode does not let an assertion \
             through, got: {attrs:?}"
        );
        assert_eq!(
            listed_enforcement(&mut client, host_address.id).await,
            Some(minimald_rpc::HostIpEnforcement::None),
            "a host-address box's listing is the daemon's own fact, not the \
             client's assertion: a host that cannot decide shows `none`"
        );

        crate::session_host::clear_host_ip_enforcement_fact();
    }

    /// NET-079's advisory is built only where it applies: a create over a
    /// host-address box on a daemon that is not itself a microVM's guest.
    /// An own-address box's verdict is decided on address leases, so over
    /// the same fact that makes a host-address create carry the advisory —
    /// pinned here as the contrast — an own-address create carries none:
    /// `None`, the same nothing a host that decides says.
    // The guard is taken before the server is even built: the fact the
    // contrast reads is process-global, so under libtest another test's
    // read in the window would answer over it too.
    #[expect(
        clippy::await_holding_lock,
        reason = "the fact is process-global, so the guard must span the awaited \
                  creates it is set for"
    )]
    #[tokio::test]
    async fn own_ip_create_has_no_classifier_advisory() {
        let _fact_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        crate::session_host::set_host_ip_enforcement_fact(&classifier::Decision::undecidable(
            classifier::Cause::StepNotInstalled,
        ));
        // The contrast: the same fact over a declaring host-address box
        // carries it.
        let mut host_address = req("host-address", "/uwu");
        host_address.config.policy = SessionPolicy::new(Some(EgressPolicy::deny_all()), None);
        let host_address = client.call::<CreateSession>(&host_address).await.unwrap();
        assert!(
            host_address.classifier_advisory.is_some(),
            "the fact carries a cause, so a host-address create over it \
             advises — the contrast this proof needs, got: {:?}",
            host_address.classifier_advisory
        );
        let own_address = own_ip_create_reply(
            &mut client,
            "own-address",
            SessionPolicy::new(Some(EgressPolicy::deny_all()), None),
        )
        .await;
        assert_eq!(
            own_address.classifier_advisory, None,
            "an own-address box's verdict is decided on address leases, so \
             its create carries no classifier advisory, got: {:?}",
            own_address.classifier_advisory
        );

        crate::session_host::clear_host_ip_enforcement_fact();
    }

    /// NET-079's advisory, the other half of where it applies: a daemon
    /// running inside a microVM never carries it, whatever its sessions are
    /// and whatever its fact holds — the guest's start-up line and each
    /// launch's own record say the interim's state, and its causes name an
    /// image's builder rather than anything the person starting a session
    /// could run. Pinned pure over the create's gate: the test harness
    /// builds native daemons only, so the guest arm is the gate's, with the
    /// same cause and declaration a native host-address create advises on as
    /// the input that proves the `None` is the guest's doing and not the
    /// cause's.
    #[test]
    fn microvm_create_has_no_classifier_advisory() {
        let cause = Some(classifier::Cause::StepNotInstalled);
        let deny_all = sessions::EgressPolicy::deny_all();
        assert_eq!(
            super::create_classifier_advisory(true, NetworkMode::HostNet, cause, Some(&deny_all)),
            None,
            "a microVM's daemon carries no classifier advisory, whatever its \
             sessions or its fact"
        );
        assert!(
            super::create_classifier_advisory(false, NetworkMode::HostNet, cause, Some(&deny_all))
                .is_some(),
            "the same cause over a native host-address create does advise — \
             the contrast that proves the guest arm is the gate's own"
        );
        assert_eq!(
            super::create_classifier_advisory(false, NetworkMode::OwnIp, cause, Some(&deny_all)),
            None,
            "the own-address arm stays the gate's own too, guest or not"
        );
    }

    /// The advisory prints only while the box declares egress: a box that
    /// declared nothing asked for no enforcement, so a native host that
    /// cannot decide per box tells it nothing — the fact still rides the
    /// reply for `min session policy` — while a deny-all declaration gets
    /// the requirement's two lines verbatim, an allow-list declaration the
    /// same first line naming "limited" access over a second that names the
    /// own-address start alone (a finished install refuses an allow-list
    /// box rather than enforce it), a section that lists nothing a first
    /// line that claims no limit, and a VM-backed daemon nothing even over
    /// a declaring box.
    #[test]
    fn classifier_advisory_prints_only_while_box_declares_egress() {
        let cause = Some(classifier::Cause::StepNotInstalled);
        assert_eq!(
            super::create_classifier_advisory(false, NetworkMode::HostNet, cause, None),
            None,
            "a box that declares no egress is told nothing"
        );
        let deny_all = sessions::EgressPolicy::deny_all();
        assert_eq!(
            super::create_classifier_advisory(false, NetworkMode::HostNet, cause, Some(&deny_all))
                .as_deref(),
            Some(
                "note: you asked this box for no network access, but this machine can't \
                 enforce it yet, so the box can still reach the network.\n  Enforce it: min \
                 finalize-install   (or start the box with --network own_ip, which \
                 enforces it now)"
            ),
            "a deny-all declaration gets the requirement's two lines"
        );
        let allow_list = sessions::EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            ..sessions::EgressPolicy::default()
        };
        assert_eq!(
            super::create_classifier_advisory(
                false,
                NetworkMode::HostNet,
                cause,
                Some(&allow_list)
            )
            .as_deref(),
            Some(
                "note: you asked this box for limited network access, but this machine \
                 can't enforce it yet, so the box can still reach the network.\n  Enforce \
                 it: start the box with --network own_ip, which enforces it now   (on a \
                 host address the classifier enforces only a deny-all declaration, so a \
                 host that finished its install refuses this box rather than enforce its \
                 rules)"
            ),
            "an allow-list declaration asked for limited access, and is not handed \
             the install, which would get the box refused"
        );
        let lists_nothing = sessions::EgressPolicy::default();
        assert_eq!(
            super::create_classifier_advisory(
                false,
                NetworkMode::HostNet,
                cause,
                Some(&lists_nothing)
            )
            .as_deref(),
            Some(
                "note: this box declares egress, but this machine can't enforce it yet, so \
                 the box can still reach the network.\n  Enforce it: min finalize-install   \
                 (or start the box with --network own_ip, which enforces it now)"
            ),
            "a section that lists nothing asked for nothing restrictive, so the line \
             claims no limit"
        );
        assert_eq!(
            super::create_classifier_advisory(true, NetworkMode::HostNet, cause, Some(&deny_all)),
            None,
            "a VM-backed daemon never advises, declaration or not"
        );
        assert_eq!(
            super::create_classifier_advisory(false, NetworkMode::HostNet, None, Some(&deny_all)),
            None,
            "a host that decides per box has nothing to advise"
        );
    }

    /// NET-081's host-table rule at the create: on a VM-backed node an
    /// own-address create that carries no handed addresses is refused with
    /// `InvalidInput`, naming the registration the client skipped, because
    /// the guest never mints a box-plane address and a box with no host row
    /// would start silently dark (NET-085). Pinned pure over the create's
    /// gate: the test harness builds native daemons only. A handed create
    /// passes, a native own-address create keeps NET-010's own allocator,
    /// and a box that is not own-address has nothing to hand.
    #[test]
    fn vm_backed_create_without_handed_addresses_is_refused() {
        let refused = super::refuse_unhanded_vm_box(true, NetworkMode::OwnIp, None)
            .expect_err("a VM-backed own-address create with no handed addresses");
        assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            refused.to_string(),
            "box not registered with the VM host (no handed addresses); register \
             through minvmd's control socket first"
        );
        let handed = sessions::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 0, 2),
        };
        assert!(
            super::refuse_unhanded_vm_box(true, NetworkMode::OwnIp, Some(&handed)).is_ok(),
            "a VM-backed create carrying the host's handed addresses passes"
        );
        assert!(
            super::refuse_unhanded_vm_box(false, NetworkMode::OwnIp, None).is_ok(),
            "a native own-address create keeps its own allocator (NET-010)"
        );
        for network in [NetworkMode::HostNet, NetworkMode::NoNet] {
            assert!(
                super::refuse_unhanded_vm_box(true, network, None).is_ok(),
                "a VM-backed {network:?} create has no box-plane address to hand"
            );
        }
    }

    /// The advisory over the two probe causes (NET-079), pinned pure: no
    /// stand-in can carry either — a fake tree's probe child never places,
    /// so the stand-ins answer a step or mount cause, and a stand-in that
    /// carried a decided tree would need a table whose refusal the probe
    /// could read. The two are the exception's one limit: natively a
    /// deny-all host-address box is refused at placement — so the advisory
    /// must not claim the box runs over a refusal a person is about to hit,
    /// while a box the host does run says so. Neither names the install: the
    /// marker the install's item reads is present over the table it does not
    /// vouch for, so the run would be a no-op, and no command makes a probe
    /// run; both name the own-address start alone.
    #[test]
    fn advisory_over_a_probe_cause_names_the_refusal_not_a_blanket_unenforced() {
        let deny_all = sessions::EgressPolicy::deny_all();
        let not_effective =
            classifier::advisory_text(classifier::Cause::TableNotEffective, &deny_all);
        assert!(
            not_effective.contains("so it refuses to start the box"),
            "the probe cause's advisory names the refusal, got: {not_effective}"
        );
        assert!(
            !not_effective.contains("so the box can still reach the network"),
            "a refused box is not said to run, got: {not_effective}"
        );
        assert!(
            !not_effective.contains("Enforce it: min finalize-install")
                && not_effective.contains("min finalize-install can't fix this:"),
            "the marker is present, so the install is a no-op over this table: the \
             advisory names the own-address start alone and says why, got: \
             {not_effective}"
        );
        assert!(
            !not_effective.contains('?'),
            "the advisory names what a person may run; it never asks: {not_effective}"
        );
        let allowed = classifier::advisory_text(
            classifier::Cause::TableNotEffective,
            &sessions::EgressPolicy::default(),
        );
        assert!(
            allowed.contains("so the box can still reach the network"),
            "a box that needs no deny verdict still runs, and is told so: {allowed}"
        );

        let unreadable = classifier::advisory_text(classifier::Cause::ProbeUnreadable, &deny_all);
        assert!(
            unreadable.contains("so it refuses to start the box"),
            "an unreadable probe leaves the same refusal, got: {unreadable}"
        );
        assert!(
            !unreadable.contains("Enforce it: min finalize-install"),
            "no command is known to make a probe run, so the install is not \
             handed out, got: {unreadable}"
        );
        assert!(
            unreadable.contains("Enforce it: start the box with --network own_ip")
                && unreadable.contains("min finalize-install can't fix this:"),
            "the own-address start is the one remedy, and the line says why \
             the install is not: {unreadable}"
        );
    }

    /// The user-namespace gate (NET-141): a host whose verdict refuses the
    /// sandbox refuses the create itself, and the reply carries the verdict
    /// — the cause in words and that cause's own remedy — with nothing
    /// allocated for a caller to tear down. The gate is this server's own
    /// state, so no other test's create sees the fixed verdict.
    #[tokio::test]
    async fn create_reply_carries_user_namespace_verdict() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // Each cause carries its own remedy: the install step lifts only the
        // AppArmor restriction — and only for the daemon that next starts, so
        // the restart is named — while a switched-off namespace names the
        // persistent sysctl instead and never the install step.
        // The harness daemon is this process, so the path the remedy names
        // for a source-built daemon is this test binary's own.
        let bin = crate::server::this_daemon_path();
        for (verdict, expected, never) in [
            (
                crate::server::UsernsRestriction::ApparmorUnconfined,
                format!(
                    "this machine blocks the private sandbox every box runs in (Ubuntu restricts \
                     unprivileged user namespaces), so no box can start here yet.\n\
                     Finish the install to allow it for Minimal only: min finalize-install   (see \
                     what it changes first: min finalize-install --show). The profile takes \
                     effect when the daemon next starts: run min stop, then your command \
                     again.\n\
                     A daemon built from source is not covered: attach the profile to this \
                     binary instead, from a checkout: sudo scripts/install-apparmor-profile.sh \
                     --path {bin}, then the same restart."
                ),
                "sysctl",
            ),
            (
                crate::server::UsernsRestriction::Disabled,
                "this machine blocks the private sandbox every box runs in (user namespaces \
                 are switched off (user.max_user_namespaces=0 or no kernel support)), so no \
                 box can start here yet.\n\
                 Set user.max_user_namespaces above 0: sudo sysctl -w \
                 user.max_user_namespaces=15000 takes effect now, a /etc/sysctl.d drop-in \
                 keeps it across reboots; or use a kernel with CONFIG_USER_NS."
                    .to_string(),
                "finalize-install",
            ),
        ] {
            server
                .state
                .set_user_namespace_gate(crate::server::UsernsGate::Fixed(verdict))
                .await;
            let refused = client.call::<CreateSession>(&req("refused", "/uwu")).await;
            server
                .state
                .set_user_namespace_gate(crate::server::UsernsGate::Off)
                .await;
            let error = refused
                .err()
                .expect("a create under a refusing verdict must be refused");
            assert!(
                error.starts_with(minimald_rpc::USER_NAMESPACE_REFUSAL_LEAD),
                "the refusal must be the user-namespace one, got: {error}"
            );
            assert_eq!(error, expected);
            assert!(
                !error.contains(never),
                "the other cause's remedy must not be named: {error}"
            );
            assert!(
                client.call::<ListSessions>(&()).await.sessions.is_empty(),
                "a refused create must not have allocated a session"
            );
        }
    }

    /// The gate reads the verdict on every create, never once at start: a
    /// create refused under a verdict goes through once the verdict clears,
    /// on the same running server, with no restart between. The live gate
    /// re-probes `/proc` the same way; a fixed verdict stands in for the
    /// host here because the harness's own host may be restricted.
    #[tokio::test]
    async fn create_succeeds_once_the_user_namespace_verdict_clears() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        server
            .state
            .set_user_namespace_gate(crate::server::UsernsGate::Fixed(
                crate::server::UsernsRestriction::Disabled,
            ))
            .await;
        let refused = client.call::<CreateSession>(&req("remedied", "/uwu")).await;
        assert!(
            refused.err().is_some(),
            "the create before the remedy must be refused"
        );

        // The remedy applied: the same server, the same connection, no
        // restart — the next create goes through.
        server
            .state
            .set_user_namespace_gate(crate::server::UsernsGate::Off)
            .await;
        client
            .call::<CreateSession>(&req("remedied", "/uwu"))
            .await
            .ok()
            .expect("a create after the verdict clears must succeed without a restart");
    }

    /// The version gate, made by the RPC the activation path already sends
    /// rather than by a `GetVersion` ahead of it (#1251).
    ///
    /// A matching assertion is invisible; a differing one fails the call with
    /// the skew message *and leaves nothing behind* — which is the whole
    /// point, since the failure this closes is a session that exists and is
    /// then destroyed by its own caller's cleanup. An absent assertion (an
    /// older client) behaves exactly as this RPC always did.
    #[tokio::test]
    async fn create_session_refuses_a_version_skew_before_allocating_anything() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let mut skewed = req("skewed", "/uwu");
        skewed.must_match_version = Some("0.0.0-not-this-build".to_string());
        let refused = client.call::<CreateSession>(&skewed).await;
        let error = refused.err().expect("a skewed create must be refused");
        assert!(
            error.contains("0.0.0-not-this-build") && error.contains(OWN_VERSION),
            "the refusal must name both builds, got: {error}"
        );
        assert!(error.contains("min stop"), "missing the recovery: {error}");
        assert!(
            error.contains(minimald_rpc::SKEW_OVERRIDE_VAR),
            "missing the override: {error}"
        );
        assert!(
            client.call::<ListSessions>(&()).await.sessions.is_empty(),
            "a refused create must not have allocated a session"
        );

        // The matching assertion goes through, and the reply names the build
        // that honoured it — the half of the handshake that catches a daemon
        // too old to have looked at `must_match_version` at all.
        let mut matching = req("matching", "/uwu");
        matching.must_match_version = Some(OWN_VERSION.to_string());
        let created = client
            .call::<CreateSession>(&matching)
            .await
            .ok()
            .expect("a matching assertion must be accepted");
        assert_eq!(created.daemon_version.as_deref(), Some(OWN_VERSION));

        // And a client that asserts nothing — an older one, or one running
        // under the skew override — is unaffected.
        let created = client
            .call::<CreateSession>(&req("unasserted", "/uwu"))
            .await
            .ok()
            .expect("an unasserted create must behave as it always has");
        assert_eq!(created.daemon_version.as_deref(), Some(OWN_VERSION));
    }

    /// The two read RPCs the attach / exec / setup-zed paths gate on must
    /// report the daemon's build, or those paths have nothing to assert
    /// against and would have to spend a `GetVersion` to find out.
    #[tokio::test]
    async fn the_read_rpcs_report_the_daemon_build() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let id = client
            .call::<CreateSession>(&req("my-session", "/uwu"))
            .await
            .unwrap()
            .id;

        assert_eq!(
            client
                .call::<ListSessions>(&())
                .await
                .daemon_version
                .as_deref(),
            Some(OWN_VERSION)
        );
        assert_eq!(
            client
                .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(id))
                .await
                .daemon_version
                .as_deref(),
            Some(OWN_VERSION)
        );
    }

    /// The probe a host whose `lo0` carries no range alias reads: the stock
    /// macOS the spike measured — every bind refused, first at `.1`.
    fn absent_range_probe() -> crate::net::loopback::RangeProbe {
        crate::net::loopback::RangeProbe {
            bound: 0,
            probed: 254,
            first_failure: Some((
                std::net::Ipv4Addr::new(127, 0, 64, 1),
                std::io::ErrorKind::AddrNotAvailable,
            )),
        }
    }

    /// The one session-start probe line this session's create produced: the
    /// record that carries the probe's result and the surface it picked
    /// (NET-123's observability contract). Attributed by session id, because
    /// under libtest the capture buffer is shared by every test in the
    /// binary — assertions on it say `contains`, never `equals`.
    fn probe_line(log: &str, session_id: &SessionId) -> String {
        let message = "session-start loopback probe picked the publish surface";
        let id = format!("session_id={session_id}");
        log.lines()
            .find(|line| line.contains(message) && line.contains(&id))
            .unwrap_or_else(|| {
                panic!("no session-start loopback probe record for {id}, got: {log}")
            })
            .to_string()
    }

    /// NET-123's reply flag: the create response carries the interim verdict
    /// the session-start probe reached — `true` when the reserved range read
    /// absent, `false` when it read present. The flag is the whole re-advise
    /// contract: a client that reads `true` surfaces the naming advisory
    /// again (NET-122).
    // The guard is taken before the server is even built: both creates read
    // the process-global probe, the first because it *must not* see another
    // test's stand-in, the second because it must. It is held across both
    // awaited creates on purpose.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn create_response_carries_interim_flag() {
        let _standin_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // The present verdict needs no stand-in: on Linux the whole 127/8 is
        // local to `lo`, so the real probe finds the range present.
        let present = client
            .call::<CreateSession>(&req("interim-present", "/uwu"))
            .await
            .ok()
            .expect("a create with the range present must publish");
        assert!(
            !present.interim_loopback,
            "a present reserved range must not report the interim"
        );

        // The absent verdict does — no real bind on this host can produce it.
        crate::net::loopback::install_probe_standin(absent_range_probe);
        let absent = client
            .call::<CreateSession>(&req("interim-absent", "/uwu"))
            .await
            .ok()
            .expect("a create with the range absent must still publish");
        crate::net::loopback::clear_probe_standin();
        assert!(
            absent.interim_loopback,
            "an absent reserved range must report the interim on the reply"
        );
    }

    /// NET-123's probe: session start bind-probes the reserved local range
    /// before publishing, and the one session-start log line carries the
    /// probe's result and the surface it picked. On this host the whole
    /// `127/8` is local to `lo`, so the probe covers every address, finds
    /// the range present, and the reply stays off the interim.
    // The guard covers the awaited create for the same reason it covers the
    // absent arm's window: this test drives no stand-in of its own, so
    // another test's installed one must not leak into its create.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn session_start_probes_reserved_range() {
        let _standin_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let log = crate::test_harness::captured_log();
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let created = client
            .call::<CreateSession>(&req("probe-covered", "/uwu"))
            .await
            .ok()
            .expect("a create with a present range");
        assert!(!created.interim_loopback);

        let line = probe_line(&log.contents(), &created.id);
        assert!(
            line.contains("127.0.64.0/24 254/254 bound"),
            "the probe covers the whole reserved range, and the line says so: {line}"
        );
        assert!(
            line.contains("surface=reserved-range"),
            "the surface the probe picked is named: {line}"
        );
    }

    /// NET-123's absent arm: when the session-start probe finds the reserved
    /// range absent the reply carries the interim and the log names it as the
    /// surface picked — the two things that make the client surface the
    /// naming advisory again. The stand-in stands in for the host without
    /// the aliases; no real bind on this Linux one can reproduce it, and the
    /// flag itself still switches no published address (see
    /// `net::loopback`'s module doc for what the verdict carries).
    // The stand-in window must cover the awaited create, so the mutex guard
    // is held across the await on purpose.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn absent_range_publishes_interim_and_readvises() {
        let log = crate::test_harness::captured_log();
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let _standin_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        crate::net::loopback::install_probe_standin(absent_range_probe);
        let interim = client
            .call::<CreateSession>(&req("interim-published", "/uwu"))
            .await
            .ok()
            .expect("an absent range must not refuse the session");
        crate::net::loopback::clear_probe_standin();

        assert!(
            interim.interim_loopback,
            "the reply carries the interim — the flag a client re-surfaces \
             the naming advisory on"
        );
        let line = probe_line(&log.contents(), &interim.id);
        assert!(
            line.contains("surface=127.0.0.1-interim"),
            "the log names the interim as the surface chosen: {line}"
        );
        assert!(
            line.contains("interim_loopback=true"),
            "the interim verdict is on the line, for the log's reader: {line}"
        );
    }

    /// NET-018: once the answerer is serving beside the proxy, the replies
    /// report the one fact that is the daemon's to know — its answerer
    /// bound — and the one log line, emitted the moment the answerer binds,
    /// names that surface and that the hostname proxy keeps serving beside
    /// it: the verdict switches what a client *reports*, never what the
    /// proxy does (NET-019). NET-019's other half is proved on this
    /// daemon's own proxy too: after the native line, one request still
    /// routes through the listener whose port the reply carries — the
    /// pure verdict in `proxy`'s test routes through a serve loop a test
    /// spun up itself; this is the daemon's. The answerer is the half the
    /// daemon's start path brings up on a detached driver; here it is
    /// driven to serving the same way, the proxy beside it — the proxy
    /// first, so the answerer's line reads an already-recorded port
    /// deterministically rather than racing the proxy's record moment.
    ///
    /// The fresh-daemon list first proves the absent half: no answerer, no
    /// bound report — and no surface line at all, the line being the
    /// answerer's bind moment, not a request's.
    // The answerer helper binds the host loopback, so this test runs only
    // where the helper does. The stand-in window covers the awaited
    // create — the one call left that runs the process-global probe — for
    // the same reason the interim tests take it. The log assertions say
    // `contains`, never `equals`: the capture buffer is shared
    // process-wide, and any test that drives an answerer to serving
    // writes a surface line into it.
    #[expect(
        clippy::await_holding_lock,
        reason = "the stand-in window has to cover the awaited create's probe"
    )]
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn name_surface_reported_when_both_deployed() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::time::Duration;

        let log = crate::test_harness::captured_log();
        let _standin_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // A daemon with neither listener up reports the read that changes
        // nothing: not bound.
        let bare = client.call::<ListSessions>(&()).await;
        assert!(
            !bare.answerer_bound,
            "a daemon whose answerer has not come up must not report it bound"
        );

        // Bring both listeners to serving — the startup loops
        // `start_host_proxies` spawns — with a compressed backoff. The
        // proxy first: the answerer's serving tail is what logs the
        // surface line, and its proxy half reads the recorded port, so
        // recording it before the answerer binds is what makes the line's
        // "keeps serving" half deterministic here.
        let compressed =
            crate::server::RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(40));
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        crate::server::retry_hostname_proxy_until_serving(
            server.state.clone(),
            loopback,
            compressed,
        )
        .await;
        crate::server::retry_zone_answerer_until_serving(
            server.state.clone(),
            loopback,
            compressed,
        )
        .await;

        // Both listeners up: the list and create replies report the
        // answerer bound, and the activation reply carries the same fact
        // the list does.
        let listed = client.call::<ListSessions>(&()).await;
        assert!(
            listed.answerer_bound,
            "a daemon whose answerer serves reports it bound"
        );
        let created = client
            .call::<CreateSession>(&req("surface-native", "/uwu"))
            .await
            .ok()
            .expect("a create on a host whose answerer serves must succeed");
        assert!(
            created.answerer_bound,
            "the activation reply carries the same bound fact the list does"
        );

        // The log says what this daemon knows and no more: the bound
        // answerer and its port — the one fact the replies carry — that
        // native DNS waits on the host's resolver before it is the live
        // surface there, that `min ls` reports the host's verdict, and the
        // proxy's half beside it. The assertions read the message, plus the
        // two fields a bundle's reader greps (`answerer_bound`,
        // `proxy_serves`); the rest of the field quoting is the
        // subscriber's business.
        let log = log.contents();
        let answerer_line = log
            .lines()
            .find(|line| line.contains("box-zone answerer is bound"))
            .expect("the answerer's bind logs one line a diagnostics bundle can tail");
        let answerer_port = created
            .zone_answerer_port
            .expect("with the answerer up, the reply carries its port");
        assert!(
            answerer_line.contains("answerer_bound=true"),
            "the line's field is the fact the daemon knows, not a surface verdict: {answerer_line}"
        );
        assert!(
            answerer_line.contains(&format!("is bound on 127.0.0.1:{answerer_port}")),
            "the line names the bound answerer and its port: {answerer_line}"
        );
        assert!(
            answerer_line.contains("once its resolver routes the zone"),
            "the line says native DNS waits on the host's resolver routing the zone: {answerer_line}"
        );
        assert!(
            answerer_line.contains("`min ls` reports the host's surface"),
            "the line points at where the host's verdict is reported: {answerer_line}"
        );
        assert!(
            !answerer_line.contains("the live name surface is native"),
            "the daemon cannot read the host's resolver, so the line must not claim its surface: \
             {answerer_line}"
        );
        assert!(
            answerer_line.contains("proxy_serves=true"),
            "the line says the proxy still serves beside the answerer (NET-019): {answerer_line}"
        );
        assert!(
            answerer_line.contains("the hostname proxy keeps serving"),
            "the line says the proxy keeps serving, in the words its reader reads: {answerer_line}"
        );
        let port = created
            .hostname_proxy_port
            .expect("with the proxy up, the reply carries its port");
        assert!(
            answerer_line.contains(&format!("127.0.0.1:{port}")),
            "the line names the port a client keeps routing through: {answerer_line}"
        );

        // NET-019 on the daemon's own proxy: the verdict that just reported
        // native DNS stops nothing — one request still routes through the
        // listener whose port the reply carries. The registry holds the
        // create's session as a host-net route the way the session-start
        // path registers one, so the request has a target to reach.
        let backend_port = crate::net::proxy::spawn_backend().await;
        server
            .state
            .sessions_manager()
            .await
            .hostnames()
            .write()
            .expect("hostname registry lock poisoned")
            .register_host_net(created.id, "surface-native");
        let routed = crate::net::proxy::proxy_get(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            &format!("surface-native.min.internal:{backend_port}"),
        )
        .await;
        assert!(
            routed.contains("200 OK"),
            "the daemon's own proxy still routes beside the native verdict (NET-019), got: {routed}"
        );
    }

    #[tokio::test]
    async fn get_session_policy_returns_the_policy_configured_at_launch() {
        // R2.6: GetSessionPolicy reads the live per-session policy from the
        // record, not a hardcoded default. Create an `OwnIp` session carrying an
        // explicit egress policy, then read it back over the RPC.
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let egress = EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: None,
            allow_protocols: None,
            deny_subnets: Some(vec!["192.168.0.0/16".to_string()]),
        };
        let created_id = client
            .call::<CreateSession>(&CreateSessionRequest {
                config: minimald_rpc::SessionConfig {
                    name: Some("policy-session".to_string()),
                    project_path: HostAbsPath::try_new("/uwu").unwrap(),
                    network: NetworkMode::OwnIp,
                    policy: SessionPolicy::new(Some(egress.clone()), None),
                    task_addresses: Vec::new(),
                    box_id: None,
                    box_addresses: None,
                    hooks_enabled: true,
                    attrs: Default::default(),
                },
                must_match_version: None,
            })
            .await
            .unwrap()
            .id;

        let policy = client
            .call::<GetSessionPolicy>(&GetSessionPolicyRequest::Id(created_id))
            .await
            .unwrap();
        assert_eq!(policy.egress, Some(egress));
        // The configured ingress was `None`, and the read reflects that rather
        // than the old hardcoded `Some(IngressPolicy::default())`.
        assert_eq!(policy.ingress, None);
    }

    /// Creates an own-address session carrying `policy` and returns the
    /// whole create reply — the box shape the deny-all default is about
    /// (NET-074): an own-address box, whatever its egress declaration.
    /// Tests that only need the box take [`own_ip_session`].
    async fn own_ip_create_reply(
        client: &mut TestClient,
        name: &str,
        policy: SessionPolicy,
    ) -> minimald_rpc::CreateSessionResponse {
        client
            .call::<CreateSession>(&CreateSessionRequest {
                config: minimald_rpc::SessionConfig {
                    name: Some(name.to_string()),
                    project_path: HostAbsPath::try_new("/uwu").unwrap(),
                    network: NetworkMode::OwnIp,
                    policy,
                    task_addresses: Vec::new(),
                    box_id: None,
                    box_addresses: None,
                    hooks_enabled: true,
                    attrs: Default::default(),
                },
                must_match_version: None,
            })
            .await
            .unwrap()
    }

    /// Creates an own-address session carrying `policy` and returns its id —
    /// [`own_ip_create_reply`] for a caller that needs only the box.
    async fn own_ip_session(
        client: &mut TestClient,
        name: &str,
        policy: SessionPolicy,
    ) -> SessionId {
        own_ip_create_reply(client, name, policy).await.id
    }

    /// NET-074/NET-075: `GetEffectiveSessionPolicy` answers, over the real
    /// SSH wire, what the gate enforces. The wire half asserts the reply the
    /// shipped phase resolves — in force, so `deny_all` — and the in-force
    /// posture is also proven by passing the phase explicitly to the same
    /// resolver the handler serves. In force, an own-address box with no
    /// `egress` section answers `deny_all` — reported as the posture, not as
    /// a materialized section — and that reply survives the wire codec it
    /// travels as, while the strict `GetSessionPolicy` reply still carries
    /// the absent section as `None`: the default reaches the client without
    /// rewriting the record. A box that declared its own egress answers it
    /// verbatim, survived the JSON round trip, with its ingress beside it.
    /// NET-134: a box that declared a credentialed upstream answers the lane
    /// over the same reply — `Some` over the wire, spelled in the JSON —
    /// while a box that declared none answers `None` and serializes without
    /// the key, byte-identical to the reply this field did not exist for.
    #[tokio::test]
    async fn effective_policy_response_round_trips() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let egress = EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: None,
            allow_protocols: None,
            deny_subnets: Some(vec!["192.168.0.0/16".to_string()]),
        };
        let declared_id = own_ip_session(
            &mut client,
            "declared-egress",
            SessionPolicy::new(Some(egress.clone()), None),
        )
        .await;
        let bare_id = own_ip_session(&mut client, "bare-egress", SessionPolicy::default()).await;
        let laned_policy = SessionPolicy {
            egress: None,
            ingress: None,
            credentialed_upstream: Some(sessions::CredentialedUpstream::default()),
        };
        let laned_id = own_ip_session(&mut client, "laned-egress", laned_policy.clone()).await;

        // The default's own case, with the phase passed explicitly
        // (NET-074): an own-address box that declared nothing is deny-all
        // once the default is in force.
        assert_eq!(
            super::effective_policy_reply(
                &SessionPolicy::default(),
                NetworkMode::OwnIp,
                sessions::EgressDefaultPhase::InForce,
                false,
            ),
            EffectiveSessionPolicy {
                egress: EffectiveEgress::DenyAll,
                ingress: None,
                credentialed_upstream: None,
            },
            "an own-address box with no egress section must answer deny-all in force",
        );

        // The response carries that posture across the wire codec it
        // travels as — the strict shape untouched beside it: the effective
        // reply spells the default, `deny_all`, and decodes back to the
        // same value. A lane-less reply serializes without the lane's key:
        // the shape an older client reads.
        let deny_all = EffectiveSessionPolicy {
            egress: EffectiveEgress::DenyAll,
            ingress: None,
            credentialed_upstream: None,
        };
        let wire = serde_json_lenient::to_string(&minimald_rpc::Errorable::Ok(deny_all.clone()))
            .expect("the deny-all reply must serialize");
        assert!(
            wire.contains(r#""egress":"deny_all""#),
            "the wire must carry the deny-all posture, got: {wire}",
        );
        assert!(
            !wire.contains("credentialed_upstream"),
            "a reply without a lane must serialize without the lane's key, got: {wire}",
        );
        assert_eq!(
            serde_json_lenient::from_str::<minimald_rpc::Errorable<EffectiveSessionPolicy>>(&wire)
                .expect("the deny-all reply must decode back"),
            minimald_rpc::Errorable::Ok(deny_all),
        );

        // Over the real wire, the reply follows the phase this build ships:
        // whatever [`sessions::EGRESS_DEFAULT_PHASE`] resolves for a bare
        // own-address box is what the daemon answers.
        let bare = client
            .call::<GetEffectiveSessionPolicy>(&GetEffectiveSessionPolicyRequest::Id(bare_id))
            .await
            .unwrap();
        assert_eq!(
            bare,
            super::effective_policy_reply(
                &SessionPolicy::default(),
                NetworkMode::OwnIp,
                sessions::EGRESS_DEFAULT_PHASE,
                false,
            ),
            "the wire must answer the shipped phase's resolution for a bare box",
        );
        assert_eq!(
            bare.egress,
            EffectiveEgress::DenyAll,
            "with the default in force the wire answers deny-all for a bare box",
        );

        // The strict reply is unchanged: the declaration the box was
        // launched with, absent section still absent.
        let strict = client
            .call::<GetSessionPolicy>(&GetSessionPolicyRequest::Id(bare_id))
            .await
            .unwrap();
        assert_eq!(
            strict,
            SessionPolicy::default(),
            "the strict policy reply must keep the declaration as launched",
        );

        // A declared section round-trips verbatim, ingress beside it.
        let declared = client
            .call::<GetEffectiveSessionPolicy>(&GetEffectiveSessionPolicyRequest::Id(declared_id))
            .await
            .unwrap();
        assert_eq!(declared.egress, EffectiveEgress::Declared(egress));
        assert_eq!(declared.ingress, None);

        // A declared lane round-trips too: the reply answers it as `Some`
        // over the real wire, spelled in the JSON the codec travels as,
        // while the strict declaration keeps it beside the record.
        let laned = client
            .call::<GetEffectiveSessionPolicy>(&GetEffectiveSessionPolicyRequest::Id(laned_id))
            .await
            .unwrap();
        assert_eq!(
            laned.credentialed_upstream,
            Some(sessions::CredentialedUpstream::default()),
            "the wire must answer the lane a declared box carries",
        );
        let lane_wire = serde_json_lenient::to_string(&minimald_rpc::Errorable::Ok(laned.clone()))
            .expect("the laned reply must serialize");
        assert!(
            lane_wire.contains(r#""credentialed_upstream":{}"#),
            "the wire must spell the lane, got: {lane_wire}",
        );
        let strict_laned = client
            .call::<GetSessionPolicy>(&GetSessionPolicyRequest::Id(laned_id))
            .await
            .unwrap();
        assert_eq!(
            strict_laned, laned_policy,
            "the strict policy reply must keep the lane as declared",
        );

        // The bare box answers no lane: `None` on the reply, and absent
        // from the wire — the reply that predates the lane.
        assert_eq!(
            bare.credentialed_upstream, None,
            "a box that declared no lane must answer none",
        );
    }

    /// NET-077: a daemon started with the deny-all opt-out keeps the earlier
    /// allow-all default — an own-address box with no `egress` section
    /// answers `allow_all` where the same box on an opted-in daemon answers
    /// `deny_all` with the default in force — and
    /// its gate resolves no section, so nothing is enforced. A box that
    /// declared its own egress keeps it either way.
    #[tokio::test]
    async fn deny_all_opt_out_keeps_prior_default() {
        let server = TestServer::new_opted_out_in(tempfile::tempdir().unwrap()).await;
        let mut client = server.connect().await;

        let egress = EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            ..EgressPolicy::default()
        };
        let declared_id = own_ip_session(
            &mut client,
            "opt-out-declared",
            SessionPolicy::new(Some(egress.clone()), None),
        )
        .await;
        let bare_id = own_ip_session(&mut client, "opt-out-bare", SessionPolicy::default()).await;

        let bare = client
            .call::<GetEffectiveSessionPolicy>(&GetEffectiveSessionPolicyRequest::Id(bare_id))
            .await
            .unwrap();
        assert_eq!(
            bare,
            EffectiveSessionPolicy {
                egress: EffectiveEgress::AllowAll,
                ingress: None,
                credentialed_upstream: None,
            },
            "behind the opt-out, an absent egress section keeps the earlier allow-all",
        );

        // The report and the gate agree, even in force: the same resolution
        // the launcher applies materializes no section to enforce. The phase
        // is passed explicitly so the opt-out stays proven against the
        // posture it exists to defer whatever the shipped constant says.
        assert_eq!(
            crate::session::effective_egress_section(
                &sessions::SessionPolicy::default(),
                NetworkMode::OwnIp,
                sessions::EgressDefaultPhase::InForce,
                true,
            ),
            None,
            "behind the opt-out, the gate compiles no egress section at all",
        );

        // The opt-out never rewrites a declaration: what the box said is
        // what it gets, whichever daemon it runs on.
        let declared = client
            .call::<GetEffectiveSessionPolicy>(&GetEffectiveSessionPolicyRequest::Id(declared_id))
            .await
            .unwrap();
        assert_eq!(declared.egress, EffectiveEgress::Declared(egress));
    }

    /// NET-076/NET-077: the create reply carries the daemon's opt-out —
    /// the rollout's one fact the client cannot know from its own build,
    /// since the phase is a build-time constant both sides share and the
    /// flag is set on the daemon alone. `min session activate` reads it to
    /// keep its coming-change notice off a deployment that has already
    /// chosen to keep the shipped default; the create reply is the RPC the
    /// activation path already holds, so the answer costs no extra round
    /// trip. An opted-out daemon says `true`, a daemon without the flag
    /// says `false` — never `None`, which is reserved for a daemon that
    /// predates the field and so cannot have opted out.
    #[tokio::test]
    async fn create_reply_reports_the_deny_all_opt_out() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        assert_eq!(
            own_ip_create_reply(
                &mut client,
                "opt-out-reply-default",
                SessionPolicy::default()
            )
            .await
            .deny_all_opt_out,
            Some(false),
            "a daemon without the flag must say it did not opt out",
        );

        let server = TestServer::new_opted_out_in(tempfile::tempdir().unwrap()).await;
        let mut client = server.connect().await;
        assert_eq!(
            own_ip_create_reply(&mut client, "opt-out-reply-set", SessionPolicy::default())
                .await
                .deny_all_opt_out,
            Some(true),
            "an opted-out daemon must say so, so the notice can stay off",
        );
    }

    #[tokio::test]
    async fn get_session_screen_snapshots_the_live_terminal() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        // Before anything attaches there is no host: the RPC answers with a
        // soft error instead of minting one.
        let inactive = client.call::<GetSessionScreen>(&session_id).await;
        assert!(
            matches!(&inactive, Errorable::Err { error } if error.contains("not active")),
            "expected a not-active error, got {inactive:?}",
        );

        // Attach a shell (the mock launcher runs an echo program), then write
        // a line the program echoes back prefixed with `got:`.
        let shell = client.open_shell(session_id).await;
        shell.data_bytes(&b"hello-screen\n"[..]).await.unwrap();

        // The echo round-trips through the pty asynchronously; poll the RPC
        // until the parser has seen it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let snapshot = loop {
            let resp = client.call::<GetSessionScreen>(&session_id).await;
            match resp {
                Errorable::Ok(snap) => {
                    let text: String = snap
                        .lines
                        .iter()
                        .map(|row| row.cells.iter().map(|c| c.ch).collect::<String>())
                        .collect::<Vec<_>>()
                        .join("\n");
                    if text.contains("got:hello-screen") {
                        break snap;
                    }
                }
                Errorable::Err { .. } => {}
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for the echo to reach the screen snapshot",
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        assert_eq!((snapshot.rows, snapshot.cols), (24, 80));
    }

    #[tokio::test]
    async fn create_session_errors_if_name_not_unique() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let id = client
            .call::<CreateSession>(&req("my-session", "/uwu"))
            .await
            .unwrap()
            .id;
        assert!(id != SessionId::nil());

        assert_eq!(
            client
                .call::<CreateSession>(&req("my-session", "/uwu"))
                .await,
            Errorable::Err {
                error: "A session with that name already exists".to_string()
            }
        );
    }

    /// The `session created` log line names the session's network mode beside
    /// its id and name, in the CLI's `--network` spellings (`none` / `host_ip`
    /// / `own_ip`) so the bundle's tail reads like the command a person typed.
    /// Attributed by session id, because under libtest the capture buffer is
    /// shared by every test in the binary — assertions on it say `contains`,
    /// never `equals`.
    #[tokio::test]
    async fn session_created_line_names_the_network_mode() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let capture = crate::test_harness::captured_log();

        // One box per mode: the default (host-address), a NoNet box, and an
        // own-address box. Each create succeeds because none declares egress
        // (so the unenforceable-declaration gate never fires) and the native
        // test host is not a microVM (so an own-address box needs no handed
        // addresses).
        let host_ip = req("host-address", "/uwu");
        let host_id = client.call::<CreateSession>(&host_ip).await.unwrap().id;

        let mut no_net = req("no-network", "/uwu");
        no_net.config.network = NetworkMode::NoNet;
        let none_id = client.call::<CreateSession>(&no_net).await.unwrap().id;

        let mut own_ip = req("own-address", "/uwu");
        own_ip.config.network = NetworkMode::OwnIp;
        let own_id = client.call::<CreateSession>(&own_ip).await.unwrap().id;

        let log = capture.contents();
        for (id, spelling) in [
            (&host_id, "host_ip"),
            (&none_id, "none"),
            (&own_id, "own_ip"),
        ] {
            assert!(
                log.lines().any(|line| {
                    line.contains("session created")
                        && line.contains(&format!("session_id={id}"))
                        && line.contains(&format!("network_mode={spelling} "))
                }),
                "the session created line for {id} must name its network mode \
                 {spelling}, got: {log}"
            );
        }
    }

    #[tokio::test]
    async fn create_session_rejects_policy_incompatible_with_network_mode() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // NET-065: an egress policy on a none (`NoNet`) box is rejected at
        // declaration time, so the invalid session is never stored. Egress on
        // a host-address box is accepted (NET-120), so `NoNet` is the only
        // mode that still refuses it.
        let egress = EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: None,
            allow_protocols: None,
            deny_subnets: None,
        };
        let resp = client
            .call::<CreateSession>(&CreateSessionRequest {
                config: minimald_rpc::SessionConfig {
                    name: Some("bad-policy".to_string()),
                    project_path: HostAbsPath::try_new("/uwu").unwrap(),
                    network: NetworkMode::NoNet,
                    policy: SessionPolicy::new(Some(egress), None),
                    task_addresses: Vec::new(),
                    box_id: None,
                    box_addresses: None,
                    hooks_enabled: true,
                    attrs: Default::default(),
                },
                must_match_version: None,
            })
            .await;
        assert_eq!(
            resp,
            Errorable::Err {
                error: "egress rules need network mode own_ip or host_ip (this box is none): \
                        a none box has no network to apply them to"
                    .to_string()
            }
        );

        // The rejected session left nothing behind in the store.
        let mngr = server.state.sessions_manager().await;
        assert!(mngr.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_session_rejects_static_ingress_on_host_net() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // A static ingress mapping on a host-address box is a configuration the
        // daemon refuses at create time, naming the policy field and the box's
        // mode (not a CLI flag: any client may send this): an own-IP box is the
        // only mode with a published address to apply the mapping to. Built by
        // hand to bypass the CLI-side refusal so the daemon path itself is what
        // is exercised.
        let ingress = IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: 18080,
                internal_port: 80,
                proto: IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
            dynamic_ingress: None,
        };
        let resp = client
            .call::<CreateSession>(&CreateSessionRequest {
                config: minimald_rpc::SessionConfig {
                    name: Some("bad-ingress".to_string()),
                    project_path: HostAbsPath::try_new("/uwu").unwrap(),
                    network: NetworkMode::HostNet,
                    policy: SessionPolicy::new(None, Some(ingress)),
                    task_addresses: Vec::new(),
                    box_id: None,
                    box_addresses: None,
                    hooks_enabled: true,
                    attrs: Default::default(),
                },
                must_match_version: None,
            })
            .await;
        assert_eq!(
            resp,
            Errorable::Err {
                error: "ingress port mappings need network mode own_ip (this box is host_ip): \
                        only an own-IP box has a published address to apply them to"
                    .to_string()
            }
        );

        // The rejected session left nothing behind in the store.
        let mngr = server.state.sessions_manager().await;
        assert!(mngr.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rename_session_propagates_into_the_running_session() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        // Bring the session up before renaming, so the rename has to reach the
        // live actor's in-memory record rather than only touching disk.
        let mngr = server.state.sessions_manager().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("freshly-created session should be retrievable");

        let resp = client
            .call::<RenameSession>(&RenameSessionRequest {
                id: session_id,
                new_name: "renamed".to_string(),
            })
            .await;
        assert_eq!(resp, Errorable::Ok(RenameSessionResponse));

        // The record held by the running session reflects the new name...
        let record = handle.record().await.unwrap();
        assert_eq!(record.name.as_deref(), Some("renamed"));
        // ...while its id is untouched by the rename.
        assert_eq!(record.id, session_id);

        // The rename is reflected by GetRecord...
        let get_session = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(record.id))
            .await;
        assert_eq!(
            get_session.record.as_ref().unwrap().name,
            Some("renamed".to_string())
        );
    }

    #[tokio::test]
    async fn rename_session_to_its_current_name_is_an_error() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        // `fresh_session` names the session "stream-test"; renaming it to that
        // same name must fail rather than silently no-op.
        let resp = client
            .call::<RenameSession>(&RenameSessionRequest {
                id: session_id,
                new_name: "stream-test".to_string(),
            })
            .await;

        assert!(
            matches!(&resp, Errorable::Err { error } if error.contains("session is already named")),
            "expected a rename-to-self error, got {resp:?}",
        );

        // The failed rename left the name intact.
        let mngr = server.state.sessions_manager().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("freshly-created session should be retrievable");
        let record = handle.record().await.unwrap();
        assert_eq!(record.name.as_deref(), Some("stream-test"));
    }

    #[tokio::test]
    async fn rename_session_errors_for_unknown_id() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<RenameSession>(&RenameSessionRequest {
                id: SessionId::nil(),
                new_name: "renamed".to_string(),
            })
            .await;

        assert!(
            matches!(resp, Errorable::Err { error } if error.contains("no session with ID")),
            "expected an unknown-id error",
        );
    }

    /// A verdict for an id with no live session is a terminal, structured
    /// `Fault::UnknownSessionId` on the wire — not a transport error. This
    /// mapping lives in `serve_submit_verdict` now that verdicts route to
    /// per-session actors.
    #[tokio::test]
    async fn submit_verdict_unknown_id_returns_unknown_session_id() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<minimald_rpc::SubmitVerdict>(&sessions::wire::request::ContributionVerdict {
                session_id: SessionId::nil(),
                vars: vec![],
                patches: vec![],
                lifecycle_hooks: vec![],
            })
            .await;
        match resp {
            Errorable::Ok(sessions::wire::request::SessionStep::Fault {
                error: sessions::wire::errors::WireError::UnknownSessionId,
            }) => {}
            other => panic!("expected Fault::UnknownSessionId, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn destroy_session_removes_it_from_get_and_list() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let resp = client
            .call::<DestroySession>(&DestroySessionRequest { id: session_id })
            .await;
        assert_eq!(resp, Errorable::Ok(DestroySessionResponse::default()));

        // The record is gone: it no longer resolves by id...
        let get_session = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(session_id))
            .await;
        assert!(get_session.record.is_none());

        // ...and it's dropped from the listing.
        let list_sessions = client.call::<ListSessions>(&()).await;
        assert!(
            list_sessions.sessions.is_empty(),
            "destroyed session should not be listed, got {:?}",
            list_sessions.sessions,
        );
    }

    #[tokio::test]
    async fn destroy_session_errors_for_unknown_id() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<DestroySession>(&DestroySessionRequest {
                id: SessionId::nil(),
            })
            .await;

        assert!(
            matches!(resp, Errorable::Err { error } if error.contains("no session with ID")),
            "expected an unknown-id error",
        );
    }

    #[tokio::test]
    async fn shutdown_reports_shutting_down_when_no_sessions_are_live() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<Shutdown>(&ShutdownRequest { force: false })
            .await;
        assert_eq!(resp, ShutdownResponse::ShuttingDown);
    }

    #[tokio::test]
    async fn shutdown_rejects_further_session_work_once_shut_down() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<Shutdown>(&ShutdownRequest { force: false })
            .await;
        assert_eq!(resp, ShutdownResponse::ShuttingDown);

        // After shutdown the manager refuses to bring sessions up, so even a
        // lookup for a well-formed id is rejected rather than answered.
        let mngr = server.state.sessions_manager().await;
        assert!(
            mngr.get_session(SessionKeyPredicate::Id(SessionId::nil()))
                .await
                .is_err(),
            "manager should reject session work while shutting down",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_without_force_refuses_while_a_session_is_live() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        // A session is only "busy" once it hosts a live shell (an idle actor
        // no longer blocks an unforced shutdown). Open one and drive an echo
        // round trip so the host is provably up before the shutdown request.
        let mut channel = client.open_shell(session_id).await;
        channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
        let mut stdout = Vec::new();
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                    if String::from_utf8_lossy(&stdout).contains("got:hello") {
                        break;
                    }
                }
                Some(_) => {}
                None => panic!("channel closed before the echo arrived"),
            }
        }

        let resp = client
            .call::<Shutdown>(&ShutdownRequest { force: false })
            .await;
        assert_eq!(resp, ShutdownResponse::SessionsLive);

        // The refusal left the daemon fully operational: the live session is
        // still reachable and no shutdown flag was latched.
        let mngr = server.state.sessions_manager().await;
        assert!(
            mngr.get_session(SessionKeyPredicate::Id(session_id))
                .await
                .unwrap()
                .is_some(),
            "an unforced, refused shutdown must not tear down live sessions",
        );
    }

    /// A session whose shell has exited still holds its host (the slot
    /// outlives the process), but nothing runs there for an unforced shutdown
    /// to interrupt, so it must not refuse. Driven the way the session e2e
    /// meets it: exit the shell, keep the session at the exit prompt, then
    /// stop the daemon.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_without_force_proceeds_once_a_sessions_shell_has_exited() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let mut channel = client.open_shell(session_id).await;
        channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
        let mut stdout = Vec::new();
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                    if String::from_utf8_lossy(&stdout).contains("got:hello") {
                        break;
                    }
                }
                Some(_) => {}
                None => panic!("channel closed before the echo arrived"),
            }
        }

        // Exit the shell and take the prompt's default (keep): the session
        // survives, its host gone.
        channel
            .data_bytes(format!("{}\n", crate::session_host::MOCK_EXIT_LINE).into_bytes())
            .await
            .unwrap();
        let mut answered = false;
        let mut prompt_out = Vec::new();
        while let Ok(msg) =
            tokio::time::timeout(std::time::Duration::from_secs(10), channel.wait()).await
        {
            match msg {
                Some(russh::ChannelMsg::Data { data }) => {
                    prompt_out.extend_from_slice(&data);
                    if !answered
                        && String::from_utf8_lossy(&prompt_out)
                            .contains(crate::session_host::SHELL_EXIT_PROMPT)
                    {
                        channel.data_bytes(b"\r".to_vec()).await.unwrap();
                        answered = true;
                    }
                }
                Some(_) => {}
                None => break,
            }
        }
        assert!(
            answered,
            "expected the session-exit prompt to render; got: {:?}",
            String::from_utf8_lossy(&prompt_out)
        );

        let mngr = server.state.sessions_manager().await;
        let session = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("keep leaves the session in place");
        // The host loop winds down after the channel closes; bounded wait.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while session.is_busy().await {
            assert!(
                tokio::time::Instant::now() < deadline,
                "a session whose shell has exited stayed busy",
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let resp = client
            .call::<Shutdown>(&ShutdownRequest { force: false })
            .await;
        assert_eq!(resp, ShutdownResponse::ShuttingDown);
    }

    #[tokio::test]
    async fn shutdown_with_force_tears_down_live_sessions() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let mngr = server.state.sessions_manager().await;
        mngr.get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("freshly-created session should be retrievable");

        // `force` overrides the live-session guard: the daemon shuts down...
        let resp = client
            .call::<Shutdown>(&ShutdownRequest { force: true })
            .await;
        assert_eq!(resp, ShutdownResponse::ShuttingDown);

        // ...and, being in shutdown, refuses to hand out sessions afterwards.
        assert!(
            mngr.get_session(SessionKeyPredicate::Id(session_id))
                .await
                .is_err(),
            "a forced shutdown should leave the manager rejecting session work",
        );
    }

    #[tokio::test]
    async fn get_mesh_status_is_unconfigured_by_default() {
        // Without a mesh installed, the RPC answers cleanly with `configured =
        // false` rather than erroring (this is also the answer a daemon built
        // without the `networking-wg` feature gives).
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client.call::<minimald_rpc::GetMeshStatus>(&()).await;

        assert!(!resp.configured);
        assert!(resp.own_public_key.is_none());
        assert!(resp.peers.is_empty());
    }

    #[cfg(feature = "networking-wg")]
    #[tokio::test]
    async fn get_mesh_status_reports_own_key_and_peers() {
        use crate::net::wg::{Keypair, MeshConfig, PeerConfig};

        let server = TestServer::new().await;

        // Stand up a real mesh peer with one configured peer and install it.
        let remote = Keypair::generate();
        let cfg = MeshConfig {
            keypair: Keypair::generate(),
            listen_port: 0, // ephemeral; no traffic is sent in this test
            advertised_subnets: vec!["100.64.0.0/16".parse().unwrap()],
            peers: vec![PeerConfig {
                name: "remote".to_string(),
                public_key: remote.public(),
                endpoint: None,
                allowed_ips: vec!["100.65.0.0/16".parse().unwrap()],
            }],
        };
        let (sink_tx, _sink_rx) = tokio::sync::mpsc::channel(1);
        let mesh = std::sync::Arc::new(crate::net::wg::start(cfg, sink_tx).await.unwrap());
        let own_pub = mesh.own_public_key().to_base64();
        server.state.set_mesh(mesh).await;

        let mut client = server.connect().await;
        let resp = client.call::<minimald_rpc::GetMeshStatus>(&()).await;

        assert!(resp.configured);
        assert_eq!(resp.own_public_key.as_deref(), Some(own_pub.as_str()));
        assert_eq!(resp.advertised_subnets, vec!["100.64.0.0/16".to_string()]);
        assert_eq!(resp.peers.len(), 1);
        assert_eq!(resp.peers[0].name, "remote");
        assert_eq!(resp.peers[0].public_key, remote.public().to_base64());
        // Keep the sink alive until the assertions complete.
        drop(_sink_rx);
    }

    /// The answerer control socket's gate mirrors the VM host daemon's
    /// door: the daemon's own uid asks every verb, root only the handover's
    /// release and its cancel — a status ask or a box verb from root is
    /// refused — and any other uid nothing.
    #[test]
    fn answerer_control_admits_root_only_the_handover_verbs() {
        let own = 1000;
        for request in [
            BoxControlRequest::AnswererStatus,
            BoxControlRequest::ReleaseAnswerer,
            BoxControlRequest::ReleaseAnswererCancel,
        ] {
            assert!(answerer_control_admits(own, own, &request), "{request:?}");
        }
        assert!(answerer_control_admits(
            0,
            own,
            &BoxControlRequest::ReleaseAnswerer
        ));
        assert!(answerer_control_admits(
            0,
            own,
            &BoxControlRequest::ReleaseAnswererCancel
        ));
        assert!(
            !answerer_control_admits(0, own, &BoxControlRequest::AnswererStatus),
            "root asking the status is refused"
        );
        assert!(
            !answerer_control_admits(
                0,
                own,
                &BoxControlRequest::ReadRow(minimald_rpc::ReadRowRequest {
                    name: "web".to_string(),
                })
            ),
            "root asking a row read is refused"
        );
        assert!(!answerer_control_admits(
            4242,
            own,
            &BoxControlRequest::ReleaseAnswerer
        ));
    }

    /// A stale control socket — a file at the daemon's own path that no
    /// listener answers — is unlinked and re-bound; a live one is refused
    /// and left in place, never taken out from under the daemon serving it.
    #[tokio::test]
    async fn answerer_control_rebinds_a_stale_socket_and_refuses_a_live_one() {
        let server = TestServer::new().await;
        let dir = std::path::PathBuf::from(server.state.minimal_state_dir().await.as_str());
        let sock = dir.join(ANSWERER_CONTROL_SOCK_FILE);

        // A corpse: bound, then its listener dropped, so the file stays.
        drop(std::os::unix::net::UnixListener::bind(&sock).expect("a stale socket binds"));
        assert!(sock.exists(), "the stale socket file is left behind");
        spawn_answerer_control(
            &server.state,
            crate::net::answerer::AnswererStatus::starting(),
        )
        .await
        .expect("a stale socket is unlinked and re-bound");
        let mut stream = tokio::net::UnixStream::connect(&sock)
            .await
            .expect("the re-bound socket answers");
        stream
            .write_all(b"{\"verb\":\"answerer_status\"}\n")
            .await
            .expect("the ask is written");
        let mut reply = String::new();
        stream
            .read_to_string(&mut reply)
            .await
            .expect("the reply is read");
        assert!(
            reply.contains("state"),
            "the re-bound door answers its own uid a status: {reply}"
        );

        // Live: a second bind at the same path is refused, the file kept.
        let refused = spawn_answerer_control(
            &server.state,
            crate::net::answerer::AnswererStatus::starting(),
        )
        .await
        .expect_err("a live door is not taken");
        assert_eq!(refused.kind(), std::io::ErrorKind::AddrInUse);
        assert!(
            tokio::net::UnixStream::connect(&sock).await.is_ok(),
            "the live door still answers"
        );
    }
}

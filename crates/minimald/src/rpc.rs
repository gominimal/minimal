use boxes::SessionId;
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
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

// Every task this module spawns carries the caller's span (TEL-022): the
// clippy `disallowed-methods` for the crate names tokio's own spawn.
use crate::traced::spawn;

use crate::{
    ChannelConfig,
    box_manager::BoxKeyPredicate,
    connection::{ConnectionError, ConnectionHandle},
    net::classifier,
    server::ServerStateHandle,
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
            let resource_pool = crate::traced::spawn_blocking(detect_resource_pool)
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
            let fact = crate::box_runtime::host_ip_enforcement_fact();
            let enforcement = futures::future::join_all(infos.iter().map(|i| async {
                let record = mngr
                    .get_record(BoxKeyPredicate::Id(i.id))
                    .await
                    .ok()
                    .flatten();
                record.map(|record| {
                    crate::box_runtime::displayed_host_ip_enforcement(
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
    mngr: &crate::box_manager::BoxManagerHandle,
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
    use crate::box_manager::BoxKeyPredicate;
    GetSessionRecord
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;
            let record = mngr
                .get_record(match req {
                    GetSessionRecordRequest::Id(id) => BoxKeyPredicate::Id(id),
                    GetSessionRecordRequest::Name(name) => BoxKeyPredicate::Name(name),
                })
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            Ok(session_record_response(record))
        })
        .await
}

/// The [`GetSessionRecord`] reply for a stored record. The reply never
/// carries the box's sealed values (BEP-007): only the daemon's own launch
/// reads them, so a daemon client does not read another box's values. The
/// store keeps them.
pub(crate) fn session_record_response(record: Option<boxes::Record>) -> GetSessionRecordResponse {
    GetSessionRecordResponse {
        daemon_version: Some(OWN_VERSION.to_string()),
        record: record.map(|mut record| {
            record.sealed_deliveries.clear();
            record
        }),
    }
}

/// Stand-in for `session_name` on the lifecycle records when the session
/// carries no user-assigned name. `BoxConfig::name` is `None` for an
/// anonymous session, and an absent field reads like a logging bug.
pub(crate) const ANONYMOUS_SESSION: &str = "<anonymous>";

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
    fn of(policy: &minimald_rpc::BoxPolicy) -> Self {
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
            let fact = crate::box_runtime::host_ip_enforcement_fact();
            let classifier_cause = fact.cause;
            let classifier_advisory = create_classifier_advisory(
                in_microvm,
                req.config.network,
                classifier_cause,
                req.config.policy.egress.as_ref(),
            );
            let host_ip_enforcement = crate::box_runtime::displayed_host_ip_enforcement(
                in_microvm,
                req.config.network,
                classifier::verdict_of(req.config.policy.egress.as_ref()),
                &fact,
                None,
            );
            req.config.attrs.remove(HOST_IP_ENFORCEMENT_ATTR);

            // The session remembers its creator, so an attach from another
            // connection cannot run the Draft shortcut while this one is
            // still mid-activation (uploading, then configuring).
            let creator = conn.liveness().await;
            Ok(match mngr
                .create_session_by(req.config, ssh_username, creator)
                .await
            {
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
        restriction.remedy(sandbox::RemedyTarget::Daemon {
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
    box_addresses: Option<&boxes::BoxAddresses>,
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
    egress: Option<&boxes::EgressPolicy>,
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
    crate::traced::spawn_blocking(probe_fn)
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
    crate::traced::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { return };
                    let status = status.clone();
                    crate::traced::spawn(serve_answerer_control(stream, status));
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
                | BoxControlRequest::RowStanding(_)
                | BoxControlRequest::ProxyListening => BoxControlReply::Error {
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
                .get_session(BoxKeyPredicate::Id(req.session_id))
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            let Some(h) = handle else {
                return Ok(Errorable::Err {
                    error: format!(
                        "{} `{}`",
                        minimald_rpc::UNKNOWN_SESSION_ID_LEAD,
                        req.session_id.as_ref()
                    ),
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
/// record `Pending → Active`. Replies with `Errorable::Ok(BoxStep)`
/// where the `BoxStep` is `Active { id }` on success or
/// `Fault { error }` for a structured failure. A verdict for an id
/// with no live session — including an actor that died between
/// resolve and delivery — maps to `Fault { UnknownSessionId }` here;
/// other `io::Error`s bubble up as `ConnectionError::Internal`.
async fn serve_submit_verdict(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    SubmitVerdict
        .handle_channel(c, async |req: boxes::wire::request::ContributionVerdict| {
            let mngr = s.sessions_manager().await;
            let unknown = || {
                Errorable::Ok(boxes::wire::request::BoxStep::Fault {
                    error: boxes::wire::errors::WireError::UnknownSessionId,
                })
            };
            let handle = mngr
                .get_session(BoxKeyPredicate::Id(req.session_id))
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
        })
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
                .get_session(BoxKeyPredicate::Id(req.session_id))
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            let Some(h) = handle else {
                return Ok(Errorable::Err {
                    error: format!(
                        "{} `{}`",
                        minimald_rpc::UNKNOWN_SESSION_ID_LEAD,
                        req.session_id.as_ref()
                    ),
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
                    .get_session(BoxKeyPredicate::Id(req.id))
                    .await?
                {
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "{} `{}`",
                            minimald_rpc::UNKNOWN_SESSION_ID_LEAD,
                            req.id.as_ref()
                        ),
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
                .get_record(BoxKeyPredicate::Id(req.id))
                .await
                .ok()
                .flatten()
                .and_then(|record| record.name);
            let outcome = if req.only_if_unfinalized {
                mngr.delete_session_if_unfinalized(req.id).await
            } else {
                mngr.delete_session(req.id).await.map(Some)
            };
            match outcome {
                Ok(Some(hook_failures)) => {
                    tracing::info!(
                        session_id = %req.id,
                        session_name = session_name.as_deref().unwrap_or(ANONYMOUS_SESSION),
                        "session destroyed"
                    );
                    Ok(Errorable::Ok(DestroySessionResponse {
                        hook_failures,
                        kept: false,
                    }))
                }
                Ok(None) => {
                    tracing::info!(
                        session_id = %req.id,
                        session_name = session_name.as_deref().unwrap_or(ANONYMOUS_SESSION),
                        "kept the session a cleanup destroy was sent for: it finished activating"
                    );
                    Ok(Errorable::Ok(DestroySessionResponse {
                        hook_failures: Vec::new(),
                        kept: true,
                    }))
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
                    // With the sessions drained, run the clean-stop steps in
                    // their fixed order (see [`clean_stop_steps`]): every fd
                    // the daemon holds write-open under the state volume is
                    // closed before the quiesce, so a caller-driven VMM
                    // teardown right after the ack leaves a clean ext4
                    // journal.
                    for step in clean_stop_steps(s.state_volume_mounted().await) {
                        run_clean_stop_step(&s, step).await;
                    }
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

/// One step of the clean stop the `Shutdown` handler runs once its sessions
/// have drained. [`clean_stop_steps`] decides which run and in what order;
/// [`run_clean_stop_step`] runs one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CleanStopStep {
    /// Close the file log (both the native daemon and the microVM): it flushes
    /// buffered records, and in the microVM its write-open fd under the
    /// mountpoint would otherwise defeat the read-only remount. Records still
    /// reach the console. A no-op for a foreground run.
    ReleaseLog,
    /// Export the telemetry recorded so far, bounded by
    /// [`CLEAN_STOP_TELEMETRY_FLUSH`]. Before the ack, because `minvmd stop`
    /// SIGTERMs the VMM as soon as the ack arrives, so the guest's exit-time
    /// flush in `main` rarely gets to run. Non-terminal: what follows (the
    /// Shutdown span itself) still goes out with that exit-time flush when it
    /// does run. Before [`CleanStopStep::ReleaseSpool`], so records the flush
    /// emits are still spooled.
    FlushTelemetry,
    /// Close the telemetry spool's file and stop spooling: the spool lives on
    /// the state volume (`<state>/telemetry/spool`), and its write-open fd
    /// would defeat the read-only remount exactly as the file log's would.
    /// Records after this point are dropped, as a spool with no directory yet
    /// drops them.
    ReleaseSpool,
    /// R2.1/R2.2: quiesce the state volume (syncfs, read-only remount, trim,
    /// detach). Best-effort with a bounded wait; the journal replay backstop
    /// covers every failure arm.
    QuiesceVolume,
}

/// Bound on the clean stop's telemetry flush. It delays the ack, and with it
/// every `minvmd stop`, by at most this much when the collector is slow or
/// down. Short, because every stop pays it while a reachable collector
/// answers in a few hundred milliseconds; the exit-time flush in `main`
/// keeps its 5 s bound.
const CLEAN_STOP_TELEMETRY_FLUSH: std::time::Duration = std::time::Duration::from_millis(1500);

/// The clean-stop steps, in order, for a daemon that did (or did not) mount
/// the state volume itself.
///
/// The order is the contract: everything that holds a write-open fd under
/// the state volume (the file log, the telemetry spool) is released before
/// the quiesce, or the read-only remount fails and the journal stays dirty.
/// Only the microVM guest (the daemon that mounted the volume) flushes before
/// the ack, since only its process is torn down right after it. A daemon that
/// mounted no volume keeps its spool: nothing is quiesced, and the records up
/// to its exit still spool.
fn clean_stop_steps(volume_mounted: bool) -> Vec<CleanStopStep> {
    let mut steps = vec![CleanStopStep::ReleaseLog];
    if volume_mounted {
        steps.push(CleanStopStep::FlushTelemetry);
        steps.push(CleanStopStep::ReleaseSpool);
        steps.push(CleanStopStep::QuiesceVolume);
    }
    steps
}

/// Runs one [`CleanStopStep`]. None fails the stop: each is best-effort.
async fn run_clean_stop_step(s: &ServerStateHandle, step: CleanStopStep) {
    match step {
        CleanStopStep::ReleaseLog => s.release_log().await,
        CleanStopStep::FlushTelemetry => flush_telemetry_for_clean_stop().await,
        CleanStopStep::ReleaseSpool => mlog::otel::release_spool(),
        CleanStopStep::QuiesceVolume => quiesce_state_volume_if_mounted(s).await,
    }
}

/// Flushes telemetry on the blocking pool, since the flush blocks its thread
/// for up to [`CLEAN_STOP_TELEMETRY_FLUSH`]. The handler stops waiting shortly
/// after that bound even if the flush thread is still stuck in the exporter.
async fn flush_telemetry_for_clean_stop() {
    let flush = crate::traced::spawn_blocking(|| mlog::otel::flush(CLEAN_STOP_TELEMETRY_FLUSH));
    let ceiling = CLEAN_STOP_TELEMETRY_FLUSH + std::time::Duration::from_millis(500);
    match tokio::time::timeout(ceiling, flush).await {
        Ok(Ok(())) => {}
        Ok(Err(join)) => tracing::warn!(error = %join, "telemetry flush task panicked"),
        Err(_) => tracing::warn!("telemetry flush outlived its bound; proceeding"),
    }
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
    // The file log and the telemetry spool were already released by the
    // shutdown handler, so their fds no longer hold the mountpoint busy.
    let mountpoint = s.minimal_state_dir().await;
    let quiesce = crate::traced::spawn_blocking(move || {
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
                    .get_session(BoxKeyPredicate::Id(req.id))
                    .await?
                {
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "{} `{}`",
                            minimald_rpc::UNKNOWN_SESSION_ID_LEAD,
                            req.id.as_ref()
                        ),
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
                GetSessionPolicyRequest::Id(id) => BoxKeyPredicate::Id(id),
                GetSessionPolicyRequest::Name(name) => BoxKeyPredicate::Name(name),
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
/// [`boxes::EGRESS_DEFAULT_PHASE`], the phase this build ships, and the
/// tests name [`boxes::EgressDefaultPhase::InForce`] so the deny-all
/// posture they prove does not hang on that constant.
pub(crate) fn effective_policy_reply(
    policy: &boxes::BoxPolicy,
    network: boxes::NetworkMode,
    phase: boxes::EgressDefaultPhase,
    opt_out: bool,
) -> minimald_rpc::EffectiveBoxPolicy {
    minimald_rpc::EffectiveBoxPolicy {
        egress: boxes::effective_egress(policy.egress.as_ref(), network, phase, opt_out),
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
/// ([`boxes::EGRESS_DEFAULT_PHASE`]) and its opt-out flag (NET-077). An
/// own-address box with no `egress` section answers `deny_all` with the
/// default in force (NET-074) and `allow_all` behind the opt-out; a declared
/// section answers as the gate resolves it — the lists it declared
/// verbatim, and under the in-force default, on a box of any network mode,
/// a destination list it left absent present and empty, the wire meaning
/// being "what this box is held to", never "what it wrote"; the strict
/// declaration the record holds is never rewritten to say any of this, and
/// `GetSessionPolicy` is the reply that echoes it.
async fn serve_get_effective_session_policy(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    GetEffectiveSessionPolicy
        .handle_channel(c, async |req| {
            let opt_out = s.deny_all_opt_out().await;
            let mngr = s.sessions_manager().await;
            let predicate = match req {
                GetEffectiveSessionPolicyRequest::Id(id) => BoxKeyPredicate::Id(id),
                GetEffectiveSessionPolicyRequest::Name(name) => BoxKeyPredicate::Name(name),
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
                        boxes::EGRESS_DEFAULT_PHASE,
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
/// RPCs read the record: [`BoxManager::get_session`] brings a known session's
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
                minimald_rpc::GetLiveIngressRequest::Id(id) => BoxKeyPredicate::Id(id),
                minimald_rpc::GetLiveIngressRequest::Name(name) => BoxKeyPredicate::Name(name),
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
                GetSessionRuntimeFactsRequest::Id(id) => BoxKeyPredicate::Id(id),
                GetSessionRuntimeFactsRequest::Name(name) => BoxKeyPredicate::Name(name),
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
                    let host_ip_enforcement = crate::box_runtime::displayed_host_ip_enforcement(
                        s.in_microvm().await,
                        record.network,
                        classifier::verdict_of(record.policy.egress.as_ref()),
                        &crate::box_runtime::host_ip_enforcement_fact(),
                        record.host_ip_enforcement,
                    );
                    // The listen publishes the audit log refused (NET-046):
                    // a watcher-driven publish has no caller to answer, so
                    // the live actor's set is read here and `min session
                    // policy` warns per port. A session whose actor cannot
                    // answer has no watcher running, and nothing to warn
                    // about.
                    let unaudited_listen_ports =
                        match mngr.get_session(BoxKeyPredicate::Id(record.id)).await {
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
                    Ok(Errorable::Ok(minimald_rpc::BoxRuntimeFacts {
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
                minimald_rpc::GetSessionHooksRequest::Id(id) => BoxKeyPredicate::Id(id),
                minimald_rpc::GetSessionHooksRequest::Name(name) => BoxKeyPredicate::Name(name),
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
            let predicate = BoxKeyPredicate::Id(req.id);
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
                .get_screen(BoxKeyPredicate::Id(id))
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

/// How long a `WorkspaceFilesTarZst` upload may deliver no bytes before the
/// daemon gives up on it. A peer that stalls half-open would otherwise hold
/// the upload — and the attach refusal its in-flight mark carries — until
/// SSH keepalive notices, which takes up to an hour and a half. Generous,
/// because the client compresses as it reads and a large, highly
/// compressible file can leave the wire quiet for a while.
const WORKSPACE_UPLOAD_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Fails a read with `TimedOut` once the peer has kept it waiting for
/// `limit`. The clock starts when a read first finds no data and stops when
/// one completes, so only a stall counts — never the length of the whole
/// transfer, nor time the consumer spent busy between reads.
struct IdleDeadline<R> {
    inner: R,
    limit: std::time::Duration,
    deadline: Pin<Box<tokio::time::Sleep>>,
    /// Whether the last poll found no data, i.e. `deadline` is armed for the
    /// current wait.
    waiting: bool,
}

impl<R> IdleDeadline<R> {
    fn new(inner: R, limit: std::time::Duration) -> Self {
        Self {
            inner,
            limit,
            deadline: Box::pin(tokio::time::sleep(limit)),
            waiting: false,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for IdleDeadline<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(read) => {
                this.waiting = false;
                Poll::Ready(read)
            }
            Poll::Pending => {
                if !this.waiting {
                    this.waiting = true;
                    let until = tokio::time::Instant::now() + this.limit;
                    this.deadline.as_mut().reset(until);
                }
                match this.deadline.as_mut().poll(cx) {
                    Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("no upload data for {:?}", this.limit),
                    ))),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
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
/// and returns its handle and paths. Shared by the `Workspace*TarZst`
/// handlers — the ones that need per-session serialization or actor
/// coordination keep the handle too.
async fn upload_session_handle(
    s: &ServerStateHandle,
    config: &ChannelConfig,
) -> Result<(crate::box_actor::BoxHandle, crate::box_actor::BoxPaths), String> {
    let session_id_str = config
        .env_vars
        .get(crate::MINIMAL_SESSION_ID_ENV)
        .ok_or("missing env-var MINIMAL_SESSION_ID")?;
    let session_id =
        SessionId::parse_str(session_id_str).map_err(|e| format!("parsing session UUID: {e}"))?;

    let mngr = s.sessions_manager().await;
    let session_handle = mngr
        .get_session(BoxKeyPredicate::Id(session_id))
        .await
        .map_err(|e| format!("session UUID lookup failed: {e}"))?
        .ok_or("unknown session UUID")?;
    let paths = session_handle
        .paths()
        .await
        .map_err(|e| format!("session is gone: {e}"))?;
    Ok((session_handle, paths))
}

/// One `WorkspaceFilesTarZst` upload marked in flight on its session, so
/// attaches are refused until the mark is cleared. [`Self::finish`] clears
/// it and awaits the actor's ack; a guard dropped without finishing (a
/// panic, or the upload task torn down mid-stream) enqueues the clear
/// without awaiting it instead, so no exit path leaves the session refusing
/// attaches forever.
pub(crate) struct WorkspaceUploadInFlight(Option<crate::box_actor::BoxHandle>);

impl WorkspaceUploadInFlight {
    /// Marks the upload in flight. Refused, marking nothing, when the
    /// session is no longer unconfigured: an upload belongs to the create
    /// flow, ahead of the configure, and one into a composed or configured
    /// session's tree is not part of it.
    pub(crate) async fn begin(handle: crate::box_actor::BoxHandle) -> Result<Self, String> {
        handle
            .set_workspace_upload_in_flight(true)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotConnected => format!("session is gone: {e}"),
                _ => e.to_string(),
            })?;
        Ok(Self(Some(handle)))
    }

    pub(crate) async fn finish(mut self) -> Result<(), String> {
        let Some(handle) = self.0.take() else {
            return Ok(());
        };
        handle
            .set_workspace_upload_in_flight(false)
            .await
            .map_err(|e| format!("session is gone: {e}"))
    }
}

impl Drop for WorkspaceUploadInFlight {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.end_workspace_upload_detached();
        }
    }
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
    let (session_handle, paths) = upload_session_handle(s, config).await?;
    // Emitted once the upload has a destination and before a single byte is
    // pulled, so a transfer that wedges mid-stream still leaves a record
    // saying which session it was for. Its pair is the complete/failed
    // record in the caller.
    tracing::info!("workspace upload started");

    // Bracket the unpack with the in-flight mark, and await both acks: the
    // Begin ack guarantees an attach that races the upload sees the mark
    // before the first byte lands, and the End ack fires before this
    // function reports, so the caller's outcome log never says complete
    // while an attach is still refused. Cleared on both arms — a failed
    // upload must not wedge the session behind a mark nothing clears —
    // and by the guard's drop if this future never reaches the clear (a
    // panic in the unpack, or the task being torn down mid-stream).
    let upload = WorkspaceUploadInFlight::begin(session_handle).await?;
    let unpacked = async_tar::Archive::new(async_compression::tokio::bufread::ZstdDecoder::new(
        tokio::io::BufReader::new(IdleDeadline::new(
            CountingReader {
                inner: c.make_reader(),
                count: Arc::clone(received),
            },
            WORKSPACE_UPLOAD_IDLE_TIMEOUT,
        )),
    ))
    .unpack(paths.working.as_utf8_path())
    .await;
    // The unpack error wins when both fail: a session destroyed mid-upload
    // fails the clear too, and "session is gone" would hide why the
    // unpack stopped.
    let cleared = upload.finish().await;
    unpacked.map_err(|e| format!("unpack failed: {e}"))?;
    cleared?;

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
    let swap_result = crate::traced::spawn_blocking({
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
/// [`staged_script_path`](boxes::core::lifecyclehook::staged_script_path)
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
    use tracing::Instrument as _;
    let span = tracing::info_span!(
        "rpc",
        rpc = name,
        telemetry = tracing::field::Empty,
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
        parent_span_id = tracing::field::Empty,
    );
    // With OTel export on, the exported span's ids are the ids; otherwise
    // adopt-or-mint exactly as before. The shared helper also notes the ids
    // for the mailbox messages this RPC sends (`traced::caller_context`),
    // and honours a client's opt-out (`MINIMAL_OTEL=off`): the span and
    // what it sends are then recorded nowhere.
    crate::exec::adopt_client_trace(&span, &config);

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
mod tests;

/// The spans an RPC's work runs in (TEL-021, TEL-022): the
/// `rpc` span adopts the client's `TRACEPARENT`, each mailbox message's
/// span is a child of its sender's, and a long-lived actor started by a
/// request does not hold that request's spans open. Export is off here, so
/// the ids are the ones `exec::adopt_trace` records for the file log.
#[cfg(test)]
mod trace_tests {
    use minimald_rpc::{CreateSession, DestroySession, DestroySessionRequest};
    use tracing_subscriber::layer::SubscriberExt as _;

    use crate::test_harness::{SpanLog, TestServer, create_session_req};

    const TRACE: &str = "0af7651916cd43dd8448eb211c80319c";
    const PARENT: &str = "b7ad6b7169203331";

    fn env() -> [(&'static str, &'static str); 1] {
        [(
            minimald_rpc::trace::TRACEPARENT_ENV,
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        )]
    }

    /// TEL-021 (daemon side), TEL-022: the `rpc` span is a child of
    /// the client's span; the manager message it sends is a child of the
    /// `rpc` span; the session message the manager sends on is a child of
    /// the manager's; all in the client's trace.
    #[tokio::test]
    async fn a_manager_and_a_session_message_are_children_of_their_senders() {
        let log = SpanLog::default();
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let id = client
            .call_with_env::<CreateSession>(&env(), &create_session_req("s", "/tmp"))
            .await
            .unwrap()
            .id;
        client
            .call_with_env::<DestroySession>(
                &env(),
                &DestroySessionRequest {
                    id,
                    only_if_unfinalized: false,
                },
            )
            .await
            .unwrap();

        let child_of = |child: &crate::test_harness::LoggedSpan,
                        parent: &crate::test_harness::LoggedSpan| {
            assert_eq!(child.field("trace_id"), Some(TRACE), "{child:?}");
            assert_eq!(
                child.field("parent_span_id"),
                parent.field("span_id"),
                "{} is a child of {}: {child:?} {parent:?}",
                child.name,
                parent.name
            );
        };
        let create = log.one("rpc", "rpc", "minimald-v1-CreateSession");
        assert_eq!(create.field("trace_id"), Some(TRACE));
        assert_eq!(create.field("parent_span_id"), Some(PARENT));
        child_of(
            &log.one("sessions.manager.message", "kind", "CreateSession"),
            &create,
        );
        let destroy = log.one("rpc", "rpc", "minimald-v1-DestroySession");
        let delete = log.one("sessions.manager.message", "kind", "DeleteSession");
        child_of(&delete, &destroy);
        child_of(&log.one("session.message", "kind", "Destroy"), &delete);
    }

    /// TEL-022: the session actor a CreateSession starts runs in
    /// a root span of its own, so the request's `rpc` and manager-message
    /// spans close once the RPC has answered while the actor lives on. They
    /// stayed open for the actor's whole life (a 313 s CreateSession message
    /// behind a 114 ms RPC).
    #[tokio::test]
    async fn a_request_span_closes_when_its_rpc_returns() {
        let log = SpanLog::default();
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        client
            .call_with_env::<CreateSession>(&env(), &create_session_req("s", "/tmp"))
            .await
            .unwrap();
        // The answer can reach the client a moment before the handler's
        // span is dropped: give it a bounded moment.
        let closed = || {
            log.one("rpc", "rpc", "minimald-v1-CreateSession").closed
                && log
                    .one("sessions.manager.message", "kind", "CreateSession")
                    .closed
        };
        for _ in 0..100 {
            if closed() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            closed(),
            "the request's spans are still open: {:#?}",
            log.spans()
        );
        let actors: Vec<_> = log
            .spans()
            .into_iter()
            .filter(|s| s.name == "session.actor")
            .collect();
        assert_eq!(actors.len(), 1, "{actors:?}");
        assert!(!actors[0].closed, "the actor lives on");
        assert!(actors[0].parent.is_none(), "the actor's span is a root");
    }
}

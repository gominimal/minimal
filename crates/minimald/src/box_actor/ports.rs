use super::*;

/// The control channel `switch`'s switch is reached on: its control
/// socket for a switch this daemon spawned, the host shuttle's vsock port
/// for the VM host's.
pub(crate) async fn switch_control_of(
    switch: &Mutex<crate::net::SwitchClient>,
) -> crate::net::policy::ControlChannel {
    let switch = switch.lock().await;
    match switch.transport() {
        crate::net::SwitchTransport::LocalSpawn => {
            crate::net::policy::ControlChannel::Unix(switch.control_socket())
        }
        crate::net::SwitchTransport::HostShuttle { cid, port } => {
            crate::net::policy::ControlChannel::Vsock { cid, port }
        }
    }
}

/// The rows `min session policy` lists as a box's live ingress (NET-044), by
/// the runtime surface that published them. Kept apart because the two are
/// read differently: a runtime expose binds before the box's relay gate
/// admits its port, so whether its row is reachable is read off the gate's
/// compile set when served, while a listen publication is admitted at the
/// gate as its own publish's last step, so its row is reachable as it
/// stands.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct LiveIngressRows {
    /// The box's own `min net expose` publications, in publish order.
    pub(crate) exposed: Vec<minimald_rpc::LiveMapping>,
    /// The listen watcher's publications of in-range listens under `allow`,
    /// in port order: one per listener still holding its port.
    pub(crate) listened: Vec<minimald_rpc::LiveMapping>,
    /// The permitted listening ports the listen watcher left unpublished
    /// because their audit record could not be written (NET-046), in port
    /// order — the warnings `min session policy` prints.
    pub(crate) unaudited_listen_ports: Vec<u16>,
}

/// The key an ask parks under (NET-045): minted per request the session
/// routes, never derived from the port — two concurrent requests can share a
/// port. The ask's continuation ([`BoxMessage::AskAnswered`]) carries it
/// back, so an answer reaches the ask it answers even when another ask on the
/// same port is parked ahead of it, and a late fail-closed answer for an ask
/// that already ended does not pop its neighbour instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AskId(u64);

/// How a routed ask ended (NET-045): the continuation's input, the same
/// for an ask this daemon's binding rendered and one the VM host daemon
/// asked the human attached on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AskEnd {
    /// The attached human answered.
    Answered(box_runtime::AskAnswer),
    /// Nobody answered: on a native host no binding, or a dialog that ended
    /// without a pick; on a VM-backed host no client attached when the ask
    /// arrived. The typed nobody-is-attached refusal.
    Unanswered,
    /// The host's attached client could not show the prompt: treated as
    /// the human's no.
    HostNoTty,
    /// The VM host daemon cancelled the ask before an answer, by `cause`.
    HostCancelled(minimald_rpc::AskCancelCause),
    /// The VM host daemon refused the ask for a reason that is not about
    /// who is attached: its row's ask queue was full, or the row's grant
    /// did not admit the ask.
    HostRefused(minimald_rpc::AskRefused),
    /// The VM host daemon could not be asked or did not answer the ask.
    HostUnreachable(String),
}

/// The binding's answer, or its absence: the native dialog's own ends.
impl From<Option<box_runtime::AskAnswer>> for AskEnd {
    fn from(answer: Option<box_runtime::AskAnswer>) -> Self {
        answer.map_or(Self::Unanswered, Self::Answered)
    }
}

impl AskEnd {
    /// The end the VM host daemon's reply names: the human's yes or no as
    /// the human's answer, the ends nobody answered as unanswered, and the
    /// host's own refusals as such.
    fn from_host(outcome: minimald_rpc::AskAdmitOutcome) -> Self {
        use minimald_rpc::AskRefused;
        match outcome {
            minimald_rpc::AskAdmitOutcome::Admitted { .. } => {
                Self::Answered(box_runtime::AskAnswer::Allowed)
            }
            minimald_rpc::AskAdmitOutcome::Refused { reason, cause, .. } => match reason {
                AskRefused::Denied => Self::Answered(box_runtime::AskAnswer::Refused),
                AskRefused::NoClient => Self::Unanswered,
                AskRefused::NoTty => Self::HostNoTty,
                // A cancellation always names its cause; one that does not
                // is a daemon that predates causes, said as its own stop.
                AskRefused::Cancelled => Self::HostCancelled(
                    cause.unwrap_or(minimald_rpc::AskCancelCause::MinvmdStopping),
                ),
                AskRefused::QueueFull
                | AskRefused::NoRow
                | AskRefused::StanceNotAsk
                | AskRefused::OutsideGrant => Self::HostRefused(reason),
            },
        }
    }
}

/// What the expose's failure says when the attached client could not show
/// the prompt (NET-045): the human's no, by default.
pub(super) const HOST_NO_TTY_REASON: &str =
    "the attached client could not show the prompt; treated as no";

/// A host cancellation as the expose's failure names it.
pub(super) fn host_ask_cancel_text(cause: minimald_rpc::AskCancelCause) -> String {
    match cause {
        minimald_rpc::AskCancelCause::LastDetach => {
            format!("the port prompt was cancelled: {cause}; nobody is attached any more")
        }
        _ => format!("the port prompt was cancelled: {cause}"),
    }
}

/// A host refusal as the expose's failure names it.
pub(super) fn host_ask_refusal_text(reason: minimald_rpc::AskRefused) -> &'static str {
    match reason {
        minimald_rpc::AskRefused::QueueFull => {
            "too many port prompts from this box are already waiting for an answer"
        }
        minimald_rpc::AskRefused::NoRow => {
            "this box's network addresses are not registered with the VM host daemon"
        }
        minimald_rpc::AskRefused::StanceNotAsk => {
            "the VM host daemon does not have this box's --dynamic-ingress set to ask"
        }
        minimald_rpc::AskRefused::OutsideGrant => {
            "the port is outside the --dynamic-range the VM host daemon holds for this box"
        }
        minimald_rpc::AskRefused::NoClient => "nobody is attached on the host to answer",
        minimald_rpc::AskRefused::Denied => "the person attached answered no",
        minimald_rpc::AskRefused::NoTty => "the attached terminal could not show the prompt",
        minimald_rpc::AskRefused::Cancelled => "the port prompt was cancelled before an answer",
    }
}

/// One runtime port-publish request this box decided `ask`, parked until the
/// attached human answers the dialog it was routed to (NET-045).
///
/// The caller's reply travels with it because the actor never answers the
/// request itself: it answers from [`BoxActor::resume_ask`] once the human
/// has, or fail-closed from [`BoxActor::stop_running`] when the session is
/// going away and nobody can. Keyed by [`AskId`] — the id the continuation
/// message carries back — so two asks for the same port each reach their own
/// asker however their answers arrive.
#[derive(Debug)]
pub(super) struct PendingAsk {
    /// The ask's key: the id its continuation carries back.
    pub(super) id: AskId,
    /// The port the box asked to publish.
    pub(super) port: u16,
    /// The box's record as it stood when the ask was routed: the publish an
    /// allow ends up running needs the address pair the box's registration
    /// handed it, and it is the same record the decision was made against.
    pub(super) record: Record,
    /// The box's name, resolved once at route time so the log line and the
    /// audit record (NET-046) name the same box the human's dialog named.
    pub(super) box_name: String,
    /// The caller's reply, answered by whichever way the ask ended.
    pub(super) reply:
        oneshot::Sender<Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>>,
    /// The task holding a VM host daemon ask open, aborted when the session
    /// answers the ask fail-closed on its way down: the abort closes the
    /// ask's connection, which the host takes as its withdrawal. `None` for
    /// an ask this daemon's binding renders.
    pub(super) host_ask: Option<tokio::task::AbortHandle>,
}

impl BoxActor {
    /// Publishes `port` for this box at runtime (NET-043): the request a
    /// process inside the box sends with its own `min net expose`, decided
    /// against the box's `dynamic_ingress` setting and — when it allows —
    /// bound on the switch and recorded as a live mapping (NET-044), which is
    /// what `min session policy` lists beside the declaration.
    ///
    /// Takes the caller's reply by value because it does not always answer it:
    /// a request the box decided `ask` is routed to the attached human
    /// (NET-045) and parked — with the reply — until they have answered, and
    /// the actor must not park with it, or every probe, read, and shutdown
    /// behind this one would wait on a human. The parked request comes back
    /// through [`BoxMessage::AskAnswered`]. Everything else is finished
    /// here, through [`Self::answer_expose`], which writes the one info line
    /// every request logs and the decision's own audit record (NET-046)
    /// beside it.
    ///
    /// The one path this actor cannot name a box on is a record that does not
    /// read — the box's name lives in it — so that path answers its own typed
    /// failure, and the env channel, which knows the name without the record,
    /// writes the info line that request owes the log.
    pub(super) async fn expose_dynamic(
        &mut self,
        port: u16,
        reply: oneshot::Sender<
            Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>,
        >,
    ) {
        use crate::net::policy::ExposeFailure;

        let record = match self.record.record().await {
            Ok(record) => record,
            // The request could not be read back to be decided, so no
            // decision was made and there is nothing to audit (NET-046): the
            // typed failure is the whole answer, and the env channel writes
            // the info line, naming the box from its own copy of the name.
            Err(e) => {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the asker may already be gone; there is nothing to answer then"
                )]
                let _ = reply.send(Err(ExposeFailure::RecordUnreadable { port, source: e }));
                return;
            }
        };
        let box_name = record.name.clone().unwrap_or_else(|| record.id.to_string());
        // A host-address box is answered before its stance is read: it
        // shares the host's network, so the port already answers there, and
        // its record can carry no `dynamic_ingress` (the policy validation
        // refuses one), so the stance check could only ever deny it — true
        // of the setting, and wrong about the port. No decision is made, so
        // nothing is audited (NET-046); the request's one info line says
        // what became of it.
        if record.network == boxes::NetworkMode::HostNet {
            // Where the port answers: the name always; the host's loopback
            // only natively, since on a VM-backed host the loopback the box
            // shares is the guest's (NET-129).
            let host_loopback =
                !crate::net::listeners::reports_to_vm_host(&self.switch_control().await);
            let refusal = crate::net::policy::ExposeRefusal::NeedsNoExposing {
                port,
                host_loopback,
            };
            tracing::info!(
                name = %box_name,
                port,
                network_mode = record.network.word(),
                outcome = "needs no exposing",
                reason = %refusal,
                "dynamic ingress expose"
            );
            #[expect(
                clippy::let_underscore_must_use,
                reason = "the asker may already be gone; there is nothing to answer then"
            )]
            let _ = reply.send(Err(ExposeFailure::Refused(refusal)));
            return;
        }
        // The setting the request is evaluated against (NET-043), spelled the
        // way the record carries it: the deny-all default for a box that
        // declared nothing.
        let decision = record
            .policy
            .ingress
            .as_ref()
            .and_then(|ingress| ingress.dynamic_ingress)
            .unwrap_or(boxes::DynamicIngress::Deny);
        // The box's own setting decides first (NET-043), whatever asked: the
        // deny-all default when nothing was declared, the range gate under an
        // `allow`, and an `ask` handed to whoever is attached (NET-045).
        match crate::net::policy::dynamic_ingress_decision(record.policy.ingress.as_ref(), port) {
            Err(crate::net::policy::ExposeRefusal::AskNeedsAnswer) => {
                self.route_ask(record, box_name, port, reply).await;
            }
            decided => {
                // The only decision that passes the gate is the box's own
                // `allow`, so an `Ok` here is one; every other refusal was
                // made with the switch asked nothing (NET-047).
                let outcome = match decided {
                    Ok(_) => {
                        self.publish_exposed_port(
                            &record,
                            port,
                            minimald_rpc::PortReportSource::Expose,
                        )
                        .await
                    }
                    Err(refusal) => Err(ExposeFailure::Refused(refusal)),
                };
                self.answer_expose(
                    &box_name,
                    port,
                    decision,
                    crate::audit::DecidedBy::BoxPolicy,
                    outcome,
                    reply,
                )
                .await;
            }
        }
    }

    /// Routes a runtime port-publish request the box decided `ask` to whoever
    /// is attached (NET-045): the host's binding renders the exit prompt's own
    /// dialog, and the human's answer decides the request.
    ///
    /// The ask itself runs off the actor, on a spawned task: the human's
    /// answer is the only bound it has, and parking the actor on it would
    /// hang `min session policy` reads, manager probes, and a daemon shutdown
    /// behind a dialog nobody may be looking at. It comes back as
    /// [`BoxMessage::AskAnswered`], which answers the parked reply.
    ///
    /// Nobody attached is not an error to route — it is the ask's own
    /// fail-closed answer, decided by the daemon, and it goes through the
    /// same continuation ([`Self::resume_ask`]) so every ask ends on the one
    /// path that writes the log line and the audit record (NET-046).
    ///
    /// On a VM-backed host the binding renders nothing: the human who
    /// answers is the one attached on the host, so the ask goes to the VM
    /// host daemon over the report door ([`crate::net::listeners::report_ask`])
    /// and its reply is the answer, with no deadline. A yes there was
    /// recorded in the box's host row, so the publish that follows reports
    /// nothing again. The native path is unchanged.
    pub(super) async fn route_ask(
        &mut self,
        record: Record,
        box_name: String,
        port: u16,
        reply: oneshot::Sender<
            Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>,
        >,
    ) {
        // The dialog needs a host with somebody attached to render it. No
        // host running means the same thing as nobody attached — there is no
        // human to ask — so it is answered fail-closed right here rather than
        // routed to a continuation that would only come back with the same
        // answer.
        let host = match &self.inner {
            BoxInner::Active {
                host: Some((host, _)),
                ..
            } => host.clone(),
            _ => {
                self.answer_expose(
                    &box_name,
                    port,
                    boxes::DynamicIngress::Ask,
                    crate::audit::DecidedBy::Daemon,
                    Err(crate::net::policy::ExposeFailure::Refused(
                        crate::net::policy::ExposeRefusal::AskNeedsAnswer,
                    )),
                    reply,
                )
                .await;
                return;
            }
        };
        // On a VM-backed host the human who answers is the one attached on
        // the host, and the VM host daemon asks them (NET-045): this
        // daemon's binding renders nothing, and the ask crosses the report
        // door as the row key, the port and the protocol. The row key is
        // the switch address the host handed the box; a box the host never
        // handed one holds no row there to ask about.
        let control = self.switch_control().await;
        let host_switch_address = if crate::net::listeners::reports_to_vm_host(&control) {
            let Some(addresses) = record.box_addresses else {
                self.answer_expose(
                    &box_name,
                    port,
                    boxes::DynamicIngress::Ask,
                    crate::audit::DecidedBy::Daemon,
                    Err(crate::net::policy::ExposeFailure::Refused(
                        crate::net::policy::ExposeRefusal::NotAttached,
                    )),
                    reply,
                )
                .await;
                return;
            };
            Some(addresses.switch_address)
        } else {
            None
        };
        // Minted before the park, not derived from the port: two asks can
        // share a port, and the continuation below keys on this so each
        // answer reaches the ask it answers however their answers arrive.
        let id = AskId(self.next_ask_id);
        self.next_ask_id += 1;
        let weak = self.weak_self.clone();
        let host_ask = match host_switch_address {
            Some(switch_address) => {
                let task = crate::traced::spawn(async move {
                    let end =
                        match crate::net::listeners::report_ask(&control, switch_address, port)
                            .await
                        {
                            Ok(outcome) => AskEnd::from_host(outcome),
                            Err(error) => {
                                tracing::warn!(
                                    port,
                                    reason = %error,
                                    "the VM host daemon did not answer the ask; it fails closed"
                                );
                                AskEnd::HostUnreachable(error.to_string())
                            }
                        };
                    if let Some(handle) = weak.upgrade() {
                        handle.ask_answered(id, port, end).await;
                    }
                });
                Some(task.abort_handle())
            }
            None => {
                crate::traced::spawn(async move {
                    let answer = host.ask_expose(port).await;
                    // A session that already went away has already answered
                    // its pending asks fail-closed (`stop_running`), so a
                    // handle that will not promote is the normal end of a
                    // late answer.
                    if let Some(handle) = weak.upgrade() {
                        handle.ask_answered(id, port, answer).await;
                    }
                });
                None
            }
        };
        // Parked after the spawn: the continuation arrives through this
        // actor's own mailbox, which this turn is still holding.
        self.pending_asks.push(PendingAsk {
            id,
            port,
            record,
            box_name,
            reply,
            host_ask,
        });
    }

    /// Continues a parked runtime port-publish ask (NET-045) with the attached
    /// human's answer — or its absence, which is the ask's own fail-closed
    /// refusal. The ask is found by its [`AskId`], not its port: two asks can
    /// share a port, and the answer is whatever the task the *ask* routed
    /// came back with. The pending request's reply is answered here and its
    /// decision audited (NET-046), whichever way it went: an allow runs the
    /// publish half against the record the ask was routed with, a deny is the
    /// box's own deny answer in the human's hand, and nobody attached is the
    /// typed nobody-is-attached refusal the request ends with.
    pub(super) async fn resume_ask(&mut self, id: AskId, port: u16, answer: AskEnd) {
        let Some(position) = self.pending_asks.iter().position(|ask| ask.id == id) else {
            // The ask already ended another way — the session answered it
            // fail-closed on its way down — or the asker went away. Nothing
            // is waiting on this answer, and no decision changes: said at
            // info like the answer it failed to be, because an answer the
            // audit cannot account for is the line that explains the port
            // that did not publish.
            tracing::info!(
                id = id.0,
                port,
                "a runtime port-publish answer arrived with no ask waiting for it"
            );
            return;
        };
        let ask = self.pending_asks.remove(position);
        let outcome = match &answer {
            // The human said allow: run the publish half. Everything that can
            // still refuse it runs there — a duplicate publish, a missing
            // address pair, a switch that would not bind — so even an
            // allowed ask can end refused, with the switch asked only now
            // (NET-047).
            AskEnd::Answered(box_runtime::AskAnswer::Allowed) => {
                let published = self
                    .publish_exposed_port(
                        &ask.record,
                        ask.port,
                        minimald_rpc::PortReportSource::Ask,
                    )
                    .await;
                // A VM host recorded the yes in the row before the publish
                // ran, so a publish refused before its bind gives the port
                // back there, leaving no partial mapping — unless the port
                // stands published already, whose admission the row's entry
                // is.
                if ask.host_ask.is_some()
                    && let Err(crate::net::policy::ExposeFailure::Refused(refusal)) = &published
                    && !matches!(
                        refusal,
                        crate::net::policy::ExposeRefusal::AlreadyPublished { .. }
                    )
                    && let Some(addresses) = ask.record.box_addresses
                {
                    let control = self.switch_control().await;
                    crate::net::listeners::unreport_port(
                        &control,
                        addresses.switch_address,
                        ask.port,
                        minimald_rpc::PortReportSource::Ask,
                    )
                    .await;
                }
                published
            }
            // The human said deny — or keyed a cancel (Ctrl-C, `q`, Escape),
            // which means the same thing: the box's own deny answer, now in
            // the human's hand. An input EOF is not this — a client that
            // went away did not answer — so it lands on the `None` below.
            AskEnd::Answered(box_runtime::AskAnswer::Refused) => {
                Err(crate::net::policy::ExposeFailure::Refused(
                    crate::net::policy::ExposeRefusal::DeniedByHuman,
                ))
            }
            // Nobody was attached to answer (NET-045's unwanted branch) — no
            // binding to render the dialog, or one that ended mid-dialog
            // without the human choosing, its reply sender dropped unsent: a
            // shed, a teardown, the host going away, an input EOF (the
            // client's channel going away with the dialog standing). The
            // typed refusal, decided by the daemon, because there was no
            // human deciding.
            AskEnd::Unanswered => Err(crate::net::policy::ExposeFailure::Refused(
                crate::net::policy::ExposeRefusal::AskNeedsAnswer,
            )),
            // The host's attached client could not show the prompt: the
            // deny an unanswerable dialog defaults to, said as such.
            AskEnd::HostNoTty => {
                tracing::info!(
                    port = ask.port,
                    reason = HOST_NO_TTY_REASON,
                    "the VM host daemon's ask ended without a prompt"
                );
                Err(crate::net::policy::ExposeFailure::Refused(
                    crate::net::policy::ExposeRefusal::AskNoTerminal,
                ))
            }
            // Cancelled at the host before an answer: nothing was recorded
            // and nothing is published; the cause says why.
            AskEnd::HostCancelled(cause) => Err(crate::net::policy::ExposeFailure::Publish {
                port: ask.port,
                source: std::io::Error::other(host_ask_cancel_text(*cause)),
            }),
            // The VM host daemon refused the ask before any human saw it:
            // nothing was recorded at the host and nothing is published.
            AskEnd::HostRefused(reason) => Err(crate::net::policy::ExposeFailure::Publish {
                port: ask.port,
                source: std::io::Error::other(format!(
                    "the VM host daemon refused the port prompt: {}",
                    host_ask_refusal_text(*reason)
                )),
            }),
            AskEnd::HostUnreachable(error) => Err(crate::net::policy::ExposeFailure::Publish {
                port: ask.port,
                source: std::io::Error::other(error.clone()),
            }),
        };
        let decided_by = match &answer {
            AskEnd::Answered(_) => crate::audit::DecidedBy::AttachedHuman,
            AskEnd::Unanswered
            | AskEnd::HostNoTty
            | AskEnd::HostCancelled(_)
            | AskEnd::HostRefused(_)
            | AskEnd::HostUnreachable(_) => crate::audit::DecidedBy::Daemon,
        };
        let because = matches!(answer, AskEnd::HostNoTty).then_some(HOST_NO_TTY_REASON);
        self.answer_expose_because(
            &ask.box_name,
            ask.port,
            boxes::DynamicIngress::Ask,
            decided_by,
            outcome,
            because,
            ask.reply,
        )
        .await;
    }

    /// Finishes one runtime port-publish request (or one parked ask now
    /// answered): one info line naming the box, the port, the decision the
    /// box's `dynamic_ingress` setting made, who actually decided it, the
    /// outcome, and — where the request met a publication, made or held —
    /// the publication's owner — the line a diagnostics bundle's daemon
    /// log tail carries every request with — and the decision's own audit
    /// record (NET-046) written beside it, then the caller's answer.
    pub(super) async fn answer_expose(
        &mut self,
        box_name: &str,
        port: u16,
        decision: boxes::DynamicIngress,
        decided_by: crate::audit::DecidedBy,
        outcome: Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>,
        reply: oneshot::Sender<
            Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>,
        >,
    ) {
        self.answer_expose_because(box_name, port, decision, decided_by, outcome, None, reply)
            .await;
    }

    /// [`Self::answer_expose`], with the audit record's reason said in
    /// `because`'s words when the refusal's own text would hide why: a
    /// VM host's no-tty end refuses with the plain deny, and its record
    /// says the client could not show the prompt.
    #[expect(
        clippy::too_many_arguments,
        reason = "answer_expose's arguments plus the one reason override"
    )]
    pub(super) async fn answer_expose_because(
        &mut self,
        box_name: &str,
        port: u16,
        decision: boxes::DynamicIngress,
        decided_by: crate::audit::DecidedBy,
        outcome: Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>,
        because: Option<&'static str>,
        reply: oneshot::Sender<
            Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>,
        >,
    ) {
        let state_dir = self
            .minimal_state_dir
            .as_utf8_path()
            .as_std_path()
            .to_path_buf();
        // An allow that stands is recorded before anything else is said
        // about it, and only a recorded one is answered as published
        // (NET-046): an allow whose record cannot be written is withdrawn and
        // answered as a failed publish, which the arms below then log and —
        // best-effort, like every refusal — audit like any other.
        let (outcome, recorded) = match outcome {
            Ok(mapping) => {
                let record = crate::audit::DecisionRecord {
                    ts: chrono::Utc::now().to_rfc3339(),
                    box_name: box_name.to_string(),
                    port,
                    decision,
                    decided_by,
                    outcome: crate::audit::DecisionOutcome::Published,
                    reason: None,
                };
                match crate::audit::try_append(&state_dir, &record).await {
                    Ok(()) => {
                        // The record is written, so the box's relay gate
                        // admits the port now, before the caller hears the
                        // publish (NET-044): an answered publish is
                        // reachable, never a bound forward the gate
                        // refuses. Nothing listening yet is answered by the
                        // box's own kernel with a reset, so no gate state
                        // waits on a listener, and a listener closing later
                        // never withdraws this admission — the box's stop
                        // does. A box with no relay gate (no switch
                        // attached) has nothing in front of it to admit
                        // through.
                        if let Some(gate) = self
                            .reported_switch_address
                            .and_then(crate::net::switch::live_gate)
                        {
                            gate.admit_exposed(port);
                        }
                        (Ok(mapping), true)
                    }
                    Err(error) => (
                        Err(self
                            .withdraw_unaudited(box_name, port, decision, error)
                            .await),
                        false,
                    ),
                }
            }
            refused => (refused, false),
        };
        let (audited, reason) = match &outcome {
            Ok(mapping) => {
                tracing::info!(
                    name = %box_name,
                    port,
                    decision = %decision,
                    decided_by = %decided_by,
                    outcome = "published",
                    local = %mapping.local,
                    owner = %crate::net::listeners::PublicationOwner::Expose.as_str(),
                    "dynamic ingress expose"
                );
                (crate::audit::DecisionOutcome::Published, None)
            }
            // The one refusal that names a publication: the port is held,
            // pending or published, by one of the box's two runtime
            // surfaces, and the reservation that refused the request carried
            // whose — this
            // surface's own on a true duplicate, the listen watcher's when
            // the box's process published first — so the line a diagnostics
            // bundle's log tail reads tells the two apart, without reading
            // the set back after the fact: the owner the refusal was
            // refused with is the owner that held the port at the refusal,
            // whoever holds it by the time this line is written.
            Err(crate::net::policy::ExposeFailure::Refused(
                refusal @ crate::net::policy::ExposeRefusal::AlreadyPublished { .. },
            )) => {
                let crate::net::policy::ExposeRefusal::AlreadyPublished { owner, .. } = refusal
                else {
                    unreachable!("matched AlreadyPublished above")
                };
                tracing::info!(
                    name = %box_name,
                    port,
                    decision = %decision,
                    decided_by = %decided_by,
                    outcome = "refused",
                    reason = %refusal,
                    owner = %owner.as_str(),
                    "dynamic ingress expose"
                );
                (
                    crate::audit::DecisionOutcome::Refused,
                    Some(refusal.to_string()),
                )
            }
            Err(crate::net::policy::ExposeFailure::Refused(refusal)) => {
                tracing::info!(
                    name = %box_name,
                    port,
                    decision = %decision,
                    decided_by = %decided_by,
                    outcome = "refused",
                    reason = %refusal,
                    "dynamic ingress expose"
                );
                (
                    crate::audit::DecisionOutcome::Refused,
                    Some(refusal.to_string()),
                )
            }
            Err(crate::net::policy::ExposeFailure::Publish { source, .. }) => {
                tracing::info!(
                    name = %box_name,
                    port,
                    decision = %decision,
                    decided_by = %decided_by,
                    outcome = "publish failed",
                    reason = %source,
                    owner = %crate::net::listeners::PublicationOwner::Expose.as_str(),
                    "dynamic ingress expose"
                );
                (
                    crate::audit::DecisionOutcome::PublishFailed,
                    Some(source.to_string()),
                )
            }
            // Neither reaches this path: the record-read failure is answered
            // in [`Self::expose_dynamic`] before a decision exists, and
            // `ActorGone` is what the asker's handle answers when this actor
            // dropped before replying. Logged and audited all the same, so
            // the one-line-per-request promise holds whatever calls this.
            Err(
                failure @ (crate::net::policy::ExposeFailure::RecordUnreadable { .. }
                | crate::net::policy::ExposeFailure::ActorGone { .. }),
            ) => {
                tracing::info!(
                    name = %box_name,
                    port,
                    decision = %decision,
                    decided_by = %decided_by,
                    outcome = "refused",
                    reason = %failure,
                    "dynamic ingress expose"
                );
                (
                    crate::audit::DecisionOutcome::Refused,
                    Some(failure.to_string()),
                )
            }
        };
        // A refusal is recorded best-effort: it already refused, and a record
        // that cannot be written must not undo it — that would open the port.
        if !recorded {
            let reason = because.map(str::to_string).or(reason);
            crate::audit::append(
                &state_dir,
                &crate::audit::DecisionRecord {
                    ts: chrono::Utc::now().to_rfc3339(),
                    box_name: box_name.to_string(),
                    port,
                    decision,
                    decided_by,
                    outcome: audited,
                    reason,
                },
            )
            .await;
        }
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the asker may already be gone; there is nothing to answer then"
        )]
        let _ = reply.send(outcome);
    }

    /// Fails an allow closed whose audit record could not be written
    /// (NET-046): the publish that stood is withdrawn — the gate's admission
    /// taken first, then the forward unbound, then the port given back in
    /// the box's publication set, then the VM host daemon's row withdrawn,
    /// because the host's gate retracts
    /// a runtime port only while the row still holds it — and the caller
    /// hears a failed publish that says why. The warn line is the refusal's
    /// record of last resort: the audit log that refused the allow may
    /// refuse the refusal too.
    ///
    /// The withdrawal is fallible, and the forward is *retained* until it
    /// takes: an unexpose the switch refuses leaves a forward standing that
    /// nothing else names, so taking it out of the set here would leave the
    /// switch exposing a port whose allow was never recorded and nothing
    /// able to unexpose it again — the box's stop sweep
    /// ([`Self::stop_running`]) and the spawn's teardown both draw their
    /// retries from [`Self::live_ingress`]. The box's publication-set entry
    /// and the VM host daemon's row entry are held back with it: a row
    /// withdrawn while its forward still stands leaves the host holding a
    /// port its retraction rule can no longer reach, so the withdrawal
    /// follows the unexpose the way it does everywhere else. The one forward
    /// that cannot be kept is one whose spawn ended mid-unbind: the cell
    /// refuses it back, so it is unbound once more, best-effort, and the
    /// port is given back like every detached publish's.
    pub(super) async fn withdraw_unaudited(
        &mut self,
        box_name: &str,
        port: u16,
        decision: boxes::DynamicIngress,
        error: std::io::Error,
    ) -> crate::net::policy::ExposeFailure {
        tracing::warn!(
            name = %box_name,
            port,
            decision = %decision,
            error = %error,
            "the dynamic ingress allow could not be audited; the publish is \
             withdrawn and the request refused"
        );
        // The surface the publish reported under: an answered ask was
        // recorded at the host as one (NET-045), every other allow is the
        // box's own expose.
        let source = if decision == boxes::DynamicIngress::Ask {
            minimald_rpc::PortReportSource::Ask
        } else {
            minimald_rpc::PortReportSource::Expose
        };
        let control = self.switch_control().await;
        let live = self.live_ingress.take(port);
        // The gate refuses the port before the forward comes down (NET-044),
        // the same order the box's stop takes every publication in. The
        // publish admits only after its record is written, so an unaudited
        // allow was never admitted and this is a no-op kept as the
        // fail-closed backstop: an allow refused cannot be crossed while
        // its forward unbinds. A relay already gone took its gate with it.
        if let Some(gate) = self
            .reported_switch_address
            .and_then(crate::net::switch::live_gate)
        {
            gate.withdraw_exposed(port);
        }
        let mut unbound = true;
        if let Some(mut live) = live {
            match crate::net::policy::unexpose_forwarder(&control, &live.forwarder).await {
                // Unbound: the switch holds no forward at its `local` any
                // more, so the row entry and the publication-set entry go
                // with it below.
                Ok(()) => {}
                Err(unexpose) => {
                    tracing::warn!(
                        name = %box_name,
                        port,
                        error = %unexpose,
                        "the unaudited publish's forward could not be unbound; \
                         it stays recorded for the box's stop to unbind again"
                    );
                    unbound = false;
                    // The forward stays recorded, and the row entry with
                    // it: the host's gate retracts a runtime port only while
                    // the row still holds it, so a withdrawal that ran
                    // first would strand the forward — bound, and
                    // retractable by nothing. Recorded back, mapping and
                    // all, rather than never taken, because the sweep that
                    // would retry the unexpose — [`Self::stop_running`] —
                    // draws from the same cell. The gate refuses the port,
                    // so the row it lists reads pending, never reachable:
                    // `min session policy` must not show a refused port as
                    // admitted (NET-044).
                    live.mapping.pending = Some(true);
                    if let Err(unrecorded) = self.live_ingress.record(live) {
                        // The spawn ended while this withdrawal was in
                        // flight, so the cell refuses the record and the
                        // guard that emptied it cannot unbind this one —
                        // we still hold it. Best-effort, like every other
                        // unwind's unexpose; then the port is given back
                        // below, as every detached publish's is: no sweep
                        // is left to retry it, so holding the publication
                        // and the row back would only strand them.
                        crate::net::policy::remove_ingress(
                            &control,
                            std::slice::from_ref(&unrecorded.forwarder),
                        )
                        .await;
                        unbound = true;
                    }
                }
            }
        }
        if unbound {
            self.publications
                .withdraw(port, crate::net::listeners::PublicationOwner::Expose);
            if let Some(switch_address) = self.reported_switch_address {
                crate::net::listeners::unreport_port(&control, switch_address, port, source).await;
            }
        }
        crate::net::policy::ExposeFailure::Publish {
            port,
            source: std::io::Error::new(
                error.kind(),
                format!("the decision could not be recorded in the audit log: {error}"),
            ),
        }
    }

    /// The publish half of a runtime port-publish request (NET-043): the
    /// live-box check, the box-detached check, the address pair the publish
    /// needs, and the switch bind — the port *reserved* in the box's shared
    /// publication set before the bind and *recorded* once it stood, so the
    /// duplicate check the set answers is atomic with the hold it makes.
    /// The set names a port published by this surface or by the listen
    /// watcher the launch started, whichever got there first. Everything
    /// the box can refuse without asking the switch runs first, so a
    /// refused request is refused with nothing bound and nothing asked
    /// (NET-047). On a VM-backed host the VM host daemon's grant is asked
    /// next (T94, NET-138): `source` names the runtime surface the report
    /// carries — the expose request, an answered ask — and a publish its
    /// grant refuses asks the switch nothing, because the egress gate in
    /// front of the switch admits a bind only for a port the grant holds.
    /// Only then is the switch asked to bind, and the forwarder is recorded
    /// only once it accepted; a publish that does not stand from there
    /// withdraws its report again.
    pub(super) async fn publish_exposed_port(
        &mut self,
        record: &Record,
        port: u16,
        source: minimald_rpc::PortReportSource,
    ) -> Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure> {
        use crate::net::policy::{ExposeFailure, ExposeRefusal, expose_dynamic};

        // A publish needs a box standing behind it. A stopped box's record
        // still reads `active` — Stop keeps the grant, the publish row and
        // the record (NET-013) — but the actor this request reached holds no
        // host, and a forward bound for its lease would name an address
        // nothing answers for. Refused here, before the registry is read or
        // the switch asked anything, so a stopped box asks nothing and
        // holds nothing (NET-047); starting the box again is what fixes it.
        if !self.has_live_host() {
            return Err(ExposeFailure::Refused(ExposeRefusal::NotRunning));
        }

        // The lease is per-spawn: the registry keeps the last one reported
        // until the box is destroyed, so a spawn that has ended leaves it
        // behind. The runtime cell knows the spawn ended — its guard's
        // teardown detached it — and a forward to the dead lease would
        // deliver wherever the switch hands that address next. This runs
        // *before* the publication set is read, not after: between a
        // spawn's end and the next launch the actor still holds the ended
        // spawn's set, and an entry standing in it is stale the way the
        // lease is — a publish in that window must answer what detached
        // it, not the duplicate a dead spawn's entry claims.
        if self.live_ingress.is_detached() {
            return Err(ExposeFailure::Refused(ExposeRefusal::NotAttached));
        }

        // The publish rides the address the box's declared ports bind at and
        // its name answers at (NET-010): the hostname registry's published
        // own address, the one source the declared path reads too, through
        // `OwnAddressReporter::published_address`. Never the raw handed
        // loopback address: a hand the loopback verdict has not vouched for
        // publishes at the `127.0.0.1` interim (NET-123 §7.1), and a hand a
        // landed verdict overrules is moved off by the landing's sweep — the
        // registry row is the address that actually binds, so the runtime
        // publish and the declaration answer at the one address a connection
        // reaches. The hand's `switch_address` (T66) — or, for a native
        // host's self-allocated box, the lease its running PTask reported
        // (design §7.1) — is what the forward delivers to, and it is taken
        // from the record and the registry without preference between the
        // two ways a box came by it.
        //
        // The two halves are refused apart, so the box's `min net expose`
        // says which one is missing: nothing published is a capability gap —
        // the daemon has no default of its own to stand in with (NET-010),
        // so the request is refused rather than bound at an address nobody
        // chose for this box — while no lease is a box not attached yet,
        // which starting it fixes.
        let (loopback_address, switch_address) = {
            let registry = self
                .hostnames
                .read()
                .expect("hostname registry lock poisoned");
            let Some(published) = registry.published_own_address(record.id) else {
                return Err(ExposeFailure::Refused(ExposeRefusal::NoPublishedAddress));
            };
            let switch_address = match record.box_addresses {
                Some(addresses) => addresses.switch_address,
                None => {
                    let Some(lease) = registry.own_lease(record.id) else {
                        return Err(ExposeFailure::Refused(ExposeRefusal::NotAttached));
                    };
                    lease
                }
            };
            (published, switch_address)
        };

        let control = self.switch_control().await;
        // The port is reserved in the box's publication set — the check and
        // the hold in one step — *before* the switch is asked to bind: the
        // set is the one both runtime surfaces read, and the other surface,
        // the listen watcher this box's launch started (NET-016), can be
        // binding this very port across the await below. Whichever surface
        // reserves second is refused here, naming the owner that holds the
        // port — pending or published — so it never asks the switch at all:
        // the port is bound once, by whichever reservation won, and a
        // second forward never doubles the box's own address. The guard
        // gives the port back on every end but `record` — a bind that
        // fails, a box that stopped under the bind, a request cancelled
        // mid-publish — each by the guard's own token, so a release never
        // touches whatever holds the port since.
        let reservation = match self
            .publications
            .reserve(port, crate::net::listeners::PublicationOwner::Expose)
        {
            Ok(reservation) => reservation,
            Err(held) => {
                return Err(ExposeFailure::Refused(ExposeRefusal::AlreadyPublished {
                    port,
                    owner: held.owner,
                    pending: !held.published,
                }));
            }
        };
        // The VM host daemon's grant decides the publish before the switch
        // is asked to bind it (T94, NET-138): on a VM-backed host the egress
        // gate in front of the switch admits a forward only for a port the
        // box's host-side row holds, and the report is what puts a runtime
        // port in that row — so a bind asked first is refused at the gate
        // with no reply at all. A report the grant refuses — or a door that
        // never answers it, fail-closed, because a publish the host never
        // vouched for is not one to stand against its grant either —
        // publishes nothing: the reservation releases itself, the switch was
        // asked nothing, and the caller hears the publish failed, carrying
        // the reason it failed. A reply lost after the host recorded the port
        // is withdrawn again by the report itself before it answers,
        // best-effort. A native host has no report channel and reports
        // nothing: its publish stands, admitted by the switch alone, exactly
        // as it always did. Every end below that leaves the port unpublished
        // withdraws the report again once the forward is down — the gate
        // applies a runtime port's retraction only while the row holds it.
        //
        // An answered ask is the exception: on a VM-backed host the human's
        // yes was recorded in the row by the VM host daemon, and the ask's
        // own reply was the one admit it is consumed by (NET-045), so it is
        // not reported again — a guest's own admit report under `ask` is
        // refused by the grant. Its unwinds below still withdraw the port.
        let host_recorded = source == minimald_rpc::PortReportSource::Ask;
        if !host_recorded
            && let Err(report) =
                crate::net::listeners::report_admitted_port(&control, switch_address, port, source)
                    .await
        {
            tracing::warn!(
                session_id = %record.id,
                session_name = record.name.as_deref().unwrap_or(crate::rpc::ANONYMOUS_SESSION),
                port,
                source = ?source,
                reason = %report,
                "the VM host daemon did not admit the port report; the \
                 publish unwound"
            );
            return Err(ExposeFailure::Publish {
                port,
                source: report,
            });
        }
        self.reported_switch_address = Some(switch_address);
        let forwarder = match expose_dynamic(
            &control,
            loopback_address,
            switch_address,
            port,
            boxes::IpProto::Tcp,
            None,
        )
        .await
        {
            Ok(forwarder) => forwarder,
            // The reservation releases itself on the guard's drop here,
            // so a publish that failed leaves the port free and the set
            // empty of it: nothing was published, and the watcher's next
            // observation of the port publishes it normally (NET-047).
            Err(source_error) => {
                crate::net::listeners::unreport_port(&control, switch_address, port, source).await;
                return Err(ExposeFailure::Publish {
                    port,
                    source: source_error,
                });
            }
        };
        // Recorded only now, with the switch's acceptance in hand: a publish
        // that failed leaves nothing in the list (NET-047), so the rows the
        // policy surfaces read never name a port the switch is not holding.
        // The liveness read and the record push are one synchronous step —
        // nothing is awaited between them — so the stopped-box answer and the
        // push cannot disagree, and `stop_running`'s unexpose sweep (which
        // runs in this actor's own turn, over `take_all`) stays complete: a
        // box that went down in the window the bind was in flight has its
        // just-bound forward unbound here instead of recorded, so nothing
        // outlives the lease it delivers to. The reservation releases
        // itself with the forward: its entry was pending, so the set never
        // named the port as a mapping.
        let mapping = minimald_rpc::LiveMapping {
            local: forwarder.local().to_string(),
            internal_port: forwarder.internal_port(),
            proto: boxes::IpProto::Tcp,
            // Never pending: the box's relay gate admits the port in the
            // same turn the mapping is recorded (NET-044, below). `Some`,
            // never the unknown `None` that a reply from a daemon older
            // than the field decodes as.
            pending: Some(false),
        };
        if !self.has_live_host() {
            // Unexpose first, then withdraw the report: the host's gate
            // applies a runtime port's retraction only while the box's row
            // still holds the port, so a withdrawal that ran first would leave
            // the forward bound and unretractable.
            crate::net::policy::remove_ingress(&control, &[forwarder]).await;
            crate::net::listeners::unreport_port(&control, switch_address, port, source).await;
            return Err(ExposeFailure::Refused(ExposeRefusal::NotRunning));
        }
        // The bind stood, so the reservation commits as this surface's own
        // publication — a mapping from here, listed by the policy surfaces,
        // withdrawable by its publisher — and the watcher reading the same
        // set is answered with it on its next poll, so the port is never
        // asked of the switch again while this publication stands.
        if !reservation.record() {
            // A revocation cleared the reservation while the bind was in
            // flight, so it never saw this forward: this surface unbinds
            // the one it holds (design §7.1), and the caller hears the
            // box's spawn is gone, the answer a revoked publish shares with
            // the stale-spawn arm below.
            // Unexpose first, then withdraw the report: the host's gate
            // applies a runtime port's retraction only while the box's row
            // still holds the port, so a withdrawal that ran first would leave
            // the forward bound and unretractable.
            crate::net::policy::remove_ingress(&control, &[forwarder]).await;
            crate::net::listeners::unreport_port(&control, switch_address, port, source).await;
            return Err(ExposeFailure::Refused(ExposeRefusal::NotAttached));
        }
        if let Err(stale) = self
            .live_ingress
            .record(crate::net::provider::LiveIngressForward {
                forwarder,
                mapping: mapping.clone(),
            })
        {
            // The spawn ended while the bind was in flight, so the entry
            // this publish just committed names a forward that is coming
            // down: the set gives the port back with the forward it named.
            self.publications
                .withdraw(port, crate::net::listeners::PublicationOwner::Expose);
            crate::net::policy::remove_ingress(&control, &[stale.forwarder]).await;
            // The withdrawal follows the unexpose for the same reason as above:
            // the gate retracts a runtime port only while the row holds it.
            // The host admitted this port a moment ago, so the box's spawn
            // ending takes the admission with it: the row the report put in
            // names a forward that is gone, and the withdrawal report clears
            // it — best-effort, like the unexpose beside it, because there
            // is no caller left to propagate a failure to.
            crate::net::listeners::unreport_port(&control, switch_address, port, source).await;
            return Err(ExposeFailure::Refused(ExposeRefusal::NotAttached));
        }
        // The publish stands, but the box's relay gate does not admit the
        // port here: an allow is admitted only once its `Published` record
        // is written (NET-046), so the admission is
        // [`Self::answer_expose_because`]'s, made right after the record —
        // every caller that gets this mapping ends there. Until then the
        // forward is bound and the gate refuses it, so nothing crosses an
        // allow the audit log has not taken.
        //
        // The gate's sets are keyed by the box's internal port. The answer
        // admits `port`, and the stop withdraws `forwarder.internal_port()`;
        // the two agree only because an expose binds the same number on
        // both sides. A host-port remap would split them and leave the
        // admission behind, so the assert pins them to the one
        // internal-port space.
        debug_assert_eq!(
            mapping.internal_port, port,
            "the admitted port must be the forward's internal port, the one the stop withdraws"
        );
        Ok(mapping)
    }

    /// Binds the forward of a shared-address port this box took over while
    /// it runs (NET-129): the port's holder was destroyed, moved off the
    /// address or stopped naming the port, and the registry elected this
    /// box. Its attach skipped the port while it yielded, so nothing is
    /// bound for it until this, or until its next attach.
    ///
    /// Nothing is asked for a box with no host running or whose spawn has
    /// ended: that box holds the port of record and its next attach binds
    /// it. Nothing is asked either when the registry no longer names this
    /// box the port's holder at `address`, since the hand-over is read
    /// after other changes may have landed.
    ///
    /// A bind that fails is logged and changes nothing: the box still holds
    /// the port of record, no forward is tracked, and the box's next attach
    /// binds the port as it would have without the hand-over. A bind that
    /// stands is tracked with the spawn it delivers to, so the box's stop
    /// or its spawn's end releases it as it releases the forwards the
    /// attach bound, and the port is recorded as one this box bound.
    #[cfg(target_os = "linux")]
    pub(super) async fn bind_handed_port(&mut self, address: std::net::Ipv4Addr, port: u16) {
        use crate::net::policy::HandedBind;

        if !self.has_live_host() || self.live_ingress.is_detached() {
            return;
        }
        let Ok(record) = self.record.record().await else {
            return;
        };
        let mappings: Vec<boxes::PortMapping> = record
            .policy
            .ingress
            .iter()
            .flat_map(|ingress| &ingress.port_mappings)
            .filter(|mapping| mapping.external_port == port)
            .cloned()
            .collect();
        let switch_address = {
            let registry = self
                .hostnames
                .read()
                .expect("hostname registry lock poisoned");
            if !registry.holds_shared_port(record.id, address, port) {
                return;
            }
            match record.box_addresses {
                Some(addresses) => Some(addresses.switch_address),
                None => registry.own_lease(record.id),
            }
        };
        let Some(switch_address) = switch_address else {
            return;
        };
        let control = self.switch_control().await;
        let gate = crate::net::switch::live_gate(switch_address);
        let mut bound_any = false;
        let mut refused_any = false;
        for mapping in &mappings {
            let local = format!("{address}:{port}");
            if self.live_ingress.holds_handed(address, mapping) {
                continue;
            }
            let bind = crate::net::policy::bind_handed_port(
                &control,
                address,
                switch_address,
                mapping,
                gate.as_ref(),
            )
            .await;
            let (forwarder, held_by_host) = match bind {
                Ok(HandedBind::Bound(forwarder)) => (forwarder, false),
                Ok(HandedBind::HeldByHost(forwarder)) => (forwarder, true),
                Err(error) => {
                    tracing::warn!(
                        session_id = %record.id,
                        session_name = record.name.as_deref().unwrap_or(crate::rpc::ANONYMOUS_SESSION),
                        %local,
                        %error,
                        action = "shared-address-port-hand-over",
                        "binding the shared-address port this box took over failed; \
                         the box still holds it, and its next attach binds it"
                    );
                    refused_any = true;
                    continue;
                }
            };
            if let Err(stale) = self.live_ingress.record_handed(forwarder) {
                // The spawn ended while the bind was in flight: the forward
                // delivers to a lease that is gone, so it comes down here.
                crate::net::policy::release_declared_ingress(&control, &[stale]).await;
                return;
            }
            bound_any = true;
            tracing::info!(
                session_id = %record.id,
                session_name = record.name.as_deref().unwrap_or(crate::rpc::ANONYMOUS_SESSION),
                %local,
                held_by_host,
                action = "shared-address-port-hand-over",
                "bound the shared-address port this box took over while it runs"
            );
        }
        // A port one of whose forwards was refused is not recorded as
        // bound: the box's next attach binds it whole.
        if !bound_any || refused_any {
            return;
        }
        // The box bound the port, so a restarted daemon gives it back to
        // this box ([`Self::record_bound_ports`]). A write that fails costs
        // only that memory.
        let bound_ports = self
            .hostnames
            .write()
            .expect("hostname registry lock poisoned")
            .mark_held_ports_bound(record.id);
        if let Err(error) = self.record_bound_ports(bound_ports).await {
            tracing::warn!(
                session_id = %record.id,
                %error,
                "the hand-over could not record the shared-address port it bound; \
                 a daemon restart may hand it to another box"
            );
        }
    }

    /// The switch's control channel, read off the daemon's shared switch under
    /// a lock held only for the two sync reads — never across the publish it
    /// feeds.
    pub(super) async fn switch_control(&self) -> crate::net::policy::ControlChannel {
        switch_control_of(&self.net_switch).await
    }

    /// The live dynamic-ingress mappings — the rows `min session policy`
    /// lists beside the declaration (NET-044): the runtime exposes in
    /// publish order, from the runtime-ingress table that holds their
    /// forwarders, and the listen watcher's in-range publications in port
    /// order, from the publication set its watcher commits them to and
    /// withdraws them from.
    pub(super) fn live_ingress_snapshot(&self) -> LiveIngressRows {
        LiveIngressRows {
            exposed: self.live_ingress.snapshot(),
            listened: self.publications.listen_rows(),
            unaudited_listen_ports: self.publications.audit_refused(),
        }
    }

    /// Records on this session's record the published ports this launch
    /// bound forwards for (NET-129), when they differ from what the last
    /// launch recorded.
    #[cfg(target_os = "linux")]
    pub(super) async fn record_bound_ports(
        &self,
        bound_ports: std::collections::BTreeSet<std::net::SocketAddrV4>,
    ) -> Result<(), std::io::Error> {
        let mut record = self.record.record().await?;
        if record.bound_ports == bound_ports {
            return Ok(());
        }
        record.bound_ports = bound_ports;
        self.record.write(record).await
    }
}

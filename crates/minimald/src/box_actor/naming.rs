use super::*;

/// The write-lock promotion of a registration headed for the interim: the
/// hand to publish instead of `127.0.0.1` when the verdict now vouches for
/// it, or `None` to keep `published` as it stands. Called under the
/// registry's write lock, so the verdict and the name are read together
/// with the publish that follows. Only a publish standing at the interim
/// with a hand behind it moves, and never over a name another session holds.
pub(super) fn promote_interim_to_hand(
    reg: &crate::net::dns::HostnameRegistry,
    book: &crate::net::dns::LoopbackLeaseBook,
    session_id: boxes::SessionId,
    name: &str,
    published: Option<std::net::Ipv4Addr>,
    handed: Option<std::net::Ipv4Addr>,
) -> Option<std::net::Ipv4Addr> {
    match (published, handed) {
        (Some(std::net::Ipv4Addr::LOCALHOST), Some(hand))
            if book.vouches_for(hand) && !reg.name_held_by_another(session_id, name) =>
        {
            Some(hand)
        }
        _ => None,
    }
}

impl BoxActor {
    /// Register this session's PTask hostname (R3.1/R3.6). A HostNet PTask's
    /// listeners are on host loopback. An OwnIp PTask routes once the attach
    /// path has reported its lease — at spawn that report has not happened
    /// yet, so this registers nothing and the route appears when the box
    /// attaches (NET-001); on a rename or re-finalize the reported lease is
    /// already on file and the name re-registers against it, carrying the
    /// ports the session's ingress declaration publishes (NET-069) — an empty
    /// set, and so a deny-all gate, when the box declares no ingress: that is
    /// the posture its own relay gate gives a direct connection, and the
    /// proxy's must match on every host form (NET-071). A NoNet
    /// PTask exposes no services, so it is not registered — and neither is a
    /// `Draft` session, which has nothing to route to until its composition
    /// finalizes.
    ///
    /// An `OwnIp` PTask is also recorded as the *caller* a proxied request
    /// from it is checked against (NET-070): its egress declaration, over the
    /// switch its own relay is attached to, is kept until the box's lease
    /// joins onto it, and the rules built there are the ones its own outbound
    /// frames are decided by on the switch
    /// ([`crate::net::switch::compiled_egress`] over the switch's subnet, so
    /// the resolver carve-out matches too, and with the box's lease, so the
    /// verdict's source check does too — NET-084), so a request from the box
    /// through the hostname proxy meets its own declaration — exactly what a
    /// direct connection from it meets (NET-071).
    ///
    /// `wait_for_verdict` is whether a hand the range verdict has not
    /// vouched for may wait for it ([`Self::hand_or_interim`]): only the
    /// box's first finalize does, inside its own actor. Every other
    /// registration — the pre-live one [`Self::run`] makes from the
    /// manager's message handling, a rename — publishes such a hand at the
    /// `127.0.0.1` interim at once, and the present landing moves it.
    #[cfg(target_os = "linux")]
    pub(super) async fn register_hostname(
        &self,
        record: &Record,
        wait_for_verdict: bool,
    ) -> Vec<crate::net::dns::SharedPortCollision> {
        if !self.owns_hostname_route(record) {
            return Vec::new();
        }
        let name = registry_name(record);
        // The hostname proxy's port for the box's own-address set (design
        // §7.1): resolved through the serving transition (see
        // [`crate::net::hostname_proxy_serving_port`]) so a registration
        // racing the proxy's detached startup cannot compile the seeded —
        // possibly relocated (NET-025) — port into the node's opening. Only a
        // registration that may wait (`wait_for_verdict`) waits for it: the
        // others run inside the manager's own message handling, where a
        // wait would park every other session's operation, so they read the
        // port only if it is already settled and fail closed otherwise. What
        // that withholds is the caller check's reach to the node address at
        // the proxy's own port — a proxied request back at the proxy — never
        // the box's relay opening, which the attach path resolves itself.
        // Scoped: the switch lock is dropped before the registry is taken, so
        // no path holds both.
        let (subnet, settled_port, unsettled) = {
            let switch = self.net_switch.lock().await;
            (
                switch.subnet(),
                switch.serving_hostname_proxy_port(),
                switch.hostname_proxy_unsettled(),
            )
        };
        // Only an `OwnIp` box carries the opening: a `HostNet` one never
        // waits for it. The wait does not count the box as stranded: this
        // is the caller check's copy, not the box's relay opening, which
        // the attach path resolves (and counts) itself.
        let hostname_proxy_port = match record.network {
            boxes::NetworkMode::OwnIp if wait_for_verdict => {
                crate::net::hostname_proxy_serving_port(&self.net_switch, None).await
            }
            boxes::NetworkMode::OwnIp if unsettled => {
                // Said, not silent: this registration keeps no opening at
                // the node address for the caller check until the session
                // re-registers (a rename, a re-finalize, a restart).
                tracing::info!(
                    session = %record.id,
                    "the hostname proxy is not serving yet; this session's \
                     caller check is registered with no node-address opening \
                     (design §7.1)"
                );
                settled_port
            }
            _ => settled_port,
        };
        let mut shared_port_collisions = Vec::new();
        match record.network {
            boxes::NetworkMode::OwnIp => {
                // NET-010/NET-011: finalize publishes the box's declaration
                // at a host loopback address of its own — the one the VM
                // host daemon handed the box's registration (T66), or one an
                // earlier finalize published and the registry kept by the
                // stable session id across a rename, a restart of the actor,
                // or a restart of the daemon — so the name answers from
                // here to destroy, whether or not a client ever attaches
                // (NET-013).
                //
                // A box nobody handed an address — a native launch, whose
                // creator is the daemon itself, or a VM lane whose client
                // spelled no provider to register with — is still owed a
                // publish (NET-040: a fresh install's `--network own_ip
                // --ingress` publishes on the host), so finalize asks the
                // answerer for one: the host-global allocation NET-010
                // names, arbitrated through the answerer's authenticated
                // channel, which no daemon self-assigns beside. The grant is
                // not the daemon choosing an address — the answerer's one
                // lease record chooses it, and the release at destroy hands
                // it back — and it is not a substitute either: it is asked
                // before any forwarder binds, so the binds and the name
                // answer at the one address it granted. A grant withheld for
                // a fault — a spent pool, an unreadable record — publishes
                // nothing and registers no name, and the attach of a box
                // that declared ingress fails with "no published address
                // handed" rather than binding forwards at an address nobody
                // granted; a grant withheld for the host's surface — an
                // absent range, a verdict still walking — publishes the box
                // on the `127.0.0.1` interim (NET-123), so the binds and
                // the name answer at the one address the host can listen
                // on.
                //
                // The address is asked for **before** the registry's write
                // lock, and never underneath it: the ask is a synchronous
                // read-modify-write of the answerer's record under its lock
                // file, and this daemon's registry is what every DNS answer
                // it serves reads — holding one across another daemon's
                // in-flight grant would stall the answers for the length of
                // the stall, and the registry is never held across the
                // record, so the two orders cannot cycle either way. A box
                // that already published one — a rename, a resume — is
                // answered from the registry alone, without asking, so no
                // ask is logged on its account — unless what it published is
                // one of the two publishes that are not the box's own
                // address: the `127.0.0.1` interim, and a reserved-range
                // address a landed verdict has since overruled. Those ask
                // again (the two filters below), so the interim cannot
                // outstay the window that made it and no box holds an
                // address the surface cannot bind; and two paths that both
                // miss and both ask are still safe, the ask idempotent by
                // namespace and answered with the address the first one
                // recorded.
                //
                // A VM-backed box publishes at the address the VM host
                // daemon handed its registration (T66) — the host's slice of
                // the reserved local range, not a grant this daemon's in-guest
                // book could hand out — so the handed address stands in for
                // the lease before the lease is ever asked for, and the
                // attach path's expose requests name exactly it as their
                // `local`. It is never drawn from the pool: the host-side
                // table's row owns it, so neither the grant's info line nor
                // the release at destroy runs for a handed box.
                //
                // The hand still goes through the verdict the host's publish
                // surface holds (NET-123 §7.1): the VM host daemon hands
                // slice addresses without measuring the loopback they bind
                // on — the root fix is the host daemon measuring before it
                // hands (#1818) — and on a host whose surface cannot bind
                // the range the hand names an address no bind will ever
                // hold. [`vouches_for`] is the gate, and only a **landed
                // present** verdict passes it: a pending one has measured
                // nothing, and the hand's own provenance (the host-side
                // row, which a resumed box keeps its address on, NET-013)
                // is a fact about who chose the address, not about the
                // surface it binds on. So a hand the verdict has not
                // vouched for is not published and not refused either —
                // the box's first finalize waits for the verdict to land,
                // bounded by the daemon's one verdict deadline
                // ([`Self::hand_or_interim`]), so the name publishes once
                // at its final address: at the hand when the walk lands
                // present inside the bound, at the interim when it lands
                // absent or never lands — and the present landing's sweep
                // upgrades an interim-standing handed box back to its own
                // hand when the verdict arrives late. Every other
                // registration publishes such a hand at the interim
                // without waiting. The recorded publish reads through the
                // same gate (the first filter above): a hand the landing
                // has since overruled does not survive in the registry
                // either.
                let (already_published, stood_on_interim) = {
                    let reg = self
                        .hostnames
                        .read()
                        .expect("hostname registry lock poisoned");
                    let standing = reg.published_own_address(record.id);
                    let kept = standing
                        // The verdict the book holds gates the recorded
                        // publish exactly as it gates the fresh hand below
                        // (NET-123): a publish that outlived the verdict
                        // that vouched for it — a landing has overruled it
                        // since — names an address the surface cannot bind,
                        // and the record's memory of it must not keep the
                        // box standing there. The ask below answers with
                        // the interim instead.
                        .filter(|address| self.loopback.vouches_for(*address))
                        // The `127.0.0.1` interim is the surface's answer,
                        // never an address the box owns, so a publish
                        // standing on it asks again: the walk's landing is
                        // the moment the ask upgrades to a grant — and a box
                        // the landing misses, because it was stopped across
                        // it, upgrades at this same ask — where a granted
                        // address is the box's own and keeps.
                        .filter(|address| *address != std::net::Ipv4Addr::LOCALHOST);
                    (kept, standing == Some(std::net::Ipv4Addr::LOCALHOST))
                };
                let handed = record
                    .box_addresses
                    .map(|addresses| addresses.loopback_address);
                let published = if already_published.is_some() {
                    already_published
                } else {
                    match handed {
                        // The hand goes through the verdict the host's
                        // publish surface holds (NET-123 §7.1) — under a
                        // verdict that has vouched for it, at the hand;
                        // under one that has not, at the interim, after the
                        // bounded wait a first finalize takes so the name
                        // does not publish twice. Never a grant: a hand is
                        // only ever replaced by `127.0.0.1`.
                        Some(hand) => Some(
                            self.hand_or_interim(
                                record,
                                &name,
                                hand,
                                wait_for_verdict,
                                stood_on_interim,
                            )
                            .await,
                        ),
                        None => self.lease_loopback_address(record, &name),
                    }
                };
                let mut reg = self
                    .hostnames
                    .write()
                    .expect("hostname registry lock poisoned");
                // The verdict re-read under the write lock: a present
                // landing that stored its verdict after the answer above
                // but before this lock may have run its sweep already —
                // which enumerated the registry without this publish — so a
                // handed box headed for the interim takes its hand here
                // instead of standing on the interim until its next
                // registration. The landing stores the verdict before its
                // sweep takes the registry, so either the sweep sees this
                // publish and moves it, or this re-read sees the verdict.
                // The box cannot have been destroyed under it: a destroy
                // runs through this session's own mailbox, after this
                // registration, and the hand is never released to a pool.
                let published = match promote_interim_to_hand(
                    &reg,
                    &self.loopback,
                    record.id,
                    &name,
                    published,
                    handed,
                ) {
                    Some(hand) => {
                        tracing::warn!(
                            session_id = %record.id,
                            session_name = &name,
                            from = %std::net::Ipv4Addr::LOCALHOST,
                            to = %hand,
                            action = "loopback-range-present-box",
                            "the verdict landed present while the box was \
                             registering; it publishes at its own hand, not \
                             the 127.0.0.1 interim"
                        );
                        Some(hand)
                    }
                    None => published,
                };
                reg.register_caller(
                    record.id,
                    &name,
                    &record.policy,
                    subnet,
                    hostname_proxy_port,
                );
                let declared = crate::net::switch::declared_request_ports(Some(&record.policy));
                if let Some(hand) = handed {
                    // The hand is the box's own address whether this
                    // publish lands at it or at the interim the wait's
                    // expiry stands it on: recorded so the present landing's
                    // sweep moves a handed box off the interim back to its
                    // own hand, never to a grant drawn from the pool.
                    reg.record_own_hand(record.id, hand);
                }
                if let Some(address) = published {
                    // One warn line per port another box at the same address
                    // already holds (NET-129): intrinsic to the shared-address
                    // mode, reported — here at finalize and at every later
                    // session start, since each re-registers — and never
                    // translated. First-come: the registry records the
                    // collisions on this box, the one that yields, so its
                    // attach skips those forwards instead of failing on a bind
                    // the forwarder refuses. The box activates and stays
                    // usable; its other forwards bind as usual. The list rides
                    // the finalize reply so the activating client can warn —
                    // the daemon log line is the only other trace, and a user
                    // reading exit 0 never sees it.
                    reg.restore_bound_ports(record.id, &record.bound_ports);
                    shared_port_collisions =
                        reg.publish_own_address(record.id, &name, address, declared.clone());
                }
                // A box whose grant was withheld registers no name: the
                // registry's own route is built only from a published
                // address, so `register_own_ip` leaves the name absent and
                // the attach path fails the box with the same fact.
                reg.register_own_ip(record.id, &name, declared);
            }
            boxes::NetworkMode::HostNet => {
                let mut reg = self
                    .hostnames
                    .write()
                    .expect("hostname registry lock poisoned");
                reg.register_host_net(record.id, &name);
            }
            _ => {}
        }
        // The cross-record collision report, at the moment the design puts it
        // (NET-010, design §7.1: cross-node collisions are reported at session
        // start, like a port collision) — the same moment the port collision
        // report above fires at, and the half the daemon's own start report
        // cannot cover: a grant another state root's daemon makes after this
        // one booted is one no report this daemon ran at its start will ever
        // see again. Outside the registry's lock, like the lease ask above:
        // the report is a read of the record under its lock file beside a
        // read of the kernel's socket table, and no DNS answer this daemon
        // serves waits behind it.
        if matches!(record.network, boxes::NetworkMode::OwnIp) {
            self.report_unrecorded_publishes();
        }
        shared_port_collisions
    }

    /// Resolves a hand to the address the box publishes at (NET-123 §7.1):
    /// the hand itself when the verdict vouches for it, the `127.0.0.1`
    /// interim when it does not — and never anything else. A hand is only
    /// ever replaced by the interim, so no grant is asked for a handed box:
    /// the hand is the host-side table's row, and the attach path's forwards
    /// name it as their `local`.
    ///
    /// With `wait_for_verdict` — the box's first finalize — a verdict still
    /// pending is waited for, bounded by the daemon's one verdict deadline
    /// ([`crate::net::dns::LoopbackLeaseBook::await_vouch_for`]), so the
    /// name publishes **once** at its final address rather than moving
    /// under the clients a live session already has. A verdict that lands
    /// present inside the bound vouches for the hand; one that lands absent,
    /// or a deadline that passes first, answers "not vouched". Without it
    /// the verdict is read as it stands. An unvouched hand publishes the
    /// interim, with the hand→interim move said out loud in one warn line
    /// naming the box and both addresses — once, not again on a
    /// re-registration of a box already standing there
    /// (`stood_on_interim`). The present landing's sweep upgrades a handed
    /// box standing at the interim back to its own hand when the verdict
    /// finally vouches for it
    /// ([`crate::box_manager::land_range_verdict`]'s present arm).
    ///
    /// Called outside every registry lock, since the wait is async.
    #[cfg(target_os = "linux")]
    pub(super) async fn hand_or_interim(
        &self,
        record: &Record,
        name: &str,
        hand: std::net::Ipv4Addr,
        wait_for_verdict: bool,
        stood_on_interim: bool,
    ) -> std::net::Ipv4Addr {
        let vouched = if wait_for_verdict {
            self.loopback.await_vouch_for(hand).await
        } else {
            self.loopback.vouches_for(hand)
        };
        if vouched {
            return hand;
        }
        if !stood_on_interim {
            tracing::warn!(
                session_id = %record.id,
                session_name = name,
                from = %hand,
                to = %std::net::Ipv4Addr::LOCALHOST,
                action = "loopback-hand-to-interim",
                "the hand's range is not vouched for by a landed present \
                 verdict; the box's publish — name and route with it — \
                 moves to the 127.0.0.1 interim, and the present landing \
                 upgrades it to the hand once the verdict vouches"
            );
        }
        std::net::Ipv4Addr::LOCALHOST
    }

    /// One warn line per reserved-range address a live publish holds on this
    /// host that the answerer's record for this daemon's state root does not
    /// name — the cross-record collision report (NET-010), at session start
    /// like a port collision, through the one emitter the daemon's own start
    /// report shares
    /// ([`warn_publish_collision`](crate::net::dns::warn_publish_collision))
    /// so the two read as one report in a diagnostics bundle's log tail.
    ///
    /// A box that publishes on the shared-address interim — a spent pool, an
    /// absent range, an unreadable record — starts too, and still gets the
    /// report: the addresses it names are other roots' grants, not this
    /// box's, and the moment the design asks for is this session's start.
    #[cfg(target_os = "linux")]
    pub(super) fn report_unrecorded_publishes(&self) {
        for address in self.loopback.unrecorded_publishes() {
            crate::net::dns::warn_publish_collision(address);
        }
    }

    /// Asks the answerer for this box's host loopback address (NET-010) — a
    /// grant of the reserved local range, arbitrated through the host's one
    /// lease record — with the one info line the observability contract asks
    /// for per lease, naming the box and the address (the diagnostics
    /// bundle's log tail carries these beside each release).
    ///
    /// This is the ask a box nobody handed an address takes (NET-040: the
    /// daemon is the creator of its own native boxes, and a VM lane whose
    /// client spelled no provider to register with has no host-side creator
    /// either), and it is not the daemon choosing an address: the answerer's
    /// record is the host-global allocation NET-010 binds, the one
    /// authenticated channel every daemon on the host asks through.
    ///
    /// `None` — with the warn line that says why — for the two answers that
    /// are faults rather than facts about the host's surface: a spent pool
    /// and an unreadable record. The box then publishes nothing and registers
    /// no name, and the attach of a box that declared ingress fails with
    /// "no published address handed" rather than binding forwards at an
    /// address nobody granted — reported, never substituted.
    ///
    /// The two answers that are facts about the surface — the range absent,
    /// the verdict still walking its deferred window — publish the box on the
    /// `127.0.0.1` interim (NET-123's absent arm): the host can listen there
    /// whatever its `lo0` carries, so the box's declared ports are published
    /// and reachable instead of failing at an address the surface cannot
    /// bind. The interim is recorded as the box's own publish — the name
    /// routes at it and the attach binds its forwards at it — but it is the
    /// surface's answer, never an address the box owns, so it cannot outstay
    /// the window that made it: the walk's landing re-points the boxes
    /// standing on it when its verdict lands, and a finalize that finds one
    /// asks again rather than answering from the record. A grant the box
    /// already holds — a resumed session asking again after a restart —
    /// answers with the recorded address once a present verdict has landed,
    /// which is how a box's address stays stable across a daemon restart
    /// (NET-013); inside a restarted daemon's pending window it answers the
    /// interim, and the present landing restores the recorded address — no
    /// reserved-range address publishes under anything but a landed present.
    #[cfg(target_os = "linux")]
    pub(super) fn lease_loopback_address(
        &self,
        record: &Record,
        name: &str,
    ) -> Option<std::net::Ipv4Addr> {
        let namespace = crate::net::dns::LeaseNamespace::Box { session: record.id };
        let granted = self.loopback.grant(namespace);
        match granted {
            crate::net::dns::LoopbackGrant::Granted(address) => {
                tracing::info!(
                    session_id = %record.id,
                    session_name = name,
                    ip = %address,
                    action = "loopback-lease",
                    "leased a host loopback address for the box's published ports"
                );
            }
            crate::net::dns::LoopbackGrant::PoolSpent => {
                tracing::warn!(
                    session_id = %record.id,
                    session_name = name,
                    action = "loopback-pool-spent",
                    "the host's reserved local range is spent; the box's \
                     declared ingress has no address to publish at"
                );
            }
            crate::net::dns::LoopbackGrant::RangePending => {
                tracing::warn!(
                    session_id = %record.id,
                    session_name = name,
                    action = "loopback-range-pending",
                    "the verdict over the reserved local range is still pending; \
                     the box's declared ingress publishes on the 127.0.0.1 interim \
                     until the publish-surface walk lands"
                );
            }
            crate::net::dns::LoopbackGrant::RangeAbsent => {
                tracing::warn!(
                    session_id = %record.id,
                    session_name = name,
                    action = "loopback-range-absent",
                    "the reserved local range is absent on this host's publish \
                     surface; the box's declared ingress publishes on the \
                     127.0.0.1 interim"
                );
            }
            crate::net::dns::LoopbackGrant::RecordUnavailable => {
                tracing::warn!(
                    session_id = %record.id,
                    session_name = name,
                    action = "loopback-record-unavailable",
                    "the answerer's lease record could not be read or written; \
                     the box's declared ingress has no address to publish at"
                );
            }
        }
        granted.publishable_address()
    }

    /// Returns a destroyed box's host loopback address to the host's pool
    /// (NET-010) — the publish's other half, at the same
    /// [`Self::lease_loopback_address`] that named the grant — with the one
    /// info line per release naming the box and the address.
    ///
    /// The answer is the record's, not the registry's: a box that holds a
    /// grant gets exactly that address back — even a box whose publish was
    /// lost to a restart leaves its grant here, so the record never outlives
    /// the session it names. No line at all — and no change — for a
    /// namespace the record does not name. A box whose address was handed
    /// from the host side (T66) never drew from this pool, so its record
    /// names no namespace and this is the no-op half for it.
    #[cfg(target_os = "linux")]
    pub(super) fn release_loopback_address(&self, record: &Record, name: &str) {
        let namespace = crate::net::dns::LeaseNamespace::Box { session: record.id };
        if let Some(address) = self.loopback.release(namespace) {
            tracing::info!(
                session_id = %record.id,
                session_name = name,
                ip = %address,
                action = "loopback-release",
                "released a destroyed box's host loopback address back into the pool"
            );
        }
    }

    /// Whether this session currently owns a PTask hostname route: `Active`
    /// with a routable network mode — exactly the condition under which
    /// [`Self::register_hostname`] registered one.
    #[cfg(target_os = "linux")]
    pub(super) fn owns_hostname_route(&self, record: &Record) -> bool {
        matches!(self.inner, BoxInner::Active { .. })
            && matches!(
                record.network,
                boxes::NetworkMode::HostNet | boxes::NetworkMode::OwnIp
            )
    }

    /// Withdraw this session's PTask hostname (R3.5), and — when the session
    /// is ending for good — drop its publish and its grant, so neither the
    /// registry nor the answerer's record outlives the box they pointed at:
    /// the address returns to the host's pool (NET-010) and every later
    /// lookup of the name answers NXDOMAIN (NET-012).
    ///
    /// `for_good` is the destroy paths' alone; `for_good = false` is the
    /// rename path, which withdraws the route and re-registers it against
    /// the same lease. A stop does not come here: a stopped box still
    /// exists — its session record survives, and a resume brings the same
    /// box back — so the Stop arm keeps the name's route and both halves of
    /// the publish, the registry's row and the answerer's grant, and marks
    /// the box stopped (NET-013: the box's address is its own from finalize
    /// to destroy, and a stopped box that resumes must find the same
    /// address waiting, whether the same daemon or a restarted one answers;
    /// NET-128: the name stays held, answering NODATA while a
    /// shared-address box is stopped). Shutdown stops every session the
    /// same way, which is how the grant a restarted daemon re-derives from
    /// the answerer's record is the very one the box held before the
    /// restart.
    ///
    /// Gated on [`Self::owns_hostname_route`] rather than relying on the
    /// registry's no-op behavior: the registry is keyed by name alone, so an
    /// ungated deregister from a session that never registered (`Draft`, or
    /// a non-routable mode) could withdraw an *unrelated* session's route
    /// that happens to share the same derived name. A rename withdraws with
    /// the grant and the publish kept: the re-register that follows it routes
    /// at the same box, on the same address (NET-001).
    ///
    /// The registry's lock is never held across the answerer's record — the
    /// same rule the grant path's [`Self::lease_loopback_address`] ask
    /// follows: the release is
    /// a synchronous read-modify-write of the record under its lock file,
    /// and this daemon's registry is what every DNS answer it serves reads,
    /// so no answer waits behind a destroyed box's release. The registry's
    /// rows go first, under the write lock alone, and the release runs after
    /// it is dropped — which is also the safe half of that order: while the
    /// record still names the grant, no other box can be handed the
    /// address, so there is no moment where the registry answers an address
    /// the pool already holds free.
    #[cfg(target_os = "linux")]
    pub(super) async fn deregister_hostname(&self, for_good: bool) {
        let record = self.record.record().await.unwrap();
        if for_good {
            // NET-010: the destroyed box's publish is withdrawn first, and the
            // grant it held returns to the host's pool — the grant the
            // finalize made, released here so the next box may publish on it.
            // NET-012: the name goes with the publish, so every later lookup
            // answers NXDOMAIN rather than a stale address.
            {
                let mut reg = self
                    .hostnames
                    .write()
                    .expect("hostname registry lock poisoned");
                let (_, hand_overs) = reg.unpublish_own_address(record.id);
                reg.forget_own_address(record.id);
                // NET-129: each shared-address port this box held has a new
                // holder of record — a running box before a stopped one. The
                // registry sends each hand-over to the sessions manager,
                // which has the new holder bind its forward if its box is
                // running ([`Self::bind_handed_port`]); a box that is not
                // binds it at its next attach.
                for hand_over in hand_overs {
                    tracing::info!(
                        session_id = %hand_over.holder,
                        address = %hand_over.address,
                        port = hand_over.port,
                        from = %record.id,
                        action = "shared-address-port-hand-over",
                        "a shared-address port passes to the earliest-created box still publishing it"
                    );
                }
            }
            self.release_loopback_address(&record, &registry_name(&record));
        }
        if !self.owns_hostname_route(&record) {
            return;
        }
        let mut reg = self
            .hostnames
            .write()
            .expect("hostname registry lock poisoned");
        reg.deregister(&registry_name(&record));
    }

    /// Renames the session: persists the new name through the record handle
    /// (a name collision surfaces as the store's `AlreadyExists`), relinks
    /// the PTask hostname so `<new>.min.internal` routes and the old name
    /// stops (R3.6).
    pub(super) async fn rename(&mut self, new_name: String) -> Result<(), std::io::Error> {
        let record = self.record.record().await?;

        // Renaming to the name the session already has is an error, not a
        // no-op: `save` deliberately treats same-id same-name as a no-op (a
        // status promotion re-saves an unchanged name), so without this guard
        // a rename-to-self would silently succeed and report a rename that
        // did not happen.
        if record.name.as_deref() == Some(new_name.as_str()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("session is already named `{new_name}`"),
            ));
        }

        // Withdraw the route under the pre-rename name before the record
        // mutates; re-register under the new name afterwards. Both calls
        // gate on this session actually owning a route, so a Draft/NoNet
        // rename never touches the registry. The lease fact stays: the
        // re-register routes at the same box (NET-001).
        #[cfg(target_os = "linux")]
        self.deregister_hostname(false).await;
        let mut new_record = record.clone();
        new_record.name = Some(new_name.clone());
        let written = self.record.write(new_record.clone()).await;

        // Re-register whichever name stuck (the new one on success, the old
        // one if the write was refused) so a failed rename never strands the
        // session without a route.
        #[cfg(target_os = "linux")]
        self.register_hostname(
            match &written {
                Ok(_) => &new_record,
                Err(_) => &record,
            },
            false,
        )
        .await;

        // Forward the new name to the running host so the shell's
        // `$MINIMAL_SESSION_NAME` is republished through the per-attach
        // environment channel. Best-effort: the record-side rename has
        // already succeeded, and a dead host drops the message silently.
        if written.is_ok()
            && let BoxInner::Active {
                host: Some((host, _)),
                ..
            } = &self.inner
        {
            host.rename(new_name).await;
        }

        written
    }
}

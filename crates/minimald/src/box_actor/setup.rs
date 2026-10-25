use super::*;

/// The egress *section* the gate compiles for a session: the materialized
/// form of [`boxes::effective_egress`]'s answer — `None` for the
/// allow-all default, the deny-all section for an absent declaration under the
/// in-force default (NET-074), and a declaration with the destination lists
/// it left absent resolved as that function documents. `phase` is the
/// rollout phase to resolve under — the launcher and the task path pass
/// [`boxes::EGRESS_DEFAULT_PHASE`], the phase this build ships, and the
/// tests name [`boxes::EgressDefaultPhase::InForce`] so the posture they
/// prove does not hang on that constant. `opt_out` is the daemon's deny-all
/// opt-out (NET-077), threaded from the server config.
///
/// Shared by the session launcher (the box's own gate) and the task path
/// ([`crate::exec::task_network`]), so a task runs under the same egress
/// its session does.
pub(crate) fn effective_egress_section(
    policy: &boxes::BoxPolicy,
    network: boxes::NetworkMode,
    phase: boxes::EgressDefaultPhase,
    opt_out: bool,
) -> Option<boxes::EgressPolicy> {
    match boxes::effective_egress(policy.egress.as_ref(), network, phase, opt_out) {
        boxes::EffectiveEgress::DenyAll => Some(boxes::EgressPolicy::deny_all()),
        boxes::EffectiveEgress::AllowAll => None,
        boxes::EffectiveEgress::Declared(section) => Some(section),
    }
}

/// The policy the gate enforces for a session: its declared ingress, and its
/// egress resolved to the section [`effective_egress_section`] names — the
/// deny-all section for an own-address box with no `egress` section once the
/// default is in force (NET-074), the allow-all default for everything an
/// opt-out (NET-077) or an earlier phase leaves in place, and a declaration
/// with the destination lists it left absent resolved. `phase` resolves
/// under, exactly as [`effective_egress_section`] documents. The
/// declaration on the record is left untouched: the strict `BoxPolicy`
/// a client reads back stays exactly what the box was launched with.
pub(crate) fn effective_session_policy(
    policy: &boxes::BoxPolicy,
    network: boxes::NetworkMode,
    phase: boxes::EgressDefaultPhase,
    opt_out: bool,
) -> boxes::BoxPolicy {
    boxes::BoxPolicy {
        egress: effective_egress_section(policy, network, phase, opt_out),
        ingress: policy.ingress.clone(),
        // The credentialed-upstream declaration (NET-134) resolves nothing —
        // the lane it opens is decided host-side, by the row the client's
        // registration fills — so it is carried verbatim, like the ingress:
        // the effective policy a box's gate reads keeps the lane the box
        // declared beside it.
        credentialed_upstream: policy.credentialed_upstream.clone(),
        // BEP-018: the declared `quic443` stance resolves nothing here
        // either. The gate resolves it, so it is carried verbatim.
        quic443: policy.quic443,
    }
}

/// How long [`BoxActor::check_composed_packages`] waits for the session
/// graph to resolve before stepping aside.
///
/// Evaluating the graph can clone the upstream repo when the daemon's
/// cache is cold — network I/O with no bound of its own — and the check
/// runs inside the `FinalizeSession` round-trip. The deadline on that
/// round-trip is otherwise the *client's* (`minimal-client`'s 60 s base
/// plus the activate-hook budget; the dashboard grants only the base),
/// and a client that expires does not cancel the daemon-side finalize:
/// the session actor runs on, and may promote the record — running the
/// activate hooks on the way — while the client, which has already
/// reported a failed activation and best-effort-destroyed the session,
/// believes nothing was activated. So the daemon bounds the work it
/// adds itself: past this deadline the check logs a warning, steps
/// aside, and reports the skip back to the client. Expiry cancels the
/// wait, not the evaluation — the detached `spawn_blocking` runs to
/// completion and warms the cache the launch reads — and finalize
/// proceeds exactly as it did before the check existed, the launch
/// resolving names at first exec as it always has.
///
/// Half the client's 60 s base: a warm cache evaluates in seconds, well
/// inside it, and what follows the check in finalize — patch
/// materialization, and the host mint an activate hook needs — keeps
/// the other half of the base for itself.
pub(crate) const PACKAGE_CHECK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// This session's workspace baseline for the shell-exit prompt's change
/// detection, established once before the first host launches and reused
/// across every host teardown and rebuild. Re-arming the baseline at each
/// launch would re-snapshot an already-modified workspace when a "keep
/// filesystem" exit is followed by a reattach, so the next exit would detect
/// no changes and drop the save-then-delete option.
pub(super) enum WorkspaceBaseline {
    /// No host has launched yet; the baseline is armed on the first launch.
    Unarmed,
    /// Armed once at first launch and reused for the session's lifetime. Holds
    /// the arm result verbatim — including the `None` of a walk that timed out
    /// — so a rebuild never re-snapshots against a dirty tree.
    Armed(Option<Arc<DeltaSource>>),
}

// Opaque so `BoxActor`'s derived `Debug` need not dump the whole baseline
// snapshot: only whether the baseline is armed and present is informative.
impl fmt::Debug for WorkspaceBaseline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unarmed => f.write_str("Unarmed"),
            Self::Armed(delta) => write!(f, "Armed(present: {})", delta.is_some()),
        }
    }
}

impl BoxActor {
    /// Compose this session's loadout from its project config and the
    /// client's wire contribution, then either finalize it (`Ok(None)`, the
    /// session is now `Active`) or park it in `Draft` holding the resume
    /// state until the client gates the returned items (`Ok(Some(response))`).
    ///
    /// Every failure leaves the actor alive and `Draft`: the caller decides
    /// whether to retry with a different contribution or tear the session
    /// down, so a compose error can't strand a half-built session.
    ///
    /// A re-`ConfigureLoadout` against a session that already holds
    /// `Draft{pending: Some(_)}` is refused with `WouldBlock`: overwriting
    /// the stashed [`PendingComposeState`] would invalidate every
    /// `PendingId` the first caller received (they were valid moments ago,
    /// but a fresh stash starts numbering from 0 again). The client must
    /// `AbortSession` and create a new session to retry rather than
    /// silently strand its outstanding verdict submission.
    /// `hooks_enabled` is passed rather than read from the record
    /// because the two callers disagree: the `ConfigureLoadout` RPC
    /// honours what the user chose at activation, while the attach
    /// shortcut always composes with hooks off (see its call site).
    pub(super) async fn configure_loadout(
        &mut self,
        contribution: WireContribution,
        hooks_enabled: bool,
    ) -> Result<Option<ContributionResponse>, std::io::Error> {
        match &self.inner {
            BoxInner::Active { .. } => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "session loadout is already configured",
                ));
            }
            BoxInner::Draft { pending: Some(_) } => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "session already has a pending contribution awaiting its verdict; \
                     abort it and create a new session to retry",
                ));
            }
            BoxInner::Draft { pending: None } => {}
        }
        // Composing mid-upload would scaffold and resolve against a
        // half-populated tree, and the session could then go `Active` with
        // the upload still streaming into it.
        if self.workspace_uploads_in_flight > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ResourceBusy,
                "session is still receiving its workspace upload; retry once \
                 the upload completes",
            ));
        }
        let object = self.record.object().await?;
        let workspace_path = object.workspace_path();

        // Scaffold before composing, not after: the launcher's package set is
        // its baseline unioned with the composition's packages (see the note
        // on `BoxInner::Active::composition`), so a default written any
        // later never reaches the sandbox. Propagated, not logged — an
        // activation that hands back a session id must hand back a usable
        // session, and a box with no blueprint can't run anything.
        //
        // Fenced: the scaffold resolves the default package repo over the
        // network and runs inline on the session actor, so an unfenced call
        // would pin a worker for the whole fetch. The compose shares the
        // fence: it resolves the graph through the checkouts cache, whose
        // lock may block for up to the lock timeout, and that wait must not
        // park a tokio worker. Flavor-guarded because `block_in_place`
        // panics on a current-thread runtime.
        let declared_path = self.record.record().await?.project_path;
        let scaffold_and_compose = || {
            self.scaffold_mfile_if_missing(&workspace_path)
                .map_err(|e| std::io::Error::other(format!("scaffolding a default mfile: {e}")))?;
            // Phase 1+2: resolve the project and drive the composer. Kept
            // fully synchronous — its non-`Send` intermediaries must not
            // cross an `.await`; `block_in_place` keeps them on this thread.
            // A session activated with `--no-hooks` drops the project's
            // hooks here, the same way the client already dropped its
            // loadouts' before sending. Both ends honour the flag, so the
            // composition — and the snapshot persisted from it — records
            // that the session has no hooks at all, rather than carrying
            // hooks that every later transition has to remember to skip.
            composables::run_compose(
                &self.daemon_ctx,
                &workspace_path,
                &declared_path,
                contribution,
                hooks_enabled,
            )
        };
        let (outcome, graph_names) = match tokio::runtime::Handle::current().runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(scaffold_and_compose)
            }
            _ => scaffold_and_compose(),
        }?;
        // Set before the outcome match: whichever arm later promotes
        // this session to `Active` — the one-shot `Ready` here, or the
        // `Pending` park resuming through `handle_verdict` — the
        // finalize check judges against the graph this same compose
        // evaluated, never a re-evaluation.
        self.composed_graph_names = graph_names;

        match outcome {
            // The composition is complete: promote the record
            // `Pending → Active` and hold the composition for the launcher.
            ComposeOutcome::Ready(composition) => {
                // Compose finalized in one shot — the record is now
                // `Materializing`, not yet `Active`. `Active` waits
                // for `FinalizeSession` after the client has
                // uploaded the composition's patches. Hostname
                // registration is deferred to the same transition
                // (a session isn't attachable until then, so
                // publishing the route would let something reach a
                // launcher that can't materialize its patches).
                //
                // Persist the composition snapshot before the record
                // write so a crash at any point leaves either a
                // reaped session (Pending/Materializing records are
                // reaped at startup) or an Active session with its
                // sidecar intact.
                self.record.store_composition(&composition).await?;
                let mut record = object.record().clone();
                record.status = BoxState::Materializing;
                self.record.write(record.clone()).await?;
                self.inner = BoxInner::Active {
                    composition: Some(Arc::new(composition)),
                    host: None,
                    sops: vec![],
                };
                Ok(None)
            }
            // The client must gate items before the composition completes.
            // Park in `Draft` with the daemon-side resume state; the record
            // is already `Pending` on disk, so nothing to write.
            ComposeOutcome::Pending {
                mut response,
                state,
            } => {
                // The composer ran before the allocated id was known to it.
                response.session_id = *self.record.id();
                self.inner = BoxInner::Draft {
                    pending: Some(Box::new(state)),
                };
                Ok(Some(response))
            }
        }
    }

    /// Resume a `Draft` session with the client's verdict: finalize the
    /// composition and transition to `Active`.
    ///
    /// Structured refusals — a session that is already `Active` or was never
    /// configured, and a verdict the composer can't apply — come back as a
    /// [`BoxStep::Fault`] and leave the session `Draft` and resumable, so
    /// a client that mis-gated an item can correct it and re-submit rather
    /// than lose the session.
    pub(super) async fn handle_verdict(
        &mut self,
        verdict: ContributionVerdict,
    ) -> Result<BoxStep, std::io::Error> {
        let wrong_state = |what: &str| {
            Ok(BoxStep::Fault {
                error: boxes::wire::errors::WireError::WrongState {
                    what: what.to_string(),
                },
            })
        };
        let pending = match &self.inner {
            BoxInner::Active { .. } => return wrong_state("expected Pending, found Active"),
            BoxInner::Draft { pending: None } => {
                return wrong_state(
                    "expected Pending, found a session with no composition to resume",
                );
            }
            BoxInner::Draft {
                pending: Some(state),
            } => state,
        };

        // Clone rather than take: `resume_from_verdict` consumes the state,
        // and a rejected verdict has to leave the session resumable.
        let composition = match resume_from_verdict((**pending).clone(), verdict) {
            Ok(c) => c,
            Err(e) => return Ok(BoxStep::Fault { error: e.into() }),
        };

        // Promote the on-disk record `Pending → Materializing`. A
        // write failure leaves both the record and the actor
        // `Draft`, so the client can re-submit the same verdict
        // once the store recovers. `Active` waits for a follow-up
        // `FinalizeSession` after patches upload — see
        // [`Self::finalize`] for the transition and its
        // preconditions.
        //
        // Persist the composition snapshot before the record write
        // (same crash-safety reasoning as the Materialized fast
        // path above).
        self.record.store_composition(&composition).await?;
        let mut record = self.record.record().await?;
        record.status = BoxState::Materializing;
        self.record.write(record.clone()).await?;
        self.inner = BoxInner::Active {
            composition: Some(Arc::new(composition)),
            host: None,
            sops: vec![],
        };
        Ok(BoxStep::Materialized { id: record.id })
    }

    /// Finalize a `Materializing` session: verify that the client
    /// has uploaded its composition patches (marker present under
    /// `<workspace>/patches/`), promote the record
    /// `Materializing → Active`, and publish the PTask route so
    /// the session becomes attachable.
    ///
    /// Idempotent: a session already in `Active` (client retried
    /// after a network blip that lost the ack) returns success
    /// without side effects. Refuses `Pending` or `Draft` sessions
    /// with `WrongState`; refuses `Materializing` sessions without
    /// a patches-ready marker with a "patches upload never
    /// finished" fault.
    pub(super) async fn finalize(
        &mut self,
    ) -> Result<minimald_rpc::FinalizeSessionResponse, std::io::Error> {
        let record = self.record.record().await?;
        match record.status {
            BoxState::Active => {
                // Already finalized — retry is a no-op, and its hooks ran
                // on the finalize that did the work. Like the hooks, a
                // skipped package check is reported only by that first
                // finalize; a retry does not re-report it.
                Ok(minimald_rpc::FinalizeSessionResponse::default())
            }
            BoxState::Materializing => {
                // Guard against a `Materializing` record whose
                // actor didn't carry compose state through — the
                // only path there is `BoxActor::run` spawning from
                // an on-disk `Materializing` record after a
                // restart survived the reap in `BoxManager::init`
                // (delete failed, log-and-skip). Without the
                // in-memory composition we can't tell whether the
                // patches were uploaded; `has_patches` below would
                // trivially match `false` and skip the marker
                // check, then `materialize_patches_into_home`
                // would iterate an empty composition and no-op —
                // silently promoting the session to `Active` with
                // an empty home. Fault the finalize so the client
                // sees the problem instead of the user attaching
                // to a broken shell.
                if !matches!(
                    &self.inner,
                    BoxInner::Active {
                        composition: Some(_),
                        ..
                    }
                ) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "session is Materializing but has no in-memory composition \
                         (restart-orphaned actor); destroy the session and re-activate",
                    ));
                }

                // Precondition: patches marker present on disk. The
                // marker is the last thing the patches unpacker
                // writes, so its presence proves every patch is
                // staged. Without this check a client-side bug
                // that skipped the patches upload would silently
                // yield an Active session with a broken sandbox
                // rootfs.
                //
                // Short-circuit: a composition with no patches has
                // nothing for the client to upload, so the marker
                // isn't required. Callers with empty compositions
                // (internal ones — sftp/exec/session-recovery — and
                // any project with no fs mappings) go straight
                // through here.
                let paths_obj = self.record.object().await?;
                let patches_dir = paths_obj.patches_path();
                let has_patches = matches!(
                    &self.inner,
                    BoxInner::Active {
                        composition: Some(c),
                        ..
                    } if !c.patches().is_empty()
                );
                if has_patches {
                    let marker = patches_dir
                        .as_utf8_path()
                        .join(crate::rpc::PATCHES_READY_MARKER);
                    // Distinguish "marker absent" (client forgot the
                    // upload; retry the upload + FinalizeSession)
                    // from "we couldn't tell" (permissions, filesystem
                    // I/O). Collapsing the latter into the former
                    // sends the operator chasing an upload that
                    // already succeeded when the real fault is a
                    // broken workspace dir.
                    let marker_present = tokio::fs::try_exists(&marker).await.map_err(|e| {
                        std::io::Error::new(
                            e.kind(),
                            format!("checking patches-ready marker at {}: {e}", marker.as_str()),
                        )
                    })?;
                    if !marker_present {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "patches upload never completed; cannot finalize \
                             (upload patches, then retry the activation)",
                        ));
                    }
                }

                // Same precondition for hook scripts that arrive by
                // upload. Without it, a client that skipped that upload
                // would produce an `Active` session whose hooks name
                // files that were never staged — and the first symptom
                // would be an activation hook failing at some later
                // point, far from the cause. Which hooks those are is
                // narrower than "any external script": see
                // [`composition_needs_staged_scripts`].
                let needs_staged_scripts = matches!(
                    &self.inner,
                    BoxInner::Active {
                        composition: Some(c),
                        ..
                    } if composition_needs_staged_scripts(c)
                );
                if needs_staged_scripts {
                    let marker = paths_obj
                        .hooks_path()
                        .as_utf8_path()
                        .join(crate::rpc::HOOKS_READY_MARKER);
                    let marker_present = tokio::fs::try_exists(&marker).await.map_err(|e| {
                        std::io::Error::new(
                            e.kind(),
                            format!("checking hooks-ready marker at {}: {e}", marker.as_str()),
                        )
                    })?;
                    if !marker_present {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "hook-script upload never completed; cannot finalize \
                             (upload hook scripts, then retry the activation)",
                        ));
                    }
                }

                // Every composed package name has to resolve before the
                // record is promoted: otherwise activate hands back an id
                // for a session whose first spawn fails with `no such
                // package`. Refusing here leaves the record unpromoted,
                // and the client's activate cleanup removes it.
                let mut package_check_skipped = false;
                if self.check_packages_at_finalize
                    && let BoxInner::Active {
                        composition: Some(comp),
                        ..
                    } = &self.inner
                {
                    package_check_skipped = self.check_composed_packages(comp).await?;
                }

                // Materialize the composition's patches into the
                // session's home dir. Done here — once — rather
                // than on every attach so the sandbox home is
                // populated exactly at the point the session
                // becomes attachable, and subsequent attaches see
                // the same tree without re-copying (which would
                // clobber any in-sandbox modifications the user
                // made in prior attaches). If the composition has
                // no patches, this is a no-op.
                if let BoxInner::Active {
                    composition: Some(comp),
                    ..
                } = &self.inner
                {
                    let home = paths_obj.home_path();
                    materialize_patches_into_home(&patches_dir, &home, comp).await?;
                }

                // Activate hooks run here — after the patches are in the
                // sandbox home, before the session becomes attachable —
                // so setup work and its failures land at
                // `min session activate` rather than at some later
                // attach.
                //
                // A hook runs *inside* the session, which means a shell
                // has to exist for its namespaces to be joined. Nothing
                // launches one this early, so this does, and keeps it:
                // the next attach reuses it, and whatever the hooks put
                // in `/tmp` survives into the session instead of dying
                // with a throwaway sandbox. Gated on there actually
                // being activate hooks, so a session without them pays
                // nothing and comes up exactly as before.
                //
                // The box's name and publish come first (NET-010/NET-011):
                // the box's first finalize, the one registration that may
                // wait for the range verdict (NET-123 §7.1), runs before
                // the hook launch below, because that launch is the box's
                // first attach. An own-address box that declared ingress
                // binds its forwards at the address this registration
                // publishes, and an attach that finds none fails with "no
                // published address handed" by design (NET-121) — so a box
                // with an activate hook and a static ingress could never
                // activate if the hooks launched first (#2070). The
                // registration reads only the record's identity, network
                // mode and policy, which the `Active` write below does not
                // change. A finalize that fails after this point — an
                // activate hook that fails, a launch that cannot start, the
                // record write — leaves the publish standing on a
                // `Materializing` record, and the client's activate cleanup
                // destroys the session, whose destroy withdraws the publish,
                // the name and any grant for good
                // ([`Self::deregister_hostname`]). A retried finalize
                // registers again, which is idempotent for one session id.
                #[cfg(target_os = "linux")]
                let shared_port_collisions: Vec<minimald_rpc::SharedPortCollision> = self
                    .register_hostname(&record, true)
                    .await
                    .into_iter()
                    .map(|c| minimald_rpc::SharedPortCollision {
                        port: c.port,
                        held_by: c.other,
                    })
                    .collect();
                #[cfg(not(target_os = "linux"))]
                let shared_port_collisions: Vec<minimald_rpc::SharedPortCollision> = Vec::new();

                let mut ran: Vec<minimald_rpc::RanHook> = Vec::new();
                if self.has_hooks_for(crate::hooks::HookEvent::Activate) {
                    self.launch_host_for_hooks(LaunchPhase::Activating).await?;
                    let outcomes = run_session_hooks(
                        &self.inner,
                        &self.record,
                        crate::hooks::HookEvent::Activate,
                    )
                    .await;
                    // Unlike every other transition, an activate failure
                    // aborts: a development environment whose setup
                    // script failed is not the environment the user
                    // asked for, and handing back a quietly-wrong
                    // session is worse than refusing.
                    if let Some(failed) = outcomes.iter().find(|o| o.failed()) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "activation hook from {} {}; the session was not \
                                 activated{}",
                                failed.declared_by,
                                failed.status,
                                if failed.output.is_empty() {
                                    String::new()
                                } else {
                                    format!(":\n{}", failed.output)
                                },
                            ),
                        ));
                    }
                    // Nothing failed, so every outcome here is a hook that
                    // ran. Reported back so the client can say what it did
                    // — an activate hook is headless, and without this the
                    // only trace is the daemon log.
                    ran.extend(outcomes.iter().map(|o| minimald_rpc::RanHook {
                        declared_by: o.declared_by.clone(),
                        description: o.description.clone(),
                        output: o.output.clone(),
                    }));
                }

                // Re-read rather than reuse the record read above: the
                // activate-hook launch wrote its own facts to it (the
                // placement outcome, the host-row binding), and promoting a
                // stale copy would erase them.
                let mut record = self.record.record().await?;
                record.status = BoxState::Active;
                self.record.write(record.clone()).await?;
                Ok(minimald_rpc::FinalizeSessionResponse {
                    activate_hooks: ran,
                    package_check_skipped,
                    shared_port_collisions,
                })
            }
            BoxState::Pending => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "session is Pending; configure the loadout first",
            )),
        }
    }

    /// Kicks off a background package build as a side-op and registers it on
    /// this session, returning the receiver end of its event stream. The build
    /// runs against a fresh workspace-rooted context (rebuilt per call so it
    /// tracks `minimal.toml` edits).
    ///
    /// The returned receiver closes when the build ends.
    pub(super) async fn start_build(
        &mut self,
        rebuild: bool,
        pkgs: Vec<String>,
    ) -> Result<mpsc::Receiver<BuildUpdate>, std::io::Error> {
        let ctx = self.context(false).await.map_err(std::io::Error::other)?;
        let (sop, rx) = SideOp::spawn_build(self.weak_self.clone(), rebuild, pkgs, ctx, 64).await?;
        match &mut self.inner {
            BoxInner::Active { sops, .. } => sops.push(sop),
            BoxInner::Draft { .. } => {
                sop.shutdown().await;
                unreachable!("`context()` already rejected a `Draft`");
            }
        }
        Ok(rx)
    }

    /// Kicks off a background check run as a side-op and registers it on this
    /// session, returning the receiver end of its result stream. Like
    /// [`start_build`](Self::start_build) it runs against a fresh
    /// workspace-rooted context, so it sees `minimal.toml` edits made since the
    /// session came up.
    ///
    /// The returned receiver closes when the run ends.
    pub(super) async fn start_check(
        &mut self,
        opts: CheckOpts,
    ) -> Result<mpsc::Receiver<CheckUpdate>, std::io::Error> {
        let ctx = self.context(false).await.map_err(std::io::Error::other)?;
        let (sop, rx) = SideOp::spawn_check(self.weak_self.clone(), opts, ctx, 64).await?;
        match &mut self.inner {
            BoxInner::Active { sops, .. } => sops.push(sop),
            BoxInner::Draft { .. } => {
                sop.shutdown().await;
                unreachable!("`context()` already rejected a `Draft`");
            }
        }
        Ok(rx)
    }

    /// Kicks off a background materialize run as a side-op and registers it on
    /// this session, returning the receiver end of its stream. Like
    /// [`start_build`](Self::start_build) it runs against a fresh
    /// workspace-rooted context, so it sees outputs declared since the session
    /// came up. The receiver closes when the run ends.
    pub(super) async fn start_materialize(
        &mut self,
        opts: MaterializeOpts,
    ) -> Result<mpsc::Receiver<MaterializeUpdate>, std::io::Error> {
        let ctx = self.context(false).await.map_err(std::io::Error::other)?;
        let (sop, rx) = SideOp::spawn_materialize(self.weak_self.clone(), opts, ctx, 64).await?;
        match &mut self.inner {
            BoxInner::Active { sops, .. } => sops.push(sop),
            BoxInner::Draft { .. } => {
                sop.shutdown().await;
                unreachable!("`context()` already rejected a `Draft`");
            }
        }
        Ok(rx)
    }

    /// Produces this session's arm result for [`WorkspaceBaseline`]: the
    /// persisted sidecar when one is readable — so a daemon restart keeps
    /// the activation-time baseline — and a fresh walk otherwise, persisted
    /// best-effort so the next restart finds it. Every failure degrades to
    /// the fresh walk or to skipping persistence with a warning: change
    /// detection is a courtesy and never blocks a launch.
    pub(super) async fn load_or_arm_baseline(
        &self,
        workspace_root: std::path::PathBuf,
    ) -> Option<Arc<DeltaSource>> {
        match self.record.load_delta_baseline().await {
            Ok(Some(bytes)) => {
                match workspace_delta::from_sidecar_bytes(&bytes, workspace_root.clone()) {
                    Ok(delta) => return delta,
                    Err(e) => {
                        tracing::warn!(
                            session_id = %self.record.id(),
                            error = %e,
                            "unreadable delta-baseline sidecar; arming afresh",
                        );
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    session_id = %self.record.id(),
                    error = %e,
                    "failed to read delta-baseline sidecar; arming afresh",
                );
            }
        }
        let delta = DeltaSource::arm(workspace_root).await;
        // Persist the arm result — a failed arm included, so a restart
        // honors "change detection disabled" instead of re-snapshotting a
        // tree the session may already have modified.
        match workspace_delta::to_sidecar_bytes(delta.as_ref()) {
            Ok(bytes) => {
                if let Err(e) = self.record.store_delta_baseline(bytes).await {
                    tracing::warn!(
                        session_id = %self.record.id(),
                        error = %e,
                        "failed to persist the delta baseline; a daemon restart will re-arm",
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    session_id = %self.record.id(),
                    error = %e,
                    "unserializable delta baseline; a daemon restart will re-arm",
                );
            }
        }
        delta
    }

    /// The held [`Composition`], if any — `None` in `Draft` or for an actor
    /// spawned from disk after a daemon restart.
    #[cfg_attr(test, allow(dead_code))]
    pub(super) fn composition(&self) -> Option<Arc<Composition>> {
        match &self.inner {
            BoxInner::Active { composition, .. } => composition.clone(),
            BoxInner::Draft { .. } => None,
        }
    }

    /// Return this session's workspace-rooted [`mctx::Context`].
    ///
    /// This is NOT cached to enable session execution to change as the
    /// `minimal.toml` file changes.
    ///
    /// Gated on the same lifecycle status as [`BoxActor::attach`]:
    /// the on-disk record must be `Active`. `BoxInner::Active`
    /// alone doesn't distinguish `Materializing` (composition done,
    /// patches not yet uploaded and not yet materialized into the
    /// sandbox home) from `Active` (fully ready). Building a
    /// context and running a task against a `Materializing`
    /// session would execute against an unpopulated home dir —
    /// the exact lifecycle escape the `Materializing` state was
    /// added to prevent.
    ///
    /// The one caller that legitimately runs before the promotion —
    /// [`BoxActor::finalize`]'s activation-hook launch — reaches
    /// [`Self::build_context`] directly instead, via
    /// [`LaunchPhase::Activating`]. It materializes the home dir first, so
    /// it satisfies the invariant this gate protects without being able to
    /// satisfy the gate itself.
    pub(super) async fn context(
        &mut self,
        scaffold_if_missing: bool,
    ) -> Result<mctx::Context, String> {
        if matches!(&self.inner, BoxInner::Draft { .. }) {
            return Err("session is pending composition".to_string());
        }
        let record = self
            .record
            .record()
            .await
            .map_err(|e| format!("reading session record: {e}"))?;
        if record.status != BoxState::Active {
            return Err(format!(
                "session isn't attachable yet (status is {:?}, need Active — \
             finish the activation first)",
                record.status,
            ));
        }

        let ctx = self.build_context(scaffold_if_missing).await?;
        Ok(ctx)
    }

    /// The mctx [`Config`] rooted at this session's workspace, shared by the
    /// scaffold and context-construction paths so both see one session.
    ///
    /// [`Config`]: mctx::Config
    pub(super) fn workspace_config(&self, wsp: &DaemonAbsPath) -> Result<mctx::Config, String> {
        ConfigBuilder::new()
            .with_repo_dir(wsp.as_utf8_path())
            .with_cache_dir(self.minimal_cache_dir.as_utf8_path())
            .with_state_dir(self.minimal_state_dir.as_utf8_path())
            // Every context this session builds reports into its operation tree.
            // The host-mint path renders that tree onto the SSH channel; the
            // task-exec path (via `MakeContext`) also feeds it, so task builds
            // surface on the same tracker even though only a mint renders it.
            .with_operation_tracker(self.tracker.clone())
            .with_daemon_id(self.daemon_ctx.daemon_id().unwrap()) // always set under minimald
            .build()
            .map_err(|e| mctx::Error::from(e).to_string())
    }

    /// TEMPORARY: write a default shell-stack `minimal.toml` into the
    /// session's workspace if it has none, so [`mctx::Context::new`] can
    /// succeed and the session gets a usable set of packages. A workspace
    /// that already holds an uploaded `minimal.toml` is left alone.
    ///
    /// Runs from [`Self::configure_loadout`], ahead of the composition that
    /// decides the launcher's packages; [`Self::build_context`] repeats it as
    /// an idempotent backstop for sessions brought up from disk.
    pub(super) fn scaffold_mfile_if_missing(&self, wsp: &DaemonAbsPath) -> Result<(), String> {
        if wsp.as_utf8_path().join(mfile::MFILE_NAME).exists() {
            return Ok(());
        }
        match mfile::File::from_dir(wsp.as_utf8_path()) {
            Ok(_) => Ok(()), // it exists
            Err(mfile::Error::NotFound) => {
                let (toml_path, content) = self.default_mfile_plan(wsp)?;
                std::fs::write(&toml_path, &content).map_err(|e| e.to_string())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// The default `minimal.toml` [`Self::scaffold_mfile_if_missing`] writes.
    ///
    /// Production: `op::InitProject` detects the workspace's stack against the
    /// default package repo, whose branch head it resolves over the network.
    ///
    /// Under `test`/`test-support`: stand in for that network round-trip. Tests
    /// run offline, and what they need from the scaffold is that it lands before
    /// the composition — not what stack detection would have picked. The two
    /// packages are what `op::InitProject` falls back to when nothing matches.
    pub(super) fn default_mfile_plan(
        &self,
        wsp: &DaemonAbsPath,
    ) -> Result<(std::path::PathBuf, String), String> {
        #[cfg(any(test, feature = "test-support"))]
        {
            Ok((
                wsp.as_utf8_path()
                    .join(mfile::MFILE_NAME)
                    .into_std_path_buf(),
                "[session]\npackages = [\"base\", \"vim\"]\n".to_string(),
            ))
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            let config = self.workspace_config(wsp)?;

            use op::ProjectOp as _;
            let mut env = mctx::ProjectSetup::for_init(config).map_err(|e| e.to_string())?;
            let plan = op::InitProject.run(&mut env).map_err(|e| e.to_string())?;

            Ok((plan.toml_path, plan.content))
        }
    }

    /// Do the actual context construction: run [`mctx::Context::new`] against
    /// a session-rooted [`Config`]. Called at most once per actor lifetime by
    /// [`Self::context`].
    ///
    /// The workspace mfile it parses is either the client's uploaded one or
    /// the default [`Self::configure_loadout`] scaffolded. The scaffold is
    /// repeated here as a backstop — it early-returns when the mfile exists,
    /// so it only fires for a session whose compose predates it.
    ///
    /// [`Config`]: mctx::Config
    pub(super) async fn build_context(
        &self,
        scaffold_if_missing: bool,
    ) -> Result<mctx::Context, String> {
        let wsp = self.record.object().await.unwrap().workspace_path();
        if scaffold_if_missing {
            // Fenced: the scaffold updates the default package checkout,
            // whose checkouts cache lock may block for up to the lock
            // timeout, and that wait must not park a tokio worker.
            // Flavor-guarded because `block_in_place` panics on a
            // current-thread runtime.
            let scaffold = || self.scaffold_mfile_if_missing(&wsp);
            match tokio::runtime::Handle::current().runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(scaffold),
                _ => scaffold(),
            }?;
        }
        mctx::Context::new(self.workspace_config(&wsp)?).map_err(|e| e.to_string())
    }

    /// Refuse a composition that names a package the session's graph does
    /// not declare, naming each such package and who declared it (the
    /// project or a loadout).
    ///
    /// Resolves names only: nothing is built, and no graph is retained
    /// here, since the launch evaluates its own. When
    /// [`Self::configure_loadout`] captured the compose-time graph's
    /// names, membership in them answers the same lookup the launch uses
    /// ([`crate::env::session_package`]) without re-evaluating the graph
    /// — the most expensive step of a compose — a second time; otherwise
    /// the check evaluates the graph itself, once. A context or graph
    /// that cannot be evaluated at all (an upstream that does not resolve)
    /// is not judged here; the launch reports it, as it did before this
    /// check existed — and so is one that does not resolve within
    /// [`PACKAGE_CHECK_DEADLINE`]: the daemon bounds the work the check
    /// adds to the `FinalizeSession` round-trip itself, because the
    /// round-trip's other deadline is the client's, and its expiry does not
    /// cancel the daemon-side finalize. An expired check steps aside,
    /// warned, and the launch resolves the names at first exec, as it
    /// always has. Because tokio polls the check before its timer, expiry
    /// is not left to the race between them: the check measures its own
    /// budget first, and a deadline already lapsed steps aside before any
    /// verdict.
    ///
    /// Returns `Ok(true)` when the check stepped aside (expired deadline,
    /// no session context, or no package graph) so the client can warn the
    /// operator; `Ok(false)` when it ran to a verdict (nothing unknown, or
    /// an unknown package refused via `Err`).
    pub(super) async fn check_composed_packages(
        &self,
        comp: &Composition,
    ) -> Result<bool, std::io::Error> {
        // Both expiry routes (the budget measured up front, the timer
        // below) step aside with the same warning.
        fn warn_check_expired(deadline: std::time::Duration) {
            tracing::warn!(
                ?deadline,
                "package check skipped at finalize: the session graph did not \
                 resolve within its deadline; unknown package names will surface \
                 at first exec, as before this check existed",
            );
        }
        if comp.packages().is_empty() {
            return Ok(false);
        }
        let started = std::time::Instant::now();
        let checked: Result<Result<bool, std::io::Error>, _> =
            tokio::time::timeout(self.package_check_deadline, async {
                // The budget check first: tokio polls this future before
                // its timer, and judging the captured names (the match
                // below) is cheap enough to complete within that first
                // poll, so an already-lapsed deadline — a
                // `Duration::ZERO` switch — would never fire against it
                // (see the expiry test). Measuring costs nothing on the
                // slow fallback, which the timeout bounds anyway.
                if started.elapsed() >= self.package_check_deadline {
                    warn_check_expired(self.package_check_deadline);
                    return Ok(true);
                }
                let unknown: Vec<String> = match self.composed_graph_names.as_ref() {
                    // A handful of set lookups: judged inline, no
                    // blocking-pool round-trip.
                    Some(known) => comp
                        .packages()
                        .iter()
                        .filter(|p| !known.contains(p.package()))
                        .map(|p| {
                            format!(
                                "{} (declared by {})",
                                crate::env::unknown_package(p.package()),
                                boxes::core::source::Provenanced::source(p)
                            )
                        })
                        .collect(),
                    None => {
                        let ctx = match self.build_context(true).await {
                            Ok(ctx) => ctx,
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    "package check skipped at finalize: no session context"
                                );
                                return Ok(true);
                            }
                        };
                        // CPU-heavy (nickel evaluation), so on the blocking pool, as
                        // the launch runs it.
                        let graph = crate::traced::spawn_blocking(move || {
                            let mut ctx = ctx;
                            ctx.graph_from_all_packages().map_err(|e| e.to_string())
                        })
                        .await
                        .map_err(std::io::Error::other)?;
                        let graph = match graph {
                            Ok(graph) => graph,
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    "package check skipped at finalize: no package graph"
                                );
                                return Ok(true);
                            }
                        };
                        comp.packages()
                            .iter()
                            .filter_map(|p| {
                                crate::env::session_package(&graph, p.package())
                                    .err()
                                    .map(|e| {
                                        format!(
                                            "{e} (declared by {})",
                                            boxes::core::source::Provenanced::source(p)
                                        )
                                    })
                            })
                            .collect()
                    }
                };
                if unknown.is_empty() {
                    return Ok(false);
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{}; the session was not activated", unknown.join("; ")),
                ))
            })
            .await;
        match checked {
            Ok(result) => result,
            Err(_expired) => {
                // Stepping aside, not failing: a graph this slow is one the
                // launch tolerates — it evaluates its own, unbounded, at
                // first exec — so the check tolerates it too. The evaluation
                // the timeout detached keeps running on the blocking pool and
                // warms the cache that launch reads.
                warn_check_expired(self.package_check_deadline);
                Ok(true)
            }
        }
    }
}

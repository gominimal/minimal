use super::*;

/// Why this host refuses the unprivileged user namespace every session
/// sandbox needs, with the fix to run — `None` when nothing is visible.
///
/// Probed at failure time rather than reused from the daemon's startup
/// probe: the sysctls it reads take effect live (the host-setup doc's
/// `sysctl -w` fix needs no daemon restart), so a startup verdict could
/// name a restriction already lifted, or miss one set since. The probe is a
/// handful of `/proc` reads on a path that has already failed.
#[cfg(target_os = "linux")]
pub(super) fn userns_spawn_hint() -> Option<String> {
    sandbox::user_namespaces_restriction()
        .map(|r| format!("{r} — fix: {}", crate::userns_restriction_fix(r)))
}

/// Off Linux no user namespace is involved, so there is nothing to name.
#[cfg(not(target_os = "linux"))]
pub(super) fn userns_spawn_hint() -> Option<String> {
    None
}

/// The error a failed host attach surfaces: the bare symptom, plus the
/// userns diagnosis and fix when there is one (see [`userns_spawn_hint`]).
/// A host that dies in the launch-to-attach window on a userns-restricted
/// host (stock Ubuntu 24.04+) otherwise leaves the client with a symptom
/// that names neither the restriction nor the fix.
pub(super) fn spawn_failed_error(userns_spawn_hint: Option<&str>) -> std::io::Error {
    with_userns_hint(
        std::io::Error::other(
            "the session's sandbox process exited before the attach could connect to it",
        ),
        userns_spawn_hint,
    )
}

/// `err` with the userns diagnosis and fix appended when there is one,
/// keeping its kind. A launch that fails outright on a userns-restricted
/// host (an own-ip session wiring the netns of a child that already died on
/// its `uid_map` write) otherwise reaches the client with the same
/// cause-less symptom as a host that dies before its attach. The probe
/// sees the host, not this error, so the hint is labelled the likely cause
/// and the error's own message stays first.
pub(super) fn with_userns_hint(
    err: std::io::Error,
    userns_spawn_hint: Option<&str>,
) -> std::io::Error {
    match userns_spawn_hint {
        Some(hint) => std::io::Error::new(err.kind(), format!("{err} — likely cause: {hint}")),
        None => err,
    }
}

impl BoxActor {
    /// Builds the session launcher used to mint a session host: the real
    /// sandboxed shell in production.
    #[cfg(not(test))]
    pub(super) async fn session_launcher(
        &mut self,
        session: BoxHandle,
        record: &Record,
        attach_env: box_runtime::AttachEnv,
        phase: LaunchPhase,
        for_hooks: bool,
    ) -> Result<box_runtime::SandboxLauncher, AttachError> {
        // R2.1: reject a policy that is incompatible with the network mode
        // (e.g. ingress forwards on a non-`OwnIp` PTask) before launching the
        // host.
        record
            .validate_policy()
            .map_err(AttachError::InvalidPolicy)?;
        let network_mode = record.network;
        // Only an `OwnIp` PTask attaches to the switch, so the policy's relay
        // halves — egress verdict and ingress forwards — are only consumed in
        // that mode. `validate_policy` rejects egress rules only on `NoNet`: a
        // host-address box may carry them (NET-120), and such a box never
        // reaches the relay. Only the ingress half is own-address-only, and
        // `validate_policy` has already rejected it on any other mode.
        //
        // NET-074: the gate enforces the *effective* egress — an absent
        // section on an own-address box is the deny-all section once the
        // default is in force, this daemon's opt-out excepted (NET-077) —
        // while the record keeps the declaration untouched for the strict
        // `GetSessionPolicy` reply.
        let policy = effective_session_policy(
            &record.policy,
            record.network,
            boxes::EGRESS_DEFAULT_PHASE,
            self.deny_all_opt_out,
        );
        // One publication set for the spawn this launch is about to run:
        // the runtime expose path reads it in this actor, and the listen
        // plan the launcher gathers shares it with the watcher the host it
        // launches starts — so the box's two runtime publishing surfaces
        // never bind one port twice, whichever reaches the switch first.
        // Built here, per launch, so a respawn starts from an empty set and
        // nothing a dead spawn published can answer for its successor.
        self.publications = Default::default();
        Ok(box_runtime::SandboxLauncher {
            ctx: match phase {
                LaunchPhase::Attached => self.context(true).await,
                // The activation launch runs inside `finalize`, before the
                // record is promoted, so the status gate in `context` would
                // reject it — see [`LaunchPhase::Activating`]. Everything
                // that gate protects has already been established by the
                // time finalize gets here: the session is composed (checked
                // before any of this runs) and its patches are materialized
                // into the home dir.
                LaunchPhase::Activating => self.build_context(true).await,
            }
            .map_err(AttachError::ContextCreationFailed)?,
            attach_env,
            network_mode,
            net_switch: Arc::clone(&self.net_switch),
            policy,
            // The attach reports the lease through this, so the box's
            // `<name>.min.internal` proxy route exists exactly while the box
            // does (NET-001).
            // It carries the box's runtime-publish cell too, so the spawn's
            // guard unbinds those forwards with its declared ones (NET-044).
            own_address: Some(
                crate::net::provider::OwnAddressReporter::new(
                    Arc::clone(&self.hostnames),
                    record.id,
                )
                .with_runtime_ingress(self.live_ingress.clone()),
            ),
            // The addresses the VM host daemon handed this box's registration
            // (T66), persisted on the record: the `OwnIp` attach reuses the
            // handed switch address instead of drawing one the host-side row
            // would not match — including on a re-attach after a restart,
            // where the record is the only thing that still knows it.
            box_addresses: record.box_addresses,
            composition: self.composition(),
            // A weak handle so in-sandbox `min build` can drive session
            // side-ops without keeping the actor alive past teardown.
            session: session.downgrade(),
            // What this launch is for; see [`BoxActor::launch_host`].
            for_hooks,
            // The classifier tree the privileged step installs natively and
            // the guest's own boot mounts; see the field's doc.
            classifier_root: std::path::PathBuf::from(sandbox::classifier::TREE_ROOT),
            // The mount table the launch's classifier facts answer over is
            // the daemon's own, read live on every launch; see the field's
            // doc.
            classifier_mountinfo: None,
            // The spawn's publication set, shared with the listen plan the
            // launch gathers; see the assignment above.
            publications: self.publications.clone(),
            // Where the listen plan's watcher audits the listens it
            // publishes: the log this actor audits its exposes in (NET-046).
            state_dir: self
                .minimal_state_dir
                .as_utf8_path()
                .as_std_path()
                .to_path_buf(),
        })
    }

    /// Under test, swap in a mock launcher that runs a plain host process wired
    /// to the pty, exercising the session-host runtime without building a real
    /// sandbox (which needs packages unavailable in the unit-test tempdir).
    ///
    /// Kept separate from the production launcher: the two return *different*
    /// launcher types (`SandboxLauncher` vs `MockLauncher`), each with its own
    /// `BoxProcess`/`BoxGuard` associated types, and `BoxLauncher`
    /// is not object-safe — merging them would force a boxed/dyn launcher
    /// through the production spawn path.
    #[cfg(test)]
    pub(super) async fn session_launcher(
        &mut self,
        _session: BoxHandle,
        record: &Record,
        _attach_env: box_runtime::AttachEnv,
        _phase: LaunchPhase,
        _for_hooks: bool,
    ) -> Result<box_runtime::MockLauncher, AttachError> {
        // Mirror the production R2.1 gate so test launches reject a
        // policy/network-mode mismatch the same way production does.
        record
            .validate_policy()
            .map_err(AttachError::InvalidPolicy)?;
        // One publication set per launch, built the way the production
        // launcher builds one, so a test's runtime exposes and the watcher
        // its launch carries read the same set the way the real box's two
        // surfaces do.
        self.publications = Default::default();
        // Mirror the production classifier half too, as the placement's
        // outcome alone: a mock launch records what its own placement would
        // — `per_box` when the fact's cause says this host has the step's
        // tree to place a leaf in (the same inference the reads make over a
        // launch that cannot tell them, `fact_places_a_leaf`), `none` when
        // it does not — over the fact a test's injected reading sets, so
        // the launches a test drives record each box's own outcome over the
        // same fact the real launcher's per-launch read produces. The mock
        // has no sandbox, so it models the placement's outcome, not the
        // placement: which box a leaf goes to, and the mapping from a
        // placement to the state it leaves the box in, are the production
        // launcher's, pinned in session_host's launch proofs. A session
        // that is not host-address keeps the plain mock — its verdict is
        // decided on address leases, never on the host's cgroup tree, so
        // there is no per-box outcome for its launches to record.
        let mut launcher = if record.network == boxes::NetworkMode::HostNet {
            let fact = crate::box_runtime::host_ip_enforcement_fact();
            let placement = if crate::box_runtime::fact_places_a_leaf(fact.cause) {
                minimald_rpc::HostIpEnforcement::PerBox
            } else {
                minimald_rpc::HostIpEnforcement::None
            };
            box_runtime::MockLauncher::with_host_ip_enforcement(placement)
        } else {
            box_runtime::MockLauncher::default()
        };
        // A listen plan a test seeded ([`listen_plan_seam`]) rides the
        // mock's `Launched` the way the launch's own gathered plan rides a
        // real one — and a launch a test seeded no plan for starts no
        // watcher at all, the way a launch that could gather none does.
        if let Some(seeded) = listen_plan_seam::take(record.id) {
            launcher = launcher.and_listen_plan(crate::net::listeners::ListenPlan::new(
                record.name.clone().unwrap_or_else(|| record.id.to_string()),
                seeded.lease,
                seeded.published,
                seeded.control,
                seeded.gate,
                self.publications.clone(),
                self.minimal_state_dir
                    .as_utf8_path()
                    .as_std_path()
                    .to_path_buf(),
                Some(Arc::clone(&self.hostnames)),
                record.id,
            ));
            // The set this launch is running on, handed back so a test can
            // contend with its two real surfaces over the real port — a
            // reservation held in it is the reservation the actor's own
            // publish would hold.
            listen_plan_seam::hand_back(record.id, self.publications.clone());
        }
        // What the launch's own-address attach would read as the box's
        // published address (NET-010), read through the reporter the
        // production launcher hands its attach, at the moment of the launch:
        // the mock attaches nothing, so this is how a test sees whether a
        // launch found the box's publish already standing (#2070).
        #[cfg(target_os = "linux")]
        if record.network == boxes::NetworkMode::OwnIp {
            launch_publish_seam::observe(
                record.id,
                crate::net::provider::OwnAddressReporter::new(
                    Arc::clone(&self.hostnames),
                    record.id,
                )
                .published_address(),
            );
        }
        // A session whose launch-record write a test fails also carries
        // the guard that test watches, so the box's teardown is
        // observable after the launch kills it.
        Ok(match launch_record_seam::teardown_guard(record.id) {
            Some(guard) => launcher.and_net_guard(guard),
            None => launcher,
        })
    }
}

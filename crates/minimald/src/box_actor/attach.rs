use super::*;

/// An error that occurred when attaching to a running session/its-shell.
#[derive(Debug)]
pub enum AttachError {
    SpawnFailed(std::io::Error),
    NoPty,
    ContextCreationFailed(String),
    /// The session's networking policy is incompatible with its network mode
    /// (R2.1): e.g. an egress section on a non-`OwnIp` PTask.
    InvalidPolicy(boxes::PolicyError),
    /// Configuring the loadout of an as-yet-unconfigured session, on the way
    /// into the attach, failed.
    LoadoutFailed(std::io::Error),
    /// Recording the launch's egress-enforcement outcome on the session
    /// record (NET-079) failed: the box the launch minted was killed and
    /// the attach failed, because a host-address box whose record says
    /// nothing about it must not run as though it had an outcome — the
    /// reads would answer the host's state for a box that did launch,
    /// which is exactly what a record exists to outrank.
    LaunchRecordUnwritable(std::io::Error),
    /// The session isn't attachable yet. Either its composition is
    /// still awaiting the client's contribution verdict
    /// (`SubmitVerdict` hasn't landed), or its composition
    /// finalized but the session is `Materializing` — the
    /// client still owes a patches upload + `FinalizeSession`
    /// before a shell can be minted.
    SessionPending,
    /// The session's `WorkspaceFilesTarZst` upload is still streaming, so
    /// the workspace the attach would configure against is incomplete:
    /// the Draft shortcut would scaffold a default against a half-empty
    /// tree and later conflict with the uploaded layout. The client
    /// should retry once the upload has landed.
    WorkspaceUploadInFlight,
    /// The session host is alive but busy (its mailbox stayed full past the
    /// attach deadline). The client should retry.
    SessionBusy,
    /// This box carries host-handed addresses (T66), the launch that bound
    /// its host-side row no longer holds the slot — its loop ended, a later
    /// launch replaced it, or the daemon restarted — and the VM host daemon
    /// holds no row for it (NET-138): the row was withdrawn after its detach
    /// grace and its creator did not resume it. The host gate drops frames
    /// from an unregistered source, so any host handed out now would be
    /// "rowless". Only the box's creator registers or resumes a row, and the
    /// client resumes it before every attach and exec, so the message names
    /// a re-run as the way forward, and a new activation once the host no
    /// longer holds the creator's record to resume from.
    BoxHostRowEnded,
}

impl std::error::Error for AttachError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AttachError::InvalidPolicy(e) => Some(e),
            AttachError::LoadoutFailed(e) => Some(e),
            AttachError::LaunchRecordUnwritable(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttachError::ContextCreationFailed(e) => {
                write!(f, "init of minimal context: {e}")
            }
            AttachError::NoPty => write!(f, "SSH channel did not configure a PTY"),
            AttachError::SpawnFailed(e) => write!(f, "session spawn: {e}"),
            AttachError::InvalidPolicy(e) => write!(f, "invalid session policy: {e}"),
            AttachError::LoadoutFailed(e) => write!(f, "configuring session loadout: {e}"),
            AttachError::LaunchRecordUnwritable(e) => write!(
                f,
                "starting the session failed: the session's saved state could \
                 not be updated: {e}"
            ),
            AttachError::SessionPending => write!(
                f,
                "session isn't attachable yet (still being activated; retry \
                 after the activation finishes)"
            ),
            AttachError::WorkspaceUploadInFlight => write!(
                f,
                "session is still receiving its workspace upload; retry the \
                 attach once the upload completes"
            ),
            AttachError::SessionBusy => {
                write!(f, "the session is busy; run the attach again in a moment")
            }
            AttachError::BoxHostRowEnded => write!(
                f,
                "the VM host daemon released this session's network addresses; run \
                 the same command again to restore them. If it is refused again, \
                 destroy the session with `min session destroy <session>` and start \
                 it again with `min session activate`"
            ),
        }
    }
}

impl BoxActor {
    pub(super) async fn attach(
        &mut self,
        session_hnd: BoxHandle,
        conn_username: String,
        channel: Channel<Msg>,
        config: ChannelConfig,
        attacher: Option<std::sync::Weak<()>>,
    ) -> Result<(), AttachError> {
        let sz = WinSize::from(match config.pty.as_ref() {
            Some(pty) => pty,
            None => return Err(AttachError::NoPty),
        });

        // Capture the environment this attach contributes to the shell it may
        // mint: the locale/timezone vars the client forwarded (folded as
        // defaults below the composition) and the per-connection facts folded
        // above it — `TERM` from the client's PTY request, and the banner's
        // detach hint derived from the negotiated keys below.
        //
        // `SSH_TTY` and `SSH_CONNECTION`/`SSH_CLIENT` are intentionally omitted:
        // the session sandbox has no host `/dev/pts` and the transport is a
        // local Unix socket (no peer IP/port), so any value would name something
        // that doesn't exist in-session and would only mislead audit logs,
        // source-IP checks, or `$SSH_TTY` consumers.
        // The negotiated session keys: the leader chord and detach/forward
        // subcommand keys the client sent on this channel, re-validated here as
        // a silent safety backstop (a bad chord falls back to the default,
        // never garbling the screen). Per-channel: two clients with different
        // configs on the same session each get their own chord.
        let session_keys = SessionKeys::from_env(&config.env_vars).validated_or_default();

        let attach_env = {
            let inherited = inherited_session_env(&config.env_vars);
            let mut connection = Vec::new();
            match config.pty.as_ref().map(|pty| pty.term.as_str()) {
                Some(term) if !term.is_empty() => {
                    tracing::info!(term, "attach carries a terminal");
                    connection.push(("TERM".to_string(), term.to_string()));
                }
                // The client had nothing to say about its terminal — OpenSSH
                // sends an empty pty-req term string when its own `TERM` is
                // unset. The session keeps whatever the last attach published,
                // which is right (an absent value is not an assertion that
                // there is no terminal) but indistinguishable from "nothing
                // changed" unless it is said out loud. Logged because the
                // silence here has already cost one debugging session: the
                // symptom is a session whose `TERM` never follows the client,
                // and this line is the difference between reading it off and
                // guessing at it.
                _ => tracing::info!(
                    "attach carries no terminal (client sent an empty pty-req term); \
                     keeping the last published TERM"
                ),
            }
            // The orientation banner's detach hint: derived from the negotiated
            // keys so a remapped leader/detach chord advertises itself. Seeded
            // daemon-side (like MINIMAL_SESSION_NAME), never forwarded from the
            // client — the client sends raw key names, the daemon builds the
            // display string. The MOTD template interpolates this with a
            // `${VAR:-fallback}` so an unset var (no negotiation) still renders.
            connection.push((
                "MINIMAL_DETACH_HINT".to_string(),
                format!(
                    "{} then {}",
                    session_keys.leader.as_config_str(),
                    session_keys.detach_key.as_config_str(),
                ),
            ));
            box_runtime::AttachEnv {
                inherited,
                connection,
            }
        };

        // A session that was created but never had its loadout configured has
        // nothing in flight, so attaching to it shouldn't be an error: set it
        // up now, with an empty contribution, and carry on into the attach.
        // Composition that comes back `Pending` is the one case we can't
        // resolve here — items need a client-side gate — and falls through to
        // the refusal below.
        //
        // The shortcut only works when the composition ends up with
        // no patches. Patches require the client to run the
        // `WorkspacePatchesTarZst` upload + `FinalizeSession`
        // sequence, and this attach path has no way to obtain those
        // files — nothing on the daemon side reaches back to the
        // client to solicit an upload. If we ran `configure_loadout`
        // and it produced patches, the record would be stuck at
        // `Materializing` with no path to `Active` and every
        // subsequent attach would hit the `SessionPending` refusal.
        // So: run the configure, and if patches surfaced, roll the
        // in-memory state back to `Draft { pending: None }` (the
        // record's on-disk `Materializing` status still leaves it
        // reachable for `DestroySession`) and refuse the attach with
        // an actionable error naming the required explicit flow.
        if let BoxInner::Draft { pending: None } = &self.inner {
            // Refuse the shortcut while the workspace upload is still
            // streaming: it configures against whatever the tree holds
            // right now, and mid-upload that is a half-populated workspace
            // whose scaffolded default would conflict with the layout the
            // upload is about to land. The client retries once the upload
            // completes.
            if self.workspace_uploads_in_flight > 0 {
                return Err(AttachError::WorkspaceUploadInFlight);
            }
            // Refuse it too while the creating connection is live, unless
            // that connection is the one attaching: it is mid-activation —
            // before its upload, or after it and before its
            // `ConfigureLoadout` — and configuring the session from elsewhere
            // would compose an empty contribution against a workspace it has
            // not finished with, then refuse the creator's own configure.
            if self.creator.as_ref().is_some_and(|creator| {
                creator.strong_count() > 0
                    && !attacher
                        .as_ref()
                        .is_some_and(|attacher| std::sync::Weak::ptr_eq(attacher, creator))
            }) {
                return Err(AttachError::SessionPending);
            }
            // Hooks are forced off on this path regardless of the
            // record. The shortcut composes with no client in the loop,
            // and a project hook needs a client-side policy decision it
            // has no way to obtain — composing with hooks on would
            // return `Pending`, which this path cannot resolve, and
            // every attach to a hook-declaring project would fail.
            // A session that wants its project's hooks has to come up
            // through `min session activate`, where the user is present
            // to answer for them.
            self.configure_loadout(WireContribution::default(), false)
                .await
                .map_err(AttachError::LoadoutFailed)?;
            let has_patches = matches!(
                &self.inner,
                BoxInner::Active {
                    composition: Some(c),
                    ..
                } if !c.patches().is_empty()
            );
            if has_patches {
                // Refuse: this attach path can't run the
                // upload + FinalizeSession sequence the composition
                // requires. `finalize`'s per-op guard will refuse
                // any later attempt against this Materializing
                // record, so the operator has to destroy it and
                // re-activate through `min session activate`, which drives
                // the full flow.
                return Err(AttachError::LoadoutFailed(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "this session's configuration includes patches that only \
                     `min session activate` can apply; destroy it with \
                     `min session destroy <session>`, then run \
                     `min session activate` again",
                )));
            }
            // No patches: finalize inline so the shortcut still
            // yields an attachable session. The marker check inside
            // `finalize` is gated on `!composition.patches().is_empty()`,
            // so an empty composition doesn't need the dir + marker
            // to exist: `finalize` skips the check, `materialize`
            // iterates zero patches, and the record is written as
            // `Active`.
            self.finalize().await.map_err(AttachError::LoadoutFailed)?;
        }

        // Attach is gated on `Active` — a Materializing session has
        // a composition but its patches may not be on disk yet,
        // and materializing without them would produce a broken
        // sandbox rootfs. See [`BoxActor::finalize`] for the
        // transition.
        let record = self
            .record
            .record()
            .await
            .map_err(AttachError::LoadoutFailed)?;
        if record.status != BoxState::Active {
            return Err(AttachError::SessionPending);
        }
        // Before any respawn or re-mint below: a registered box whose row is
        // gone must not be handed a rowless host, whichever way the slot came
        // to be without its binding launch — the shell exited, a hook run
        // relaunched over a dead host, or the daemon restarted.
        if self.host_row_lost(&record).await {
            return Err(AttachError::BoxHostRowEnded);
        }
        let holds_host_row = record.box_addresses.is_some();

        // A host minted to run hooks has an environment that describes no
        // terminal, because there was none — and the shell's `environ` cannot
        // be revised in place. Nothing of the user's is running in it (its
        // shell is still held at the launch's start gate, and the activation
        // hooks it was launched for have completed by the time an attach can
        // arrive), so replace it with one minted for the terminal that is
        // actually here. An `Exec`-minted host is deliberately not
        // replaced: a command is live inside that sandbox, and killing it to
        // improve `TERM` is a bad trade. A box the host registered is not
        // replaced either, because ending its PTask ends the shuttle
        // connection the host-side row is tied to. Both cases ride on the
        // per-attach environment the host republishes instead; a kept hook
        // host's shell starts only now, when this attach releases its start
        // gate, so its startup still runs after the activate hooks (#2118).
        let declares_terminal = attach_env.declares_terminal();
        let respawn_for_terminal =
            replaces_host_for_terminal(self.host_origin, declares_terminal, holds_host_row);
        // Kept only for its row: the same host would be replaced without one.
        let kept_for_host_row = !respawn_for_terminal
            && replaces_host_for_terminal(self.host_origin, declares_terminal, false);
        if respawn_for_terminal
            && let BoxInner::Active {
                host: slot @ Some(_),
                ..
            } = &mut self.inner
        {
            tracing::info!(
                "replacing the hook-launched session shell with one minted for the attaching terminal"
            );
            let (handle, mut join) = slot.take().expect("matched on Some");
            // Bound the wait for the hook host to wind down, aborting a wedged
            // loop rather than parking the attach behind it. Same bounded
            // kill-and-stop as shutdown; see [`BoxActor::kill_and_stop_loop`].
            Self::kill_and_stop_loop(&handle, &mut join, false).await;
        } else if kept_for_host_row {
            tracing::info!(
                "kept the hook-launched session shell: replacing it would end the box's \
                 host-side row; the terminal's environment rides the per-attach republish"
            );
        }

        let host = match &mut self.inner {
            // Awaiting a verdict: a client is mid create flow, and composing
            // over it here would discard the items it is still gating.
            BoxInner::Draft { .. } => return Err(AttachError::SessionPending),
            BoxInner::Active { host, .. } => host,
        };
        match host {
            None => {
                self.mint_session_host(
                    session_hnd,
                    conn_username,
                    channel,
                    sz,
                    attach_env,
                    session_keys,
                )
                .await
            }
            Some((h, _)) => {
                // Every attach carries the connection facts, not just the one
                // that mints the shell: `TERM` describes whichever terminal is
                // on the other end of *this* channel.
                match h
                    .attach(channel, sz, attach_env.connection_env(), session_keys)
                    .await
                {
                    Ok(()) => Ok(()),
                    Err(box_runtime::HostAttachError::Closed(channel, sz)) => {
                        // A registered box's row ended with this loop
                        // (NET-138); re-minting would re-attach it rowless.
                        // The check at the top of this attach normally
                        // refuses first, but the loop can end between that
                        // check and this send, so ask again.
                        if self.host_row_lost(&record).await {
                            return Err(AttachError::BoxHostRowEnded);
                        }
                        // The host's loop has ended; mint a fresh one from the
                        // channel it handed back.
                        self.mint_session_host(
                            session_hnd,
                            conn_username,
                            channel,
                            sz,
                            attach_env,
                            session_keys,
                        )
                        .await
                    }
                    Err(box_runtime::HostAttachError::Timeout) => {
                        // The host is alive but its mailbox stayed full past
                        // the attach deadline. Re-minting here would abort a
                        // busy-but-healthy shell, orphaning its processes and
                        // skipping its NetGuard teardown. Refuse instead: the
                        // client can retry once the host drains.
                        Err(AttachError::SessionBusy)
                    }
                }
            }
        }
    }
}

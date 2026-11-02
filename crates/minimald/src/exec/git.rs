//! `git-receive-pack` and `git-upload-pack` against a session's
//! workspace.

use super::*;

/// Serves `git-receive-pack min://<session>` (a `min` push to a session's
/// workspace) on channel `id`.
///
/// Runs in a `git_receive` span that adopts the client's `TRACEPARENT`: the
/// session lookup and the spawned receive-pack process's work are its
/// children, so a push is one trace with the CLI's (TEL-022).
pub(super) async fn handle_git_receive(
    ident: &str,
    serv: ServerStateHandle,
    conn: ConnectionHandle,
    id: ChannelId,
    session: &mut Session,
    channel: Channel<Msg>,
    config: ChannelConfig,
) -> Result<(), ConnectionError> {
    let session_pred = {
        match config.env_vars.get(MINIMAL_SESSION_ID_ENV) {
            Some(id_str) => match SessionId::parse_str(id_str) {
                Ok(id) => BoxKeyPredicate::Id(id),
                Err(_e) => {
                    tracing::warn!(
                        value = %id_str,
                        "git-receive-pack rejected on channel {id}: {MINIMAL_SESSION_ID_ENV} is not a uuid",
                    );
                    session.channel_failure(id)?;
                    return Ok(());
                }
            },
            None => match SessionId::parse_str(ident) {
                Ok(id) => BoxKeyPredicate::Id(id),
                Err(_e) => BoxKeyPredicate::Name(ident.to_string()),
            },
        }
    };

    // The lookup runs in this push's span, so its manager message is not a
    // trace root of its own (as for an exec: see `handle_exec`).
    let span = tracing::info_span!(
        "git_receive",
        telemetry = tracing::field::Empty,
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
        parent_span_id = tracing::field::Empty,
    );
    adopt_client_trace(&span, &config);
    let mngr = serv.sessions_manager().await;
    let session_handle = match mngr
        .get_session(session_pred)
        .instrument(span.clone())
        .await
    {
        Ok(Some(h)) => h,
        Ok(None) => {
            tracing::warn!("git-receive-pack rejected: unknown session");
            session.channel_failure(id)?;
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(error = %e, "git-receive-pack rejected: lookup failed");
            session.channel_failure(id)?;
            return Ok(());
        }
    };
    session.channel_success(id)?;

    // The receive-pack process ends with this channel: request-bounded work,
    // so it runs as the span's child (`traced::spawn` carries the entered
    // span), not as a root of its own.
    let task = async move {
        let paths = match session_handle.paths().await {
            Ok(paths) => paths,
            // The actor died between resolve and this call (raced an
            // abort/destroy); the channel was already acked, so just drop it.
            Err(e) => {
                tracing::warn!(error = %e, "git-receive-pack aborted: session is gone");
                return;
            }
        };

        let dotgit_dir = paths.working.as_utf8_path().join(".git");
        if let Ok(false) = tokio::fs::try_exists(&dotgit_dir).await {
            // No .git directory exists, so this is likely
            // the first push to populate. Create an empty git
            // repo, and make sure its configured to checkout
            // the ref it recieves.
            let mut init = tokio::process::Command::new("git");
            init.arg("init").current_dir(paths.working.as_utf8_path());
            for name in git_repo_location_env() {
                init.env_remove(name);
            }
            let res = init.output().await;
            if let Err(e) = res {
                tracing::warn!(error = %e, "git init failed");
                channel.close().await.unwrap();
                return;
            }
        }
        let hooks_tmp = TempDir::new().unwrap();
        tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o755)
            .open(hooks_tmp.path().join("post-receive"))
            .await
            .unwrap()
            .write_all(
                r#"#!/bin/sh
                GIT_DIR_ABS=$(pwd -P)
                WORK_TREE=$(dirname "$GIT_DIR_ABS")
                unset GIT_DIR GIT_WORK_TREE GIT_QUARANTINE_PATH
                g() { git --git-dir="$GIT_DIR_ABS" --work-tree="$WORK_TREE" "$@"; }
                # The branch currently checked out in the worktree, and
                # whether HEAD resolves to a commit (`born`). The first push
                # into a fresh workspace has no commit on HEAD, so the first
                # pushed branch that checks out cleanly populates the
                # worktree and becomes HEAD. After that, a push to any branch
                # other than the checked-out one must not move HEAD or touch
                # the worktree. post-receive runs after the refs moved, so a
                # first push that includes HEAD's own branch already reads as
                # born, and that branch is the one checked out.
                cur=$(g symbolic-ref -q HEAD)
                born=
                detached_moved=
                g rev-parse -q --verify HEAD >/dev/null && born=yes

                zero=0000000000000000000000000000000000000000
                while read -r old new ref; do
                    case "$ref" in refs/heads/*) ;; *) continue ;; esac
                    # A deleted branch (new = zeros) has nothing to check out.
                    # Deleting the CURRENT branch never reaches here: git's own
                    # receive.denyDeleteCurrent refuses it during receive-pack.
                    [ "$new" = "$zero" ] && continue
                    branch=${ref#refs/heads/}

                    # A push to a branch that is not the one checked out
                    # leaves HEAD and the worktree alone: the ref itself has
                    # already moved in receive-pack, so there is nothing more
                    # to do. Only on the still-unborn first push does the
                    # hook check out the first arriving branch.
                    # A detached HEAD (`cur` empty) matches no branch, so
                    # every push lands here; note it for the message below.
                    if [ "$ref" != "$cur" ] && [ -n "$born" ]; then
                        [ -z "$cur" ] && detached_moved=yes
                        continue
                    fi

                    if [ "$old" = "$zero" ]; then
                        # Previously-unborn branch: nothing tracked, so tracked
                        # dirtiness cannot exist — but uploaded/untracked files
                        # may collide with the pushed tree, and -f would
                        # silently clobber them. -B pins the branch at the
                        # pushed tip and checks it out; WITHOUT -f, git refuses
                        # to overwrite untracked files (its stderr names them),
                        # and we surface the skip like the dirty case below.
                        if g checkout -q -B "$branch" "$new"; then
                            # HEAD is born now: later refs in this same push
                            # are other branches and must not move it.
                            cur=$ref
                            born=yes
                        else
                            echo "remote worktree has local files the push would overwrite; skipping checkout of $branch" >&2
                        fi
                        continue
                    fi

                    # Dirtiness is measured against the PRE-push tip ($old):
                    # post-receive runs after the ref has already moved, so a
                    # plain `diff --cached` (index vs the NEW tip) would flag
                    # the pushed delta itself and skip every checkout.
                    if ! g diff --quiet "$old" || ! g diff --cached --quiet "$old"; then
                        echo "remote worktree has uncommitted changes; skipping checkout of $branch" >&2
                        continue
                    fi
                    g checkout -qf "$branch"
                done

                # A detached HEAD stays detached, as with plain git; say so
                # once, so the pusher knows the worktree did not change.
                if [ -n "$detached_moved" ]; then
                    echo "remote worktree HEAD is detached; moved refs without checking out (run git switch <branch> in the session)" >&2
                fi"#
                    .as_bytes(),
            )
            .await
            .unwrap();

        let exec_task = ExecTask {
            conn,
            serv,
            session: session_handle,
            channel_id: id,
            exec: TokioExec {
                // receive.denyCurrentBranch=ignore: the workspace is a
                // non-bare repo with the pushed branch typically checked
                // out, and stock git refuses that ref update outright —
                // before any hook runs. `ignore` accepts it silently; the
                // post-receive hook above then syncs the worktree (or
                // warns and skips when it is dirty). NOT `updateInstead`:
                // that rejects the whole push on a dirty worktree, while
                // the hook's contract is "ref lands, checkout best-effort".
                argv: format!(
                    "git -c core.hooksPath={} -c receive.denyCurrentBranch=ignore receive-pack .",
                    hooks_tmp.path().to_str().unwrap()
                ),
                cwd: paths.working,
                env: BTreeMap::new(),
                drop_env: git_repo_location_env(),
            },
        };
        exec_task.run(channel).await;
        drop(hooks_tmp);
    };
    span.in_scope(|| crate::traced::spawn(task));

    Ok(())
}

/// Serves `git-upload-pack min://<session>` (a `min` fetch, clone or
/// ls-remote of a session's workspace) on channel `id`.
///
/// Runs in a `git_upload` span that adopts the client's `TRACEPARENT`, as a
/// push runs in `git_receive`: the session lookup and the spawned pack
/// process's work are its children, so a fetch is one trace with the CLI's
/// (TEL-022) rather than a root `GetSession` of its own.
pub(super) async fn handle_git_upload(
    ident: &str,
    serv: ServerStateHandle,
    conn: ConnectionHandle,
    id: ChannelId,
    session: &mut Session,
    channel: Channel<Msg>,
    config: ChannelConfig,
) -> Result<(), ConnectionError> {
    let session_pred = {
        match config.env_vars.get(MINIMAL_SESSION_ID_ENV) {
            Some(id_str) => match SessionId::parse_str(id_str) {
                Ok(id) => BoxKeyPredicate::Id(id),
                Err(_e) => {
                    tracing::warn!(
                        value = %id_str,
                        "git-upload-pack rejected on channel {id}: {MINIMAL_SESSION_ID_ENV} is not a uuid",
                    );
                    session.channel_failure(id)?;
                    return Ok(());
                }
            },
            None => match SessionId::parse_str(ident) {
                Ok(id) => BoxKeyPredicate::Id(id),
                Err(_e) => BoxKeyPredicate::Name(ident.to_string()),
            },
        }
    };

    // The lookup runs in this fetch's span, so its manager message is not a
    // trace root of its own (as for a push: see `handle_git_receive`).
    let span = tracing::info_span!(
        "git_upload",
        telemetry = tracing::field::Empty,
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
        parent_span_id = tracing::field::Empty,
    );
    adopt_client_trace(&span, &config);
    let mngr = serv.sessions_manager().await;
    let lookup = mngr
        .get_session(session_pred)
        .instrument(span.clone())
        .await;
    let session_handle = match lookup {
        Ok(Some(h)) => h,
        Ok(None) => {
            span.in_scope(|| tracing::warn!("git-upload-pack rejected: unknown session"));
            session.channel_failure(id)?;
            return Ok(());
        }
        Err(e) => {
            span.in_scope(|| tracing::warn!(error = %e, "git-upload-pack rejected: lookup failed"));
            session.channel_failure(id)?;
            return Ok(());
        }
    };
    session.channel_success(id)?;

    // The pack process ends with this channel: request-bounded work, so it
    // runs as the span's child (`traced::spawn` carries the entered span).
    let task = async move {
        let paths = match session_handle.paths().await {
            Ok(paths) => paths,
            Err(e) => {
                tracing::warn!(error = %e, "git-upload-pack aborted: session is gone");
                let _ = channel.close().await;
                return;
            }
        };

        let dotgit_dir = paths.working.as_utf8_path().join(".git");
        if let Ok(false) = tokio::fs::try_exists(&dotgit_dir).await {
            // A read-only request (ls-remote, fetch, clone) must not create
            // a repository in the session workspace: `git init` would write
            // a `.git` directory as the daemon user on an operation the
            // client believes is read-only, and would turn an
            // uploaded/generated workspace into a repo with an unborn
            // branch. Reject instead of initializing.
            let msg = "minimald: session has no repository yet\n";
            tracing::warn!("git-upload-pack rejected: session has no repository");
            let _ = channel.extended_data(1, msg.as_bytes()).await;
            let _ = channel.exit_status(1).await;
            let _ = channel.eof().await;
            let _ = channel.close().await;
            return;
        }

        let exec_task = ExecTask {
            conn,
            serv,
            session: session_handle,
            channel_id: id,
            exec: TokioExec {
                argv: "git upload-pack .".to_string(),
                cwd: paths.working,
                env: BTreeMap::new(),
                drop_env: git_repo_location_env(),
            },
        };
        exec_task.run(channel).await;
    };
    span.in_scope(|| crate::traced::spawn(task));

    Ok(())
}

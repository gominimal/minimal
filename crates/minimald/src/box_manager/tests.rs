use super::*;
use crate::box_actor::PACKAGE_CHECK_DEADLINE;
use boxes::daemon::composer::ComposeOutcome;
use boxes::wire::request::{BoxStep, ContributionVerdict, WireContribution};
use common::SpecHash;
use paths::HostAbsPath;
use std::collections::HashSet;
use std::io::ErrorKind;
use tempfile::TempDir;

/// A stand-in for the client-side project path a session record
/// carries — the identity the composer stamps onto the project's
/// contributions, distinct from the daemon workspace it reads.
fn declared_path() -> paths::HostAbsPath {
    paths::HostAbsPath::try_new("/home/dev/myproject").unwrap()
}

/// Resolves the session's live actor and peeks its held
/// [`Composition`](boxes::core::compose::Composition).
async fn peek_composition(
    mngr: &BoxManagerHandle,
    id: SessionId,
) -> Arc<boxes::core::compose::Composition> {
    mngr.get_session(BoxKeyPredicate::Id(id))
        .await
        .expect("get_session succeeds")
        .expect("session resolves")
        .peek_composition()
        .await
        .expect("the session actor should hold a composition")
}

/// Resolves the session's live actor.
async fn session(mngr: &BoxManagerHandle, id: SessionId) -> BoxHandle {
    mngr.get_session(BoxKeyPredicate::Id(id))
        .await
        .expect("get_session succeeds")
        .expect("session resolves")
}

/// Writes `contents` as the project mfile in the session's daemon-side
/// workspace, standing in for the client's `WorkspaceFilesTarZst`
/// upload. The compose path reads the mfile off that workspace, so
/// tests that want `configure_loadout` to see a project seed it here
/// between `create_session` and `configure_loadout` — exactly the
/// spot a real client's upload lands in.
async fn seed_workspace_mfile(mngr: &BoxManagerHandle, id: SessionId, contents: &str) {
    let paths = session(mngr, id).await.paths().await.unwrap();
    tokio::fs::write(
        paths.working.as_utf8_path().join(mfile::MFILE_NAME),
        contents,
    )
    .await
    .unwrap();
}

/// Creates a session, seeds `mfile` into its workspace, and configures
/// its loadout with an empty client contribution — the whole create
/// flow a client drives, in one call. Returns the manager and the id
/// alongside the compose outcome.
async fn create_and_configure(
    mfile: &str,
) -> (
    TempDir,
    TempDir,
    BoxManagerHandle,
    SessionId,
    Option<boxes::wire::request::ContributionResponse>,
) {
    let (state, cache, mngr) = manager().await;
    let id = mngr.create_session(sample_config(), None).await.unwrap();
    seed_workspace_mfile(&mngr, id, mfile).await;
    let response = session(&mngr, id)
        .await
        .configure_loadout(WireContribution::default())
        .await
        .expect("configuring the loadout should succeed");
    (state, cache, mngr, id, response)
}

/// A project mfile whose `[session.vars]` entry forces the composer down
/// the Pending path: a daemon-collected var must be gated by the client.
const PENDING_VAR_MFILE: &str = "[session.vars]\nRUST_LOG = \"info\"\n";

/// Drives a session to the point of awaiting a verdict: created,
/// workspace seeded with [`PENDING_VAR_MFILE`], loadout configured and
/// come back `Pending`. Returns the manager, the id, and the wire
/// response carrying the pending var.
async fn create_pending_session() -> (
    TempDir,
    TempDir,
    BoxManagerHandle,
    SessionId,
    boxes::wire::request::ContributionResponse,
) {
    let (state, cache, mngr, id, response) = create_and_configure(PENDING_VAR_MFILE).await;
    let response = response.expect("a daemon-side var should pend, not finalize");
    (state, cache, mngr, id, response)
}

/// An approve-everything verdict for the given pending response.
fn approve_all(
    id: SessionId,
    response: &boxes::wire::request::ContributionResponse,
) -> ContributionVerdict {
    ContributionVerdict {
        session_id: id,
        vars: response
            .vars
            .iter()
            .map(|pv| boxes::wire::policy::WireVarVerdict::Approved {
                id: pv.id,
                value: boxes::wire::primitives::WireResolvedVar {
                    name: pv.name.clone(),
                    value: "info".into(),
                    carries_user_data: true,
                },
            })
            .collect(),
        patches: vec![],
        lifecycle_hooks: vec![],
    }
}

fn sample_config() -> minimald_rpc::BoxConfig {
    minimald_rpc::BoxConfig {
        name: Some("doomed".to_string()),
        project_path: HostAbsPath::try_new("/proj").unwrap(),
        network: boxes::NetworkMode::default(),
        policy: Default::default(),
        task_addresses: Vec::new(),
        box_id: None,
        box_addresses: None,
        hooks_enabled: true,
        ends_with_run: false,
        attrs: Default::default(),
        sealed_deliveries: Vec::new(),
        root_certificate: None,
        creating_verb: minimald_rpc::CreatingVerb::Session,
        project_root: None,
    }
}

/// Test helper: create a session via the in-process manager actor (not
/// RPC) and configure its loadout against an empty workspace, so it
/// lands `Active` with an empty composition — the shape most lifecycle
/// tests want.
async fn create_active_session(mngr: &BoxManagerHandle) -> SessionId {
    create_active_session_with(mngr, sample_config()).await
}

/// [`create_active_session`] with a caller-supplied config.
/// Drives the whole `CreateSession → ConfigureLoadout →
/// FinalizeSession` sequence in-process so the returned
/// session's record is `Active` (attachable, hostname
/// registered). No patches for these fixtures, so the
/// composition-empty short-circuit in `finalize` covers the
/// marker precondition.
async fn create_active_session_with(
    mngr: &BoxManagerHandle,
    config: minimald_rpc::BoxConfig,
) -> SessionId {
    create_active_session_contributing(mngr, config, WireContribution::default()).await
}

/// [`create_active_session_with`] carrying a client contribution —
/// the way a test gets lifecycle hooks into a session's composition.
async fn create_active_session_contributing(
    mngr: &BoxManagerHandle,
    config: minimald_rpc::BoxConfig,
    contribution: WireContribution,
) -> SessionId {
    let id = mngr.create_session(config, None).await.unwrap();
    let handle = session(mngr, id).await;
    let response = handle
        .configure_loadout(contribution)
        .await
        .expect("configuring an empty loadout should succeed");
    assert!(response.is_none(), "an empty loadout should finalize");
    handle
        .finalize()
        .await
        .expect("finalize should succeed for a patchless composition");
    id
}

async fn manager() -> (TempDir, TempDir, BoxManagerHandle) {
    let state = TempDir::new().unwrap();
    let cache = TempDir::new().unwrap();
    let mngr = manager_over(state.path(), cache.path()).await;
    (state, cache, mngr)
}

/// A manager rooted at existing state and cache directories, so a
/// test can stand a second one up over the first's store — the way
/// a daemon restart sees a session it never started.
async fn manager_over(state: &std::path::Path, cache: &std::path::Path) -> BoxManagerHandle {
    let state = state.to_path_buf();
    let cache = cache.to_path_buf();
    // These tests never start an `OwnIp` launch (they use the mock
    // launcher), so the switch is never spawned; a placeholder binary path
    // is sufficient.
    let switch = Arc::new(Mutex::new(crate::net::SwitchClient::new(
        "/nonexistent/gvproxy",
        state.join("gvproxy"),
    )));
    // Tests use per-TempDir cache/state dirs so they don't pollute the
    // shared daemon paths a real invocation would touch.
    let mctx_config = mctx::ConfigBuilder::new()
        .with_cache_dir(&cache)
        .with_state_dir(&state)
        .with_daemon_id("test".to_string())
        .build()
        .unwrap();
    let daemon_ctx = Arc::new(mctx::DaemonContext::init(mctx_config).unwrap());
    // `false`: these tests run the default the build ships, not the
    // opt-out.
    BoxManager::init(
        daemon_abs(&state),
        daemon_abs(&cache),
        daemon_ctx,
        switch,
        false,
    )
    .await
    .unwrap()
}

/// A [`DaemonAbsPath`] for a test directory.
fn daemon_abs(p: &std::path::Path) -> DaemonAbsPath {
    DaemonAbsPath::try_new(p.to_str().unwrap()).unwrap()
}

/// `GetScreen` answers every resolution outcome, by id and by name.
///
/// Worth pinning because the probe no longer runs on the manager's
/// mainloop: it is spawned, so the responder travels into a task and a
/// mis-wired arm would leave the caller on a oneshot that is never sent
/// rather than failing loudly. A live session with no host takes the
/// spawned path, which is what proves that wiring delivers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_screen_answers_whether_or_not_a_session_resolves() {
    let (_state, _cache, mngr) = manager().await;

    // Nothing created yet: neither predicate resolves.
    assert!(
        mngr.get_screen(BoxKeyPredicate::Id(SessionId::nil()))
            .await
            .unwrap()
            .is_none(),
        "an unknown id should answer None, not hang or error"
    );
    assert!(
        mngr.get_screen(BoxKeyPredicate::Name("nonesuch".to_string()))
            .await
            .unwrap()
            .is_none(),
        "an unknown name should answer None, not hang or error"
    );

    // A live actor that never launched a host: resolves, so the probe
    // is spawned, and the session reports no screen.
    let id = create_active_session(&mngr).await;
    assert!(
        mngr.get_screen(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "a session with no running host should answer None"
    );
    assert!(
        mngr.get_screen(BoxKeyPredicate::Name("doomed".to_string()))
            .await
            .unwrap()
            .is_none(),
        "resolving by name should reach the same session"
    );

    // The mainloop is still serving after all of it.
    assert_eq!(mngr.list().await.unwrap().len(), 1);
}

/// Destroying a known-but-not-running session removes its record so it no
/// longer resolves or lists, and frees its name for reuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destroy_removes_a_non_running_session() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session(&mngr).await;

    mngr.delete_session(id).await.unwrap();

    assert!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "the record should be gone after destroy"
    );
    assert!(mngr.list().await.unwrap().is_empty());
    // The name index entry was dropped, so the name can be taken again.
    let _ = create_active_session(&mngr).await;
}

/// Destroying a session whose actor is not running must still go
/// through that actor, because teardown is the actor's job — and now
/// includes running the session's `on_destroy` hooks.
///
/// The shortcut this replaced ("never spawned, so nothing to undo —
/// just remove the record") predated hooks and skipped them in
/// silence for every session whose actor had been reaped, which after
/// a daemon restart is all of them. Asserted through the live-actor
/// count: the destroy has to bring one up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destroying_an_idle_session_goes_through_its_actor() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("destroyed");

    let (state, cache, mngr) = manager().await;
    // A destroy hook is the discriminator: both the actor path and the
    // old shortcut delete the record, so only the hook's side effect
    // tells them apart.
    let id = create_active_session_contributing(
        &mngr,
        sample_config(),
        WireContribution {
            lifecycle_hooks: vec![boxes::wire::primitives::WireProvenancedHook {
                hook: boxes::wire::primitives::WireLifecycleHook {
                    on_destroy: Some(boxes::wire::primitives::WireHookScript::Inline {
                        body: format!("echo ran > {}", marker.display()),
                        timeout_secs: 60,
                    }),
                    ..Default::default()
                },
                source: boxes::wire::primitives::WireSource::UserLoadout {
                    name: "test".to_string(),
                },
            }],
            ..Default::default()
        },
    )
    .await;

    // A second manager over the same store knows the session from disk
    // and has never run it — a daemon restart's view, and the state the
    // old shortcut applied to.
    let restarted = manager_over(state.path(), cache.path()).await;
    assert_eq!(restarted.running_count().await, 0);

    restarted.delete_session(id).await.unwrap();

    assert!(
        marker.exists(),
        "destroying an idle session skipped its on_destroy hook",
    );
    assert!(
        restarted
            .get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "the record should be gone after destroy"
    );
}

/// `sample_config` for a box created for a `min task run` without
/// `--keep`: marked to end with its run from its create.
fn run_owned_config() -> minimald_rpc::BoxConfig {
    let mut config = sample_config();
    config.ends_with_run = true;
    config
}

/// Waits for the resume's detached teardown of `id` to remove its
/// record. The resume returns before the teardown ends, by design.
///
/// A read that lands while the teardown deletes the record can find
/// the index entry and then miss the record, and answers `NotFound`
/// rather than `None`. Both mean the record is gone.
async fn wait_for_record_gone(mngr: &BoxManagerHandle, id: SessionId) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match mngr.get_record(BoxKeyPredicate::Id(id)).await {
            Ok(None) => break,
            Err(error) if error.kind() == NotFound => break,
            Ok(Some(_)) => {}
            Err(error) => panic!("reading the run-owned box's record failed: {error}"),
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the run-owned box's record should be gone after the resume"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// A box marked run-owned is destroyed by the restart's resume, not
/// resumed: the run it was minted for is over the moment the daemon
/// that accepted it died, and bringing the box back would strand it
/// `Active` forever. The teardown goes through the actor — the same
/// path `DeleteSession` takes — so the box's `on_destroy` hooks run,
/// which the marker file stands in for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_destroys_a_run_owned_box_instead_of_resuming_it() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("destroyed");

    let (state, cache, mngr) = manager().await;
    let id = create_active_session_contributing(
        &mngr,
        run_owned_config(),
        WireContribution {
            lifecycle_hooks: vec![boxes::wire::primitives::WireProvenancedHook {
                hook: boxes::wire::primitives::WireLifecycleHook {
                    on_destroy: Some(boxes::wire::primitives::WireHookScript::Inline {
                        body: format!("echo ran > {}", marker.display()),
                        timeout_secs: 60,
                    }),
                    ..Default::default()
                },
                source: boxes::wire::primitives::WireSource::UserLoadout {
                    name: "test".to_string(),
                },
            }],
            ..Default::default()
        },
    )
    .await;

    // A second manager over the same store: a daemon restart's view,
    // holding a box whose run died with the first daemon.
    let restarted = manager_over(state.path(), cache.path()).await;
    let resumed = restarted.resume_active_sessions().await.unwrap();

    assert_eq!(
        resumed, 0,
        "a run-owned box must not be resumed by a restart",
    );
    wait_for_record_gone(&restarted, id).await;
    assert!(
        marker.exists(),
        "destroying the run-owned box on resume skipped its on_destroy hook",
    );
    wait_for_no_actors(&restarted).await;
}

/// Waits for the manager to hold `count` actors. The resume's teardown
/// evicts its actor only after the actor has deleted the record and
/// answered, so the record goes first.
async fn wait_for_actor_count(mngr: &BoxManagerHandle, count: usize, what: &str) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while mngr.running_count().await != count {
        assert!(tokio::time::Instant::now() < deadline, "{what}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Waits for the manager to hold no actor.
async fn wait_for_no_actors(mngr: &BoxManagerHandle) {
    wait_for_actor_count(mngr, 0, "the destroyed box must leave no actor behind").await;
}

/// A `DeleteSession` that lands while the resume's teardown of a run-owned
/// box runs its `on_destroy` hooks reaches the teardown's own actor, so
/// the hooks run once. The realistic sender is the surviving `min task run`
/// client on Ctrl-C. The hook marks its start, then waits, so the delete
/// lands inside it, and appends one line per run to the marker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_during_resume_teardown_runs_the_destroy_hooks_once() {
    let dir = tempfile::tempdir().unwrap();
    let started = dir.path().join("started");
    let marker = dir.path().join("destroyed");

    let (state, cache, mngr) = manager().await;
    let id = create_active_session_contributing(
        &mngr,
        run_owned_config(),
        WireContribution {
            lifecycle_hooks: vec![boxes::wire::primitives::WireProvenancedHook {
                hook: boxes::wire::primitives::WireLifecycleHook {
                    on_destroy: Some(boxes::wire::primitives::WireHookScript::Inline {
                        body: format!(
                            "touch {}; sleep 3; echo ran >> {}",
                            started.display(),
                            marker.display()
                        ),
                        timeout_secs: 60,
                    }),
                    ..Default::default()
                },
                source: boxes::wire::primitives::WireSource::UserLoadout {
                    name: "test".to_string(),
                },
            }],
            ..Default::default()
        },
    )
    .await;

    let restarted = manager_over(state.path(), cache.path()).await;
    let resumed = restarted.resume_active_sessions().await.unwrap();
    assert_eq!(
        resumed, 0,
        "a run-owned box must not be resumed by a restart"
    );

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while !started.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the resume's teardown never started the on_destroy hook",
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    match restarted.delete_session(id).await {
        Ok(hook_failures) => assert!(
            hook_failures.is_empty(),
            "the delete reported hook failures: {hook_failures:?}"
        ),
        // The teardown won the race to the record; still one run.
        Err(error) if error.kind() == NotFound => {}
        Err(error) => panic!("deleting the box during its resume teardown failed: {error}"),
    }

    wait_for_record_gone(&restarted, id).await;
    wait_for_no_actors(&restarted).await;
    let lines = std::fs::read_to_string(&marker).expect("the on_destroy hook never ran");
    assert_eq!(
        lines.lines().count(),
        1,
        "the on_destroy hook must run exactly once, got {lines:?}",
    );
}

/// A resume teardown of a run-owned box whose record delete fails keeps
/// its closed actor, so a later `DeleteSession` reaches that actor and
/// removes the record without running the `on_destroy` hooks again. The
/// store fails the record delete once. The hook appends one line per run
/// to the marker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_after_a_failed_resume_teardown_runs_the_destroy_hooks_once() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("destroyed");

    let (state, cache, mngr) = manager().await;
    let id = create_active_session_contributing(
        &mngr,
        run_owned_config(),
        WireContribution {
            lifecycle_hooks: vec![boxes::wire::primitives::WireProvenancedHook {
                hook: boxes::wire::primitives::WireLifecycleHook {
                    on_destroy: Some(boxes::wire::primitives::WireHookScript::Inline {
                        body: format!("echo ran >> {}", marker.display()),
                        timeout_secs: 60,
                    }),
                    ..Default::default()
                },
                source: boxes::wire::primitives::WireSource::UserLoadout {
                    name: "test".to_string(),
                },
            }],
            ..Default::default()
        },
    )
    .await;

    crate::store::test_faults::fail_next_delete(id);
    let restarted = manager_over(state.path(), cache.path()).await;
    let resumed = restarted.resume_active_sessions().await.unwrap();
    assert_eq!(
        resumed, 0,
        "a run-owned box must not be resumed by a restart"
    );

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while crate::store::test_faults::delete_failure_armed(&id) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the resume's teardown never tried to delete the record",
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // Give the detached teardown time to finish after its failed delete,
    // so an eviction on failure lands before the retry below.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        restarted
            .get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_some(),
        "the failed delete must leave the record on disk",
    );
    assert_eq!(
        restarted.running_count().await,
        1,
        "the failed teardown must keep its closed actor",
    );

    let hook_failures = restarted.delete_session(id).await.unwrap();
    assert!(
        hook_failures.is_empty(),
        "the retry reported hook failures: {hook_failures:?}"
    );

    wait_for_record_gone(&restarted, id).await;
    wait_for_no_actors(&restarted).await;
    let lines = std::fs::read_to_string(&marker).expect("the on_destroy hook never ran");
    assert_eq!(
        lines.lines().count(),
        1,
        "the on_destroy hook must run exactly once across the retry, got {lines:?}",
    );
}

/// The run-owned check takes only the boxes it marked: a plain
/// session in the same store survives the restart. The restart sets it
/// `stopped` and keeps it (BOX-154), and the resume does not bring it
/// back: its next attach does (BOX-025).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_keeps_a_plain_session_stopped_beside_a_run_owned_one() {
    let (state, cache, mngr) = manager().await;
    let marked = create_active_session_with(&mngr, run_owned_config()).await;
    let mut keeper_config = sample_config();
    keeper_config.name = Some("keeper".to_string());
    let keeper = create_active_session_with(&mngr, keeper_config).await;

    let restarted = manager_over(state.path(), cache.path()).await;
    let resumed = restarted.resume_active_sessions().await.unwrap();

    assert_eq!(resumed, 0, "the restart brings no box back");
    wait_for_record_gone(&restarted, marked).await;
    let record = restarted
        .get_record(BoxKeyPredicate::Id(keeper))
        .await
        .unwrap()
        .expect("the plain session's record should survive the resume");
    assert_eq!(
        record.state().unwrap(),
        boxes::core::record::RecordState::Stopped(boxes::core::record::StopEnding::AtDaemonStart),
        "the restart sets the plain session stopped and keeps it"
    );
    wait_for_no_actors(&restarted).await;
}

/// The create writes the run-owned mark on the record itself, so the
/// mark is there before any task starts, and a fresh manager over the
/// same store (a restart's) reads it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_persists_the_run_owned_mark_on_the_record() {
    let (state, cache, mngr) = manager().await;
    let marked = create_active_session_with(&mngr, run_owned_config()).await;
    let mut plain_config = sample_config();
    plain_config.name = Some("plain".to_string());
    let plain = create_active_session_with(&mngr, plain_config).await;

    let restarted = manager_over(state.path(), cache.path()).await;
    let read = |id| {
        let restarted = &restarted;
        async move {
            restarted
                .get_record(BoxKeyPredicate::Id(id))
                .await
                .unwrap()
                .expect("the record must survive the create")
        }
    };
    assert!(
        read(marked).await.ends_with_run,
        "a run-owned create must mark its record",
    );
    assert!(
        !read(plain).await.ends_with_run,
        "a plain create must leave its record unmarked",
    );
}

/// The resume's teardown of a run-owned box takes no route for its name
/// and leaves alone a box with the same name. Both boxes are unnamed,
/// with projects that share the basename "app", so both derive the
/// registry name "app". The restart sets the plain box `stopped` and
/// keeps it (BOX-154), so the resume brings only the run-owned box up,
/// to destroy it.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_teardown_keeps_the_route_of_a_same_named_box() {
    let (state, cache, mngr) = manager().await;
    let plain_project = TempDir::new().unwrap();
    let plain_dir = plain_project.path().join("app");
    std::fs::create_dir_all(&plain_dir).unwrap();
    let run_project = TempDir::new().unwrap();
    let run_dir = run_project.path().join("app");
    std::fs::create_dir_all(&run_dir).unwrap();

    let mut config = sample_config();
    config.name = None;
    config.network = boxes::NetworkMode::HostNet;
    config.project_path = HostAbsPath::try_new(plain_dir.to_str().unwrap()).unwrap();
    let plain = create_active_session_with(&mngr, config).await;

    let mut config = run_owned_config();
    config.name = None;
    config.network = boxes::NetworkMode::HostNet;
    config.project_path = HostAbsPath::try_new(run_dir.to_str().unwrap()).unwrap();
    let marked = create_active_session_with(&mngr, config).await;

    let restarted = manager_over(state.path(), cache.path()).await;
    let resumed = restarted.resume_active_sessions().await.unwrap();
    assert_eq!(resumed, 0, "the restart brings no box back");
    wait_for_record_gone(&restarted, marked).await;

    assert!(
        !restarted
            .hostnames()
            .read()
            .expect("registry lock")
            .name_held_by(marked, "app"),
        "the run-owned box's teardown must not take the route of its name",
    );
    let record = restarted
        .get_record(BoxKeyPredicate::Id(plain))
        .await
        .unwrap()
        .expect("the teardown leaves the same-named box's record alone");
    assert_eq!(
        record.state().unwrap(),
        boxes::core::record::RecordState::Stopped(boxes::core::record::StopEnding::AtDaemonStart),
    );
}

/// Reading a session's composition must not resurrect it.
///
/// `min session hooks` is a report, and a report has no business
/// starting what it reports on — `get_session` would, since it
/// brings an actor up from disk on demand. Asserted against the
/// live-actor count because that is the only place the difference
/// shows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reading_a_composition_does_not_start_the_session() {
    let (state, cache, mngr) = manager().await;
    let id = create_active_session(&mngr).await;

    // A second manager over the same store: it knows the session
    // from disk and has never run it, which is the state a daemon
    // restart leaves and the one where "did this start an actor?"
    // is answerable.
    let restarted = manager_over(state.path(), cache.path()).await;
    assert_eq!(
        restarted.running_count().await,
        0,
        "a fresh manager should not have started anything",
    );

    // The read answers for the session...
    let composition = restarted
        .get_composition(BoxKeyPredicate::Id(id))
        .await
        .expect("reading the snapshot should succeed");
    assert!(
        composition.is_some(),
        "an Active session should have a persisted composition",
    );
    // ...without bringing it up. `get_session` here would.
    assert_eq!(
        restarted.running_count().await,
        0,
        "reading the composition started the session's actor",
    );
}

/// no host is attached) tears the actor down and removes the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destroy_tears_down_a_running_session() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session(&mngr).await;

    // Bring the session actor up (populating the running map) without
    // attaching a host.
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("session should resolve");
    assert!(
        !handle.is_destroying(),
        "a session nobody destroys is not destroying",
    );

    mngr.delete_session(id).await.unwrap();

    // The handle an exec holds sees the destroy, which is how the
    // exec knows to tell its client why the command stopped.
    assert!(
        handle.is_destroying(),
        "the destroy did not mark the session's handle destroying",
    );

    // The destroy cascade completed: the record is gone, and a fresh
    // get_session no longer resolves the (now removed) session.
    assert!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        mngr.get_session(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "the session should no longer resolve after destroy"
    );
    drop(handle);
}

/// A destroy that waits on its actor must not hold the mainloop. Here
/// the wait is an `on_destroy` hook that sleeps; in the lab (710d) it
/// was the reap of a session whose actor sat inside a stalled
/// package-graph clone after its client gave up, and `min ls` queued
/// behind it for 70 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_destroy_does_not_hold_the_mainloop() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session_contributing(
        &mngr,
        sample_config(),
        WireContribution {
            lifecycle_hooks: vec![boxes::wire::primitives::WireProvenancedHook {
                hook: boxes::wire::primitives::WireLifecycleHook {
                    on_destroy: Some(boxes::wire::primitives::WireHookScript::Inline {
                        body: "sleep 5".to_string(),
                        timeout_secs: 60,
                    }),
                    ..Default::default()
                },
                source: boxes::wire::primitives::WireSource::UserLoadout {
                    name: "test".to_string(),
                },
            }],
            ..Default::default()
        },
    )
    .await;

    let destroying = mngr.clone();
    let destroy = crate::traced::spawn(async move { destroying.delete_session(id).await });
    // Measure once the destroy holds the session (its hook then runs
    // on the teardown task).
    until_claimed(&mngr, id).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), mngr.list())
        .await
        .expect("`list` queued behind a destroy that was waiting on its actor")
        .unwrap();
    assert!(
        !destroy.is_finished(),
        "the destroy hook should still be running"
    );

    let hook_failures = destroy.await.unwrap().unwrap();
    assert!(hook_failures.is_empty(), "{hook_failures:?}");
    assert!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "the record should be gone after destroy"
    );
}

/// Shutdown waits out a teardown in flight: the destroy runs on a task of
/// its own, and its hook and record delete end before the state volume
/// is quiesced, so neither races the unmount. The hook sleeps, so a
/// shutdown that did not wait would return in milliseconds with the
/// destroy still running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_waits_for_a_teardown_in_flight() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session_contributing(
        &mngr,
        sample_config(),
        WireContribution {
            lifecycle_hooks: vec![boxes::wire::primitives::WireProvenancedHook {
                hook: boxes::wire::primitives::WireLifecycleHook {
                    on_destroy: Some(boxes::wire::primitives::WireHookScript::Inline {
                        body: "sleep 2".to_string(),
                        timeout_secs: 60,
                    }),
                    ..Default::default()
                },
                source: boxes::wire::primitives::WireSource::UserLoadout {
                    name: "test".to_string(),
                },
            }],
            ..Default::default()
        },
    )
    .await;

    let destroying = mngr.clone();
    let destroy = crate::traced::spawn(async move { destroying.delete_session(id).await });
    until_claimed(&mngr, id).await;
    let started = std::time::Instant::now();
    mngr.shutdown(false)
        .await
        .expect("a teardown in flight does not refuse an unforced shutdown");
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(1),
        "shutdown returned before the destroy hook could have ended"
    );
    // The destroy answered before shutdown returned: its result is
    // already in, so the join does not wait.
    let hook_failures = tokio::time::timeout(std::time::Duration::from_millis(500), destroy)
        .await
        .expect("shutdown returned with the teardown still running")
        .unwrap()
        .unwrap();
    assert!(hook_failures.is_empty(), "{hook_failures:?}");
}

/// A resume during a teardown brings up nothing for it: the record is
/// still there (it outlives the actor by the teardown's length) and has
/// no actor in `running`, which is what resume looks for, but the
/// session is being destroyed, not idle. Without the tearing-down check a
/// resume mid-teardown started a second actor on the record the first
/// was about to delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resume_during_a_teardown_does_not_bring_the_session_up() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session_contributing(
        &mngr,
        sample_config(),
        WireContribution {
            lifecycle_hooks: vec![boxes::wire::primitives::WireProvenancedHook {
                hook: boxes::wire::primitives::WireLifecycleHook {
                    on_destroy: Some(boxes::wire::primitives::WireHookScript::Inline {
                        body: "sleep 2".to_string(),
                        timeout_secs: 60,
                    }),
                    ..Default::default()
                },
                source: boxes::wire::primitives::WireSource::UserLoadout {
                    name: "test".to_string(),
                },
            }],
            ..Default::default()
        },
    )
    .await;

    let destroying = mngr.clone();
    let destroy = crate::traced::spawn(async move { destroying.delete_session(id).await });
    until_claimed(&mngr, id).await;
    let resumed = mngr.resume_active_sessions().await.unwrap();
    assert_eq!(resumed, 0, "a session being torn down is not resumed");
    assert!(
        mngr.get_composition(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "a session being torn down has no composition to read, as it has no record"
    );
    assert!(
        !destroy.is_finished(),
        "the destroy hook should still be running"
    );

    let hook_failures = destroy.await.unwrap().unwrap();
    assert!(hook_failures.is_empty(), "{hook_failures:?}");
    assert!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "the record is gone after the destroy, not resurrected by the resume"
    );
}

/// A session being torn down is gone to everyone else: a second destroy
/// in the window is refused, a resolve finds nothing, and the
/// `on_destroy` hook runs once. With the teardown off the mainloop the
/// window is real (the first review of #2224 found it): without the
/// tearing-down set, the second destroy brought up a fresh actor from
/// the still-present record and ran the hook again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_destroy_during_a_teardown_runs_no_hook_twice() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session_contributing(
        &mngr,
        sample_config(),
        WireContribution {
            lifecycle_hooks: vec![boxes::wire::primitives::WireProvenancedHook {
                hook: boxes::wire::primitives::WireLifecycleHook {
                    on_destroy: Some(boxes::wire::primitives::WireHookScript::Inline {
                        body: format!("sleep 2; echo ran >> {}", marker.display()),
                        timeout_secs: 60,
                    }),
                    ..Default::default()
                },
                source: boxes::wire::primitives::WireSource::UserLoadout {
                    name: "test".to_string(),
                },
            }],
            ..Default::default()
        },
    )
    .await;

    let first = {
        let mngr = mngr.clone();
        crate::traced::spawn(async move { mngr.delete_session(id).await })
    };
    // Once the first destroy holds the session.
    until_claimed(&mngr, id).await;

    let second = mngr.delete_session(id).await;
    assert!(
        matches!(&second, Err(e) if e.kind() == std::io::ErrorKind::ResourceBusy),
        "a second destroy during the teardown should be refused, got {second:?}"
    );
    assert!(
        mngr.get_session(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "a session being torn down should resolve to nothing"
    );
    assert!(
        mngr.list().await.unwrap().iter().all(|s| s.id != id),
        "a session being torn down should not be listed"
    );
    assert!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "a session being torn down should have no record to read"
    );

    first.await.unwrap().unwrap();
    let ran = std::fs::read_to_string(&marker).unwrap_or_default();
    assert_eq!(ran.lines().count(), 1, "the destroy hook ran {ran:?}");
    assert!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "the record should be gone after destroy"
    );
}

/// A create whose name is held by a session still being torn down says
/// so, rather than reporting a plain collision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_create_during_a_teardown_names_the_destroy() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session_contributing(
        &mngr,
        sample_config(),
        WireContribution {
            lifecycle_hooks: vec![boxes::wire::primitives::WireProvenancedHook {
                hook: boxes::wire::primitives::WireLifecycleHook {
                    on_destroy: Some(boxes::wire::primitives::WireHookScript::Inline {
                        body: "sleep 2".to_string(),
                        timeout_secs: 60,
                    }),
                    ..Default::default()
                },
                source: boxes::wire::primitives::WireSource::UserLoadout {
                    name: "test".to_string(),
                },
            }],
            ..Default::default()
        },
    )
    .await;
    let destroying = {
        let mngr = mngr.clone();
        crate::traced::spawn(async move { mngr.delete_session(id).await })
    };
    until_claimed(&mngr, id).await;

    let err = mngr
        .create_session(sample_config(), None)
        .await
        .expect_err("the name is still held by the session being destroyed");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(
        err.to_string().contains("still being destroyed"),
        "the error should name the destroy: {err}"
    );
    destroying.await.unwrap().unwrap();
}

/// Waits until a destroy has claimed `id`: from that moment the
/// listing no longer shows it (a session in the tearing-down set is
/// gone to it), so a test can act on the teardown window itself rather
/// than on a guess at how long reaching it takes.
async fn until_claimed(mngr: &BoxManagerHandle, id: SessionId) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while mngr.list().await.unwrap().iter().any(|s| s.id == id) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the destroy never claimed the session");
}

/// A cleanup destroy (`only_if_unfinalized`) keeps a session that
/// finished activating and destroys one that did not (inbox#690).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cleanup_destroy_keeps_a_finished_session() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session(&mngr).await;
    let kept = mngr.delete_session_if_unfinalized(id).await.unwrap();
    assert!(kept.is_none(), "an Active session should be kept");
    assert!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_some(),
        "a kept session keeps its record"
    );
    assert_eq!(mngr.list().await.unwrap().len(), 1, "and is listed");

    let (_state, _cache, pending_mngr, pending, _response) = create_pending_session().await;
    let destroyed = pending_mngr
        .delete_session_if_unfinalized(pending)
        .await
        .unwrap();
    assert!(
        destroyed.is_some(),
        "an unfinished session should be destroyed"
    );
    assert!(
        pending_mngr
            .get_record(BoxKeyPredicate::Id(pending))
            .await
            .unwrap()
            .is_none(),
        "the destroyed session's record should be gone"
    );
}

/// The race inbox#690 is about, pinned: a cleanup destroy queued in the
/// session's mailbox behind a finalize that is still running waits for
/// it, and keeps the session it finished. While the cleanup is in
/// flight the session is in the tearing-down set: a second destroy is
/// refused, and a listing skips it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cleanup_destroy_queued_behind_a_running_finalize_keeps_the_session() {
    let (_state, _cache, mngr) = manager().await;
    let id = mngr.create_session(sample_config(), None).await.unwrap();
    let handle = session(&mngr, id).await;
    assert!(
        handle
            .configure_loadout(WireContribution::default())
            .await
            .expect("an empty loadout configures")
            .is_none(),
        "an empty loadout needs no verdict"
    );

    // The actor is held, so the finalize and then the cleanup queue in
    // its mailbox in that order: the finalize is the one "still running".
    let release = handle.hold_for_test().await;
    let finalize = crate::traced::spawn({
        let handle = handle.clone();
        async move { handle.finalize().await }
    });
    handle.until_queued(1).await;
    let cleanup = crate::traced::spawn({
        let mngr = mngr.clone();
        async move { mngr.delete_session_if_unfinalized(id).await }
    });
    handle.until_queued(2).await;

    let second = mngr
        .delete_session(id)
        .await
        .expect_err("a second destroy while the cleanup is in flight is refused");
    assert_eq!(second.kind(), ErrorKind::ResourceBusy);
    assert!(
        mngr.list().await.unwrap().is_empty(),
        "a session a cleanup is in flight for is not listed"
    );

    release.send(()).expect("the actor is held");
    finalize
        .await
        .unwrap()
        .expect("the finalize ahead of the cleanup succeeds");
    let kept = cleanup.await.unwrap().unwrap();
    assert!(
        kept.is_none(),
        "the cleanup keeps the session the finalize finished"
    );
    let listed = mngr.list().await.unwrap();
    assert_eq!(listed.len(), 1, "the kept session is listed again");
    assert_eq!(listed[0].status, boxes::BoxState::Active);
}

/// A cleanup destroy that does destroy — the session never finished —
/// leaves a listing whole: the session is skipped while its actor
/// deletes the record, and gone after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listing_survives_a_cleanup_destroy_of_an_unfinished_session() {
    let (_state, _cache, mngr, id, _response) = create_pending_session().await;
    let handle = session(&mngr, id).await;
    let release = handle.hold_for_test().await;
    let cleanup = crate::traced::spawn({
        let mngr = mngr.clone();
        async move { mngr.delete_session_if_unfinalized(id).await }
    });
    handle.until_queued(1).await;
    assert!(mngr.list().await.unwrap().is_empty());
    release.send(()).expect("the actor is held");
    let destroyed = cleanup.await.unwrap().unwrap();
    assert!(destroyed.is_some(), "an unfinished session is destroyed");
    assert!(mngr.list().await.unwrap().is_empty());
    assert!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none()
    );
}

/// A listing must not wait on a box actor: its attrs come from the host the
/// actor last published, not from the actor's mailbox. With an actor parked
/// (a clone inside `ConfigureLoadout`, an inline attach), `list` answered
/// only after `HOST_PROBE_TIMEOUT` for that box: 2 s per `min ls` through
/// the whole of a stalled activation (710d).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listing_does_not_wait_on_a_parked_actor() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session(&mngr).await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("session should resolve");

    // Returns once the actor is inside the park: every earlier message, and
    // its post-message publish, is done.
    handle.park_for(std::time::Duration::from_secs(3)).await;
    let started = std::time::Instant::now();
    let listed = tokio::time::timeout(std::time::Duration::from_millis(500), mngr.list())
        .await
        .expect("`list` waited on the parked actor")
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].attrs.is_none(), "no host, so no attrs");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "the listing took {:?}",
        started.elapsed()
    );
    drop(handle);
}

/// The slot path with a live host, the 710d case itself: an actor parked in
/// a long message still has its host's attrs listed, at once, read through
/// the slot and not the actor's mailbox.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_parked_actors_live_host_is_still_listed() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session(&mngr).await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("session should resolve");

    handle.park_for(std::time::Duration::from_secs(3)).await;
    // Published while the actor is parked (park_for returns once it is), as
    // a host it had before would be: nothing overwrites it until the park ends.
    handle.put_host_for_test(crate::box_runtime::HostHandle::answering_attrs());
    let listed = tokio::time::timeout(std::time::Duration::from_millis(500), mngr.list())
        .await
        .expect("`list` waited on the parked actor")
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert!(
        listed[0].attrs.is_some(),
        "the live host's attrs come through the slot while the actor is parked"
    );
    drop(handle);
}

/// The slot is emptied when the actor ends, so a handle that outlives it
/// reads no host, and holds no sender to one. The destroy's message ends the
/// actor with a `break`, after which nothing is published.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ended_actors_slot_is_emptied() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session(&mngr).await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("session should resolve");
    // The actor rewrites the slot after every message it handles, and it
    // replies to a message before that rewrite, so a host put right after a
    // reply can still be overwritten by the publish that follows it. Put
    // until the put survives: once the mailbox is empty nothing rewrites
    // the slot, and the host stays.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            handle.put_host_for_test(crate::box_runtime::HostHandle::answering_attrs());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if handle.get_attrs().await.is_some() {
                break;
            }
        }
    })
    .await
    .expect("no put of a host survived the actor's publishes");
    mngr.delete_session(id).await.unwrap();
    // The destroy replies just before the actor's loop ends.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while handle.get_attrs().await.is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the ended actor's slot still served a host");
}

/// Destroying an unknown ID is a `NotFound` error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destroy_unknown_id_errors() {
    let (_state, _cache, mngr) = manager().await;
    let err = mngr
        .delete_session(SessionId::nil())
        .await
        .expect_err("deleting an unknown id should error");
    assert_eq!(err.kind(), ErrorKind::NotFound);
}

/// A non-empty `WireContribution` from the client is accepted:
/// the composer produces a non-empty
/// [`Composition`](boxes::core::compose::Composition), the
/// create flow holds it on the live [`BoxActor`] actor, and the
/// record persists as `Active`.
///
/// Replaces an earlier test that asserted the opposite while
/// no apply layer existed to consume the composition; that
/// silent-data-loss guard is gone now that the actor keeps
/// its composition.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_session_accepts_non_empty_client_contribution() {
    use boxes::core::source::Source;
    use boxes::wire::primitives::{WireResolvedVar, WireSessionVar, WireSource};

    let (_state, _cache, mngr) = manager().await;
    let mut contribution = WireContribution::default();
    contribution.vars.push(WireSessionVar {
        var: WireResolvedVar {
            name: "EDITOR".into(),
            value: "hx".into(),
            carries_user_data: true,
        },
        source: WireSource::from(Source::UserLoadout {
            name: "test".into(),
        }),
    });

    let id = mngr.create_session(sample_config(), None).await.unwrap();
    let response = session(&mngr, id)
        .await
        .configure_loadout(contribution)
        .await
        .expect("a non-empty client contribution should compose");
    assert!(
        response.is_none(),
        "an already-gated client contribution needs no verdict, so the \
         loadout should finalize in one shot",
    );
    // Compose returned `Materialized` — the record status is
    // `Materializing`, not `Active`. Attach requires an
    // explicit `FinalizeSession` after any patches have
    // uploaded; this fixture doesn't drive that step.
    assert_eq!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the record should survive")
            .status,
        boxes::BoxState::Materializing,
    );
}

/// An unknown id resolves to no session at all — the `NotFound`
/// (abort/rename) and `Fault::UnknownSessionId` (verdict) wire
/// mappings all hang off this `None`, in the RPC handlers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_session_unknown_id_resolves_to_none() {
    let (_state, _cache, mngr) = manager().await;
    assert!(
        mngr.get_session(BoxKeyPredicate::Id(SessionId::nil()))
            .await
            .expect("get_session succeeds")
            .is_none(),
    );
}

/// Abort refuses `Active` sessions — abort is for `Pending`
/// only; `DeleteSession` handles `Active`. Guards against a
/// client accidentally tearing down a running session via the
/// wrong RPC.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abort_refuses_active_session() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session(&mngr).await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("session resolves");
    let err = handle
        .abort()
        .await
        .expect_err("aborting an Active session should error");
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    // Record is untouched.
    assert!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_some(),
        "the Active record should survive a refused abort"
    );
}

/// The full Pending → verdict → Active flow through the session
/// actor's state machine: a project `[session.vars]` entry pends
/// the loadout, `get_session` resolves the live Draft actor, an
/// approving verdict promotes the on-disk record to `Active`,
/// and the finalized composition (carrying the gated var) stays
/// on the actor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_session_activates_on_approving_verdict() {
    let (_state, _cache, mngr, id, response) = create_pending_session().await;
    assert_eq!(response.vars.len(), 1, "the project var should pend");
    assert_eq!(
        response.session_id, id,
        "the response should carry the allocated id, not the composer's \
         placeholder",
    );
    assert_eq!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the Pending record should exist")
            .status,
        boxes::BoxState::Pending,
    );

    let handle = mngr
        .get_session(BoxKeyPredicate::Id(id))
        .await
        .expect("get_session succeeds")
        .expect("a Pending session's live actor should resolve");
    let step = handle
        .submit_verdict(approve_all(id, &response))
        .await
        .expect("the verdict should be accepted");
    assert_eq!(step, BoxStep::Materialized { id });

    // SubmitVerdict promotes Pending → Materializing, not
    // Pending → Active. The client still has to upload
    // patches (there are none for this fixture) and call
    // FinalizeSession before the record advances to Active.
    assert_eq!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the record should survive promotion")
            .status,
        boxes::BoxState::Materializing,
    );
    let comp = handle
        .peek_composition()
        .await
        .expect("the promoted actor should hold the composition");
    assert!(
        comp.vars().iter().any(|v| v.var().name() == "RUST_LOG"),
        "the gated var should reach the composition",
    );
}

/// A verdict against an `Active` session is answered by the
/// actor's state machine with a structured `WrongState` fault —
/// not an error, and not silent acceptance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_verdict_on_active_session_returns_wrong_state() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session(&mngr).await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("session resolves");
    let step = handle
        .submit_verdict(ContributionVerdict {
            session_id: id,
            vars: vec![],
            patches: vec![],
            lifecycle_hooks: vec![],
        })
        .await
        .expect("actor reply should succeed");
    match step {
        BoxStep::Fault {
            error: boxes::wire::errors::WireError::WrongState { what },
        } => assert!(what.contains("expected Pending"), "got: {what}"),
        other => panic!("expected Fault::WrongState, got {other:?}"),
    }
}

/// Aborting a Draft session through its handle deletes the
/// record and stops the actor; the session no longer resolves
/// (the actor evicted itself from the manager's running map, and
/// the record is gone).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abort_via_handle_deletes_pending_session() {
    let (_state, _cache, mngr, id, _response) = create_pending_session().await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the Draft actor should resolve");
    handle.abort().await.expect("abort should succeed");

    assert!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "the record should be deleted by the abort",
    );
    assert!(
        mngr.get_session(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "the aborted session should no longer resolve",
    );
}

/// A verdict the composer can't apply (a denied project item)
/// faults, but isn't terminal: the session stays `Pending` and
/// resumable, so the client can correct the verdict and re-submit
/// rather than lose the session to a mis-gated item.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denying_verdict_faults_and_leaves_session_resumable() {
    let (_state, _cache, mngr, id, response) = create_pending_session().await;
    let handle = session(&mngr, id).await;
    let verdict = ContributionVerdict {
        session_id: id,
        vars: response
            .vars
            .iter()
            .map(|pv| boxes::wire::policy::WireVarVerdict::Denied {
                id: pv.id,
                name: pv.name.clone(),
            })
            .collect(),
        patches: vec![],
        lifecycle_hooks: vec![],
    };
    let step = handle
        .submit_verdict(verdict)
        .await
        .expect("actor reply should succeed");
    assert!(
        matches!(step, BoxStep::Fault { .. }),
        "a denied item should fault the resume, got {step:?}",
    );
    assert_eq!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the record should survive a faulted resume")
            .status,
        boxes::BoxState::Pending,
    );

    // The compose state survived the fault: a corrected verdict still
    // finalizes the same session.
    let step = handle
        .submit_verdict(approve_all(id, &response))
        .await
        .expect("the corrected verdict should be accepted");
    assert_eq!(step, BoxStep::Materialized { id });
}

/// Renaming a session that owns no PTask hostname route (NoNet here)
/// must not touch the registry: it is keyed by name alone, so an
/// ungated deregister would withdraw an unrelated routable session's
/// route that shares the same *derived* name (both unnamed, projects
/// with the same basename).
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_of_unroutable_session_leaves_other_routes_alone() {
    let (_state, _cache, mngr) = manager().await;

    // Two unnamed sessions whose projects share the basename "app":
    // both derive the registry name "app". Only the HostNet one
    // registers a route when its actor spawns.
    let routable_project = TempDir::new().unwrap();
    let routable_dir = routable_project.path().join("app");
    std::fs::create_dir_all(&routable_dir).unwrap();
    let unroutable_project = TempDir::new().unwrap();
    let unroutable_dir = unroutable_project.path().join("app");
    std::fs::create_dir_all(&unroutable_dir).unwrap();

    let mut config = sample_config();
    config.name = None;
    config.network = boxes::NetworkMode::HostNet;
    config.project_path = HostAbsPath::try_new(routable_dir.to_str().unwrap()).unwrap();
    // Finalizing the loadout registers the "app" route.
    let _routable_id = create_active_session_with(&mngr, config).await;

    let mut config = sample_config();
    config.name = None;
    config.network = boxes::NetworkMode::NoNet;
    config.project_path = HostAbsPath::try_new(unroutable_dir.to_str().unwrap()).unwrap();
    let unroutable_id = create_active_session_with(&mngr, config).await;
    let handle = session(&mngr, unroutable_id).await;

    handle
        .rename("renamed".to_string())
        .await
        .expect("rename should succeed");

    // The routable session's route survived the other session's rename.
    assert!(
        mngr.hostnames()
            .write()
            .expect("registry lock")
            .deregister("app")
            .is_some(),
        "the HostNet session's route must survive a NoNet rename \
         under the same derived name",
    );
}

/// A handle to a self-terminated actor answers `paths`/`record`/
/// `context` with errors, not panics — callers (SFTP, exec, uploads)
/// race actor death.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dead_actor_handle_reads_error_instead_of_panicking() {
    let (_state, _cache, mngr, id, _response) = create_pending_session().await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the Draft actor should resolve");
    handle.abort().await.expect("abort should succeed");

    let err = handle
        .paths()
        .await
        .expect_err("paths on a dead actor should error");
    assert_eq!(err.kind(), ErrorKind::NotConnected);
    let err = handle
        .record()
        .await
        .expect_err("record on a dead actor should error");
    assert_eq!(err.kind(), ErrorKind::NotConnected);
    assert!(
        handle
            .context()
            .await
            .expect_err("context on a dead actor should error")
            .contains("gone"),
    );
}

/// A Draft session refuses context creation — there is no
/// workspace-rooted context to build until composition
/// finalizes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn draft_session_refuses_context_creation() {
    let (_state, _cache, mngr, id, _response) = create_pending_session().await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the Draft actor should resolve");
    let err = handle
        .context()
        .await
        .expect_err("a Draft session should refuse context creation");
    assert!(err.contains("pending"), "got: {err}");
}

/// An idle `Active` session (created, never attached) does not
/// block an unforced shutdown — every created session now has a
/// live actor, so mere existence can't be the guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_session_does_not_block_unforced_shutdown() {
    let (_state, _cache, mngr) = manager().await;
    let _id = create_active_session(&mngr).await;
    mngr.shutdown(false)
        .await
        .expect("an idle session should not block unforced shutdown");
}

/// A Draft session (mid create flow, awaiting its verdict) is
/// busy: it blocks an unforced shutdown until the client
/// finalizes or aborts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn draft_session_blocks_unforced_shutdown() {
    let (_state, _cache, mngr, _id, _response) = create_pending_session().await;
    mngr.shutdown(false)
        .await
        .expect_err("a Draft session should block unforced shutdown");
}

/// `CreateSession` against a `project_path` that has a real
/// `minimal.toml` shouldn't error out — the mfile parse
/// succeeds and graph resolution is attempted; both feed
/// nowhere (yet), and the session persists `Active` on the
/// empty-contribution fast path.
///
/// The bare `minimal.toml` fixture must resolve to a graph:
/// a graph-resolution error now fails `configure_loadout`, so
/// `CreateSession` returning `Ready` here also proves the
/// fixture's graph resolves.
/// Guards against a regression where the mfile parse or graph
/// pipeline breaks creation for real projects. Once composition
/// consumes the parsed mfile + graph, this test evolves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configure_loadout_with_real_project_mfile_succeeds() {
    let (_state, _cache, _mngr, _id, response) =
        create_and_configure("[stack]\nuse = \"empty\"\n").await;
    assert!(
        response.is_none(),
        "a stack-only mfile gates nothing, so the loadout should finalize"
    );
}

/// Configuring a loadout against a workspace with no `minimal.toml`
/// scaffolds a default one *before* composing, so the packages that
/// default declares land in the composition — and from there in the
/// launcher's package set, which is its baseline unioned with the
/// composition's packages and nothing else. Scaffolding after the
/// compose (as `build_context` alone used to) left a session running
/// without the packages its own workspace mfile declared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configure_loadout_scaffolds_missing_mfile_into_composition() {
    let (_state, _cache, mngr) = manager().await;
    // No `seed_workspace_mfile`: the workspace stays empty, mirroring
    // an activation against a directory with no `minimal.toml`.
    let id = mngr.create_session(sample_config(), None).await.unwrap();
    let response = session(&mngr, id)
        .await
        .configure_loadout(WireContribution::default())
        .await
        .expect("configuring against a missing mfile should still succeed");
    assert!(response.is_none(), "the scaffolded default gates nothing");

    let comp = peek_composition(&mngr, id).await;
    let package_names: std::collections::BTreeSet<&str> =
        comp.packages().iter().map(|p| p.package()).collect();
    assert!(
        package_names.contains("vim"),
        "the scaffolded mfile's packages should reach the composition, \
         got {package_names:?}"
    );
}

/// A `[session]` block that contributes a package is picked up
/// by [`ProjectComposable`] and lands in the composition. With
/// the non-empty-composition guard gone, the record now
/// persists as `Active` and the composition stays on the live
/// [`BoxActor`] actor.
///
/// Uses a package contribution rather than a var so no
/// env-resolution (or graph presence) is needed — the test
/// stays a pure-parse exercise regardless of stdlib config.
///
/// [`ProjectComposable`]: mfile::ProjectComposable
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn project_composable_contribution_reaches_composer() {
    let (_state, _cache, mngr, id, response) =
        create_and_configure("[session]\npackages = [\"rustc\"]\n").await;
    assert!(
        response.is_none(),
        "a project package needs no client gate, so the loadout finalizes"
    );
    // Compose advances the record to `Materializing`, not
    // `Active` — see the note on
    // `create_session_accepts_non_empty_client_contribution`.
    assert_eq!(
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the record should survive")
            .status,
        boxes::BoxState::Materializing,
    );
}

/// A finalized loadout leaves the session's actor live and holding its
/// composition — the actor `get_session` resolves is the same one the
/// create flow spawned, composition intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn created_session_actor_holds_its_composition() {
    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session(&mngr).await;
    assert!(
        session(&mngr, id).await.peek_composition().await.is_some(),
        "the create-flow actor should still hold its composition",
    );
}

/// Writes `pkg` as a package of the session's own workspace layer, so its
/// graph resolves the name with no upstream layer (and no network) in play.
async fn seed_workspace_package(mngr: &BoxManagerHandle, id: SessionId, pkg: &str) {
    let paths = session(mngr, id).await.paths().await.unwrap();
    let dir = paths.working.as_utf8_path().join("packages").join(pkg);
    tokio::fs::create_dir_all(&dir).await.unwrap();
    tokio::fs::write(
        dir.join("build.ncl"),
        format!(
            r#"let {{ BuildSpec, .. }} = import "minimal.ncl" in
{{
  name = "{pkg}",
  build_deps = [],
  runtime_deps = [],
  outputs = {{}},
}} | BuildSpec
"#
        ),
    )
    .await
    .unwrap();
}

/// Brings up an `Active` session called `name` whose workspace declares
/// local package `pkg` in its `[session]` block — a session that needs
/// exactly one package, and a different one per call.
pub(crate) async fn active_session_needing(
    mngr: &BoxManagerHandle,
    name: &str,
    pkg: &str,
) -> SessionId {
    let config = minimald_rpc::BoxConfig {
        name: Some(name.to_string()),
        ..sample_config()
    };
    let id = mngr.create_session(config, None).await.unwrap();
    seed_workspace_package(mngr, id, pkg).await;
    seed_workspace_mfile(mngr, id, &format!("[session]\npackages = [\"{pkg}\"]\n")).await;

    let handle = session(mngr, id).await;
    handle
        .configure_loadout(WireContribution::default())
        .await
        .expect("a project-only loadout gates nothing");
    // The composition carries packages but no patches, so finalize skips
    // the patches marker and the record lands `Active`.
    handle.finalize().await.expect("finalize should succeed");
    id
}

/// The manager's answer is the union of what each session answered, and
/// each session resolved its own package against its own workspace.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn needed_packages_unions_across_sessions() {
    let (_state, _cache, mngr) = manager().await;
    let a = active_session_needing(&mngr, "sess-a", "pkg-a").await;
    let b = active_session_needing(&mngr, "sess-b", "pkg-b").await;

    let from_a = session(&mngr, a).await.needed_packages().await.unwrap();
    let from_b = session(&mngr, b).await.needed_packages().await.unwrap();
    assert_eq!(from_a.len(), 1, "session a needs exactly its own package");
    assert_eq!(from_b.len(), 1, "session b needs exactly its own package");
    assert_ne!(from_a, from_b, "different packages hash differently");

    let want: HashSet<SpecHash> = from_a.union(&from_b).cloned().collect();
    assert_eq!(mngr.needed_packages().await.unwrap(), want);
}

/// A session that hasn't composed yet has no workspace context to resolve,
/// so it is skipped rather than faulting the whole union.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn needed_packages_skips_sessions_that_arent_active() {
    let (_state, _cache, mngr) = manager().await;
    // Created but never configured: the record stays `Pending`.
    let _pending = mngr.create_session(sample_config(), None).await.unwrap();

    assert!(mngr.needed_packages().await.unwrap().is_empty());
}

/// Creates a session over a workspace declaring local package `pkg` in
/// its `[session]` block plus `extra` as further session packages,
/// configures it with `contribution`, and finalizes it with the package
/// check on, bounded by `deadline`. Returns the manager, the id, and
/// the finalize's outcome.
async fn finalize_with_package_check(
    extra: &[&str],
    contribution: WireContribution,
    deadline: std::time::Duration,
) -> (
    TempDir,
    TempDir,
    BoxManagerHandle,
    SessionId,
    Result<minimald_rpc::FinalizeSessionResponse, std::io::Error>,
) {
    let (state, cache, mngr, id, handle) =
        configure_with_package_check(extra, contribution, deadline).await;
    let outcome = handle.finalize().await;
    (state, cache, mngr, id, outcome)
}

/// [`finalize_with_package_check`] up to, not including, the finalize:
/// returns the configured session's handle so a test can change the
/// workspace or the actor between compose and finalize.
async fn configure_with_package_check(
    extra: &[&str],
    contribution: WireContribution,
    deadline: std::time::Duration,
) -> (TempDir, TempDir, BoxManagerHandle, SessionId, BoxHandle) {
    let (state, cache, mngr) = manager().await;
    let id = mngr.create_session(sample_config(), None).await.unwrap();
    seed_workspace_package(&mngr, id, "pkg-ok").await;
    let packages: Vec<String> = std::iter::once("pkg-ok")
        .chain(extra.iter().copied())
        .map(|p| format!("\"{p}\""))
        .collect();
    seed_workspace_mfile(
        &mngr,
        id,
        &format!("[session]\npackages = [{}]\n", packages.join(", ")),
    )
    .await;
    let handle = session(&mngr, id).await;
    let response = handle
        .configure_loadout(contribution)
        .await
        .expect("packages gate nothing at compose");
    assert!(response.is_none(), "nothing in the composition is gated");
    handle.check_packages_at_finalize(deadline).await;
    (state, cache, mngr, id, handle)
}

/// Removes local package `pkg` from the session's workspace, so a graph
/// evaluated after this no longer declares it.
async fn remove_workspace_package(mngr: &BoxManagerHandle, id: SessionId, pkg: &str) {
    let paths = session(mngr, id).await.paths().await.unwrap();
    tokio::fs::remove_dir_all(paths.working.as_utf8_path().join("packages").join(pkg))
        .await
        .unwrap();
}

/// Finalize judges the names the compose-time graph declared and does
/// not evaluate the graph again: a package removed from the workspace
/// after compose still counts as declared, so the session activates
/// with a verdict. The control is the next test, where the same removal
/// is seen by an actor that must evaluate the graph itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finalize_judges_the_compose_time_graph() {
    let (_state, _cache, mngr, id, handle) =
        configure_with_package_check(&[], WireContribution::default(), PACKAGE_CHECK_DEADLINE)
            .await;
    remove_workspace_package(&mngr, id, "pkg-ok").await;
    let response = handle
        .finalize()
        .await
        .expect("the compose-time graph declared pkg-ok");
    assert!(
        !response.package_check_skipped,
        "a check judged against captured names reaches a verdict"
    );
    assert_eq!(status_of(&mngr, id).await, boxes::BoxState::Active);
}

/// Without compose-time names (an actor restored from disk), finalize
/// evaluates the graph itself and still refuses: both the unknown
/// package and one removed from the workspace after compose are named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finalize_without_compose_time_names_evaluates_the_graph() {
    let (_state, _cache, mngr, id, handle) = configure_with_package_check(
        &["no-such-pkg-rr"],
        WireContribution::default(),
        PACKAGE_CHECK_DEADLINE,
    )
    .await;
    handle.forget_composed_graph_names().await;
    remove_workspace_package(&mngr, id, "pkg-ok").await;
    let err = handle
        .finalize()
        .await
        .expect_err("the fallback check must still refuse an unknown package");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    let msg = err.to_string();
    assert!(
        msg.contains("no such package: no-such-pkg-rr") && msg.contains("no such package: pkg-ok"),
        "the fallback judges a freshly evaluated graph, got {msg:?}"
    );
    assert_ne!(status_of(&mngr, id).await, boxes::BoxState::Active);
}

async fn status_of(mngr: &BoxManagerHandle, id: SessionId) -> boxes::BoxState {
    mngr.get_record(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the record should survive the finalize")
        .status
}

/// A `[session]` package the graph does not declare is refused at
/// finalize, naming the package and the project that declared it, and
/// the record is not promoted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finalize_refuses_an_unknown_session_package() {
    let (_state, _cache, mngr, id, outcome) = finalize_with_package_check(
        &["no-such-pkg-zz"],
        WireContribution::default(),
        PACKAGE_CHECK_DEADLINE,
    )
    .await;
    let err = outcome.expect_err("an unknown package must not activate");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    let msg = err.to_string();
    assert!(
        msg.contains("no such package: no-such-pkg-zz") && msg.contains("project"),
        "the error should name the package and its declarer, got {msg:?}"
    );
    assert!(
        !msg.contains("pkg-ok"),
        "a package that resolves is not reported, got {msg:?}"
    );
    assert_ne!(status_of(&mngr, id).await, boxes::BoxState::Active);
}

/// The same refusal for a package that arrives through a loadout: the
/// project resolves, the loadout's package does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finalize_refuses_an_unknown_loadout_package() {
    use boxes::wire::primitives::{WirePackageRef, WireSource};

    let mut contribution = WireContribution::default();
    contribution.requested_packages.push(WirePackageRef {
        name: "no-such-pkg-qq".into(),
        source: WireSource::UserLoadout {
            name: "editor".into(),
        },
    });
    let (_state, _cache, mngr, id, outcome) =
        finalize_with_package_check(&[], contribution, PACKAGE_CHECK_DEADLINE).await;
    let err = outcome.expect_err("an unknown loadout package must not activate");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    let msg = err.to_string();
    assert!(
        msg.contains("no such package: no-such-pkg-qq") && msg.contains("loadout `editor`"),
        "the error should name the package and its loadout, got {msg:?}"
    );
    assert_ne!(status_of(&mngr, id).await, boxes::BoxState::Active);
}

/// A composition whose every package resolves still finalizes to
/// `Active` with the check on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finalize_with_resolvable_packages_still_activates() {
    let (_state, _cache, mngr, id, outcome) =
        finalize_with_package_check(&[], WireContribution::default(), PACKAGE_CHECK_DEADLINE).await;
    let response = outcome.expect("a session whose packages resolve should finalize");
    assert!(
        !response.package_check_skipped,
        "a check that ran to a verdict is not skipped"
    );
    assert_eq!(status_of(&mngr, id).await, boxes::BoxState::Active);
}

/// A check that cannot resolve the graph within its deadline steps
/// aside instead of failing the finalize: the session activates with
/// its unknown name unresolved, which the launch reports at first
/// exec, exactly as before the check existed. This is the daemon-side
/// bound on the work the check adds to the `FinalizeSession`
/// round-trip — a cold-cache upstream clone can outlast the client's
/// own deadline, and a client that expires does not cancel the
/// daemon-side finalize, so the check must not hold the record's
/// promotion hostage to work the client has stopped waiting for.
///
/// A zero deadline pins the expiry path without a slow graph to wait
/// out: the check measures its budget before any judging, and an
/// already-lapsed deadline steps aside at that first measurement —
/// deterministically, because tokio polls the check once before its
/// timer, so the zero-duration timer alone cannot be relied on to
/// fire first against judging this cheap. The composition names an
/// unknown package so a check that ignored its deadline would refuse
/// instead of activate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finalize_with_an_expired_package_check_still_activates() {
    let (_state, _cache, mngr, id, outcome) = finalize_with_package_check(
        &["no-such-pkg-exp"],
        WireContribution::default(),
        std::time::Duration::ZERO,
    )
    .await;
    let response = outcome.expect("an expired check steps aside; the session still activates");
    assert!(
        response.package_check_skipped,
        "an expired check reports the skip so the client can warn"
    );
    assert_eq!(status_of(&mngr, id).await, boxes::BoxState::Active);
}

/// The held [`Composition`] actually carries the project
/// composable's packages — not just an entry-shaped placeholder.
/// Guards against a `run_composer` refactor that would produce
/// a well-shaped-but-empty composition and silently pass the
/// existing lifecycle tests.
///
/// [`Composition`]: boxes::core::compose::Composition
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn created_session_composition_carries_project_packages() {
    let (_state, _cache, mngr, id, _response) =
        create_and_configure("[session]\npackages = [\"ripgrep\", \"jq\"]\n").await;

    let comp = peek_composition(&mngr, id).await;
    let package_names: std::collections::BTreeSet<&str> =
        comp.packages().iter().map(|p| p.package()).collect();
    assert!(
        package_names.contains("ripgrep"),
        "ripgrep should be in composition packages, got {package_names:?}"
    );
    assert!(
        package_names.contains("jq"),
        "jq should be in composition packages, got {package_names:?}"
    );
}

/// `[stack] build_packages` and `runtime_packages` land in the
/// composition alongside any `[session] packages`, so a project
/// declaring stack extras (or having no `[session]` block at
/// all) still gets those packages into its sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn created_session_composition_includes_stack_packages() {
    let (_state, _cache, mngr, id, _response) = create_and_configure(
        "[stack]\n\
         use = \"shell\"\n\
         build_packages = [\"cmake\"]\n\
         runtime_packages = [\"postgres\"]\n",
    )
    .await;

    let comp = peek_composition(&mngr, id).await;
    let package_names: std::collections::BTreeSet<&str> =
        comp.packages().iter().map(|p| p.package()).collect();
    assert!(
        package_names.contains("cmake"),
        "stack build_packages should reach the composition, got {package_names:?}"
    );
    assert!(
        package_names.contains("postgres"),
        "stack runtime_packages should reach the composition, got {package_names:?}"
    );
}

/// [`build_composables`] with a [`ProjectResolution::NoMFile`]
/// yields no composables regardless of the wire contribution.
/// The wire contribution isn't discarded by the composer — it
/// still lands via `SessionComposer::new(contribution)`; this
/// helper is only responsible for daemon-side additions.
#[test]
fn build_composables_no_mfile_yields_nothing() {
    use boxes::wire::primitives::{WirePackageRef, WireSource};

    let path = DaemonAbsPath::try_new("/proj").unwrap();
    let mut contribution = WireContribution::default();
    contribution.requested_packages.push(WirePackageRef {
        name: "helix".into(),
        source: WireSource::UserLoadout {
            name: "test".into(),
        },
    });
    let (project, packages) = build_composables(
        &path,
        &declared_path(),
        &ProjectResolution::NoMFile,
        &contribution,
        true,
    )
    .unwrap();
    assert!(project.is_none(), "NoMFile → no ProjectComposable");
    assert!(packages.is_empty(), "NoMFile → no PackageComposables");
}

/// [`build_composables`] on a resolved project stamps every
/// project-contributed package with `Source::Project` naming the
/// *declared* project path, not the per-session workspace the
/// mfile was read out of. The hooks policy matches projects by
/// this path and every error message quotes it, so a per-session
/// value would be unmatchable and unrecognizable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn build_composables_project_provenance_names_declared_path() {
    use std::io::Write;

    let project = TempDir::new().unwrap();
    let mfile_path = project.path().join(mfile::MFILE_NAME);
    let mut f = std::fs::File::create(&mfile_path).unwrap();
    writeln!(f, "[session]\npackages = [\"cargo\"]").unwrap();
    drop(f);

    let cache = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let mctx_config = mctx::ConfigBuilder::new()
        .with_cache_dir(cache.path())
        .with_state_dir(state.path())
        .with_daemon_id("test".to_string())
        .build()
        .unwrap();
    let daemon = std::sync::Arc::new(mctx::DaemonContext::init(mctx_config).unwrap());

    let path = DaemonAbsPath::try_new(project.path().to_str().unwrap()).unwrap();
    let resolution = resolve_project_ctx_and_graph(&daemon, &path)
        .expect("a stdlib-only mfile resolves offline");
    assert!(
        matches!(resolution, ProjectResolution::Full(..)),
        "an mfile on disk with a resolvable graph → Full",
    );
    let (project_composable, _packages) = build_composables(
        &path,
        &declared_path(),
        &resolution,
        &WireContribution::default(),
        true,
    )
    .unwrap();

    use boxes::core::compose::Composable as _;
    let contribution = project_composable
        .expect("[session] block → ProjectComposable present")
        .contribute(&|_| Err(std::env::VarError::NotPresent))
        .expect("the fixture's [session] block contributes cleanly");
    let sources: Vec<_> = contribution
        .packages()
        .iter()
        .map(boxes::core::source::Provenanced::source)
        .collect();
    assert!(!sources.is_empty(), "fixture should contribute a package");
    for source in sources {
        let boxes::core::source::Source::Project { path } = source else {
            panic!("project material should carry Source::Project, got {source:?}");
        };
        assert_eq!(
            path.as_utf8_path().as_str(),
            declared_path().as_utf8_path().as_str(),
            "provenance should name the declared project path, not the workspace",
        );
    }
}

/// A project whose `minimal.toml` demands a newer standard
/// library than the daemon ships fails graph resolution, and
/// [`run_compose`] surfaces that as an `InvalidInput` error
/// rather than silently dropping every package contribution.
/// Regression guard for the `MFileOnly` fallback, which let
/// `min session activate` succeed (exit 0) while the session
/// came up missing all package material.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_compose_returns_invalid_input_when_graph_resolution_fails() {
    use std::io::Write;

    let project = TempDir::new().unwrap();
    let mfile_path = project.path().join(mfile::MFILE_NAME);
    let mut f = std::fs::File::create(&mfile_path).unwrap();
    writeln!(
        f,
        "[stdlib]\nminimum_version = \"999.0.0\"\n\n[session]\npackages = [\"cargo\"]"
    )
    .unwrap();
    drop(f);

    let cache = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let mctx_config = mctx::ConfigBuilder::new()
        .with_cache_dir(cache.path())
        .with_state_dir(state.path())
        .with_daemon_id("test".to_string())
        .build()
        .unwrap();
    let daemon = std::sync::Arc::new(mctx::DaemonContext::init(mctx_config).unwrap());

    let path = DaemonAbsPath::try_new(project.path().to_str().unwrap()).unwrap();
    let err = run_compose(
        &daemon,
        &path,
        &declared_path(),
        WireContribution::default(),
        true,
    )
    .expect_err("an outdated stdlib must fail the compose, not degrade");
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidInput,
        "graph-resolution failure should surface as InvalidInput, got {err:?}",
    );
    assert!(
        err.to_string()
            .contains("newer version of the standard library needed"),
        "the error should carry the graph's own diagnostic, got {err}",
    );
}

/// [`run_composer`] with an empty client contribution and no
/// daemon-side composables produces a Ready outcome with an
/// empty [`Composition`]. Baseline for the composer wiring.
#[test]
fn run_composer_empty_inputs_yield_ready_empty() {
    let outcome = run_composer(WireContribution::default(), None, Vec::new()).expect("no failures");
    match outcome {
        ComposeOutcome::Ready(composition) => {
            assert!(composition.packages().is_empty());
            assert!(composition.vars().is_empty());
            assert!(composition.patches().is_empty());
            assert!(composition.lifecycle_hooks().is_empty());
        }
        other => panic!("expected Ready, got {other:?}"),
    }
}

/// `min check` runs as a session side-op, so the stream contract the
/// renderer in `env::run_check` depends on has to hold: the actor accepts
/// a `StartCheck`, results flow, and the channel closes after exactly one
/// terminal outcome. This workspace holds no `packages/`, `profiles/`, or
/// `stacks/` dirs, so there is nothing to check and the run completes
/// clean — the terminal update is the whole point here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_check_closes_with_exactly_one_terminal_outcome() {
    use crate::box_ops::{CheckOpts, CheckOutcome, CheckUpdate};

    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session(&mngr).await;
    // `start_check` builds a fresh workspace-rooted context per call, so
    // the workspace needs an mfile for it to resolve at all.
    seed_workspace_mfile(&mngr, id, "").await;

    let mut updates = session(&mngr, id)
        .await
        .start_check(CheckOpts {
            packages: true,
            stacks: true,
            fix: false,
            filter_names: vec![],
            skip_checkers: vec![],
        })
        .await
        .expect("starting a check on an Active session should succeed");

    let mut outcomes = Vec::new();
    while let Some(update) = updates.recv().await {
        match update {
            CheckUpdate::Checked { object, .. } => {
                panic!("nothing to check in an empty workspace, got {object}")
            }
            CheckUpdate::Finished(o) => outcomes.push(o),
        }
    }

    assert!(
        matches!(
            outcomes.as_slice(),
            [CheckOutcome::Completed { failed: false }]
        ),
        "expected exactly one clean terminal outcome, got {outcomes:?}",
    );
}

/// The output is resolved before the side-op spawns, so an unknown name is
/// a plain error rather than a terminal update on a channel the caller
/// would first have to be handed and drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_materialize_rejects_an_unknown_output_by_name() {
    use crate::box_ops::MaterializeOpts;

    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session(&mngr).await;
    // Builds a fresh workspace-rooted context, so an mfile must exist.
    seed_workspace_mfile(&mngr, id, "").await;

    let err = session(&mngr, id)
        .await
        .start_materialize(MaterializeOpts {
            output_name: "no-such-output".to_string(),
            arch: None,
        })
        .await
        .expect_err("an output the minimal file does not declare must be refused");

    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "an undeclared output is a NotFound, got {err:?}"
    );
    assert!(
        err.to_string().contains("no-such-output"),
        "the error must name the output that was asked for, got {err}"
    );
}

/// The manager's holder of live boxes keeps them in the time order of
/// their box ids, which is the order they were created in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creation_order_holder_follows_box_id_time_order() {
    let (_state, _cache, mngr) = manager().await;

    let mut created = Vec::new();
    for n in 0..4 {
        let mut config = sample_config();
        config.name = Some(format!("box-{n}"));
        created.push(mngr.create_session(config, None).await.unwrap());
        // A clock tick between creates, so each id's timestamp is its own.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let (send, recv) = Responder::channel();
    let _ = mngr.sender.send(ManagerMessage::RunningIds(send)).await;
    let held = recv.await.unwrap().unwrap();
    assert_eq!(held, created, "the holder keeps creation order");

    let stamps: Vec<_> = held
        .iter()
        .map(|id| {
            let uuid: &uuid::Uuid = id.as_ref();
            assert_eq!(uuid.get_version_num(), 7, "every box id is a UUIDv7");
            uuid.get_timestamp()
                .expect("a UUIDv7 carries its mint time")
                .to_unix()
        })
        .collect();
    assert!(
        stamps.windows(2).all(|w| w[0] <= w[1]),
        "the holder's order is the ids' time order: {stamps:?}"
    );
    for id in &created {
        let record = mngr
            .get_record(BoxKeyPredicate::Id(*id))
            .await
            .unwrap()
            .expect("each created box has a record");
        assert_eq!(record.id, *id, "the record is keyed by the box id");
    }
}

/// BEP-007: the sealed values a create request carries ride the box's
/// stored record, and a host launch takes them from it, so every launch,
/// after a daemon restart included, places them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sealed_deliveries_ride_the_record_to_the_host_params() {
    let (_state, _cache, mngr) = manager().await;
    let deliveries = vec![
        boxes::SealedDelivery {
            variable: "GH_TOKEN".to_string(),
            sealed: "v1.sealed-one".to_string(),
        },
        boxes::SealedDelivery {
            variable: "GITHUB_TOKEN".to_string(),
            sealed: "v1.sealed-two".to_string(),
        },
    ];
    let config = minimald_rpc::BoxConfig {
        sealed_deliveries: deliveries.clone(),
        ..sample_config()
    };
    let id = mngr.create_session(config, None).await.unwrap();
    let record = mngr
        .get_record(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the created box has a record");
    assert_eq!(record.sealed_deliveries, deliveries);
    assert_eq!(crate::box_runtime::launch_deliveries(&record), deliveries);

    // The `GetSessionRecord` reply for the grant box carries no sealed
    // value, on the wire or in the record, while the store keeps them.
    let reply = crate::rpc::session_record_response(Some(record.clone()));
    let replied = reply.record.as_ref().expect("the reply carries the record");
    assert!(replied.sealed_deliveries.is_empty(), "{replied:?}");
    assert_eq!(replied.id, record.id);
    let wire = serde_json_lenient::to_string(&reply).unwrap();
    assert!(
        !wire.contains("v1.sealed-one") && !wire.contains("sealed_deliveries"),
        "{wire}"
    );
    let stored = mngr
        .get_record(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the store still has the record");
    assert_eq!(stored.sealed_deliveries, deliveries);

    // A box with no grant carries none.
    let id = mngr
        .create_session(
            minimald_rpc::BoxConfig {
                name: Some("no-grant".to_string()),
                ..sample_config()
            },
            None,
        )
        .await
        .unwrap();
    let record = mngr
        .get_record(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the created box has a record");
    assert!(crate::box_runtime::launch_deliveries(&record).is_empty());

    // A grant whose name is not a variable name is refused, and no record
    // is stored for it.
    let err = mngr
        .create_session(
            minimald_rpc::BoxConfig {
                name: Some("bad-grant".to_string()),
                sealed_deliveries: vec![boxes::SealedDelivery {
                    variable: "X=1; touch /tmp/owned #".to_string(),
                    sealed: "v1.sealed-three".to_string(),
                }],
                ..sample_config()
            },
            None,
        )
        .await
        .expect_err("a grant name that is not a variable name is refused");
    assert!(
        err.to_string()
            .contains("not a valid environment variable name"),
        "{err}"
    );
    assert!(
        mngr.get_record(BoxKeyPredicate::Name("bad-grant".to_string()))
            .await
            .unwrap()
            .is_none()
    );
}

/// BEP-011: the root certificate a create request carries rides the box's
/// stored record, and a host launch takes it from there, so every launch,
/// after a daemon restart included, adds it to the box's trust store. A box
/// with no grant, or with steering `off`, gets none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn record_carries_the_root_certificate_to_the_launch() {
    use boxes::core::bep::{BepSettings, Steering};
    let (_state, _cache, mngr) = manager().await;
    let pem = "-----BEGIN CERTIFICATE-----\nUk9PVA==\n-----END CERTIFICATE-----\n".to_string();
    let grant_policy = |steering: Steering| boxes::BoxPolicy {
        credentialed_upstream: Some(boxes::CredentialedUpstream {
            bep: BepSettings {
                steering: Some(steering),
                ..BepSettings::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    let created =
        |name: &str, policy: boxes::BoxPolicy, root: Option<String>| minimald_rpc::BoxConfig {
            name: Some(name.to_string()),
            policy,
            root_certificate: root,
            ..sample_config()
        };

    let id = mngr
        .create_session(
            created("grant", grant_policy(Steering::ProxyEnv), Some(pem.clone())),
            None,
        )
        .await
        .unwrap();
    let record = mngr
        .get_record(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the created box has a record");
    assert_eq!(record.root_certificate.as_deref(), Some(pem.as_str()));
    assert_eq!(
        crate::box_runtime::launch_root_certificate(&record).as_deref(),
        Some(pem.as_str())
    );
    // The stored record reads back with it, as a restarted daemon reads it.
    let wire = serde_json_lenient::to_string(&record).unwrap();
    let reread: boxes::Record = serde_json_lenient::from_str(&wire).unwrap();
    assert_eq!(reread.root_certificate, record.root_certificate);

    // Steering `off` keeps the root out, whatever the record holds.
    let id = mngr
        .create_session(
            created("off", grant_policy(Steering::Off), Some(pem.clone())),
            None,
        )
        .await
        .unwrap();
    let record = mngr
        .get_record(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the created box has a record");
    assert_eq!(crate::box_runtime::launch_root_certificate(&record), None);

    // A box with no grant carries no root and gets none.
    let id = mngr
        .create_session(created("no-grant", Default::default(), None), None)
        .await
        .unwrap();
    let record = mngr
        .get_record(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the created box has a record");
    assert_eq!(record.root_certificate, None);
    assert_eq!(crate::box_runtime::launch_root_certificate(&record), None);
    let wire = serde_json_lenient::to_string(&record).unwrap();
    assert!(!wire.contains("root_certificate"), "{wire}");
}

/// BOX-012: a restart reaps the pending record and keeps the running one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_keeps_running_records_and_reaps_pending_ones() {
    let (state, cache, mngr, pending, _response) = create_pending_session().await;
    let mut config = sample_config();
    config.name = Some("still-running".to_string());
    let running = create_active_session_with(&mngr, config).await;
    assert_eq!(status_of(&mngr, pending).await, boxes::BoxState::Pending);

    let restarted = manager_over(state.path(), cache.path()).await;

    assert_eq!(
        restarted
            .get_record(BoxKeyPredicate::Id(pending))
            .await
            .unwrap(),
        None,
        "the restart reaps a pending record"
    );
    assert!(
        restarted
            .get_record(BoxKeyPredicate::Id(running))
            .await
            .unwrap()
            .is_some(),
        "the restart keeps a running record"
    );
}

/// Milliseconds since the Unix epoch, the unit of an event's `ts`.
fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// The directories a box sees: every one of them is mounted into it.
async fn box_visible_dirs(mngr: &BoxManagerHandle, id: SessionId) -> Vec<DaemonAbsPath> {
    let paths = session(mngr, id).await.paths().await.unwrap();
    vec![
        paths.working,
        paths.cache,
        paths.home,
        paths.patches,
        paths.hooks,
    ]
}

/// BOX-040: creating a box writes its `created` event, naming the box,
/// its parent and when, into a file beside the record in the daemon's
/// state directory, outside every directory the box sees.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_written_outside_box_filesystem_with_box_parent_ts_type() {
    let (state, _cache, mngr) = manager().await;
    let before = now_ms();
    let id = mngr.create_session(sample_config(), None).await.unwrap();
    let after = now_ms();

    let mut reader = mngr.box_events(id).await.unwrap();
    let events = reader.read_new().unwrap();
    assert_eq!(events.len(), 1, "one event per transition: {events:?}");
    let created = &events[0];
    assert_eq!(created.kind, BoxEventType::Created);
    assert_eq!(created.box_id, id);
    assert_eq!(
        created.parent, None,
        "a box created outside any box has no parent"
    );
    assert!(
        (before..=after).contains(&created.ts),
        "{before} <= {} <= {after}",
        created.ts
    );

    let events_path = reader.object.events_path();
    let events_path = events_path.as_utf8_path();
    let sessions = camino::Utf8Path::from_path(state.path())
        .unwrap()
        .join("sessions");
    assert!(events_path.starts_with(&sessions));
    assert!(
        events_path.parent().unwrap().join("record.json").exists(),
        "the events file sits beside the record"
    );
    for seen in box_visible_dirs(&mngr, id).await {
        assert!(
            !events_path.starts_with(seen.as_utf8_path()),
            "{events_path} is inside {seen}, which the box sees"
        );
    }
}

/// BOX-041, placement only: the box's events file is outside every
/// directory the box can see. An events file written into those
/// directories, whatever it claims, is not the box's events. The read
/// returns only what the daemon wrote. No process runs inside a box here.
/// The proof that uid 0 inside a real sandbox cannot append is the
/// `_root_integration` test that #2661 owns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_box_root_cannot_append_events() {
    let (_state, _cache, mngr) = manager().await;
    let id = mngr.create_session(sample_config(), None).await.unwrap();

    let forged = BoxEvent {
        box_id: id,
        parent: None,
        ts: now_ms(),
        kind: BoxEventType::Exited,
        data: EventData::new(),
    };
    let line = forged.to_line().unwrap();
    for seen in box_visible_dirs(&mngr, id).await {
        let dir = seen.as_utf8_path();
        std::fs::create_dir_all(dir).unwrap();
        for name in [boxes::events::EVENTS_FILE, "record.json"] {
            std::fs::write(dir.join(name), &line).unwrap();
        }
    }

    let mut reader = mngr.box_events(id).await.unwrap();
    let events = reader.read_new().unwrap();
    assert_eq!(
        events.iter().map(|e| e.kind).collect::<Vec<_>>(),
        [BoxEventType::Created],
        "no event written inside the box reaches its stream"
    );
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(reader.object.events_path().as_utf8_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "only the daemon's user can open it");
    }
}

/// BOX-162: a complete line of the events file that is not an event
/// makes the read fail with `InvalidData`, naming the line's byte offset.
/// The read cannot return every retained event, so it does not end as
/// complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_read_fails_on_a_refused_line() {
    use std::io::Write as _;

    let (_state, _cache, mngr) = manager().await;
    let id = mngr.create_session(sample_config(), None).await.unwrap();
    let mut reader = mngr.box_events(id).await.unwrap();
    let path = reader.object.events_path();
    let bad_at = std::fs::metadata(path.as_utf8_path()).unwrap().len();
    std::fs::OpenOptions::new()
        .append(true)
        .open(path.as_utf8_path())
        .unwrap()
        .write_all(b"not an event\n")
        .unwrap();

    let err = reader.read_new().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains(&format!("byte {bad_at}")),
        "the error names the offset: {err}"
    );
}

/// BOX-040: the event a writer passes `data` to carries it, and reads back
/// with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn written_event_carries_its_data() {
    let (_state, _cache, mngr) = manager().await;
    let id = mngr.create_session(sample_config(), None).await.unwrap();
    let mut reader = mngr.box_events(id).await.unwrap();
    let created = reader.read_new().unwrap();
    assert!(created[0].data.is_empty(), "created carries an empty data");

    let data: EventData = [("reason".to_string(), "stopped".into())]
        .into_iter()
        .collect();
    let written = write_box_event(&reader.object, BoxEventType::Exited, data.clone()).unwrap();
    assert_eq!(written.data, data);
    assert_eq!(reader.read_new().unwrap(), [written]);
}

/// Drives the `ReadEvents` subsystem: writes the request and half-closes,
/// and returns the response lines as they arrive.
async fn open_events_read(
    client: &mut crate::test_harness::TestClient,
    id: SessionId,
    follow: bool,
) -> tokio::io::Lines<tokio::io::BufReader<russh::ChannelStream<russh::client::Msg>>> {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    let channel = client
        .open_subsystem(minimald_rpc::READ_EVENTS_SUBSYSTEM, &[])
        .await;
    let mut stream = channel.into_stream();
    let req = minimald_rpc::ReadEventsRequest { id, follow };
    stream
        .write_all(&serde_json_lenient::to_vec(&req).unwrap())
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    tokio::io::BufReader::new(stream).lines()
}

/// The next update line, or `None` at the end of the stream.
async fn next_update(
    lines: &mut tokio::io::Lines<tokio::io::BufReader<russh::ChannelStream<russh::client::Msg>>>,
) -> Option<minimald_rpc::ReadEventsUpdate> {
    tokio::time::timeout(std::time::Duration::from_secs(30), lines.next_line())
        .await
        .expect("the read answers in time")
        .unwrap()
        .map(|line| serde_json_lenient::from_str(&line).expect("each line is an update"))
}

/// BOX-162: a read of a box's events returns every retained event, in
/// the order the daemon wrote them, then `Done`. A read of a box no
/// record names returns no event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_read_returns_full_retained_stream_in_order() {
    use minimald_rpc::ReadEventsUpdate;

    let server = crate::test_harness::TestServer::new().await;
    let mut client = server.connect().await;
    let id = crate::test_harness::create_configured_session(&mut client, "evts", "/tmp").await;
    let mngr = server.state.sessions_manager().await;
    let reader = mngr.box_events(id).await.unwrap();
    let mut written = reader.object.read_events_from(0).unwrap().events;
    assert_eq!(written[0].kind, BoxEventType::Created);
    for kind in [
        BoxEventType::Started,
        BoxEventType::ExecStarted,
        BoxEventType::ExecExited,
        BoxEventType::Detached,
        BoxEventType::Resumed,
        BoxEventType::Renamed,
        BoxEventType::OomKilled,
        BoxEventType::Exited,
    ] {
        written.push(write_box_event(&reader.object, kind, EventData::new()).unwrap());
    }

    let mut lines = open_events_read(&mut client, id, false).await;
    let mut read = Vec::new();
    while let Some(update) = next_update(&mut lines).await {
        read.push(update);
    }
    let mut expected: Vec<ReadEventsUpdate> = written
        .into_iter()
        .map(|event| ReadEventsUpdate::Event { event })
        .collect();
    expected.push(ReadEventsUpdate::Done);
    assert_eq!(read, expected);

    let mut lines = open_events_read(&mut client, SessionId::mint(), false).await;
    assert_eq!(
        next_update(&mut lines).await,
        None,
        "an unknown box has no events"
    );
}

/// BOX-162: a followed read returns every retained event, then each new
/// one as it is written, and ends with `Reaped` once the box is reaped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_follow_replays_then_tails_until_reaped() {
    use minimald_rpc::ReadEventsUpdate;

    let server = crate::test_harness::TestServer::new().await;
    let mut client = server.connect().await;
    let id = crate::test_harness::create_configured_session(&mut client, "tail", "/tmp").await;
    let mngr = server.state.sessions_manager().await;
    let reader = mngr.box_events(id).await.unwrap();
    let mut retained = reader.object.read_events_from(0).unwrap().events;
    retained
        .push(write_box_event(&reader.object, BoxEventType::Started, EventData::new()).unwrap());

    let mut lines = open_events_read(&mut client, id, true).await;
    for event in retained {
        assert_eq!(
            next_update(&mut lines).await,
            Some(ReadEventsUpdate::Event { event })
        );
    }

    for kind in [BoxEventType::Detached, BoxEventType::Resumed] {
        let event = write_box_event(&reader.object, kind, EventData::new()).unwrap();
        assert_eq!(
            next_update(&mut lines).await,
            Some(ReadEventsUpdate::Event { event }),
            "a new event reaches the follower"
        );
    }

    mngr.delete_session(id).await.unwrap();
    assert_eq!(
        next_update(&mut lines).await,
        Some(ReadEventsUpdate::Reaped)
    );
    assert_eq!(
        next_update(&mut lines).await,
        None,
        "the stream ends at the reap"
    );
}

/// BOX-154: a daemon that starts and finds a `running` record with no
/// process left in the box sets it to `stopped`, with no exit code and no
/// signal, and records an `exited` event with that reason and no signal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_sets_orphaned_running_record_stopped_without_signal() {
    use boxes::core::record::{RecordState, StopEnding};

    let (state, cache, mngr) = manager().await;
    let mut config = sample_config();
    config.name = Some("orphaned".to_string());
    let orphaned = create_active_session_with(&mngr, config).await;
    let run_owned = create_active_session_with(&mngr, run_owned_config()).await;
    drop(mngr);

    // The restart: a fresh manager over the same state, and no process of
    // the earlier daemon's boxes left. Its start sets the record stopped.
    let restarted = manager_over(state.path(), cache.path()).await;

    let record = restarted
        .get_record(BoxKeyPredicate::Id(orphaned))
        .await
        .unwrap()
        .expect("the restart keeps the record");
    assert_eq!(
        record.state().unwrap(),
        RecordState::Stopped(StopEnding::AtDaemonStart)
    );
    assert_eq!(record.status, boxes::BoxState::Stopped);
    assert_eq!(record.exit_code, None);
    assert_eq!(record.signal, None);

    let mut reader = restarted.box_events(orphaned).await.unwrap();
    let events = reader.read_new().unwrap();
    let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, [BoxEventType::Created, BoxEventType::Exited]);
    let exited = &events[1];
    assert_eq!(exited.box_id, orphaned);
    assert_eq!(exited.data["reason"], "stopped");
    assert!(!exited.data.contains_key("signal"), "{:?}", exited.data);
    assert!(!exited.data.contains_key("exit_code"), "{:?}", exited.data);

    // The run's box is the resume's to destroy (NET-131), not this flip's.
    let run_record = restarted
        .get_record(BoxKeyPredicate::Id(run_owned))
        .await
        .unwrap()
        .expect("the flip leaves a run's box alone");
    assert_eq!(run_record.status, boxes::BoxState::Active);
}

/// BOX-018: a stopped box keeps its spec, exit code, ending signal, events
/// and parent readable until it is reaped, and the reap removes them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_box_record_readable_until_reaped() {
    use boxes::core::record::{RecordState, StopEnding};

    let (_state, _cache, mngr) = manager().await;
    let id = create_active_session_with(&mngr, sample_config()).await;
    // A spec beside the record, as a create that carries one writes it
    // (BOX-068).
    let spec = br#"{"type":"session"}"#.to_vec();
    mngr.box_events(id)
        .await
        .unwrap()
        .object
        .store_spec(&spec)
        .unwrap();
    session(&mngr, id)
        .await
        .ensure_host("tester".to_string())
        .await
        .expect("an Active session launches a headless host");

    let ending = mngr
        .stop_box_with_grace(id, false, std::time::Duration::from_secs(5))
        .await
        .expect("the stop succeeds");
    assert_eq!(
        ending,
        StopEnding::Signalled {
            signal: libc::SIGTERM
        }
    );

    // A second stop is refused: the box is not running.
    let again = mngr
        .stop_box_with_grace(id, false, std::time::Duration::from_secs(5))
        .await
        .expect_err("a stopped box cannot be stopped again");
    assert_eq!(again.kind(), ErrorKind::InvalidInput);

    // Read twice, so the record stays readable and unchanged.
    for _ in 0..2 {
        let record = mngr
            .get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("a stopped box keeps its record");
        assert_eq!(record.state().unwrap(), RecordState::Stopped(ending));
        assert_eq!(record.signal, Some(libc::SIGTERM));
        assert_eq!(record.exit_code, None);
        assert_eq!(record.parent, None, "a box created outside any box");

        let reader = mngr.box_events(id).await.unwrap();
        assert_eq!(reader.object.load_spec().unwrap(), Some(spec.clone()));
        let mut reader = reader;
        let events = reader.read_new().unwrap();
        let exited = events
            .iter()
            .find(|e| e.kind == BoxEventType::Exited)
            .expect("the stop's exited event is kept");
        assert_eq!(exited.data["reason"], "stopped");
        assert_eq!(exited.data["signal"], libc::SIGTERM);
        assert_eq!(exited.parent, None);
    }

    // The reap removes the record and its events.
    mngr.delete_session(id).await.unwrap();
    assert_eq!(
        mngr.get_record(BoxKeyPredicate::Id(id)).await.unwrap(),
        None
    );
    assert_eq!(
        mngr.box_events(id).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

/// Sets a retained record to `state` through a store over `state_dir`, as
/// the box's own stop or exit would have left it.
async fn set_record_state(
    state_dir: &std::path::Path,
    id: SessionId,
    state: boxes::core::record::RecordState,
) {
    let store = crate::store::Store::init(daemon_abs(state_dir))
        .await
        .unwrap();
    let handle = store
        .find(RecordPredicate::Id(id))
        .await
        .unwrap()
        .expect("the record is retained");
    let mut record = handle.record().await.unwrap();
    record.set_state(state);
    handle.write(record).await.unwrap();
}

/// A config named `name` whose project root is `root`, built from a
/// working path that is the same for every box.
fn rooted_config(name: &str, root: &str) -> minimald_rpc::BoxConfig {
    let mut config = sample_config();
    config.name = Some(name.to_string());
    config.project_path = HostAbsPath::try_new("/home/dev/proj").unwrap();
    config.project_root = Some(HostAbsPath::try_new(root).unwrap());
    config
}

/// BOX-158: the listing holds every retained record, in any state, with
/// its id, name, type, parent, project root and state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_returns_every_retained_record_with_state() {
    use boxes::core::record::{ExitEnding, RecordState, StopEnding};

    let (state, cache, mngr) = manager().await;
    let stopped =
        create_active_session_with(&mngr, rooted_config("stopped", "/home/dev/proj")).await;
    let exited = create_active_session_with(&mngr, rooted_config("exited", "/home/dev/proj")).await;
    drop(mngr);
    set_record_state(
        state.path(),
        stopped,
        RecordState::Stopped(StopEnding::Signalled {
            signal: libc::SIGTERM,
        }),
    )
    .await;
    set_record_state(state.path(), exited, RecordState::Exited(ExitEnding::Oom)).await;

    let mngr = manager_over(state.path(), cache.path()).await;
    let running =
        create_active_session_with(&mngr, rooted_config("running", "/home/dev/proj")).await;
    let pending = mngr
        .create_session(rooted_config("pending", "/home/dev/proj"), None)
        .await
        .unwrap();

    let listing = mngr.list_boxes(None).await.unwrap();
    let ids: Vec<_> = listing.iter().map(|entry| entry.box_id).collect();
    let mut expected = vec![stopped, exited, running, pending];
    expected.sort();
    assert_eq!(ids, expected, "every retained record, in box id order");

    let entry = |id| listing.iter().find(|entry| entry.box_id == id).unwrap();
    let root = Some(HostAbsPath::try_new("/home/dev/proj").unwrap());
    for (id, name, state) in [
        (stopped, "stopped", "stopped"),
        (exited, "exited", "exited"),
        (running, "running", "running"),
        (pending, "pending", "pending"),
    ] {
        let entry = entry(id);
        assert_eq!(entry.name.as_deref(), Some(name));
        assert_eq!(entry.state, state, "{entry:?}");
        assert_eq!(entry.box_type.as_deref(), Some(boxes::SESSION_BOX_TYPE));
        assert_eq!(entry.parent, None, "a box created outside any box");
        assert_eq!(entry.project_root, root);
    }
    assert_eq!(entry(stopped).reason.as_deref(), Some("stopped"));
    assert_eq!(entry(stopped).signal, Some(libc::SIGTERM));
    assert_eq!(entry(stopped).exit_code, None);
    assert_eq!(entry(exited).reason.as_deref(), Some("oom"));
    assert_eq!(entry(exited).exit_code, Some(137));
    assert_eq!(entry(running).reason, None);
}

/// BOX-158: a listing scoped to a project holds only the records whose
/// recorded project root is that project's, whatever their working path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_scoped_to_project_reads_project_root() {
    let (_state, _cache, mngr) = manager().await;
    let inside = mngr
        .create_session(rooted_config("inside", "/home/dev/proj"), None)
        .await
        .unwrap();
    // Built from the same working path, under another project's root.
    let _outside = mngr
        .create_session(rooted_config("outside", "/home/dev"), None)
        .await
        .unwrap();

    let root = HostAbsPath::try_new("/home/dev/proj").unwrap();
    let scoped = mngr.list_boxes(Some(&root)).await.unwrap();
    let ids: Vec<_> = scoped.iter().map(|entry| entry.box_id).collect();
    assert_eq!(ids, [inside]);

    let elsewhere = HostAbsPath::try_new("/home/dev/elsewhere").unwrap();
    assert!(mngr.list_boxes(Some(&elsewhere)).await.unwrap().is_empty());
    assert_eq!(mngr.list_boxes(None).await.unwrap().len(), 2);
}

/// BOX-159: a read returns the record with its state and ending, the
/// identity the box runs under, and its live execs. An unknown id reads
/// as none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn show_returns_record_state_identity_and_live_execs() {
    use boxes::core::record::{RecordState, StopEnding};

    let (state, cache, mngr) = manager().await;
    let id = create_active_session_with(&mngr, rooted_config("shown", "/home/dev/proj")).await;

    let running = mngr
        .show_box(id)
        .await
        .unwrap()
        .expect("the box is retained");
    assert_eq!(running.record.state, "running");
    assert_eq!(running.identity, minimald_rpc::BoxIdentity::None);
    // No exec runs in the box.
    assert!(running.live_execs.is_empty(), "{:?}", running.live_execs);
    drop(mngr);

    set_record_state(
        state.path(),
        id,
        RecordState::Stopped(StopEnding::ExitedFirst { exit_code: 3 }),
    )
    .await;
    let mngr = manager_over(state.path(), cache.path()).await;
    let shown = mngr
        .show_box(id)
        .await
        .unwrap()
        .expect("the box is retained");
    assert_eq!(
        shown.record,
        minimald_rpc::BoxListingEntry {
            box_id: id,
            name: Some("shown".to_string()),
            box_type: Some(boxes::SESSION_BOX_TYPE.to_string()),
            parent: None,
            project_root: Some(HostAbsPath::try_new("/home/dev/proj").unwrap()),
            state: "stopped".to_string(),
            reason: Some("stopped".to_string()),
            exit_code: Some(3),
            signal: None,
        }
    );
    assert_eq!(shown.identity, minimald_rpc::BoxIdentity::None);
    assert!(shown.live_execs.is_empty());
    assert_eq!(
        mngr.running_count().await,
        0,
        "a read starts no actor for the box"
    );

    assert_eq!(mngr.show_box(SessionId::mint()).await.unwrap(), None);
}

/// BOX-158, BOX-159: the id a listing prints reads back through show,
/// also for a record whose `box_id` differs from its `id`, as on a VM
/// guest. The record `id` still reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn show_box_finds_a_box_by_the_id_list_prints() {
    let (state, cache, mngr) = manager().await;
    let id = create_active_session_with(&mngr, rooted_config("guest", "/home/dev/proj")).await;
    drop(mngr);

    let box_id = SessionId::mint();
    assert_ne!(box_id, id);
    let store = crate::store::Store::init(daemon_abs(state.path()))
        .await
        .unwrap();
    let handle = store
        .find(RecordPredicate::Id(id))
        .await
        .unwrap()
        .expect("the record is retained");
    let mut record = handle.record().await.unwrap();
    record.box_id = Some(box_id);
    handle.write(record).await.unwrap();
    drop(store);

    let mngr = manager_over(state.path(), cache.path()).await;
    let listing = mngr.list_boxes(None).await.unwrap();
    let listed: Vec<_> = listing.iter().map(|entry| entry.box_id).collect();
    assert_eq!(listed, [box_id], "the listing prints the box_id");

    let shown = mngr
        .show_box(box_id)
        .await
        .unwrap()
        .expect("the id the listing prints finds the box");
    assert_eq!(shown.record, listing[0]);
    let by_record_id = mngr
        .show_box(id)
        .await
        .unwrap()
        .expect("the record id still finds the box");
    assert_eq!(by_record_id.record.box_id, box_id);
}

/// Creates an `Active` box through the whole create flow a client drives,
/// with `verb` as the creating verb and `spec` as the expanded spec the
/// create sends (BOX-068).
#[cfg(target_os = "linux")]
async fn create_box_by_verb(
    client: &mut crate::test_harness::TestClient,
    name: &str,
    verb: minimald_rpc::CreatingVerb,
    spec: Option<serde_json_lenient::Value>,
) -> SessionId {
    use crate::test_harness::{create_session_req, unwrap_ready};
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable, FinalizeSession,
        FinalizeSessionRequest,
    };

    let mut req = create_session_req(name, "/uwu");
    req.config.creating_verb = verb;
    req.spec = spec;
    let id = client.call::<CreateSession>(&req).await.unwrap().id;
    unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    match client
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: false,
        })
        .await
    {
        Errorable::Ok(_) => {}
        Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
    }
    id
}

/// Attaches to `id`, sends a line and waits for the shell to echo it.
/// Panics with what the channel carried when it closes first.
#[cfg(target_os = "linux")]
async fn attach_until_echo(client: &mut crate::test_harness::TestClient, id: SessionId) {
    use russh::ChannelMsg;

    let mut channel = client.open_shell(id).await;
    let _ = channel.data_bytes(b"hello\n".to_vec()).await;
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(30), channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => {
                out.extend_from_slice(&data);
                if String::from_utf8_lossy(&out).contains("got:hello") {
                    return;
                }
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => panic!(
                "the attach to {id} closed before its shell answered: {:?}",
                String::from_utf8_lossy(&out)
            ),
        }
    }
}

/// The listing entry for `id` in a `ListBoxes` reply over the socket.
#[cfg(target_os = "linux")]
async fn listed(
    client: &mut crate::test_harness::TestClient,
    id: SessionId,
) -> minimald_rpc::BoxListingEntry {
    use minimald_rpc::{Errorable, ListBoxes, ListBoxesRequest};

    match client.call::<ListBoxes>(&ListBoxesRequest::default()).await {
        Errorable::Ok(listing) => listing
            .boxes
            .into_iter()
            .find(|entry| entry.box_id == id)
            .unwrap_or_else(|| panic!("the listing holds {id}")),
        Errorable::Err { error } => panic!("ListBoxes failed: {error}"),
    }
}

/// The first slice, end to end over the daemon socket (BOX-001, BOX-003,
/// BOX-011, BOX-013, BOX-154, BOX-158, BOX-159, BOX-068, BOX-025). A
/// session box is stopped and retained, and a task box is left running.
/// After a daemon restart, the listing holds both, with the type of the
/// creating verb, no parent, and the `stopped` state. The daemon log
/// names the record the restart set stopped. A read returns the stopped
/// box's ending. An attach resumes it from its stored spec under the same
/// id, and the listing then reads it `running`.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_session_survives_restart_then_lists_reads_and_resumes() {
    use crate::test_harness::TestServer;
    use minimald_rpc::{CreatingVerb, Errorable, ShowBox, ShowBoxRequest, StopBox, StopBoxRequest};

    let log = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let mut spec = mfile::spec::BoxSpec::for_session(None, mfile::spec::SpecFlags::default());
    spec.pty_enabled = true;
    let spec = serde_json_lenient::to_value(&spec).expect("a spec serializes");
    let kept = create_box_by_verb(
        &mut client,
        "kept-session",
        CreatingVerb::Session,
        Some(spec.clone()),
    )
    .await;
    let left = create_box_by_verb(&mut client, "left-task", CreatingVerb::Task, None).await;

    // Before the restart, both boxes run under ids the daemon minted.
    assert_ne!(kept, left);
    assert_eq!(listed(&mut client, kept).await.state, "running");
    assert_eq!(listed(&mut client, left).await.state, "running");

    // The session box runs a shell, then a stop ends it and keeps its
    // record (BOX-013, BOX-018).
    attach_until_echo(&mut client, kept).await;
    match client
        .call::<StopBox>(&StopBoxRequest {
            id: kept,
            force: true,
        })
        .await
    {
        Errorable::Ok(_) => {}
        Errorable::Err { error } => panic!("StopBox failed: {error}"),
    }
    let stopped = listed(&mut client, kept).await;
    assert_eq!(stopped.state, "stopped", "{stopped:?}");
    assert_eq!(stopped.reason.as_deref(), Some("stopped"));

    // The restart: every process of the first daemon's boxes is gone.
    server
        .state
        .sessions_manager()
        .await
        .shutdown(true)
        .await
        .expect("a forced shutdown has nothing left to refuse it");
    drop(client);
    let server = TestServer::new_in(server.into_state_dir()).await;
    let mut client = server.connect().await;

    // The listing holds both records, with the creating verb's type, no
    // parent and the `stopped` state (BOX-158, BOX-001, BOX-011).
    let kept_entry = listed(&mut client, kept).await;
    assert_eq!(kept_entry.name.as_deref(), Some("kept-session"));
    assert_eq!(
        kept_entry.box_type.as_deref(),
        Some(boxes::SESSION_BOX_TYPE)
    );
    assert_eq!(kept_entry.parent, None, "a box created outside any box");
    assert_eq!(kept_entry.state, "stopped", "{kept_entry:?}");
    assert_eq!(kept_entry.reason.as_deref(), Some("stopped"));

    let left_entry = listed(&mut client, left).await;
    assert_eq!(left_entry.name.as_deref(), Some("left-task"));
    assert_eq!(left_entry.box_type.as_deref(), Some(boxes::TASK_BOX_TYPE));
    assert_eq!(left_entry.parent, None);
    // BOX-154: the restart set the running box stopped, with no signal.
    assert_eq!(left_entry.state, "stopped", "{left_entry:?}");
    assert_eq!(left_entry.reason.as_deref(), Some("stopped"));
    assert_eq!((left_entry.exit_code, left_entry.signal), (None, None));
    let logged = log.contents();
    assert!(
        logged.lines().any(|line| line.contains(&left.to_string())
            && line.contains("restart: set a running record with no process left to stopped")),
        "the daemon log names the record the restart set stopped:\n{logged}"
    );

    // A read returns the same record, its identity and its live execs
    // (BOX-159).
    let shown = match client.call::<ShowBox>(&ShowBoxRequest { id: kept }).await {
        Errorable::Ok(shown) => shown,
        Errorable::Err { error } => panic!("ShowBox failed: {error}"),
    };
    assert_eq!(shown.record, kept_entry);
    assert_eq!(shown.identity, minimald_rpc::BoxIdentity::None);
    assert!(shown.live_execs.is_empty(), "{:?}", shown.live_execs);

    // The record kept the spec its create sent (BOX-068).
    let reader = server
        .state
        .sessions_manager()
        .await
        .box_events(kept)
        .await
        .unwrap();
    let stored: serde_json_lenient::Value =
        serde_json_lenient::from_slice(&reader.object.load_spec().unwrap().expect("a stored spec"))
            .unwrap();
    assert_eq!(stored, spec);

    // An attach resumes the stopped box from that spec, under the same id
    // (BOX-025). The other box stays stopped.
    attach_until_echo(&mut client, kept).await;
    let resumed = listed(&mut client, kept).await;
    assert_eq!(resumed.state, "running", "{resumed:?}");
    assert_eq!(resumed.name.as_deref(), Some("kept-session"));
    assert_eq!(listed(&mut client, left).await.state, "stopped");
}

/// A create request with no name of its own, as a client that names its
/// box through the spec sends it.
fn unnamed_config() -> minimald_rpc::BoxConfig {
    let mut config = sample_config();
    config.name = None;
    config
}

/// The JSON spec of a `[tasks.<entry>]` box, with `name` as its
/// `[box] name` when set.
fn task_spec(entry: &str, name: Option<&str>) -> serde_json_lenient::Value {
    let mut spec = mfile::spec::BoxSpec::for_session(None, mfile::spec::SpecFlags::default());
    spec.box_type = boxes::TASK_BOX_TYPE.to_string();
    spec.pty_enabled = false;
    spec.entry = entry.to_string();
    spec.name = name.map(str::to_string);
    serde_json_lenient::to_value(&spec).expect("a spec serializes")
}

/// The name the record of box `id` carries.
async fn record_name(mngr: &BoxManagerHandle, id: SessionId) -> Option<String> {
    mngr.get_record(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the created record is filed")
        .name
}

/// BOX-163: a box takes the spec's `[box] name`, else its entry's name.
/// A request with no spec keeps the name it sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_names_box_from_box_name_else_entry() {
    let (_state, _cache, mngr) = manager().await;

    let named = mngr
        .create_box_with_spec(
            unnamed_config(),
            Some(task_spec("lint", Some("dev"))),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(record_name(&mngr, named).await.as_deref(), Some("dev"));

    let entry = mngr
        .create_box_with_spec(unnamed_config(), Some(task_spec("lint", None)), None, None)
        .await
        .unwrap();
    assert_eq!(
        record_name(&mngr, entry).await.as_deref(),
        Some("lint"),
        "no `[box] name`: the entry's name"
    );

    // The spec's `[box] name` comes before a name the request sends.
    let mut config = unnamed_config();
    config.name = Some("given".to_string());
    let over = mngr
        .create_box_with_spec(config, Some(task_spec("other", Some("web"))), None, None)
        .await
        .unwrap();
    assert_eq!(record_name(&mngr, over).await.as_deref(), Some("web"));

    let mut config = unnamed_config();
    config.name = Some("legacy".to_string());
    let legacy = mngr
        .create_box_with_spec(config, None, None, None)
        .await
        .unwrap();
    assert_eq!(record_name(&mngr, legacy).await.as_deref(), Some("legacy"));
}

/// BOX-163: a create that asks for no fresh instance, under a name a
/// running box holds, is refused with exit 2, naming the holder, and
/// files nothing. A stopped holder blocks nothing (BOX-004).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_with_name_held_by_running_box_refused_exit2_names_holder() {
    let log = crate::test_harness::captured_log();
    let (state, _cache, mngr) = manager().await;
    let holder = mngr
        .create_box_with_spec(unnamed_config(), Some(task_spec("dev", None)), None, None)
        .await
        .unwrap();

    for asked in ["dev", "DEV"] {
        let err = mngr
            .create_box_with_spec(
                unnamed_config(),
                Some(task_spec("lint", Some(asked))),
                None,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AlreadyExists, "{err}");
        let refusal = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<HeldNameRefusal>())
            .unwrap_or_else(|| panic!("the refusal names the holder: {err}"));
        assert_eq!(
            refusal,
            &HeldNameRefusal {
                name: asked.to_string(),
                holder,
                holder_name: "dev".to_string(),
            }
        );
        assert_eq!(refusal.exit_code(), 2);
        let text = err.to_string();
        assert!(text.contains(&holder.to_string()), "{text}");
        assert!(text.contains("`dev`"), "{text}");
        assert!(
            text.contains(&format!("min session rename {holder} <new-name>")),
            "the refusal names the next step: {text}"
        );
    }
    let listed = mngr.list_boxes(None).await.unwrap();
    assert_eq!(
        listed.len(),
        1,
        "a refused create files nothing: {listed:?}"
    );
    let logged = log.contents();
    assert!(
        logged.lines().any(
            |line| line.contains("refused a create: a running box holds its name")
                && line.contains(&holder.to_string())
                && line.contains("exit_code=2")
        ),
        "the daemon log names the holder and the exit code:\n{logged}"
    );

    // A stopped box keeps its name and leaves it free for a new box.
    set_record_state(
        state.path(),
        holder,
        boxes::core::record::RecordState::Stopped(boxes::core::record::StopEnding::AtDaemonStart),
    )
    .await;
    let reuse = mngr
        .create_box_with_spec(unnamed_config(), Some(task_spec("dev", None)), None, None)
        .await
        .expect("a stopped holder leaves the name free");
    assert_ne!(reuse, holder);
    assert_eq!(record_name(&mngr, reuse).await.as_deref(), Some("dev"));
}

/// BOX-163: only the entry is cleaned into a label. A `[box] name` is
/// taken unchanged, so an invalid one is refused, not rewritten.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_name_is_refused_unchanged_and_entry_is_cleaned() {
    let (_state, _cache, mngr) = manager().await;
    let refused = mngr
        .create_box_with_spec(
            unnamed_config(),
            Some(task_spec("lint", Some("My_Box"))),
            None,
            None,
        )
        .await
        .expect_err("an invalid `[box] name` is refused");
    let text = format!("{refused:#}");
    assert!(
        text.contains("invalid session name") && text.contains("DNS label"),
        "the refusal says the name is invalid: {text}"
    );
    assert!(
        mngr.list_boxes(None).await.unwrap().is_empty(),
        "a refused name files nothing, and no `my-box` exists"
    );

    let id = mngr
        .create_box_with_spec(
            unnamed_config(),
            Some(task_spec("build_all", None)),
            None,
            None,
        )
        .await
        .expect("an entry name is cleaned into a label");
    assert_eq!(record_name(&mngr, id).await.as_deref(), Some("build-all"));
}

/// BOX-163: a fresh instance is named `<name>-<n>`, with the smallest `n`
/// no retained record on the host uses, whether or not a running box
/// holds `<name>`. A stopped record keeps its suffix used.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_instance_creation_named_smallest_unused_suffix() {
    let log = crate::test_harness::captured_log();
    let (state, _cache, mngr) = manager().await;
    let fresh = |entry: &'static str| {
        let mngr = mngr.clone();
        async move {
            let id = mngr
                .create_fresh_box_with_spec(
                    unnamed_config(),
                    Some(task_spec(entry, None)),
                    None,
                    None,
                )
                .await
                .unwrap();
            record_name(&mngr, id).await.unwrap()
        }
    };

    // A running `dev` holds the name: a fresh run is not refused.
    let dev = mngr
        .create_box_with_spec(unnamed_config(), Some(task_spec("dev", None)), None, None)
        .await
        .unwrap();
    assert_eq!(fresh("dev").await, "dev-1");
    assert_eq!(fresh("dev").await, "dev-2");

    // A gap is filled first, and a stopped record still uses its suffix.
    let three = mngr
        .create_box_with_spec(
            unnamed_config(),
            Some(task_spec("lint", Some("Dev-4"))),
            None,
            None,
        )
        .await
        .unwrap();
    set_record_state(
        state.path(),
        three,
        boxes::core::record::RecordState::Stopped(boxes::core::record::StopEnding::AtDaemonStart),
    )
    .await;
    assert_eq!(fresh("dev").await, "dev-3");
    assert_eq!(
        fresh("dev").await,
        "dev-5",
        "a stopped `Dev-4` keeps 4 used"
    );

    // With no box of the name at all, a fresh run still takes a suffix.
    assert_eq!(fresh("web").await, "web-1");
    assert_eq!(record_name(&mngr, dev).await.as_deref(), Some("dev"));

    let logged = log.contents();
    assert!(
        logged.lines().any(|line| line.contains("named a fresh box")
            && line.contains("dev-5")
            && line.contains("suffix=5")),
        "the daemon log names the suffix:\n{logged}"
    );
}

/// The id of the record that answers to `name`, if any (BOX-005).
async fn answers_to(mngr: &BoxManagerHandle, name: &str) -> Option<SessionId> {
    mngr.get_record(BoxKeyPredicate::Name(name.to_string()))
        .await
        .unwrap()
        .map(|record| record.id)
}

/// The state of the retained record of box `id`.
async fn state_of(mngr: &BoxManagerHandle, id: SessionId) -> boxes::core::record::RecordState {
    mngr.get_record(BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the record is retained")
        .state()
        .expect("the record's state is readable")
}

/// Renames box `id` the way the rename RPC does: through its actor.
async fn rename_box(mngr: &BoxManagerHandle, id: SessionId, new_name: &str) {
    session(mngr, id)
        .await
        .rename(new_name.to_string())
        .await
        .unwrap_or_else(|e| panic!("rename of {id} to `{new_name}`: {e}"));
}

/// BOX-004, BOX-005, BOX-010: a stopped `dev` keeps its name and id, a new
/// `dev` starts beside it with an id of its own, and a rename of either
/// moves only that box's name. Through each step the name resolves to the
/// running box, and the daemon log names the id of each box it renames.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_dev_and_new_dev_keep_ids_through_rename() {
    use boxes::core::record::{RecordState, StopEnding};

    let log = crate::test_harness::captured_log();
    let (state, _cache, mngr) = manager().await;

    // Stop a box named `dev`.
    let old = mngr
        .create_box_with_spec(unnamed_config(), Some(task_spec("dev", None)), None, None)
        .await
        .unwrap();
    assert_eq!(answers_to(&mngr, "dev").await, Some(old));
    let stopped = RecordState::Stopped(StopEnding::AtDaemonStart);
    set_record_state(state.path(), old, stopped).await;
    assert_eq!(
        answers_to(&mngr, "dev").await,
        Some(old),
        "a stopped `dev` still answers while no other `dev` exists"
    );

    // Start a new `dev`: the stopped one leaves the name free.
    let new = mngr
        .create_box_with_spec(unnamed_config(), Some(task_spec("dev", None)), None, None)
        .await
        .expect("a stopped `dev` does not hold the name");
    assert_ne!(new, old, "the new `dev` has an id of its own");
    assert_eq!(record_name(&mngr, old).await.as_deref(), Some("dev"));
    assert_eq!(record_name(&mngr, new).await.as_deref(), Some("dev"));
    assert_eq!(
        answers_to(&mngr, "dev").await,
        Some(new),
        "only the running `dev` answers to the name"
    );

    // Rename the stopped one: it keeps its id and its state, and `dev`
    // still answers with the running one.
    rename_box(&mngr, old, "old").await;
    assert_eq!(record_name(&mngr, old).await.as_deref(), Some("old"));
    assert_eq!(
        state_of(&mngr, old).await,
        stopped,
        "a rename starts nothing"
    );
    assert_eq!(answers_to(&mngr, "old").await, Some(old));
    assert_eq!(answers_to(&mngr, "dev").await, Some(new));
    assert_eq!(record_name(&mngr, new).await.as_deref(), Some("dev"));

    // Rename the running one: it keeps its id, and its name moves with it.
    rename_box(&mngr, new, "web").await;
    assert_eq!(record_name(&mngr, new).await.as_deref(), Some("web"));
    assert_eq!(answers_to(&mngr, "web").await, Some(new));
    assert_eq!(answers_to(&mngr, "old").await, Some(old));
    assert_eq!(
        answers_to(&mngr, "dev").await,
        None,
        "no box answers to `dev` once both are renamed"
    );

    // The listing holds the same two ids, each under its new name.
    let mut listed: Vec<(SessionId, Option<String>)> = mngr
        .list_boxes(None)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| (entry.box_id, entry.name))
        .collect();
    listed.sort();
    let mut expected = vec![
        (old, Some("old".to_string())),
        (new, Some("web".to_string())),
    ];
    expected.sort();
    assert_eq!(listed, expected);

    let logged = log.contents();
    for (id, name) in [(old, "old"), (new, "web")] {
        assert!(
            logged.lines().any(|line| line.contains("renamed a box")
                && line.contains(&id.to_string())
                && line.contains(name)),
            "the daemon log names box {id} and its new name `{name}`:\n{logged}"
        );
    }
}

/// The suffix rule alone (BOX-163): ASCII case is folded, and only the
/// plain spelling of `n` uses it.
#[test]
fn fresh_instance_name_skips_used_suffixes() {
    assert_eq!(fresh_instance_name("dev", []), ("dev-1".to_string(), 1));
    assert_eq!(
        fresh_instance_name(
            "dev",
            ["dev", "DEV-1", "dev-2", "dev-04", "dev-x", "devs-3"]
        ),
        ("dev-3".to_string(), 3)
    );
}

/// A stand-in for the VM host daemon's report door at `door`: it answers
/// each mint ask with the next reply in `replies` and hands the ask it read
/// to the returned receiver.
fn mint_door(
    door: &std::path::Path,
    replies: Vec<minimald_rpc::BoxControlReply>,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::UnboundedReceiver<minimald_rpc::BoxControlRequest>,
) {
    mint_door_dropping(door, replies.into_iter().map(Some).collect())
}

/// The mint ask `ask` carries: a create's token is fresh each time, so a
/// test reads the ask's fields, never the whole ask.
fn mint_ask(ask: minimald_rpc::BoxControlRequest) -> minimald_rpc::MintBoxIdRequest {
    match ask {
        minimald_rpc::BoxControlRequest::MintBoxId(request) => {
            assert!(request.create_token.is_some(), "every create sends a token");
            request
        }
        other => panic!("expected a mint ask, got {other:?}"),
    }
}

/// [`mint_door`], where a `None` reply reads the ask and closes the
/// connection without an answer: a reply lost on its way to the guest.
fn mint_door_dropping(
    door: &std::path::Path,
    replies: Vec<Option<minimald_rpc::BoxControlReply>>,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::UnboundedReceiver<minimald_rpc::BoxControlRequest>,
) {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::UnixListener::bind(door).expect("bind the report door stand-in");
    let (asks_tx, asks) = tokio::sync::mpsc::unbounded_channel();
    let task = crate::traced::spawn(async move {
        for reply in replies {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            tokio::io::BufReader::new(read)
                .read_line(&mut line)
                .await
                .expect("read the ask");
            let ask = serde_json_lenient::from_str(line.trim()).expect("the ask parses");
            #[expect(
                clippy::let_underscore_must_use,
                reason = "the test may drop its receiver once it has its answer"
            )]
            let _ = asks_tx.send(ask);
            let Some(reply) = reply else {
                continue;
            };
            let mut out = serde_json_lenient::to_string(&reply).unwrap();
            out.push('\n');
            write
                .write_all(out.as_bytes())
                .await
                .expect("write the reply");
        }
    });
    (task, asks)
}

/// The control socket of the switch [`manager_over`] hands its manager:
/// the key a stand-in report door is seeded under.
fn manager_switch_control(state: &std::path::Path) -> std::path::PathBuf {
    crate::net::SwitchClient::new("/nonexistent/gvproxy", state.join("gvproxy")).control_socket()
}

/// BOX-002: on a VM guest a create files the box under the id the VM host
/// daemon mints, and never under the id the request carries. A box with a
/// row asks for its row's id by the switch address its registration
/// handed. A mint the VM host daemon refuses refuses the create and leaves
/// no record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_create_ignores_a_client_supplied_box_id() {
    let (state, _cache, mngr) = manager().await;
    let control = manager_switch_control(state.path());
    let door = state.path().join("vm-host-door.sock");
    let rowless = SessionId::mint();
    let rowed = SessionId::mint();
    let (door_task, mut asks) = mint_door(
        &door,
        vec![
            minimald_rpc::BoxControlReply::BoxIdMinted {
                minted_box_id: rowless,
            },
            minimald_rpc::BoxControlReply::BoxIdMinted {
                minted_box_id: rowed,
            },
            minimald_rpc::BoxControlReply::Error {
                error: "no box is registered at 100.64.0.9".to_string(),
            },
        ],
    );
    crate::net::listeners::seed_vm_report_door_for_tests(&control, &door);

    // A box with no row: the VM host daemon mints a fresh id.
    let client = SessionId::mint();
    let mut config = sample_config();
    config.box_id = Some(client);
    let id = mngr.create_session(config, None).await.unwrap();
    assert_eq!(id, rowless, "the box takes the VM host daemon's id");
    assert_eq!(mint_ask(asks.recv().await.unwrap()).switch_address, None);
    let shown = mngr.show_box(id).await.unwrap().expect("the box is filed");
    assert_eq!(shown.record.box_id, rowless);
    assert!(
        mngr.show_box(client).await.unwrap().is_none(),
        "no box is filed under the request's id"
    );

    // A box with a row: the ask names its switch address, and the record
    // names the row's id as its own id and as its row id.
    let switch_address = std::net::Ipv4Addr::new(100, 64, 0, 8);
    let mut config = sample_config();
    config.name = Some("rowed".to_string());
    config.box_id = Some(client);
    config.box_addresses = Some(boxes::BoxAddresses {
        switch_address,
        loopback_address: std::net::Ipv4Addr::LOCALHOST,
    });
    let id = mngr.create_session(config, None).await.unwrap();
    assert_eq!(id, rowed);
    assert_eq!(
        mint_ask(asks.recv().await.unwrap()).switch_address,
        Some(switch_address)
    );
    let handle = session(&mngr, id).await;
    let record = handle.record().await.unwrap();
    assert_eq!((record.id, record.box_id), (rowed, Some(rowed)));

    // A refused mint refuses the create.
    let mut config = sample_config();
    config.name = Some("refused".to_string());
    config.box_id = Some(client);
    config.box_addresses = Some(boxes::BoxAddresses {
        switch_address: std::net::Ipv4Addr::new(100, 64, 0, 9),
        loopback_address: std::net::Ipv4Addr::LOCALHOST,
    });
    let err = mngr.create_session(config, None).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "No session was created. The VM gave the new session no id: no box is registered \
         at 100.64.0.9. Run the command again."
    );
    assert_eq!(mngr.list_boxes(None).await.unwrap().len(), 2);

    crate::net::listeners::clear_vm_report_door_for_tests(&control);
    door_task.abort();
}

/// BOX-002: a create whose mint reply is lost asks again with the same
/// token, so the VM host daemon can give the retry the id it already
/// gave that create.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_create_ignores_a_client_supplied_box_id_and_retries_with_one_token() {
    let (state, _cache, mngr) = manager().await;
    let control = manager_switch_control(state.path());
    let door = state.path().join("vm-host-door.sock");
    let minted = SessionId::mint();
    let (door_task, mut asks) = mint_door_dropping(
        &door,
        vec![
            None,
            Some(minimald_rpc::BoxControlReply::BoxIdMinted {
                minted_box_id: minted,
            }),
        ],
    );
    crate::net::listeners::seed_vm_report_door_for_tests(&control, &door);

    let switch_address = std::net::Ipv4Addr::new(100, 64, 0, 8);
    let mut config = sample_config();
    config.name = Some("retried".to_string());
    config.box_id = Some(SessionId::mint());
    config.box_addresses = Some(boxes::BoxAddresses {
        switch_address,
        loopback_address: std::net::Ipv4Addr::LOCALHOST,
    });
    let id = mngr.create_session(config, None).await.unwrap();
    assert_eq!(id, minted, "the retry takes the minted id");
    let first = mint_ask(asks.recv().await.unwrap());
    let retry = mint_ask(asks.recv().await.unwrap());
    assert_eq!(first.switch_address, Some(switch_address));
    assert_eq!(retry, first, "a retry of one create sends the same token");

    // The next create sends another token.
    let (door_task_2, mut asks_2) = {
        crate::net::listeners::clear_vm_report_door_for_tests(&control);
        door_task.abort();
        let door = state.path().join("vm-host-door-2.sock");
        let served = mint_door(
            &door,
            vec![minimald_rpc::BoxControlReply::BoxIdMinted {
                minted_box_id: SessionId::mint(),
            }],
        );
        crate::net::listeners::seed_vm_report_door_for_tests(&control, &door);
        served
    };
    let mut config = sample_config();
    config.name = Some("next".to_string());
    mngr.create_session(config, None).await.unwrap();
    let next = mint_ask(asks_2.recv().await.unwrap());
    assert_ne!(
        next.create_token, first.create_token,
        "each create has its own token"
    );

    crate::net::listeners::clear_vm_report_door_for_tests(&control);
    door_task_2.abort();
}

/// BOX-001: on a native host the store mints the id, and the id the
/// request carries names nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_create_ignores_a_client_supplied_box_id() {
    let (_state, _cache, mngr) = manager().await;
    let client = SessionId::mint();
    let mut config = sample_config();
    config.box_id = Some(client);
    let id = mngr.create_session(config, None).await.unwrap();
    assert_ne!(id, client);
    let record = session(&mngr, id).await.record().await.unwrap();
    assert_eq!(record.box_id, None, "a native box has no row id");
    assert!(mngr.show_box(client).await.unwrap().is_none());
}

/// The switch control socket of `server`'s daemon, whose state dir is
/// `state`: the key a stand-in report door is seeded under for a create
/// that comes in over the socket.
async fn server_switch_control(
    server: &crate::test_harness::TestServer,
    state: &std::path::Path,
) -> std::path::PathBuf {
    let daemon_id = server.state.daemon_id().await;
    crate::net::SwitchClient::new(
        "/nonexistent/gvproxy",
        state.join("gvproxy").join(daemon_id),
    )
    .control_socket()
}

/// BOX-002: a create over the socket on a VM guest whose report door
/// serves the mint gets a reply that names the minted id, and never the
/// id the request carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_create_ignores_a_client_supplied_box_id_and_replies_with_the_minted_id() {
    use minimald_rpc::{CreateSession, Errorable};
    let temp = TempDir::new().unwrap();
    let state = temp.path().to_path_buf();
    let server = crate::test_harness::TestServer::new_in(temp).await;
    let control = server_switch_control(&server, &state).await;
    let door = state.join("vm-host-door.sock");
    let minted = SessionId::mint();
    let (door_task, mut asks) = mint_door(
        &door,
        vec![minimald_rpc::BoxControlReply::BoxIdMinted {
            minted_box_id: minted,
        }],
    );
    crate::net::listeners::seed_vm_report_door_for_tests(&control, &door);

    let mut client = server.connect().await;
    let mut request = crate::test_harness::create_session_req("served", "/uwu");
    request.config.box_id = Some(SessionId::mint());
    let reply = client.call::<CreateSession>(&request).await;
    crate::net::listeners::clear_vm_report_door_for_tests(&control);
    door_task.abort();
    match reply {
        Errorable::Ok(created) => assert_eq!(created.id, minted, "the box takes the minted id"),
        Errorable::Err { error } => panic!("the create was refused: {error}"),
    }
    assert!(matches!(
        asks.recv().await,
        Some(minimald_rpc::BoxControlRequest::MintBoxId(_))
    ));
}

/// BOX-002: a create over the socket on a VM guest whose report door is
/// absent (a bare `minvmd boot` binds none) gets a refusal as its reply,
/// never a closed channel, and leaves no box behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_create_ignores_a_client_supplied_box_id_and_replies_when_no_door_answers() {
    use minimald_rpc::{CreateSession, Errorable};
    let temp = TempDir::new().unwrap();
    let state = temp.path().to_path_buf();
    let server = crate::test_harness::TestServer::new_in(temp).await;
    let control = server_switch_control(&server, &state).await;
    let door = state.join("no-door-here.sock");
    crate::net::listeners::seed_vm_report_door_for_tests(&control, &door);

    let mut client = server.connect().await;
    let mut request = crate::test_harness::create_session_req("doorless", "/uwu");
    request.config.box_id = Some(SessionId::mint());
    let reply = client.call::<CreateSession>(&request).await;
    crate::net::listeners::clear_vm_report_door_for_tests(&control);
    match reply {
        Errorable::Err { error } => assert_eq!(
            error,
            "No session was created. The VM gave the new session no id: it did not answer \
             in time."
        ),
        Errorable::Ok(created) => panic!("a create with no minted id was filed as {}", created.id),
    }
    let manager = server.state.sessions_manager().await;
    assert!(manager.list_boxes(None).await.unwrap().is_empty());
}

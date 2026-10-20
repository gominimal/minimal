use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use super::testing::{MockEndpoints, build_mock, build_mock_seq};
use super::{bridge, bridge_noting_shutdown};

/// A never-firing client-loss signal for tests that exercise the
/// bridge without modelling a disconnect.
fn client_lost() -> tokio::sync::watch::Receiver<bool> {
    tokio::sync::watch::channel(false).1
}

/// `start_kill` asks the shim to exit with SIGTERM, not SIGKILL: SIGTERM
/// is what runs the shim's handler, which kills the injected process's
/// whole group. A SIGKILL here would leave the grandchildren running.
#[tokio::test]
async fn start_kill_sends_sigterm() {
    use std::os::unix::process::ExitStatusExt as _;

    use super::{Process as _, TokioProcess};

    let child = tokio::process::Command::new("sleep")
        .arg("600")
        .spawn()
        .expect("spawning sleep");
    let mut process = TokioProcess::shim(child);
    process.start_kill().expect("signalling the child");
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), process.child.wait())
        .await
        .expect("the child exits on SIGTERM")
        .expect("reaping the child");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
}

/// Any child other than the shim (the git service path's `/bin/sh -c`)
/// has no group-kill handler, so `start_kill` SIGKILLs it at once.
#[tokio::test]
async fn start_kill_sigkills_a_plain_child() {
    use std::os::unix::process::ExitStatusExt as _;

    use super::{Process as _, TokioProcess};

    let child = tokio::process::Command::new("sleep")
        .arg("600")
        .spawn()
        .expect("spawning sleep");
    let mut process = TokioProcess::new(child);
    process.start_kill().expect("signalling the child");
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), process.child.wait())
        .await
        .expect("the child exits on SIGKILL")
        .expect("reaping the child");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
}

/// A child that ignores SIGTERM is not waited on forever: after the grace
/// period, `wait` escalates to SIGKILL.
#[tokio::test]
async fn wait_escalates_to_sigkill_when_sigterm_is_ignored() {
    use super::{Process as _, TokioProcess};

    // The ignored disposition survives the `exec`, so `sleep` itself
    // ignores SIGTERM. The marker line says the trap is installed.
    let child = tokio::process::Command::new("/bin/sh")
        .args(["-c", "trap '' TERM; echo ready; exec sleep 600"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawning sh");
    let mut process = TokioProcess::shim(child);
    let mut stdout = process.child.stdout.take().expect("piped stdout");
    let mut ready = [0u8; 6];
    stdout
        .read_exact(&mut ready)
        .await
        .expect("reading the ready marker");

    process.start_kill().expect("signalling the child");
    let code = tokio::time::timeout(std::time::Duration::from_secs(10), process.wait())
        .await
        .expect("the escalation to SIGKILL ends the wait")
        .expect("reaping the child");
    assert_eq!(code, None, "a signalled child has no exit code");
}

/// `inherit_cwd` on the daemon side: a task that declares it starts at
/// `/workbench/<cwd>` when that directory is in the uploaded tree, and
/// falls back to `/workbench` with a stderr notice when it is not. A task
/// without `inherit_cwd`, or a run from the root, keeps `/workbench`.
#[test]
fn task_start_dir_honours_inherit_cwd() {
    use super::task_start_dir;

    let tree = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tree.path().join("sub/inner")).unwrap();

    assert_eq!(
        task_start_dir(true, "sub/inner", tree.path()),
        Ok(Some("/workbench/sub/inner".to_string()))
    );
    assert_eq!(task_start_dir(false, "sub/inner", tree.path()), Ok(None));
    assert_eq!(task_start_dir(true, "", tree.path()), Ok(None));

    let notice = task_start_dir(true, "sub/gone", tree.path()).unwrap_err();
    assert!(notice.contains("sub/gone"), "{notice}");
    assert!(notice.contains("/workbench"), "{notice}");
    assert_eq!(notice.lines().count(), 1, "one line: {notice:?}");
}

/// A session record carrying `mode`, with everything else at its default.
#[cfg(target_os = "linux")]
fn record_with(mode: boxes::NetworkMode) -> boxes::Record {
    boxes::Record {
        id: boxes::SessionId::nil(),
        name: None,
        username: None,
        project_path: paths::HostAbsPath::try_new("/tmp/project").unwrap(),
        network: mode,
        policy: boxes::BoxPolicy::default(),
        task_addresses: Vec::new(),
        box_addresses: None,
        status: boxes::BoxState::Active,
        hooks_enabled: true,
        // No launch ever minted these records, so none has recorded its
        // outcome on one.
        host_ip_enforcement: None,
        box_id: None,
        host_row_bound: false,
        bound_ports: std::collections::BTreeSet::new(),
        attrs: Default::default(),
    }
}

/// NET-138: a task run of a registered box whose record names no box
/// id is refused before anything attaches — the host cannot be asked
/// for that box's row, and an address-only answer could be another
/// box's — while a box the host registered nothing for asks nothing.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_task_run_of_a_registered_box_with_no_box_id_is_refused() {
    let switch = tokio::sync::Mutex::new(
        crate::net::SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy").with_transport(
            crate::net::SwitchTransport::HostShuttle {
                cid: crate::net::VSOCK_HOST_CID,
                port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
            },
        ),
    );
    let unregistered = record_with(boxes::NetworkMode::OwnIp);
    super::ensure_task_rows_stand(&unregistered, &switch)
        .await
        .expect("a box with no host registration asks nothing");

    let mut registered = record_with(boxes::NetworkMode::OwnIp);
    registered.name = Some("web".to_string());
    registered.box_addresses = Some(boxes::BoxAddresses {
        switch_address: std::net::Ipv4Addr::new(100, 64, 128, 1),
        loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 2),
    });
    registered.task_addresses = vec![std::net::Ipv4Addr::new(100, 64, 128, 2)];
    let refused = super::ensure_task_rows_stand(&registered, &switch)
        .await
        .expect_err("a registered box with no id is never answered as standing");
    assert!(
        refused.to_string().contains("could not confirm session"),
        "{refused}"
    );
    // The bare command fails: a destroy needs a session or `--all`.
    assert!(
        refused
            .to_string()
            .contains("`min session destroy <session>`"),
        "{refused}"
    );
}

/// 017-005. A task's sandbox is planned for its session's mode; `OwnIp`
/// is the case that matters, as it used to arrive as `HostNet`. The switch
/// is `HostShuttle`, so an own-IP plan is pure bookkeeping.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_task_takes_the_network_of_its_session() {
    use std::sync::Arc;

    let switch = Arc::new(tokio::sync::Mutex::new(
        crate::net::SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy").with_transport(
            crate::net::SwitchTransport::HostShuttle {
                cid: crate::net::VSOCK_HOST_CID,
                port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
            },
        ),
    ));

    let host = super::task_network(
        &record_with(boxes::NetworkMode::HostNet),
        &switch,
        boxes::EGRESS_DEFAULT_PHASE,
        false,
    );
    assert!(!host.plan().await.unwrap().isolates_netns());

    let no_net = super::task_network(
        &record_with(boxes::NetworkMode::NoNet),
        &switch,
        boxes::EGRESS_DEFAULT_PHASE,
        false,
    );
    let plan = no_net.plan().await.unwrap();
    assert!(plan.isolates_netns() && plan.tap().is_none());

    let mut record = record_with(boxes::NetworkMode::OwnIp);
    record.name = Some("web".to_string());
    record.policy.ingress = Some(boxes::IngressPolicy::default());
    // A VM host's switch draws nothing (NET-138): the task attaches at a
    // task address its box's registration filed.
    record.task_addresses = vec![std::net::Ipv4Addr::new(100, 64, 128, 2)];
    let own_ip = super::task_network(&record, &switch, boxes::EGRESS_DEFAULT_PHASE, false);
    let plan = own_ip.plan().await.unwrap();
    assert!(
        plan.isolates_netns(),
        "an own-IP task gets its own namespace"
    );
    assert!(matches!(plan.resolver(), sandbox::Resolver::Nameservers(_)));
    // Its own identity on the switch, and the session's *effective*
    // egress (NET-074) — resolved under the phase this build ships, so
    // the same rules the session's own gate enforces, whatever the
    // rollout leaves in force — but none of its ingress, because the
    // session's PTask is attached at the same time. The gate exists only
    // where that egress has rules, so the answer follows the shipped
    // phase rather than a literal a cutover would invalidate.
    let gated = crate::box_actor::effective_egress_section(
        &record.policy,
        record.network,
        boxes::EGRESS_DEFAULT_PHASE,
        false,
    )
    .is_some();
    let described = format!("{own_ip:?}");
    assert!(
        described.contains("\"web-task\"") && described.contains(&format!("has_policy: {gated}")),
        "got {described}"
    );
    own_ip.abandon().await;

    // No name: the session id, rather than an empty hostname.
    let unnamed = super::task_network(
        &record_with(boxes::NetworkMode::OwnIp),
        &switch,
        boxes::EGRESS_DEFAULT_PHASE,
        false,
    );
    assert!(format!("{unnamed:?}").contains(&boxes::SessionId::nil().to_string()));
}

/// A VM host's switch, which hands every address and draws none
/// (NET-138).
#[cfg(target_os = "linux")]
fn vm_host_switch() -> std::sync::Arc<tokio::sync::Mutex<crate::net::SwitchClient>> {
    std::sync::Arc::new(tokio::sync::Mutex::new(
        crate::net::SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy").with_transport(
            crate::net::SwitchTransport::HostShuttle {
                cid: crate::net::VSOCK_HOST_CID,
                port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
            },
        ),
    ))
}

/// NET-138 for a task run, whichever door started it — `min run` from
/// inside the box and a task run over exec both plan through
/// [`super::task_network`]: the task's sandbox attaches at a task
/// address its box's registration filed, the first one no run holds,
/// and never draws one of its own.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn in_box_run_task_draws_a_task_slot() {
    let switch = vm_host_switch();
    let mut record = record_with(boxes::NetworkMode::OwnIp);
    record.task_addresses = vec![
        std::net::Ipv4Addr::new(100, 64, 128, 2),
        std::net::Ipv4Addr::new(100, 64, 128, 3),
    ];
    let first = super::task_network(&record, &switch, boxes::EGRESS_DEFAULT_PHASE, false);
    first.plan().await.expect("a free task address");
    let second = super::task_network(&record, &switch, boxes::EGRESS_DEFAULT_PHASE, false);
    second.plan().await.expect("a second free task address");
    let held: Vec<_> = switch
        .lock()
        .await
        .leases()
        .iter()
        .map(|lease| lease.ip)
        .collect();
    assert_eq!(
        held, record.task_addresses,
        "each run holds one task address"
    );

    let third = super::task_network(&record, &switch, boxes::EGRESS_DEFAULT_PHASE, false);
    let err = third.plan().await.expect_err("every task address is held");
    assert!(
        err.to_string()
            .contains("2 task runs already in progress for this session"),
        "{err}"
    );
    first.abandon().await;
    third
        .plan()
        .await
        .expect("the address the first run held is free again");
}

/// A VM session record from before task addresses were registered
/// carries none: its task run is refused, naming the remedy, rather
/// than drawn an address no host row is keyed by.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn legacy_unregistered_vm_record_refused_with_reactivate_message() {
    let switch = vm_host_switch();
    let record = record_with(boxes::NetworkMode::OwnIp);
    let task = super::task_network(&record, &switch, boxes::EGRESS_DEFAULT_PHASE, false);
    let err = task.plan().await.expect_err("nothing is drawn");
    assert!(
        err.to_string()
            .contains("destroy the session and re-activate it"),
        "{err}"
    );
    assert!(switch.lock().await.leases().is_empty());
}

/// NET-074/NET-076/NET-077 for the task path: a task runs under the same
/// egress default its session does, and nothing else changes with it. A
/// gate is attached only where the effective egress has rules to enforce,
/// because a gate with no ingress declaration blocks a task's *inbound*
/// too. Under InForce, the shipped phase, a bare own-address task with no
/// opt-out carries the deny-all gate. The retired announced arm, pinned
/// here by name, attaches the same task ungated, as every task did before
/// the deny-all default.
///
/// The phase decides only the *default* for a box that declared nothing.
/// A box that declared an `egress` section is enforced on its session's
/// own PTask in every phase, so a task in such a session carries that
/// declaration's gate under either phase — the same inbound posture the
/// in-force case below accepts: a task PTask holds no ingress of its own,
/// so its gate default-blocks unsolicited inbound.
///
/// The phase is passed by name, not read from the shipped constant, so
/// both arms stay proven whichever one ships. `own_ip_default_deny_all`
/// proves what the deny-all section itself enforces.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_task_gate_follows_the_egress_default() {
    use std::sync::Arc;

    let switch = Arc::new(tokio::sync::Mutex::new(
        crate::net::SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy").with_transport(
            crate::net::SwitchTransport::HostShuttle {
                cid: crate::net::VSOCK_HOST_CID,
                port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
            },
        ),
    ));
    // A bare own-address box: no egress declaration, so its egress is
    // whatever the default resolves for an absent one.
    let record = record_with(boxes::NetworkMode::OwnIp);

    // Announced, no opt-out: an absent section still allows all, so the
    // task gets no gate at all — its inbound stays as open as it was
    // before the default was announced.
    assert_eq!(
        crate::box_actor::effective_egress_section(
            &record.policy,
            record.network,
            boxes::EgressDefaultPhase::Announced,
            false,
        ),
        None,
        "an announced default resolves an absent section to allow-all"
    );
    let announced = super::task_network(
        &record,
        &switch,
        boxes::EgressDefaultPhase::Announced,
        false,
    );
    assert!(
        format!("{announced:?}").contains("has_policy: false"),
        "an announced default gates nothing: {announced:?}"
    );

    // In force, no opt-out: the same absent section is the deny-all one,
    // and the task carries the gate built from it.
    assert_eq!(
        crate::box_actor::effective_egress_section(
            &record.policy,
            record.network,
            boxes::EgressDefaultPhase::InForce,
            false,
        ),
        Some(boxes::EgressPolicy::deny_all()),
        "the in-force default resolves an absent section to deny-all"
    );
    let in_force = super::task_network(&record, &switch, boxes::EgressDefaultPhase::InForce, false);
    assert!(
        format!("{in_force:?}").contains("has_policy: true"),
        "the in-force default gates a bare box's task: {in_force:?}"
    );

    // A box that *declared* an egress section is the other case where
    // the task path attaches a gate, and the announcement does not defer
    // it: the declaration is enforced on the session's own PTask in every
    // phase, so a task in that session resolves the same section its
    // session's gate did — the declaration, not the deny-all section and
    // not nothing — under either phase. In force, the default also
    // decides the destination list the declaration left absent
    // (`allow_dns_hosts`): present and empty, granting nothing
    // (NET-074); announced, the section is carried as declared.
    let section = boxes::EgressPolicy {
        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
        ..boxes::EgressPolicy::default()
    };
    let mut declared_record = record_with(boxes::NetworkMode::OwnIp);
    declared_record.policy.egress = Some(section.clone());
    for (phase, expected) in [
        (boxes::EgressDefaultPhase::Announced, section.clone()),
        (
            boxes::EgressDefaultPhase::InForce,
            boxes::EgressPolicy {
                allow_dns_hosts: Some(Vec::new()),
                ..section.clone()
            },
        ),
    ] {
        assert_eq!(
            crate::box_actor::effective_egress_section(
                &declared_record.policy,
                declared_record.network,
                phase,
                false,
            ),
            Some(expected),
            "a declared egress section reaches the task's gate as the \
             default resolves it while the default is {phase:?}",
        );
    }
    let declared = super::task_network(
        &declared_record,
        &switch,
        boxes::EGRESS_DEFAULT_PHASE,
        false,
    );
    assert!(
        format!("{declared:?}").contains("has_policy: true"),
        "a declared egress section gates the task under the shipped \
         phase too: {declared:?}"
    );
}

/// 017-005. An own-IP task whose attach is refused stops with the
/// provider's error: the process is killed and reaped, and the plan it was
/// built from was the provider's, never the host's.
#[tokio::test]
async fn a_refused_task_attach_stops_the_task() {
    use std::sync::Arc;

    #[derive(Debug)]
    struct Refuses;
    impl sandbox::Network for Refuses {
        fn plan(&self) -> sandbox::PlanFuture<'_> {
            Box::pin(std::future::ready(Ok(sandbox::NetPlan::isolated())))
        }
        fn attach(&self, _: sandbox::Spawned) -> sandbox::AttachFuture<'_> {
            Box::pin(std::future::ready(Err(sandbox::NetworkError::new(
                std::io::Error::other("switch refused the client"),
            ))))
        }
    }

    struct Child {
        reaped: bool,
    }
    impl super::Reapable for Child {
        fn kill_and_reap(&mut self) {
            self.reaped = true;
        }
    }

    let planned = sandbox::PlannedLaunch::begin(Arc::new(Refuses))
        .await
        .expect("planning succeeds; it is the attach that fails");
    assert!(planned.plan().isolates_netns());

    let mut child = Child { reaped: false };
    let err = super::attach_or_reap(planned, sandbox::Spawned::new(1), &mut child)
        .await
        .err()
        .expect("a refused attach must surface as an error");
    assert!(child.reaped, "the task must not run on");
    assert!(
        err.to_string().contains("switch refused the client"),
        "the provider's reason must reach the caller, got: {err}",
    );
}

/// A guard whose teardown blocks until told to finish, then counts.
struct SlowGuard {
    go: std::sync::Arc<tokio::sync::Notify>,
    done: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl sandbox::NetGuard for SlowGuard {
    fn teardown(
        self: Box<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            self.go.notified().await;
            self.done.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
    }
}

/// 017-003 on the task path. `wait` is polled inside a `select!` and can
/// be dropped while the network is being released; the release must still
/// run, once, and the next `wait` must not return before it is done. A
/// process dropped before any `wait` completed releases the same way.
#[tokio::test]
async fn a_dropped_wait_still_releases_the_network_once() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let go = Arc::new(tokio::sync::Notify::new());
    let done = Arc::new(AtomicUsize::new(0));
    let guard = || {
        Box::new(SlowGuard {
            go: go.clone(),
            done: done.clone(),
        })
    };

    // The first `wait` is dropped mid-release, as `select!` does.
    let mut net = super::NetRelease::new(guard());
    let dropped = tokio::time::timeout(std::time::Duration::from_millis(20), net.release())
        .await
        .is_err();
    assert!(dropped, "the release must still be in flight");
    assert_eq!(done.load(Ordering::SeqCst), 0);

    // The next `wait` waits for the same release, which then finishes;
    // a later one has nothing left to do.
    go.notify_one();
    net.release().await;
    net.release().await;
    assert_eq!(done.load(Ordering::SeqCst), 1, "released exactly once");

    // Dropped before any `wait`: `Drop` spawns the release; let it run.
    drop(super::NetRelease::new(guard()));
    go.notify_one();
    tokio::task::yield_now().await;
    assert_eq!(
        done.load(Ordering::SeqCst),
        2,
        "a dropped process still releases"
    );
}

/// Bytes flow client→child stdin and child stdout/stderr→client,
/// and the child's exit code propagates to the bridge's return.
#[tokio::test]
async fn bridge_round_trips_stdio_and_propagates_exit_code() {
    let (
        process,
        MockEndpoints {
            mut stdin_reader,
            mut stdout_writer,
            mut stderr_writer,
            ctrl,
        },
    ) = build_mock();

    let (mut client_stdin, mut bridge_stdin) = duplex(64 * 1024);
    let (mut bridge_stdout, mut client_stdout) = duplex(64 * 1024);
    let (mut bridge_stderr, mut client_stderr) = duplex(64 * 1024);

    let bridge_task = crate::traced::spawn(async move {
        bridge(
            "test",
            process,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost(),
        )
        .await
    });

    client_stdin.write_all(b"hello\n").await.unwrap();
    client_stdin.shutdown().await.unwrap();

    let mut received_stdin = Vec::new();
    stdin_reader.read_to_end(&mut received_stdin).await.unwrap();
    assert_eq!(received_stdin, b"hello\n");

    stdout_writer.write_all(b"out!").await.unwrap();
    stderr_writer.write_all(b"err!").await.unwrap();
    drop(stdout_writer);
    drop(stderr_writer);

    ctrl.signal_exit(42).await;

    let exit = bridge_task.await.unwrap();
    assert_eq!(exit, 42);

    let mut out = Vec::new();
    client_stdout.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"out!");

    let mut err = Vec::new();
    client_stderr.read_to_end(&mut err).await.unwrap();
    assert_eq!(err, b"err!");

    assert!(!ctrl.was_killed());
}

/// A child that stops reading stdin must not stop the bridge from
/// relaying the child's output to the client, nor from delivering the
/// queued stdin once the child reads again. The child's stdin pipe
/// holds 64 KiB; a 256 KiB write to it parks, and with the write
/// parked inside the loop's select the child's stdout would never be
/// polled and this test would time out.
#[tokio::test]
async fn bridge_relays_output_while_a_stdin_write_is_blocked() {
    use std::time::Duration;
    use tokio::time::timeout;

    let (
        process,
        MockEndpoints {
            mut stdin_reader,
            mut stdout_writer,
            stderr_writer: _stderr_writer,
            ctrl,
        },
    ) = build_mock();

    let (mut client_stdin, mut bridge_stdin) = duplex(64 * 1024);
    let (mut bridge_stdout, mut client_stdout) = duplex(64 * 1024);
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);

    let bridge_task = tokio::spawn(async move {
        bridge(
            "test",
            process,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost(),
        )
        .await
    });

    // Far more than the child's stdin pipe holds; this writer blocks
    // once both pipes are full, which is the point.
    let feeder = tokio::spawn(async move {
        let _ = client_stdin.write_all(&vec![b'x'; 256 * 1024]).await;
    });

    // Reads the child's output as the bridge relays it; the final
    // read_exact would hang if any of the payload stalled behind the
    // blocked stdin write.
    let reader = tokio::spawn(async move {
        let mut received = vec![0u8; 256 * 1024];
        client_stdout.read_exact(&mut received).await.unwrap();
        received
    });

    // With a stdin write parked behind a full pipe, output from the
    // child must still reach the client.
    let payload = vec![b'o'; 256 * 1024];
    timeout(Duration::from_secs(10), stdout_writer.write_all(&payload))
        .await
        .expect("child output must keep flowing while a stdin write is blocked")
        .unwrap();

    let out = timeout(Duration::from_secs(10), reader)
        .await
        .expect("the client must receive child output while a stdin write is blocked")
        .unwrap();
    assert_eq!(out, payload);

    // The queued stdin reaches the child as soon as it reads.
    let mut received_stdin = vec![0u8; 256 * 1024];
    timeout(
        Duration::from_secs(10),
        stdin_reader.read_exact(&mut received_stdin),
    )
    .await
    .expect("queued stdin must reach the child once it reads")
    .unwrap();
    assert_eq!(received_stdin, vec![b'x'; 256 * 1024]);
    feeder.await.unwrap();

    // Both output pipes at EOF end the loop; the child then exits.
    drop(stdout_writer);
    ctrl.signal_exit(0).await;

    let exit = timeout(Duration::from_secs(10), bridge_task)
        .await
        .expect("the bridge must end once both output pipes close and the child exits")
        .unwrap();
    assert_eq!(exit, 0);
    assert!(!ctrl.was_killed());
}

/// A real child that writes its output before it reads more input
/// (`cat`) gets several MB streamed through it in both directions at
/// once: every byte comes back in order, and the child sees EOF only
/// after the queued stdin has drained. With the stdin write parked
/// inside the loop's select, `cat` blocks on a full stdout pipe, stops
/// reading stdin, and the bridge never finishes.
#[tokio::test]
async fn bridge_streams_megabytes_through_cat() {
    use std::process::Stdio;
    use std::time::Duration;

    use futures::stream;
    use tokio::time::timeout;

    use super::TokioProcess;

    const LEN: usize = 4 * 1024 * 1024;

    let child = tokio::process::Command::new("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning cat");
    let processes = stream::iter(vec![Ok::<_, std::io::Error>(TokioProcess::new(child))]);

    let (mut client_stdin, mut bridge_stdin) = duplex(64 * 1024);
    let (mut bridge_stdout, mut client_stdout) = duplex(64 * 1024);
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);

    let bridge_task = tokio::spawn(async move {
        bridge(
            "test",
            processes,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost(),
        )
        .await
    });

    let payload: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let sent = payload.clone();
    // Dropping the write half once the payload is in is the client's EOF.
    let feeder = tokio::spawn(async move {
        client_stdin.write_all(&sent).await.unwrap();
    });
    let reader = tokio::spawn(async move {
        let mut received = Vec::with_capacity(LEN);
        client_stdout.read_to_end(&mut received).await.unwrap();
        received
    });

    let exit = timeout(Duration::from_secs(60), bridge_task)
        .await
        .expect("cat must finish while its stdin and stdout stream at once")
        .unwrap();
    assert_eq!(exit, 0);
    feeder.await.unwrap();
    let received = reader.await.unwrap();
    assert_eq!(received.len(), LEN);
    assert!(received == payload, "cat must echo the payload in order");
}

/// A child that exits with stdin still queued behind its full pipe
/// drops the queued bytes and still reports its own exit status.
///
/// Every pipe end stays open until the bridge returns, so the only
/// way out of the loop is the `wait` branch with a chunk still
/// queued: closing the child's stdin first would instead end the
/// parked write with `BrokenPipe` and take the write-failure path.
#[tokio::test]
async fn bridge_reports_exit_when_child_exits_with_stdin_queued() {
    use std::time::Duration;
    use tokio::time::timeout;

    let (
        process,
        MockEndpoints {
            // Not read until the bridge returns: the child's stdin
            // pipe fills and a chunk queues behind it.
            mut stdin_reader,
            stdout_writer,
            stderr_writer,
            ctrl,
        },
    ) = build_mock();

    let (mut client_stdin, mut bridge_stdin) = duplex(64 * 1024);
    let (_unused_stdout_peer, mut bridge_stdout) = duplex(64 * 1024);
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);

    let feeder = tokio::spawn(async move {
        let _ = client_stdin.write_all(&vec![b'x'; 512 * 1024]).await;
    });

    let bridge_task = tokio::spawn(async move {
        bridge(
            "test",
            process,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost(),
        )
        .await
    });

    // Let the bridge fill the child's stdin pipe and queue a chunk.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!bridge_task.is_finished());

    // The child is reaped while every pipe end is still open.
    ctrl.signal_exit(3).await;

    let exit = timeout(Duration::from_secs(10), bridge_task)
        .await
        .expect("a child exiting with stdin queued must end the bridge")
        .unwrap();
    assert_eq!(exit, 3);
    assert!(!ctrl.was_killed());

    // The child's stdin holds exactly what fit in its pipe, then EOF:
    // the queued chunk was dropped, not delivered late.
    let mut delivered = Vec::new();
    timeout(
        Duration::from_secs(10),
        stdin_reader.read_to_end(&mut delivered),
    )
    .await
    .expect("the bridge must close the child's stdin on return")
    .unwrap();
    assert_eq!(delivered.len(), 64 * 1024);

    drop(stdout_writer);
    drop(stderr_writer);
    feeder.abort();
}

/// An exec the daemon's shutdown ends tells the client why on stderr,
/// after whatever the command itself wrote there, and still reports the
/// command's own status. One that ends outside a shutdown gets no notice.
#[tokio::test]
async fn an_exec_ended_by_shutdown_writes_the_notice_to_stderr() {
    for shutting_down in [true, false] {
        let (
            process,
            MockEndpoints {
                stdin_reader: _stdin_reader,
                stdout_writer,
                mut stderr_writer,
                ctrl,
            },
        ) = build_mock();

        let (closed_stdin_w, mut bridge_stdin) = duplex(64);
        drop(closed_stdin_w);
        let (mut bridge_stdout, _client_stdout) = duplex(64 * 1024);
        let (mut bridge_stderr, mut client_stderr) = duplex(64 * 1024);

        let bridge_task = crate::traced::spawn(async move {
            let exit = bridge_noting_shutdown(
                "test",
                process,
                &mut bridge_stdin,
                &mut bridge_stdout,
                &mut bridge_stderr,
                client_lost(),
                || shutting_down,
            )
            .await;
            (exit, bridge_stderr)
        });

        stderr_writer.write_all(b"err!").await.unwrap();
        drop(stderr_writer);
        drop(stdout_writer);
        // What a box killed by the shutdown reports: 128 + SIGKILL.
        ctrl.signal_exit(137).await;

        let (exit, bridge_stderr) = bridge_task.await.unwrap();
        assert_eq!(exit, 137, "the command's own status passes through");
        drop(bridge_stderr);

        let mut err = Vec::new();
        client_stderr.read_to_end(&mut err).await.unwrap();
        let expected: &[u8] = if shutting_down {
            b"err!minimald is shutting down; the command was stopped\n"
        } else {
            b"err!"
        };
        assert_eq!(
            err,
            expected,
            "shutting down: {shutting_down}; stderr was {:?}",
            String::from_utf8_lossy(&err),
        );
    }
}

/// When the SSH-channel write side fails, the bridge must call
/// `start_kill` so the child unblocks and `wait` resolves —
/// otherwise the loop would hang waiting on the now-dead channel.
#[tokio::test]
async fn bridge_kills_child_when_ssh_write_fails() {
    let (
        process,
        MockEndpoints {
            stdin_reader: _stdin_reader,
            mut stdout_writer,
            stderr_writer,
            ctrl,
        },
    ) = build_mock();
    // Model a process with nothing on stderr — bridge sees EOF on
    // child_stderr immediately and never writes to bridge_stderr.
    drop(stderr_writer);

    // SSH-side stdout reader dropped, so every bridge write to
    // bridge_stdout errors with BrokenPipe.
    let (broken_reader, mut bridge_stdout) = duplex(64);
    drop(broken_reader);

    // bridge_stderr exists only because the signature requires it;
    // the bridge will never touch it in this test.
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64);

    // SSH stdin closed: bridge sees EOF immediately.
    let (closed_stdin_w, mut bridge_stdin) = duplex(64);
    drop(closed_stdin_w);

    let bridge_task = crate::traced::spawn(async move {
        bridge(
            "test",
            process,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost(),
        )
        .await
    });

    stdout_writer.write_all(b"output").await.unwrap();
    drop(stdout_writer);

    let exit = bridge_task.await.unwrap();
    // A killed mock returns Ok(None) from wait, which the bridge
    // maps to exit status 1.
    assert_eq!(exit, 1);
    assert!(ctrl.was_killed());
}

/// NET-015: a lost client on a non-PTY exec ends the command that exec
/// spawned — and only it. The lost client is the SSH write side failing
/// (the channel's peer is gone): the bridge kills the child it was
/// driving, reports the kill as exit 1, and stops the sequence without
/// ever pulling the next process, so nothing beyond the exec's own
/// command was touched. The box the exec ran against is the session
/// plane's concern (`box_actor::tests` proves it survives the same loss).
#[tokio::test]
async fn lost_exec_client_kills_only_its_own_process() {
    use std::time::Duration;
    use tokio::time::timeout;

    let (iter, mut endpoints) = build_mock_seq(2);
    let second = endpoints.pop().unwrap();
    let MockEndpoints {
        stdin_reader: _stdin_reader,
        stdout_writer: mut first_stdout,
        stderr_writer: first_stderr,
        ctrl: first_ctrl,
    } = endpoints.pop().unwrap();
    // Nothing on stderr; its EOF is the ordinary case.
    drop(first_stderr);

    // The client hung up: writes to its stdout side fail at once.
    let (lost_client, mut bridge_stdout) = duplex(64);
    drop(lost_client);
    // bridge_stderr exists only because the signature requires it; the
    // bridge never touches it in this test.
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64);
    // The client's stdin went with it: EOF.
    let (closed_stdin_w, mut bridge_stdin) = duplex(64);
    drop(closed_stdin_w);

    let bridge_task = crate::traced::spawn(async move {
        bridge(
            "test",
            iter,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost(),
        )
        .await
    });

    // The child prints; forwarding it to the dead channel is the write
    // that models the lost client.
    first_stdout.write_all(b"output").await.unwrap();
    drop(first_stdout);

    let exit = timeout(Duration::from_secs(10), bridge_task)
        .await
        .expect("a lost client must end the exec promptly, not hang the bridge")
        .unwrap();
    // A killed mock waits back Ok(None), which the bridge maps to 1.
    assert_eq!(exit, 1);
    assert!(
        first_ctrl.was_killed(),
        "the exec's own command must be killed when its client is lost"
    );
    assert!(
        !second.ctrl.was_killed(),
        "nothing beyond the exec's own command was spawned, let alone killed"
    );
}

/// gominimal/inbox#813: a lost client on the *read* side — the SSH
/// channel closes or its sender drops while the child is silent —
/// must still kill the child. `make_reader()` used to reduce the
/// read half to a bare `AsyncRead`, which only surfaces `Data` and
/// `Eof`; a lost client then looked like stdin EOF and a silent
/// child (sleep, quiet build) kept running indefinitely. The
/// client-loss watch signal must end the bridge and kill the child
/// even though the child never writes a byte.
#[tokio::test]
async fn bridge_kills_silent_child_when_client_disconnects() {
    use std::time::Duration;
    use tokio::time::timeout;

    let (
        process,
        MockEndpoints {
            stdin_reader: _stdin_reader,
            // Held, never written: a silent child keeps its stdio
            // open. Dropping them would let output EOF end the loop
            // before the client-loss branch wins the `select!`.
            stdout_writer: _stdout_writer,
            stderr_writer: _stderr_writer,
            ctrl,
        },
    ) = build_mock();
    // A silent child: nothing on stdout or stderr, and it never
    // exits on its own.

    // SSH stdin closed: bridge sees EOF immediately.
    let (closed_stdin_w, mut bridge_stdin) = duplex(64);
    drop(closed_stdin_w);
    let (_unused_stdout_peer, mut bridge_stdout) = duplex(64 * 1024);
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);

    // The client-loss signal fires: the SSH channel closed.
    let (client_lost_tx, client_lost_rx) = tokio::sync::watch::channel(false);

    let bridge_task = crate::traced::spawn(async move {
        bridge(
            "test",
            process,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost_rx,
        )
        .await
    });

    client_lost_tx.send(true).unwrap();

    let exit = timeout(Duration::from_secs(10), bridge_task)
        .await
        .expect("a lost client must kill a silent child promptly, not hang the bridge")
        .unwrap();
    // A killed mock waits back Ok(None), which the bridge maps to 1.
    assert_eq!(exit, 1);
    assert!(
        ctrl.was_killed(),
        "a silent child must be killed when its client disconnects"
    );
}

/// gominimal/inbox#813: stdin EOF alone — the client closing its
/// input but keeping the channel open — must NOT kill a silent
/// child. EOF is a normal close, not a disconnect; the child keeps
/// running and the bridge returns the child's own exit code.
#[tokio::test]
async fn bridge_does_not_kill_silent_child_on_stdin_eof() {
    use std::time::Duration;
    use tokio::time::timeout;

    let (
        process,
        MockEndpoints {
            stdin_reader: _stdin_reader,
            stdout_writer,
            stderr_writer,
            ctrl,
        },
    ) = build_mock();
    // A silent child: nothing on stdout or stderr.
    drop(stdout_writer);
    drop(stderr_writer);

    // SSH stdin closed: bridge sees EOF immediately.
    let (closed_stdin_w, mut bridge_stdin) = duplex(64);
    drop(closed_stdin_w);
    let (_unused_stdout_peer, mut bridge_stdout) = duplex(64 * 1024);
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);

    // The client-loss signal never fires: the channel stays open.
    let (_client_lost_tx, client_lost_rx) = tokio::sync::watch::channel(false);

    let bridge_task = crate::traced::spawn(async move {
        bridge(
            "test",
            process,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost_rx,
        )
        .await
    });

    // The child exits cleanly on its own; the bridge must return its
    // code without killing it.
    ctrl.signal_exit(7).await;

    let exit = timeout(Duration::from_secs(10), bridge_task)
        .await
        .expect("stdin EOF alone must not hang the bridge")
        .unwrap();
    assert_eq!(exit, 7);
    assert!(
        !ctrl.was_killed(),
        "stdin EOF is a normal close, not a disconnect; the child must not be killed"
    );
}

/// A child that never reads stdin leaves the bridge parked writing
/// into a full stdin pipe. A disconnect arriving then must still
/// kill the child rather than wait on a write that never completes.
#[tokio::test]
async fn bridge_kills_child_blocked_on_stdin_when_client_disconnects() {
    use std::time::Duration;
    use tokio::time::timeout;

    let (
        process,
        MockEndpoints {
            // Held but never read: the child's stdin pipe fills.
            stdin_reader: _stdin_reader,
            stdout_writer: _stdout_writer,
            stderr_writer: _stderr_writer,
            ctrl,
        },
    ) = build_mock();

    let (mut client_stdin, mut bridge_stdin) = duplex(64 * 1024);
    let (_unused_stdout_peer, mut bridge_stdout) = duplex(64 * 1024);
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);
    let (client_lost_tx, client_lost_rx) = tokio::sync::watch::channel(false);

    // Far more than the child's stdin pipe holds; this writer blocks
    // once both pipes are full, which is the point.
    let feeder = crate::traced::spawn(async move {
        let _ = client_stdin.write_all(&vec![b'x'; 512 * 1024]).await;
    });

    let bridge_task = crate::traced::spawn(async move {
        bridge(
            "test",
            process,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost_rx,
        )
        .await
    });

    // Let the bridge fill the child's stdin pipe and park on it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!bridge_task.is_finished());

    client_lost_tx.send(true).unwrap();

    let exit = timeout(Duration::from_secs(10), bridge_task)
        .await
        .expect("a lost client must interrupt a blocked stdin write")
        .unwrap();
    assert_eq!(exit, 1);
    assert!(ctrl.was_killed());
    feeder.abort();
}

/// A child that closes stdout and stderr but keeps running ends the
/// I/O loop with the child still alive. A disconnect arriving while
/// the bridge waits on it must still kill the child; if it did not,
/// this test times out, since nothing else ever ends the child.
#[tokio::test]
async fn bridge_kills_child_with_closed_output_when_client_disconnects() {
    use std::time::Duration;
    use tokio::time::timeout;

    let (
        process,
        MockEndpoints {
            stdin_reader: _stdin_reader,
            stdout_writer,
            stderr_writer,
            ctrl,
        },
    ) = build_mock();
    // Output closed, but the child never exits on its own.
    drop(stdout_writer);
    drop(stderr_writer);

    let (closed_stdin_w, mut bridge_stdin) = duplex(64);
    drop(closed_stdin_w);
    let (_unused_stdout_peer, mut bridge_stdout) = duplex(64 * 1024);
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);
    let (client_lost_tx, client_lost_rx) = tokio::sync::watch::channel(false);

    let bridge_task = crate::traced::spawn(async move {
        bridge(
            "test",
            process,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost_rx,
        )
        .await
    });

    // Let the loop see both EOFs and park on the final wait.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!bridge_task.is_finished());

    client_lost_tx.send(true).unwrap();

    let exit = timeout(Duration::from_secs(10), bridge_task)
        .await
        .expect("a lost client must kill a child whose output is already closed")
        .unwrap();
    assert_eq!(exit, 1);
    assert!(ctrl.was_killed());
}

/// `min task run` from a terminal half-closes stdin before anything
/// else, so a disconnect arrives *after* EOF. The pump must close the
/// child's stdin on EOF yet keep watching, and still signal client
/// loss when the channel then closes.
#[tokio::test]
async fn pump_signals_client_loss_after_stdin_eof() {
    use std::time::Duration;
    use tokio::time::timeout;

    let (msg_tx, msg_rx) = tokio::sync::mpsc::unbounded_channel();
    let msgs = Box::pin(futures::stream::unfold(msg_rx, |mut rx| async move {
        rx.recv().await.map(|m| (m, rx))
    }));
    let (stdin_w, mut stdin_r) = duplex(64);
    let (lost_tx, mut lost_rx) = tokio::sync::watch::channel(false);
    let pump = crate::traced::spawn(super::pump_channel_input(msgs, stdin_w, lost_tx));

    msg_tx
        .send(russh::ChannelMsg::Data {
            data: b"hi".as_slice().into(),
        })
        .unwrap();
    msg_tx.send(russh::ChannelMsg::Eof).unwrap();

    let mut got = Vec::new();
    timeout(Duration::from_secs(10), stdin_r.read_to_end(&mut got))
        .await
        .expect("stdin EOF must close the child's stdin")
        .unwrap();
    assert_eq!(got, b"hi");
    assert!(!*lost_rx.borrow(), "stdin EOF is not a disconnect");
    assert!(!pump.is_finished(), "the pump must outlive stdin EOF");

    msg_tx.send(russh::ChannelMsg::Close).unwrap();
    timeout(Duration::from_secs(10), lost_rx.changed())
        .await
        .expect("a close after EOF must still signal client loss")
        .unwrap();
    assert!(*lost_rx.borrow());
    pump.await.unwrap();
}

/// The channel's sender dropping (the connection died without a
/// `Close`) ends the message stream; that is a disconnect too.
#[tokio::test]
async fn pump_signals_client_loss_when_channel_sender_drops() {
    use std::time::Duration;
    use tokio::time::timeout;

    let (msg_tx, msg_rx) = tokio::sync::mpsc::unbounded_channel::<russh::ChannelMsg>();
    let msgs = Box::pin(futures::stream::unfold(msg_rx, |mut rx| async move {
        rx.recv().await.map(|m| (m, rx))
    }));
    let (stdin_w, _stdin_r) = duplex(64);
    let (lost_tx, mut lost_rx) = tokio::sync::watch::channel(false);
    let pump = crate::traced::spawn(super::pump_channel_input(msgs, stdin_w, lost_tx));

    drop(msg_tx);
    timeout(Duration::from_secs(10), lost_rx.changed())
        .await
        .expect("a dropped channel must signal client loss")
        .unwrap();
    assert!(*lost_rx.borrow());
    pump.await.unwrap();
}

/// A grandchild that inherited the child's stdout keeps the pipe
/// open past the child's own exit — `sh -c 'sleep 20 & echo
/// STARTED'`. The bridge must return on the *child's* exit, relay
/// what the child wrote before exiting, and keep reading the orphan's
/// pipe rather than dropping it (gominimal/inbox#566).
///
/// Every other test here drops the stdout writer *before* signalling
/// exit, which is why none of them caught this: holding it is the
/// whole point.
#[tokio::test]
async fn bridge_returns_on_child_exit_with_stdout_still_held_open() {
    use std::time::Duration;
    use tokio::time::timeout;

    let (
        process,
        MockEndpoints {
            stdin_reader: _stdin_reader,
            mut stdout_writer,
            stderr_writer,
            ctrl,
        },
    ) = build_mock();
    // Only stdout models the inherited fd; stderr EOFs as usual.
    drop(stderr_writer);

    // SSH stdin closed: bridge sees EOF immediately.
    let (closed_stdin_w, mut bridge_stdin) = duplex(64);
    drop(closed_stdin_w);
    let (mut client_stdout, mut bridge_stdout) = duplex(1024 * 1024);
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);

    let bridge_task = crate::traced::spawn(async move {
        bridge(
            "test",
            process,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost(),
        )
        .await
    });

    // What the child printed before exiting, then the exit — with
    // the writer still held, standing in for the backgrounded
    // grandchild's copy of the fd.
    stdout_writer.write_all(b"STARTED\n").await.unwrap();
    ctrl.signal_exit(0).await;

    let exit = timeout(Duration::from_secs(10), bridge_task)
        .await
        .expect("bridge must return on child exit, not wait out the orphan")
        .unwrap();
    assert_eq!(exit, 0);
    assert!(!ctrl.was_killed());

    // The orphan lives on. Its next write must not hit a closed read
    // end — that is EPIPE, and SIGPIPE kills a real process — and
    // more than a pipeful must still move, proving something is
    // actually draining rather than merely holding the fd.
    let orphan_output = vec![b'x'; 256 * 1024];
    timeout(
        Duration::from_secs(10),
        stdout_writer.write_all(&orphan_output),
    )
    .await
    .expect("the daemon must keep draining the orphan's pipe, not stall on a full one")
    .expect("dropping the read end would break the orphan's pipe (EPIPE/SIGPIPE)");

    // Pre-exit output is still relayed in full; post-exit output is
    // discarded, so the client sees exactly the former.
    drop(stdout_writer);
    let mut out = Vec::new();
    client_stdout.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"STARTED\n");
}

/// A two-process sequence: the first child exits non-zero, so the
/// bridge must stop and report that code without ever pulling the
/// second process from the iter. If it tried to drive process 2,
/// `bridge_task.await` would hang (proc 2's ctrl is never signalled)
/// and the test would time out.
#[tokio::test]
async fn bridge_stops_sequence_on_first_non_zero_exit() {
    let (iter, mut endpoints) = build_mock_seq(2);
    let second = endpoints.pop().unwrap();
    let MockEndpoints {
        stdin_reader: _stdin_reader,
        stdout_writer: mut first_stdout,
        stderr_writer: mut first_stderr,
        ctrl: first_ctrl,
    } = endpoints.pop().unwrap();

    let (closed_stdin_w, mut bridge_stdin) = duplex(64);
    drop(closed_stdin_w);
    let (_unused_stdout_peer, mut bridge_stdout) = duplex(64 * 1024);
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);

    let bridge_task = crate::traced::spawn(async move {
        bridge(
            "test",
            iter,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost(),
        )
        .await
    });

    // Drive the first child to exit non-zero. Closing the writers
    // gives the bridge EOF on both child stdout and stderr.
    first_stdout.write_all(b"first").await.unwrap();
    first_stderr.write_all(b"oops").await.unwrap();
    drop(first_stdout);
    drop(first_stderr);
    first_ctrl.signal_exit(5).await;

    let exit = bridge_task.await.unwrap();
    assert_eq!(exit, 5);
    // The second process was never spawned, so its kill flag should
    // still be unset.
    assert!(!second.ctrl.was_killed());
}

/// A disconnect consumed by the first step must still stop the
/// sequence when that child reports exit 0 (it exited just before
/// the kill landed, or ignores kill like `EchoProcess`). The watch
/// transition is already spent, so a second, silent child would
/// never see it: the bridge must not start it. If it did, this test
/// times out, since nothing ever ends the second child.
#[tokio::test]
async fn bridge_stops_sequence_on_client_loss_after_zero_exit() {
    use std::time::Duration;
    use tokio::time::timeout;

    let (iter, mut endpoints) = build_mock_seq(2);
    // Silent and never exiting: stdio held open, ctrl never signalled.
    let second = endpoints.pop().unwrap();
    let MockEndpoints {
        stdin_reader: _stdin_reader,
        stdout_writer: first_stdout,
        stderr_writer: first_stderr,
        ctrl: first_ctrl,
    } = endpoints.pop().unwrap();
    drop(first_stdout);
    drop(first_stderr);
    first_ctrl.signal_exit(0).await;

    let (closed_stdin_w, mut bridge_stdin) = duplex(64);
    drop(closed_stdin_w);
    let (_unused_stdout_peer, mut bridge_stdout) = duplex(64 * 1024);
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);

    // The client is gone and the transition is already observed, as
    // the first step's `changed()` branch would have left it.
    let (client_lost_tx, mut client_lost_rx) = tokio::sync::watch::channel(false);
    client_lost_tx.send(true).unwrap();
    client_lost_rx.borrow_and_update();

    let bridge_task = crate::traced::spawn(async move {
        bridge(
            "test",
            iter,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost_rx,
        )
        .await
    });

    timeout(Duration::from_secs(10), bridge_task)
        .await
        .expect("a lost client must end the sequence, not start the next child")
        .unwrap();
    assert!(
        !second.ctrl.was_killed(),
        "the second child must never be started"
    );
    drop(client_lost_tx);
}

/// A two-process sequence where both children exit cleanly: the
/// bridge runs them back-to-back, concatenates their stdout to the
/// SSH channel, and returns the second's exit code.
#[tokio::test]
async fn bridge_runs_sequence_to_completion_and_concatenates_stdout() {
    let (iter, mut endpoints) = build_mock_seq(2);
    let MockEndpoints {
        stdin_reader: _r2,
        stdout_writer: mut second_stdout,
        stderr_writer: second_stderr,
        ctrl: second_ctrl,
    } = endpoints.pop().unwrap();
    let MockEndpoints {
        stdin_reader: _r1,
        stdout_writer: mut first_stdout,
        stderr_writer: first_stderr,
        ctrl: first_ctrl,
    } = endpoints.pop().unwrap();
    drop(first_stderr);
    drop(second_stderr);

    let (closed_stdin_w, mut bridge_stdin) = duplex(64);
    drop(closed_stdin_w);
    let (mut client_stdout, mut bridge_stdout) = duplex(64 * 1024);
    let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);

    let bridge_task = crate::traced::spawn(async move {
        bridge(
            "test",
            iter,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost(),
        )
        .await
    });

    first_stdout.write_all(b"AAA").await.unwrap();
    drop(first_stdout);
    first_ctrl.signal_exit(0).await;

    second_stdout.write_all(b"BBB").await.unwrap();
    drop(second_stdout);
    second_ctrl.signal_exit(0).await;

    let exit = bridge_task.await.unwrap();
    assert_eq!(exit, 0);

    let mut out = Vec::new();
    client_stdout.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"AAABBB");
}

/// An `EchoProcess` drives through the bridge as a zero-cost stand-in
/// for a spawned child: its text (plus a trailing newline, matching
/// `/bin/echo`) reaches the SSH stdout stream, stderr stays empty, and
/// it reports exit 0 — no sandbox involved.
#[tokio::test]
async fn echo_process_writes_text_and_exits_zero() {
    use futures::stream::{self, StreamExt};

    use super::{EchoProcess, TaskProcess};

    let echo = TaskProcess::Echo(EchoProcess::new("MINIMALD_SESSION_OK"));
    let mut echo_stream = stream::iter(vec![Ok(echo)]).boxed();

    // SSH stdin closed: bridge sees EOF immediately.
    let (closed_stdin_w, mut bridge_stdin) = duplex(64);
    drop(closed_stdin_w);
    let (mut client_stdout, mut bridge_stdout) = duplex(64 * 1024);
    let (mut client_stderr, mut bridge_stderr) = duplex(64 * 1024);

    let bridge_task = crate::traced::spawn(async move {
        bridge(
            "test",
            &mut echo_stream,
            &mut bridge_stdin,
            &mut bridge_stdout,
            &mut bridge_stderr,
            client_lost(),
        )
        .await
    });

    let exit = bridge_task.await.unwrap();
    assert_eq!(exit, 0);

    let mut out = Vec::new();
    client_stdout.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"MINIMALD_SESSION_OK\n");

    let mut err = Vec::new();
    client_stderr.read_to_end(&mut err).await.unwrap();
    assert!(err.is_empty(), "echo should produce no stderr: {err:?}");
}

mod end_to_end {
    //! Tests that exercise the full ssh-exec stack against a real
    //! `TestServer`: russh transport, `ConnectionHandler` dispatch,
    //! and `handle_exec` request routing.
    use boxes::SessionId;

    use minimald_rpc::exec::ExecRequest;

    use crate::MINIMAL_SESSION_ID_ENV;
    use crate::test_harness::{
        TestClient, TestServer, create_configured_session, create_session_req,
    };

    /// Creates a fresh session through the public CreateSession RPC
    /// and returns its id, mirroring how a real client sets up state
    /// before running commands against the session.
    async fn fresh_session(client: &mut TestClient) -> SessionId {
        create_configured_session(client, "exec-test", "/tmp").await
    }

    /// A path in the daemon's own filesystem that a command would create if
    /// it ran there. Unique per call so parallel tests cannot collide.
    fn daemon_marker(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "minimald-exec-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ))
    }

    /// An exec request the daemon does not service itself is handed to the
    /// session's sandbox — and must never run on the daemon's own
    /// filesystem.
    ///
    /// The marker file is what pins that: had the command run here, it
    /// would exist. This harness launches a mock host with no sandbox to
    /// join, so the command fails rather than running in-session; where it
    /// was *sent* is the part that matters and the part that can be proved
    /// without a real sandbox.
    #[tokio::test]
    async fn an_unrecognised_command_never_runs_on_the_daemon() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;
        let session_str = session_id.to_string();
        let marker = daemon_marker("arbitrary");
        let _ = std::fs::remove_file(&marker);

        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &format!("printf pwned > {}", marker.display()),
                &[],
            )
            .await
            .expect("the request is serviced over the channel, not a channel failure");

        assert!(
            !marker.exists(),
            "an exec request ran on the daemon's filesystem, creating {}",
            marker.display(),
        );
        assert_ne!(
            out.exit_status,
            Some(0),
            "the mock harness has no sandbox to run in, so this cannot succeed; stdout was {:?}",
            String::from_utf8_lossy(&out.stdout),
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("unsupported command"),
            "the command should be routed to the session, not refused, got {stderr:?}",
        );
    }

    /// Brings a session to `Active` with a task-only `minimal.toml` in
    /// its workspace: the create → populate → configure → finalize
    /// sequence a task run's client drives, shared by every test here
    /// that execs a task.
    ///
    /// The mfile holds only echo tasks — `tasks.echo_ok`, plus
    /// `tasks.greet`, which declares one defaulted arg — whose entire
    /// output lives in their declarations: no `[upstream]`, package
    /// graph, or sandbox:
    /// the echo short-circuit never builds a graph, so nothing here
    /// reaches the (network-bound) package machinery. A task-only mfile
    /// gates nothing, so the loadout composes in one shot, and this
    /// composition has no patches, so `FinalizeSession` takes the
    /// empty-composition shortcut past the marker check and promotes
    /// the record to `Active` in one call.
    async fn active_session_with_echo_task(
        server: &TestServer,
        client: &mut TestClient,
        name: &str,
    ) -> SessionId {
        use minimald_rpc::{
            ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, FinalizeSession,
            FinalizeSessionRequest,
        };

        let session_id = client
            .call::<CreateSession>(&create_session_req(name, "/tmp"))
            .await
            .unwrap()
            .id;

        // Drop a task-only `minimal.toml` into the session workspace,
        // standing in for the e2e test's SFTP upload.
        server
            .seed_workspace_mfile(
                session_id,
                "[tasks.echo_ok]\necho = \"MINIMALD_SESSION_OK\"\n\n\
                 [tasks.greet]\n\
                 args.name = { type = \"string\", default = \"world\" }\n\
                 echo = \"hi %{name}\"\n",
            )
            .await;

        crate::test_harness::unwrap_ready(
            client
                .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                    session_id,
                    contribution: Default::default(),
                })
                .await
                .unwrap(),
        );

        match client
            .call::<FinalizeSession>(&FinalizeSessionRequest {
                session_id,
                report_shared_port_collisions: false,
            })
            .await
        {
            minimald_rpc::Errorable::Ok(_) => {}
            minimald_rpc::Errorable::Err { error } => {
                panic!("FinalizeSession failed: {error}");
            }
        }

        session_id
    }

    /// End-to-end happy path for `min run <task>`: an `echo` task is
    /// serviced straight from the workspace `minimal.toml` — no
    /// package graph, upstream, or sandbox — and its text (plus a
    /// trailing newline) round-trips over the channel with exit 0.
    ///
    /// Drives the client's real ordering — create, populate the
    /// workspace, *then* configure the loadout against it — which is the
    /// sequence `minvmd`'s libkrun e2e test runs over the bridge. Keeping
    /// it in-process here means a break in that sequence (e.g. execing a
    /// session whose loadout was never configured, which has no context
    /// to resolve a task against) surfaces without needing a VM.
    #[tokio::test]
    async fn exec_runs_echo_task() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = active_session_with_echo_task(&server, &mut client, "exec-test").await;
        let session_str = session_id.to_string();

        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &ExecRequest::TaskRun {
                    task: "echo_ok".to_string(),
                    owns_box: false,
                    args: vec![],
                    cwd: String::new(),
                }
                .encode(),
                &[],
            )
            .await
            .expect("a task/run request should be accepted");

        assert_eq!(out.stdout, b"MINIMALD_SESSION_OK\n");
        assert_eq!(out.exit_status, Some(0));
        assert!(
            out.stderr.is_empty(),
            "echo task should produce no stderr: {:?}",
            out.stderr,
        );
    }

    /// A task run's args reach the task: the daemon parses the argv off
    /// the wire against the task's declared `args`, so `%{name}` binds
    /// to the default when none is given, to the value when one is, and
    /// an undeclared flag fails the run rather than being dropped.
    #[tokio::test]
    async fn exec_binds_task_args_and_defaults() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = active_session_with_echo_task(&server, &mut client, "args-test").await;
        let session_str = session_id.to_string();

        let run = |args: Vec<String>| {
            ExecRequest::TaskRun {
                task: "greet".to_string(),
                owns_box: false,
                args,
                cwd: String::new(),
            }
            .encode()
        };

        // No args: the declared default applies.
        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &run(vec![]),
                &[],
            )
            .await
            .expect("a task/run request should be accepted");
        assert_eq!(out.stdout, b"hi world\n");
        assert_eq!(out.exit_status, Some(0));

        // An explicit value overrides the default.
        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &run(vec!["--name".into(), "Alice".into()]),
                &[],
            )
            .await
            .expect("a task/run request should be accepted");
        assert_eq!(out.stdout, b"hi Alice\n");
        assert_eq!(out.exit_status, Some(0));

        // An undeclared flag fails the run instead of being ignored.
        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &run(vec!["--nope".into(), "x".into()]),
                &[],
            )
            .await
            .expect("a task/run request should be accepted");
        assert!(out.stdout.is_empty(), "stdout: {:?}", out.stdout);
        assert_ne!(out.exit_status, Some(0));
    }

    /// NET-131: a box created for a run ends when the run's command
    /// exits, whether or not the client that started it is still here.
    /// The request carries the owns-box flag; the daemon destroys the
    /// session after the exit status is on the wire — the destroy the
    /// client used to issue after a normal run, moved here so a client
    /// killed mid-run strands nothing.
    ///
    /// The destroy runs after the channel closes, so this client's exec
    /// can return before the box is gone: the end is polled for, not
    /// raced on. The info line the run's end emits is asserted too — it
    /// is what a diagnostic bundle's daemon-log tail reads the end of a
    /// run box from.
    #[tokio::test]
    async fn run_box_ends_when_its_run_ends() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let capture = crate::test_harness::captured_log();

        let session_id = active_session_with_echo_task(&server, &mut client, "run-box-ends").await;
        let session_str = session_id.to_string();

        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &ExecRequest::TaskRun {
                    task: "echo_ok".to_string(),
                    owns_box: true,
                    args: vec![],
                    cwd: String::new(),
                }
                .encode(),
                &[],
            )
            .await
            .expect("a task/run request should be accepted");
        assert_eq!(out.exit_status, Some(0));
        assert_eq!(out.stdout, b"MINIMALD_SESSION_OK\n");

        // The box ends after the channel closes; poll until the listing
        // is empty rather than racing the destroy.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let listed = client.call::<minimald_rpc::ListSessions>(&()).await;
            if listed.sessions.is_empty() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the run's box must end once its task exits, but {} session(s) are still \
                 listed: {:?}",
                listed.sessions.len(),
                listed.sessions,
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // The one info line the run's end emits, naming the session, the
        // exec and the exit code.
        let logged = capture.contents();
        assert!(
            logged.contains("run box ended"),
            "expected the run-box-end info line, got: {logged}"
        );
        assert!(logged.contains(&session_str), "names the session: {logged}");
        assert!(logged.contains("echo_ok"), "names the exec: {logged}");
        assert!(logged.contains("exit=0"), "names the exit code: {logged}");
    }

    /// A task run that does not own its box leaves the session standing:
    /// the daemon ends only what the run owns, and the unflagged
    /// spelling — what `min session run` sends, and what every client
    /// from before the flag sent — keeps the box for whoever holds it.
    /// After the exec has returned, and the moment a stray destroy would
    /// have needed, the session is still listed.
    #[tokio::test]
    async fn run_box_survives_when_run_keeps_it() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = active_session_with_echo_task(&server, &mut client, "run-box-kept").await;
        let session_str = session_id.to_string();

        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &ExecRequest::TaskRun {
                    task: "echo_ok".to_string(),
                    owns_box: false,
                    args: vec![],
                    cwd: String::new(),
                }
                .encode(),
                &[],
            )
            .await
            .expect("a task/run request should be accepted");
        assert_eq!(out.exit_status, Some(0));
        assert_eq!(out.stdout, b"MINIMALD_SESSION_OK\n");

        // The exec is over; the box is not. Give the moment a stray
        // destroy would have needed before asserting.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let listed = client.call::<minimald_rpc::ListSessions>(&()).await;
        assert_eq!(
            listed.sessions.iter().map(|s| s.id).collect::<Vec<_>>(),
            vec![session_id],
            "a run that keeps its box must not end it; got {:?}",
            listed.sessions,
        );
    }

    /// `min task run <task>` is the canonical spelling of the legacy
    /// `min run <task>` and must be accepted by the exec channel; a
    /// prefix-matched `min task runx` must still be refused. Acceptance
    /// (vs `channel_failure`) is settled purely by argv parsing before any
    /// process spawns, so an unpopulated task name is enough to exercise
    /// the dispatch arm.
    #[tokio::test]
    async fn exec_accepts_task_run_canonical_form() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;
        let session_str = session_id.to_string();

        let accepted = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &ExecRequest::TaskRun {
                    task: "some_task".to_string(),
                    owns_box: false,
                    args: vec![],
                    cwd: String::new(),
                }
                .encode(),
                &[],
            )
            .await;
        assert!(
            accepted.is_ok(),
            "a task/run request naming a task must be accepted, got {accepted:?}",
        );

        // A task/run naming no task is refused before anything spawns, and
        // there is nothing useful to stream, so it is a channel failure.
        let empty = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &ExecRequest::TaskRun {
                    task: String::new(),
                    owns_box: false,
                    args: vec![],
                    cwd: String::new(),
                }
                .encode(),
                &[],
            )
            .await;
        assert!(
            empty.is_err(),
            "a task/run naming no task must be refused, got {empty:?}",
        );

        // A near-miss tag is a form this daemon does not serve. It is not
        // silently downgraded to a session shell command: the scheme was
        // named, so the client asked for something specific.
        let unknown = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                "min://task/runx some_task",
                &[],
            )
            .await
            .expect("an unknown form is reported over the channel, not a channel failure");
        assert_ne!(unknown.exit_status, Some(0));
        assert!(
            String::from_utf8_lossy(&unknown.stderr).contains("min://task/runx"),
            "the refusal should name the form asked for, got {:?}",
            String::from_utf8_lossy(&unknown.stderr),
        );
    }

    /// End-to-end happy path for `min check`: the exec is accepted,
    /// routed to a check side-op, and the run reports a terminal outcome
    /// with an exit status. This workspace holds no `packages/`,
    /// `profiles/`, or `stacks/` dirs, so there is nothing to lint and
    /// the run completes clean — what's under test is the routing and the
    /// exit-status contract a scripted `min check` depends on.
    #[tokio::test]
    async fn exec_runs_check_and_exits_zero_when_nothing_fails() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;
        let session_str = session_id.to_string();
        // `start_check` builds a fresh workspace-rooted context per call,
        // so the workspace needs an mfile for it to resolve at all.
        server.seed_workspace_mfile(session_id, "").await;

        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &ExecRequest::Check(String::new()).encode(),
                &[],
            )
            .await
            .expect("a check request should be accepted");

        assert_eq!(out.exit_status, Some(0));
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "check finished",
        );
        assert!(
            out.stderr.is_empty(),
            "a clean check should produce no stderr: {:?}",
            out.stderr,
        );
    }

    /// A mistyped flag must exit non-zero. Parsed as a name filter it
    /// would match nothing, so the run would check zero objects and report
    /// success — and the exit status is the whole contract for a scripted
    /// `min check` over SSH.
    #[tokio::test]
    async fn exec_check_rejects_a_typod_flag_rather_than_passing() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;
        let session_str = session_id.to_string();
        server.seed_workspace_mfile(session_id, "").await;

        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &ExecRequest::Check("--packags".to_string()).encode(),
                &[],
            )
            .await
            .expect("the exec itself is accepted; the flag fails the run");

        assert_eq!(
            out.exit_status,
            Some(1),
            "a typo'd flag must not exit 0; stdout was {:?}",
            String::from_utf8_lossy(&out.stdout),
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("unknown flag `--packags`"),
            "the bad flag should be named on stderr, got {:?}",
            String::from_utf8_lossy(&out.stderr),
        );
    }

    /// A command that merely *looks* like one of the daemon's own belongs
    /// to the session, and reaches it.
    ///
    /// This is the contract that replaced prefix-sniffing: the daemon used
    /// to claim every command starting with `min ` and refuse the ones it
    /// did not recognise, which made a session's own `min` binary
    /// unreachable through exec (gominimal/inbox#558). Now only the
    /// `min://` scheme addresses the daemon, so `min checkx` is just a
    /// command — routed to the session, and never run on the daemon's own
    /// filesystem.
    ///
    /// The marker file pins the second half: had it run here, it would
    /// exist. This harness launches a mock host with no sandbox to join, so
    /// the command fails rather than running in-session; where it was
    /// *sent* is what matters and what can be proved without a real sandbox.
    #[tokio::test]
    async fn a_min_lookalike_goes_to_the_session_not_the_daemon() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;
        let session_str = session_id.to_string();
        let marker = daemon_marker("checkx");
        let _ = std::fs::remove_file(&marker);

        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &format!("min checkx > {}", marker.display()),
                &[],
            )
            .await
            .expect("the request is serviced over the channel, not a channel failure");

        assert!(
            !marker.exists(),
            "`min checkx` ran on the daemon's filesystem, creating {}",
            marker.display(),
        );
        assert_ne!(
            out.exit_status,
            Some(0),
            "the mock harness has no sandbox to run in, so this cannot succeed; stdout was {:?}",
            String::from_utf8_lossy(&out.stdout),
        );
        // Routed, not refused: the old daemon answered this with an
        // "unsupported command" refusal instead of handing it over.
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("unsupported"),
            "a `min` lookalike must be routed to the session, not refused, got {stderr:?}",
        );
    }

    /// An argv reaches the session as words, not as a line for some shell
    /// to re-split — the fix for gominimal/inbox#558. The mock harness has
    /// no sandbox, so what is provable here is that the form is accepted
    /// and routed to the session rather than refused or run on the daemon.
    #[tokio::test]
    async fn an_argv_form_is_accepted_and_routed_to_the_session() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;
        let session_str = session_id.to_string();
        let marker = daemon_marker("argv");
        let _ = std::fs::remove_file(&marker);

        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &ExecRequest::Argv(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    format!("printf pwned > {}", marker.display()),
                ])
                .encode(),
                &[],
            )
            .await
            .expect("an argv request is serviced over the channel");

        assert!(
            !marker.exists(),
            "an argv exec ran on the daemon's filesystem, creating {}",
            marker.display(),
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("unsupported"),
            "the argv form must be routed to the session, not refused, got {stderr:?}",
        );
    }

    /// An argv naming no program is refused rather than guessed at.
    #[tokio::test]
    async fn an_empty_argv_is_refused() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;
        let session_str = session_id.to_string();

        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                "min://argv []",
                &[],
            )
            .await
            .expect("the refusal is reported over the channel");

        assert_ne!(out.exit_status, Some(0));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("names no program"),
            "got {:?}",
            String::from_utf8_lossy(&out.stderr),
        );
    }

    /// An argv exec carrying a credential-shaped token emits an `exec
    /// request` line without the token and with the rest of the command
    /// intact.
    #[tokio::test]
    async fn exec_request_scrubs_credentials_from_log() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;
        let session_str = session_id.to_string();

        let capture = crate::test_harness::captured_log();

        let out = client
            .exec(
                &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                false,
                &ExecRequest::Argv(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "curl -H 'Authorization: Bearer ghp_FAKETOKEN' https://x/".to_string(),
                ])
                .encode(),
                &[],
            )
            .await
            .expect("an argv request is serviced over the channel");

        // The exec itself may fail (no sandbox), but the log line must
        // be scrubbed.
        let logged = capture.contents();
        assert!(
            logged.contains("exec request"),
            "expected an exec request line, got: {logged}"
        );
        assert!(
            !logged.contains("ghp_FAKETOKEN"),
            "token must be scrubbed from the exec request line, got: {logged}"
        );
        assert!(
            logged.contains("<redacted:len=13>"),
            "token must be replaced with placeholder, got: {logged}"
        );
        // The rest of the command is intact.
        assert!(
            logged.contains("curl -H 'Authorization: Bearer"),
            "non-credential parts of the command must survive, got: {logged}"
        );
        assert!(
            logged.contains("https://x/"),
            "URL must survive, got: {logged}"
        );

        // The exec outcome is not the point of this test.
        let _ = out;
    }
}

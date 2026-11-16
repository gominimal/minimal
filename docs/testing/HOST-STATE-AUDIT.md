# Host-wide state in the workspace's tests

An audit of the unit and integration tests for state they share with the
rest of the machine. nextest runs every test in its own process, many at a
time, and developers and the lab run the suite beside a live `minimald`,
`minvmd` or session e2e. A test that reaches outside its own process can fail
because of something else on the host, or can break that something else.

## What was looked for

- Fixed TCP/UDP ports: literal `7654`, `7656` and any other literal port a
  test binds or connects to, and production calls a test makes that fall
  back to those defaults.
- Real connects to `127.0.0.1` or `localhost`, including a port the test
  released and still expects to be closed or free (a "released port").
- Reads of `/proc/net/*`, of the whole network namespace, or of other
  processes' `/proc/<pid>`.
- Hardcoded `/tmp` or `$HOME` paths that are written or read.
- Process-wide environment changes (`set_var`, `remove_var`) made without a
  lock.
- Reliance on no other daemon running: the default daemon socket, the
  machine-global answerer channel (`/run/minimal/answerer.sock`), the
  install marker, or spawning a real `minimald run` or `minvmd`.

## Method

Every `.rs` file under `crates/` was split into test code (files under
`tests/` and `benches/`, `tests.rs` modules, and everything from the first
`#[cfg(test)] mod` on). The test code was grepped for the patterns above:
about 4,600 hits. Most were string data, such as an egress rule or an
expected message that names `127.0.0.1:7654`. Every hit that does real I/O
was read and classified, and so was every production function those tests
call that probes a default port, the global channel or `/proc`. The
nextest failures in recent lab prepush logs were matched against the list.

Classes:

1. **Hazard.** The test can fail, or can disturb other programs, under a
   parallel runner or beside a running daemon.
2. **Safe.** Port 0 kept bound, a per-test tempdir, `ENV_LOCK` held, or a
   string or path that is only computed and compared.
3. **Unsure or accepted.** A window that is real but narrow and that the
   code under test forces, or that depends on how a lane runs.

## Counts

| Class | Rows | Fixed on this branch | Fixed by #3152 | Not fixed |
| --- | --- | --- | --- | --- |
| 1 hazard | 9 | 6 | 2 | 1 |
| 2 safe | 17 | - | - | - |
| 3 unsure / accepted | 10 | - | - | 10 |

One row can cover several tests that share a helper or a shape, so the
counts are rows, not tests.

## Class 1: hazards

| Crate | Test | Pattern | Fix or reason |
| --- | --- | --- | --- |
| minimal | `resolver::tests`, the answerer beside a down proxy (`host_answerer_read` with `Holder { port: 7656 }`) | Real UDP liveness query to `127.0.0.1:7656`: any zone answerer on the machine answers it | Fixed by #3152: the probe is a parameter of `host_answerer_read_probing`, and the test passes its own answer |
| minimald | `box_actor::tests::a_present_landing_moves_a_running_interim_boxs_runtime_publications_to_its_hand`, and its sibling `..._forward_to_its_hand` | The mock box's leader is a host child, so the listen watcher reads the host's whole `/proc/net/tcp`: another process's listener in the test's range is published too | Fixed by #3152: under `cfg(test)` the watcher keeps the table to the sockets this test process holds. The filter is in the watcher, so it covers every mock-leader test, the forward sibling (also seen failing in the lab) included |
| minvmd | `cmd::run::tests::node_port_draw_skips_a_held_preferred_port_and_hands_it_back_once_released` | Released port: the test drops its hold and expects the same draw to hand the port back, but any process can take the port first | Fixed: the round retries on a fresh port only when the port is held again (the #2653 pattern, `NODE_PORT_RACE_ATTEMPTS`). A skip of a port nothing holds still fails at once |
| minvmd | `cmd::run::tests::node_port_probe_keeps_a_free_preferred_port` (TCP and UDP halves) | Released port, the same shape, with no retry, unlike its #2653 sibling | Fixed: the same retry |
| minvmd | `cmd::run::tests::node_port_assigned_on_host_and_handed_to_daemon`, the `assign_node_proxy_port` step | With no pin, the draw's probes bound `127.0.0.1:7654` and `0.0.0.0:7654` and dialled `127.0.0.1:7654`: beside a daemon or session e2e that owns the default, the test held its port for a moment | Fixed: `assign_node_proxy_port_from(dir, preferred)`. The supervisor passes `NODE_DEFAULT_PROXY_PORT`; the test passes the port it holds and checks that the draw moved off it |
| common | `remote_storage::placed::tests::a_connection_that_succeeds_clears_an_earlier_failure` | Released port expected to refuse: if anything binds it, the tunnel answers 200 instead of 502 (seen failing in the lab) | Fixed: `refusing_addr()` keeps a socket bound to the port without listening, so the connect is refused and nothing else can bind the port |
| common | `remote_storage::placed::tests::a_placed_download_connects_from_the_placement`, the unreachable-destination step | Released port expected to refuse | Fixed: `refusing_addr()` |
| minimald | `tests/otel_shutdown_integration.rs`, both tests | A real `minimald run` with only its state and cache dirs moved: the hostname proxy takes `127.0.0.1:7654` when it is free, and the answerer acquisition publishes into `/run/minimal/answerer.sock` or hosts the interim on `127.0.0.1:7656` | Fixed: `--hostname-proxy-port 0` (the OS picks the port, and it cannot be busy), `--zone-answerer-port` set to a UDP port the test holds (the acquisition finds it held and binds nothing), and `MINIMAL_ANSWERER_CHANNEL_SOCK` and `MINIMAL_ANSWERER_INSTALL_MARKER` pointing into the test's dir (test and debug builds read them) |
| minimald | `net::policy::tests::the_probe_names_only_a_port_another_process_holds` | Released port expected to stay free: if another process binds it, `host_ports_in_use` names it and the first assertion fails | **Not fixed.** The function under test decides by binding, so the test cannot hold the port. A clean fix needs a bind-probe parameter on `host_ports_in_use`, which changes what the test proves. The window is a few microseconds |

## Class 3: unsure or accepted

| Crate | Test | Pattern | Reason |
| --- | --- | --- | --- |
| minimald | `net::answerer` acquisition tests through `free_udp_port()` (11 uses) | Probe-and-release: the port is read and released, then the acquisition under test binds that number | The code under test takes a port number, not a socket. The window runs from the drop to the acquisition's bind. Removing it would mean passing a pre-bound socket to `acquire_at`, a production signature change |
| minvmd | `net::answerer` tests through `free_port()` and `service_sockets()` (9 uses), including the "port is free once released" rebinds | Probe-and-release, then the reverse: a rebind after the daemon releases the port | Same reason. The rebind asserts the release happened, which only a real bind proves |
| minvmd | `box_registry` tests through `free_port()` (6 uses) | Probe-and-release | Same reason |
| minimal | `tests/cli.rs` through `free_loopback_port()` (5 uses, `min net forward` laptop side) | Probe-and-release, then the forward under test binds the number | Same reason: the CLI takes `0:<port>` as an argument |
| minimald | `server/tests.rs` proxy and answerer default-and-rung walks (`next_host_publish_port` ladders, TCP and UDP) | Probe-and-release on the default and its rung | The tests document the window and keep the state's construction out of it; the drive must bind the number itself |
| minimald | `net::proxy` two-VM publish tests (`guest_port` and `zone_port` ladders) | Both numbers are held until the forwards take them over | Held, so the window is only the handover, and it is commented |
| minimald | `net::listeners` restart tests (`listener_close_withdraws_publication` and three more that rebind `0.0.0.0:<port>` after dropping a listener) | Rebinding a port the test just dropped | The rebind is the behaviour under test (a fresh listener on the same port republishes). The port is ephemeral and the window is one poll |
| minvmd | `cmd::run::tests::draw_skips_the_answerer_hook_port_while_free` | Premise `!loopback_answers(7656)`: a TCP dial to the host's real `127.0.0.1:7656` | Nothing in Minimal listens on TCP 7656 (the answerer is UDP), so the premise fails only if some foreign program holds TCP 7656, and it fails loudly with that message. The draw itself never probes 7656, because the reserved-set check runs first |
| minvmd | `tests/*_integration.rs` VM boots (`boot`, `egress_allowlist`, `guest_classifier`, `minimald_session`, `otel`, `otel_vsock`, `resource_vm`, `supervision`, `vm_escape`, `volume_quiesce`, `named_vm`) | A real `minvmd` assigns the node proxy at 7654 first and runs the host answerer at 7656 and the global channel | They get their own state dirs and `HOME`, and run in the `vm` nextest profile one at a time. They deliberately exercise the defaults the session e2e depends on, so the isolation belongs to the lane (its own netns or runner), not to a seam |
| minimald | `guest` (handed proxy port token tests) and `server/tests.rs` (`HANDED_PROXY_PORT_TOKEN`) | `set_var` on one variable from two modules of one test binary | Safe under nextest, which CI and the lab run. `just test-cross` runs `cross test` on `minimald`, a threaded `cargo test`, where the two race and either can fail. Fixing it means an `ENV_LOCK` shared by the two modules, left for a follow-up |

## Class 2: safe

| Crate | Test | Pattern | Reason |
| --- | --- | --- | --- |
| all | Most loopback servers and clients (`TcpListener::bind(("127.0.0.1", 0))` then `local_addr()`, about 500 sites) | Loopback I/O | Port 0, held for the test's life |
| minimald | `box_actor::tests` own-address boxes through `declared_port()` | A fixed band, 23000-24000 | A cross-process lease: one `flock` per port in a per-uid dir, and the band sits below the ephemeral range. The doc comment states the one gap (a listener on a specific `127.0.64.x` address) |
| minimald | Harness-daemon tests (`TestServer`, `test_harness::Config`) | Daemon RPCs | The harness never starts the host proxies or the answerer (`hostname_proxy_port: None`, the comment in `test_harness.rs`); state is a tempdir |
| minimal | `tests/cli.rs` and `src/tests.rs` `min` runs | Spawned CLI | `--minimal-dir` and `--config-dir` are per-test tempdirs, and the daemon is the harness one, or a fake control socket |
| minimal | `tests/cli.rs` `ls_*` tests with `Holder { port: 7656 }` | Status naming 7656 | `format_ls` and `format_ls_across_vms` render a status that is already computed and do no probe |
| minimal | `cmd::finalize_install` `--show` tests with `PortHeldNoChannel { port: 7656 }` | Status naming 7656 | That arm of `host_answerer_read` does no liveness query |
| minimal | `resolver::tests` `ProxyNotServing` read (`host_answerer_read(redrawn)`) | Calls the probing read | That arm carries no answerer port, so no query is sent |
| minimal | `resolver::tests::answerer_bound_at_reads_silent_and_closed_ports_as_not_bound` | Released UDP port | A later holder would have to answer Minimal's exact DNS query with the host row to fail it |
| minvmd | `cmd::run::tests::port_holder_identifies_a_child_listener_pid`, `port_holder_is_none_when_the_lookup_fails` | Whole `/proc/net/tcp` and `/proc/*/fd` | Filtered to a port the test or its child holds; the copy of the table goes into a tempdir |
| minvmd | `net::answerer::tests::registration_fails_naming_a_channelless_hook_port_holder` | `/proc/net/udp` and `/proc/*/fd` | Filtered to a port the test holds |
| minimald | `diag` bundle tests | Bundle reads `/proc/net/route`, `fib_trie`, `unix` | Assert that sections are present, not what they contain |
| minimald, mlog, bep | `/proc/self/fd`, `/proc/self/fdinfo`, `/proc/<own child>/stat` | procfs | This process or its own children |
| minimald, minvmd, paths, check, switch | Env tests with `ENV_LOCK` or `UDS_ENV_LOCK` (`logging`, `image`, `sock`, `switch`, `check` sources and outputs, `paths` XDG config) and `#[serial]` (`mip`) | `set_var` | Locked |
| minimald, minvmd, minimal-client, paths, mlog | Env tests without a lock: `connection` (`RelayPathGuard`), `minvmd cmd::run` (`MINVMD_NODE_PROXY_PORT`), `minimal-client` (`GIT_CEILING_DIRECTORIES`), `paths` (`XDG_STATE_HOME`), `mlog/tests/otel_without_ca_roots.rs` (its own binary), and `guest`'s egress opt-out tokens | `set_var` | nextest gives every test its own process, and CI and the lab run nextest only. Each variable here has one writer per test binary, so a threaded `cargo test` does not race on it either |
| many | Literal `/tmp/...`, `/run/user/1000/...` and `/run/minimal/...` paths (`mfile`, `minimal-client`, `attach`, `minvmd sock`, `shuttle`, `timekeep`, `krun ctx`, `sandbox config`, `resolver` undo scripts) | `/tmp` and `/run` | Computed and compared, never opened. The script tests run the script under a tempdir root with stub `systemctl` and `resolvectl` |
| minimal | `tests::resolve_upload_root_returns_input_when_no_mfile`, `sync_none_drops_project_config_false_when_no_mfile` | `tempdir_in($HOME)` | A unique tempdir, removed afterwards. `$HOME` is the walk's boundary, which is the point of the tests; they skip when `$HOME` is read-only |
| minimald, sandbox | `*_root_integration.rs`, `mesh_uc7.rs`, `nsenter_integration.rs` | netns, nft, `/var/run/netns`, fixed lock and fixture names in `temp_dir()` | Root lane only, each in its own namespace, serialized by `minimald-classifier-root-proof.lock`; the fixed names are deliberate |

## Not covered

- Tests outside `crates/` (shell harnesses under `tests/` or `scripts/`).
- Unix-socket paths, beyond checking that they sit under tempdirs.
- Release-profile test runs (`cargo test --release`). The answerer's path overrides are
  honoured by debug builds only, so `tests/otel_shutdown_integration.rs` is compiled
  out there rather than left to reach the machine-global answerer; no CI, lab or
  `just` target runs tests in release.
- Recurring lab failures that were not tied to host state:
  `rpc::trace_tests::the_reap_of_an_unfinalized_session_joins_its_creators_trace`,
  `box_actor::tests::a_mint_whose_host_dies_before_attach_reports_a_spawn_failure`,
  `minimal::otel_cli exec_run_attach_and_task_run_share_the_commands_trace`.
  The pruned logs had no panic text, so they are not classified here.

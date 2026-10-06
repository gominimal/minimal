---
id: arch-telemetry
title: Telemetry architecture
kind: architecture
tracking-issue: gominimal/inbox#515
---

# Telemetry architecture

The requirements are in [25-spec-telemetry.md](25-spec-telemetry.md). This
page says where spans are born, how a trace crosses each process boundary,
and which settings reach which process.

## Where spans are born

`min`, `minimald` and `minvmd` call `mlog::otel::init(<service>)` before
they install their tracing subscriber. Each then adds `span_layer()` and
`log_layer()`, which are `None` when telemetry is off. The service names are
`minimal-cli`, `minimald` and `minvmd`.

| Process | Spans it starts | Parent |
|---|---|---|
| `min` | `cmd`, one per invocation, with `client.connect` and `client.rpc` under it | an inherited `TRACEPARENT` when valid, else a new trace |
| `minimald` (native or guest) | `rpc` per request, and `exec`, `attach`, `forward`, `git_receive` per channel | the `TRACEPARENT` the CLI sends in the channel environment, or in the `direct-tcpip` originator field for a forward |
| `minimald` actors | `sessions.manager.message` and `session.message` per mailbox message | the sender's trace ids, carried in the message |
| `minimald` long-lived tasks | `session.actor`, `session.host`, `binding`, `net.relay`, `session.env`, `sessions.manager`, `store`, `maintenance` | none: each is a root with a `follows_from` link to the span that spawned it |
| `minimald` maintenance | `maintenance.clean` (`trigger` = `tick` or `request`) | the `maintenance` root |
| `minimald` checkouts | `checkouts.update`, `checkouts.update_remote`, `checkouts.checkout_of` | the request's span |
| `minvmd` | `minvmd` root per process (`cmd` = the subcommand) | an inherited `TRACEPARENT`, adopted only while exporting |
| `minvmd run` | `supervisor.start` with `net.switch.start` and `vm.boot` under it, then `supervisor.serve` | `supervisor.start` is under the root. `supervisor.serve` is a new root linked to `supervisor.start` |
| `minvmd stop` | `vm.stop`, and `guest.shutdown` under it | the stop process's root |
| guest `minimald` (pid 1) | `guest.ready` | the `TRACEPARENT` on the kernel command line, which names `vm.boot` |

The exporter sends a span when it ends. For that reason the supervisor
splits its life into a bounded `supervisor.start` (it ends and flushes when
the VM is ready) and an open-ended `supervisor.serve`. Long-lived actors are
roots for the same reason. So is the order at the end of a `min` command. It
ends `cmd` before it `exit()`s with the status of ssh, or before it dies of a
signal in `min net forward`. (`min` stays the parent of ssh for
`session exec`, `run` and an attach.)

## The trace across process boundaries

```text
shell / CI  --TRACEPARENT env-->  min (cmd)
min         --channel env TRACEPARENT-->  minimald (rpc, exec, attach)
min         --direct-tcpip originator-->  minimald (forward)
min         --TRACEPARENT env-->  minvmd run --detach --> supervisor --> __krun-vmm
minvmd      --kernel command line TRACEPARENT-->  guest minimald (guest.ready)
guest minimald  --vsock port 7353, OTLP-JSON frames-->  minvmd --> the host's endpoints
minimald    --box env TRACEPARENT (recorded exec span only)-->  min inside a box
min (off)   --opt-out with each request, no TRACEPARENT-->  minimald (records nothing)
```

`min` always adopts a valid inbound `TRACEPARENT` for its ids and forwards a
trace context to its daemon, whether or not it exports. Adopting is not
exporting. A `min` in a box with no opt-in of its own still joins the outer
trace through the daemon. `minvmd` and the guest daemon adopt an inbound
context only while they export.

A `min` whose telemetry decision is off, for any cause, sends an explicit
opt-out with each request and no `TRACEPARENT`. The marker is
`MINIMAL_OTEL=off`: in the channel environment, in the `direct-tcpip`
originator for a forward, and as the same variable on the OpenSSH attach
path. A daemon that is on gives that request's spans an unsampled parent
and `telemetry=opt-out`, and no `command` (TEL-045). A daemon
that is off records nothing in any case (TEL-009).

The guest daemon does not export over the guest's network. It writes each
finished record to its spool and hands the same line to a sender thread.
That thread connects out to the host on vsock port 7353 and writes
length-delimited OTLP-JSON frames. `minvmd run` receives them on a door
beside the control socket, accepts one OTLP request with one resource per
line (strict JSON, 1 MiB a frame, 64 KiB a second per VM after a 4 MiB
burst), stamps each with `minimal.forwarded_by=minvmd` and
`minimal.vm=<name>`, appends the re-serialized line to its own spool and
forwards batches built from the parsed lines from a second thread under the
host's switches (TEL-034). A missing
receiver costs the guest nothing but a retry every 5 s (TEL-046). The
design is [guest-vsock.md](guest-vsock.md).

A daemon span for a request from a box has the box and session ids of the
host-side connection, never a value the box supplied (TEL-048).

## Environment surface

Each process reads the values once, at `init`. A daemon keeps the settings
of the `min` that started it until it stops.

| Variable | Effect |
|---|---|
| `MINIMAL_TELEMETRY` | `1`, `true`, `yes` or `on` (any case) opts in. Anything else, or unset, is off. |
| `DO_NOT_TRACK` | Any non-empty value vetoes export and spool, `0` and `false` included. |
| `OTEL_SDK_DISABLED` | `true` (any case) vetoes export and spool. `1` does not. |
| `MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT`, then `OTEL_EXPORTER_OTLP_ENDPOINT` | Base endpoint. `/v1/traces` and `/v1/logs` are appended. |
| `MINIMAL_OTEL_EXPORTER_OTLP_{TRACES,LOGS}_ENDPOINT`, then the `OTEL_` names | Per-signal endpoint, used as given. A per-signal endpoint under either name wins over a base endpoint under either name. |
| `MINIMAL_OTEL_{TRACES,LOGS}_EXPORTER`, then the `OTEL_` names | `none` turns that signal off, export and spool. A set `MINIMAL_` name hides the plain one. |
| `MINIMAL_OTEL_SPOOL` | `0`, `false`, `no` or `off` turns only the spool off. |
| `MINIMAL_OTEL_SPOOL_DIR` | Spool location for every process. Wins over the state directory. |
| `MINIMAL_OTEL_FILTER` | Export filter in `RUST_LOG` syntax, default `info`. The exporter's HTTP stack and the SDK are always off. |
| `MINIMAL_OTEL_FORWARD` | Guest only. `vsock:7353` makes the guest daemon send its records to the host over that vsock port instead of exporting. The guest ignores any `MINIMAL_OTEL_EXPORTER_*` it is given. |
| `RUST_LOG` | Console and file logs only. It never gates export. |
| `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_{TRACES,LOGS}_HEADERS` | Read by the OTLP exporter itself on host processes once telemetry is on. Sent only to an endpoint chosen under a plain `OTEL_` name. An endpoint chosen under a `MINIMAL_` name never receives them: it gets `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` instead. With plain headers set and no `MINIMAL_` ones, that signal is not exported (decision S3). |
| `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` | The headers for an endpoint chosen under a `MINIMAL_` name, in the same `k=v,k=v` syntax. One variable for both signals. Ignored for an endpoint chosen under a plain `OTEL_` name. |
| `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_BSP_*`, `OTEL_BLRP_*` and the other standard variables of the SDK | Applied by the SDK on host processes once telemetry is on. |
| `TRACEPARENT` | Inbound parent (see above). |
| `CI` | Not a switch. |

### What reaches which process

| Destination | What crosses | What never crosses |
|---|---|---|
| A daemon `min` starts (`minimald`, `minvmd`) | The whole environment of that `min`, plus the CLI's `TRACEPARENT` for `minvmd` | |
| `minvmd`'s own child processes | The environment, with `TRACEPARENT` set to the current span when exporting | |
| The guest daemon (kernel command line) | Only while telemetry is enabled on the host: `MINIMAL_TELEMETRY`, `MINIMAL_OTEL_FORWARD=vsock:7353`, `MINIMAL_OTEL_FILTER` when set, `MINIMAL_OTEL_TRACES_EXPORTER=none` or `MINIMAL_OTEL_LOGS_EXPORTER=none` when the host has that signal off, `MINIMAL_OTEL_SPOOL=0` when the host spool is off, and a well-formed `TRACEPARENT` | Any endpoint, headers, resource attributes, `BAGGAGE`, `TRACESTATE`, `OTEL_BSP_*`, `MINIMAL_OTEL_SPOOL_DIR`, and any value with whitespace |
| A box (`min session exec`, `run`, `task run`) | `TRACEPARENT` of the exec span, only when that span is recorded. TEL-047 asks for it to appear wherever a box's injected environment is reported (nothing does yet) | Every other variable of the host telemetry environment. Variables a Box Spec's `[otel]` block declares are the box's own and are outside spec 25 |
| An interactive attach shell | Nothing | |

Every process creates its spool directory 0700 and opens it with
`O_NOFOLLOW` and `O_DIRECTORY`. It refuses the directory when its owner is
not the process uid or when any group or other bit is set (TEL-019). A
refused `MINIMAL_OTEL_SPOOL_DIR` falls back to the state-directory spool
with one warning that names it (TEL-020). A refused default directory
means nothing is spooled.

## Spool layout

| Item | Value |
|---|---|
| Directory | `MINIMAL_OTEL_SPOOL_DIR`, else `<minimal state dir>/telemetry/spool` (natively `$XDG_STATE_HOME/minimal/telemetry/spool`, default `~/.local/state/minimal/telemetry/spool`. In the guest `/var/lib/minimal/telemetry/spool`) |
| File | `<service>-<pid>-<start_ms>.jsonl`, then `-<n>.jsonl` after each rotation |
| Line | one `ExportTraceServiceRequest` or `ExportLogsServiceRequest` in OTLP-JSON |
| Modes | directory 0700, files 0600 |
| Segment | 4 MiB |
| Prune | when a file opens: older than 7 days, then oldest first down to 46 MiB. A first file prunes only when no prune ran in 60 s (the `.pruned` stamp) |
| Recheck | every 5 s, a writer checks its file still has a name |

A native `minimald` started with `--minimal-state-dir` moves its spool under
that directory once it knows it, unless the environment sets
`MINIMAL_OTEL_SPOOL_DIR`. The guest daemon starts with `HOME=/` and moves its
spool onto the state volume after mounting it. Records written before the
move stay in the initramfs.

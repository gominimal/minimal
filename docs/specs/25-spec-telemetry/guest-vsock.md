---
id: arch-telemetry-guest-vsock
title: Guest telemetry over the VM channel
kind: design note
tracking-issue: gominimal/inbox#515
---

# Guest telemetry over the VM channel

Design for the eighth commit of the spec 25 series. The microVM guest daemon
stops exporting over the guest's network. Its records travel to `minvmd` over
a vsock port, and `minvmd` forwards them under the host's switches. The spec
changes and the lab scenario changes are in the last sections.

## Transport

A dedicated vsock port, `VSOCK_TELEMETRY_PORT = 7353`, beside the READY
marker port 7350, the host time updates' 7351 and the report door 7352. The guest connects out to the
host (`VMADDR_CID_HOST`, 2). That is what `minimald::guest::emit_marker`
does today. The wiring copies the report door's:

- The `run` supervisor binds `guest-telemetry.sock` beside the control
  socket in the per-VM provider directory, with the control socket's
  posture (path length checked, 0700 owned parent, stale socket removed,
  0600), before it spawns the VMM child. It hands the path down in
  `MINVMD_GUEST_TELEMETRY_SOCK`.
- The VMM child registers the path with `ctx.add_vsock_port(7353, path)`,
  next to the marker in `cmd/vmm_child.rs`. libkrun dials the socket each
  time a guest process connects to CID 2 port 7353 and splices the two
  streams.
- The supervisor serves the socket on its own thread, one guest connection
  at a time. Only `minvmd run` binds the door, and only with telemetry on.
  Under `minvmd boot` the guest's connect fails and the guest behaves as
  under "receiver absent" below.

`minvmd` has no Cloud Hypervisor wiring. The lab's Cloud Hypervisor guests
are the lab's own test hosts, inside which `minvmd` runs libkrun. The SSH
bridge (`VSOCK_BRIDGE_PORT`) was not reused: that bridge is host-to-guest
and authenticated as the daemon's control plane. Telemetry is guest-to-host
and stays data.

## Peer binding

`minvmd` treats a connection on the door as the guest's pid-1 daemon for
three reasons, each with a test:

1. The port exists only for this VM, for the life of this VMM child, and
   the socket is owner-only on the host. A host process of the same user
   can dial it, as it can the marker socket today. That is the existing
   trust (`sock::enforce_socket_permissions`, the peer uid check).
2. Inside the guest, every box runs under the socket-family seal of
   `sandbox2`. No seal admits `AF_VSOCK`, so `socket(2)` for a vsock fails
   with `EAFNOSUPPORT` in every box, in every network mode. The guest
   daemon and its non-box children are the only guest processes that can
   open the port. Tests: `sandbox2::tests::no_seal_admits_af_vsock`,
   `every_seal_refuses_a_vsock_socket`.
3. The receiver takes the data as data, never as identity. It accepts a
   frame only when the line parses as strict JSON (`serde_json`: no
   comments, no trailing commas, no repeated top-level key) to one object
   with one key, `resourceSpans` or `resourceLogs`, holding an array of
   exactly one resource entry. The frame must be at most 1 MiB, and the VM
   gets 64 KiB a second after a 4 MiB burst, one budget across reconnects
   (`GUEST_BYTES_PER_SEC`, `GUEST_BURST_BYTES`). An accepted line costs
   the larger of its frame and the stamped line the host spools for it.
   The receiver refuses and counts anything else. The host stamps every
   resource with its own provenance, `minimal.forwarded_by=minvmd` and
   `minimal.vm=<name>`, as the first two resource attributes, and drops
   any `minimal.*` attribute the guest wrote at any level: resource,
   scope, span, span event and link, and log record. So a receiver tells a
   guest's records apart by what the host says. What the host spools and
   sends is serialized again from the parsed, stamped value, never the
   guest's text, so the collector reads what the host's parser read.
   The guest never names an endpoint or a header, and nothing the guest
   sent is logged on the host: lengths, counts and error kinds only.
   Tests: `guest_telemetry::tests::only_one_otlp_request_per_line_is_accepted`,
   `a_batch_is_one_strict_json_request_serialized_from_the_parsed_lines`,
   `a_guests_minimal_attributes_are_dropped_at_every_level`,
   `a_reconnect_does_not_reset_the_byte_budget`,
   `the_guest_budget_is_a_small_share_of_the_host_spool`,
   `an_oversized_or_empty_frame_ends_the_connection_after_a_flush`,
   `a_stream_cut_mid_frame_keeps_what_came_before`.

## Wire format and backpressure

Frames are length-delimited: a 4-byte big-endian length, then one OTLP-JSON
line exactly as the spool writes it (`spool::span_line`, `log_line`),
without the newline. The sender writes a burst of up to 64 frames per
`write_all`. A record longer than the 1 MiB frame bound, or empty, is
dropped and counted on the guest (it stays in the guest's spool) rather
than sent, since the host ends the connection on such a frame. The
receiver keeps a frame's bytes across its read timeouts, so a timeout
inside a length never shifts the framing.

In `mlog`, two more processors sit beside the spool's, `ForwardSpans` and
`ForwardLogs`, installed when `MINIMAL_OTEL_FORWARD` names a destination.
They push each encoded line into a bounded queue of 1024 lines. One
dedicated thread in `minimald::telemetry_forward` takes the queue's reading
end (`mlog::otel::take_forward_receiver`), connects, writes, and reconnects
after 5 s when a connect or a write fails. A full queue drops the newest
record and counts it. The spool processors run as before, so TEL-014 and
TEL-015 hold. Nothing on the daemon's request paths waits on the host.

## Forwarding on the host

The door appends every accepted, stamped line to the host spool
(`mlog::otel::spool_foreign_line`). A line is a self-describing OTLP request
with the guest's own resource plus the stamp, so `min bug` and the lab see
guest records in `minvmd-<pid>-*.jsonl`. Guest lines have no spool of their
own: they share the host spool's 50 MiB bound and its pruning order with
the host's records. The byte budget is their share, and it is charged on
the larger of the frame and the spooled line, so it bounds what the spool
gains. Past its 4 MiB burst, one VM at 64 KiB a second needs
(50 - 4) MiB / 64 KiB/s = 736 s, about 12 minutes, to write a spool's worth
and push the host's own files out. The budget is per VM and the spool is
shared, so N VMs flooding at once take (50 - 4N) x 16 / N seconds: 336 s
for two, 136 s for four. Batches go to a second thread over
a queue of 16; with the queue full, a batch is dropped and counted, so a
hanging collector never stops the door reading. That thread forwards under
the host's switches, per signal:

- Host telemetry off, `DO_NOT_TRACK`, or `OTEL_SDK_DISABLED=true`: the
  supervisor never binds the door, and the boot line has no port token.
- The signal's export is off on the host (no endpoint, `none`, or a plain
  headers refusal): the line stays in the spool and goes nowhere.
- The signal's export is on: a batch becomes one `ExportTraceServiceRequest`
  or `ExportLogsServiceRequest` body. A batch closes at 64 lines, at 256 KiB,
  or one second after the last frame. The door serializes the batch's
  parsed, stamped entries as one request, and `mlog::otel::forward_request` sends it
  as `application/json` to the host's endpoint for that signal, under
  `EXPORT_TIMEOUT`, on the door's thread. The request gets the headers the
  host's rules give that endpoint (`ExportClient`, review S3). The first
  failure in a process logs one warning.

OTLP/HTTP collectors accept JSON on the same `/v1/traces` and `/v1/logs`
paths as protobuf. The lab's 715b sink decodes protobuf only today.

## The boot line

`guest_env` shrinks to `MINIMAL_TELEMETRY=1`, `MINIMAL_OTEL_SPOOL=0` when
the host spool is off, `MINIMAL_OTEL_FILTER` when set,
`MINIMAL_OTEL_{TRACES,LOGS}_EXPORTER=none` when the host has a signal off,
`MINIMAL_OTEL_FORWARD=vsock:7353` when the door is bound, and
`TRACEPARENT`. No endpoint token of any kind crosses, so the endpoint
recognizer and the secret-shape rules leave `minvmd`. The guest ignores any
`MINIMAL_OTEL_EXPORTER_*` in its environment. In the guest, `init` with
`MINIMAL_OTEL_FORWARD` set installs the tracer and log providers with the
spool and forward processors and no OTLP exporter. So `exporting()` is true,
and `guest.ready` adopts the boot line's parent.

## Trace shape

Unchanged. `guest.ready` is a child of `vm.boot` in the run's trace, and the
guest's spans keep their trace id, span ids and resource
(`service.name=minimald`, the guest's `service.instance.id`).

The guest's spans also keep their timestamps, which are the guest clock's.
That clock follows the host's only to within the timekeep step threshold
(80 ms) plus its drift between updates, so where a guest span has a host
parent (`guest.shutdown` -> the guest's `rpc`) the child can appear to start
before the parent by that offset (TEL-034).

## Stop ordering

A stop delivers the guest's spans to the host before the VM goes down,
within a bounded grace after the guest acknowledges Shutdown. It does not
deliver them before the acknowledgement. The order is:

1. `minvmd stop` sends Shutdown. Before it acknowledges, the guest flushes
   what has finished, bounded at 1.5 s (TEL-037), then quiesces its state
   volume.
2. The guest writes the acknowledgement. Its `rpc` span for Shutdown, its
   one child of `guest.shutdown`, ends only now, so no flush before the
   acknowledgement can carry it.
3. `minvmd stop` waits up to 3 s for the VMM to exit by itself (TEL-049).
   Meanwhile the guest's exit path runs: the server drain, the runtime
   shutdown, the telemetry flush (TEL-038), and the vsock sender's drain,
   which waits for records written or dropped. Then the guest powers the
   VM off, and the VMM exits. A guest that is not done in 3 s is
   signalled as before, and what it had not sent stays in its own spool.
4. The VMM's exit closes the door's connection. The supervisor waits up
   to 2 s for the door to read it to the end and to forward every queued
   batch to the host's endpoints (TEL-050). Each accepted line was
   spooled on arrival, so the spool has it either way.

Before the fix, `minvmd stop` signalled the VMM as soon as the
acknowledgement arrived. That raced step 3, and on a loaded host the
signal won: lab 715k on debian-12 on 2026-10-06 saw the door's connection
close 60 ms after the acknowledgement, with no guest span under
`guest.shutdown`. The guest's drain also counted records taken off the
queue, which the sender counts before its write.

Observation, not a telemetry fault: in that run the guest's Shutdown
handler took 7.6 s, almost all of it the state volume's trim (475 MB,
TEL-039's quiesce, spec 08) on a host at load 13. Healthy stops take
under 1 s in total. Every `minvmd stop` pays the trim before the
acknowledgement, so a large trim is user-visible stop latency.

## Failure modes

- Receiver absent (an old `minvmd`, `minvmd boot`, the socket gone): the
  guest's connect fails. The sender retries every 5 s and logs once. The
  queue drops at its bound. The guest spools as before.
- Host slow: the queue fills and drops the newest. The guest's work never
  blocks on the socket.
- Host endpoint down: the door pays `EXPORT_TIMEOUT` per batch on its own
  thread, as the host's exporter does. The guest sees nothing of it.
- VM stops: the door flushes what it read and closes, and the supervisor
  drains its forward for up to 2 s before it exits (see Stop ordering).
- Guest slow to power off after its acknowledgement: `minvmd stop`
  signals the VMM after 3 s, and the guest's last spans can be lost on
  the host. They stay in the guest's spool.

## Spec 25 changes

- **TEL-033** lists the allowlist by name: `MINIMAL_TELEMETRY`,
  `MINIMAL_OTEL_SPOOL`, `MINIMAL_OTEL_FILTER`, the two `*_EXPORTER`
  switches, `MINIMAL_OTEL_FORWARD` and `TRACEPARENT`. It forbids every
  endpoint. The secret-shape clause is gone with the endpoints.
- **TEL-034** binds the guest's records to the vsock port and to `minvmd`'s
  forward under the host's switches. `guest.ready` stays under `vm.boot`,
  and the guest makes no network use.
- **TEL-046** (new) covers the unreachable receiver. The guest keeps
  spooling and drops at the queue bound. It warns once and retries every
  5 s. No request path waits.
- **TEL-049** (new) gives an acknowledging guest up to 3 s to power off
  before `minvmd stop` signals the VMM. **TEL-050** (new) drains the door's
  forward for up to 2 s when the VMM exits. Both came with the 715k fix.
- The invariants in Security considerations change with them. The trust
  model says what a compromised guest daemon can still do (send any record)
  and what it cannot do (name a collector, or attach a header).

## Lab scenario changes

- 715b: the boot line has `MINIMAL_TELEMETRY=1` and
  `MINIMAL_OTEL_FORWARD=vsock:7353` and no `MINIMAL_OTEL_EXPORTER_OTLP_*`
  token at all, so the endpoint-token check inverts. The sink must accept
  `application/json` bodies as well as protobuf. The `guest.ready` parent
  and trace checks stay as they are. The control "a span from service
  minimald reached the sink" still holds, through the host.
- 715f: the guest's init line reads `telemetry on: traces -> vsock:7353,
  logs -> vsock:7353, spool -> ...`. The `could not be built` branch cannot
  happen in the guest any more. The spool relocation line stays.
- 715g: no change in substance. The boot line is shorter.
- 715h: no change. No endpoint token crosses now, in every case.
- 715k: its verdict line should say the guest's spans reached the host
  before the VM went down, within the grace after the acknowledgement,
  not that they were flushed before the acknowledgement. The check itself
  (a stamped guest span under `guest.shutdown`) stands.

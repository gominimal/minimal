---
title: Telemetry
description: "Opt-in OpenTelemetry traces and logs for min, minimald and minvmd. Covers the switches, the local spool, the recorded data, the cost and troubleshooting."
---

# Telemetry

`min`, `minimald` and `minvmd` can send OpenTelemetry traces and logs to a
collector you run, and keep a local copy of the same records on your disk.
One command becomes one trace. The CLI's work, the session daemon's work, the
VM's boot and the guest daemon's start-up all appear together.

Telemetry is **off** unless you turn it on. In that state minimal exports
nothing and writes nothing, and the process has no telemetry thread or
connection.

The requirements behind this page are in
[spec 25](../specs/25-spec-telemetry/25-spec-telemetry.md).

## Turning it on

Set `MINIMAL_TELEMETRY=1`. With nothing else set, records go only to the
local spool:

```sh
export MINIMAL_TELEMETRY=1
min stop   # daemons keep the settings they started with; see below
min ls
```

To also send them to a collector, name its OTLP/HTTP endpoint:

```sh
export MINIMAL_TELEMETRY=1
export MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
min stop
min ls
```

`MINIMAL_TELEMETRY` accepts `1`, `true`, `yes` or `on`, in any case.

**Daemons keep the settings they started with.** `minimald` and `minvmd`
read the telemetry variables once, when they start, from the environment of
the `min` command that started them. Changing a variable in your shell does
not change a daemon that is already running. Run `min stop`, and the next
`min` command starts the daemon again with your current settings.

## Pointing at a collector

minimal speaks OTLP over HTTP with protobuf payloads, the protocol a
collector's HTTP receiver accepts on port 4318 by default. gRPC is not
supported.

| Variable | Meaning |
|---|---|
| `MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT` | Base endpoint. `/v1/traces` and `/v1/logs` are appended for each signal. |
| `MINIMAL_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `MINIMAL_OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` | One signal's endpoint, used exactly as given. It wins over the base endpoint. |
| `MINIMAL_OTEL_TRACES_EXPORTER=none`, `MINIMAL_OTEL_LOGS_EXPORTER=none` | Turn one signal off, both export and spool. |
| `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` | Request headers for an endpoint set with a `MINIMAL_` variable, as `key=value` pairs separated by commas (the `OTEL_EXPORTER_OTLP_HEADERS` format). See [Authentication](#authentication). |
| `MINIMAL_OTEL_FILTER` | Which spans and events are exported, in `RUST_LOG` syntax. The default is `info`. |

The standard `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`,
`OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`, `OTEL_TRACES_EXPORTER` and
`OTEL_LOGS_EXPORTER` names work too, but only once `MINIMAL_TELEMETRY` is on,
and a `MINIMAL_` endpoint, base or per-signal, always wins over every plain
one. A plain `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` therefore does not take
traces away from `MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT`. Plain `OTEL_*`
variables alone never turn telemetry on, so settings your shell or CI runner
exports for other programs do not send minimal's records anywhere.

`RUST_LOG` controls only what the terminal and the log files show. It does
not limit what minimal exports.

### Authentication

Headers follow the endpoint they go with:

- An endpoint set with a plain `OTEL_` variable gets the plain
  `OTEL_EXPORTER_OTLP_HEADERS` (or the per-signal
  `OTEL_EXPORTER_OTLP_TRACES_HEADERS` and `OTEL_EXPORTER_OTLP_LOGS_HEADERS`),
  as any OpenTelemetry program sends them.
- An endpoint set with a `MINIMAL_` variable gets
  `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` and never the plain ones. Headers
  your shell exports for another backend, often a key, never reach a
  collector you named for minimal.
- If a plain headers variable is present, the endpoint comes from a
  `MINIMAL_` variable, and `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` is absent,
  minimal does not export that signal. Each process logs one warning per
  signal and keeps writing the spool as usual:

  ```text
  telemetry: refusing to export traces: OTEL_EXPORTER_OTLP_HEADERS is set but the endpoint comes from MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT; set MINIMAL_OTEL_EXPORTER_OTLP_HEADERS to send headers there
  ```

  Set `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` to the headers that collector
  needs, or to something harmless such as `x-minimal=1` when it needs none.

Headers stay on your machine. They never reach a VM or a box.

The OpenTelemetry library reads other standard variables too, such as
`OTEL_RESOURCE_ATTRIBUTES` and the batch settings. They apply to `min` and
to the daemons on your machine once telemetry is on.

### Sessions in a microVM

When your sessions run in a microVM, the guest daemon receives the on/off
switches on its kernel command line and nothing else. It does not get your
endpoint or headers. Its records travel to `minvmd` on your machine over a
VM channel (vsock port 7353). `minvmd` sends them to your collector with
the same settings and headers as its own records. The guest needs no
network for this, and a box inside the VM cannot open that channel.

`minvmd` also keeps a copy of the guest's records in its own spool file
(`minvmd-<pid>-*.jsonl`), marked `minimal.forwarded_by=minvmd`, so `min
bug` and the local spool show them beside the host's. The guest daemon
keeps its own spool on the VM's state volume as well.

A VM's records may use up to 64 KiB a second of that path, after a 4 MiB
burst, counted as the larger of what the guest sent and what `minvmd`
spools. `minvmd` refuses and counts records past that, and they stay in the
guest's own spool. This keeps a VM that writes too much from pushing your
own records out of the host spool, whose size bound the two share. The
limit is per VM: several VMs that each write at the limit fill the shared
spool that many times faster.

The guest's records carry the guest's clock, which can run up to about a
tenth of a second behind your machine's. In a trace, a guest span under a
host span (the guest's `rpc` under `guest.shutdown`, or under a `cmd` when
the daemon runs in the VM) can therefore appear to start a little before
its parent.

## The local spool

Every finished span and log record also goes to a local file the moment it
ends, as long as telemetry is on. A collector is optional for this. If a
process crashes or a signal kills it, what already finished is on disk.

| | |
|---|---|
| Location | `$XDG_STATE_HOME/minimal/telemetry/spool`, by default `~/.local/state/minimal/telemetry/spool` |
| Inside a microVM | `/var/lib/minimal/telemetry/spool`, on the VM's state volume |
| Files | `<service>-<pid>-<start>.jsonl`, one per process, continued in `-1.jsonl`, `-2.jsonl` and so on every 4 MiB |
| Format | One OTLP-JSON export request per line, the shape a collector's file exporter writes |
| Permissions | The directory is readable by you only (0700), and so are the files (0600). minimal refuses a spool directory that belongs to another user or that group or other can access |
| Size | When a new file is opened, files older than 7 days are deleted, then the oldest ones until the directory is under about 46 MiB |

- `MINIMAL_OTEL_SPOOL=0` turns the spool off and leaves export on.
- `MINIMAL_OTEL_SPOOL_DIR=<dir>` puts every process's spool in `<dir>`. The
  size and age limits delete only spool files, named as above, and leave
  anything else in `<dir>` alone. If minimal refuses `<dir>` (wrong owner,
  or group or other can access it), it logs one warning naming `<dir>` and
  uses the default location instead. If it refuses the default location, it
  spools nothing.
- A daemon started with `--minimal-state-dir` keeps its spool under that
  directory, unless you set `MINIMAL_OTEL_SPOOL_DIR`.

Nothing uploads the spool today. The files stay on your disk until the limits
above delete them. `min bug` includes the daemon's spool (the newest files,
redacted) in its bundle, and the CLI's and `minvmd`'s spools too. On macOS
the daemon is the microVM guest's, so the bundle holds the guest's spool.
`min bug` reads one host spool directory: `MINIMAL_OTEL_SPOOL_DIR` as set in
the shell that runs it, or the default location. A `minvmd` or CLI that
spools somewhere else because its own environment says so, such as a service
unit's, is not in the bundle.

## Recorded data

Each process names itself with these resource attributes: `service.name`
(`minimal-cli`, `minimald` or `minvmd`), `service.version`, a random
`service.instance.id` chosen at start, `os.type`, `host.arch` and
`process.pid`. The machine id is never used.

Spans and log records contain what minimal's own logs contain at `info`
level and above, from every part of minimal. That includes command and
request names, session ids and names, paths (which can include your user
name), host names, timing, and errors.

- The command line of a session exec goes on its span only after the secret
  scrubber that `min bug` also uses runs over it. The scrubber masks
  `Authorization` and `Proxy-Authorization` header values, credentials in
  URLs, and tokens with well-known prefixes (GitHub, `sk-`, Slack, AWS access
  key ids). It also masks the values of `key=value` pairs and long options
  whose name looks secret, such as `TOKEN=...` or `--password ...`. Other
  values on a command line, such as program text passed inline, go on the
  span as typed.
- A git remote on a checkout span appears without its user name, password,
  query or fragment. `git@github.com:org/repo.git` appears as
  `github.com:org/repo.git`.
- The line that reports telemetry's own start-up names each endpoint as
  `scheme://host:port` only.

### What a box sees

This page is about minimal's own telemetry. A box exports only what you
configure for the software in it, and minimal adds nothing to that.

A box with telemetry on gets one variable, `TRACEPARENT`, so a `min` you run
inside the box joins the same trace. A box joins a trace only when
minimal's own export is on. Propagation that does not need minimal's export
is out of scope here. The box does
not get an endpoint, a header or any other telemetry setting from your
environment. An interactive attach shell gets nothing. The daemon's span for
a request from a box names the box and session as the daemon knows them,
not as the box says.

The guest's kernel command line holds the on/off switches and
`TRACEPARENT`. Every process in the VM, boxes included, can read the kernel
command line. Endpoints, headers and resource attributes never go there.
(Before the release with the VM channel, the endpoints that passed the rule
in [Sessions in a microVM](#sessions-in-a-microvm) are there too.)

### Diagnostic bundles

`min bug` and the daemon's diagnostic bundle report the
`MINIMAL_OTEL_EXPORTER_OTLP_*` variables and any variable ending in
`_HEADERS` without their values. `MINIMAL_TELEMETRY`, `MINIMAL_OTEL_SPOOL`
and `MINIMAL_OTEL_FILTER` appear with their values.

Spool files in a bundle lose every exporter header value you configured,
wherever it appears, and the bare token of a value such as
`Bearer%20<token>`. The values come from the shell that runs `min bug` and,
on Linux and macOS, from the process that wrote each file while it still runs, so a
header the daemon or `minvmd` started with is removed too. Spool files also
lose the value of any attribute whose name looks secret or names a header,
such as `api_key`, `password` or `http.request.header.x-honeycomb-team`. A
spool line that is not valid JSON stays out of the bundle.

The bundle's `host/telemetry.json` records how telemetry was set in the
shell that ran `min bug`. A running daemon keeps the settings it started
with, so its state can differ. The file records:

- Whether it was on, and which variable decided that.
- Whether each signal was exported, and its endpoint as `scheme://host:port`.
- Whether the spool was on, and its directory: the only spool directory the
  bundle read.
- The trace id of the newest command in the CLI's spool, to look up in your
  collector.

With telemetry off, that file is the only change to `min bug`.

## Turning it off

| Scope | How |
|---|---|
| One command | Unset `MINIMAL_TELEMETRY`, or set `DO_NOT_TRACK` to any value, or set `OTEL_SDK_DISABLED=true`. |
| The daemons | Run `min stop` and start the next command from a shell where telemetry is off. A running daemon keeps the setting it started with, and records nothing for a command that runs with telemetry off. |
| One signal | `MINIMAL_OTEL_TRACES_EXPORTER=none` or `MINIMAL_OTEL_LOGS_EXPORTER=none`. |
| The spool only | `MINIMAL_OTEL_SPOOL=0`. |
| One project | There is no setting in `minimal.toml`. Set the variables in that project's shell environment. The daemons are shared by all your projects, so they follow whichever command started them. |

`DO_NOT_TRACK` follows the [Console Do Not Track](https://consoledonottrack.com/)
convention. Any non-empty value turns telemetry off, `0` and `false`
included. `OTEL_SDK_DISABLED` turns it off only when it is `true`. `1` does
not.

## Cost

Background threads send the records, and each export request gives up
after 3 seconds. A process waits for unsent records only when it exits, and
only for a bounded time:

| Process | Wait at exit |
|---|---|
| `min` | 200 ms |
| `minimald` | up to 2 s for running tasks, then up to 5 s for the export |
| `minvmd` | up to 2 s |
| `minvmd run`, for the guest's last records once the VM is gone | up to 2 s |
| The guest daemon, before it acknowledges a stop | up to 1.5 s |
| `minvmd stop`, for the guest to power off after it acknowledges | up to 3 s |

On a stop, the guest's records reach the host before the VM goes down,
within that 3 s grace after the guest acknowledges. The guest's last
spans, among them the span of the stop request itself, end only when it
acknowledges, so they are sent after the acknowledgement.

If the collector is down, records that did not get through are still in the
spool. If its port refuses connections, each `min` command spends about
200 ms on the exit wait. The first command that starts a daemon can wait
several seconds longer when the collector accepts connections but never
answers.

## Troubleshooting

**Check what telemetry decided.** Each process logs one line when telemetry
starts:

```text
telemetry on: traces -> http://localhost:4318, logs -> http://localhost:4318, spool -> /home/you/.local/state/minimal/telemetry/spool
```

`off` in place of an endpoint means minimal does not export that signal.
`off` for the spool means the spool is off. Where to find the line:

- `min`: run the command with `RUST_LOG=info` (the terminal shows only
  warnings by default). The line is also in the command's spool file.
- `minimald` on your machine: in its spool file, `minimald-<pid>-*.jsonl`.
- `minvmd`: in `~/.local/state/minimal/logs/minvmd.log`.
- The guest daemon writes it to the VM's console log,
  `~/.local/state/minimal/providers/local-minvmd0/boot.log` for the default
  VM.

No line at all means telemetry is off for that process: check
`MINIMAL_TELEMETRY`, `DO_NOT_TRACK` and `OTEL_SDK_DISABLED`, and for a daemon,
the environment of the command that started it.

**"the OTLP exporter for traces could not be built".** The warning ends with
the whole error chain, and export of that signal is off for the process while
the spool keeps working. The common cause is an `https://` endpoint on a
machine without CA certificates:

```text
telemetry: the OTLP exporter for traces could not be built (building its HTTP client: builder error: unexpected error: No CA certificates were loaded from the system); traces export is off for this process
```

Install CA certificates, or use an `http://` endpoint.

**"refusing to export traces".** Plain `OTEL_EXPORTER_OTLP_HEADERS` is
present in that process's environment and the endpoint came from a
`MINIMAL_` variable. See [Authentication](#authentication).

**Nothing from the VM.** Look in the VM's `boot.log` for the start-up line
(`traces -> vsock:7353`) and any warning. A guest that cannot reach the
host's receiver says so once and keeps spooling. Then look in `minvmd.log`
for "bound the guest telemetry door" and for "guest telemetry door counts":
the guest's records reach your collector through `minvmd`, so a collector
problem shows on the host side.

**Records reach the spool but not the collector.** A base endpoint gets
`/v1/traces` and `/v1/logs` appended. A per-signal endpoint goes out as
given, so it needs the full path. Check that headers your collector needs are in
`MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` for a `MINIMAL_` endpoint, or in
`OTEL_EXPORTER_OTLP_HEADERS` for a plain one.

**A change did not take effect.** Run `min stop`: the daemons still have the
settings they started with.

## Privacy

minimal does not send telemetry to its authors. Nothing leaves your machine
or reaches your disk unless you set `MINIMAL_TELEMETRY`. Then records go
only to the endpoints you name and to the spool on your own disk.
`DO_NOT_TRACK` and `OTEL_SDK_DISABLED=true` always win over every other
setting in the process that has them. A command run with either tells the
daemon to record nothing for it. Request headers stay on your machine,
boxes receive only a trace id, and the secret scrubbing above applies to
what minimal exports. Exported records still
contain paths, session names, host names and command lines. Send them only
to a collector you trust with that.

## The daemon's own switch

`minimald` reads the telemetry switches from its own environment, which is
the environment of the `min` that started it. A later `min` that opts in
(`MINIMAL_TELEMETRY=1`) does not turn a running daemon on. The daemon's own
`MINIMAL_TELEMETRY` (an explicit `0`, or unset) wins, so the daemon keeps
exporting nothing and spooling nothing while that CLI spools its own
command. A running daemon that is on records nothing for a command whose
`min` is off. That command sends an opt-out with each request and no trace
id. minimal does not print a warning, because it exports nothing for that command. This is review item S7 as decided on 2026-10-04 and tightened on
2026-10-05. Scenario 785 pins each phase.

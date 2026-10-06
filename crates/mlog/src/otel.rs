//! Opt-in OpenTelemetry export for minimal's processes (spec 25: traces and
//! logs to a collector the user runs).
//!
//! Opt-in (spec 25 TEL-001, "bring your own collector"): export needs
//! an explicit `MINIMAL_TELEMETRY=1`. Standard `OTEL_*` variables are ambient
//! (a developer's shell or a CI runner often sets them for its own apps), so
//! `min` never exports just because they are set. Once enabled, the endpoint
//! comes from `MINIMAL_OTEL_EXPORTER_OTLP_[TRACES_|LOGS_]ENDPOINT` first and
//! the plain `OTEL_EXPORTER_OTLP_*` names second (the Docker CLI pattern):
//! any `MINIMAL_` endpoint, base or per-signal, beats every plain one.
//! `OTEL_SDK_DISABLED=true` and `DO_NOT_TRACK` set to any non-empty value
//! always win. When off, [`span_layer`] and [`log_layer`] return `None` and
//! nothing else happens: no thread, no exporter, no filter, no network, and
//! every other function here is a no-op.
//!
//! When on, spans export through `tracing-opentelemetry` and events through
//! the OTel logs bridge, over OTLP/HTTP (protobuf), batched on the SDK's own
//! threads. [`align`] makes a span's OTel ids (and sampling flag) the ids
//! minimal logs and propagates as `TRACEPARENT`. [`shutdown`] flushes with one
//! overall deadline; it also runs from an `atexit` hook, so `process::exit`
//! paths flush too.
//!
//! Also when on, and whether or not an endpoint is configured, every finished
//! span and exported log record is appended as it happens to a local
//! OTLP-JSON spool under `<state>/telemetry/spool/` (TEL-014; see
//! [`spool`]), so a crash, a SIGKILL or a hang keeps what already finished
//! and nothing waits on the network. `MINIMAL_OTEL_SPOOL=0` turns only the
//! spool off.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use opentelemetry::trace::{
    SpanContext, SpanId, TraceContextExt as _, TraceFlags, TraceId, TraceState, TracerProvider as _,
};
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_otlp::WithHttpConfig as _;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use reqwest::Url;
use reqwest::header::{HeaderName, HeaderValue};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::Filtered;

mod forward;
pub use forward::{
    Destination as ForwardDestination, FORWARD_ENV, MAX_FRAME_BYTES as FORWARD_MAX_FRAME_BYTES,
    Signal, classify_line, dropped as forward_dropped, queued as forward_queued,
    take_receiver as take_forward_receiver,
};
mod spool;
pub use spool::is_spool_file;
mod switches;

/// The providers installed by [`layers`], kept so [`shutdown`] can flush them.
static PROVIDERS: OnceLock<(Option<SdkTracerProvider>, Option<SdkLoggerProvider>)> =
    OnceLock::new();
static SHUT_DOWN: AtomicBool = AtomicBool::new(false);

/// Per-export timeout for the OTLP HTTP exporter: a slow or blackholed
/// collector costs at most this per batch, never a command's latency.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(3);

/// The exit flush of a short-lived CLI process. A `min ls` lives ~40 ms; its
/// only export attempt is the one at exit, so with the collector down it
/// waited the whole bound (2035 ms against 36 ms) on
/// every invocation. Telemetry that cannot deliver must cost nothing
/// (spec 25 principle 8): a reachable collector answers in a few ms, and
/// what this bound cuts off is in the spool already. The daemons keep their
/// longer bounds (they flush once, at shutdown).
pub const CLI_EXIT_FLUSH: Duration = Duration::from_millis(200);

/// The bound [`flush_at_exit`] uses, in milliseconds (see [`set_exit_flush`]).
static EXIT_FLUSH_MS: AtomicU64 = AtomicU64::new(2000);

/// This process's spool, when telemetry is on and the spool is not switched
/// off; kept so [`relocate_spool`] can move it once the state directory is
/// known.
static SPOOL: OnceLock<Option<std::sync::Arc<spool::SpoolFile>>> = OnceLock::new();

/// What [`init`] has to say, emitted by [`report_init`] once a subscriber is
/// installed (init runs before it, so it cannot log itself).
static INIT_LOG: OnceLock<InitLog> = OnceLock::new();

#[derive(Debug, Default)]
struct InitLog {
    /// One line per signal whose exporter could not be built.
    warnings: Vec<String>,
    /// One line describing the export that was installed, if any.
    summary: Option<String>,
}

/// Log what [`init`] decided: a warning per OTLP exporter that could not be
/// built (the signal's export is then off; before this it was swallowed, so
/// a process could be silently without export), and one info line naming the
/// endpoints and spool in use. A no-op when nothing was installed and nothing
/// failed. Call right after the global subscriber is installed.
pub fn report_init() {
    let Some(log) = INIT_LOG.get() else {
        return;
    };
    for w in &log.warnings {
        tracing::warn!("{w}");
    }
    if let Some(s) = &log.summary {
        tracing::info!("{s}");
    }
}

/// Where this process's spool files go: the directory its open spool writes
/// to when the spool is on and has one (after [`relocate_spool`], a pinned
/// `MINIMAL_OTEL_SPOOL_DIR`, or a fallback from a refused directory), else
/// `MINIMAL_OTEL_SPOOL_DIR` when set and not empty, else `default` (the
/// caller's `<state>/telemetry/spool`). A diagnostic bundle reads this, so it
/// finds the files the writer wrote, also when telemetry is off now but a
/// pinned spool from an earlier run is on disk.
pub fn spool_dir_or(default: std::path::PathBuf) -> std::path::PathBuf {
    let live = SPOOL.get().and_then(|f| f.as_ref()).and_then(|f| f.dir());
    pick_spool_dir(live, spool::dir_override(), default)
}

/// [`spool_dir_or`]'s rule over its inputs: the open spool's directory,
/// else the pinned one, else the default.
fn pick_spool_dir(
    live: Option<std::path::PathBuf>,
    pinned: Option<std::path::PathBuf>,
    default: std::path::PathBuf,
) -> std::path::PathBuf {
    live.or(pinned).unwrap_or(default)
}

/// Move this process's spool to `dir` (`<state>/telemetry/spool`): the
/// microVM's `/init` has no home when telemetry initialises and mounts its
/// state volume later, and a daemon given `--minimal-state-dir` keeps
/// everything under that directory. A no-op when the spool is off, already
/// there, or placed by an explicit `MINIMAL_OTEL_SPOOL_DIR`: that variable
/// names where the spool goes (tests, isolated daemons), and the state
/// directory only replaces the home default. Logs the move, so a daemon's log
/// says where its spool is.
pub fn relocate_spool(dir: std::path::PathBuf) {
    if let Some(Some(f)) = SPOOL.get()
        && relocate_unless_pinned(f, &dir, spool::dir_override().is_some())
    {
        tracing::info!(dir = %dir.display(), "telemetry spool relocated");
    }
}

/// Append one OTLP-JSON line to this process's spool for another process's
/// records: a line carries its own resource, so a guest daemon's records
/// forwarded to the VM host (TEL-034) sit in the host's `minvmd-<pid>-*.jsonl`
/// beside the host's own, and `min bug` carries them. The caller writes the
/// line (`minvmd` re-serializes what it parsed and stamped), never passes
/// through text it did not check. A no-op when telemetry or the spool is
/// off. A trailing newline is dropped; the spool adds one.
///
/// Foreign lines have no spool budget of their own: they share this
/// process's spool, its 50 MiB size bound and its pruning order (expired
/// files first, then the oldest), with the host's own records. What bounds
/// them is the caller's: `minvmd` charges each VM, across reconnects, the
/// larger of a line's frame and the stamped line it writes here, at most
/// 64 KiB a second after a 4 MiB burst
/// (`minvmd::guest_telemetry::GUEST_BYTES_PER_SEC` and `GUEST_BURST_BYTES`).
/// So one VM that floods writes a spool's worth in no less than
/// (50 - 4) MiB / 64 KiB/s = 736 s. The budget is per VM and this spool is
/// shared: N VMs flooding at once take (50 - 4N) x 16 / N seconds, 336 s
/// for two.
pub fn spool_foreign_line(line: &str) {
    if let Some(Some(f)) = SPOOL.get() {
        f.append(line.trim_end_matches(['\n', '\r']));
    }
}

/// What [`forward_request`] did with a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forwarded {
    /// The signal's export is off in this process: nothing was sent.
    Off,
    /// A request carrying this many records' lines went out.
    Sent(usize),
}

/// A forward destination for one signal, built once per process: the
/// host's endpoint, the client with its header rule, and the plain headers
/// the OTLP exporter itself would add for a plain endpoint.
struct ForwardTarget {
    url: Url,
    client: ExportClient,
    plain: Vec<(HeaderName, HeaderValue)>,
}

/// [`forward_target`]'s answer, kept per signal for the process's life.
type ForwardTargetResult = Result<Option<std::sync::Arc<ForwardTarget>>, String>;

/// The target for `signal`, from this process's switches: `Ok(None)` when
/// the signal's export is off (no endpoint, `none`, or the header rule
/// refused it), `Err` when the endpoint value or the client was refused.
fn forward_target(signal: Signal) -> ForwardTargetResult {
    static TARGETS: OnceLock<
        std::sync::Mutex<std::collections::HashMap<Signal, ForwardTargetResult>>,
    > = OnceLock::new();
    let targets = TARGETS.get_or_init(Default::default);
    let mut targets = targets
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    targets
        .entry(signal)
        .or_insert_with(|| {
            let d = read_switches().decide();
            let sd = match signal {
                Signal::Traces => d.traces,
                Signal::Logs => d.logs,
            };
            let name = signal.switch_name();
            let Some(url) = export_url(sd.export, name) else {
                return Ok(None);
            };
            let url = url?;
            let prefixed = sd.export.prefixed();
            let client = ExportClient::new(&url, name, prefixed, env_nonempty)?;
            let plain = if prefixed {
                Vec::new()
            } else {
                // As the exporter reads them: the signal's own headers after
                // the base ones, so a name in both takes the signal's value.
                let mut h = env_nonempty("OTEL_EXPORTER_OTLP_HEADERS")
                    .map(|v| parse_headers(&v))
                    .unwrap_or_default();
                h.extend(
                    env_nonempty(&format!("OTEL_EXPORTER_OTLP_{name}_HEADERS"))
                        .map(|v| parse_headers(&v))
                        .unwrap_or_default(),
                );
                h
            };
            Ok(Some(std::sync::Arc::new(ForwardTarget {
                url,
                client,
                plain,
            })))
        })
        .clone()
}

/// Send `body`, one OTLP/JSON request for `signal` that carries `records`
/// lines of another process's records (a guest daemon's, TEL-034), to this
/// process's endpoint for `signal`, under this process's switches and
/// header rule: the request goes where this process's own records of that
/// signal go, with the headers that endpoint gets, and nowhere when that
/// export is off. The caller serializes `body` from what it parsed and
/// checked (`minvmd` builds it from the parsed, stamped requests), so the
/// collector reads the bytes this host's parser read; a body without the
/// request shape for `signal`, and an empty one, is not sent. Blocking (at
/// most [`EXPORT_TIMEOUT`]); not for an async context.
pub fn forward_request(signal: Signal, body: String, records: usize) -> Result<Forwarded, String> {
    let Some(target) = forward_target(signal)? else {
        return Ok(Forwarded::Off);
    };
    if records == 0 {
        return Ok(Forwarded::Sent(0));
    }
    if forward::classify_line(&body) != Some(signal) {
        return Err(format!("not one {} request", signal.key()));
    }
    let n = records;
    let mut headers = reqwest::header::HeaderMap::new();
    for (k, v) in &target.plain {
        headers.insert(k.clone(), v.clone());
    }
    target.client.rewrite(&mut headers);
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let response = target
        .client
        .inner
        .post(target.url.clone())
        .headers(headers)
        .body(body)
        .send()
        .map_err(|e| error_chain(&e))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("the collector answered HTTP {status}"));
    }
    Ok(Forwarded::Sent(n))
}

/// Close this process's spool file and stop spooling: later records are
/// dropped, as a deferred spool drops them, until [`relocate_spool`] names a
/// directory again. A no-op when telemetry or the spool is off, or the spool
/// has no directory. It exists so the microVM guest can remount its state
/// volume read-only at a clean stop: the spool lives on that volume, and a
/// file still open for writing defeats the read-only remount.
/// Call it after the last record worth keeping, right before the remount.
pub fn release_spool() {
    if let Some(Some(f)) = SPOOL.get() {
        f.release();
    }
}

/// [`relocate_spool`]'s rule for one spool: move `f` to `dir` unless its
/// location is `pinned` (by `MINIMAL_OTEL_SPOOL_DIR`) or it is there already.
/// True when it moved.
fn relocate_unless_pinned(f: &spool::SpoolFile, dir: &std::path::Path, pinned: bool) -> bool {
    if pinned || f.dir().as_deref() == Some(dir) {
        return false;
    }
    f.relocate(dir.to_path_buf());
    true
}

/// Targets never exported, whatever `MINIMAL_OTEL_FILTER` or `RUST_LOG` say:
/// the exporter's own HTTP stack (it runs on threads the SDK's suppression
/// scope does not cover, so its events would feed back into export) and the
/// SDK itself. A target is in the list when it starts with one of these, the
/// way an `EnvFilter` directive matches (`hyper` covers `hyper_util::client`).
const NEVER_EXPORT: &[&str] = &[
    "hyper",
    "hyper_util",
    "h2",
    "reqwest",
    "tower",
    "opentelemetry",
    "opentelemetry_sdk",
    "opentelemetry_otlp",
    "opentelemetry_http",
];

/// `name`'s value when it is set and not empty, as the environment holds it:
/// nothing is decoded here, so a value that is not UTF-8 is present (langsec
/// F4; `std::env::var` read it as absent).
fn env_os(name: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

/// `name`'s value when it is set, not empty and UTF-8 (the header variables,
/// which the exporter reads the same way).
fn env_nonempty(name: &str) -> Option<String> {
    env_os(name)?.into_string().ok()
}

fn read_switches() -> switches::Switches {
    switches::Switches::read(env_os)
}

/// The explicit opt-in: `MINIMAL_TELEMETRY` truthy, and neither
/// `OTEL_SDK_DISABLED=true` nor `DO_NOT_TRACK` set.
pub fn telemetry_enabled() -> bool {
    read_switches().enabled()
}

/// Why an endpoint value was refused ([`parse_endpoint`]): fixed text, as
/// the value may carry a credential and the refusal is logged.
const NOT_A_URL: &str = "is not an absolute http:// or https:// URL";
/// Why a base endpoint was refused ([`with_signal_path`]).
const BASE_HAS_QUERY: &str = "has a query or fragment, so the signal path cannot be appended to it";

/// The one recognizer for an endpoint value, run where the value enters
/// ([`export_url_from`]) and with the parser reqwest applies at send
/// (`url::Url`, which reqwest re-exports), so nothing downstream reads the
/// raw text and build and send cannot disagree (review F7 to F9: `http::Uri`
/// accepted ports and credentials every send then rejected, and a hand
/// split of the string printed part of a password). An endpoint is an
/// absolute `http://` or `https://` URL; the error is [`NOT_A_URL`].
fn parse_endpoint(raw: &str) -> Result<Url, &'static str> {
    #[expect(
        clippy::map_err_ignore,
        reason = "the refusal is fixed text by contract: the parse error quotes the \
                  value, which may carry a credential, and the refusal is logged"
    )]
    let url = Url::parse(raw).map_err(|_| NOT_A_URL)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(NOT_A_URL);
    }
    Ok(url)
}

/// `base` with the OTLP signal path (`/v1/traces`, `/v1/logs`) appended
/// inside the URL grammar: a trailing `/` is not doubled and a path prefix
/// is kept, as the string form did. A base with a query or fragment is
/// refused ([`BASE_HAS_QUERY`]): concatenation put `/v1/<signal>` into the
/// query (review F10), and the OTLP spec gives such a base no meaning.
fn with_signal_path(mut base: Url, signal: &str) -> Result<Url, &'static str> {
    if base.query().is_some() || base.fragment().is_some() {
        return Err(BASE_HAS_QUERY);
    }
    base.path_segments_mut()
        .map_err(|()| NOT_A_URL)?
        .pop_if_empty()
        .extend(["v1", &signal.to_ascii_lowercase()]);
    Ok(base)
}

/// The OTLP/HTTP URL `export` names for one signal (`"TRACES"` / `"LOGS"`):
/// the per-signal endpoint as given, else the base endpoint plus the signal
/// path (the OTLP spec's rule), with every `MINIMAL_` name tried before any
/// plain one ([`switches::Switches::decide`], TEL-004). `None` when the
/// signal is not exported or its variable is not set; `Some(Err(warning))`
/// when the value is refused ([`parse_endpoint`], [`with_signal_path`]; a
/// value that is not UTF-8 is not a URL): the warning names the variable and the rule, never the
/// value, and the signal is then not exported (it does not fall back to
/// another variable).
fn export_url_from(
    export: switches::Export,
    signal: &str,
    var: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<Result<Url, String>> {
    use switches::{Export, Pick};
    let (pick, name) = match export {
        Export::Off => return None,
        Export::Signal(p) => (p, format!("OTEL_EXPORTER_OTLP_{signal}_ENDPOINT")),
        Export::Base(p) => (p, "OTEL_EXPORTER_OTLP_ENDPOINT".to_owned()),
    };
    let name = match pick {
        Pick::Prefixed => format!("MINIMAL_{name}"),
        Pick::Plain => name,
    };
    let raw = var(&name)?;
    let url = raw
        .to_str()
        .ok_or(NOT_A_URL)
        .and_then(parse_endpoint)
        .and_then(|url| match export {
            Export::Base(_) => with_signal_path(url, signal),
            Export::Off | Export::Signal(_) => Ok(url),
        });
    Some(url.map_err(|why| {
        format!(
            "telemetry: {name} {why}; {} export is off for this process",
            signal.to_ascii_lowercase()
        )
    }))
}

/// [`export_url_from`] over this process's environment.
fn export_url(export: switches::Export, signal: &str) -> Option<Result<Url, String>> {
    export_url_from(export, signal, env_os)
}

/// The telemetry decision a supervisor hands a guest that cannot read this
/// process's environment (minvmd, over the kernel command line): what the
/// switches settle to, never the variables they were settled from, so the
/// guest cannot decide again over a different input and reach an endpoint
/// the host had overridden. Read through `var` like [`Switches::read`]
/// (an empty value counts as unset); nothing here touches the process
/// environment.
///
/// [`Switches::read`]: switches::Switches::read
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuestExports {
    /// Finished records are spooled locally: `MINIMAL_OTEL_SPOOL` is not
    /// false and at least one signal is not switched off (with both off,
    /// nothing is spooled either way).
    pub spool: bool,
    pub traces: GuestSignal,
    pub logs: GuestSignal,
}

/// One signal's part of a [`GuestExports`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuestSignal {
    /// The signal's exporter is `none` (`MINIMAL_OTEL_<signal>_EXPORTER`
    /// first, else `OTEL_<signal>_EXPORTER`).
    pub off: bool,
    /// The OTLP/HTTP URL the signal exports to, as [`export_url`] builds
    /// it: the per-signal endpoint as given, else the base endpoint plus the
    /// signal path, in the recognizer's canonical form. `None` when nothing
    /// is exported: telemetry off, the exporter `none`, no endpoint, or a
    /// `MINIMAL_` endpoint refused for ambient plain headers. `Some(Err(w))`
    /// when the configured value was refused ([`export_url_from`]): the
    /// supervisor logs `w` (it names the variable and the rule, never the
    /// value) and the signal stays off in the guest.
    pub url: Option<Result<String, String>>,
}

/// The decision [`GuestExports`] describes, over the variables `var` gives.
pub fn guest_exports(var: impl Fn(&str) -> Option<String>) -> GuestExports {
    // The recognizers read `OsString`s (a non-UTF-8 value is present, never a
    // URL); a supervisor's environment is already text, so lift it.
    let var = |name: &str| {
        var(name)
            .filter(|v| !v.is_empty())
            .map(std::ffi::OsString::from)
    };
    let switches = switches::Switches::read(var);
    let d = switches.decide();
    // A refused endpoint (`Some(Err(_))`) leaves the signal off in the guest:
    // the host never hands down a value its own exporter would not send to.
    let signal = |sw: switches::SignalSwitches, sd: switches::SignalDecision, name| GuestSignal {
        off: sw.off,
        url: export_url_from(sd.export, name, var).map(|r| r.map(|u| u.to_string())),
    };
    GuestExports {
        spool: d.traces.spool || d.logs.spool,
        traces: signal(switches.traces, d.traces, "TRACES"),
        logs: signal(switches.logs, d.logs, "LOGS"),
    }
}

/// The OTLP/HTTP URL for one signal, when export is enabled and an accepted
/// endpoint is configured.
fn signal_url(signal: &str) -> Option<String> {
    let d = read_switches().decide();
    let export = if signal == "TRACES" {
        d.traces.export
    } else {
        d.logs.export
    };
    export_url(export, signal)?
        .ok()
        .map(|u| u.as_str().to_owned())
}

/// Whether trace export is configured for this process (read from the env).
pub fn traces_enabled() -> bool {
    signal_url("TRACES").is_some()
}

/// Whether log export is configured for this process (read from the env).
pub fn logs_enabled() -> bool {
    signal_url("LOGS").is_some()
}

/// Whether a tracer is installed (cheap; no env reads). Callers adopt an
/// inbound `TRACEPARENT` only when this is true, so a process with export off
/// keeps minting its own ids exactly as before.
pub fn exporting() -> bool {
    PROVIDERS.get().is_some_and(|p| p.0.is_some())
}

/// Whether `meta` is from the exporter's own stack ([`NEVER_EXPORT`]).
fn exportable(meta: &tracing::Metadata<'_>) -> bool {
    let target = meta.target();
    !NEVER_EXPORT.iter().any(|t| target.starts_with(t))
}

/// The export filter: what `MINIMAL_OTEL_FILTER` (default `info`) admits,
/// and of that only what is not from the exporter's own stack.
pub type ExportFilter<S> = tracing_subscriber::filter::combinator::And<
    EnvFilter,
    tracing_subscriber::filter::FilterFn<fn(&tracing::Metadata<'_>) -> bool>,
    S,
>;

/// The filter for exported spans and events: `MINIMAL_OTEL_FILTER` or
/// `info`, and then never [`NEVER_EXPORT`]. The exclusion is a filter of its
/// own after the user's rather than `=off` directives in it: an `EnvFilter`
/// lets the most specific directive win, so `hyper_util::client=trace` beside
/// `hyper_util=off` let the stack back in.
fn export_filter<S>() -> ExportFilter<S> {
    use tracing_subscriber::filter::FilterExt as _;
    let user =
        EnvFilter::try_from_env("MINIMAL_OTEL_FILTER").unwrap_or_else(|_| EnvFilter::new("info"));
    let own: fn(&tracing::Metadata<'_>) -> bool = exportable;
    // The hint keeps the user filter's: `And` takes the lower of the two,
    // and no hint at all would be none for the pair.
    user.and(
        tracing_subscriber::filter::filter_fn(own)
            .with_max_level_hint(tracing_subscriber::filter::LevelFilter::TRACE),
    )
}

/// Silence the OTel SDK's own error events on a console or file log filter,
/// so a down collector does not print ERROR lines into `min`'s output. A
/// no-op for anything else the filter shows.
#[must_use]
pub fn quiet(mut filter: EnvFilter) -> EnvFilter {
    for t in [
        "opentelemetry",
        "opentelemetry_sdk",
        "opentelemetry_otlp",
        "opentelemetry_http",
    ] {
        if let Ok(d) = format!("{t}=off").parse() {
            filter = filter.add_directive(d);
        }
    }
    filter
}

/// A random id (`service.instance.id`), drawn once per process by [`init`]
/// for the resource both providers share. Never the machine id
/// (TEL-006: not the host resource detector, which exports it).
///
/// The bytes come from the kernel's generator through a system call
/// ([`os_random`]), which needs no `/dev`: the microVM guest's daemon is
/// pid 1 and starts telemetry before `/dev` is mounted. Only when that call
/// fails is the id the time XOR the pid, which is unique enough to tell
/// processes apart but not random (TEL-006 asks for random).
fn instance_id() -> String {
    let mut b = [0u8; 16];
    if !os_random(&mut b) {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        b = (t ^ u128::from(std::process::id())).to_le_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Fill `b` from the kernel's random generator: getrandom(2) on Linux (it
/// blocks only until the pool is first seeded), getentropy(2) on macOS,
/// `/dev/urandom` elsewhere. False when that fails.
fn os_random(b: &mut [u8; 16]) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut done = 0;
        while let Some(rest) = b.get_mut(done..) {
            if rest.is_empty() {
                return true;
            }
            // SAFETY: `rest` is a writable buffer of `rest.len()` bytes for
            // the duration of the call; flags 0 reads the urandom pool.
            let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
            match usize::try_from(n) {
                Ok(n) if n > 0 => done += n,
                _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {}
                _ => return false,
            }
        }
        false
    }
    #[cfg(target_vendor = "apple")]
    {
        // SAFETY: `b` is a writable 16-byte buffer, under getentropy's
        // 256-byte limit.
        unsafe { libc::getentropy(b.as_mut_ptr().cast(), b.len()) == 0 }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    {
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, b))
            .is_ok()
    }
}

/// This process's resource; [`init`] builds it once and gives both
/// providers a clone, so traces and logs name the same instance.
fn resource(service_name: &str) -> opentelemetry_sdk::Resource {
    opentelemetry_sdk::Resource::builder()
        .with_service_name(service_name.to_string())
        .with_attribute(opentelemetry::KeyValue::new(
            "service.instance.id",
            instance_id(),
        ))
        .with_attribute(opentelemetry::KeyValue::new(
            "os.type",
            std::env::consts::OS,
        ))
        .with_attribute(opentelemetry::KeyValue::new(
            "host.arch",
            std::env::consts::ARCH,
        ))
        .with_attribute(opentelemetry::KeyValue::new(
            opentelemetry_semantic_conventions::attribute::SERVICE_VERSION,
            version::LONG_VERSION,
        ))
        .with_attribute(opentelemetry::KeyValue::new(
            "process.pid",
            i64::from(std::process::id()),
        ))
        .build()
}

/// The span layer, already filtered by the export filter.
pub type SpanLayer<S> = Filtered<
    tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::SdkTracer>,
    ExportFilter<S>,
    S,
>;
/// The event (logs) layer, already filtered by the export filter.
pub type LogLayer<S> = Filtered<
    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge<
        SdkLoggerProvider,
        opentelemetry_sdk::logs::SdkLogger,
    >,
    ExportFilter<S>,
    S,
>;

extern "C" fn flush_at_exit() {
    shutdown(Duration::from_millis(EXIT_FLUSH_MS.load(Ordering::Relaxed)));
}

/// Bound the flush the `atexit` hook runs on a `process::exit` path (the
/// default is 2 s). The CLI sets [`CLI_EXIT_FLUSH`] so an exit through
/// `process::exit` costs no more than its normal return does.
pub fn set_exit_flush(timeout: Duration) {
    EXIT_FLUSH_MS.store(
        u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}

/// `url` as `scheme://host[:port]`, without userinfo, path, query or
/// fragment: the form an endpoint is logged in. The summary line [`init`]
/// leaves for [`report_init`] goes to the console, the spool and the
/// collector, and an endpoint's path or query can carry an ingest key. Read
/// from the parsed URL, so a credential the user did not percent-encode
/// cannot leak a prefix (review F7).
///
/// ```text
/// https://u:p@collector.example:4318/v1/abc?k=v  ->  https://collector.example:4318
/// ```
fn endpoint_origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

/// Whether `url` is a plain `http://` endpoint, one no TLS is ever spoken to.
fn is_plain_http(url: &Url) -> bool {
    url.scheme() == "http"
}

/// The blocking HTTP client one OTLP exporter sends through to `url`.
///
/// Built here rather than left to `opentelemetry-otlp`, whose own client
/// loads the platform's CA roots and fails to build where there are none
/// (`rustls-platform-verifier`: "No CA certificates were loaded from the
/// system"). The microVM guest's `/init` initialises telemetry from an
/// initramfs that holds the daemon binary and nothing else, so the guest
/// daemon never had an exporter. A plain `http://`
/// endpoint needs no roots, so its client loads none; it also ignores the
/// proxy environment, since an `https://` proxy would need the roots it does
/// not have. An `https://` endpoint keeps reqwest's defaults: the platform
/// verifier and the environment's proxies.
///
/// Call off any tokio runtime: the blocking client owns one.
///
/// # Errors
///
/// The builder's error with its whole `source()` chain ([`error_chain`]):
/// reqwest's own `Display` says only "builder error", and
/// `opentelemetry-otlp`'s build error keeps no source to recover it from.
fn http_client(url: &Url) -> Result<reqwest::blocking::Client, String> {
    let b = reqwest::blocking::Client::builder().timeout(EXPORT_TIMEOUT);
    let b = if is_plain_http(url) {
        b.tls_certs_only(std::iter::empty()).no_proxy()
    } else {
        b
    };
    b.build()
        .map_err(|e| format!("building its HTTP client: {}", error_chain(&e)))
}

/// Headers in the `OTEL_EXPORTER_OTLP_HEADERS` format, as the OTLP exporter
/// reads them: comma-separated `key=value` pairs, each side trimmed and the
/// value percent-decoded (taken as given when it does not decode). A pair
/// with an empty side, or not a valid header, is skipped.
fn parse_headers(s: &str) -> Vec<(HeaderName, HeaderValue)> {
    s.split_terminator(',')
        .filter_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            let (k, v) = (k.trim(), v.trim());
            let v = percent_decode(v).unwrap_or_else(|| v.to_owned());
            if k.is_empty() || v.is_empty() {
                return None;
            }
            Some((k.parse().ok()?, HeaderValue::from_str(&v).ok()?))
        })
        .collect()
}

/// `s` with every `%XX` replaced by its byte; `None` when an escape is not
/// two hex digits (RFC 3986 `pct-encoded`, either case) or the result is
/// not UTF-8. Each digit is checked and decoded here, not by a number
/// parser, so no leniency of one (a sign, a space) widens what counts as an
/// escape.
fn percent_decode(s: &str) -> Option<String> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let (hi, lo) = (hex(bytes.next()?)?, hex(bytes.next()?)?);
            out.push((hi << 4) | lo);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).ok()
}

/// The HTTP client one OTLP exporter sends through: [`http_client`]'s, plus
/// the header rule for an endpoint named by a `MINIMAL_` variable (review
/// S3). The exporter adds the plain `OTEL_EXPORTER_OTLP_[<signal>_]HEADERS`
/// to every request by itself; for such an endpoint this client removes
/// those headers and sets `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` instead, so
/// a key meant for another backend never reaches it. For a plain endpoint it
/// changes nothing.
#[derive(Debug)]
struct ExportClient {
    inner: reqwest::blocking::Client,
    /// The plain headers' names, removed from each request.
    strip: Vec<HeaderName>,
    /// `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS`, set on each request (values
    /// marked sensitive, so `Debug` does not print them).
    add: Vec<(HeaderName, HeaderValue)>,
}

impl ExportClient {
    /// The client for `signal` (`"TRACES"` / `"LOGS"`) sending to `url`;
    /// `prefixed` when the endpoint came from a `MINIMAL_` variable. Reads
    /// the header variables through `var`.
    fn new(
        url: &Url,
        signal: &str,
        prefixed: bool,
        var: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, String> {
        let inner = http_client(url)?;
        if !prefixed {
            return Ok(Self {
                inner,
                strip: Vec::new(),
                add: Vec::new(),
            });
        }
        let plain = [
            "OTEL_EXPORTER_OTLP_HEADERS".to_owned(),
            format!("OTEL_EXPORTER_OTLP_{signal}_HEADERS"),
        ];
        let strip = plain
            .iter()
            .filter_map(|name| var(name))
            .flat_map(|v| parse_headers(&v))
            .map(|(k, _)| k)
            .collect();
        let add = var("MINIMAL_OTEL_EXPORTER_OTLP_HEADERS")
            .map(|v| parse_headers(&v))
            .unwrap_or_default()
            .into_iter()
            .map(|(k, mut v)| {
                v.set_sensitive(true);
                (k, v)
            })
            .collect();
        Ok(Self { inner, strip, add })
    }

    /// Apply the header rule to `request`'s headers.
    fn rewrite(&self, headers: &mut reqwest::header::HeaderMap) {
        for k in &self.strip {
            headers.remove(k);
        }
        for (k, v) in &self.add {
            headers.insert(k.clone(), v.clone());
        }
    }
}

// `HttpClient` is an `async_trait`; this is the signature it expands to.
impl opentelemetry_http::HttpClient for ExportClient {
    fn send_bytes<'life0, 'async_trait>(
        &'life0 self,
        mut request: opentelemetry_http::Request<opentelemetry_http::Bytes>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        opentelemetry_http::Response<opentelemetry_http::Bytes>,
                        opentelemetry_http::HttpError,
                    >,
                > + Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.rewrite(request.headers_mut());
        self.inner.send_bytes(request)
    }
}

/// The warning for a signal refused by the header rule: it
/// names the plain headers variable the exporter would have sent (the
/// signal's own first, as the exporter reads them) and the `MINIMAL_`
/// variable the endpoint came from.
fn refusal_warning(signal: &str, refused: switches::Export, own_headers: bool) -> String {
    let upper = signal.to_ascii_uppercase();
    let headers = if own_headers {
        format!("OTEL_EXPORTER_OTLP_{upper}_HEADERS")
    } else {
        "OTEL_EXPORTER_OTLP_HEADERS".to_owned()
    };
    let endpoint = match refused {
        switches::Export::Signal(_) => format!("MINIMAL_OTEL_EXPORTER_OTLP_{upper}_ENDPOINT"),
        _ => "MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT".to_owned(),
    };
    format!(
        "telemetry: refusing to export {signal}: {headers} is set but the endpoint comes from \
         {endpoint}; set MINIMAL_OTEL_EXPORTER_OTLP_HEADERS to send headers there"
    )
}

/// The warning for a signal whose `OTEL_<signal>_EXPORTER` list names an
/// exporter this build does not have (langsec F15); `prefixed` when the list
/// came from the `MINIMAL_` name. The value is a list of names, but the
/// message repeats none of it.
fn unsupported_exporter_warning(signal: &str, prefixed: bool) -> String {
    let prefix = if prefixed { "MINIMAL_" } else { "" };
    format!(
        "telemetry: {prefix}OTEL_{}_EXPORTER names an exporter this build does not have (otlp \
         and none are the ones recognised); {signal} are exported over OTLP as if it were unset",
        signal.to_ascii_uppercase()
    )
}

/// What a signal's build failure says in the log. The SDK's configuration
/// error repeats the endpoint it rejected (`invalid endpoint '<value>': ..`),
/// which can carry a key (review F8), so that variant becomes fixed text and
/// the endpoint's origin; the other variants carry no input.
fn build_error(url: &Url, e: &opentelemetry_otlp::ExporterBuildError) -> String {
    match e {
        opentelemetry_otlp::ExporterBuildError::InvalidConfiguration(_) => {
            format!(
                "the exporter rejected the endpoint at {}",
                endpoint_origin(url)
            )
        }
        other => error_chain(other),
    }
}

/// `e` and its `source()` chain on one line, joined by `": "`.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

static SERVICE: OnceLock<String> = OnceLock::new();

/// Build the exporters for `service_name` (`"minimal-cli"`, `"minimald"`, ...). Call
/// once per process, before assembling the global subscriber; then `.with()`
/// [`span_layer`] and [`log_layer`] unconditionally (`Option<Layer>` is a
/// layer). When export is off this installs nothing and both are `None`.
pub fn init(service_name: &str) {
    #[expect(
        clippy::let_underscore_must_use,
        reason = "a second init keeps the first value, which is the intent"
    )]
    let _ = SERVICE.set(service_name.to_string());
    let switches = read_switches();
    let d = switches.decide();
    let mut log = InitLog::default();
    for (signal, sd, sw) in [
        ("traces", d.traces, switches.traces),
        ("logs", d.logs, switches.logs),
    ] {
        if sw.unsupported_exporter {
            let prefixed = env_os(&format!(
                "MINIMAL_OTEL_{}_EXPORTER",
                signal.to_ascii_uppercase()
            ))
            .is_some();
            log.warnings
                .push(unsupported_exporter_warning(signal, prefixed));
        }
        if let Some(refused) = sd.refused {
            log.warnings
                .push(refusal_warning(signal, refused, sw.headers));
        }
    }
    let (traces_prefixed, logs_prefixed) = (d.traces.export.prefixed(), d.logs.export.prefixed());
    // A refused endpoint value is one warning and no export for its signal.
    let mut want = |signal: &str, export| match export_url(export, signal) {
        Some(Ok(url)) => Some(url),
        Some(Err(warning)) => {
            log.warnings.push(warning);
            None
        }
        None => None,
    };
    let want_traces = want("TRACES", d.traces.export);
    let want_logs = want("LOGS", d.logs.export);
    // The forward path (the microVM guest, TEL-034): `MINIMAL_OTEL_FORWARD`
    // names where the records go instead of an OTLP endpoint, so no exporter
    // is built beside it and any endpoint is ignored. A value that is not a
    // destination is one warning and no forwarding. Only with the opt-in and
    // no veto, like everything else; a signal switched off stays off.
    let forward = match env_nonempty(forward::FORWARD_ENV) {
        Some(v) if switches.enabled() => {
            let dest = forward::Destination::parse(&v);
            if dest.is_none() {
                log.warnings.push(format!(
                    "telemetry: {} is not a destination (vsock:<port>); nothing is forwarded",
                    forward::FORWARD_ENV
                ));
            }
            dest
        }
        _ => None,
    };
    let (want_traces, want_logs) = if forward.is_some() {
        (None, None)
    } else {
        (want_traces, want_logs)
    };
    let forward_traces = forward.is_some() && !switches.traces.off;
    let forward_logs = forward.is_some() && !switches.logs.off;
    // The spool directory, from the environment. The microVM's `/init` (the
    // daemon as pid 1) has none yet: no home, and its state volume mounts
    // later. Its spool is deferred, and minimald relocates it onto the volume
    // (`relocate_spool`). Any other process without a home spools nothing, as
    // before: nobody would relocate it, and a tracer that records nowhere is
    // worse than none.
    let spool_wanted = d.traces.spool || d.logs.spool;
    let spool_file = spool_wanted
        .then(|| match spool::dir() {
            Some(dir) => Some(spool::SpoolFile::open(dir, service_name)),
            None if std::process::id() == 1 && service_name == "minimald" => {
                Some(spool::SpoolFile::deferred(service_name))
            }
            None => None,
        })
        .flatten();
    let spool_traces = spool_file.is_some() && d.traces.spool;
    let spool_logs = spool_file.is_some() && d.logs.spool;
    if want_traces.is_none()
        && want_logs.is_none()
        && !spool_traces
        && !spool_logs
        && !forward_traces
        && !forward_logs
    {
        forward::mark_absent();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "a second init keeps the first value, which is the intent"
        )]
        let _ = PROVIDERS.set((None, None));
        #[expect(
            clippy::let_underscore_must_use,
            reason = "a second init keeps the first value, which is the intent"
        )]
        let _ = INIT_LOG.set(log);
        return;
    }
    // Built off the caller's thread: both `min` and `minimald` assemble their
    // subscribers inside a tokio runtime, and the blocking HTTP client must
    // not be created there. A failure means no export for that signal, never
    // a panic; `report_init` says so once a subscriber can carry the line.
    let (traces_url, logs_url) = (want_traces.clone(), want_logs.clone());
    let built = if want_traces.is_none() && want_logs.is_none() {
        Ok((None, None))
    } else {
        std::thread::Builder::new()
            .name("otel-init".into())
            .spawn(move || {
                let spans = want_traces.map(|url| {
                    opentelemetry_otlp::SpanExporter::builder()
                        .with_http()
                        .with_http_client(ExportClient::new(
                            &url,
                            "TRACES",
                            traces_prefixed,
                            env_nonempty,
                        )?)
                        .with_endpoint(url.as_str())
                        .with_timeout(EXPORT_TIMEOUT)
                        .build()
                        .map_err(|e| build_error(&url, &e))
                });
                let logs = want_logs.map(|url| {
                    opentelemetry_otlp::LogExporter::builder()
                        .with_http()
                        .with_http_client(ExportClient::new(
                            &url,
                            "LOGS",
                            logs_prefixed,
                            env_nonempty,
                        )?)
                        .with_endpoint(url.as_str())
                        .with_timeout(EXPORT_TIMEOUT)
                        .build()
                        .map_err(|e| build_error(&url, &e))
                });
                (spans, logs)
            })
            .map_err(|e| format!("spawning the exporter-build thread: {e}"))
            .and_then(|h| {
                h.join().map_err(|payload| {
                    // the payload is whatever the thread panicked with: say it when it is a string
                    let what = payload
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_owned())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "a non-string panic payload".to_owned());
                    format!("the exporter-build thread panicked: {what}")
                })
            })
    };
    /// The exporter when it was built; a warning in `log` when it was not.
    fn keep<E>(log: &mut InitLog, signal: &str, r: Option<Result<E, String>>) -> Option<E> {
        match r {
            Some(Ok(e)) => Some(e),
            Some(Err(e)) => {
                log.warnings.push(format!(
                    "telemetry: the OTLP exporter for {signal} could not be built ({e}); \
                     {signal} export is off for this process"
                ));
                None
            }
            None => None,
        }
    }
    let built = match built {
        Ok((spans, logs)) => {
            let spans = keep(&mut log, "traces", spans);
            let logs = keep(&mut log, "logs", logs);
            (spans, logs)
        }
        Err(e) => {
            log.warnings.push(format!(
                "telemetry: no OTLP exporter could be built ({e}); export is off for this process"
            ));
            (None, None)
        }
    };
    #[expect(
        clippy::let_underscore_must_use,
        reason = "a second init keeps the first value, which is the intent"
    )]
    let _ = SPOOL.set(spool_file.clone());
    let span_spool = spool_file.clone().filter(|_| spool_traces);
    let log_spool = spool_file.clone().filter(|_| spool_logs);
    let queue = (forward_traces || forward_logs).then(forward::install);
    if queue.is_none() {
        forward::mark_absent();
    }
    // Where a signal goes, for the summary line: its endpoint's origin, the
    // forward destination, or off.
    let destination =
        |exporter: bool, url: Option<&Url>, forwarded: bool| match (forwarded, forward) {
            (true, Some(d)) => d.to_string(),
            _ => exporter
                .then_some(url)
                .flatten()
                .map_or_else(|| "off".to_owned(), endpoint_origin),
        };
    log.summary = Some(format!(
        "telemetry on: traces -> {}, logs -> {}, spool -> {}",
        destination(built.0.is_some(), traces_url.as_ref(), forward_traces),
        destination(built.1.is_some(), logs_url.as_ref(), forward_logs),
        match spool_file.as_ref().and_then(|f| f.dir()) {
            Some(d) => d.display().to_string(),
            None if spool_file.is_some() => "deferred until the state dir is known".to_string(),
            None => "off".to_string(),
        }
    ));
    #[expect(
        clippy::let_underscore_must_use,
        reason = "a second init keeps the first value, which is the intent"
    )]
    let _ = INIT_LOG.set(log);
    // One resource for both providers: its `service.instance.id` is drawn
    // once, so a backend can join a process's traces and logs.
    let resource = resource(service_name);
    let tracer_provider =
        (built.0.is_some() || span_spool.is_some() || forward_traces).then(|| {
            let mut b = SdkTracerProvider::builder().with_resource(resource.clone());
            if let Some(exporter) = built.0 {
                b = b.with_batch_exporter(exporter);
            }
            if let Some(f) = span_spool {
                b = b.with_span_processor(spool::SpoolSpans::new(f));
            }
            if forward_traces && let Some(q) = &queue {
                b = b.with_span_processor(forward::ForwardSpans::new(q.clone()));
            }
            b.build()
        });
    let logger_provider = (built.1.is_some() || log_spool.is_some() || forward_logs).then(|| {
        let mut b = SdkLoggerProvider::builder().with_resource(resource);
        if let Some(exporter) = built.1 {
            b = b.with_batch_exporter(exporter);
        }
        if let Some(f) = log_spool {
            b = b.with_log_processor(spool::SpoolLogs::new(f));
        }
        if forward_logs && let Some(q) = &queue {
            b = b.with_log_processor(forward::ForwardLogs::new(q.clone()));
        }
        b.build()
    });
    let installed = tracer_provider.is_some() || logger_provider.is_some();
    #[expect(
        clippy::let_underscore_must_use,
        reason = "a second init keeps the first value, which is the intent"
    )]
    let _ = PROVIDERS.set((tracer_provider, logger_provider));
    if installed {
        // `process::exit` skips `main`'s flush; atexit handlers still run.
        // SAFETY: registering a plain `extern "C" fn` with no captured state.
        unsafe {
            libc::atexit(flush_at_exit);
        }
    }
}

/// The span export layer (filtered by the export filter), or `None` when
/// trace export is off. Generic over its own position in the subscriber stack.
pub fn span_layer<S>() -> Option<SpanLayer<S>>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let p = PROVIDERS.get()?.0.as_ref()?;
    let name = SERVICE.get().cloned().unwrap_or_default();
    Some(
        tracing_opentelemetry::layer()
            .with_tracer(p.tracer(name))
            .with_location(false)
            .with_filter(export_filter()),
    )
}

/// The event (logs) export layer (filtered by the export filter), or `None`
/// when log export is off.
pub fn log_layer<S>() -> Option<LogLayer<S>>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let p = PROVIDERS.get()?.1.as_ref()?;
    Some(
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(p)
            .with_filter(export_filter()),
    )
}

/// The ids and W3C flags to use for `span`: when a tracer is installed, the
/// span's OTel ids and its sampling decision — as a child of `parent` (trace
/// id, span id, flags) when one was propagated — so exported spans, file-log
/// fields and the outgoing `TRACEPARENT` agree. `None` when export is off or
/// the export filter did not admit this span: the caller keeps its existing
/// mint-or-adopt.
pub fn align(
    span: &tracing::Span,
    parent: Option<([u8; 16], [u8; 8], u8)>,
) -> Option<([u8; 16], [u8; 8], u8)> {
    if !exporting() {
        return None;
    }
    if let Some((trace_id, span_id, flags)) = parent {
        let remote = SpanContext::new(
            TraceId::from_bytes(trace_id),
            SpanId::from_bytes(span_id),
            TraceFlags::new(flags),
            true,
            TraceState::default(),
        );
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best effort: a telemetry failure is a silent no-op (spec 25 principle 8)"
        )]
        let _ = span.set_parent(opentelemetry::Context::new().with_remote_span_context(remote));
    }
    let cx = span.context();
    let sc = cx.span().span_context().clone();
    sc.is_valid().then(|| {
        (
            sc.trace_id().to_bytes(),
            sc.span_id().to_bytes(),
            sc.trace_flags().to_u8(),
        )
    })
}

/// Make `span` non-recording, and with it every span opened under it: the
/// request of a client that opted out of telemetry (`MINIMAL_OTEL=off`
/// beside no `TRACEPARENT`). The span is given a fresh, unsampled remote
/// parent (flags `00`), which the SDK's parent-based sampler turns into a
/// span that is neither exported nor spooled, and whose children inherit
/// the decision (TEL-024's mechanism, applied on purpose). Events logged
/// inside are still log records; the caller keeps what it must out of
/// them.
///
/// Returns the span's ids as [`align`] does, for the caller's file-log
/// fields, `None` when no span layer is installed under `span` (nothing
/// records it then anyway). Unlike [`align`] this does not ask whether the
/// process exports: an opt-out is honoured by whatever tracer is under the
/// span, which is what lets a test prove it in-process.
pub fn opt_out(span: &tracing::Span) -> Option<([u8; 16], [u8; 8], u8)> {
    use opentelemetry_sdk::trace::{IdGenerator as _, RandomIdGenerator};

    let ids = RandomIdGenerator::default();
    let remote = SpanContext::new(
        ids.new_trace_id(),
        ids.new_span_id(),
        TraceFlags::default(),
        true,
        TraceState::default(),
    );
    #[expect(
        clippy::let_underscore_must_use,
        reason = "best effort: a telemetry failure is a silent no-op (spec 25 principle 8)"
    )]
    let _ = span.set_parent(opentelemetry::Context::new().with_remote_span_context(remote));
    let cx = span.context();
    let sc = cx.span().span_context().clone();
    sc.is_valid().then(|| {
        (
            sc.trace_id().to_bytes(),
            sc.span_id().to_bytes(),
            sc.trace_flags().to_u8(),
        )
    })
}

/// Export what is pending, within `timeout`, and keep exporting afterwards.
///
/// Unlike [`shutdown`] this is not terminal: the providers stay installed, so
/// later spans and events (a daemon's Shutdown span, the exit-time flush) are
/// still recorded and exported. For a process that may be killed right after
/// it answers (the microVM guest after acknowledging Shutdown) and wants what
/// it has so far delivered first. Both signals flush concurrently on helper
/// threads; the caller stops waiting at the deadline and an unfinished flush
/// carries on in the background. A no-op when nothing was installed or after
/// [`shutdown`]. A telemetry failure never fails, panics or hangs the caller.
pub fn flush(timeout: Duration) {
    let Some((traces, logs)) = PROVIDERS.get() else {
        return;
    };
    if SHUT_DOWN.load(Ordering::SeqCst) {
        return;
    }
    flush_providers(traces.clone(), logs.clone(), timeout);
}

/// [`flush`] for given providers: force-flush each on its own thread, and
/// wait for both until `timeout` at most.
fn flush_providers(
    traces: Option<SdkTracerProvider>,
    logs: Option<SdkLoggerProvider>,
    timeout: Duration,
) {
    if traces.is_none() && logs.is_none() {
        return;
    }
    // `None` only for a timeout too long to add to now: then wait it out.
    let deadline = std::time::Instant::now().checked_add(timeout);
    let (tx, rx) = std::sync::mpsc::channel();
    // One thread per signal; each says when it is done. A thread that could
    // not be spawned is not waited for.
    let spawn = |flush: Box<dyn FnOnce() + Send>| {
        let tx = tx.clone();
        std::thread::Builder::new()
            .name("otel-flush".into())
            .spawn(move || {
                flush();
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the receiver may already be gone; there is nothing to do then"
                )]
                let _ = tx.send(());
            })
            .is_ok()
    };
    // best effort: a telemetry failure is a silent no-op (spec 25 principle 8)
    let pending =
        usize::from(traces.is_some_and(|p| spawn(Box::new(move || drop(p.force_flush())))))
            + usize::from(logs.is_some_and(|p| spawn(Box::new(move || drop(p.force_flush())))));
    drop(tx);
    for _ in 0..pending {
        let left = deadline.map_or(timeout, |d| {
            d.saturating_duration_since(std::time::Instant::now())
        });
        if rx.recv_timeout(left).is_err() {
            return; // the deadline passed (or a flush thread panicked)
        }
    }
}

/// Flush and stop the exporters within one overall `timeout` (both signals
/// shut down concurrently on their own thread; the caller stops waiting at
/// the deadline). Idempotent; a no-op when nothing was installed. A telemetry
/// failure never fails or hangs the caller.
pub fn shutdown(timeout: Duration) {
    let Some((traces, logs)) = PROVIDERS.get() else {
        return;
    };
    if (traces.is_none() && logs.is_none()) || SHUT_DOWN.swap(true, Ordering::SeqCst) {
        return;
    }
    let (traces, logs) = (traces.clone(), logs.clone());
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("otel-shutdown".into())
        .spawn(move || {
            // shutdown_with_timeout exports what is pending; no separate
            // force_flush (its wait is a fixed 5 s in the SDK).
            let t = traces.map(|p| std::thread::spawn(move || p.shutdown_with_timeout(timeout)));
            let l = logs.map(|p| std::thread::spawn(move || p.shutdown_with_timeout(timeout)));
            if let Some(h) = t {
                #[expect(clippy::let_underscore_must_use, reason = "a panicked export thread must not take the caller down; shutdown is best effort")]
                let _ = h.join();
            }
            if let Some(h) = l {
                #[expect(clippy::let_underscore_must_use, reason = "the receiver may already be gone; there is nothing to do then")]
                let _ = h.join();
            }
            #[expect(clippy::let_underscore_must_use, reason = "the receiver may already be gone; there is nothing to do then")]
            let _ = tx.send(());
        });
    if spawned.is_ok() {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best effort: a telemetry failure is a silent no-op (spec 25 principle 8)"
        )]
        let _ = rx.recv_timeout(timeout + Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    use tracing_subscriber::prelude::*;

    /// A bundle reads the directory the open spool
    /// writes to, else a pinned `MINIMAL_OTEL_SPOOL_DIR`, else the state
    /// directory's default.
    #[test]
    fn a_bundle_reads_the_live_then_the_pinned_spool_dir() {
        use std::path::PathBuf;
        let (live, pinned, default) = (
            PathBuf::from("/live"),
            PathBuf::from("/pinned"),
            PathBuf::from("/state/telemetry/spool"),
        );
        assert_eq!(
            super::pick_spool_dir(Some(live.clone()), Some(pinned.clone()), default.clone()),
            live
        );
        assert_eq!(
            super::pick_spool_dir(None, Some(pinned.clone()), default.clone()),
            pinned
        );
        assert_eq!(super::pick_spool_dir(None, None, default.clone()), default);
    }

    /// TEL-006: the instance id's bytes come from the kernel's
    /// generator through a system call that needs no `/dev`, so two draws
    /// differ and are not the time-and-pid fallback.
    #[test]
    fn the_instance_id_is_drawn_from_the_kernel() {
        let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
        assert!(super::os_random(&mut a), "the system call works here");
        assert!(super::os_random(&mut b));
        assert_ne!(a, b, "two draws differ");
        assert_ne!(a, [0u8; 16]);
        let (x, y) = (super::instance_id(), super::instance_id());
        assert_eq!(x.len(), 32, "{x}");
        assert_ne!(x, y, "each draw is new");
    }

    /// A span exporter that records what it is given, after `delay`.
    #[derive(Debug, Clone)]
    struct Sink {
        delay: std::time::Duration,
        got: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl opentelemetry_sdk::trace::SpanExporter for Sink {
        async fn export(
            &self,
            batch: Vec<opentelemetry_sdk::trace::SpanData>,
        ) -> opentelemetry_sdk::error::OTelSdkResult {
            std::thread::sleep(self.delay);
            if let Ok(mut got) = self.got.lock() {
                got.extend(batch.into_iter().map(|s| s.name.into_owned()));
            }
            Ok(())
        }
    }

    fn batched(delay: std::time::Duration) -> (SdkTracerProvider, Sink) {
        let sink = Sink {
            delay,
            got: Default::default(),
        };
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(sink.clone())
            .build();
        (provider, sink)
    }

    /// `flush` delivers what was recorded before it, and the provider keeps
    /// recording and exporting after it (it is not a shutdown).
    /// `guest_exports` is the host's decision as a value: per-signal URLs
    /// as `export_url` builds them, the exporter switch as read, and `None`
    /// wherever the host exports nothing (an exporter `none`, a `MINIMAL_`
    /// endpoint refused for ambient plain headers).
    #[test]
    fn guest_exports_is_the_decision_not_the_variables() {
        let env = |pairs: &'static [(&str, &str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).to_string())
            }
        };
        assert_eq!(
            super::guest_exports(env(&[
                ("MINIMAL_TELEMETRY", "1"),
                (
                    "MINIMAL_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                    "http://t:4318/x"
                ),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://b:4318/"),
                ("OTEL_LOGS_EXPORTER", "none"),
            ])),
            super::GuestExports {
                spool: true,
                traces: super::GuestSignal {
                    off: false,
                    url: Some(Ok("http://t:4318/x".into())),
                },
                logs: super::GuestSignal {
                    off: true,
                    url: None
                },
            }
        );
        // Plain headers with a MINIMAL_ endpoint: refused, so no URL, but
        // the exporter is not `none` and the spool stays on.
        let refused = super::guest_exports(env(&[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", "http://m:4318"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "k=v"),
            ("MINIMAL_OTEL_SPOOL", ""),
        ]));
        assert_eq!(
            refused,
            super::GuestExports {
                spool: true,
                traces: super::GuestSignal::default(),
                logs: super::GuestSignal::default(),
            }
        );
        // Off: nothing is decided for the guest.
        let off = super::guest_exports(env(&[
            ("DO_NOT_TRACK", "1"),
            ("MINIMAL_TELEMETRY", "1"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://b:4318"),
        ]));
        assert_eq!(off, super::GuestExports::default());
    }

    #[test]
    fn a_flush_delivers_and_leaves_the_provider_usable() {
        use opentelemetry::trace::{Span as _, Tracer as _};
        let (provider, sink) = batched(std::time::Duration::ZERO);
        let tracer = provider.tracer("t");
        tracer.start("before").end();
        super::flush_providers(
            Some(provider.clone()),
            None,
            std::time::Duration::from_secs(5),
        );
        assert_eq!(
            *sink.got.lock().unwrap(),
            ["before"],
            "delivered by the flush"
        );
        tracer.start("after").end();
        super::flush_providers(
            Some(provider.clone()),
            None,
            std::time::Duration::from_secs(5),
        );
        assert_eq!(
            *sink.got.lock().unwrap(),
            ["before", "after"],
            "still recording"
        );
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the test is over; a shutdown error changes nothing"
        )]
        let _ = provider.shutdown();
    }

    /// A collector that never answers in time costs the caller the bound, not
    /// the export.
    #[test]
    fn a_flush_returns_within_its_bound() {
        use opentelemetry::trace::{Span as _, Tracer as _};
        let (provider, _sink) = batched(std::time::Duration::from_secs(3));
        provider.tracer("t").start("slow").end();
        let t = std::time::Instant::now();
        super::flush_providers(Some(provider), None, std::time::Duration::from_millis(100));
        assert!(
            t.elapsed() < std::time::Duration::from_secs(1),
            "took {:?}",
            t.elapsed()
        );
        super::flush_providers(None, None, std::time::Duration::MAX); // nothing to wait for
    }

    /// The alignment contract: a span given a remote parent exports under the
    /// parent's trace id, with the parent as its parent span, and the ids
    /// `context()` reports before the span closes are exactly the exported ids.
    #[test]
    fn a_child_of_a_propagated_parent_exports_under_its_trace_with_the_reported_ids() {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("t")));
        let parent_trace = [0x0a; 16];
        let parent_span = [0x0b; 8];
        let reported = tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("cmd");
            let remote = opentelemetry::trace::SpanContext::new(
                opentelemetry::trace::TraceId::from_bytes(parent_trace),
                opentelemetry::trace::SpanId::from_bytes(parent_span),
                opentelemetry::trace::TraceFlags::SAMPLED,
                true,
                Default::default(),
            );
            use opentelemetry::trace::TraceContextExt as _;
            #[expect(
                clippy::let_underscore_must_use,
                reason = "best effort: a telemetry failure is a silent no-op (spec 25 principle 8)"
            )]
            let _ = span.set_parent(opentelemetry::Context::new().with_remote_span_context(remote));
            let sc = span.context().span().span_context().clone();
            let ids = (sc.trace_id().to_bytes(), sc.span_id().to_bytes());
            drop(span);
            ids
        });
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best effort: a telemetry failure is a silent no-op (spec 25 principle 8)"
        )]
        let _ = provider.force_flush();
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1, "one span exported");
        let s = &spans[0];
        assert_eq!(
            s.span_context.trace_id().to_bytes(),
            parent_trace,
            "same trace as the propagated parent"
        );
        assert_eq!(
            s.parent_span_id.to_bytes(),
            parent_span,
            "the propagated span is the parent"
        );
        assert_eq!(reported.0, parent_trace);
        assert_eq!(
            reported.1,
            s.span_context.span_id().to_bytes(),
            "ids reported before close are the exported ids"
        );
    }

    /// An opted-out span records nowhere, nor does anything under it, while
    /// a sibling span under the same tracer does; the opted-out span still
    /// has ids (flags `00`) for the file log.
    #[test]
    fn an_opted_out_span_and_its_children_are_not_recorded() {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("t")));
        let ids = tracing::subscriber::with_default(subscriber, || {
            let off = tracing::info_span!("rpc", rpc = "off");
            let ids = super::opt_out(&off);
            off.in_scope(|| {
                tracing::info_span!("session.message").in_scope(|| {
                    tracing::info_span!("deeper").in_scope(|| {});
                });
            });
            drop(off);
            tracing::info_span!("rpc", rpc = "on").in_scope(|| {});
            ids
        });
        let names: Vec<_> = exporter
            .get_finished_spans()
            .unwrap()
            .iter()
            .map(|s| {
                let rpc = s
                    .attributes
                    .iter()
                    .find(|kv| kv.key.as_str() == "rpc")
                    .map(|kv| kv.value.as_str().into_owned())
                    .unwrap_or_default();
                format!("{}:{rpc}", s.name)
            })
            .collect();
        assert_eq!(names, ["rpc:on"], "only the span that was not opted out");
        let (trace_id, span_id, flags) = ids.expect("a span layer is installed");
        assert_ne!(trace_id, [0; 16]);
        assert_ne!(span_id, [0; 8]);
        assert_eq!(flags, 0, "unsampled");
    }

    /// Without a span layer under it, `opt_out` has nothing to decide and
    /// says so.
    #[test]
    fn opt_out_without_a_layer_gives_no_ids() {
        let subscriber = tracing_subscriber::registry();
        let ids = tracing::subscriber::with_default(subscriber, || {
            super::opt_out(&tracing::info_span!("rpc"))
        });
        assert_eq!(ids, None);
    }

    /// An explicit `MINIMAL_OTEL_SPOOL_DIR` pins the spool: the state
    /// directory minimald passes does not move it. Without
    /// the pin, a home-default or deferred spool moves, once.
    #[test]
    fn relocation_leaves_a_pinned_spool_alone_and_moves_any_other() {
        let tmp = tempfile::tempdir().unwrap();
        let (pinned_dir, state) = (tmp.path().join("pinned"), tmp.path().join("state"));

        let f = super::spool::SpoolFile::open(pinned_dir.clone(), "svc");
        assert!(!super::relocate_unless_pinned(&f, &state, true));
        assert_eq!(f.dir(), Some(pinned_dir), "a pinned spool stays put");

        let f = super::spool::SpoolFile::open(tmp.path().join("home-default"), "svc");
        assert!(super::relocate_unless_pinned(&f, &state, false));
        assert_eq!(
            f.dir().as_deref(),
            Some(state.as_path()),
            "an unpinned spool moves"
        );
        assert!(
            !super::relocate_unless_pinned(&f, &state, false),
            "already there: no move, so no second log line"
        );

        let d = super::spool::SpoolFile::deferred("svc");
        assert!(super::relocate_unless_pinned(&d, &state, false));
        assert_eq!(
            d.dir().as_deref(),
            Some(state.as_path()),
            "a deferred spool moves"
        );
    }

    /// The pin is `MINIMAL_OTEL_SPOOL_DIR` set and not empty, read in a child
    /// process so the variable never leaks across tests.
    #[test]
    fn the_spool_dir_variable_is_the_pin() {
        let exe = std::env::current_exe().unwrap();
        let case = |v: Option<&str>| -> bool {
            let mut c = std::process::Command::new(&exe);
            c.args([
                "--exact",
                "otel::tests::print_spool_pin",
                "--nocapture",
                "--test-threads=1",
            ]);
            c.env("MLOG_OTEL_PRINT", "1");
            match v {
                Some(v) => c.env("MINIMAL_OTEL_SPOOL_DIR", v),
                None => c.env_remove("MINIMAL_OTEL_SPOOL_DIR"),
            };
            let out = String::from_utf8(c.output().unwrap().stdout).unwrap();
            assert!(out.contains("PIN "), "child printed nothing: {out}");
            out.contains("PIN true")
        };
        assert!(case(Some("/tmp/explicit-spool")), "set: pinned");
        assert!(!case(None), "unset: not pinned");
        assert!(!case(Some("")), "empty: not pinned");
    }

    /// Helper for [`the_spool_dir_variable_is_the_pin`]: prints whether this
    /// process's environment pins the spool. Inert unless `MLOG_OTEL_PRINT`.
    #[test]
    fn print_spool_pin() {
        if std::env::var_os("MLOG_OTEL_PRINT").is_some() {
            println!("PIN {}", super::spool::dir_override().is_some());
        }
    }

    /// The summary names an endpoint by its origin only (the same rule as
    /// minvmd's boot-line warning), read from the parsed URL: a credential
    /// the user did not percent-encode is refused by the parser (below)
    /// rather than leaking a prefix the way a split on `/`, `?` and `#` did
    /// (review F7).
    #[test]
    fn an_endpoint_is_logged_as_its_origin() {
        for (url, origin) in [
            (
                "https://u:p@collector.example:4318/v1/abc?k=v#f",
                "https://collector.example:4318",
            ),
            ("http://10.79.0.1:4318/v1/traces", "http://10.79.0.1:4318"),
            ("http://h?token=x", "http://h"),
            ("http://h#f", "http://h"),
            ("https://user:p@ss@h", "https://h"),
            ("http://[fe80::1]:4318/v1/traces", "http://[fe80::1]:4318"),
        ] {
            let parsed = super::parse_endpoint(url).unwrap_or_else(|e| panic!("{url}: {e}"));
            assert_eq!(super::endpoint_origin(&parsed), origin, "{url}");
        }
    }

    /// The endpoint has one recognizer, the URL parser reqwest sends with:
    /// a value is an absolute `http://` or `https://` URL or it is refused
    /// with fixed text that never repeats the value (reviews F7 to F9). What
    /// `http::Uri` used to accept and every send then rejected (a non-digit
    /// port, a port above 65535, a `;` in the authority, a credential with
    /// `#` or `?` that reads as the port) is refused at the boundary.
    #[test]
    fn an_endpoint_is_an_absolute_http_url_or_is_refused() {
        for ok in [
            "http://a:4318",
            "https://collector.example/v1/traces",
            "HTTP://Collector:4318",
            "http://t/x?api_key=k",
            "https://user:p@ss@h",
        ] {
            assert!(super::parse_endpoint(ok).is_ok(), "{ok}");
        }
        for (bad, secret) in [
            ("https://user:tok#en@collector.example:4318", "tok"),
            ("https://user:tok?en@collector.example:4318", "tok"),
            ("https://user:pa/ss@c:4318", "pa"),
            ("http://h:99999/v1/traces", "99999"),
            ("http://h:65536", "65536"),
            ("http://h:4318;key=v/v1/traces", "key"),
            ("u:p@h:4318/v1", "u:p"),
            ("h:4318", "4318"),
            ("ftp://h:4318", "ftp"),
            ("file:///tmp/x", "tmp"),
            ("http:/", ""),
            ("", ""),
        ] {
            let e = super::parse_endpoint(bad).expect_err(bad);
            assert_eq!(e, super::NOT_A_URL, "{bad}");
            assert!(!e.contains(secret) || secret.is_empty(), "{bad}: {e}");
        }
        // The accepted value reaches the SDK as the parser serialises it.
        assert_eq!(
            super::parse_endpoint("HTTP://Collector:4318")
                .unwrap()
                .as_str(),
            "http://collector:4318/"
        );
    }

    /// The base endpoint takes the signal path inside the URL grammar: a
    /// trailing `/` is not doubled and a prefix path is kept, as before; a
    /// base with a query or fragment is refused rather than having `/v1/..`
    /// land in its query (review F10). A per-signal endpoint is taken as
    /// given, query included.
    #[test]
    fn the_signal_path_is_appended_as_path_segments() {
        let base = |s: &str| super::parse_endpoint(s).unwrap();
        for (b, want) in [
            ("http://a:4318", "http://a:4318/v1/traces"),
            ("http://a:4318/", "http://a:4318/v1/traces"),
            ("http://a:4318/otlp", "http://a:4318/otlp/v1/traces"),
            ("http://a:4318/otlp/", "http://a:4318/otlp/v1/traces"),
            (
                "https://u:p@c.example:4318",
                "https://u:p@c.example:4318/v1/traces",
            ),
        ] {
            let u =
                super::with_signal_path(base(b), "TRACES").unwrap_or_else(|e| panic!("{b}: {e}"));
            assert_eq!(u.as_str(), want, "{b}");
        }
        assert_eq!(
            super::with_signal_path(base("http://a:4318"), "LOGS")
                .unwrap()
                .as_str(),
            "http://a:4318/v1/logs"
        );
        for bad in ["http://h:4318?tenant=a", "http://h#f", "http://h/x?k=v#f"] {
            let e = super::with_signal_path(base(bad), "TRACES").expect_err(bad);
            assert_eq!(e, super::BASE_HAS_QUERY, "{bad}");
        }
    }

    /// A refused endpoint variable produces one warning naming the variable
    /// and the rule, never the value, and no URL (reviews F7, F8).
    #[test]
    fn a_refused_endpoint_warns_without_echoing_it() {
        use super::switches::{Export, Pick};
        let secret = "s3cr3t";
        let cases: [(&str, &str, Export, &str, &str); 3] = [
            (
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "http://h:4318?api_key=s3cr3t",
                Export::Base(Pick::Plain),
                "TRACES",
                "telemetry: OTEL_EXPORTER_OTLP_ENDPOINT has a query or fragment, so the signal \
                 path cannot be appended to it; traces export is off for this process",
            ),
            (
                "MINIMAL_OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                "https://user:s3cr3t#x@h/v1/logs",
                Export::Signal(Pick::Prefixed),
                "LOGS",
                "telemetry: MINIMAL_OTEL_EXPORTER_OTLP_LOGS_ENDPOINT is not an absolute http:// \
                 or https:// URL; logs export is off for this process",
            ),
            (
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "http://h:4318/v1/traces?api_key=s3cr3t",
                Export::Signal(Pick::Plain),
                "TRACES",
                "",
            ),
        ];
        for (name, value, export, signal, warning) in cases {
            let var = |n: &str| (n == name).then(|| value.into());
            match super::export_url_from(export, signal, var) {
                Some(Err(w)) => {
                    assert_eq!(w, warning, "{name}");
                    assert!(!w.contains(secret));
                }
                Some(Ok(u)) => {
                    assert_eq!(warning, "", "{name}: accepted");
                    assert_eq!(u.as_str(), value);
                }
                None => panic!("{name}: not read"),
            }
        }
        // The SDK's configuration error repeats the endpoint; the log gets
        // the origin and fixed text instead. Other build errors pass through.
        let url = super::parse_endpoint("https://c.example:4318/v1/traces?api_key=s3cr3t").unwrap();
        let e = opentelemetry_otlp::ExporterBuildError::InvalidConfiguration(format!(
            "invalid endpoint '{url}': invalid uri character"
        ));
        let got = super::build_error(&url, &e);
        assert_eq!(
            got,
            "the exporter rejected the endpoint at https://c.example:4318"
        );
        assert!(!got.contains(secret));
        let e = opentelemetry_otlp::ExporterBuildError::InternalFailure("no client".into());
        assert_eq!(
            super::build_error(&url, &e),
            "exporter initialization failed: no client"
        );
    }

    /// What [`super::parse_endpoint`] does with one entry of
    /// [`URL_CONFUSION_CORPUS`].
    #[derive(Debug)]
    enum Expect {
        /// Parsed; the serialisation the SDK is handed and reqwest sends to.
        Accepted(&'static str),
        /// Refused with [`super::NOT_A_URL`].
        Refused,
    }

    /// The published URL-parsing-confusion literature as inputs to the one
    /// recognizer: `(input, outcome, decoys)`, where the decoys are the
    /// substrings of the input (a credential, a host the attack meant another
    /// parser to see) that must never appear in the logged origin or the
    /// refusal. The outcomes were first derived from the WHATWG algorithm
    /// and then confirmed by running the test; the crate is the oracle for
    /// the canonical form, because it is the parser reqwest sends with.
    ///
    /// Sources:
    /// - Claroty Team82 and Snyk, "Exploiting URL Parsing Confusion" (Jan
    ///   2022), <https://claroty.com/team82/research/exploiting-url-parsing-confusion>
    ///   and <https://snyk.io/blog/url-confusion-vulnerabilities>: sixteen
    ///   parsers compared and five confusion classes named, each with the
    ///   example this table takes: scheme confusion (`google.com/abc`),
    ///   slash confusion (`http:///google.com`, `http:/google.com`),
    ///   backslash confusion (`http:\\google.com`), URL-encoded data
    ///   confusion (`http://%67oogle.com`, decoded by some parsers only) and
    ///   scheme mixup (the Log4Shell `ldap://127.0.0.1#.evilhost.com:1389/a`
    ///   bypass, validated by one parser and fetched by another).
    /// - Orange Tsai, "A New Era of SSRF - Exploiting URL Parser in Trending
    ///   Programming Languages", Black Hat USA 2017,
    ///   <https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf>:
    ///   "the inconsistency between URL parser and requester", with
    ///   `http://1.1.1.1 &@2.2.2.2# @3.3.3.3/` (four Python stacks, three
    ///   hosts), `http://127.0.0.1:11211:80/`, `http://google.com#@evil.com/`,
    ///   `http://foo@evil.com:80@google.com/`, `http://foo@127.0.0.1 @google.com/`
    ///   (the cURL patch bypass), `http://127.0.0.1\tfoo.google.com` with its
    ///   `%09` and `%2509` forms (glibc trailing-rubbish stripping and double
    ///   decoding), `http://0/`, and the IDNA case `http://ß.orange.tw/`.
    /// - The WHATWG URL Standard, <https://url.spec.whatwg.org/>, "URL
    ///   parsing" and "Host parsing": leading and trailing C0 controls and
    ///   spaces are removed and every ASCII tab or newline is removed before
    ///   parsing; for a special scheme `\` is `/` and any run of slashes
    ///   follows the scheme; a second `@` in the authority is percent-encoded
    ///   as `%40`, so the last `@` ends the userinfo; the host is
    ///   percent-decoded, then mapped by IDNA (UTS 46) to ASCII, then read as
    ///   an IPv4 address when it ends in a number (hex, octal and short
    ///   forms, one trailing dot allowed); the forbidden host code points
    ///   (`@ / \ ? # : [ ] space`, C0, `%` and DEL in a domain) make the
    ///   parse fail; IPv6 zone identifiers are "intentionally omitted"; a
    ///   default port is set to null.
    /// - The `url` crate 2.5.8, <https://docs.rs/url/2.5.8/url/>: "based on
    ///   the WHATWG URL Standard"; `as_str` is the stored serialisation;
    ///   `origin()` is the WHATWG origin and `ascii_serialization` gives
    ///   `scheme://host[:port]`; `host_str` is punycode for a special URL;
    ///   "default port numbers are never reflected by the serialization".
    const URL_CONFUSION_CORPUS: &[(&str, Expect, &[&str])] = &[
        // Scheme confusion and scheme mixup: no scheme, a scheme-relative
        // reference, a wrapping scheme, a non-http scheme. Case folds.
        ("google.com/v1/traces", Expect::Refused, &[]),
        ("//h:4318/v1/traces", Expect::Refused, &[]),
        ("url:http://h:4318/", Expect::Refused, &[]),
        ("ftp://h:4318", Expect::Refused, &[]),
        ("javascript:alert(1)", Expect::Refused, &[]),
        (
            "HTTP://Collector:4318",
            Expect::Accepted("http://collector:4318/"),
            &[],
        ),
        ("hTtPs://H:443/X", Expect::Accepted("https://h/X"), &[]),
        // Slash confusion: for a special scheme any run of slashes (or none)
        // after `http:` is the authority marker. Where urllib saw no host
        // and curl "added the missing slashes", there is one answer here.
        ("http:/h:4318/", Expect::Accepted("http://h:4318/"), &[]),
        ("http:h:4318/", Expect::Accepted("http://h:4318/"), &[]),
        ("http:///h:4318/", Expect::Accepted("http://h:4318/"), &[]),
        // Backslash confusion: `\` is `/`, so `\@evil` is a path segment
        // under the host before it, never a userinfo terminator, and a `\`
        // before `?` ends the path with a `/`. An encoded `%5c` stays text.
        (
            "http:\\\\h:4318\\v1\\traces",
            Expect::Accepted("http://h:4318/v1/traces"),
            &[],
        ),
        ("http://h\\@evil/", Expect::Accepted("http://h/@evil/"), &[]),
        (
            "http://evil.com\\@good.com/",
            Expect::Accepted("http://evil.com/@good.com/"),
            &[],
        ),
        (
            "http://127.1.1.1:80\\@@127.2.2.2:80/",
            Expect::Accepted("http://127.1.1.1/@@127.2.2.2:80/"),
            &[],
        ),
        (
            "http://u:p@h\\@evil/",
            Expect::Accepted("http://u:p@h/@evil/"),
            &["u:p", "p@"],
        ),
        (
            "http://h:4318\\..\\v1",
            Expect::Accepted("http://h:4318/v1"),
            &[],
        ),
        (
            "http://h:4318/v1/traces\\?x=1",
            Expect::Accepted("http://h:4318/v1/traces/?x=1"),
            &[],
        ),
        (
            "http://evil.com%5c@good.com/",
            Expect::Accepted("http://evil.com%5c@good.com/"),
            &["evil.com"],
        ),
        // Authority confusion (Tsai): which `@`, `#` or `:` ends what. The
        // host is the one reqwest connects to; a decoy host lands in the
        // userinfo, the fragment or the path, and the origin shows neither.
        (
            "http://u:p@h/",
            Expect::Accepted("http://u:p@h/"),
            &["u:p", "p@"],
        ),
        (
            "http://good.com#@evil.com/",
            Expect::Accepted("http://good.com/#@evil.com/"),
            &["evil.com"],
        ),
        // The encoded `#` does not end the URL: the `@` wins and the host
        // is the other one. Deterministic, and the origin says which.
        (
            "http://good.com%23@evil.com/",
            Expect::Accepted("http://good.com%23@evil.com/"),
            &["good.com"],
        ),
        (
            "http://foo@evil.com:80@google.com/",
            Expect::Accepted("http://foo%40evil.com:80@google.com/"),
            &["foo", "evil.com", ":80"],
        ),
        (
            "http://foo@127.0.0.1 @google.com:11211/",
            Expect::Accepted("http://foo%40127.0.0.1%20@google.com:11211/"),
            &["foo", "127.0.0.1"],
        ),
        (
            "http://1.1.1.1 &@2.2.2.2# @3.3.3.3/",
            Expect::Accepted("http://1.1.1.1%20&@2.2.2.2/#%20@3.3.3.3/"),
            &["1.1.1.1", "3.3.3.3"],
        ),
        ("http://127.0.0.1:11211:80/", Expect::Refused, &["11211"]),
        ("http://:@h/", Expect::Accepted("http://h/"), &[]),
        ("http://h@/", Expect::Refused, &[]),
        ("http://u:p/ss@h:4318", Expect::Refused, &["u:p", "ss@"]),
        // URL-encoded data confusion: the host is decoded once, then held
        // to the forbidden code points, so an encoded `@`, tab or `%`
        // cannot smuggle a second host; a path keeps its encoding, so
        // `%2f` splits no segment and `%zz` is passed through as text.
        (
            "http://%6c%6fcalhost:4318/",
            Expect::Accepted("http://localhost:4318/"),
            &[],
        ),
        ("http://h%40evil:4318/", Expect::Refused, &["evil"]),
        ("http://127.0.0.1%09foo.google.com/", Expect::Refused, &[]),
        ("http://127.0.0.1%2509foo.google.com/", Expect::Refused, &[]),
        (
            "http://h:4318/a/%2e%2e/v1",
            Expect::Accepted("http://h:4318/v1"),
            &[],
        ),
        (
            "http://h/v1/traces/../../sk-1234567890abcdef",
            Expect::Accepted("http://h/sk-1234567890abcdef"),
            &[],
        ),
        (
            "http://h:4318/v1/..%2fsk-1234567890abcdef",
            Expect::Accepted("http://h:4318/v1/..%2fsk-1234567890abcdef"),
            &[],
        ),
        ("http://h/%zz", Expect::Accepted("http://h/%zz"), &[]),
        (
            "http://%68%74%74%70://h/",
            Expect::Accepted("http://http//h/"),
            &[],
        ),
        // Host forms where WHATWG and RFC 3986 part: IPv4 shorthands are
        // canonicalised to dotted decimal (and a trailing dot dropped,
        // which a domain keeps), out-of-range numbers fail, IPv6 is
        // compressed and takes no zone id, IDNA maps fullwidth letters and
        // removes a zero-width space, a tab anywhere is removed first.
        (
            "http://127.1:4318",
            Expect::Accepted("http://127.0.0.1:4318/"),
            &[],
        ),
        ("http://0x7f.1/", Expect::Accepted("http://127.0.0.1/"), &[]),
        (
            "http://2130706433/",
            Expect::Accepted("http://127.0.0.1/"),
            &[],
        ),
        ("http://0/", Expect::Accepted("http://0.0.0.0/"), &[]),
        ("http://256.1.1.1/", Expect::Refused, &[]),
        (
            "http://127.0.0.1.:4318/",
            Expect::Accepted("http://127.0.0.1:4318/"),
            &[],
        ),
        (
            "http://collector.example.:4318/v1/traces",
            Expect::Accepted("http://collector.example.:4318/v1/traces"),
            &[],
        ),
        (
            "http://[::1]:4318",
            Expect::Accepted("http://[::1]:4318/"),
            &[],
        ),
        (
            "http://[0:0:0:0:0:0:0:1]:80/",
            Expect::Accepted("http://[::1]/"),
            &[],
        ),
        ("http://[fe80::1%25eth0]:4318/", Expect::Refused, &[]),
        ("http://[fe80::1%eth0]:4318/", Expect::Refused, &[]),
        (
            "http://ｅｘａｍｐｌｅ.com/",
            Expect::Accepted("http://example.com/"),
            &[],
        ),
        (
            "http://Bücher.example/",
            Expect::Accepted("http://xn--bcher-kva.example/"),
            &[],
        ),
        (
            "http://ex\u{200b}ample.com/",
            Expect::Accepted("http://example.com/"),
            &[],
        ),
        (
            "http://127.0.0.1\tfoo.google.com/",
            Expect::Accepted("http://127.0.0.1foo.google.com/"),
            &[],
        ),
        ("http://h /", Expect::Refused, &[]),
        ("http://h:0080/", Expect::Accepted("http://h/"), &[]),
        ("http://h:443/", Expect::Accepted("http://h:443/"), &[]),
        // Leading and trailing whitespace and C0 controls are stripped, so
        // a copy-pasted trailing newline is accepted silently; a tab or
        // newline inside is removed (`43<TAB>18` is port 4318); another C0
        // inside a path is percent-encoded; a non-ASCII space is not
        // whitespace to the parser and leaves no scheme.
        (
            "  http://h:4318/v1/traces",
            Expect::Accepted("http://h:4318/v1/traces"),
            &[],
        ),
        (
            "http://h:4318/v1/traces\n",
            Expect::Accepted("http://h:4318/v1/traces"),
            &[],
        ),
        (
            "http://h:4318/v1/traces\r\n",
            Expect::Accepted("http://h:4318/v1/traces"),
            &[],
        ),
        (
            "\u{1f}http://h:4318/\0",
            Expect::Accepted("http://h:4318/"),
            &[],
        ),
        ("http://h:43\t18/", Expect::Accepted("http://h:4318/"), &[]),
        (
            "http://h:4318/v1/tr\u{7}aces",
            Expect::Accepted("http://h:4318/v1/tr%07aces"),
            &[],
        ),
        (
            "http://h:4318/\r\nSLAVEOF x",
            Expect::Accepted("http://h:4318/SLAVEOF%20x"),
            &[],
        ),
        ("\u{a0}http://h:4318/", Expect::Refused, &[]),
        // A query or fragment is a URL (a per-signal endpoint takes it as
        // given); as a base endpoint it is the second refusal.
        (
            "http://h:4318?tenant=a",
            Expect::Accepted("http://h:4318/?tenant=a"),
            &["tenant"],
        ),
        ("http://h#f", Expect::Accepted("http://h/#f"), &[]),
        (
            "http://h/v1/traces?token=abc",
            Expect::Accepted("http://h/v1/traces?token=abc"),
            &["abc"],
        ),
    ];

    /// Every entry of [`URL_CONFUSION_CORPUS`] either parses to one
    /// canonical absolute http(s) URL or is refused with the fixed text
    /// (property a); the origin an accepted one is logged as is exactly
    /// `scheme://host[:port]`, with no `@` and none of the input's decoys
    /// (property b); and the serialisation handed to the SDK is a fixed
    /// point of the parser reqwest sends with, so build and send cannot
    /// disagree (property c; `reqwest::Url` is `url::Url`, which makes this
    /// trivially true and is why it is written down). The base-endpoint
    /// rule holds across the corpus: the signal path is appended under the
    /// same origin, or the base is refused for its query or fragment.
    #[test]
    fn url_confusion_corpus_is_one_canonical_url_or_refused() {
        for (raw, expect, decoys) in URL_CONFUSION_CORPUS {
            let url = match (super::parse_endpoint(raw), expect) {
                (Err(e), Expect::Refused) => {
                    assert_eq!(e, super::NOT_A_URL, "{raw:?}");
                    for decoy in *decoys {
                        assert!(!e.contains(decoy), "{raw:?}: the refusal echoes {decoy:?}");
                    }
                    continue;
                }
                (Ok(url), Expect::Accepted(canonical)) => {
                    assert_eq!(url.as_str(), *canonical, "{raw:?}");
                    url
                }
                (got, _) => panic!("{raw:?}: expected {expect:?}, got {got:?}"),
            };
            // (c) What the SDK is handed is what reqwest parses at send,
            // and parsing it again changes nothing.
            let again =
                reqwest::Url::parse(url.as_str()).unwrap_or_else(|e| panic!("{raw:?}: {e}"));
            assert_eq!(again.as_str(), url.as_str(), "{raw:?}");
            assert!(url.as_str().is_ascii(), "{raw:?}: {}", url.as_str());
            // (b) The origin is the scheme, the host and the explicit port,
            // and nothing else from the input.
            let origin = super::endpoint_origin(&url);
            let host = url.host_str().unwrap_or_else(|| panic!("{raw:?}: no host"));
            let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
            assert_eq!(
                origin,
                format!("{}://{host}{port}", url.scheme()),
                "{raw:?}"
            );
            assert!(!origin.contains('@'), "{raw:?}: {origin}");
            for decoy in *decoys {
                assert!(
                    !origin.contains(decoy),
                    "{raw:?}: the origin {origin} shows {decoy:?}"
                );
            }
            // The base-endpoint rule, under the same origin.
            let appended = super::with_signal_path(url.clone(), "TRACES");
            if url.query().is_some() || url.fragment().is_some() {
                assert_eq!(appended, Err(super::BASE_HAS_QUERY), "{raw:?}");
            } else {
                let appended = appended.unwrap_or_else(|e| panic!("{raw:?}: {e}"));
                let stem = url.as_str().trim_end_matches('/');
                assert!(
                    appended.as_str().starts_with(stem)
                        && appended.as_str().ends_with("/v1/traces"),
                    "{raw:?}: {appended}"
                );
                assert_eq!(super::endpoint_origin(&appended), origin, "{raw:?}");
            }
        }
    }

    /// Only an `http://` endpoint is plain: its client loads no roots and
    /// ignores proxies; an `https://` one keeps reqwest's defaults.
    #[test]
    fn only_an_http_endpoint_is_plain() {
        let url = |s: &str| super::parse_endpoint(s).unwrap();
        assert!(super::is_plain_http(&url(
            "http://10.79.0.1:4318/v1/traces"
        )));
        assert!(super::is_plain_http(&url("HTTP://collector:4318")));
        assert!(!super::is_plain_http(&url(
            "https://collector:4318/v1/logs"
        )));
    }

    /// Both kinds of endpoint get a client in an environment with CA roots
    /// (an `https` one through the platform verifier, as before). The no-roots
    /// case needs a process that finds no CA roots on disk, so it is the
    /// integration test `tests/otel_without_ca_roots.rs`.
    #[test]
    fn http_and_https_endpoints_get_a_client() {
        if reqwest::blocking::Client::builder().build().is_err() {
            eprintln!("skipped: no default reqwest client builds here (no CA roots?)");
            return;
        }
        for url in [
            "http://127.0.0.1:9/v1/traces",
            "https://127.0.0.1:9/v1/traces",
        ] {
            if let Err(e) = super::http_client(&super::parse_endpoint(url).unwrap()) {
                panic!("no client for {url}: {e}");
            }
        }
    }

    /// A percent escape is `%` and exactly two hex digits (RFC 3986
    /// `pct-encoded`, either case). A sign or a space in the digits, which a
    /// number parser would take, is not an escape, so the value stays as
    /// given (LangSec F2, sibling instance).
    #[test]
    fn a_percent_escape_is_two_hex_digits() {
        for (s, want) in [
            ("%41", Some("A")),
            ("%4a%4A", Some("JJ")),
            ("%E2%9C%93", Some("\u{2713}")),
            ("a%20b", Some("a b")),
            ("%%41", None),
            ("%+1", None),
            ("%-1", None),
            ("% 1", None),
            ("%1 ", None),
            ("%4", None),
            ("%", None),
            ("%zz", None),
            // decodes, but not to UTF-8
            ("%ff", None),
        ] {
            assert_eq!(super::percent_decode(s).as_deref(), want, "{s:?}");
        }
    }

    /// Headers parse as the OTLP exporter parses them: trimmed pairs,
    /// percent-decoded values, malformed pairs skipped.
    #[test]
    fn headers_parse_as_the_exporter_reads_them() {
        let got: Vec<(String, String)> =
            super::parse_headers(" a=1 ,B = two%20words,bad,=x,y=,c=%zz,d=%E2%9C%93,e=%+1,")
                .into_iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect();
        let want = [
            ("a", "1"),
            ("b", "two words"),
            ("c", "%zz"),
            ("d", "\u{2713}"),
            ("e", "%+1"),
        ];
        let want: Vec<(String, String)> = want
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        assert_eq!(got, want);
    }

    /// TEL-008: for a `MINIMAL_` endpoint the client drops every plain header
    /// (the base and the signal's own) and sets the `MINIMAL_` ones, which
    /// win a shared name; for a plain endpoint it changes nothing.
    #[test]
    fn a_prefixed_client_swaps_plain_headers_for_minimal_ones() {
        let env = |n: &str| match n {
            "OTEL_EXPORTER_OTLP_HEADERS" => Some("x-api-key=S3CRET,x-plain=1".to_owned()),
            "OTEL_EXPORTER_OTLP_TRACES_HEADERS" => Some("x-traces=2".to_owned()),
            "MINIMAL_OTEL_EXPORTER_OTLP_HEADERS" => Some("x-api-key=ours".to_owned()),
            _ => None,
        };
        let url = super::parse_endpoint("http://h:4318").unwrap();
        let sent = |prefixed: bool| {
            let c = super::ExportClient::new(&url, "TRACES", prefixed, env).unwrap();
            let mut h = reqwest::header::HeaderMap::new();
            for (k, v) in [("x-api-key", "S3CRET"), ("x-plain", "1"), ("x-traces", "2")] {
                h.insert(k, v.parse().unwrap());
            }
            c.rewrite(&mut h);
            let mut v: Vec<String> = h
                .iter()
                .map(|(k, v)| format!("{k}={}", v.to_str().unwrap()))
                .collect();
            v.sort();
            v
        };
        assert_eq!(sent(true), ["x-api-key=ours"]);
        assert_eq!(sent(false), ["x-api-key=S3CRET", "x-plain=1", "x-traces=2"]);
        let c = super::ExportClient::new(&url, "TRACES", true, env).unwrap();
        assert!(
            !format!("{c:?}").contains("ours"),
            "a MINIMAL_ value is printed"
        );
    }

    /// F15: the warning for an unsupported exporter list names the variable
    /// it was read from and says what happens instead.
    #[test]
    fn an_unsupported_exporter_warning_names_its_variable() {
        assert_eq!(
            super::unsupported_exporter_warning("traces", false),
            "telemetry: OTEL_TRACES_EXPORTER names an exporter this build does not have (otlp \
             and none are the ones recognised); traces are exported over OTLP as if it were unset"
        );
        assert_eq!(
            super::unsupported_exporter_warning("logs", true),
            "telemetry: MINIMAL_OTEL_LOGS_EXPORTER names an exporter this build does not have \
             (otlp and none are the ones recognised); logs are exported over OTLP as if it were \
             unset"
        );
    }

    /// TEL-008: the refusal warning names the plain headers variable the
    /// exporter would send (the signal's own first) and the `MINIMAL_`
    /// endpoint variable.
    #[test]
    fn a_refusal_names_both_variables() {
        use super::switches::{Export, Pick};
        assert_eq!(
            super::refusal_warning("traces", Export::Base(Pick::Prefixed), false),
            "telemetry: refusing to export traces: OTEL_EXPORTER_OTLP_HEADERS is set but the \
             endpoint comes from MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT; set \
             MINIMAL_OTEL_EXPORTER_OTLP_HEADERS to send headers there"
        );
        assert_eq!(
            super::refusal_warning("logs", Export::Signal(Pick::Prefixed), true),
            "telemetry: refusing to export logs: OTEL_EXPORTER_OTLP_LOGS_HEADERS is set but the \
             endpoint comes from MINIMAL_OTEL_EXPORTER_OTLP_LOGS_ENDPOINT; set \
             MINIMAL_OTEL_EXPORTER_OTLP_HEADERS to send headers there"
        );
    }

    /// The warn line carries every cause, not just the outermost `Display`.
    #[test]
    fn an_error_chain_names_every_cause() {
        #[derive(Debug)]
        struct E(&'static str, Option<Box<E>>);
        impl std::fmt::Display for E {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.0)
            }
        }
        impl std::error::Error for E {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.1.as_deref().map(|e| e as _)
            }
        }
        let e = E(
            "builder error",
            Some(Box::new(E("no CA certificates", None))),
        );
        assert_eq!(super::error_chain(&e), "builder error: no CA certificates");
        assert_eq!(super::error_chain(&E("alone", None)), "alone");
    }

    /// Export stays off without the explicit opt-in, and nothing is installed.
    #[test]
    fn without_the_opt_in_export_is_off_and_installs_nothing() {
        if !super::telemetry_enabled() {
            super::init("test");
            assert!(super::span_layer::<tracing_subscriber::Registry>().is_none());
            assert!(super::log_layer::<tracing_subscriber::Registry>().is_none());
            assert!(!super::exporting());
            let span = tracing::info_span!("x");
            assert!(super::align(&span, None).is_none());
            super::shutdown(std::time::Duration::from_millis(10));
        }
    }

    /// The enable and endpoint rules (TEL-001 to TEL-004), exercised in a
    /// child process per case so the env changes never leak across tests.
    #[test]
    fn enable_and_endpoint_rules() {
        let case = |env: &[(&str, &str)]| -> String {
            let env: Vec<(&str, &std::ffi::OsStr)> = env
                .iter()
                .map(|(k, v)| (*k, std::ffi::OsStr::new(v)))
                .collect();
            signal_urls_with(&env)
        };
        // Ambient OTEL_* alone never exports.
        assert_eq!(
            case(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "http://a:4318")]),
            "URLS None None"
        );
        // Opt-in + plain base endpoint: signal paths appended.
        assert_eq!(
            case(&[
                ("MINIMAL_TELEMETRY", "1"),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://a:4318/")
            ]),
            "URLS Some(\"http://a:4318/v1/traces\") Some(\"http://a:4318/v1/logs\")"
        );
        // The MINIMAL_ prefix wins over the plain name.
        assert_eq!(
            case(&[
                ("MINIMAL_TELEMETRY", "true"),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://a:4318"),
                ("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", "http://b:4318"),
            ]),
            "URLS Some(\"http://b:4318/v1/traces\") Some(\"http://b:4318/v1/logs\")"
        );
        // A per-signal endpoint is used as given; `none` turns a signal off.
        assert_eq!(
            case(&[
                ("MINIMAL_TELEMETRY", "1"),
                ("MINIMAL_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://t/x"),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://a:4318"),
                ("OTEL_LOGS_EXPORTER", "none"),
            ]),
            "URLS Some(\"http://t/x\") None"
        );
        // An exporter list: an exporter this build does not have exports
        // over OTLP as if unset (F15); `none`, trimmed and in any case, is
        // off.
        assert_eq!(
            case(&[
                ("MINIMAL_TELEMETRY", "1"),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://a:4318"),
                ("OTEL_TRACES_EXPORTER", "console"),
                ("OTEL_LOGS_EXPORTER", " NONE "),
            ]),
            "URLS Some(\"http://a:4318/v1/traces\") None"
        );
        // A base with a query cannot take the signal path and is refused
        // (F10); a per-signal endpoint keeps its query; a value that is not
        // an absolute http(s) URL is refused (F7, F9), and it never falls
        // back to the plain name.
        assert_eq!(
            case(&[
                ("MINIMAL_TELEMETRY", "1"),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://a:4318?tenant=a"),
                (
                    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                    "http://l:4318/v1/logs?tenant=a"
                ),
            ]),
            "URLS None Some(\"http://l:4318/v1/logs?tenant=a\")"
        );
        assert_eq!(
            case(&[
                ("MINIMAL_TELEMETRY", "1"),
                (
                    "MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT",
                    "https://u:tok#en@b:4318"
                ),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://a:4318"),
            ]),
            "URLS None None"
        );
        // Plain headers never go to a MINIMAL_ endpoint: without MINIMAL_
        // headers the export is refused, with them it goes ahead (TEL-008).
        let refused = [
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", "http://b:4318"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "k=v"),
        ];
        assert_eq!(case(&refused), "URLS None None");
        let mut allowed = refused.to_vec();
        allowed.push(("MINIMAL_OTEL_EXPORTER_OTLP_HEADERS", "k=w"));
        assert_eq!(
            case(&allowed),
            "URLS Some(\"http://b:4318/v1/traces\") Some(\"http://b:4318/v1/logs\")"
        );
        // DO_NOT_TRACK and OTEL_SDK_DISABLED always win.
        for off in [("DO_NOT_TRACK", "1"), ("OTEL_SDK_DISABLED", "true")] {
            assert_eq!(
                case(&[
                    ("MINIMAL_TELEMETRY", "1"),
                    ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://a:4318"),
                    off
                ]),
                "URLS None None"
            );
        }
    }

    /// What [`print_signal_urls`] prints in a child process that has every
    /// telemetry variable removed and `env` set.
    fn signal_urls_with(env: &[(&str, &std::ffi::OsStr)]) -> String {
        let exe = std::env::current_exe().unwrap();
        let mut c = std::process::Command::new(&exe);
        c.args([
            "--exact",
            "otel::tests::print_signal_urls",
            "--nocapture",
            "--test-threads=1",
        ]);
        // Every telemetry variable, by prefix (review T16): a listed
        // subset let an ambient OTEL_LOGS_EXPORTER or
        // OTEL_EXPORTER_OTLP_LOGS_ENDPOINT change the answers.
        for (k, _) in std::env::vars_os() {
            let name = k.to_string_lossy();
            if name.starts_with("OTEL_") || name.starts_with("MINIMAL_") || name == "DO_NOT_TRACK" {
                c.env_remove(&k);
            }
        }
        c.env("MLOG_OTEL_PRINT", "1");
        for (k, v) in env {
            c.env(k, v);
        }
        let out = String::from_utf8(c.output().unwrap().stdout).unwrap();
        // libtest prints "test <name> ... " on the same line first
        out.lines()
            .find_map(|l| l.find("URLS ").and_then(|k| l.get(k..)).map(str::to_string))
            .unwrap_or_else(|| "URLS missing".to_string())
    }

    /// Langsec F4, in a process: a `DO_NOT_TRACK` that is not UTF-8 (set, to
    /// every getenv-based tool) vetoes export; a `MINIMAL_` endpoint that is
    /// not UTF-8 is refused, and does not fall back to the plain one.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_veto_still_vetoes_in_a_process() {
        use std::os::unix::ffi::OsStrExt as _;
        let junk = std::ffi::OsStr::from_bytes(b"\xff");
        let s = std::ffi::OsStr::new;
        assert_eq!(
            signal_urls_with(&[
                ("MINIMAL_TELEMETRY", s("1")),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", s("http://a:4318")),
                ("DO_NOT_TRACK", junk),
            ]),
            "URLS None None"
        );
        assert_eq!(
            signal_urls_with(&[
                ("MINIMAL_TELEMETRY", s("1")),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", s("http://a:4318")),
                ("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", junk),
            ]),
            "URLS None None"
        );
    }

    /// The spool end to end through `init` and the tracing layers, in a child
    /// process per case (init is once per process): with the opt-in and no
    /// endpoint at all, a finished span and an event are on disk before any
    /// shutdown; with `OTEL_SDK_DISABLED=true`, or without the opt-in, or with
    /// `MINIMAL_OTEL_SPOOL=0`, nothing is written.
    #[test]
    fn spool_is_written_only_when_telemetry_is_on() {
        let exe = std::env::current_exe().unwrap();
        let run = |env: &[(&str, &str)]| -> (std::path::PathBuf, tempfile::TempDir) {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("spool");
            let mut c = std::process::Command::new(&exe);
            c.args([
                "--exact",
                "otel::tests::spool_child",
                "--nocapture",
                "--test-threads=1",
            ]);
            for (k, _) in std::env::vars() {
                if k.starts_with("OTEL_") || k.starts_with("MINIMAL_") || k == "DO_NOT_TRACK" {
                    c.env_remove(k);
                }
            }
            c.env("MLOG_SPOOL_CHILD", "1")
                .env("MINIMAL_OTEL_SPOOL_DIR", &dir);
            for (k, v) in env {
                c.env(k, v);
            }
            let out = c.output().unwrap();
            assert!(
                out.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            (dir, tmp)
        };
        let (dir, _t) = run(&[("MINIMAL_TELEMETRY", "1")]);
        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "one spool file per process: {files:?}");
        let name = files[0].file_name().unwrap().to_string_lossy().to_string();
        assert!(
            name.starts_with("test-") && name.ends_with(".jsonl"),
            "{name}"
        );
        let text = std::fs::read_to_string(&files[0]).unwrap();
        assert!(
            text.contains("\"resourceSpans\"") && text.contains("\"name\":\"spool-e2e\""),
            "{text}"
        );
        assert!(
            text.contains("\"resourceLogs\"") && text.contains("spooled-event"),
            "{text}"
        );
        for off in [
            vec![("MINIMAL_TELEMETRY", "1"), ("OTEL_SDK_DISABLED", "true")],
            vec![("MINIMAL_TELEMETRY", "1"), ("MINIMAL_OTEL_SPOOL", "0")],
            vec![("MINIMAL_TELEMETRY", "1"), ("DO_NOT_TRACK", "1")],
            vec![],
        ] {
            let (dir, _t) = run(&off);
            assert!(!dir.exists(), "nothing written with {off:?}");
        }
    }

    /// Helper for `spool_is_written_only_when_telemetry_is_on` (acts only in
    /// the child): records a span and an event, then exits without shutdown.
    #[test]
    fn spool_child() {
        if std::env::var_os("MLOG_SPOOL_CHILD").is_none() {
            return;
        }
        super::init("test");
        let subscriber = tracing_subscriber::registry()
            .with(super::span_layer())
            .with(super::log_layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info_span!("spool-e2e").in_scope(|| tracing::info!("spooled-event"));
        });
    }

    /// The CLI's exit flush against a collector that accepts and never
    /// answers (`min ls` once took 2035 ms against 36 ms
    /// with such an endpoint) stays within [`super::CLI_EXIT_FLUSH`] plus the
    /// shutdown's slack, and the span is in the spool regardless. In a child
    /// process, since init is once per process.
    #[test]
    fn the_cli_exit_flush_is_bounded_when_the_collector_is_silent() {
        let tarpit = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tarpit.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for c in tarpit.incoming() {
                held.push(c); // accepted, never read, never answered
            }
        });
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("spool");
        let mut c = std::process::Command::new(std::env::current_exe().unwrap());
        c.args([
            "--exact",
            "otel::tests::flush_child",
            "--nocapture",
            "--test-threads=1",
        ]);
        for (k, _) in std::env::vars() {
            if k.starts_with("OTEL_") || k.starts_with("MINIMAL_") || k == "DO_NOT_TRACK" {
                c.env_remove(k);
            }
        }
        c.env("MLOG_FLUSH_CHILD", "1")
            .env("MINIMAL_TELEMETRY", "1")
            .env(
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                format!("http://127.0.0.1:{port}"),
            )
            .env("MINIMAL_OTEL_SPOOL_DIR", &dir);
        let out = c.output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // libtest prints "test <name> ... " on the same line first
        let ms: u64 = stdout
            .lines()
            .find_map(|l| l.find("FLUSH_MS ").and_then(|k| l.get(k + 9..)))
            .and_then(|v| v.split_whitespace().next()?.parse().ok())
            .unwrap_or_else(|| panic!("no FLUSH_MS line in {stdout}"));
        let bound = u64::try_from(super::CLI_EXIT_FLUSH.as_millis()).unwrap_or(u64::MAX) + 250;
        assert!(
            ms <= bound + 500,
            "exit flush took {ms} ms against a silent collector (bound {bound} ms)"
        );
        let text: String = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect();
        assert!(
            text.contains("\"name\":\"flush-e2e\""),
            "the span is spooled: {text}"
        );
    }

    /// Helper for `the_cli_exit_flush_is_bounded_when_the_collector_is_silent`
    /// (acts only in the child): one span, then the CLI's exit flush, timed.
    #[test]
    fn flush_child() {
        if std::env::var_os("MLOG_FLUSH_CHILD").is_none() {
            return;
        }
        super::init("test");
        super::set_exit_flush(super::CLI_EXIT_FLUSH);
        let subscriber = tracing_subscriber::registry().with(super::span_layer());
        tracing::subscriber::with_default(subscriber, || {
            drop(tracing::info_span!("flush-e2e"));
        });
        let t = std::time::Instant::now();
        super::shutdown(super::CLI_EXIT_FLUSH);
        println!("FLUSH_MS {}", t.elapsed().as_millis());
    }

    /// Helper for `enable_and_endpoint_rules` (prints only in the child).
    #[test]
    fn print_signal_urls() {
        if std::env::var_os("MLOG_OTEL_PRINT").is_some() {
            println!(
                "URLS {:?} {:?}",
                super::signal_url("TRACES"),
                super::signal_url("LOGS")
            );
        }
    }

    /// Run this test binary's `child` helper with only the given telemetry
    /// variables, a spool directory, and `flag` set, and return its stdout.
    fn in_child(child: &str, flag: &str, env: &[(&str, &str)]) -> (String, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = std::process::Command::new(std::env::current_exe().unwrap());
        c.args(["--exact", child, "--nocapture", "--test-threads=1"]);
        for (k, _) in std::env::vars() {
            if k.starts_with("OTEL_") || k.starts_with("MINIMAL_") || k == "DO_NOT_TRACK" {
                c.env_remove(k);
            }
        }
        c.env(flag, "1")
            .env("MINIMAL_OTEL_SPOOL_DIR", tmp.path().join("spool"));
        for (k, v) in env {
            c.env(k, v);
        }
        let out = c.output().unwrap();
        assert!(
            out.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        (String::from_utf8(out.stdout).unwrap(), tmp)
    }

    /// TEL-034: with `MINIMAL_OTEL_FORWARD` set, `init` installs the
    /// providers with the forward processors and no OTLP exporter (an
    /// endpoint beside it is ignored), the summary names the destination,
    /// and each finished span and emitted event reaches the queue as the
    /// spool's line. A signal switched off is not forwarded; without the
    /// opt-in nothing is.
    #[test]
    fn a_forward_destination_queues_every_record_and_builds_no_exporter() {
        let (out, _t) = in_child(
            "otel::tests::forward_child",
            "MLOG_FORWARD_CHILD",
            &[
                ("MINIMAL_TELEMETRY", "1"),
                ("MINIMAL_OTEL_FORWARD", "vsock:7353"),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9"),
            ],
        );
        assert!(out.contains("EXPORTING true"), "{out}");
        assert!(
            out.contains(
                "SUMMARY telemetry on: traces -> vsock:7353, logs -> vsock:7353, spool -> "
            ),
            "{out}"
        );
        assert!(out.contains("LINE {\"resourceSpans\":["), "{out}");
        assert!(out.contains("LINE {\"resourceLogs\":["), "{out}");
        assert!(out.contains("\"name\":\"forward-e2e\""), "{out}");

        let (out, _t) = in_child(
            "otel::tests::forward_child",
            "MLOG_FORWARD_CHILD",
            &[
                ("MINIMAL_TELEMETRY", "1"),
                ("MINIMAL_OTEL_FORWARD", "vsock:7353"),
                ("MINIMAL_OTEL_TRACES_EXPORTER", "none"),
            ],
        );
        assert!(!out.contains("resourceSpans"), "{out}");
        assert!(out.contains("LINE {\"resourceLogs\":["), "{out}");

        let (out, _t) = in_child(
            "otel::tests::forward_child",
            "MLOG_FORWARD_CHILD",
            &[("MINIMAL_OTEL_FORWARD", "vsock:7353")],
        );
        assert!(out.contains("RECEIVER none"), "{out}");

        let (out, _t) = in_child(
            "otel::tests::forward_child",
            "MLOG_FORWARD_CHILD",
            &[
                ("MINIMAL_TELEMETRY", "1"),
                ("MINIMAL_OTEL_FORWARD", "udp:1"),
            ],
        );
        assert!(out.contains("RECEIVER none"), "{out}");
        assert!(
            out.contains("WARNING telemetry: MINIMAL_OTEL_FORWARD is not a destination"),
            "{out}"
        );
    }

    /// Helper for `a_forward_destination_queues_every_record_and_builds_no_exporter`
    /// (acts only in the child): records a span and an event, then prints
    /// what the queue holds.
    #[test]
    fn forward_child() {
        if std::env::var_os("MLOG_FORWARD_CHILD").is_none() {
            return;
        }
        super::init("test");
        println!("EXPORTING {}", super::exporting());
        if let Some(log) = super::INIT_LOG.get() {
            for w in &log.warnings {
                println!("WARNING {w}");
            }
            if let Some(s) = &log.summary {
                println!("SUMMARY {s}");
            }
        }
        let Some(rx) = super::take_forward_receiver() else {
            println!("RECEIVER none");
            return;
        };
        let subscriber = tracing_subscriber::registry()
            .with(super::span_layer())
            .with(super::log_layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info_span!("forward-e2e").in_scope(|| tracing::info!("forwarded-event"));
        });
        while let Ok(line) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
            println!("LINE {line}");
        }
    }

    /// One HTTP request a sink accepted: the request line, the headers
    /// (lower-cased names) and the body.
    struct Received {
        request_line: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    /// A one-request HTTP sink on the loopback: answers `200` with an empty
    /// body and hands back what it got.
    fn http_sink() -> (u16, std::sync::mpsc::Receiver<Received>) {
        use std::io::{BufRead as _, Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = std::io::BufReader::new(stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut headers = Vec::new();
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let line = line.trim_end().to_owned();
                if line.is_empty() {
                    break;
                }
                let (k, v) = line.split_once(':').unwrap();
                let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_owned());
                if k == "content-length" {
                    length = v.parse().unwrap();
                }
                headers.push((k, v));
            }
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).unwrap();
            let mut stream = reader.into_inner();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .unwrap();
            // The test is gone when this fails; nothing to do.
            if tx
                .send(Received {
                    request_line: request_line.trim_end().to_owned(),
                    headers,
                    body: String::from_utf8(body).unwrap(),
                })
                .is_err()
            {
                eprintln!("http_sink: the test is gone");
            }
        });
        (port, rx)
    }

    /// TEL-034: `forward_request` sends a request of foreign records to this
    /// process's endpoint for the signal as OTLP/JSON, with the headers
    /// that endpoint gets under the header rule: the plain ones
    /// for a plain endpoint, the `MINIMAL_` ones for a `MINIMAL_` endpoint,
    /// and nothing at all when the signal's export is off or refused.
    #[test]
    fn forwarded_lines_go_where_this_process_exports_with_its_headers() {
        let lines = "{\"resourceSpans\":[{\"a\":1},{\"b\":2}]}";
        let header = |r: &Received, name: &str| -> Option<String> {
            r.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };

        // A plain endpoint: the plain headers travel.
        let (port, rx) = http_sink();
        let (out, _t) = in_child(
            "otel::tests::forward_lines_child",
            "MLOG_FORWARD_LINES_CHILD",
            &[
                ("MINIMAL_TELEMETRY", "1"),
                (
                    "OTEL_EXPORTER_OTLP_ENDPOINT",
                    &format!("http://127.0.0.1:{port}"),
                ),
                ("OTEL_EXPORTER_OTLP_HEADERS", "x-plain=1"),
                ("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "x-plain-traces=t"),
                ("MINIMAL_OTEL_EXPORTER_OTLP_HEADERS", "x-ours=2"),
                ("MLOG_FORWARD_LINES", lines),
            ],
        );
        assert!(out.contains("RESULT Ok(Sent(2))"), "{out}");
        let got = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(got.request_line, "POST /v1/traces HTTP/1.1");
        assert_eq!(
            header(&got, "content-type").as_deref(),
            Some("application/json")
        );
        assert_eq!(header(&got, "x-plain").as_deref(), Some("1"));
        assert_eq!(header(&got, "x-plain-traces").as_deref(), Some("t"));
        assert_eq!(header(&got, "x-ours"), None);
        assert_eq!(got.body, "{\"resourceSpans\":[{\"a\":1},{\"b\":2}]}");

        // A `MINIMAL_` endpoint: its own headers, never the plain ones.
        let (port, rx) = http_sink();
        let (out, _t) = in_child(
            "otel::tests::forward_lines_child",
            "MLOG_FORWARD_LINES_CHILD",
            &[
                ("MINIMAL_TELEMETRY", "1"),
                (
                    "MINIMAL_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                    &format!("http://127.0.0.1:{port}/ours/v1/traces"),
                ),
                ("OTEL_EXPORTER_OTLP_HEADERS", "x-plain=1"),
                ("MINIMAL_OTEL_EXPORTER_OTLP_HEADERS", "x-ours=2"),
                ("MLOG_FORWARD_LINES", lines),
            ],
        );
        assert!(out.contains("RESULT Ok(Sent(2))"), "{out}");
        let got = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(got.request_line, "POST /ours/v1/traces HTTP/1.1");
        assert_eq!(header(&got, "x-ours").as_deref(), Some("2"));
        assert_eq!(header(&got, "x-plain"), None);

        // Refused by the header rule, off, and no endpoint: nothing is sent.
        for env in [
            vec![
                ("MINIMAL_TELEMETRY", "1"),
                ("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9"),
                ("OTEL_EXPORTER_OTLP_HEADERS", "x-plain=1"),
            ],
            vec![("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9")],
            vec![("MINIMAL_TELEMETRY", "1")],
            vec![
                ("MINIMAL_TELEMETRY", "1"),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9"),
                ("MINIMAL_OTEL_TRACES_EXPORTER", "none"),
            ],
        ] {
            let mut env = env;
            env.push(("MLOG_FORWARD_LINES", lines));
            let (out, _t) = in_child(
                "otel::tests::forward_lines_child",
                "MLOG_FORWARD_LINES_CHILD",
                &env,
            );
            assert!(out.contains("RESULT Ok(Off)"), "{env:?}: {out}");
        }

        // A body that is not a request for the signal is not sent.
        let (out, _t) = in_child(
            "otel::tests::forward_lines_child",
            "MLOG_FORWARD_LINES_CHILD",
            &[
                ("MINIMAL_TELEMETRY", "1"),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9"),
                ("MLOG_FORWARD_LINES", "{\"resourceLogs\":[{\"l\":1}]}"),
            ],
        );
        assert!(
            out.contains("RESULT Err(\"not one resourceSpans request\")"),
            "{out}"
        );

        // A collector that is not there: the error, and no panic.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
            // Dropped here: the port refuses connections.
        };
        let (out, _t) = in_child(
            "otel::tests::forward_lines_child",
            "MLOG_FORWARD_LINES_CHILD",
            &[
                ("MINIMAL_TELEMETRY", "1"),
                (
                    "OTEL_EXPORTER_OTLP_ENDPOINT",
                    &format!("http://127.0.0.1:{port}"),
                ),
                ("MLOG_FORWARD_LINES", lines),
            ],
        );
        assert!(out.contains("RESULT Err("), "{out}");
    }

    /// Helper for `forwarded_lines_go_where_this_process_exports_with_its_headers`
    /// (acts only in the child): forwards the request `MLOG_FORWARD_LINES`
    /// carries as traces of two records, and prints the outcome.
    #[test]
    fn forward_lines_child() {
        if std::env::var_os("MLOG_FORWARD_LINES_CHILD").is_none() {
            return;
        }
        let body = std::env::var("MLOG_FORWARD_LINES").unwrap();
        println!(
            "RESULT {:?}",
            super::forward_request(super::Signal::Traces, body, 2)
        );
    }
}

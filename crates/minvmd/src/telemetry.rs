//! minvmd's part of minimal's OpenTelemetry (spec 25): one trace
//! from the `min` invocation that needs a VM, through minvmd, to the guest
//! minimald.
//!
//! minvmd is a process tree, not a request server: `min` spawns `minvmd run
//! --detach`, which re-execs the supervisor, which spawns the `__krun-vmm`
//! child, which boots the guest whose `/init` is minimald. The trace context
//! crosses each process boundary as a W3C `TRACEPARENT` environment variable
//! ([`forward_trace`]), each minvmd process adopts it for its root span
//! ([`root_span`]), and minvmd's own RPCs to the guest daemon carry it as the
//! same channel env the CLI's RPCs do ([`traceparent`]).
//!
//! The guest is the exception. minimald runs as the guest's `/init` with an
//! empty environment; the kernel command line is the only way in (see
//! `vm::kernel_cmdline`). [`guest_env`] hands it the host's telemetry
//! decision (`mlog::otel::guest_exports`), not the variables it was decided
//! from: the opt-in, the spool and filter settings, the per-signal
//! off-switch under the `MINIMAL_` names the guest reads first and
//! `TRACEPARENT`. Never a bare `OTEL_*` name, never headers and never an
//! endpoint (TEL-033): the boot line is world-readable in the guest as
//! `/proc/cmdline`, and minvmd logs it. With no endpoint, the guest exports
//! nothing: every signal is `none` there and its records stay in its own
//! spool. They reach the host's collector only over the VM's vsock channel
//! (TEL-034), never over the guest's own network.
//!
//! Everything here is a no-op when telemetry is off (`mlog::otel`'s opt-in):
//! no ids are adopted, nothing is forwarded, the guest boot line is unchanged.

use minimald_rpc::trace::{TRACEPARENT_ENV, TraceContext};

/// The root span of one minvmd process: `minvmd` with the subcommand, a child
/// of the caller's `TRACEPARENT` when telemetry is on and one was passed.
/// With telemetry off the span is still created (the file log's span fields),
/// but no inbound context is adopted.
pub fn root_span(cmd: &'static str) -> tracing::Span {
    let span = tracing::info_span!(
        "minvmd",
        cmd,
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
        parent_span_id = tracing::field::Empty,
    );
    let inbound = mlog::otel::exporting()
        .then(|| std::env::var(TRACEPARENT_ENV).ok())
        .flatten()
        .and_then(|v| TraceContext::parse_traceparent(&v));
    if let Some((t, s, f)) = mlog::otel::align(&span, inbound.as_ref().map(TraceContext::parts)) {
        let ctx = TraceContext::from_parts(t, s, f);
        span.record("trace_id", tracing::field::display(ctx.trace_id_hex()));
        span.record("span_id", tracing::field::display(ctx.span_id_hex()));
        if let Some(p) = &inbound {
            span.record("parent_span_id", tracing::field::display(p.span_id_hex()));
        }
    }
    span
}

/// The `run` supervisor's start phase: its process root ([`root_span`]) and,
/// under it, `supervisor.start`, which covers the switch start
/// (`net.switch.start`) and the boot (`vm.boot`, the guest's `guest.ready`
/// below it) and ends when the VM is ready.
///
/// The supervisor lives as long as its VM, and is often SIGKILLed or SIGTERMed
/// at the end rather than exiting. A span is exported only when it ends, so
/// a root and a `supervisor` span that stay open for the VM's life reach the
/// collector late or never, and every child exported at boot (the guest's
/// included) is an orphan in the meantime. Each phase gets a bounded span
/// instead: [`SupervisorStart::ready`] ends the start phase and the root,
/// flushes them, and opens `supervisor.serve` for the rest of the VM's life.
///
/// Field order is drop order: on an early return (a failed boot) the phase
/// span exits before the root it was entered in.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test)),
    expect(
        dead_code,
        reason = "used only by the libkrun build's supervisor; the tests cover it on every target"
    )
)]
pub(crate) struct SupervisorStart {
    /// `supervisor.start`, entered.
    start: tracing::span::EnteredSpan,
    /// The process root (`minvmd cmd=run`), entered.
    root: tracing::span::EnteredSpan,
}

#[cfg_attr(
    all(not(minvmd_libkrun), not(test)),
    expect(
        dead_code,
        reason = "used only by the libkrun build's supervisor; the tests cover it on every target"
    )
)]
impl SupervisorStart {
    /// How long [`ready`](Self::ready) waits for the start phase to export.
    /// The VM is already up and its state already `Running` by then, so the
    /// wait delays only the supervisor's own watch over its VMM child. The
    /// bound matches the exit-time flush in `main`.
    const READY_FLUSH: std::time::Duration = std::time::Duration::from_secs(2);

    /// Enter `supervisor.start` under `root`, the process's entered root span.
    /// Every record until [`ready`](Self::ready) carries the VM's name.
    pub(crate) fn enter(root: tracing::span::EnteredSpan) -> Self {
        let start =
            tracing::info_span!("supervisor.start", vm = %crate::state::vm_name()).entered();
        Self { start, root }
    }

    /// The VM is ready: end `supervisor.start` and the process root, flush
    /// telemetry (non-terminal, bounded by [`Self::READY_FLUSH`]) so both
    /// export while the VM runs, and return `supervisor.serve`, entered.
    /// The flush is unconditional and synchronous: it waits (up to the
    /// bound) for the start phase to leave the process before supervision
    /// goes on. Both spans end here only if nothing else holds them: every
    /// task that outlives this point runs under [`vm_task`], not under the
    /// start phase.
    ///
    /// `supervisor.serve` is a new root, not a child: it lasts as long as the
    /// VM, so as a child it would only reopen the wait this phase split ends.
    /// It carries a link to `supervisor.start` instead, which joins the two in
    /// a trace view. It carries `vm` too, so the shared file log
    /// (`<state>/logs/minvmd.log`) keeps attributing the supervisor's records
    /// to their VM after the start phase.
    pub(crate) fn ready(self) -> tracing::span::EnteredSpan {
        let serve = tracing::info_span!(
            parent: None,
            "supervisor.serve",
            vm = %crate::state::vm_name(),
        );
        // The link is taken while `supervisor.start` is open: the OTel layer
        // finds a span's context only until the span closes.
        serve.follows_from(self.start.id());
        let Self { start, root } = self;
        drop(start);
        drop(root);
        mlog::otel::flush(Self::READY_FLUSH);
        serve.entered()
    }
}

/// The span for a task or thread that outlives the supervisor's start
/// phase (the switch's supervision and datapath monitor, the egress gate's
/// accept loop, the late-report watcher): `supervisor.task`, a root of its
/// own that follows from the span it was spawned in, carrying `vm` and the
/// task's name, so its records stay attributable in the shared log.
///
/// Not the current span, on purpose. A tracing span closes, and so
/// exports, only when its last handle is dropped, and an open child keeps
/// its parent open. A task that held `supervisor.start` (or
/// `net.switch.start` under it) for the VM's life kept the whole start
/// phase open and the process root with it, so neither exported at READY
/// nor ever for a supervisor killed with its VM: `vm.boot` reached the
/// collector without its parent (macOS, 2026-10-05, the libkrun
/// supervisor). [`SupervisorStart::ready`] can end and flush only what no
/// long-lived task holds; this is what such a task holds instead.
pub(crate) fn vm_task(task: &'static str) -> tracing::Span {
    let span = tracing::info_span!(
        parent: None,
        "supervisor.task",
        task,
        vm = %crate::state::vm_name(),
    );
    span.follows_from(tracing::Span::current().id());
    span
}

/// Marks a span failed (`otel.status_code = ERROR`) when dropped, unless
/// [`ErrorUnlessOk::ok`] was called first: a span held over a stretch with
/// many returns (`?`, `bail!`) is failed by every one of them, and only the
/// path that reaches the end clears it. The span must declare
/// `otel.status_code`. `minvmd boot` and `minvmd run` each hold one over
/// `vm.boot` from its entry to READY (TEL-035).
#[cfg_attr(
    all(not(minvmd_libkrun), not(test)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests cover it on every target"
    )
)]
pub(crate) struct ErrorUnlessOk<'a>(Option<&'a tracing::Span>);

#[cfg_attr(
    all(not(minvmd_libkrun), not(test)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests cover it on every target"
    )
)]
impl<'a> ErrorUnlessOk<'a> {
    pub(crate) fn new(span: &'a tracing::Span) -> Self {
        Self(Some(span))
    }

    /// The stretch succeeded: leave the status unset.
    pub(crate) fn ok(mut self) {
        self.0 = None;
    }
}

impl Drop for ErrorUnlessOk<'_> {
    fn drop(&mut self) {
        if let Some(span) = self.0 {
            span.record("otel.status_code", "ERROR");
        }
    }
}

/// The current span's context as a W3C `traceparent`, when telemetry is on
/// and the span is exported; `None` otherwise.
pub fn traceparent() -> Option<String> {
    let (t, s, f) = mlog::otel::align(&tracing::Span::current(), None)?;
    Some(TraceContext::from_parts(t, s, f).traceparent())
}

/// Make a child minvmd process a child of the current span: set its
/// `TRACEPARENT`. With telemetry off the environment is left as it is (the
/// child does not adopt an inbound context then either).
pub fn forward_trace(cmd: &mut std::process::Command) {
    if let Some(tp) = traceparent() {
        cmd.env(TRACEPARENT_ENV, tp);
    }
}

/// The `KEY=VALUE` boot tokens that carry telemetry into the guest, read
/// through `get` (the process environment in production). Empty unless
/// telemetry is enabled on the host: a host with it off boots the guest
/// exactly as before.
///
/// What crosses is the host's decision (`mlog::otel::guest_exports`, the
/// same `Switches::decide` the host exports by), under the names the guest
/// reads first, so the guest cannot decide differently over what reached
/// it (audit F6): `MINIMAL_TELEMETRY=1`; `MINIMAL_OTEL_SPOOL=0` when the
/// spool is off; `MINIMAL_OTEL_FILTER` as given; then
/// `MINIMAL_OTEL_<signal>_EXPORTER=none` for each signal. No endpoint,
/// headers or resource attributes ever cross (TEL-033), so the guest
/// exports nothing and keeps its records in its own spool; no bare
/// `OTEL_*` name crosses either, so nothing ambient can turn it back on.
/// Any value is refused, with a warning naming the variable, when it
/// cannot be one boot token (`vm::boot_token`: a byte outside printable
/// ASCII without `"`). `TRACEPARENT` is added last when it is a well-formed
/// W3C version-00 value, so the guest daemon's own startup can join the
/// trace that booted it; anything else is dropped.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests cover it on every target"
    )
)]
pub(crate) fn guest_env(
    get: impl Fn(&str) -> Option<String>,
    enabled: bool,
    traceparent: Option<&str>,
) -> Vec<String> {
    if !enabled {
        return Vec::new();
    }
    let decided = mlog::otel::guest_exports(&get);
    let mut out = vec!["MINIMAL_TELEMETRY=1".to_string()];
    if !decided.spool {
        out.push("MINIMAL_OTEL_SPOOL=0".to_string());
    }
    if let Some(filter) = get("MINIMAL_OTEL_FILTER").filter(|v| !v.is_empty()) {
        push_token(&mut out, "MINIMAL_OTEL_FILTER", &filter);
    }
    // TEL-033: no endpoint crosses, so the guest exports no signal.
    for signal in ["TRACES", "LOGS"] {
        out.push(format!("MINIMAL_OTEL_{signal}_EXPORTER=none"));
    }
    match traceparent.map(|tp| (tp, TraceContext::parse_traceparent(tp))) {
        // A parsed traceparent is lower-case hex and dashes, always a token.
        Some((_, Some(ctx))) => {
            out.extend(crate::vm::boot_token(TRACEPARENT_ENV, &ctx.traceparent()).ok());
        }
        Some((tp, None)) => tracing::warn!(
            len = tp.len(),
            "not forwarding a malformed TRACEPARENT to the guest boot line"
        ),
        None => {}
    }
    out
}

/// Append `key=value` to `out` as one boot token, or warn why it cannot be
/// one and leave `out` as it was.
#[cfg_attr(
    all(not(minvmd_libkrun), not(test)),
    expect(
        dead_code,
        reason = "used only by the libkrun build; the tests cover it on every target"
    )
)]
fn push_token(out: &mut Vec<String>, key: &str, value: &str) {
    match crate::vm::boot_token(key, value) {
        Ok(token) => out.push(token),
        Err(reason) => tracing::warn!(
            env = %key,
            value_len = value.len(),
            reason,
            "not forwarding a telemetry setting to the guest boot line"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    /// Run `f` under a subscriber that records every warning it emits.
    fn warnings<T>(f: impl FnOnce() -> T) -> (T, String) {
        #[derive(Clone, Default)]
        struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
            type Writer = Self;
            fn make_writer(&'a self) -> Self {
                self.clone()
            }
        }
        let buf = Buf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        (out, log)
    }

    #[test]
    fn nothing_crosses_to_the_guest_when_telemetry_is_off() {
        let get = env(&[
            ("MINIMAL_TELEMETRY", "1"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://10.77.0.1:4318"),
        ]);
        assert!(guest_env(&get, false, Some("00-aa-bb-01")).is_empty());
    }

    #[test]
    fn the_decision_crosses_in_order_and_traceparent_last() {
        let get = env(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://10.77.0.1:4318"),
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_SPOOL", "0"),
            ("PATH", "/usr/bin"),
        ]);
        assert_eq!(
            guest_env(
                &get,
                true,
                Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
            ),
            vec![
                "MINIMAL_TELEMETRY=1",
                "MINIMAL_OTEL_SPOOL=0",
                "MINIMAL_OTEL_TRACES_EXPORTER=none",
                "MINIMAL_OTEL_LOGS_EXPORTER=none",
                "TRACEPARENT=00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            ]
        );
    }

    #[test]
    fn headers_and_resource_attributes_never_cross() {
        let get = env(&[
            ("MINIMAL_TELEMETRY", "1"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer_secret"),
            (
                "MINIMAL_OTEL_EXPORTER_OTLP_HEADERS",
                "authorization=Bearer_secret",
            ),
            ("OTEL_RESOURCE_ATTRIBUTES", "team=x"),
        ]);
        let out = guest_env(&get, true, None);
        assert_eq!(
            out,
            vec![
                "MINIMAL_TELEMETRY=1",
                "MINIMAL_OTEL_TRACES_EXPORTER=none",
                "MINIMAL_OTEL_LOGS_EXPORTER=none",
            ]
        );
    }

    /// TEL-033: no endpoint ever crosses, whatever the host has set and
    /// under either name, so the guest exports nothing: every signal is
    /// `none` there. An endpoint on the boot line would be readable by
    /// everything in the guest as `/proc/cmdline` and would send the guest's
    /// records over the guest's own network.
    #[test]
    fn an_endpoint_never_crosses_to_the_guest() {
        let get = env(&[
            ("MINIMAL_TELEMETRY", "1"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://10.77.0.1:4318"),
            (
                "MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT",
                "https://ingest.example/v1/9f86d081884c7d659a2feaa0c55ad015/",
            ),
            (
                "MINIMAL_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "http://10.77.0.1:4318/v1/traces",
            ),
            (
                "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                "https://user:pw@collector.example:4318/v1/logs",
            ),
            ("MINIMAL_OTEL_TRACES_EXPORTER", "otlp"),
        ]);
        let out = guest_env(&get, true, None);
        assert_eq!(
            out,
            vec![
                "MINIMAL_TELEMETRY=1",
                "MINIMAL_OTEL_TRACES_EXPORTER=none",
                "MINIMAL_OTEL_LOGS_EXPORTER=none",
            ]
        );
        assert!(
            out.iter()
                .all(|t| !t.contains("ENDPOINT") && !t.contains("4318")),
            "{out:?}"
        );
    }

    /// F11: a value that is not one token to both readers of the boot line
    /// (libkrun's printable-ASCII `Cmdline`, the kernel's quote-aware
    /// tokenizer) is dropped with a warning naming the variable, and every
    /// other setting still crosses: the boot proceeds.
    #[test]
    fn a_value_outside_the_boot_alphabet_is_dropped_with_a_warning() {
        let get = env(&[
            ("MINIMAL_TELEMETRY", "1"),
            ("MINIMAL_OTEL_FILTER", "x\u{e0}info"),
        ]);
        let (out, log) = warnings(|| guest_env(&get, true, None));
        assert_eq!(
            out,
            vec![
                "MINIMAL_TELEMETRY=1",
                "MINIMAL_OTEL_TRACES_EXPORTER=none",
                "MINIMAL_OTEL_LOGS_EXPORTER=none",
            ]
        );
        assert!(
            log.contains("MINIMAL_OTEL_FILTER"),
            "no warning names MINIMAL_OTEL_FILTER: {log}"
        );
        assert!(
            !log.contains("info"),
            "a refused value itself is not logged: {log}"
        );
    }

    /// Every token is a `MINIMAL_` name or `TRACEPARENT`: no bare `OTEL_*`
    /// variable crosses, so nothing ambient in the guest's environment can
    /// take part in its decision.
    #[test]
    fn no_bare_otel_variable_crosses_to_the_guest() {
        let get = env(&[
            ("MINIMAL_TELEMETRY", "yes"),
            ("MINIMAL_OTEL_SPOOL", "off"),
            ("MINIMAL_OTEL_FILTER", "warn"),
            ("OTEL_SDK_DISABLED", "false"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://10.77.0.1:4318"),
            (
                "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                "http://10.77.0.2:4318/v1/logs",
            ),
            ("OTEL_LOGS_EXPORTER", "otlp"),
            ("OTEL_RESOURCE_ATTRIBUTES", "team=x"),
        ]);
        let out = guest_env(
            &get,
            true,
            Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
        );
        assert_eq!(
            out,
            vec![
                "MINIMAL_TELEMETRY=1",
                "MINIMAL_OTEL_SPOOL=0",
                "MINIMAL_OTEL_FILTER=warn",
                "MINIMAL_OTEL_TRACES_EXPORTER=none",
                "MINIMAL_OTEL_LOGS_EXPORTER=none",
                "TRACEPARENT=00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            ]
        );
        assert!(
            out.iter()
                .all(|t| t.starts_with("MINIMAL_") || t.starts_with("TRACEPARENT=")),
            "{out:?}"
        );
    }

    #[test]
    fn only_a_well_formed_traceparent_crosses() {
        let get = env(&[("MINIMAL_TELEMETRY", "1")]);
        let good = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        assert_eq!(
            guest_env(&get, true, Some(good)),
            vec![
                "MINIMAL_TELEMETRY=1".to_string(),
                "MINIMAL_OTEL_TRACES_EXPORTER=none".to_string(),
                "MINIMAL_OTEL_LOGS_EXPORTER=none".to_string(),
                format!("TRACEPARENT={good}")
            ]
        );
        for bad in [
            "",
            "00-aa-bb-01",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01 init=/bin/sh",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-x",
            "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01",
            "00-00000000000000000000000000000000-b7ad6b7169203331-01",
            "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-zz",
        ] {
            assert_eq!(
                guest_env(&get, true, Some(bad)),
                vec![
                    "MINIMAL_TELEMETRY=1",
                    "MINIMAL_OTEL_TRACES_EXPORTER=none",
                    "MINIMAL_OTEL_LOGS_EXPORTER=none",
                ],
                "{bad}"
            );
        }
    }

    /// The supervisor's phases: the root and `supervisor.start`
    /// export at READY, while `supervisor.serve` is still open, with the
    /// boot's spans under `supervisor.start`; `supervisor.serve` is a new
    /// root linked to `supervisor.start`.
    #[test]
    fn the_supervisor_start_phase_exports_at_ready_and_serve_links_back() {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
        use tracing_subscriber::prelude::*;

        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("t")));
        let named = |spans: &[SpanData], name: &str| {
            spans
                .iter()
                .find(|s| s.name == name)
                .cloned()
                .unwrap_or_else(|| panic!("no {name} span in {spans:?}"))
        };

        let (at_ready, at_exit) = tracing::subscriber::with_default(subscriber, || {
            let start = SupervisorStart::enter(root_span("run").entered());
            tracing::info_span!("net.switch.start").in_scope(|| {});
            tracing::info_span!("vm.boot").in_scope(|| {});
            let serve = start.ready();
            tracing::info!("VM is up");
            let at_ready = exporter.get_finished_spans().unwrap();
            drop(serve);
            (at_ready, exporter.get_finished_spans().unwrap())
        });

        // At READY: everything but `supervisor.serve` has ended.
        let mut names: Vec<_> = at_ready.iter().map(|s| s.name.to_string()).collect();
        names.sort();
        assert_eq!(
            names,
            ["minvmd", "net.switch.start", "supervisor.start", "vm.boot"]
        );
        let root = named(&at_ready, "minvmd");
        let start = named(&at_ready, "supervisor.start");
        assert_eq!(start.parent_span_id, root.span_context.span_id());
        for child in ["net.switch.start", "vm.boot"] {
            let s = named(&at_ready, child);
            assert_eq!(s.parent_span_id, start.span_context.span_id(), "{child}");
            assert_eq!(
                s.span_context.trace_id(),
                root.span_context.trace_id(),
                "{child}"
            );
        }

        // `supervisor.serve`: its own root, linked to `supervisor.start`.
        let serve = named(&at_exit, "supervisor.serve");
        assert_eq!(serve.parent_span_id, opentelemetry::trace::SpanId::INVALID);
        assert_ne!(serve.span_context.trace_id(), root.span_context.trace_id());
        let links: Vec<_> = serve.links.iter().map(|l| l.span_context.clone()).collect();
        assert_eq!(links, std::slice::from_ref(&start.span_context));
        assert_eq!(serve.events.len(), 1, "the post-READY record is serve's");
    }

    /// (code review, macOS 2026-10-05) A task that outlives READY does not
    /// hold the start phase open: running under a [`vm_task`] span, it lets
    /// the root and `supervisor.start` export at READY, and its own span
    /// links back to where it was spawned. The control shows the failure
    /// this guards against: a handle on the current span, which is what
    /// `in_current_span()` keeps, holds `supervisor.start` and the root
    /// open past READY, so neither is exported while the task runs.
    #[test]
    fn a_task_that_outlives_ready_does_not_hold_the_start_phase_open() {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
        use tracing_subscriber::prelude::*;

        let tracer = || {
            let exporter = InMemorySpanExporter::default();
            let provider = SdkTracerProvider::builder()
                .with_simple_exporter(exporter.clone())
                .build();
            let subscriber = tracing_subscriber::registry()
                .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("t")));
            (exporter, subscriber)
        };
        let names = |spans: &[SpanData]| {
            let mut v: Vec<_> = spans.iter().map(|s| s.name.to_string()).collect();
            v.sort();
            v
        };

        let (exporter, subscriber) = tracer();
        tracing::subscriber::with_default(subscriber, || {
            let start = SupervisorStart::enter(root_span("run").entered());
            // What the switch's supervision task runs under, spawned from
            // `net.switch.start`; still running at READY and long after.
            let task = tracing::info_span!("net.switch.start")
                .in_scope(|| vm_task("net.switch.supervise"));
            let running = task.clone().entered();
            tracing::info_span!("vm.boot").in_scope(|| {});
            let serve = start.ready();
            let at_ready = exporter.get_finished_spans().unwrap();
            assert_eq!(
                names(&at_ready),
                ["minvmd", "net.switch.start", "supervisor.start", "vm.boot"],
                "the whole start phase exported at READY with a task still running"
            );
            let switch_start = at_ready
                .iter()
                .find(|s| s.name == "net.switch.start")
                .unwrap()
                .span_context
                .clone();
            drop(running);
            drop(task);
            drop(serve);
            let at_exit = exporter.get_finished_spans().unwrap();
            let task = at_exit
                .iter()
                .find(|s| s.name == "supervisor.task")
                .expect("the task's span exports when it ends");
            assert_eq!(task.parent_span_id, opentelemetry::trace::SpanId::INVALID);
            let links: Vec<_> = task.links.iter().map(|l| l.span_context.clone()).collect();
            assert_eq!(
                links,
                [switch_start],
                "it follows from where it was spawned"
            );
            assert!(
                task.attributes
                    .iter()
                    .any(|kv| kv.key.as_str() == "task"
                        && kv.value.as_str() == "net.switch.supervise"),
                "{:?}",
                task.attributes
            );
        });

        // Control: the mechanism this guards against.
        let (exporter, subscriber) = tracer();
        tracing::subscriber::with_default(subscriber, || {
            let start = SupervisorStart::enter(root_span("run").entered());
            let held = tracing::Span::current();
            let serve = start.ready();
            assert_eq!(
                names(&exporter.get_finished_spans().unwrap()),
                Vec::<String>::new(),
                "a held handle on the start phase keeps it, and the root, unexported"
            );
            drop(held);
            assert_eq!(
                names(&exporter.get_finished_spans().unwrap()),
                ["minvmd", "supervisor.start"],
                "they export once the handle goes, long after READY"
            );
            drop(serve);
        });
    }

    /// TEL-035: a failed boot marks `vm.boot` as an error. The supervisor
    /// declares the span with an empty `otel.status_code` and records
    /// `"ERROR"` when the boot fails (`cmd/run.rs`); this pins that the
    /// declaration and the record, exactly as written there, export as an
    /// OTel error status, and that a boot that succeeds leaves it unset. No
    /// VM boots here: the boot itself needs libkrun and a kernel.
    #[test]
    fn a_failed_boot_exports_vm_boot_with_an_error_status() {
        use opentelemetry::trace::{Status, TracerProvider as _};
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
        use tracing_subscriber::prelude::*;

        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("t")));
        tracing::subscriber::with_default(subscriber, || {
            for failed in [true, false] {
                let boot_span = tracing::info_span!(
                    "vm.boot",
                    vm = "default",
                    failed,
                    otel.status_code = tracing::field::Empty,
                )
                .entered();
                if failed {
                    boot_span.record("otel.status_code", "ERROR");
                }
                drop(boot_span);
            }
        });
        let spans = exporter.get_finished_spans().unwrap();
        let status = |failed: bool| {
            spans
                .iter()
                .find(|s| {
                    s.attributes
                        .iter()
                        .any(|kv| kv.key.as_str() == "failed" && kv.value == failed.into())
                })
                .map(|s| s.status.clone())
                .unwrap_or_else(|| panic!("no vm.boot with failed={failed} in {spans:?}"))
        };
        assert!(
            matches!(status(true), Status::Error { .. }),
            "{:?}",
            status(true)
        );
        assert_eq!(status(false), Status::Unset);
    }

    /// TEL-035 for `minvmd boot`: every return before READY marks
    /// `vm.boot` failed through the guard it holds, and the path that
    /// reaches READY leaves the status unset.
    #[test]
    fn an_early_return_marks_vm_boot_failed() {
        use opentelemetry::trace::{Status, TracerProvider as _};
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
        use tracing_subscriber::prelude::*;

        fn boot(step: i64) -> Result<(), &'static str> {
            let boot_span =
                tracing::info_span!("vm.boot", step, otel.status_code = tracing::field::Empty)
                    .entered();
            let failed = ErrorUnlessOk::new(&boot_span);
            if step == 0 {
                return Err("spawn failed");
            }
            (step != 1).then_some(()).ok_or("boot timed out")?;
            failed.ok();
            drop(boot_span);
            Ok(())
        }

        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("t")));
        tracing::subscriber::with_default(subscriber, || {
            assert_eq!(boot(0), Err("spawn failed"));
            assert_eq!(boot(1), Err("boot timed out"));
            assert_eq!(boot(2), Ok(()));
        });
        let spans = exporter.get_finished_spans().unwrap();
        let status = |step: i64| {
            spans
                .iter()
                .find(|s| {
                    s.attributes
                        .iter()
                        .any(|kv| kv.key.as_str() == "step" && kv.value == step.into())
                })
                .map(|s| s.status.clone())
                .unwrap_or_else(|| panic!("no vm.boot with step={step} in {spans:?}"))
        };
        assert!(matches!(status(0), Status::Error { .. }), "{:?}", status(0));
        assert!(matches!(status(1), Status::Error { .. }), "{:?}", status(1));
        assert_eq!(status(2), Status::Unset);
    }

    /// TEL-035 for `minvmd run`: the foreground supervisor
    /// boots in a loop (a T93 redraw boots again under a fresh `vm.boot`),
    /// and every return between the span's entry and READY — the spawn's
    /// `?`, the lifecycle lock/read/write `?`s, the `bail!` on a lifecycle
    /// changed during spawn, a failed wait — marks that boot's span failed,
    /// while a redrawn boot that reaches READY leaves its own span unset.
    /// The model mirrors `run_foreground`'s shape; the source check below
    /// pins the real function to it.
    #[test]
    fn an_early_return_from_run_marks_vm_boot_failed() {
        use opentelemetry::trace::{Status, TracerProvider as _};
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
        use tracing_subscriber::prelude::*;

        /// `fail_at`: 0 spawn, 1 lifecycle lock, 2 lifecycle changed during
        /// spawn, 3 READY wait; anything else reaches READY. `redraws`
        /// boots that reach READY but are redrawn before the final one.
        fn run(fail_at: i64, redraws: i64) -> Result<(), &'static str> {
            let mut boot = 0;
            loop {
                let boot_span = tracing::info_span!(
                    "vm.boot",
                    fail_at,
                    boot,
                    otel.status_code = tracing::field::Empty
                )
                .entered();
                let failed = ErrorUnlessOk::new(&boot_span);
                let last = boot == redraws;
                (!(last && fail_at == 0))
                    .then_some(())
                    .ok_or("spawn failed")?;
                (!(last && fail_at == 1))
                    .then_some(())
                    .ok_or("acquiring lifecycle write lock")?;
                if last && fail_at == 2 {
                    return Err("lifecycle changed during spawn");
                }
                (!(last && fail_at == 3))
                    .then_some(())
                    .ok_or("boot timed out")?;
                failed.ok();
                drop(boot_span);
                if last {
                    return Ok(());
                }
                boot += 1;
            }
        }

        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("t")));
        tracing::subscriber::with_default(subscriber, || {
            assert_eq!(run(0, 0), Err("spawn failed"));
            assert_eq!(run(1, 0), Err("acquiring lifecycle write lock"));
            assert_eq!(run(2, 1), Err("lifecycle changed during spawn"));
            assert_eq!(run(3, 0), Err("boot timed out"));
            assert_eq!(run(4, 1), Ok(()));
        });
        let spans = exporter.get_finished_spans().unwrap();
        let status = |fail_at: i64, boot: i64| {
            spans
                .iter()
                .find(|s| {
                    let has = |k: &str, v: i64| {
                        s.attributes
                            .iter()
                            .any(|kv| kv.key.as_str() == k && kv.value == v.into())
                    };
                    has("fail_at", fail_at) && has("boot", boot)
                })
                .map(|s| s.status.clone())
                .unwrap_or_else(|| panic!("no vm.boot {fail_at}/{boot} in {spans:?}"))
        };
        for fail_at in 0..4 {
            let last = i64::from(fail_at == 2);
            assert!(
                matches!(status(fail_at, last), Status::Error { .. }),
                "fail_at={fail_at}: {:?}",
                status(fail_at, last)
            );
        }
        assert_eq!(status(2, 0), Status::Unset, "a redrawn boot that was ready");
        assert_eq!(status(4, 0), Status::Unset);
        assert_eq!(status(4, 1), Status::Unset);
    }

    /// TEL-035: both supervisors that open `vm.boot` (`minvmd boot` and the
    /// foreground `minvmd run`) take an [`ErrorUnlessOk`] on it straight
    /// after entering it and clear it just before the span drops, and
    /// neither marks the status by hand (a hand-written mark covers one
    /// return, not every `?`). A source check: the guard's behaviour is what
    /// the two model tests above prove.
    #[test]
    fn every_vm_boot_is_held_by_the_guard() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cmd");
        for file in ["boot.rs", "run.rs"] {
            let text = std::fs::read_to_string(src.join(file)).unwrap();
            let (_, rest) = text
                .split_once("\"vm.boot\"")
                .unwrap_or_else(|| panic!("{file} opens vm.boot"));
            let (_, after_entry) = rest.split_once(".entered();").expect("entered");
            let (before_guard, _) = after_entry
                .split_once("ErrorUnlessOk::new(&boot_span);")
                .unwrap_or_else(|| panic!("{file} holds ErrorUnlessOk over vm.boot"));
            // Only comments, and the guard's own `let`, between the two.
            let code_between: Vec<&str> = before_guard
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with("//"))
                .collect();
            assert_eq!(
                code_between,
                ["let boot_failed = crate::telemetry::"],
                "{file}: the guard is taken right after entering vm.boot"
            );
            assert!(
                !text.contains("boot_span.record(\"otel.status_code\""),
                "{file} marks vm.boot by hand"
            );
            if let Some((before_drop, _)) = rest.split_once("drop(boot_span);") {
                assert!(
                    before_drop.contains("boot_failed.ok();"),
                    "{file}: READY clears the guard before vm.boot drops"
                );
            } else {
                assert!(
                    rest.contains("boot_failed.ok();"),
                    "{file}: READY clears the guard"
                );
            }
        }
    }

    /// Every tokio task minvmd spawns carries the caller's span
    /// (`.in_current_span()` or `.instrument(..)` on the spawned future): a
    /// task starts with no current span, so a bare spawn cuts its records
    /// out of the trace and off the VM they belong to.
    ///
    /// A source scan, with the limits of one. It finds `tokio::spawn(`,
    /// `task::spawn(` and `spawn_local(`; `.spawn(` on a binding made with
    /// `JoinSet::new()` in the same file; and `spawn_blocking(`, whose
    /// closure must enter a span (`in_scope(` or `.entered()`). It refuses
    /// a `use` of tokio's `spawn`, so a bare `spawn(` cannot hide one. The
    /// call's extent is found by matching its parentheses, so formatting
    /// does not move it. It cannot see a spawn through a helper, an alias
    /// other than those, or a macro, and it proves the code's shape, not the
    /// span at run time: the span tests above do that for the phases.
    #[test]
    fn every_tokio_spawn_carries_the_callers_span() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        /// The text of the call whose `(` is at `open`, through its `)`.
        /// Byte offsets of ASCII parentheses, so every slice is on a char
        /// boundary.
        fn call_args(text: &str, open: usize) -> &str {
            let mut depth = 0usize;
            for (i, b) in text.bytes().enumerate().skip(open) {
                match b {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            return text.get(open..=i).unwrap_or_default();
                        }
                    }
                    _ => {}
                }
            }
            text.get(open..).unwrap_or_default()
        }
        let before = |text: &str, at: usize| text.get(..at).unwrap_or_default().to_owned();
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        let mut bad = Vec::new();
        let mut seen = 0usize;
        for f in &files {
            let text = std::fs::read_to_string(f).unwrap();
            // Built with concat! so this test's own source never matches.
            let mut needles: Vec<String> = [
                concat!("tokio::", "spawn("),
                concat!("task::", "spawn("),
                concat!("spawn_", "local("),
                concat!("spawn_", "blocking("),
            ]
            .map(String::from)
            .to_vec();
            for line in text.lines() {
                let t = line.trim_start();
                if t.starts_with("//") {
                    continue;
                }
                let imports_spawn = (t.contains(concat!("tokio::", "spawn"))
                    && !t.contains("spawn_"))
                    || t.contains(concat!("task::", "spawn"));
                if t.starts_with("use ") && imports_spawn {
                    bad.push(format!("{}: imports tokio's spawn: {t}", f.display()));
                }
                // `let mut relays = JoinSet::new();` makes `relays.spawn(` one.
                if let Some(rest) = t.strip_prefix("let mut ")
                    && let Some((name, init)) = rest.split_once(" = ")
                    && init.starts_with(concat!("JoinSet", "::new()"))
                {
                    needles.push(format!("{name}.spawn("));
                }
            }
            for needle in &needles {
                for (at, _) in text.match_indices(needle.as_str()) {
                    let head = before(&text, at);
                    let line_start = head.rfind('\n').map_or(0, |i| i + 1);
                    let this_line = text
                        .get(line_start..)
                        .and_then(|rest| rest.lines().next())
                        .unwrap_or_default();
                    if this_line.trim_start().starts_with("//") {
                        continue;
                    }
                    seen += 1;
                    let args = call_args(&text, at + needle.len() - 1);
                    let carried = if needle.starts_with(concat!("spawn_", "blocking")) {
                        args.contains("in_scope(") || args.contains(".entered()")
                    } else {
                        args.contains("in_current_span()") || args.contains(".instrument(")
                    };
                    if !carried {
                        bad.push(format!(
                            "{}:{}: {}",
                            f.display(),
                            head.matches('\n').count() + 1,
                            this_line.trim()
                        ));
                    }
                }
            }
        }
        assert!(
            seen > 0,
            "the scan found no spawn at all: it is looking in the wrong place"
        );
        assert!(
            bad.is_empty(),
            "spawn in the caller's span:\n{}",
            bad.join("\n")
        );
    }
}

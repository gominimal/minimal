//! A body for an exported log record that has none.
//!
//! `#[tracing::instrument(err)]` logs a failure as an event whose only field
//! is `error`: no `message`, so the bridge exports the record with an empty
//! body and a search of log bodies never finds it (gominimal/minimal#3223).
//! [`BodyFromError`] wraps the bridge and notes, for an event with an `error`
//! field and no `message` field, its target (the module, such as
//! `op::materialize`) and the span it was emitted in; [`FillBody`], the
//! logger's first processor, then gives the record the body
//! `<target>::<span name> failed: <error>`, or `<target>: <error>` when there
//! is no span or the span is from another target. For a contextual event the
//! span is the subscriber's current one, so it is the span the event was
//! emitted in even when the export filter hides it, provided another layer
//! admitted that span; when none did, the span was never created, and a
//! current span the caller entered is named in its place if it has the
//! event's target. An explicit `parent:` is named only when the export filter
//! admits it; a parent it hides names no span. The rule is structural, so it
//! applies at every level (`err(level = "warn")` makes the same record at
//! WARN). The `error` attribute is kept as it is; a record with a message, or
//! with no string `error` attribute, is not touched.

use std::cell::Cell;
use std::time::Duration;

use opentelemetry::InstrumentationScope;
use opentelemetry::logs::{AnyValue, LogRecord as _, Severity};
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::{LogProcessor, SdkLogRecord};
use tracing::level_filters::LevelFilter;
use tracing::subscriber::Interest;
use tracing::{Dispatch, Event, Metadata, Subscriber, span};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

thread_local! {
    /// Set by [`BodyFromError`] while the bridge handles an event that has an
    /// `error` field and no `message` field: the event's target and the name
    /// of the span it was emitted in, if any. The bridge emits synchronously,
    /// so [`FillBody`] reads it on the same thread.
    static PENDING: Cell<Option<(&'static str, Option<&'static str>)>> = const { Cell::new(None) };
}

fn put(pending: Option<(&'static str, Option<&'static str>)>) {
    // During thread teardown the slot is gone; the record keeps its body.
    PENDING.try_with(|p| p.set(pending)).unwrap_or(());
}

/// Clears [`PENDING`] when the bridge is done, even if it panicked.
struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        put(None);
    }
}

/// The log export layer's wrapper: forwards everything to the bridge, and
/// around an event with an `error` field and no `message` field records its
/// target and span name for [`FillBody`]. Other events cost two field-name lookups.
pub struct BodyFromError<L>(pub(crate) L);

impl<S, L> Layer<S> for BodyFromError<L>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    L: Layer<S>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let fields = metadata.fields();
        if fields.field("message").is_some() || fields.field("error").is_none() {
            self.0.on_event(event, ctx);
            return;
        }
        // Not `ctx.event_span`: this layer sits behind the export filter, so
        // `ctx` looks spans up through it, and a span the filter hides (an
        // `#[instrument(level = "debug", err)]` function's under the default
        // `info`) gives way to the nearest ancestor it admits, a caller's span.
        // The subscriber's current span ignores per-layer filters. An explicit
        // parent can only be looked up through `ctx`; hidden, it names nothing.
        let span = if event.is_root() {
            None
        } else if event.is_contextual() {
            ctx.current_span().metadata()
        } else {
            event
                .parent()
                .and_then(|id| ctx.span(id))
                .map(|s| s.metadata())
        };
        // `#[instrument]` gives its span and its `err` event the same target.
        // A span from another module is a caller's (the function's own span
        // was never created), so the body names no span rather than that one.
        let span = span
            .filter(|s| s.target() == metadata.target())
            .map(|s| s.name());
        put(Some((metadata.target(), span)));
        let _reset = Reset;
        self.0.on_event(event, ctx);
    }

    fn on_register_dispatch(&self, subscriber: &Dispatch) {
        self.0.on_register_dispatch(subscriber);
    }
    fn on_layer(&mut self, subscriber: &mut S) {
        self.0.on_layer(subscriber);
    }
    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        self.0.register_callsite(metadata)
    }
    fn enabled(&self, metadata: &Metadata<'_>, ctx: Context<'_, S>) -> bool {
        self.0.enabled(metadata, ctx)
    }
    fn max_level_hint(&self) -> Option<LevelFilter> {
        self.0.max_level_hint()
    }
    fn event_enabled(&self, event: &Event<'_>, ctx: Context<'_, S>) -> bool {
        self.0.event_enabled(event, ctx)
    }
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        self.0.on_new_span(attrs, id, ctx);
    }
    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        self.0.on_record(id, values, ctx);
    }
    fn on_follows_from(&self, id: &span::Id, follows: &span::Id, ctx: Context<'_, S>) {
        self.0.on_follows_from(id, follows, ctx);
    }
    fn on_enter(&self, id: &span::Id, ctx: Context<'_, S>) {
        self.0.on_enter(id, ctx);
    }
    fn on_exit(&self, id: &span::Id, ctx: Context<'_, S>) {
        self.0.on_exit(id, ctx);
    }
    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        self.0.on_close(id, ctx);
    }
    fn on_id_change(&self, old: &span::Id, new: &span::Id, ctx: Context<'_, S>) {
        self.0.on_id_change(old, new, ctx);
    }
}

/// The logger's first processor: gives a record [`BodyFromError`] marked, and
/// that still has no body, the body built from its target, span and `error`
/// attribute. Changes made here reach every later processor.
#[derive(Debug)]
pub(crate) struct FillBody;

impl LogProcessor for FillBody {
    fn emit(&self, record: &mut SdkLogRecord, _scope: &InstrumentationScope) {
        let Some((target, span)) = PENDING.try_with(Cell::get).ok().flatten() else {
            return;
        };
        if record.body().is_some() {
            return;
        }
        let Some(error) = record.attributes_iter().find_map(|(k, v)| match v {
            AnyValue::String(s) if k.as_str() == "error" => Some(s.as_str()),
            _ => None,
        }) else {
            return;
        };
        let body = match span {
            Some(name) => format!("{target}::{name} failed: {error}"),
            None => format!("{target}: {error}"),
        };
        record.set_body(AnyValue::from(body));
    }

    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        Ok(())
    }

    /// Never the reason a record is created: the logger asks whether any
    /// processor wants it, and this one only edits what others take.
    fn event_enabled(&self, _level: Severity, _target: &str, _name: Option<&str>) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry::logs::AnyValue;
    use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
    use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider};
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::layer::Identity;
    use tracing_subscriber::prelude::*;

    /// Runs `f` under the export stack as `log_layer` builds it (the wrapper
    /// in front of the bridge behind a per-layer filter, `info` as
    /// `MINIMAL_OTEL_FILTER` defaults to, and [`super::FillBody`] first) and
    /// returns each exported record's body and `error` attribute.
    fn exported(f: impl FnOnce()) -> Vec<(Option<String>, Option<String>)> {
        exported_with(false, f)
    }

    /// [`exported`], and with `debug_elsewhere` another layer that admits
    /// every level (a console at `RUST_LOG=debug`), so debug spans exist in
    /// the registry while the export filter still hides them.
    fn exported_with(
        debug_elsewhere: bool,
        f: impl FnOnce(),
    ) -> Vec<(Option<String>, Option<String>)> {
        let exporter = InMemoryLogExporter::default();
        let provider = SdkLoggerProvider::builder()
            .with_log_processor(super::FillBody)
            .with_simple_exporter(exporter.clone())
            .build();
        // The export layer is built in each branch: a `Filtered` layer is
        // typed by the subscriber below it, and the branches differ there.
        let bridge = || super::BodyFromError(OpenTelemetryTracingBridge::new(&provider));
        if debug_elsewhere {
            let subscriber = tracing_subscriber::registry()
                .with(Identity::new().with_filter(LevelFilter::TRACE))
                .with(bridge().with_filter(LevelFilter::INFO));
            tracing::subscriber::with_default(subscriber, f);
        } else {
            let subscriber =
                tracing_subscriber::registry().with(bridge().with_filter(LevelFilter::INFO));
            tracing::subscriber::with_default(subscriber, f);
        }
        let text = |v: &AnyValue| match v {
            AnyValue::String(s) => s.as_str().to_owned(),
            other => format!("{other:?}"),
        };
        exporter
            .get_emitted_logs()
            .unwrap()
            .iter()
            .map(|l| {
                let error = l
                    .record
                    .attributes_iter()
                    .find(|(k, _)| k.as_str() == "error")
                    .map(|(_, v)| text(v));
                (l.record.body().map(text), error)
            })
            .collect()
    }

    #[tracing::instrument(err)]
    fn fails() -> Result<(), String> {
        Err("disk full".to_owned())
    }

    /// The #3223 shape: a failing `#[instrument(err)]` function's record gets
    /// `<target>::<span> failed: <error>`, and the `error` attribute is
    /// unchanged; with no span the body is `<target>: <error>`.
    #[test]
    fn an_instrumented_failure_gets_a_body_from_its_span_and_error() {
        let got = exported(|| {
            assert!(fails().is_err());
            tracing::error!(error = "boom");
        });
        assert_eq!(
            got,
            vec![
                (
                    Some("mlog::otel::body::tests::fails failed: disk full".to_owned()),
                    Some("disk full".to_owned())
                ),
                (
                    Some("mlog::otel::body::tests: boom".to_owned()),
                    Some("boom".to_owned())
                ),
            ]
        );
    }

    #[tracing::instrument(level = "debug", err)]
    fn loads() -> Result<(), String> {
        Err("bad graph".to_owned())
    }

    /// A debug-level instrumented function's `err` event is ERROR, so it is
    /// exported while its span is hidden by the `info` export filter; the
    /// body still names that function's span, inside an `info` span of the
    /// caller or under no span at all.
    #[test]
    fn a_span_the_export_filter_hides_is_still_the_one_named() {
        let got = exported_with(true, || {
            let _in = tracing::info_span!("materialize").entered();
            assert!(loads().is_err());
        });
        let alone = exported_with(true, || assert!(loads().is_err()));
        let want = (
            Some("mlog::otel::body::tests::loads failed: bad graph".to_owned()),
            Some("bad graph".to_owned()),
        );
        assert_eq!((got, alone), (vec![want.clone()], vec![want]));
    }

    /// Control: an info-level function's span passes the export filter and
    /// is named, inside a caller's span as well, under the same two-layer stack.
    #[test]
    fn a_span_the_export_filter_admits_names_itself() {
        let got = exported_with(true, || {
            let _in = tracing::info_span!("materialize").entered();
            assert!(fails().is_err());
        });
        assert_eq!(
            got,
            vec![(
                Some("mlog::otel::body::tests::fails failed: disk full".to_owned()),
                Some("disk full".to_owned())
            )]
        );
    }

    /// With no layer admitting debug the function's span is never created,
    /// so the current span is the caller's. One from another module is not
    /// named as the failing function; the body falls back to `<target>: <error>`.
    #[test]
    fn a_callers_span_from_another_module_is_not_named() {
        let got = exported_with(false, || {
            let _in = tracing::info_span!(target: "op::materialize", "materialize").entered();
            assert!(loads().is_err());
        });
        assert_eq!(
            got,
            vec![(
                Some("mlog::otel::body::tests: bad graph".to_owned()),
                Some("bad graph".to_owned())
            )]
        );
    }

    /// Control: an explicit parent is named when the export filter admits
    /// it, and names nothing (not some other span) when the filter hides it.
    #[test]
    fn an_explicit_parent_is_named_only_when_admitted() {
        let got = exported_with(true, || {
            let shown = tracing::info_span!("step");
            let hidden = tracing::debug_span!("load");
            let _in = tracing::info_span!("outer").entered();
            tracing::error!(parent: &shown, error = "a");
            tracing::error!(parent: &hidden, error = "b");
        });
        assert_eq!(
            got,
            vec![
                (
                    Some("mlog::otel::body::tests::step failed: a".to_owned()),
                    Some("a".to_owned())
                ),
                (
                    Some("mlog::otel::body::tests: b".to_owned()),
                    Some("b".to_owned())
                ),
            ]
        );
    }

    /// A record with its own message keeps it; one with no `error` field keeps
    /// an empty body (no text is invented).
    #[test]
    fn a_message_or_a_missing_error_is_left_alone() {
        let got = exported(|| {
            let _in = tracing::info_span!("step").entered();
            tracing::error!(error = "e", "own message");
            tracing::error!(code = 3);
        });
        assert_eq!(
            got,
            vec![
                (Some("own message".to_owned()), Some("e".to_owned())),
                (None, None),
            ]
        );
    }
}

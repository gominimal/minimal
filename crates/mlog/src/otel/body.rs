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
//! is no span. The rule
//! is structural, so it applies at every level (`err(level = "warn")` makes
//! the same record at WARN). The `error` attribute is kept as it is; a record
//! with a message, or with no string `error` attribute, is not touched.

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
        put(Some((
            metadata.target(),
            ctx.event_span(event).map(|s| s.name()),
        )));
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
    use tracing_subscriber::prelude::*;

    /// Runs `f` under the export stack as `log_layer` builds it (the wrapper
    /// in front of the bridge, [`super::FillBody`] first) and returns each
    /// exported record's body and `error` attribute.
    fn exported(f: impl FnOnce()) -> Vec<(Option<String>, Option<String>)> {
        let exporter = InMemoryLogExporter::default();
        let provider = SdkLoggerProvider::builder()
            .with_log_processor(super::FillBody)
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(super::BodyFromError(
            OpenTelemetryTracingBridge::new(&provider),
        ));
        tracing::subscriber::with_default(subscriber, f);
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

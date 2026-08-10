//! The JSON-lines file-log layer shared by the `minimald` and `minvmd`
//! daemons. Both write their on-disk diagnostic logs through
//! [`json_file_layer`], so the file format — one flat JSON object per line,
//! span fields hoisted to the top level, static resource fields under their
//! OTEL semantic-convention names — has a single definition and a single
//! contract test. Console output stays human-format everywhere; this layer is
//! only for the files `min bug` collects and downstream tools parse.

/// Build the JSON-lines file-log layer for a daemon named `service_name`.
///
/// Records are flat — span fields (`trace_id`/`span_id`/`conn`/`channel`) are
/// flattened to the top level so OTLP-mapped consumers can copy them — and
/// carry the static resource fields `service.name` and `service.version` under
/// their OTEL semantic-convention keys. The version is the shared workspace
/// value ([`version::LONG_VERSION`]), identical for every binary, so only the
/// service name varies between callers.
#[must_use]
pub fn json_file_layer<S>(
    writer: tracing_appender::non_blocking::NonBlocking,
    service_name: &str,
) -> json_subscriber::fmt::Layer<S, tracing_appender::non_blocking::NonBlocking>
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    let mut layer = json_subscriber::fmt::layer()
        .with_writer(writer)
        .flatten_span_list_on_top_level(true)
        .with_current_span(false);
    let inner = layer.inner_layer_mut();
    inner.add_static_field(
        opentelemetry_semantic_conventions::attribute::SERVICE_NAME,
        service_name.into(),
    );
    inner.add_static_field(
        opentelemetry_semantic_conventions::attribute::SERVICE_VERSION,
        version::LONG_VERSION.into(),
    );
    layer
}

#[cfg(test)]
mod json_log_shape {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::prelude::*;

    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The file-log contract Unit 4 promises: one JSON object per line,
    /// span fields (trace ids) flattened to top level, resource fields
    /// under their OTEL semantic-convention names.
    #[test]
    fn file_lines_are_flat_json_with_resource_fields_and_span_ids() {
        let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
        let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .lossy(false)
            .finish(buf.clone());
        let subscriber =
            tracing_subscriber::registry().with(super::json_file_layer(writer, "testsvc"));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "cmd",
                trace_id = "0af7651916cd43dd8448eb211c80319c",
                span_id = "b7ad6b7169203331",
            );
            let _e = span.enter();
            tracing::info!(answer = 42, "hello file");
        });
        drop(guard); // flush the worker

        let bytes = buf.0.lock().unwrap().clone();
        let line = String::from_utf8(bytes).unwrap();
        let json: serde_json_lenient::Value =
            serde_json_lenient::from_str(line.lines().next().unwrap())
                .unwrap_or_else(|e| panic!("not JSON: {e}: {line}"));
        assert_eq!(json["service.name"], "testsvc");
        assert_eq!(json["service.version"], version::LONG_VERSION);
        assert_eq!(
            json["trace_id"], "0af7651916cd43dd8448eb211c80319c",
            "span fields flatten to top level: {json}"
        );
        assert_eq!(json["span_id"], "b7ad6b7169203331");
        assert_eq!(json["fields"]["message"], "hello file");
        assert_eq!(json["fields"]["answer"], 42);
        assert_eq!(json["level"], "INFO");
        assert!(json["timestamp"].is_string(), "got: {json}");
    }
}

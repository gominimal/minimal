//! Progress events for materializing a declared output, shared by the
//! operation itself and the image writer it drives.

use std::borrow::Cow;

use futures::channel::mpsc::UnboundedSender;

/// Progress emitted while an artifact is assembled. [`crate::Materialize`]
/// never prints; every consumer renders these itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializeEvent {
    /// Assembly of the named output began, from these top-level packages.
    Started {
        output: String,
        packages: Vec<String>,
    },
    /// The image will be assembled from this many layers, base layer included.
    Layers { total: usize },
    /// A layer's assembly started.
    LayerStarted { package: String, subset: bool },
    /// A layer was archived, compressed and digested. `bytes` is compressed.
    LayerFinished {
        package: String,
        subset: bool,
        bytes: u64,
    },
    /// The image's target architecture, as read from the graph.
    Architecture { arch: String },
    /// A [`crate::OutputSpec::RawFile`] was located in this package's cached
    /// build.
    Found { package: String, path: String },
    /// The artifact is complete.
    Finished { bytes: u64 },
}

impl MaterializeEvent {
    /// This event as one human-readable log line. Shared so every transport
    /// reports a materialize identically.
    pub fn render(&self) -> String {
        fn layer(package: &str, subset: bool) -> Cow<'_, str> {
            match subset {
                true => Cow::Owned(format!("{package} (subset)")),
                false => Cow::Borrowed(package),
            }
        }

        match self {
            MaterializeEvent::Started { output, packages } => {
                format!("Materializing {output} from packages: {packages:?}")
            }
            MaterializeEvent::Layers { total } => format!(
                "Will create {total} layers: base layer + {} packages",
                total.saturating_sub(1)
            ),
            MaterializeEvent::LayerStarted { package, subset } => {
                format!("Creating layer for: {}", layer(package, *subset))
            }
            MaterializeEvent::LayerFinished {
                package,
                subset,
                bytes,
            } => format!(
                "Created layer for {}: {}",
                layer(package, *subset),
                size::Size::from_bytes(*bytes)
            ),
            MaterializeEvent::Architecture { arch } => format!("OCI image architecture: {arch}"),
            MaterializeEvent::Found { package, path } => format!("Found {path} in {package}"),
            MaterializeEvent::Finished { bytes } => {
                format!("Wrote {}", size::Size::from_bytes(*bytes))
            }
        }
    }
}

/// Best-effort progress reporting; a hung-up receiver must never fail the
/// artifact.
#[derive(Clone)]
pub(crate) struct Emitter(Option<UnboundedSender<MaterializeEvent>>);

impl Emitter {
    pub(crate) fn new(sender: Option<UnboundedSender<MaterializeEvent>>) -> Self {
        Self(sender)
    }

    pub(crate) fn send(&self, event: MaterializeEvent) {
        if let Some(tx) = &self.0 {
            let _ = tx.unbounded_send(event);
        }
    }
}

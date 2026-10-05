//! Actor mailboxes and blocking-pool calls that carry the caller's trace.
//!
//! The session manager and each session actor handle messages on their own
//! tasks, so spans they open have no parent: in a trace they appeared as
//! separate roots, cut off from the RPC that caused them. These wrappers
//! capture the caller's trace context at `send` and hand it back at `recv`, so
//! a handler's span can name its caller as parent ([`Receiver::recv`] says
//! how). Everything else is tokio's `mpsc`, unchanged.
//!
//! A message carries the caller's ids, never the caller's `Span`: a strong
//! `Span` in a queue held the caller's span open until the message was
//! handled, so a caller that timed out (List's bounded probe of a busy
//! session) stayed open and its children started after it had ended. The ids
//! name the parent whether or not the sender is still there; a parent exported
//! later still joins.
//!
//! [`spawn_blocking`] does the same for work moved onto tokio's blocking pool:
//! the pool thread has no current span, so spans opened there (the package
//! graph, `checkouts.checkout_of`, composition) became roots of their own
//! traces, invisible from the RPC that caused them. Use it instead of
//! `tokio::task::spawn_blocking` in this crate; a test below enforces that.
//!
//! [`spawn`] carries the caller's span into a task that ends with the
//! caller's request; [`spawn_detached`] gives a task that outlives it (an
//! actor, a host loop, a relay) a root span of its own, linked to the
//! request instead of parented by it.

use minimald_rpc::trace::TraceContext;
use tokio::sync::mpsc;

/// `tokio::spawn`, with the caller's current span carried into the task: for
/// work that ends with the request that started it (a handler, a pump, a
/// relay bounded by its channel). A task that outlives its request takes
/// [`spawn_detached`] instead.
///
/// A spawned task starts with no current span, so every span it (or anything
/// it awaits) opens becomes the root of a trace of its own. In the daemon the
/// exec's `task_producer`, the connection and channel handlers and the session
/// actors are all spawned, and the harness measured 51 stray traces per
/// baseline run: package fetches
/// (`materialize`), `session.message`, `conn`, all cut off from their RPC.
#[expect(
    clippy::disallowed_methods,
    reason = "the one place a bare tokio spawn belongs: this is the wrapper the lint sends everyone to"
)]
pub fn spawn<F>(f: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(tracing::Instrument::instrument(f, tracing::Span::current()))
}

/// `tokio::spawn` for a task that outlives the request that started it: an
/// actor, a host loop, a relay. It runs in `root`, a span of its own, which
/// records the caller's current span as a link (`follows_from`), not as its
/// parent.
///
/// [`spawn`] is right for work that ends with its request. A long-lived task
/// spawned that way keeps the request's span open for its whole life: the
/// request's span is exported only when the actor dies (and lost if the
/// daemon is killed), it outlives its own children's parent, and every span
/// the actor opens for later requests nests under the first one (a
/// CreateSession `sessions.manager.message` that lasted 313 s behind a
/// 114 ms RPC). Here the request's span ends when the request does, and the
/// task's spans join the request's trace through the link.
///
/// `root` must be a root span (`tracing::info_span!(parent: None, ..)`),
/// named for the task (`session.host`, `sessions.manager`). A span with a
/// parent would pin that parent exactly as [`spawn`] does; debug builds
/// assert this.
#[expect(
    clippy::disallowed_methods,
    reason = "the one place a bare tokio spawn belongs: this is the wrapper the lint sends everyone to"
)]
pub fn spawn_detached<F>(root: tracing::Span, f: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(tracing::Instrument::instrument(f, detach(root)))
}

/// Links `root` to the caller's current span (`follows_from`) and returns
/// it: the step [`spawn_detached`] takes, for a caller that starts several
/// long-lived tasks under one root (enter the returned span, then [`spawn`]
/// each). `root` must be a root span; see [`spawn_detached`].
pub fn detach(root: tracing::Span) -> tracing::Span {
    debug_assert!(
        !has_parent(&root),
        "a detached task's span must be a root (`parent: None`)"
    );
    root.follows_from(tracing::Span::current());
    root
}

/// Whether the subscriber knows `span` to have a parent. False for a
/// disabled span and under a subscriber without a span registry.
fn has_parent(span: &tracing::Span) -> bool {
    use tracing_subscriber::registry::LookupSpan as _;
    let Some(id) = span.id() else {
        return false;
    };
    tracing::dispatcher::get_default(|d| {
        d.downcast_ref::<tracing_subscriber::Registry>()
            .and_then(|r| r.span(&id))
            .is_some_and(|s| s.parent().is_some())
    })
}

/// `tokio::task::spawn_blocking`, with the caller's current span entered
/// around `f` on the pool thread.
#[expect(
    clippy::disallowed_methods,
    reason = "the one place a bare tokio spawn belongs: this is the wrapper the lint sends everyone to"
)]
pub fn spawn_blocking<F, R>(f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || span.in_scope(f))
}

/// The current span's trace context, for a message to carry.
///
/// With export on, the current span's own OTel ids (`mlog::otel::align`), so
/// the handler's span is that span's child in the export; `None` when the
/// export does not record the current span. With export off, the nearest
/// enclosing span whose ids [`remember`] noted (the `rpc`, `exec`, `attach`
/// and `*.message` spans), so the file log's `trace_id` still joins the
/// handler's lines to the request.
pub(crate) fn caller_context() -> Caller {
    let current = tracing::Span::current();
    // The ids the enclosing request adopted come first (`remember`, set by
    // `adopt_trace` on the `rpc`, `exec`, `attach` and `*.message` spans):
    // they are the trace the sender belongs to whether or not the export
    // records the current span. Asking the current span for its own exported
    // ids instead sent a message from a request that had adopted a forwarded
    // `TRACEPARENT` into another trace (717b, 770 on the 50-commit stack): a
    // span opened with `parent: None` holds the trace id it was given at
    // creation, and a span the export filter drops has no ids at all.
    if let Some(ctx) = remembered_context(&current) {
        return Some(ctx);
    }
    if mlog::otel::exporting() {
        return mlog::otel::align(&current, None)
            .map(|(trace_id, span_id, flags)| TraceContext::from_parts(trace_id, span_id, flags));
    }
    None
}

/// The ids recorded on a span by [`remember`], kept in the span registry's
/// extensions.
#[derive(Clone, Copy)]
struct Remembered(TraceContext);

/// Notes `ctx` as `span`'s trace context, for [`caller_context`] to find
/// from inside it (or inside any span it encloses). A no-op for a disabled
/// span or under a subscriber without a span registry.
pub(crate) fn remember(span: &tracing::Span, ctx: TraceContext) {
    use tracing_subscriber::registry::LookupSpan as _;
    let Some(id) = span.id() else {
        return;
    };
    tracing::dispatcher::get_default(|d| {
        if let Some(s) = d
            .downcast_ref::<tracing_subscriber::Registry>()
            .and_then(|r| r.span(&id))
        {
            s.extensions_mut().replace(Remembered(ctx));
        }
    });
}

/// The context [`remember`] noted on `span` or its nearest ancestor that has
/// one. The lookup runs inside a live span (the caller's), so it never
/// touches a closed one.
fn remembered_context(span: &tracing::Span) -> Caller {
    use tracing_subscriber::registry::LookupSpan as _;
    let id = span.id()?;
    tracing::dispatcher::get_default(|d| {
        let s = d
            .downcast_ref::<tracing_subscriber::Registry>()?
            .span(&id)?;
        s.scope()
            .find_map(|s| s.extensions().get::<Remembered>().map(|r| r.0))
    })
}

/// A bounded mailbox: `(sender, receiver)`.
pub(crate) fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    let (tx, rx) = mpsc::channel(capacity);
    (Sender(tx), Receiver(rx))
}

/// The trace context a message was sent from: the sender's span's ids, or
/// `None` when the sender ran in no traced span.
pub(crate) type Caller = Option<TraceContext>;

pub(crate) struct Sender<T>(mpsc::Sender<(T, Caller)>);

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> std::fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("traced::Sender").finish()
    }
}

impl<T> Sender<T> {
    /// Send `msg` with the caller's trace context attached (see
    /// [`caller_context`]).
    pub(crate) async fn send(&self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
        self.0
            .send((msg, caller_context()))
            .await
            .map_err(|e| mpsc::error::SendError(e.0.0))
    }

    pub(crate) fn downgrade(&self) -> WeakSender<T> {
        WeakSender(self.0.downgrade())
    }
}

pub(crate) struct WeakSender<T>(mpsc::WeakSender<(T, Caller)>);

impl<T> Clone for WeakSender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> std::fmt::Debug for WeakSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("traced::WeakSender").finish()
    }
}

impl<T> WeakSender<T> {
    pub(crate) fn upgrade(&self) -> Option<Sender<T>> {
        self.0.upgrade().map(Sender)
    }
}

pub(crate) struct Receiver<T>(mpsc::Receiver<(T, Caller)>);

impl<T> std::fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("traced::Receiver").finish()
    }
}

impl<T> Receiver<T> {
    /// The next message and the trace context it was sent from.
    ///
    /// The handler opens its span at handling time as a root
    /// (`parent: None`, declaring `trace_id`, `span_id` and
    /// `parent_span_id`) and adopts the context with
    /// [`crate::exec::adopt_trace`]: the span is the sender's child in the
    /// export and in the file log's ids, and nothing the queue holds keeps the
    /// sender's span open.
    pub(crate) async fn recv(&mut self) -> Option<(T, Caller)> {
        self.0.recv().await
    }

    /// Messages waiting behind the one being handled.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use tracing::Instrument as _;

    /// A message carries its sender's ids, not its sender's span: the
    /// sender's span closes once the sender is done (here: gone before the
    /// message is handled), and the span the handler opens at handling time
    /// is still the sender's child.
    #[tokio::test]
    async fn a_message_carries_its_senders_context_not_its_span() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let subscriber = tracing_subscriber::registry().with(RecordFields);
        let _g = tracing::subscriber::set_default(subscriber);
        let (tx, mut rx) = super::channel::<u8>(1);
        let sender = tracing::info_span!(
            "rpc",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            parent_span_id = tracing::field::Empty,
        );
        let sender_id = sender.id().unwrap();
        crate::exec::adopt_trace(&sender, None);
        let sent_from = super::remembered_context(&sender).expect("adopt_trace remembers");
        async { tx.send(7).await.unwrap() }.instrument(sender).await;
        assert!(
            !is_open(&sender_id),
            "a queued message does not hold its sender's span open"
        );

        let (msg, caller) = rx.recv().await.unwrap();
        assert_eq!(msg, 7);
        assert_eq!(caller, Some(sent_from));
        let handler = tracing::info_span!(
            parent: None,
            "session.message",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            parent_span_id = tracing::field::Empty,
        );
        crate::exec::adopt_trace(&handler, caller);
        let handled = super::remembered_context(&handler).unwrap();
        assert_eq!(handled.trace_id_hex(), sent_from.trace_id_hex());
        assert_ne!(handled.span_id_hex(), sent_from.span_id_hex());
        assert_eq!(
            fields_of(&handler).get("parent_span_id"),
            Some(&sent_from.span_id_hex()),
            "the handler's span names the sender's span as parent"
        );
    }

    /// From inside a span that remembered no ids, a message carries the
    /// nearest enclosing remembered context; outside any span, none.
    #[tokio::test]
    async fn a_message_from_a_nested_span_carries_the_enclosing_request() {
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry());
        let (tx, mut rx) = super::channel::<u8>(2);
        tx.send(1).await.unwrap();
        assert_eq!(rx.recv().await.unwrap().1, None);

        let request = tracing::info_span!(
            "exec",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            parent_span_id = tracing::field::Empty,
        );
        crate::exec::adopt_trace(&request, None);
        let ctx = super::remembered_context(&request);
        assert!(ctx.is_some());
        let nested = tracing::info_span!(parent: &request, "checkouts.checkout_of");
        drop(request);
        async { tx.send(2).await.unwrap() }.instrument(nested).await;
        assert_eq!(rx.recv().await.unwrap().1, ctx);
    }

    /// The values a span recorded after creation (`Span::record`), by field
    /// name, kept in the span's extensions by [`RecordFields`].
    #[derive(Clone, Default)]
    struct Recorded(std::collections::BTreeMap<String, String>);

    /// Keeps each span's recorded values as a [`Recorded`] extension.
    struct RecordFields;

    impl<S> tracing_subscriber::Layer<S> for RecordFields
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_record(
            &self,
            id: &tracing::Id,
            values: &tracing::span::Record<'_>,
            cx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Visit<'a>(&'a mut std::collections::BTreeMap<String, String>);
            impl tracing::field::Visit for Visit<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.insert(field.name().to_owned(), format!("{value:?}"));
                }
            }
            let span = cx.span(id).unwrap();
            let mut ext = span.extensions_mut();
            if ext.get_mut::<Recorded>().is_none() {
                ext.insert(Recorded::default());
            }
            values.record(&mut Visit(&mut ext.get_mut::<Recorded>().unwrap().0));
        }
    }

    /// The values recorded on `span` (via `Span::record`), by field name.
    fn fields_of(span: &tracing::Span) -> std::collections::BTreeMap<String, String> {
        use tracing_subscriber::registry::LookupSpan as _;
        let id = span.id().unwrap();
        tracing::dispatcher::get_default(|d| {
            d.downcast_ref::<tracing_subscriber::Registry>()
                .unwrap()
                .span(&id)
                .unwrap()
                .extensions()
                .get::<Recorded>()
                .map(|r| r.0.clone())
                .unwrap_or_default()
        })
    }

    /// Records every `follows_from` the subscriber is told of, as
    /// `(span, follows)` pairs.
    #[derive(Clone, Default)]
    struct Links(std::sync::Arc<std::sync::Mutex<Vec<(tracing::Id, tracing::Id)>>>);

    impl<S> tracing_subscriber::Layer<S> for Links
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_follows_from(
            &self,
            span: &tracing::Id,
            follows: &tracing::Id,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.0.lock().unwrap().push((span.clone(), follows.clone()));
        }
    }

    /// Whether the default subscriber still holds the span `id` open.
    fn is_open(id: &tracing::Id) -> bool {
        use tracing_subscriber::registry::LookupSpan as _;
        tracing::dispatcher::get_default(|d| {
            d.downcast_ref::<tracing_subscriber::Registry>()
                .unwrap()
                .span(id)
                .is_some()
        })
    }

    /// A detached task runs in its own root span, which links (not parents)
    /// the span that spawned it, and that span closes when its request ends
    /// although the task lives on (TEL-030).
    #[tokio::test]
    async fn a_detached_task_links_its_caller_and_does_not_hold_it_open() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let links = Links::default();
        let subscriber = tracing_subscriber::registry().with(links.clone());
        let _g = tracing::subscriber::set_default(subscriber);

        let request = tracing::info_span!("request");
        let request_id = request.id().unwrap();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let actor = request.in_scope(|| {
            super::spawn_detached(tracing::info_span!(parent: None, "actor"), async move {
                let current = tracing::Span::current();
                seen_tx
                    .send((current.id(), super::has_parent(&current)))
                    .unwrap();
                release_rx.await.unwrap();
            })
        });
        drop(request);

        let (actor_id, actor_has_parent) = seen_rx.await.unwrap();
        let actor_id = actor_id.expect("the task runs in its root span");
        assert!(!actor_has_parent, "the task's span is a root");
        assert_eq!(
            *links.0.lock().unwrap(),
            vec![(actor_id.clone(), request_id.clone())],
            "the root links the request it was spawned by"
        );
        assert!(
            !is_open(&request_id),
            "the request's span closed while the task lives on"
        );
        assert!(is_open(&actor_id));
        release_tx.send(()).unwrap();
        actor.await.unwrap();
    }

    /// TEL-022: a task started with [`super::spawn`] runs in the
    /// span that was current where it was spawned; a bare `tokio::spawn`
    /// runs in none, which is what cut the daemon's tasks out of their
    /// request's trace.
    #[tokio::test]
    async fn a_spawned_task_runs_in_the_callers_span() {
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry());
        let caller = tracing::info_span!("caller");
        let id = caller.id();
        assert!(id.is_some(), "the subscriber records spans");
        let traced = caller
            .in_scope(|| super::spawn(async { tracing::Span::current().id() }))
            .await
            .unwrap();
        assert_eq!(traced, id);
        #[expect(
            clippy::disallowed_methods,
            reason = "the bare call is the failure this wrapper exists for; the test shows it"
        )]
        let bare = caller
            .in_scope(|| tokio::spawn(async { tracing::Span::current().id() }))
            .await
            .unwrap();
        assert_eq!(bare, None, "the bare call loses the caller's span");
    }

    /// Plain `spawn`, for contrast: the task's span is the caller's, so the
    /// caller's span stays open as long as the task runs, and closes once
    /// the task ends. The subscriber is layered: a bare `Registry` never
    /// frees a closed span (the close is `Layered::try_close`'s), so
    /// [`is_open`] would hold whether or not the task kept the span.
    #[tokio::test]
    async fn a_spawned_task_holds_its_callers_span_open() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let _g = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(tracing_subscriber::layer::Identity::new()),
        );
        let request = tracing::info_span!("request");
        let request_id = request.id().unwrap();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let task = request.in_scope(|| super::spawn(async move { release_rx.await.unwrap() }));
        drop(request);
        tokio::task::yield_now().await;
        assert!(is_open(&request_id), "the task holds the request's span");
        release_tx.send(()).unwrap();
        task.await.unwrap();
        assert!(
            !is_open(&request_id),
            "the request's span closes with the task"
        );
    }

    /// Work on the blocking pool runs inside the caller's span. The pool
    /// thread sees only the global dispatcher, so this test installs one
    /// (nextest runs each test in its own process).
    #[tokio::test(flavor = "multi_thread")]
    async fn blocking_work_runs_in_the_callers_span() {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best effort: a telemetry failure is a silent no-op (spec 25 principle 8)"
        )]
        let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry());
        let span = tracing::info_span!("caller");
        let id = span.id();
        assert!(
            id.is_some(),
            "the subscriber must be enabled for the test to mean anything"
        );
        let got = async {
            super::spawn_blocking(|| tracing::Span::current().id())
                .await
                .unwrap()
        }
        .instrument(span)
        .await;
        assert_eq!(got, id);
        // the bare tokio call loses it: the failure this wrapper exists for
        #[expect(
            clippy::disallowed_methods,
            reason = "the bare call is the failure this wrapper exists for; the test shows it"
        )]
        let bare = async {
            tokio::task::spawn_blocking(|| tracing::Span::current().id())
                .await
                .unwrap()
        }
        .instrument(tracing::info_span!("caller2"))
        .await;
        assert_eq!(bare, None);
    }

    /// Every task and blocking-pool call in minimald goes through
    /// [`super::spawn`], [`super::spawn_detached`] or
    /// [`super::spawn_blocking`]. A direct `tokio::spawn` or
    /// `tokio::task::spawn_blocking` (a rebase, a new call site) would silently
    /// cut its spans out of the caller's trace.
    #[test]
    fn no_direct_tokio_spawn_blocking() {
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
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        let mut bad = Vec::new();
        for f in files.iter().filter(|f| !f.ends_with("traced.rs")) {
            let text = std::fs::read_to_string(f).unwrap();
            for (i, line) in text.lines().enumerate() {
                // An imported bare `spawn` (`use tokio::task::spawn;`, or
                // `spawn,` in a `use tokio::{..}` list) escapes a text
                // check; the crate's clippy `disallowed-methods` names it.
                let direct = line.contains("tokio::task::spawn_blocking")
                    || line.contains("tokio::spawn(")
                    || line.contains("tokio::task::spawn(")
                    || line.contains("use tokio::spawn")
                    || line.contains("use tokio::task::spawn;")
                    || (line.contains("use tokio::task::") && line.contains("spawn_blocking"));
                if direct && !line.trim_start().starts_with("//") {
                    bad.push(format!("{}:{}: {}", f.display(), i + 1, line.trim()));
                }
            }
        }
        assert!(
            bad.is_empty(),
            "use crate::traced::{{spawn, spawn_detached, spawn_blocking}} instead:\n{}",
            bad.join("\n")
        );
    }
}

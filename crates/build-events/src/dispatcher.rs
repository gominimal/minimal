//! Build event dispatcher implementation
//!
//! The [`BuildEventDispatcher`] manages multiple subscribers and distributes
//! events from a broadcast channel to all registered subscribers.

use crate::events::BuildEvent;
use crate::subscriber::BuildEventSubscriber;
use tokio::sync::broadcast;
use tracing::{info, warn};

/// Dispatcher that distributes events to multiple subscribers
///
/// The dispatcher receives events from a broadcast channel and forwards
/// them to all registered subscribers. It handles subscriber errors
/// gracefully by logging them without stopping other subscribers.
///
/// # Example
/// ```
/// use build_events::{BuildEventBus, BuildEventDispatcher, subscribers::LoggerSubscriber};
///
/// #[tokio::main]
/// async fn main() {
///     let bus = BuildEventBus::new(1000);
///     let mut dispatcher = BuildEventDispatcher::new(bus.subscribe());
///
///     dispatcher.add_subscriber(Box::new(LoggerSubscriber::new()));
///
///     tokio::spawn(async move {
///         dispatcher.run().await;
///     });
///
///     // Use the bus to emit events...
/// }
/// ```
pub struct BuildEventDispatcher {
    receiver: broadcast::Receiver<BuildEvent>,
    subscribers: Vec<Box<dyn BuildEventSubscriber>>,
}

impl BuildEventDispatcher {
    /// Create a new dispatcher with a broadcast receiver
    ///
    /// # Arguments
    /// * `receiver` - Broadcast receiver from the event bus
    ///
    /// # Example
    /// ```
    /// use build_events::{BuildEventBus, BuildEventDispatcher};
    ///
    /// let bus = BuildEventBus::new(1000);
    /// let dispatcher = BuildEventDispatcher::new(bus.subscribe());
    /// ```
    pub fn new(receiver: broadcast::Receiver<BuildEvent>) -> Self {
        Self {
            receiver,
            subscribers: Vec::new(),
        }
    }

    /// Add a subscriber to receive events
    ///
    /// # Arguments
    /// * `subscriber` - Boxed subscriber implementation
    ///
    /// # Example
    /// ```
    /// use build_events::{BuildEventBus, BuildEventDispatcher, subscribers::LoggerSubscriber};
    ///
    /// let bus = BuildEventBus::new(1000);
    /// let mut dispatcher = BuildEventDispatcher::new(bus.subscribe());
    /// dispatcher.add_subscriber(Box::new(LoggerSubscriber::new()));
    /// ```
    pub fn add_subscriber(&mut self, subscriber: Box<dyn BuildEventSubscriber>) {
        info!("Registered subscriber: {}", subscriber.name());
        self.subscribers.push(subscriber);
    }

    /// Run the dispatcher, processing events until the channel closes
    ///
    /// This method will block until the broadcast channel is closed (which
    /// happens when all senders are dropped). It distributes each event
    /// to all registered subscribers.
    ///
    /// Subscriber errors are logged via `tracing::warn!` but don't stop
    /// event processing or affect other subscribers.
    ///
    /// # Example
    /// ```no_run
    /// use build_events::{BuildEventBus, BuildEventDispatcher, subscribers::LoggerSubscriber};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let bus = BuildEventBus::new(1000);
    ///     let mut dispatcher = BuildEventDispatcher::new(bus.subscribe());
    ///     dispatcher.add_subscriber(Box::new(LoggerSubscriber::new()));
    ///
    ///     // Run dispatcher until bus is closed
    ///     dispatcher.run().await;
    /// }
    /// ```
    pub async fn run(mut self) {
        info!(
            "BuildEventDispatcher started with {} subscribers",
            self.subscribers.len()
        );

        loop {
            match self.receiver.recv().await {
                Ok(event) => {
                    // Distribute event to all subscribers
                    for subscriber in &self.subscribers {
                        if let Err(e) = subscriber.on_event(&event).await {
                            warn!(
                                "Subscriber '{}' error processing event: {}",
                                subscriber.name(),
                                e
                            );
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    // Channel closed, shutdown gracefully
                    info!("Event channel closed, shutting down dispatcher");
                    break;
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    // This receiver is too slow and missed some events
                    warn!("Dispatcher lagged and skipped {} events", skipped);
                }
            }
        }

        // Call on_close for all subscribers
        for subscriber in &self.subscribers {
            if let Err(e) = subscriber.on_close().await {
                warn!(
                    "Subscriber '{}' error during close: {}",
                    subscriber.name(),
                    e
                );
            }
        }

        info!("BuildEventDispatcher shutdown complete");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{build_event, BuildStarted, current_millis};
    use crate::subscriber::SubscriberError;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingSubscriber {
        name: String,
        count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BuildEventSubscriber for CountingSubscriber {
        async fn on_event(&self, _event: &BuildEvent) -> Result<(), SubscriberError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[tokio::test]
    async fn test_dispatcher_single_subscriber() {
        let (sender, receiver) = broadcast::channel(100);
        let count = Arc::new(AtomicUsize::new(0));

        let mut dispatcher = BuildEventDispatcher::new(receiver);
        dispatcher.add_subscriber(Box::new(CountingSubscriber {
            name: "counter".to_string(),
            count: count.clone(),
        }));

        // Spawn dispatcher
        let handle = tokio::spawn(async move {
            dispatcher.run().await;
        });

        // Send some events
        for i in 0..5 {
            sender
                .send(BuildEvent {
                    invocation_id: format!("test-{}", i),
                    event: Some(build_event::Event::BuildStarted(BuildStarted {
                        invocation_id: format!("test-{}", i),
                        command: "build".to_string(),
                        timestamp_millis: current_millis(),
                        working_directory: "/tmp".to_string(),
                    })),
                })
                .unwrap();
        }

        // Wait a bit for events to process
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Close channel
        drop(sender);

        // Wait for dispatcher to finish
        handle.await.unwrap();

        assert_eq!(count.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn test_dispatcher_multiple_subscribers() {
        let (sender, receiver) = broadcast::channel(100);
        let count1 = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::new(AtomicUsize::new(0));

        let mut dispatcher = BuildEventDispatcher::new(receiver);
        dispatcher.add_subscriber(Box::new(CountingSubscriber {
            name: "counter1".to_string(),
            count: count1.clone(),
        }));
        dispatcher.add_subscriber(Box::new(CountingSubscriber {
            name: "counter2".to_string(),
            count: count2.clone(),
        }));

        let handle = tokio::spawn(async move {
            dispatcher.run().await;
        });

        // Send events
        for i in 0..3 {
            sender
                .send(BuildEvent {
                    invocation_id: format!("test-{}", i),
                    event: Some(build_event::Event::BuildStarted(BuildStarted {
                        invocation_id: format!("test-{}", i),
                        command: "build".to_string(),
                        timestamp_millis: current_millis(),
                        working_directory: "/tmp".to_string(),
                    })),
                })
                .unwrap();
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        drop(sender);
        handle.await.unwrap();

        // Both subscribers should have received all events
        assert_eq!(count1.load(Ordering::SeqCst), 3);
        assert_eq!(count2.load(Ordering::SeqCst), 3);
    }

    struct ErrorSubscriber {
        name: String,
    }

    #[async_trait]
    impl BuildEventSubscriber for ErrorSubscriber {
        async fn on_event(&self, _event: &BuildEvent) -> Result<(), SubscriberError> {
            Err(SubscriberError::Custom("intentional error".to_string()))
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[tokio::test]
    async fn test_dispatcher_subscriber_error() {
        let (sender, receiver) = broadcast::channel(100);
        let count = Arc::new(AtomicUsize::new(0));

        let mut dispatcher = BuildEventDispatcher::new(receiver);
        // Add an error subscriber and a counting subscriber
        dispatcher.add_subscriber(Box::new(ErrorSubscriber {
            name: "error".to_string(),
        }));
        dispatcher.add_subscriber(Box::new(CountingSubscriber {
            name: "counter".to_string(),
            count: count.clone(),
        }));

        let handle = tokio::spawn(async move {
            dispatcher.run().await;
        });

        // Send event
        sender
            .send(BuildEvent {
                invocation_id: "test".to_string(),
                event: Some(build_event::Event::BuildStarted(BuildStarted {
                    invocation_id: "test".to_string(),
                    command: "build".to_string(),
                    timestamp_millis: current_millis(),
                    working_directory: "/tmp".to_string(),
                })),
            })
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        drop(sender);
        handle.await.unwrap();

        // Counting subscriber should still have received the event
        // even though error subscriber failed
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}

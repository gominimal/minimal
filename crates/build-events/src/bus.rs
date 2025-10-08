//! Build event bus implementation
//!
//! The [`BuildEventBus`] is the central event dispatcher that uses a tokio
//! broadcast channel to distribute events to multiple subscribers.

use crate::events::BuildEvent;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Central event bus for distributing build events to subscribers
///
/// The bus uses a tokio broadcast channel internally and can be cheaply cloned
/// to share across multiple components. Events are emitted in a non-blocking
/// manner using try_send.
///
/// # Example
/// ```
/// use build_events::{BuildEventBus, BuildEvent, events::*};
///
/// #[tokio::main]
/// async fn main() {
///     let bus = BuildEventBus::new(1000);
///     let mut receiver = bus.subscribe();
///
///     bus.emit(BuildEvent::BuildStarted(BuildStarted {
///         invocation_id: "test-123".to_string(),
///         command_line: vec!["cargo".to_string(), "build".to_string()],
///         timestamp_millis: current_millis(),
///         working_directory: "/tmp".to_string(),
///     }));
///
///     let event = receiver.recv().await.unwrap();
///     match event {
///         BuildEvent::BuildStarted(_) => println!("Build started!"),
///         _ => {}
///     }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct BuildEventBus {
    sender: Arc<broadcast::Sender<BuildEvent>>,
}

impl BuildEventBus {
    /// Create a new build event bus with the specified channel capacity
    ///
    /// The capacity determines how many events can be buffered before
    /// slow subscribers start lagging and missing events.
    ///
    /// # Arguments
    /// * `capacity` - Maximum number of events to buffer
    ///
    /// # Example
    /// ```
    /// use build_events::BuildEventBus;
    ///
    /// let bus = BuildEventBus::new(10000);
    /// ```
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender: Arc::new(sender),
        }
    }

    /// Emit an event to all subscribers
    ///
    /// This is a non-blocking operation. If the channel is full, the event
    /// will be dropped and slow subscribers may miss it. This ensures that
    /// event emission never blocks the build process.
    ///
    /// # Arguments
    /// * `event` - The event to emit
    ///
    /// # Example
    /// ```
    /// use build_events::{BuildEventBus, BuildEvent, events::*};
    ///
    /// let bus = BuildEventBus::new(1000);
    /// bus.emit(BuildEvent::BuildStarted(BuildStarted {
    ///     invocation_id: "test-123".to_string(),
    ///     command_line: vec!["cargo".to_string(), "build".to_string()],
    ///     timestamp_millis: current_millis(),
    ///     working_directory: "/tmp".to_string(),
    /// }));
    /// ```
    pub fn emit(&self, event: BuildEvent) {
        // Use try_send to avoid blocking. If the channel is full, the event
        // will be dropped. This is acceptable because we prioritize not
        // blocking the build process over guaranteed delivery.
        let _ = self.sender.send(event);
    }

    /// Subscribe to build events
    ///
    /// Creates a new receiver that will receive all events emitted after
    /// this subscription is created. Events emitted before subscription
    /// will not be received.
    ///
    /// # Example
    /// ```
    /// use build_events::BuildEventBus;
    ///
    /// let bus = BuildEventBus::new(1000);
    /// let receiver1 = bus.subscribe();
    /// let receiver2 = bus.subscribe();
    /// // Both receivers will get events emitted from now on
    /// ```
    pub fn subscribe(&self) -> broadcast::Receiver<BuildEvent> {
        self.sender.subscribe()
    }

    /// Get the current number of active subscribers
    ///
    /// # Example
    /// ```
    /// use build_events::BuildEventBus;
    ///
    /// let bus = BuildEventBus::new(1000);
    /// assert_eq!(bus.receiver_count(), 0);
    /// let _receiver = bus.subscribe();
    /// assert_eq!(bus.receiver_count(), 1);
    /// ```
    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{BuildStarted, current_millis};

    #[tokio::test]
    async fn test_bus_emit_and_receive() {
        let bus = BuildEventBus::new(100);
        let mut receiver = bus.subscribe();

        let event = BuildEvent::BuildStarted(BuildStarted {
            invocation_id: "test-123".to_string(),
            command_line: vec!["cargo".to_string(), "build".to_string()],
            timestamp_millis: current_millis(),
            working_directory: "/tmp".to_string(),
        });

        bus.emit(event.clone());

        let received = receiver.recv().await.unwrap();
        assert_eq!(received, event);
    }

    #[tokio::test]
    async fn test_bus_multiple_subscribers() {
        let bus = BuildEventBus::new(100);
        let mut receiver1 = bus.subscribe();
        let mut receiver2 = bus.subscribe();

        let event = BuildEvent::BuildStarted(BuildStarted {
            invocation_id: "test-456".to_string(),
            command_line: vec!["cargo".to_string(), "test".to_string()],
            timestamp_millis: current_millis(),
            working_directory: "/tmp".to_string(),
        });

        bus.emit(event.clone());

        let received1 = receiver1.recv().await.unwrap();
        let received2 = receiver2.recv().await.unwrap();
        assert_eq!(received1, event);
        assert_eq!(received2, event);
    }

    #[tokio::test]
    async fn test_bus_clone() {
        let bus = BuildEventBus::new(100);
        let bus_clone = bus.clone();
        let mut receiver = bus.subscribe();

        let event = BuildEvent::BuildStarted(BuildStarted {
            invocation_id: "test-789".to_string(),
            command_line: vec!["cargo".to_string(), "run".to_string()],
            timestamp_millis: current_millis(),
            working_directory: "/tmp".to_string(),
        });

        // Emit from the cloned bus
        bus_clone.emit(event.clone());

        let received = receiver.recv().await.unwrap();
        assert_eq!(received, event);
    }

    #[test]
    fn test_receiver_count() {
        let bus = BuildEventBus::new(100);
        assert_eq!(bus.receiver_count(), 0);

        let _receiver1 = bus.subscribe();
        assert_eq!(bus.receiver_count(), 1);

        let _receiver2 = bus.subscribe();
        assert_eq!(bus.receiver_count(), 2);
    }

    #[tokio::test]
    async fn test_late_subscription() {
        let bus = BuildEventBus::new(100);

        let event1 = BuildEvent::BuildStarted(BuildStarted {
            invocation_id: "early".to_string(),
            command_line: vec![],
            timestamp_millis: current_millis(),
            working_directory: "/tmp".to_string(),
        });

        // Emit before subscription
        bus.emit(event1.clone());

        // Subscribe after event was emitted
        let mut receiver = bus.subscribe();

        let event2 = BuildEvent::BuildStarted(BuildStarted {
            invocation_id: "late".to_string(),
            command_line: vec![],
            timestamp_millis: current_millis(),
            working_directory: "/tmp".to_string(),
        });

        bus.emit(event2.clone());

        // Should only receive event2, not event1
        let received = receiver.recv().await.unwrap();
        assert_eq!(received, event2);
    }
}

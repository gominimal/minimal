//! Integration tests for the build-events crate
//!
//! Tests the full end-to-end flow of event emission, distribution, and subscription.

use async_trait::async_trait;
use build_events::{
    BuildEvent, BuildEventBus, BuildEventDispatcher, BuildEventSubscriber, SubscriberError,
    events::{
        ActionCompleted, ActionStarted, BuildFinished, BuildStarted, TargetCompleted, TargetKind,
        TargetStarted, current_millis,
    },
    subscribers::{JsonFileWriter, LoggerSubscriber},
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Test subscriber that counts events
struct CountingSubscriber {
    count: Arc<AtomicUsize>,
}

#[async_trait]
impl BuildEventSubscriber for CountingSubscriber {
    async fn on_event(&self, _event: &BuildEvent) -> Result<(), SubscriberError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn name(&self) -> &str {
        "CountingSubscriber"
    }
}

#[tokio::test]
async fn test_full_event_flow() {
    let bus = BuildEventBus::new(100);
    let count = Arc::new(AtomicUsize::new(0));

    let mut dispatcher = BuildEventDispatcher::new(bus.subscribe());
    dispatcher.add_subscriber(Box::new(CountingSubscriber {
        count: count.clone(),
    }));

    // Start dispatcher
    let handle = tokio::spawn(async move {
        dispatcher.run().await;
    });

    // Emit all event types
    bus.emit(BuildEvent::BuildStarted(BuildStarted {
        invocation_id: "test-integration".to_string(),
        command: "build".to_string(),
        timestamp_millis: current_millis(),
        working_directory: "/tmp".to_string(),
    }));

    bus.emit(BuildEvent::TargetStarted(TargetStarted {
        target_id: "target-1".to_string(),
        label: "//foo:bar".to_string(),
        target_kind: TargetKind::Binary,
        timestamp_millis: current_millis(),
    }));

    bus.emit(BuildEvent::ActionStarted(ActionStarted {
        action_id: "action-1".to_string(),
        action_name: "CppCompile".to_string(),
        target_id: "target-1".to_string(),
        timestamp_millis: current_millis(),
    }));

    bus.emit(BuildEvent::ActionCompleted(ActionCompleted {
        action_id: "action-1".to_string(),
        success: true,
        timestamp_millis: current_millis(),
        exit_code: 0,
        stdout: Some("compiled successfully".to_string()),
        stderr: None,
    }));

    bus.emit(BuildEvent::TargetCompleted(TargetCompleted {
        target_id: "target-1".to_string(),
        label: "//foo:bar".to_string(),
        success: true,
        timestamp_millis: current_millis(),
        error_message: None,
        outputs: vec!["foo/bar".to_string()],
        cache_hit: false,
    }));

    bus.emit(BuildEvent::BuildFinished(BuildFinished {
        invocation_id: "test-integration".to_string(),
        success: true,
        timestamp_millis: current_millis(),
        error_message: None,
    }));

    // Wait for events to process
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Close bus and wait for dispatcher
    drop(bus);
    handle.await.unwrap();

    // Verify all events were received
    assert_eq!(count.load(Ordering::SeqCst), 6);
}

#[tokio::test]
async fn test_multiple_subscribers() {
    let temp_dir = tempfile::tempdir().unwrap();
    let json_path = temp_dir.path().join("events.jsonl");

    let bus = BuildEventBus::new(100);
    let count = Arc::new(AtomicUsize::new(0));

    let mut dispatcher = BuildEventDispatcher::new(bus.subscribe());
    dispatcher.add_subscriber(Box::new(LoggerSubscriber::new()));
    dispatcher.add_subscriber(Box::new(JsonFileWriter::new(&json_path).unwrap()));
    dispatcher.add_subscriber(Box::new(CountingSubscriber {
        count: count.clone(),
    }));

    let handle = tokio::spawn(async move {
        dispatcher.run().await;
    });

    // Emit a few events
    for i in 0..3 {
        bus.emit(BuildEvent::BuildStarted(BuildStarted {
            invocation_id: format!("test-{}", i),
            command: "build".to_string(),
            timestamp_millis: current_millis(),
            working_directory: "/tmp".to_string(),
        }));
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    drop(bus);
    handle.await.unwrap();

    // Verify counter subscriber received events
    assert_eq!(count.load(Ordering::SeqCst), 3);

    // Verify JSON file has events
    let content = std::fs::read_to_string(&json_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 3);

    // Verify each line is valid JSON
    for line in lines {
        let _: BuildEvent = serde_json::from_str(line).unwrap();
    }
}

#[tokio::test]
async fn test_late_subscriber_misses_early_events() {
    let bus = BuildEventBus::new(100);

    // Emit event before subscription
    bus.emit(BuildEvent::BuildStarted(BuildStarted {
        invocation_id: "early".to_string(),
        command: "build".to_string(),
        timestamp_millis: current_millis(),
        working_directory: "/tmp".to_string(),
    }));

    // Subscribe after emission
    let count = Arc::new(AtomicUsize::new(0));
    let mut dispatcher = BuildEventDispatcher::new(bus.subscribe());
    dispatcher.add_subscriber(Box::new(CountingSubscriber {
        count: count.clone(),
    }));

    let handle = tokio::spawn(async move {
        dispatcher.run().await;
    });

    // Emit event after subscription
    bus.emit(BuildEvent::BuildStarted(BuildStarted {
        invocation_id: "late".to_string(),
        command: "build".to_string(),
        timestamp_millis: current_millis(),
        working_directory: "/tmp".to_string(),
    }));

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    drop(bus);
    handle.await.unwrap();

    // Should only have received the late event
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_bus_cloning() {
    let bus = BuildEventBus::new(100);
    let bus_clone = bus.clone();
    let count = Arc::new(AtomicUsize::new(0));

    let mut dispatcher = BuildEventDispatcher::new(bus.subscribe());
    dispatcher.add_subscriber(Box::new(CountingSubscriber {
        count: count.clone(),
    }));

    let handle = tokio::spawn(async move {
        dispatcher.run().await;
    });

    // Emit from original bus
    bus.emit(BuildEvent::BuildStarted(BuildStarted {
        invocation_id: "original".to_string(),
        command: "build".to_string(),
        timestamp_millis: current_millis(),
        working_directory: "/tmp".to_string(),
    }));

    // Emit from cloned bus
    bus_clone.emit(BuildEvent::BuildStarted(BuildStarted {
        invocation_id: "clone".to_string(),
        command: "build".to_string(),
        timestamp_millis: current_millis(),
        working_directory: "/tmp".to_string(),
    }));

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    drop(bus);
    drop(bus_clone);
    handle.await.unwrap();

    // Both events should be received
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

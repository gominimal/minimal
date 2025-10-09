//! Basic usage example for the build-events crate
//!
//! This example demonstrates:
//! - Creating a BuildEventBus
//! - Setting up multiple subscribers (LoggerSubscriber and JsonFileWriter)
//! - Emitting all event types
//! - Graceful shutdown

use build_events::{
    BuildEvent, BuildEventBus, BuildEventDispatcher,
    events::{
        ActionCompleted, ActionStarted, BuildFinished, BuildStarted, TargetCompleted, TargetKind,
        TargetStarted, current_millis,
    },
    subscribers::{JsonFileWriter, LoggerSubscriber},
};

#[tokio::main]
async fn main() {
    // Initialize tracing for LoggerSubscriber
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    println!("=== Build Events System Demo ===\n");

    // Create event bus with capacity for 10,000 events
    let event_bus = BuildEventBus::new(10000);
    println!("Created BuildEventBus with capacity 10,000");

    // Setup subscribers
    let mut dispatcher = BuildEventDispatcher::new(event_bus.subscribe());

    // Add LoggerSubscriber to emit events to tracing
    dispatcher.add_subscriber(Box::new(LoggerSubscriber::new()));

    // Add JsonFileWriter to write events to a file
    let json_path = "build_events.jsonl";
    dispatcher.add_subscriber(Box::new(
        JsonFileWriter::new(json_path).expect("Failed to create JSON file writer"),
    ));

    println!("Registered subscribers: LoggerSubscriber, JsonFileWriter");
    println!("Events will be written to: {}\n", json_path);

    // Start event processing in background
    let dispatcher_handle = tokio::spawn(async move {
        dispatcher.run().await;
    });

    println!("Started event dispatcher\n");

    // Simulate a build by emitting events
    simulate_build(&event_bus).await;

    println!("\nBuild simulation complete");

    // Shutdown: drop event_bus to close channel, wait for dispatcher to drain
    println!("Shutting down event bus...");
    drop(event_bus);

    // Wait for dispatcher to finish processing
    dispatcher_handle.await.expect("Dispatcher task failed");

    println!("Event dispatcher shutdown complete\n");
    println!("=== Demo Complete ===");
    println!("\nYou can view the emitted events in: {}", json_path);
}

async fn simulate_build(bus: &BuildEventBus) {
    println!("--- Simulating Build ---\n");

    // 1. Build started
    println!("1. Emitting BuildStarted event");
    bus.emit(BuildEvent::BuildStarted(BuildStarted {
        invocation_id: "demo-invocation-123".to_string(),
        command: "build //example:target".to_string(),
        timestamp_millis: current_millis(),
        working_directory: std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .to_string(),
    }));
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 2. Target started
    println!("2. Emitting TargetStarted event");
    bus.emit(BuildEvent::TargetStarted(TargetStarted {
        target_id: "target-1".to_string(),
        label: "//example:target".to_string(),
        target_kind: TargetKind::Binary,
        timestamp_millis: current_millis(),
    }));
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 3. Action started - compile
    println!("3. Emitting ActionStarted event (compile)");
    bus.emit(BuildEvent::ActionStarted(ActionStarted {
        action_id: "action-compile-1".to_string(),
        action_name: "RustcCompile".to_string(),
        target_id: "target-1".to_string(),
        timestamp_millis: current_millis(),
    }));
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // 4. Action completed - compile
    println!("4. Emitting ActionCompleted event (compile)");
    bus.emit(BuildEvent::ActionCompleted(ActionCompleted {
        action_id: "action-compile-1".to_string(),
        success: true,
        timestamp_millis: current_millis(),
        exit_code: 0,
        stdout: Some("Compiling example v0.1.0".to_string()),
        stderr: None,
    }));
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 5. Action started - link
    println!("5. Emitting ActionStarted event (link)");
    bus.emit(BuildEvent::ActionStarted(ActionStarted {
        action_id: "action-link-1".to_string(),
        action_name: "RustcLink".to_string(),
        target_id: "target-1".to_string(),
        timestamp_millis: current_millis(),
    }));
    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    // 6. Action completed - link
    println!("6. Emitting ActionCompleted event (link)");
    bus.emit(BuildEvent::ActionCompleted(ActionCompleted {
        action_id: "action-link-1".to_string(),
        success: true,
        timestamp_millis: current_millis(),
        exit_code: 0,
        stdout: Some("Finished release [optimized] target(s)".to_string()),
        stderr: None,
    }));
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 7. Target completed
    println!("7. Emitting TargetCompleted event");
    bus.emit(BuildEvent::TargetCompleted(TargetCompleted {
        target_id: "target-1".to_string(),
        label: "//example:target".to_string(),
        success: true,
        timestamp_millis: current_millis(),
        error_message: None,
        outputs: vec!["target/release/example".to_string()],
        cache_hit: false,
    }));
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 8. Build finished
    println!("8. Emitting BuildFinished event");
    bus.emit(BuildEvent::BuildFinished(BuildFinished {
        invocation_id: "demo-invocation-123".to_string(),
        success: true,
        timestamp_millis: current_millis(),
        error_message: None,
    }));
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
}

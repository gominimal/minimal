# Build Events System Design Proposal (Revised)

## Overview
Create a dedicated build event protocol (BEP) system for `minimal` that enables remote observability of build execution. This system will be separate from diagnostic tracing and will emit structured, strongly-typed events that can be consumed by local and remote services.

## Goals
- Separate build events from diagnostic logs (`tracing`)
- Provide structured, serializable Rust events
- Enable multiple concurrent subscribers (local UI, remote services, file writers)
- Maintain low overhead and back-pressure handling
- Allow subscribers to choose their own serialization format

## Crate Structure

**Crate name**: `build-events`

**Location**: `crates/build-events/`

**Dependencies**:
```toml
[dependencies]
tokio = { version = "1", features = ["sync", "time"] }
serde = { version = "1", features = ["derive"] }
thiserror = "1"
async-trait = "0.1"

[dev-dependencies]
tokio = { version = "1", features = ["full", "test-util"] }
serde_json = "1"
```

## Architecture

### Core Components

1. **Event Types** (Pure Rust)
   - Strongly-typed event enums representing build lifecycle
   - Derive `Clone`, `Debug`, `Serialize`, `Deserialize`
   - Minimal initial set: BuildStarted, TargetStarted, TargetCompleted, ActionStarted, ActionCompleted, BuildFinished

2. **BuildEventBus** (publisher)
   - Central event dispatcher using `tokio::sync::broadcast`
   - Thread-safe, can be cloned and passed to any component
   - Non-blocking emission with configurable buffer size

3. **BuildEventSubscriber** (trait)
   - Similar to `tracing::Subscriber`
   - Allows pluggable event consumers
   - Async trait for handling events
   - **Subscribers handle their own serialization** (JSON, protobuf, bincode, etc.)

4. **Event Stream Handler**
   - Manages subscriber registration
   - Distributes events from broadcast channel to subscribers
   - Handles subscriber lifecycle

## API Design

### Event Emission (Producer Side)

```rust
// Initialize at build start
let event_bus = BuildEventBus::new(capacity: 10000);

// Clone and use anywhere in the codebase
let bus = event_bus.clone();
bus.emit(BuildEvent::BuildStarted {
    invocation_id: uuid::Uuid::new_v4().to_string(),
    command_line: args,
    timestamp_millis: current_millis(),
    working_directory: env::current_dir().unwrap(),
});

// Emit from any component
bus.emit(BuildEvent::TargetStarted {
    label: "//foo:bar".to_string(),
    target_kind: TargetKind::Binary,
    timestamp_millis: current_millis(),
});
```

### Event Consumption (Consumer Side)

```rust
#[async_trait]
pub trait BuildEventSubscriber: Send + Sync {
    async fn on_event(&self, event: &BuildEvent) -> Result<(), SubscriberError>;
    
    fn name(&self) -> &str;
    
    // Optional: called when subscriber is dropped
    async fn on_close(&self) -> Result<(), SubscriberError> {
        Ok(())
    }
}

// Register subscribers
let mut dispatcher = BuildEventDispatcher::new(event_bus.subscribe());
dispatcher.add_subscriber(Box::new(JsonFileWriter::new("build_events.jsonl")));
dispatcher.add_subscriber(Box::new(TerminalUI::new()));

// Start processing (runs until bus is closed)
tokio::spawn(async move {
    dispatcher.run().await;
});
```

## Event Schema (Pure Rust)

```rust
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BuildEvent {
    BuildStarted(BuildStarted),
    BuildFinished(BuildFinished),
    TargetStarted(TargetStarted),
    TargetCompleted(TargetCompleted),
    ActionStarted(ActionStarted),
    ActionCompleted(ActionCompleted),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildStarted {
    pub invocation_id: String,
    pub command_line: Vec<String>,
    pub timestamp_millis: i64,
    pub working_directory: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildFinished {
    pub invocation_id: String,
    pub success: bool,
    pub timestamp_millis: i64,
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetStarted {
    pub label: String,
    pub target_kind: TargetKind,
    pub timestamp_millis: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetCompleted {
    pub label: String,
    pub success: bool,
    pub timestamp_millis: i64,
    pub error_message: Option<String>,
    pub outputs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionStarted {
    pub action_id: String,
    pub label: String,
    pub mnemonic: String,
    pub timestamp_millis: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionCompleted {
    pub action_id: String,
    pub success: bool,
    pub timestamp_millis: i64,
    pub exit_code: i32,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Binary,
    Library,
    Test,
}
```

## Module Structure

```
crates/build-events/
├── Cargo.toml
└── src/
    ├── lib.rs               # Public API exports
    ├── bus.rs               # BuildEventBus implementation
    ├── subscriber.rs        # BuildEventSubscriber trait
    ├── dispatcher.rs        # Event distribution logic
    ├── events.rs            # Event type definitions
    └── subscribers/         # Built-in subscriber implementations
        ├── mod.rs
        ├── logger.rs        # Logs events via tracing (for debugging)
        └── json_file.rs     # Writes JSON-lines to file
```

## Future: Protobuf Subscriber Layer

When you need gRPC support, create a separate crate:

```
crates/build-events-proto/
├── Cargo.toml
├── build.rs                 # prost-build configuration
├── proto/
│   └── events.proto         # Protobuf definitions
└── src/
    ├── lib.rs
    ├── convert.rs           # Conversions: BuildEvent <-> proto
    └── subscriber.rs        # GrpcStreamSubscriber implementation
```

The proto crate would:
- Define protobuf schema
- Implement `From<BuildEvent>` for proto types
- Provide a `GrpcStreamSubscriber` that converts and streams events

## Integration with Minimal

### 1. Workspace Configuration
Add to root `Cargo.toml`:
```toml
[workspace]
members = [
    "crates/build-events",
    # ... other crates
]
```

### 2. Usage in Main Binary

```rust
use build_events::{BuildEventBus, BuildEventDispatcher, BuildEvent, subscribers};

#[tokio::main]
async fn main() {
    // Initialize tracing (existing diagnostic logs)
    tracing_subscriber::fmt::init();
    
    // Initialize build events
    let event_bus = BuildEventBus::new(10000);
    
    // Setup subscribers
    let mut dispatcher = BuildEventDispatcher::new(event_bus.subscribe());
    dispatcher.add_subscriber(Box::new(
        subscribers::JsonFileWriter::new("build_events.jsonl").unwrap()
    ));
    
    // Start event processing
    let dispatcher_handle = tokio::spawn(async move {
        dispatcher.run().await
    });
    
    // Pass event_bus to build executor
    let build_result = run_build(event_bus.clone(), build_config).await;
    
    // Shutdown: drop event_bus, wait for dispatcher to drain
    drop(event_bus);
    let _ = dispatcher_handle.await;
    
    // Continue with result handling...
}
```

### 3. Emitting Events in Build Logic

```rust
async fn execute_target(bus: BuildEventBus, target: &Target) -> Result<()> {
    bus.emit(BuildEvent::TargetStarted(TargetStarted {
        label: target.label.clone(),
        target_kind: target.kind,
        timestamp_millis: current_millis(),
    }));
    
    // ... build logic ...
    
    bus.emit(BuildEvent::TargetCompleted(TargetCompleted {
        label: target.label.clone(),
        success: result.is_ok(),
        timestamp_millis: current_millis(),
        error_message: result.as_ref().err().map(|e| e.to_string()),
        outputs: result.as_ref().ok().cloned().unwrap_or_default(),
    }));
    
    result
}
```

## Implementation Phases

### Phase 1: Core Infrastructure
- [ ] Setup `build-events` crate with serde
- [ ] Define Rust event types (6 event variants)
- [ ] Implement `BuildEventBus` with broadcast channel
- [ ] Define `BuildEventSubscriber` trait
- [ ] Implement `BuildEventDispatcher`
- [ ] Write unit tests for bus and dispatcher

### Phase 2: Built-in Subscribers
- [ ] Implement `LoggerSubscriber` (emits to tracing for debugging)
- [ ] Implement `JsonFileWriter` (JSON-lines format)
- [ ] Add integration tests

### Phase 3: Integration
- [ ] Add to `minimal` workspace
- [ ] Wire into main binary
- [ ] Add event emission to key build phases
- [ ] Documentation and examples

### Phase 4: Future (Out of Scope)
- `build-events-proto` crate with protobuf definitions
- gRPC streaming subscriber
- Event filtering/sampling
- Additional event types
- Metrics/analytics subscriber

## Error Handling

- **Bus emission**: Best-effort, never blocks. If channel is full, events are dropped (lagging subscribers)
- **Subscriber errors**: Logged via `tracing::warn!`, but don't stop other subscribers
- **Backpressure**: Broadcast channel size is configurable; slow subscribers will lag and miss events

## Testing Strategy

- Unit tests for event bus mechanics
- Unit tests for dispatcher subscription management
- Integration tests with mock subscribers
- Benchmark tests for overhead measurement
- Example subscriber implementations as test fixtures

## Open Questions / Future Considerations

1. Should we add event sequence numbers for ordering guarantees?
2. Do we need event filtering at the bus level?
3. Should the JSON file writer support rotation/compression?
4. Metrics on dropped events?

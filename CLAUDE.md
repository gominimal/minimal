# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building the Project
```bash
# Build all workspace members
cargo build

# Build specific crates
cargo build --package build-sandbox
cargo build --package minimal  
cargo build --package nickel-proto
```

### Running Tests
```bash
# Run all tests
cargo test

# Run tests for specific packages
cargo test --package nickel-proto
cargo test --package build-sandbox

# Run a specific test
cargo test --package nickel-proto experimenting_with_manual_api
```

### Running Applications
```bash
# Run the minimal package manager (executes zlib build)
cargo run --package minimal

# Run build-sandbox CLI with config
cargo run --package build-sandbox -- --config path/to/config.json --output /path/to/output
```

### Checking Code
```bash
# Check compilation without building
cargo check

# Check specific package
cargo check --package minimal
```

## Architecture Overview

### High-Level Components

This is a **minimal package manager** with three main components:

1. **nickel-proto**: Nickel language integration for declarative build specifications
2. **build-sandbox**: Cross-platform sandboxed build execution (Linux namespaces, macOS sandbox-exec)
3. **minimal**: Package manager orchestrator with dependency graph execution

### Data Flow

```
Package Spec (build.ncl) → SpecReader → DepGraph → ExecutionGraph → Sandboxed Builds → Output Collection
```

1. **Package Specifications**: Written in Nickel (`.ncl` files) in `packages/` directory
2. **Spec Parsing**: `nickel-proto` parses Nickel build specs into structured data
3. **Dependency Resolution**: `ExecutionGraph` orders builds topologically 
4. **Sandboxed Execution**: `build-sandbox` runs builds in isolated environments
5. **Output Management**: Collects enumerated outputs, warns about untracked files

### Key Architectural Decisions

**Sandbox Isolation Strategy**:
- **Linux**: User namespaces + mount namespaces for filesystem isolation
- **macOS**: `sandbox-exec` with dynamically generated policies
- **Dependencies vs Inputs**: Dependencies are read-only bind mounts, inputs are copied to TMPDIR

**Build Configuration Model**:
- **Dependencies**: System paths with read-only access (e.g., `/usr/bin/bash`)
- **Inputs**: Package files copied into build TMPDIR 
- **Outputs**: Glob patterns for build artifacts (e.g., `lib/libz.so*`)
- **Working Directory**: Always TMPDIR (no explicit working_directory)

**Execution Graph**: 
- Uses `petgraph` for topological sort of build dependencies
- Currently limited by private `BuildSpecRef` fields in nickel-proto
- Builds execute sequentially in dependency order

### Important Directories

- `packages/`: Contains package definitions (`.ncl` and build scripts)
- `toolchains/`: Cross-compilation toolchain (x86_64-unknown-linux-gnu)
- `crates/nickel-proto/minimal-ncl/`: Nickel schema definitions

### Critical Implementation Details

**TMPDIR Management**: 
- Temporary directories are NOT auto-deleted (for debugging)
- Build scripts receive `OUTPUT_DIR` environment variable pointing to staging area
- Only enumerated outputs are copied from staging to final destination

**BuildSpec Input Types**:
- `BuildSpecInput::Path(PathBuf)`: Host filesystem paths
- `BuildSpecInput::Build(BuildSpecRef)`: Dependencies on other builds (currently limited due to private fields)

**Platform Abstractions**:
- `Sandbox` trait with platform-specific implementations
- Linux uses direct syscalls via `nix` crate (no external dependencies)
- Error handling includes platform-specific sandbox violations

### Working with Package Specs

Package specifications are written in Nickel in `packages/<name>/build.ncl`:

```nickel
{
    name = "package-name",
    inputs = [
        {path = "/usr/bin/bash"} | HostPath,  # System dependencies
        # {name = "other-build"} | BuildSpec   # Build dependencies (future)
    ],
    cmd = "build.sh",
    outputs = {
        libname = { glob = "lib/libname.so*" } | OutputLib,
    },
} | BuildSpec
```

The minimal schema is defined in `crates/nickel-proto/minimal-ncl/minimal.ncl`.

### Known Limitations

- **BuildSpecRef Access**: Private fields prevent full BuildSpecInput::Build resolution
- **Single Package Focus**: Current implementation assumes zlib package 
- **Sequential Execution**: No parallel build execution
- **Limited Caching**: No build result caching between runs

### Development Notes

When debugging builds, check `/tmp/build-sandbox-*` directories which contain:
- Package contents copied to TMPDIR
- `output/` subdirectory with build artifacts
- Build execution logs and sandbox debug information

The `execution_graph` module provides the foundation for dependency-aware builds but currently has limited inter-build dependency resolution due to API constraints in the nickel-proto crate.

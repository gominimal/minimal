# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building Packages
```bash
# Build a package from source
cargo run -- build --package libffi --source

# Build a package using prebuilt dependencies (default)
cargo run -- build --package libffi

# Launch debug shell for troubleshooting builds
cargo run -- build --package libffi --debug

# Build with custom cache directory
cargo run -- build --package libffi --cache-dir /path/to/cache
```

### Planning Builds
```bash
# Show execution plan for a package
cargo run -- plan --package libffi
```

### Managing Prebuilts
```bash
# Upload prebuilt package to remote storage
cargo run -- upload-prebuilt --package libffi
```

### Development Commands
```bash
# Build all workspace members
cargo build

# Build specific crates
cargo build --package build-sandbox
cargo build --package minimal  
cargo build --package graph
cargo build --package cache

# Run all tests
cargo test

# Run tests for specific packages
cargo test --package graph
cargo test --package build-sandbox

# Check compilation without building
cargo check
```

## Architecture Overview

### High-Level Components

This is a **minimal package manager** with four main components:

1. **graph**: Nickel language integration for declarative build specifications and dependency graph management
2. **build-sandbox**: Cross-platform sandboxed build execution (Linux namespaces, macOS sandbox-exec)
3. **minimal**: Package manager orchestrator with CLI and execution coordination
4. **cache**: Content-addressed build artifact caching system using Blake3 hashes

### Data Flow

```
Package Spec (build.ncl) → SpecReader → DepGraph → ExecPlan → Build Resolution → Sandboxed Builds → Cache Storage
```

1. **Package Specifications**: Written in Nickel (`.ncl` files) in `packages/` directory (41 packages currently)
2. **Spec Parsing**: `graph` crate parses Nickel build specs into structured dependency graphs
3. **Build Planning**: `ExecPlan` creates topologically ordered execution phases supporting parallel builds within phases
4. **Input Resolution**: Resolves 5 input types (Build deps, Host paths, Sources, Local files, Prebuilts)
5. **Cache Lookup**: Content-addressed cache using Blake3 hashes of complete build specifications
6. **Sandboxed Execution**: `build-sandbox` runs builds in isolated environments when cache miss occurs
7. **Output Management**: Collects enumerated outputs, stores in cache with computed hashes

### Key Architectural Decisions

**Cache System**:
- **Content-addressed**: Uses Blake3 hash of complete build specification
- **Deterministic**: Same inputs always produce same cache key
- **Persistent**: Located at `~/.cache/minimal-builds/` by default
- **Hierarchical**: Organized by hash prefix for filesystem performance

**Remote Storage Integration**:
- **Google Cloud Storage**: Sources fetched from `gs://` URLs with SHA256 verification
- **Prebuilt distribution**: Upload/download of cached build results
- **Integrity verification**: All downloads verified against expected hashes

**Sandbox Isolation Strategy**:
- **Linux**: User namespaces + mount namespaces for filesystem isolation
- **macOS**: `sandbox-exec` with dynamically generated policies
- **Dependency mounting**: Build dependencies mounted read-only at specific paths
- **Input copying**: Source files and local inputs copied to TMPDIR
- **Output staging**: Builds write to `OUTPUT_DIR`, enumerated outputs copied to cache

**SpongeBob Integration**:
- **Build events**: Executor emits TargetStarted and TargetCompleted events for observability
- **Target identifiers**: Package names (e.g., "tar", "glibc") used as target IDs
- **File uploads**: stdout/stderr uploaded to SpongeBob after build execution
- **Event flow**: TargetStarted → Build executes → Files uploaded → TargetCompleted
- **Error handling**: Events published even on build failure for complete observability

### Package Ecosystem

**Current Package Count**: 41 packages including:
- **Toolchain**: gcc, binutils, glibc, linux-headers
- **Core utilities**: bash, coreutils, findutils, diffutils
- **Build tools**: make, autoconf, automake, m4, perl
- **Libraries**: zlib, bzip2, xz, zstd, libffi, expat, gmp, mpfr, mpc
- **Development**: python, file, grep, sed, gawk, bison, flex

**Package Dependencies**: Complex dependency graph with ~27 prebuilt packages in lockfile

### Build Input Types

**1. Build Dependencies (`BuildSpecRef`)**:
```nickel
bash,  // References to other package build specs
gcc,
```

**2. Host Paths (`HostPath`)**:
```nickel
{path = "/usr/bin/bash"} | HostPath,  // System dependencies
```

**3. Source Downloads (`Source`)**:
```nickel
{
    url = "gs://minimal-staging-archives/libffi-3.5.2.tar.gz",
    sha256 = "f3a3082a23b37c293a4fcd1053147b371f2ff91fa7ea1b2a52e335676bac82dc"
} | Source,
```

**4. Local Files (`Local`)**:
```nickel
{file = "build.sh"} | Local,  // Files from package directory
```

**5. Prebuilt Packages (`Prebuilt`)**:
```nickel
{package = "gcc"} | Prebuilt,  // Prebuilt from remote storage
```

## Important Directories

- `packages/`: Contains package definitions (`.ncl` and build scripts) - 41 packages
- `crates/graph/minimal-ncl/`: Nickel schema definitions for build specifications
- `prebuilts.lock`: Lockfile with Blake3 hashes for reproducible prebuilt selection
- `~/.cache/minimal-builds/`: Default location for build artifact cache

## Critical Implementation Details

**Spec Hashing**:
- Complete build specification (including transitive dependencies) hashed with Blake3
- Cache keys are deterministic and include all inputs that affect build output
- Local file inputs include file content hash to detect changes

**Prebuilts Lockfile**:
- `prebuilts.lock` contains Blake3 hashes for all prebuilt packages
- Ensures reproducible builds by pinning specific versions of prebuilt dependencies
- Updated when uploading new prebuilt packages

**TMPDIR Management**: 
- Temporary directories are NOT auto-deleted (for debugging)
- Build scripts receive `OUTPUT_DIR` environment variable pointing to staging area
- Only enumerated outputs are copied from staging to cache
- Debug builds preserve sandbox environment for inspection

**Execution Phases**:
- `ExecPlan` iterator yields `Vec<BuildSpecRef>` for parallel execution within phases
- Dependencies between builds enforce ordering between phases
- Single builds can have multiple dependency types resolved simultaneously

**Platform Abstractions**:
- `Sandbox` trait with platform-specific implementations
- Linux uses direct syscalls via `nix` crate (no external dependencies)
- Error handling includes platform-specific sandbox violations

**Build Observability (SpongeBob Integration)**:
- **build-sandbox executor** emits build events automatically when a SpongeBobInvocation is provided
- **TargetStarted event**: Published before build execution begins, creates target in database
- **TargetCompleted event**: Published after build finishes (success or failure)
- **File uploads**: stdout/stderr automatically uploaded to SpongeBob for each target
- **Target naming**: Uses package name as semantic target identifier (e.g., "tar" not a random UUID)
- **Requirement**: Targets must exist (via TargetStarted) before file uploads succeed

## Working with Package Specs

Package specifications are written in Nickel in `packages/<name>/build.ncl`:

```nickel
let {BuildSpec, HostPath, OutputLib, Local, Source, Prebuilt, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let gcc = import "../gcc/build.ncl" in
{
    name = "package-name",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://bucket/source.tar.gz",
            sha256 = "abc123..."
        } | Source,
        bash,  // Build dependency
        {package = "gcc"} | Prebuilt,  // Prebuilt dependency
    ],
    cmd = "./build.sh",
    outputs = {
        lib = { glob = "usr/lib/*" } | OutputLib,
        bin = { path = "usr/bin/tool" } | OutputBin,
    },
} | BuildSpec
```

The minimal schema is defined in `crates/graph/minimal-ncl/minimal.ncl`.

## Development Workflows

### Adding New Packages
1. Create `packages/<name>/` directory
2. Write `build.ncl` with proper input/output specifications  
3. Add `build.sh` script (referenced as Local input)
4. Test with `cargo run -- build --package <name> --source`
5. Upload prebuilt: `cargo run -- upload-prebuilt --package <name>`

### Debugging Build Issues
```bash
# Launch debug shell in build environment
cargo run -- build --package <name> --debug

# Check cache contents
ls ~/.cache/minimal-builds/

# View execution plan
cargo run -- plan --package <name>
```

### Cache Management
- Cache directories follow pattern: `~/.cache/minimal-builds/<hash_prefix>/<full_hash>/`
- Each successful build creates immutable cache entry
- Build failures don't create cache entries
- Manual cache clearing: `rm -rf ~/.cache/minimal-builds/`

## Known Limitations

- **macOS Support**: Sandbox implementation uses `sandbox-exec` (requires system binary)
- **GCS Dependency**: Source downloads currently only support Google Cloud Storage
- **Sequential Phases**: While builds within phases can be parallel, phases execute sequentially
- **No Incremental Builds**: Cache is all-or-nothing per complete build specification
- **Limited Cleanup**: Temporary build directories persist for debugging (manual cleanup required)

## Development Notes

### Debugging Builds
- Check `/tmp/build-sandbox-*` directories for build artifacts and logs
- Debug flag preserves sandbox environment for inspection
- Build scripts can examine `$OUTPUT_DIR` for expected output location

### Cache Inspection
- Cache entries are content-addressed by Blake3 hash of complete build spec
- Use `find ~/.cache/minimal-builds -name "*pattern*"` to locate specific builds
- Each cache entry contains the complete build output directory tree

### Testing Changes
- Always test new packages with `--source` flag first to ensure build scripts work
- Use `plan` command to verify dependency resolution before building
- Check prebuilts.lock gets updated when uploading new prebuilt packages

The `graph` crate provides the foundation for dependency-aware builds with full resolution of all input types and robust caching based on content-addressed build specifications.

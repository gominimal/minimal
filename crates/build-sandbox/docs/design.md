# Build Sandbox Utility - Design Proposal

## Overview
A cross-platform Rust-based CLI tool that provides filesystem-isolated build environments for macOS and Linux. On macOS, it uses `sandbox-exec` with custom policies. On Linux, it leverages unprivileged user namespaces and mount namespaces. Designed as a component for package managers and build tools, it ensures builds can only access explicitly declared input files while preventing interference with the host system.

## Architecture

### Core Components
- **Config Parser**: JSON deserializer for build specifications
- **Platform Abstraction Layer**: Trait-based sandbox interface with platform-specific implementations
- **Sandbox Policy Generator** (macOS): Dynamically creates sandbox-exec profiles based on input/output declarations
- **Namespace Sandbox** (Linux): Manages user/mount namespace creation and filesystem isolation
- **Build Executor**: Manages sandbox process lifecycle and build script execution
- **Output Collector**: Validates that all declared output files were produced and handles extraction

### Module Structure
```
src/
├── config.rs          # Shared configuration parsing
├── sandbox/
│   ├── mod.rs        # Sandbox trait definition and platform detection
│   ├── macos.rs      # macOS sandbox-exec implementation
│   └── linux.rs      # Linux namespace implementation
├── executor.rs       # Platform-agnostic build execution
├── output.rs         # Output validation and collection
└── error.rs          # Unified error types with platform-specific variants
```

### Execution Flow
1. Parse JSON configuration file
2. Detect platform and initialize appropriate sandbox implementation
3. Configure sandbox with input/output paths:
   - **macOS**: Generate sandbox-exec policy
   - **Linux**: Setup namespace and mount points
4. Execute build script within sandbox with restricted filesystem access
5. Validate that all declared output files were produced (fail if any are missing)
6. Extract output files and report results

## JSON Configuration Format

```json
{
  "dependencies": [
    "/path/to/system/libs",
    "/usr/local/lib/"
  ],
  "inputs": [
    "/path/to/source.rs",
    "/path/to/project/"
  ],
  "build_script": {
    "executable": "/usr/bin/cargo",
    "args": ["build", "--release"]
  },
  "outputs": [
    "target/release/binary",
    "target/release/lib*.dylib"
  ]
}
```

## Implementation Details

### Sandbox Policy Generation (macOS)
- Infer file vs directory type at runtime for each dependency path
- Create temporary sandbox profile allowing:
  - Read-only access to dependency files/directories
  - Read access to system libraries and standard tools
  - Write access to TMPDIR (which serves as working directory)
  - Execute permissions for build script and system utilities
- Input files are copied to TMPDIR before execution
- Deny all other filesystem access

### Linux Namespace Sandbox Implementation

#### Overview
Linux implementation uses unprivileged user namespaces combined with mount namespaces to create isolated build environments without requiring root privileges. **This implementation directly uses mount namespaces for filesystem isolation**, not wrapper commands like `unshare`. The sandboxing is implemented using native Linux namespace system calls via the `nix` crate.

#### Namespace Setup Process
1. **Create User Namespace**: Establishes a new user namespace where the process has full capabilities
2. **Create Mount Namespace**: Isolates filesystem mounts from the host system
3. **Setup Root Filesystem**:
   - Create a minimal root with bind-mounted essentials (/usr, /lib, /bin, /etc readonly)
   - Mount tmpfs for /tmp and /dev/shm
   - Create isolated /proc and /sys if needed by build tools
4. **Mount Dependency Paths**:
   - Bind mount each declared dependency file/directory as read-only
   - Preserve original path structure to maintain build script compatibility
   - Input files are copied to TMPDIR (not bind-mounted)
5. **Create Output Directory**:
   - Mount tmpfs or bind mount temporary directory for outputs
   - Ensure write permissions in the working directory

#### Implementation Using Native Mount Namespaces
- **Direct namespace manipulation** using the `nix` crate for safe Rust bindings:
  - `unshare()` system call for namespace creation
  - `mount()` and `umount()` for filesystem operations  
  - `pivot_root()` for root filesystem switching
  - `setuid()/setgid()` for user mapping within namespace
- **Mount namespace workflow** (executed within the sandbox process):
  ```rust
  // Native mount namespace implementation
  unshare(CLONE_NEWUSER | CLONE_NEWNS)
  setup_uid_gid_mappings()
  mount("none", "/", None, MS_REC | MS_PRIVATE)
  setup_minimal_root_with_bind_mounts()
  bind_mount_declared_inputs()
  pivot_root_to_sandbox()
  exec_build_script_in_isolated_environment()
  ```
- **Key principle**: The build process runs in a completely isolated mount namespace where only explicitly declared inputs are accessible

#### Minimal Permission Model
- Requires **no root privileges** - runs entirely as unprivileged user
- Requires kernel support for unprivileged user namespaces (enabled by default on most distros)
- Fallback error messages if user namespaces are disabled (e.g., some hardened kernels)
- No setuid binaries or sudo required

### Error Handling & Reporting
- **Build Script Failures**: Forward exit codes and stderr from build process
- **Sandbox Violations**: 
  - macOS: Capture and report sandbox-exec denial messages
  - Linux: Report mount failures and permission errors
- **Missing Outputs**: Fail build if any declared output files are not produced
- **Config Errors**: Detailed JSON parsing and validation error messages
- **Platform-Specific Errors**:
  - Linux: User namespace not available (suggest kernel config changes)
  - macOS: Sandbox-exec not available (incompatible OS version)
  - Unsupported platform detection with helpful error message

### CLI Interface
```bash
build-sandbox --config build.json [--verbose] [--dry-run]
```

## Technical Considerations

### Dependencies
- `serde_json` for configuration parsing
- `tempfile` for output staging directories
- Standard library `std::process` for sandbox-exec integration (macOS)
- `nix` crate for Linux namespace operations
- `libc` for low-level Linux system calls

### Platform Abstraction
- Unified CLI interface with automatic platform detection
- Common `Sandbox` trait implemented by platform-specific modules
- Shared configuration format across platforms
- Platform-specific error handling and reporting

### macOS Integration
- Leverage `sandbox-exec` with custom profiles for fine-grained filesystem control
- Handle macOS-specific path resolution and permission models
- Support for macOS system integrity protection boundaries

### Linux Integration
- **Native mount namespace sandboxing** - Direct use of Linux namespace system calls for true filesystem isolation
- User namespaces for unprivileged operation (no root/sudo required)
- Mount namespaces with `pivot_root()` for complete filesystem isolation
- Bind mounts for selective file/directory access to declared inputs only
- Isolated root filesystem with minimal system directories
- Compatible with most modern Linux distributions (kernel 3.8+)
- **No dependency on external sandbox tools** - Pure Rust implementation using `nix` crate

### Platform Compatibility Matrix

| Platform | Minimum Version | Requirements | Notes |
|----------|----------------|--------------|-------|
| macOS | 10.15 (Catalina) | sandbox-exec available | Uses Seatbelt/sandbox-exec profiles |
| Linux | Kernel 3.8+ | Unprivileged user namespaces enabled | Check with `sysctl kernel.unprivileged_userns_clone` |
| Ubuntu | 16.04+ | Default configuration | User namespaces enabled by default |
| Debian | 10+ | Default configuration | User namespaces enabled by default |
| Fedora | 30+ | Default configuration | User namespaces enabled by default |
| RHEL/CentOS | 8+ | May require sysctl configuration | Enable with `sysctl -w kernel.unprivileged_userns_clone=1` |
| Alpine Linux | 3.8+ | Default configuration | Minimal distro, works out of the box |

### Performance & Reliability
- Minimal overhead through direct sandbox-exec integration (macOS)
- Efficient namespace creation and teardown (Linux)
- Robust cleanup of temporary directories and processes
- Atomic output collection to prevent partial results

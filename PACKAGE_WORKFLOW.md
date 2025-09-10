# Package Creation Workflow for Claude

This guide provides step-by-step instructions for Claude (AI assistants) to add new packages to the minpkgs system using Linux From Scratch (LFS) and Beyond Linux From Scratch (BLFS) as reference sources.

## Overview

The workflow involves:
1. Finding package information from LFS or BLFS
2. Uploading source archives to Google Cloud Storage
3. Creating package specifications and build scripts
4. Iteratively resolving dependencies through build failures

## Step 1: Research Package in Linux From Scratch or Beyond Linux From Scratch

### For Core System Packages (LFS)

1. **Find the package list**: Visit https://www.linuxfromscratch.org/lfs/view/systemd/chapter03/packages.html
2. **Locate your package**: Find the package name, version, and download URL
3. **Check build instructions**: Navigate to the corresponding chapter (e.g., Chapter 8 for system packages) to see the build commands

Example for "patch":
- Download URL: `https://ftp.gnu.org/gnu/patch/patch-2.8.tar.xz`
- Build instructions in Chapter 8.24

### For Additional Packages (BLFS)

1. **Browse BLFS index**: Visit https://www.linuxfromscratch.org/blfs/view/systemd/index.html
2. **Navigate by category**: Browse sections like:
   - General Libraries (e.g., libffi, gmp, mpfr)
   - System Utilities (e.g., which, tree)
   - Programming (e.g., Python modules, development tools)
   - Multimedia Libraries (e.g., SDL, audio/video codecs)
   - Networking (e.g., curl, wget)
   - Text Web Browsers, Desktop environments, etc.
3. **Find package page**: Each package has its own page with download URLs and build instructions
4. **Note dependencies**: BLFS packages often have more complex dependency chains

Example for "libffi" (BLFS General Libraries):
- BLFS page: https://www.linuxfromscratch.org/blfs/view/systemd/general/libffi.html
- Download URL: `https://github.com/libffi/libffi/releases/download/v3.5.2/libffi-3.5.2.tar.gz`
- Build instructions with configure options specific to libffi

### Choosing Between LFS and BLFS

- **LFS packages**: Core system components needed for a minimal Linux system (toolchain, basic utilities)
- **BLFS packages**: Additional functionality beyond basic system (libraries, applications, development tools)
- **Check LFS first**: If a package isn't in LFS Chapter 3, check BLFS
- **Version consistency**: Use versions that match the LFS/BLFS book you're following

## Step 2: Upload Source Archive

1. **Download the source**: Use the URL from LFS or BLFS package page
```bash
# LFS example
wget https://ftp.gnu.org/gnu/patch/patch-2.8.tar.xz

# BLFS example  
wget https://github.com/libffi/libffi/releases/download/v3.5.2/libffi-3.5.2.tar.gz
```

2. **Upload to Google Cloud Storage**:
```bash
# LFS example
gcloud storage cp patch-2.8.tar.xz gs://minimal-staging-archives/

# BLFS example
gcloud storage cp libffi-3.5.2.tar.gz gs://minimal-staging-archives/
```

## Step 3: Create Package Directory Structure

Create the package directory and files:
```bash
mkdir -p packages/<package-name>
```

## Step 4: Create build.ncl Specification

Create `packages/<package-name>/build.ncl` with this template:

```nickel
let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
    name = "package-name",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/package-version.tar.ext",
            sha256 = "placeholder_sha256_will_be_updated_from_build_failure"
        } | Source,
        base,
        toolchain,
    ],
    cmd = "./build.sh",
    outputs = {
        # Define outputs based on what the package installs
        # Common patterns:
        # bin = { glob = "usr/bin/*" } | OutputLib,
        # lib = { glob = "usr/lib/*" } | OutputLib,
        # include = { glob = "usr/include/*" } | OutputLib,
        # man = { glob = "usr/share/man/man*/*" } | OutputLib,
    },
} | BuildSpec
```

### Understanding Metapackages

The minpkgs system uses two key metapackages that simplify dependency management:

#### `base` metapackage
Contains common build and system utilities:
- bash, coreutils, sed, grep, gawk, make
- tar, xz, bzip2, gzip (archive utilities)
- diffutils, findutils, file, perl

#### `toolchain` metapackage  
Contains core compilation tools:
- gcc (C/C++ compiler)
- binutils (assembler, linker, etc.)
- glibc (C library)
- linux_headers (kernel headers)
- Includes `base` as a dependency

**Key Benefits:**
- **Simplified dependencies**: Just import `base` and `toolchain` instead of 10+ individual packages
- **Consistent environment**: All packages get the same standard build environment
- **Reduced maintenance**: Changes to core tools propagate automatically

## Step 5: Create build.sh Script

Create `packages/<package-name>/build.sh` based on LFS or BLFS instructions:

### LFS Pattern (Simple autotools)
```bash
#!/bin/sh
set -e

# Extract archive (adjust command based on file type)
tar xfo package-version.tar.ext
cd package-version

# Build commands from LFS (common pattern)
./configure --prefix=/usr
make
make DESTDIR="$OUTPUT_DIR" install
```

### BLFS Pattern (More complex configuration)
```bash
#!/bin/sh
set -e

# Extract archive
tar xfo libffi-3.5.2.tar.gz
cd libffi-3.5.2

# BLFS often has more configure options
./configure --prefix=/usr          \
            --disable-static       \
            --with-gcc-arch=native \
            --disable-exec-static-tramp
make
make DESTDIR="$OUTPUT_DIR" install
```

**Important notes:**
- Always use `DESTDIR="$OUTPUT_DIR"` for installation
- Use `make -j$(nproc)` for parallel builds if the package supports it
- Copy configuration flags exactly from LFS/BLFS documentation
- BLFS packages often have more complex configure options and dependencies

## Step 5a: Make Build Script Executable

After creating the build.sh script, make it executable:
```bash
chmod +x packages/<package-name>/build.sh
```

## Step 6: Initial Build Attempt

Run the build command:
```bash
cargo run -- build --package <package-name>
```

**Expected outcome:** The build will fail with a SHA256 mismatch error that shows the correct hash.

Copy the correct SHA256 from the error message and update `build.ncl`.

## Step 7: Iterative Dependency Resolution

Re-run the build command. Most packages will build successfully with just `base` and `toolchain` metapackages, but some may need additional dependencies.

When a build fails due to missing dependencies:

1. **Identify the missing tool/library** from error messages
2. **Add the specific package** to the inputs in `build.ncl`
3. **Re-run the build**

### Common Additional Dependencies

Most basic build tools are included in `base` and `toolchain`, but you may need to add:

- `m4 = import "../m4/build.ncl" in` for macro processing
- `autoconf = import "../autoconf/build.ncl" in` for autotools
- `automake = import "../automake/build.ncl" in` for autotools  
- `pkgconf = import "../pkgconf/build.ncl" in` for pkg-config
- Other library dependencies specific to the package

### Adding Dependencies

When you identify a missing dependency:

1. Add the import at the top:
```nickel
let m4 = import "../m4/build.ncl" in
```

2. Add it to the inputs array:
```nickel
inputs = [
    {file = "build.sh"} | Local,
    {url = "...", sha256 = "..."} | Source,
    base,
    toolchain,
    m4,  # Additional dependency
],
```

### When NOT to Add Individual Dependencies

**Do NOT add these individually** - they're already included in the metapackages:
- bash, coreutils, sed, grep, gawk, make (in `base`)
- tar, xz, bzip2, gzip (in `base`) 
- gcc, binutils, glibc, linux_headers (in `toolchain`)

## Step 8: Define Outputs

Update the `outputs` section based on what the package installs. Common patterns:

```nickel
outputs = {
    # For packages that install executables in /usr/bin
    bin = { glob = "usr/bin/*" } | OutputLib,
    
    # For system admin tools in /usr/sbin (like libcap)
    sbin = { glob = "usr/sbin/*" } | OutputLib,
    
    # For libraries (includes .so files, .a files, pkgconfig)
    lib = { glob = "usr/lib/*" } | OutputLib,
    
    # For header files (use ** for nested directories)
    include = { glob = "usr/include/**/*" } | OutputLib,
    
    # For man pages (use ** for multiple sections)
    man = { glob = "usr/share/man/**/*" } | OutputLib,
    
    # For specific files (like patch executable)
    patch = { glob = "usr/bin/patch" } | OutputLib,
    
    # For complex libraries with multiple components (like libcap)
    cap_libs = { glob = "usr/lib/libcap*" } | OutputLib,
    psx_libs = { glob = "usr/lib/libpsx*" } | OutputLib,
    
    # For packages with both shared and static libraries
    shared_libs = { glob = "usr/lib/*.so*" } | OutputLib,
    static_libs = { glob = "usr/lib/*.a" } | OutputLib,
    pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
},
```

**Output Pattern Notes:**
- Use `*` for single-level wildcards (files in one directory)
- Use `**/*` for recursive wildcards (files in nested subdirectories)
- Check build logs to see exactly where files are installed
- Some packages install tools in `/usr/sbin` instead of `/usr/bin`

## Examples

### Simple LFS Package (patch)
- Basic configure/make/install pattern
- Uses `base` and `toolchain` metapackages
- Single binary output
- Found in LFS Chapter 8

### Complex LFS Package (ncurses) 
- Multiple configure flags
- Uses `base` and `toolchain` metapackages
- Many library outputs
- Parallel make with `-j$(nproc)`
- Found in LFS Chapter 8

### BLFS Library Package (libffi, libunistring)
- Complex configure options for optimization
- Uses `base` and `toolchain` metapackages
- Library outputs with development headers
- Most build successfully with just the metapackages
- Found in BLFS General Libraries section

### BLFS Utility Package (which)
- Simple utility but sourced from BLFS
- Uses `base` and `toolchain` metapackages
- Minimal build requirements
- Found in BLFS System Utilities section

## Debugging Tips

1. **Use debug mode**: `cargo run -- build --package <name> --debug` launches a shell in the build environment
2. **Check build logs**: Temporary directories are preserved in `/tmp/build-sandbox-*`
3. **Examine LFS/BLFS instructions carefully**: Some packages have special installation steps
4. **Look at existing packages**: Check similar packages in the codebase for patterns
5. **BLFS dependency chains**: BLFS packages may have complex dependency requirements not obvious from the main instructions

## Common Pitfalls

1. **Forgetting DESTDIR**: Always use `make DESTDIR="$OUTPUT_DIR" install`
2. **Adding individual dependencies unnecessarily**: Use `base` and `toolchain` metapackages instead of individual tools
3. **Incomplete outputs**: Make sure all important files are listed in outputs
4. **Wrong configure flags**: Copy flags exactly from LFS/BLFS documentation
5. **Executable permissions**: Run `chmod +x` on build.sh before testing
6. **BLFS version mismatches**: Ensure BLFS package versions are compatible with your LFS base system
7. **Missing library dependencies**: BLFS packages may require other BLFS library packages

## Troubleshooting Output Pattern Errors

When you get `Output(MissingOutput { path: "..." })` errors:

1. **Check the build logs** to see where files are actually installed:
   ```bash
   # Look for "install" commands in the build output
   # Check /tmp/build-sandbox-*/output/ directory structure
   ```

2. **Common mismatches**:
   - Executables in `/usr/sbin` instead of `/usr/bin` (system admin tools)
   - Headers in nested directories requiring `usr/include/**/*` 
   - Libraries with specific naming patterns needing exact globs

3. **Debug with directory listing**:
   - Build logs show the exact `install` commands and target paths
   - Check what actually gets created in the OUTPUT_DIR

4. **Pattern matching rules**:
   - `usr/bin/*` matches files directly in usr/bin
   - `usr/include/*` matches files directly in usr/include (not subdirectories)
   - `usr/include/**/*` matches files in usr/include and all subdirectories

## Completion

Once the build succeeds without errors:
1. The package is ready to use
2. Other packages can depend on it by importing its `build.ncl`
3. No additional upload steps are needed (this workflow is for non-split packages only)
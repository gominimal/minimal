# Package Creation Workflow for Claude

This guide provides step-by-step instructions for Claude (AI assistants) to add new packages to the minpkgs system using Linux From Scratch (LFS) as a reference source.

## Overview

The workflow involves:
1. Finding package information from LFS
2. Uploading source archives to Google Cloud Storage
3. Creating package specifications and build scripts
4. Iteratively resolving dependencies through build failures

## Step 1: Research Package in Linux From Scratch

1. **Find the package list**: Visit https://www.linuxfromscratch.org/lfs/view/systemd/chapter03/packages.html
2. **Locate your package**: Find the package name, version, and download URL
3. **Check build instructions**: Navigate to the corresponding chapter (e.g., Chapter 8 for system packages) to see the build commands

Example for "patch":
- Download URL: `https://ftp.gnu.org/gnu/patch/patch-2.8.tar.xz`
- Build instructions in Chapter 8.24

## Step 2: Upload Source Archive

1. **Download the source**: Use the URL from LFS package list
```bash
wget https://ftp.gnu.org/gnu/patch/patch-2.8.tar.xz
```

2. **Upload to Google Cloud Storage**:
```bash
gcloud storage cp patch-2.8.tar.xz gs://minimal-staging-archives/
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
let bash = import "../bash/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let tar = import "../tar/build.ncl" in
# Add archive utility based on file extension:
# let gzip = import "../gzip/build.ncl" in      # for .tar.gz
# let xz = import "../xz/build.ncl" in          # for .tar.xz
# let bzip2 = import "../bzip2/build.ncl" in    # for .tar.bz2
{
    name = "package-name",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/package-version.tar.ext",
            sha256 = "placeholder_sha256_will_be_updated_from_build_failure"
        } | Source,
        bash,
        binutils, 
        coreutils,
        gcc,
        glibc,
        linux_headers,
        tar,
        # Add archive utility here
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

## Step 5: Create build.sh Script

Create `packages/<package-name>/build.sh` based on LFS instructions:

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

**Important notes:**
- Always use `DESTDIR="$OUTPUT_DIR"` for installation
- Use `make -j$(nproc)` for parallel builds if the package supports it
- Copy configuration flags from LFS documentation

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

Re-run the build command. When it fails due to missing dependencies:

1. **Identify the missing tool/library** from error messages
2. **Add the corresponding package** to the inputs in `build.ncl`
3. **Re-run the build**

### Common Dependencies to Add

Based on build failures, you'll typically need to add:

- `make = import "../make/build.ncl" in` for build systems
- `sed = import "../sed/build.ncl" in` for text processing
- `grep = import "../grep/build.ncl" in` for pattern matching  
- `diffutils = import "../diffutils/build.ncl" in` for diff, cmp commands
- `gawk = import "../gawk/build.ncl" in` for AWK processing
- `m4 = import "../m4/build.ncl" in` for macro processing
- `autoconf = import "../autoconf/build.ncl" in` for autotools
- `automake = import "../automake/build.ncl" in` for autotools
- `perl = import "../perl/build.ncl" in` for Perl scripts

### Adding Dependencies

When you identify a missing dependency:

1. Add the import at the top:
```nickel
let make = import "../make/build.ncl" in
```

2. Add it to the inputs array:
```nickel
inputs = [
    # ... existing inputs ...
    make,
],
```

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

### Simple Package (patch)
- Basic configure/make/install pattern
- Minimal dependencies
- Single binary output

### Complex Package (ncurses) 
- Multiple configure flags
- Many library outputs
- Parallel make with `-j$(nproc)`

## Debugging Tips

1. **Use debug mode**: `cargo run -- build --package <name> --debug` launches a shell in the build environment
2. **Check build logs**: Temporary directories are preserved in `/tmp/build-sandbox-*`
3. **Examine LFS instructions carefully**: Some packages have special installation steps
4. **Look at existing packages**: Check similar packages in the codebase for patterns

## Common Pitfalls

1. **Forgetting DESTDIR**: Always use `make DESTDIR="$OUTPUT_DIR" install`
2. **Missing archive utilities**: Add gzip/xz/bzip2 based on archive type
3. **Incomplete outputs**: Make sure all important files are listed in outputs
4. **Wrong configure flags**: Copy flags exactly from LFS documentation
5. **Missing make dependency**: Most packages need the `make` package
6. **Executable permissions**: Run `chmod +x` on build.sh before testing

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
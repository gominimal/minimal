# Linux From Scratch (LFS) Package Progress Tracker

## Overview
This document tracks progress on packaging all 79 Linux From Scratch Chapter 8 packages in our minimal package manager format.

## General Instructions

### Package Structure
Each package should follow this structure:
```
packages/{package-name}/
├── build.ncl          # Nickel build specification
├── build.sh           # Build script following LFS instructions
└── {source-archive}   # Downloaded source archive (e.g., package-1.2.tar.xz)
```

### Build Specification Template (build.ncl)
```nickel
let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make_static = import "../make_static/build.ncl" in
{
    name = "{package-name}",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "{source-archive}"} | Local,
        # Add any patch files: {file = "package.patch"} | Local,
        busybox_static,
        make_static,
        # Add other build dependencies as needed
    ],
    cmd = "./build.sh",
    outputs = {
        # Define specific outputs with glob patterns
        # Example: binary = { glob = "bin/program" } | OutputLib,
        # Example: library = { glob = "lib/lib*.so*" } | OutputLib,
        # Example: headers = { glob = "include/*.h" } | OutputLib,
    },
} | BuildSpec
```

### Build Script Template (build.sh)
```bash
#!/usr/bin/bash
set -e

# Source shared toolchain setup
source "${SCRIPTS_DIR}/toolchain-setup.sh"

# Extract and build following LFS instructions
# Use $OUTPUT_DIR as installation prefix
# Follow exact LFS steps from the relevant page
```

### Testing
Each package should be tested with:
```bash
cargo run -- build --package {package-name}
```

**Mark as Complete**: After successful build testing, mark the package as complete in the progress tracker below.

## Package Status

### ✅ Completed (27/79)
- [x] Zlib (compression library)
- [x] Grep (text search utility)
- [x] Iana-Etc (protocols and services files)
- [x] Bzip2 (compression library and utilities)
- [x] Xz (LZMA compression library and utilities)  
- [x] Zstd (Zstandard compression)
- [x] File (file type identification utility) - libmagic 5.46, file command, man pages
- [x] M4 (macro processor) - GNU M4 1.4.19, includes locale support
- [x] BC (basic calculator) - BC 7.0.3 with DC, arbitrary precision math
- [x] Tcl (Tool Command Language) - Tcl 8.6.16, scripting language with extensive API
- [x] Bison (parser generator) - Bison 3.8.2, yacc replacement with GLR/LALR parsers
- [x] Readline (command line editing library)
- [x] Lz4 (fast compression algorithm) - LZ4 1.10.0 with lossless compression, binaries and library
- [x] Make (build tool) - GNU Make 4.4.1 for controlling package compilation
- [x] Sed (stream editor) - GNU Sed 4.9 for filtering and transforming text
- [x] Bash (shell) - Bash 5.3, the Bourne Again Shell
- [x] Tar (archive utility) - Tar 1.35 for creating and extracting archives
- [x] Gzip (compression utility) - Gzip 1.14 for compressing and decompressing files
- [x] Gawk (GNU Awk) - Gawk 5.3.2 for pattern scanning and processing
- [x] Diffutils (file comparison utilities) - Diffutils 3.12 for comparing files and directories
- [x] Attr (extended attribute library) - Attr 2.5.2 for managing filesystem extended attributes
- [x] Acl (Access Control List library) - ACL 2.3.2 for managing POSIX access control lists
- [x] Autoconf (automatic configure script builder) - Autoconf 2.72 for generating configure scripts
- [x] Automake (automatic Makefile generator) - Automake 1.17 for generating Makefile.in files
- [x] Coreutils (core utilities) - Coreutils 9.7 with essential utilities like ls, cp, mv, etc.
- [x] Perl (Practical Extraction and Report Language) - Perl 5.42.0 scripting language
- [x] Binutils (binary utilities) - Binutils 2.45 with assembler, linker, and other binary tools

### 🔄 In Progress (0/79)
- [ ] Man-pages (manual pages for Linux kernel and C library) - moved back from completed, not in packages/
- [ ] Flex (lexical analyzer generator) - moved back from completed, not in packages/

### ⏳ Pending (50/79)
3. **Expect** - Automate interactive applications
4. **DejaGNU** - Testing framework
5. **Pkgconf** - Package configuration system
12. **Libcap** - POSIX capabilities library
13. **Libxcrypt** - Extended crypt library
14. **Shadow** - Password and account management tools
16. **Ncurses** - Terminal handling library
18. **Psmisc** - Process utilities
19. **Gettext** - Internationalization library
21. **Libtool** - Generic library support script
22. **GDBM** - GNU database library
23. **Gperf** - Perfect hash function generator
24. **Expat** - XML parser library
25. **Inetutils** - Network utilities
26. **Less** - Text pager
28. **XML::Parser** - Perl XML parser module
29. **Intltool** - Internationalization tool
32. **OpenSSL** - Cryptography library
33. **Libelf** - ELF file access library
34. **Libffi** - Foreign Function Interface library
35. **Python** - Python programming language
36. **Flit-Core** - Python packaging build backend
37. **Packaging** - Python packaging library
38. **Wheel** - Python wheel packaging format
39. **Setuptools** - Python package build system
40. **Ninja** - Small build system
41. **Meson** - Build system
42. **Kmod** - Kernel module utilities
46. **Findutils** - File finding utilities
47. **Groff** - Document formatting system
48. **GRUB** - Boot loader
50. **IPRoute2** - Network routing utilities
51. **Kbd** - Keyboard utilities
52. **Libpipeline** - Pipeline manipulation library
53. **Patch** - File patching utility
56. **Texinfo** - Documentation system
57. **Vim** - Text editor
58. **MarkupSafe** - Python HTML/XML markup library
59. **Jinja2** - Python templating engine
60. **Systemd** - System and service manager
61. **D-Bus** - Message bus system
62. **Man-DB** - Manual page database
63. **Procps-ng** - Process monitoring utilities
64. **Util-linux** - System utilities
65. **E2fsprogs** - Ext2/3/4 filesystem utilities

## Priority Order
1. **System Libraries**: Glibc, Zlib (done), Bzip2 (done), Xz (done), Readline (done)
2. **Build Tools**: M4 (done), Autoconf, Automake, Make, GCC, Binutils
3. **Core Utilities**: Coreutils, Bash, Sed, Grep (done)
4. **Package Management**: Pkgconf
5. **Development Tools**: Flex, Bison (done), Perl, Python
6. **System Components**: Systemd, D-Bus, Shadow

## Package Sources
- **Official LFS Package List**: https://www.linuxfromscratch.org/lfs/view/systemd/chapter08/chapter08.html
- **Download URLs**: Individual package download URLs can be found in each package's LFS section
- **Versions**: Using exact versions specified in LFS systemd edition for consistency

## Notes
- Each package should be built in dependency order
- Some packages may require patches or modifications from stock LFS instructions
- All packages use the same toolchain located at `./toolchains/x86_64-unknown-linux-gnu`

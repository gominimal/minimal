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
let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "{package-name}",
    inputs = [
        {path = "/bin"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        # Add other required system tools based on LFS instructions
    ],
    cmd = "build.sh",
    outputs = {
        # Define outputs based on what the package installs
        # Use glob patterns like "bin/*", "lib/lib*.so*", etc.
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
cargo run --bin minimal -- --package {package-name}
```

## Package Status

### ✅ Completed (13/79)
- [x] Zlib (compression library)
- [x] Grep (text search utility)
- [x] Man-pages (3,007 manual pages installed)
- [x] Iana-Etc (protocols and services files)
- [x] Bzip2 (compression library and utilities)
- [x] Xz (LZMA compression library and utilities)  
- [x] Zstd (Zstandard compression)
- [x] File (file type identification utility) - libmagic 5.46, file command, man pages
- [x] M4 (macro processor) - GNU M4 1.4.19, includes locale support
- [x] BC (basic calculator) - BC 7.0.3 with DC, arbitrary precision math
- [x] Tcl (Tool Command Language) - Tcl 8.6.16, scripting language with extensive API
- [x] Bison (parser generator) - Bison 3.8.2, yacc replacement with GLR/LALR parsers
- [x] Flex (lexical analyzer generator) - Flex 2.6.4, generates lexical analyzers with libfl

### 🔄 In Progress (0/79)

### ⏳ Pending (66/79)

1. **Man-pages** - Manual pages for Linux kernel and C library
2. **Iana-Etc** - Data for /etc/protocols and /etc/services  
3. **Glibc** - GNU C Library (critical system component)
4. **Bzip2** - Compression library and utilities
5. **Xz** - LZMA compression library and utilities
6. **Lz4** - Fast compression algorithm
7. **Zstd** - Zstandard compression
8. **File** - File type identification utility
9. **Readline** - Command line editing library
10. **M4** - Macro processor
11. **Bc** - Arbitrary precision calculator language
12. **Tcl** - Tool Command Language
13. **Expect** - Automate interactive applications
14. **DejaGNU** - Testing framework
15. **Pkgconf** - Package configuration system
16. **Binutils** - Binary utilities (assembler, linker, etc.)
17. **GMP** - GNU Multiple Precision Arithmetic Library
18. **MPFR** - Multiple-precision floating-point library
19. **MPC** - Multiple-precision complex number library
20. **Attr** - Extended attribute library
21. **Acl** - Access Control List library
22. **Libcap** - POSIX capabilities library
23. **Libxcrypt** - Extended crypt library
24. **Shadow** - Password and account management tools
25. **GCC** - GNU Compiler Collection
26. **Ncurses** - Terminal handling library
27. **Sed** - Stream editor
28. **Psmisc** - Process utilities
29. **Gettext** - Internationalization library
30. **Bison** - Parser generator
31. **Bash** - Bourne Again Shell
32. **Libtool** - Generic library support script
33. **GDBM** - GNU database library
34. **Gperf** - Perfect hash function generator
35. **Expat** - XML parser library
36. **Inetutils** - Network utilities
37. **Less** - Text pager
38. **Perl** - Practical Extraction and Report Language
39. **XML::Parser** - Perl XML parser module
40. **Intltool** - Internationalization tool
41. **Autoconf** - Automatic configure script builder
42. **Automake** - Automatic Makefile generator
43. **OpenSSL** - Cryptography library
44. **Libelf** - ELF file access library
45. **Libffi** - Foreign Function Interface library
46. **Python** - Python programming language
47. **Flit-Core** - Python packaging build backend
48. **Packaging** - Python packaging library
49. **Wheel** - Python wheel packaging format
50. **Setuptools** - Python package build system
51. **Ninja** - Small build system
52. **Meson** - Build system
53. **Kmod** - Kernel module utilities
54. **Coreutils** - Core utilities (ls, cp, mv, etc.)
55. **Diffutils** - File comparison utilities
56. **Gawk** - GNU Awk
57. **Findutils** - File finding utilities
58. **Groff** - Document formatting system
59. **GRUB** - Boot loader
60. **Gzip** - Compression utility
61. **IPRoute2** - Network routing utilities
62. **Kbd** - Keyboard utilities
63. **Libpipeline** - Pipeline manipulation library
64. **Make** - Build tool
65. **Patch** - File patching utility
66. **Tar** - Archive utility
67. **Texinfo** - Documentation system
68. **Vim** - Text editor
69. **MarkupSafe** - Python HTML/XML markup library
70. **Jinja2** - Python templating engine
71. **Systemd** - System and service manager
72. **D-Bus** - Message bus system
73. **Man-DB** - Manual page database
74. **Procps-ng** - Process monitoring utilities
75. **Util-linux** - System utilities
76. **E2fsprogs** - Ext2/3/4 filesystem utilities

## Priority Order
1. **System Libraries**: Glibc, Zlib (done), Bzip2, Xz, Readline
2. **Build Tools**: M4, Autoconf, Automake, Make, GCC, Binutils
3. **Core Utilities**: Coreutils, Bash, Sed, Grep (done)
4. **Package Management**: Pkgconf
5. **Development Tools**: Flex, Bison, Perl, Python
6. **System Components**: Systemd, D-Bus, Shadow

## Known Issues / Blockers

### 1. Package Dependency Resolution (Critical)
**Issue**: The current system doesn't properly handle package-to-package dependencies. While the ExecutionGraph framework exists, BuildSpecInput::Build dependencies aren't fully functional.

**Impact**: Complex packages like Glibc, GCC, and other system components that depend on previously built packages cannot be properly built.

**Required Solution**: 
- Implement proper BuildSpecInput::Build dependency resolution in ExecutionGraph
- Ensure dependency outputs are available to dependent builds
- Verify dependency ordering works correctly

**Workaround**: Continue with simple packages that don't have complex dependencies first

## Package Sources
- **Official LFS Package List**: https://www.linuxfromscratch.org/lfs/view/systemd/chapter08/chapter08.html
- **Download URLs**: Individual package download URLs can be found in each package's LFS section
- **Versions**: Using exact versions specified in LFS systemd edition for consistency

## Notes
- Each package should be built in dependency order
- Some packages may require patches or modifications from stock LFS instructions
- All packages use the same toolchain located at `./toolchains/x86_64-unknown-linux-gnu`
- Output files are installed to `./minimal-out` with flattened directory structure

## Session Notes
- **Session 1**: Created progress tracker, identified 79 packages total with 2 already completed
- **Session 1 (continued)**: Successfully packaged Man-pages (3,007 files) and Iana-Etc (2 files). Identified critical tooling issue with package dependency resolution that will block complex packages.

let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let expect = import "../expect/build.ncl" in
let file = import "../file/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let tcl = import "../tcl/build.ncl" in
let texinfo = import "../texinfo/build.ncl" in
let xz = import "../xz/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
    name = "binutils",
    inputs = [
        {file = "binutils-2.45.tar.xz"} | Local,
        {file = "build.sh"} | Local,
        bash,
        coreutils,
        expect,
        file,
        gawk,
        grep,
        gzip,
        make,
        perl,
        sed,
        tar,
        tcl,
        texinfo,
        xz,
        zlib,
    ],
    cmd = "./build.sh",
    outputs = {
        addr2line = { glob = "usr/bin/addr2line" } | OutputLib,
        ar = { glob = "usr/bin/ar" } | OutputLib,
        as = { glob = "usr/bin/as" } | OutputLib,
        cpp_filt = { glob = "usr/bin/c++filt" } | OutputLib,
        elfedit = { glob = "usr/bin/elfedit" } | OutputLib,
        gprof = { glob = "usr/bin/gprof" } | OutputLib,
        ld = { glob = "usr/bin/ld" } | OutputLib,
        ld_bfd = { glob = "usr/bin/ld.bfd" } | OutputLib,
        nm = { glob = "usr/bin/nm" } | OutputLib,
        objcopy = { glob = "usr/bin/objcopy" } | OutputLib,
        objdump = { glob = "usr/bin/objdump" } | OutputLib,
        ranlib = { glob = "usr/bin/ranlib" } | OutputLib,
        readelf = { glob = "usr/bin/readelf" } | OutputLib,
        size = { glob = "usr/bin/size" } | OutputLib,
        strings = { glob = "usr/bin/strings" } | OutputLib,
        strip = { glob = "usr/bin/strip" } | OutputLib,
        
        libbfd = { glob = "usr/lib/libbfd.so*" } | OutputLib,
        libctf = { glob = "usr/lib/libctf.so*" } | OutputLib,
        libctf_nobfd = { glob = "usr/lib/libctf-nobfd.so*" } | OutputLib,
        libopcodes = { glob = "usr/lib/libopcodes.so*" } | OutputLib,
        libsframe = { glob = "usr/lib/libsframe.so*" } | OutputLib,
        
        headers = { glob = "usr/include/*.h" } | OutputLib,
        
        manpages = { glob = "usr/share/man/man*/*" } | OutputLib,
        info_docs = { glob = "usr/share/info/*" } | OutputLib,
        locale_data = { glob = "usr/share/locale/**/*.mo" } | OutputLib,
    },
} | BuildSpec

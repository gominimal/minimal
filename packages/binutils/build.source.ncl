let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let sed = import "../sed/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let binutils = import "build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
# let diffutils = import "../diffutils/build.ncl" in
# let expect = import "../expect/build.ncl" in
# let file = import "../file/build.ncl" in
# let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
# let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
# let perl = import "../perl/build.ncl" in
# let sed = import "../sed/build.ncl" in
# let tar = import "../tar/build.ncl" in
# let tcl = import "../tcl/build.ncl" in
# # let texinfo = import "../texinfo/build.ncl" in
# let xz = import "../xz/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
    name = "binutils",
    inputs = [
        {file = "binutils-2.45.tar.xz"} | Local,
        {file = "build.source.sh"} | Local,
        bash,
        coreutils,
        sed,
        glibc,
        gcc,
        binutils,
        linux_headers,
        grep,
        make,
        # diffutils,
        # expect,
        # file,
        # gawk,
        # grep,
        # gzip,
        # make,
        # perl,
        # sed,
        # tar,
        # tcl,
        # xz,
        zlib,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec

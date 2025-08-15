let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_gzip = import "../host_gzip/build.ncl" in
let host_sed = import "../host_sed/build.ncl" in
let host_tar = import "../host_tar/build.ncl" in
let host_make = import "../host_make/build.ncl" in
let host_grep = import "../host_grep/build.ncl" in
let host_gawk = import "../host_gawk/build.ncl" in
{
    name = "tcl",
    inputs = [
        host_bash,
        host_gzip,
        host_sed,
        host_tar,
        host_make,
        host_grep,
        host_gawk,
    ],
    cmd = "./build.sh",
    outputs = {
        tcl_bin = { glob = "bin/tclsh*" } | OutputLib,
        tcl_lib = { glob = "lib/libtcl*.so*" } | OutputLib,
        tcl_libdir = { glob = "lib/tcl*" } | OutputLib,
        tcl_headers = { glob = "include/tcl*.h" } | OutputLib,
        tcl_man = { glob = "share/man/man1/tclsh*.1" } | OutputLib,
        tcl_man3 = { glob = "share/man/man3/Tcl*.3" } | OutputLib,
    },
} | BuildSpec

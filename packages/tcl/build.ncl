let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make_static = import "../make_static/build.ncl" in
{
    name = "tcl",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "tcl8.6.16-src.tar.gz"} | Local,
        busybox_static,
        make_static,
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

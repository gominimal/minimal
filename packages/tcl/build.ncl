let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
{
    name = "tcl",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "tcl8.6.16-src.tar.gz"} | Local,
        busybox_static,
        make,
    ],
    cmd = "./build.sh",
    outputs = {
        tcl_bin = { glob = "usr/bin/tclsh*" } | OutputLib,
        tcl_lib = { glob = "usr/lib/libtcl*.so*" } | OutputLib,
        tcl_libdir = { glob = "usr/lib/tcl*" } | OutputLib,
        tcl_headers = { glob = "usr/include/tcl*.h" } | OutputLib,
        tcl_man = { glob = "usr/share/man/man1/tclsh*.1" } | OutputLib,
        tcl_man3 = { glob = "usr/share/man/man3/Tcl*.3" } | OutputLib,
    },
} | BuildSpec

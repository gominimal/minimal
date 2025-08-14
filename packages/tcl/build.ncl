let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "tcl",
    inputs = [
        {path = "/usr"} | HostPath,
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

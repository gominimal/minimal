let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "tcl",
    inputs = [
        {path = "/bin"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/make"} | HostPath,
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/usr/bin/gzip"} | HostPath,
        {path = "/usr/bin/sed"} | HostPath,
        {path = "/usr/bin/chmod"} | HostPath,
        {path = "/usr/bin/ln"} | HostPath,
        {path = "/usr/bin/awk"} | HostPath,
        {path = "/usr/bin/gawk"} | HostPath,
        {path = "/usr/bin/mv"} | HostPath,
    ],
    cmd = "build.sh",
    outputs = {
        tcl_bin = { glob = "bin/tclsh*" } | OutputLib,
        tcl_lib = { glob = "lib/libtcl*.so*" } | OutputLib,
        tcl_libdir = { glob = "lib/tcl*" } | OutputLib,
        tcl_headers = { glob = "include/tcl*.h" } | OutputLib,
        tcl_man = { glob = "share/man/man1/tclsh*.1" } | OutputLib,
        tcl_man3 = { glob = "share/man/man3/Tcl*.3" } | OutputLib,
    },
} | BuildSpec

let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let host_make = import "../host_make/build.ncl" in
{
    name = "grep",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "grep-3.12.tar.xz"} | Local,
        busybox_static,
        host_make,
    ],
    cmd = "./build.sh",
    outputs = {
        grep_bin = { glob = "bin/grep" } | OutputLib,
        egrep_bin = { glob = "bin/egrep" } | OutputLib,
        fgrep_bin = { glob = "bin/fgrep" } | OutputLib,
    },
} | BuildSpec

let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
{
    name = "grep",
    inputs = [
        {file = "build.source.sh"} | Local,
        {file = "grep-3.12.tar.xz"} | Local,
        busybox_static,
        make,
    ],
    cmd = "./build.source.sh",
    outputs = {
        grep_bin = { glob = "usr/bin/grep" } | OutputLib,
        egrep_bin = { glob = "usr/bin/egrep" } | OutputLib,
        fgrep_bin = { glob = "usr/bin/fgrep" } | OutputLib,
    },
} | BuildSpec

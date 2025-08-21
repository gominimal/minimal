let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "grep",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "prebuilt/usr/bin/grep"} | Local,
        {file = "prebuilt/usr/bin/egrep"} | Local,
        {file = "prebuilt/usr/bin/fgrep"} | Local,
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        grep_bin = { glob = "usr/bin/grep" } | OutputLib,
        egrep_bin = { glob = "usr/bin/egrep" } | OutputLib,
        fgrep_bin = { glob = "usr/bin/fgrep" } | OutputLib,
    },
} | BuildSpec

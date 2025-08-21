let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "sed",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "prebuilt/usr/bin/sed"} | Local,
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        sed_bin = { glob = "usr/bin/sed" } | OutputLib,
    },
} | BuildSpec

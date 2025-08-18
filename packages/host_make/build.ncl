let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "make",
    inputs = [
        {path = "/usr/bin/make"} | HostPath,
        {file = "build.sh"} | Local,
        busybox_static
    ],
    cmd = "./build.sh",
    outputs = {
        make = { glob = "usr/bin/make" } | OutputLib,
    },
} | BuildSpec

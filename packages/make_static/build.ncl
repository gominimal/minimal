let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "make_static",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "output/bin/make"} | Local,
        busybox_static
    ],
    cmd = "./build.sh",
    outputs = {
        make = { glob = "usr/bin/make" } | OutputLib,
    },
} | BuildSpec

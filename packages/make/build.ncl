let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "make",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "prebuilt/usr/bin/make"} | Local,
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        make = { glob = "usr/bin/make" } | OutputLib,
    },
} | BuildSpec

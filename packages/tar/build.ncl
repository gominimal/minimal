let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "tar",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "prebuilt/usr/bin/tar"} | Local,
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        tar = { glob = "usr/bin/tar" } | OutputLib,
    },
} | BuildSpec
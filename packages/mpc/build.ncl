let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "mpc",
    inputs = [
        {file = "build.sh"} | Local,
        # Header file
        {file = "prebuilt/usr/include/mpc.h"} | Local,
        # Library files
        {file = "prebuilt/usr/lib/libmpc.la"} | Local,
        {file = "prebuilt/usr/lib/libmpc.so"} | Local,
        {file = "prebuilt/usr/lib/libmpc.so.3"} | Local,
        {file = "prebuilt/usr/lib/libmpc.so.3.3.1"} | Local,
        # Info file
        {file = "prebuilt/usr/share/info/mpc.info"} | Local,
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        include = { glob = "usr/include/*.h" } | OutputLib,
        lib = { glob = "usr/lib/libmpc*.so*" } | OutputLib,
        lib_la = { glob = "usr/lib/*.la" } | OutputLib,
        info = { glob = "usr/share/info/*" } | OutputLib,
    },
} | BuildSpec

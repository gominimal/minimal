let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "zlib",
    inputs = [
        {file = "build.sh"} | Local,
        # Library files
        {file = "prebuilt/usr/lib/libz.so"} | Local,
        {file = "prebuilt/usr/lib/libz.so.1"} | Local,
        {file = "prebuilt/usr/lib/libz.so.1.3.1"} | Local,
        # Header files
        {file = "prebuilt/usr/include/zconf.h"} | Local,
        {file = "prebuilt/usr/include/zlib.h"} | Local,
        # pkg-config file
        {file = "prebuilt/usr/lib/pkgconfig/zlib.pc"} | Local,
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        libz = { glob = "usr/lib/libz.so*" } | OutputLib,
        zconf_h = { glob = "usr/include/zconf.h" } | OutputLib,
        zlib_h = { glob = "usr/include/zlib.h" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/zlib.pc" } | OutputLib,
    },
} | BuildSpec

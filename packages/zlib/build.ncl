let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
{
    name = "zlib",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "zlib-1.3.1.tar.gz"} | Local,
        busybox_static,
        make,
    ],
    cmd = "./build.sh",
    outputs = {
        libz = { glob = "usr/lib/libz.so*" } | OutputLib,
        libz_static = { glob = "usr/lib/libz.a" } | OutputLib,
        zconf_h = { glob = "usr/include/zconf.h" } | OutputLib,
        zlib_h = { glob = "usr/include/zlib.h" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/zlib.pc" } | OutputLib,
    },
} | BuildSpec

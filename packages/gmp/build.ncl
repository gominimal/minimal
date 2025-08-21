let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "gmp",
    inputs = [
        {file = "build.sh"} | Local,
        # Header files
        {file = "prebuilt/usr/include/gmp.h"} | Local,
        {file = "prebuilt/usr/include/gmpxx.h"} | Local,
        # Library files
        {file = "prebuilt/usr/lib/libgmp.la"} | Local,
        {file = "prebuilt/usr/lib/libgmp.so"} | Local,
        {file = "prebuilt/usr/lib/libgmp.so.10"} | Local,
        {file = "prebuilt/usr/lib/libgmp.so.10.5.0"} | Local,
        {file = "prebuilt/usr/lib/libgmpxx.la"} | Local,
        {file = "prebuilt/usr/lib/libgmpxx.so"} | Local,
        {file = "prebuilt/usr/lib/libgmpxx.so.4"} | Local,
        {file = "prebuilt/usr/lib/libgmpxx.so.4.7.0"} | Local,
        # pkg-config files
        {file = "prebuilt/usr/lib/pkgconfig/gmp.pc"} | Local,
        {file = "prebuilt/usr/lib/pkgconfig/gmpxx.pc"} | Local,
        # Info files
        {file = "prebuilt/usr/share/info/gmp.info"} | Local,
        {file = "prebuilt/usr/share/info/gmp.info-1"} | Local,
        {file = "prebuilt/usr/share/info/gmp.info-2"} | Local,
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        include = { glob = "usr/include/*.h" } | OutputLib,
        lib = { glob = "usr/lib/libgmp*.so*" } | OutputLib,
        lib_la = { glob = "usr/lib/*.la" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
        info = { glob = "usr/share/info/*" } | OutputLib,
    },
} | BuildSpec

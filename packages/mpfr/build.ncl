let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "mpfr",
    inputs = [
        {file = "build.sh"} | Local,
        # Header files
        {file = "prebuilt/usr/include/mpf2mpfr.h"} | Local,
        {file = "prebuilt/usr/include/mpfr.h"} | Local,
        # Library files
        {file = "prebuilt/usr/lib/libmpfr.la"} | Local,
        {file = "prebuilt/usr/lib/libmpfr.so"} | Local,
        {file = "prebuilt/usr/lib/libmpfr.so.6"} | Local,
        {file = "prebuilt/usr/lib/libmpfr.so.6.2.2"} | Local,
        # pkg-config file
        {file = "prebuilt/usr/lib/pkgconfig/mpfr.pc"} | Local,
        # Documentation files
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/AUTHORS"} | Local,
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/BUGS"} | Local,
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/COPYING"} | Local,
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/COPYING.LESSER"} | Local,
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/FAQ.html"} | Local,
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/NEWS"} | Local,
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/TODO"} | Local,
        # Example files
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/examples/ReadMe"} | Local,
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/examples/can_round.c"} | Local,
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/examples/divworst.c"} | Local,
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/examples/rndo-add.c"} | Local,
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/examples/sample.c"} | Local,
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/examples/threads.c"} | Local,
        {file = "prebuilt/usr/share/doc/mpfr-4.2.2/examples/version.c"} | Local,
        # Info file
        {file = "prebuilt/usr/share/info/mpfr.info"} | Local,
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        include = { glob = "usr/include/*.h" } | OutputLib,
        lib = { glob = "usr/lib/libmpfr*.so*" } | OutputLib,
        lib_la = { glob = "usr/lib/*.la" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
        doc = { glob = "usr/share/doc/mpfr-4.2.2/**/*" } | OutputLib,
        info = { glob = "usr/share/info/*" } | OutputLib,
    },
} | BuildSpec

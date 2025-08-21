let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "zstd",
    inputs = [
        {file = "build.sh"} | Local,
        # Binary files
        {file = "prebuilt/usr/bin/zstd"} | Local,
        {file = "prebuilt/usr/bin/zstdcat"} | Local,
        {file = "prebuilt/usr/bin/zstdgrep"} | Local,
        {file = "prebuilt/usr/bin/zstdless"} | Local,
        {file = "prebuilt/usr/bin/zstdmt"} | Local,
        {file = "prebuilt/usr/bin/unzstd"} | Local,
        # Library files
        {file = "prebuilt/usr/lib/libzstd.so"} | Local,
        {file = "prebuilt/usr/lib/libzstd.so.1"} | Local,
        {file = "prebuilt/usr/lib/libzstd.so.1.5.6"} | Local,
        {file = "prebuilt/usr/lib/libzstd.a"} | Local,
        # Header files
        {file = "prebuilt/usr/include/zdict.h"} | Local,
        {file = "prebuilt/usr/include/zstd.h"} | Local,
        {file = "prebuilt/usr/include/zstd_errors.h"} | Local,
        # pkg-config file
        {file = "prebuilt/usr/lib/pkgconfig/libzstd.pc"} | Local,
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        zstd_bin = { glob = "usr/bin/zstd" } | OutputLib,
        zstdcat = { glob = "usr/bin/zstdcat" } | OutputLib,
        zstdgrep = { glob = "usr/bin/zstdgrep" } | OutputLib,
        zstdless = { glob = "usr/bin/zstdless" } | OutputLib,
        zstdmt = { glob = "usr/bin/zstdmt" } | OutputLib,
        unzstd = { glob = "usr/bin/unzstd" } | OutputLib,
        libzstd = { glob = "usr/lib/libzstd.so*" } | OutputLib,
        libzstd_a = { glob = "usr/lib/libzstd.a" } | OutputLib,
        headers = { glob = "usr/include/*.h" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/libzstd.pc" } | OutputLib,
    },
} | BuildSpec

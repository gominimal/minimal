let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "gzip",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "prebuilt/usr/bin/gzip"} | Local,
        {file = "prebuilt/usr/bin/gunzip"} | Local,
        {file = "prebuilt/usr/bin/gzexe"} | Local,
        {file = "prebuilt/usr/bin/uncompress"} | Local,
        {file = "prebuilt/usr/bin/zcat"} | Local,
        {file = "prebuilt/usr/bin/zcmp"} | Local,
        {file = "prebuilt/usr/bin/zdiff"} | Local,
        {file = "prebuilt/usr/bin/zegrep"} | Local,
        {file = "prebuilt/usr/bin/zfgrep"} | Local,
        {file = "prebuilt/usr/bin/zforce"} | Local,
        {file = "prebuilt/usr/bin/zgrep"} | Local,
        {file = "prebuilt/usr/bin/zmore"} | Local,
        {file = "prebuilt/usr/bin/znew"} | Local,
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        binaries = { glob = "usr/bin/*" } | OutputLib,
    },
} | BuildSpec

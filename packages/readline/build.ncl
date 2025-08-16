let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make_static = import "../make_static/build.ncl" in
{
    name = "readline",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "readline-8.3.tar.gz"} | Local,
        busybox_static,
        make_static,
    ],
    cmd = "./build.sh",
    outputs = {
        readline_lib = { glob = "lib/libreadline.so*" } | OutputLib,
        history_lib = { glob = "lib/libhistory.so*" } | OutputLib,
        headers = { glob = "include/readline/*.h" } | OutputLib,
        pkgconfig = { glob = "lib/pkgconfig/*.pc" } | OutputLib,
    },
} | BuildSpec

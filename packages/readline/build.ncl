let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_coreutils = import "../host_coreutils/build.ncl" in
let host_gawk = import "../host_gawk/build.ncl" in
let host_grep = import "../host_grep/build.ncl" in
{
    name = "readline",
    inputs = [
        host_bash,
        host_coreutils,
        host_gawk,
        host_grep,
    ],
    cmd = "./build.sh",
    outputs = {
        readline_lib = { glob = "lib/libreadline.so*" } | OutputLib,
        history_lib = { glob = "lib/libhistory.so*" } | OutputLib,
        headers = { glob = "include/readline/*.h" } | OutputLib,
        pkgconfig = { glob = "lib/pkgconfig/*.pc" } | OutputLib,
    },
} | BuildSpec

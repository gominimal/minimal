let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_coreutils = import "../host_coreutils/build.ncl" in
let host_gawk = import "../host_gawk/build.ncl" in
let host_grep = import "../host_grep/build.ncl" in
let host_gzip = import "../host_gzip/build.ncl" in 
let host_make = import "../host_make/build.ncl" in
let host_sed = import "../host_sed/build.ncl" in
let host_tar = import "../host_tar/build.ncl" in
{
    name = "readline",
    inputs = [
        host_bash,
        host_coreutils,
        host_gawk,
        host_grep,
        host_gzip,
        host_make,
        host_sed,
        host_tar,
    ],
    cmd = "./build.sh",
    outputs = {
        readline_lib = { glob = "lib/libreadline.so*" } | OutputLib,
        history_lib = { glob = "lib/libhistory.so*" } | OutputLib,
        headers = { glob = "include/readline/*.h" } | OutputLib,
        pkgconfig = { glob = "lib/pkgconfig/*.pc" } | OutputLib,
    },
} | BuildSpec

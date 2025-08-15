let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_gzip = import "../host_gzip/build.ncl" in
let host_make = import "../host_make/build.ncl" in
let host_tar = import "../host_tar/build.ncl" in
let host_grep = import "../host_grep/build.ncl" in
let host_sed = import "../host_sed/build.ncl" in
{
    name = "zstd",
    inputs = [
        host_bash,
        host_gzip,
        host_make,
        host_tar,
        host_grep,
        host_sed,
    ],
    cmd = "./build.sh",
    outputs = {
        zstd_bin = { glob = "bin/zstd" } | OutputLib,
        zstdcat = { glob = "bin/zstdcat" } | OutputLib,
        zstdgrep = { glob = "bin/zstdgrep" } | OutputLib,
        zstdless = { glob = "bin/zstdless" } | OutputLib,
        zstdmt = { glob = "bin/zstdmt" } | OutputLib,
        unzstd = { glob = "bin/unzstd" } | OutputLib,
        libzstd = { glob = "lib/libzstd.so*" } | OutputLib,
        headers = { glob = "include/*.h" } | OutputLib,
    },
} | BuildSpec

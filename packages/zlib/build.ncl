let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_coreutils = import "../host_coreutils/build.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_gzip = import "../host_gzip/build.ncl" in
let host_make = import "../host_make/build.ncl" in
let host_sed = import "../host_sed/build.ncl" in
let host_tar = import "../host_tar/build.ncl" in
{
    name = "zlib",
    inputs = [
        host_coreutils,
        host_bash,
        host_gzip,
        host_make,
        host_sed,
        host_tar,
    ],
    cmd = "./build.sh",
    outputs = {
        libz = { glob = "lib/libz.so*" } | OutputLib,
        libz_static = { glob = "lib/libz.a" } | OutputLib,
        headers = { glob = "include/*.h" } | OutputLib,
        pkgconfig = { glob = "lib/pkgconfig/zlib.pc" } | OutputLib,
    },
} | BuildSpec

let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let bzip2 = import "../bzip2/build.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_coreutils = import "../host_coreutils/build.ncl" in
let host_gawk = import "../host_gawk/build.ncl" in
let host_grep = import "../host_grep/build.ncl" in
let host_gzip = import "../host_gzip/build.ncl" in
let host_make = import "../host_make/build.ncl" in
let host_sed = import "../host_sed/build.ncl" in
let host_tar = import "../host_tar/build.ncl" in
{
    name = "file",
    inputs = [
        bzip2,
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
        file_bin = { glob = "bin/file" } | OutputLib,
        libmagic = { glob = "lib/libmagic.so*" } | OutputLib,
        headers = { glob = "include/magic.h" } | OutputLib,
        magic_data = { glob = "share/misc/magic*" } | OutputLib,
    },
} | BuildSpec

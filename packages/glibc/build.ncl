let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let bison = import "../bison/build.ncl" in
let host_bash = import "../host_bash/build.ncl" in 
let host_gzip = import "../host_gzip/build.ncl" in
let host_patch = import "../host_patch/build.ncl" in
let host_python = import "../host_python/build.ncl" in
let host_python = import "../host_python/build.ncl" in 
let host_tar = import "../host_tar/build.ncl" in
let xz = import "../xz/build.ncl" in 
{
    name = "glibc",
    inputs = [
        bison,
        host_bash,
        host_gzip,
        host_patch,
        host_python,
        host_tar,
        xz,
    ],
    cmd = "./build.sh",
    outputs = {
        lib = { glob = "lib/*" } | OutputLib,
        libexec = { glob = "libexec/*" } | OutputLib,
        include = { glob = "include/*" } | OutputLib,
    },
} | BuildSpec

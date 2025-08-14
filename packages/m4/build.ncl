let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_tar = import "../host_tar/build.ncl" in
let host_sed = import "../host_sed/build.ncl" in
let xz = import "../host_xz/build.ncl" in
{
    name = "m4",
    inputs = [
        host_bash,
        host_tar,
        host_sed,
        xz,
    ],
    cmd = "./build.sh",
    outputs = {
        m4_bin = { glob = "bin/m4" } | OutputLib,
        m4_man = { glob = "share/man/man1/m4.1" } | OutputLib,
        m4_info = { glob = "share/info/m4.info*" } | OutputLib,
    },
} | BuildSpec

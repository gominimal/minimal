let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let acl = import "../make/build.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
let texinfo = import "../texinfo/build.ncl" in
{
    name = "tar",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "tar-1.35.tar.xz"} | Local,
        acl,
        busybox_static,
        make,
        perl,
        texinfo,
    ],
    cmd = "./build.sh",
    outputs = {
        tar = { glob = "bin/tar" } | OutputLib,
        info = { glob = "share/info/tar.info*" } | OutputLib,
    },
} | BuildSpec

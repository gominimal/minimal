let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
let readline = import "../readline/build.ncl" in
{
    name = "bash",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "bash-5.3.tar.gz"} | Local,
        busybox_static,
        make,
        readline,
    ],
    cmd = "./build.sh",
    outputs = {
        bash = { glob = "bin/bash" } | OutputLib,
        sh = { glob = "bin/sh" } | OutputLib,
        bashbug = { glob = "bin/bashbug" } | OutputLib,
        docs = { glob = "share/doc/bash-5.3/*" } | OutputLib,
        man = { glob = "share/man/man1/*.1" } | OutputLib,
    },
} | BuildSpec
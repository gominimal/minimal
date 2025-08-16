let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make_static = import "../make_static/build.ncl" in 
{
    name = "bc",
    inputs = [
        {file = "bc-7.0.3.tar.xz"} | Local,
        {file = "build.sh"} | Local,
        busybox_static,
        make_static,
    ],
    cmd = "./build.sh",
    outputs = {
        bc_bin = { glob = "bin/bc" },
        dc_bin = { glob = "bin/dc" },
        bc_man = { glob = "share/man/man1/bc.1" },
        dc_man = { glob = "share/man/man1/dc.1" },
    },
} | BuildSpec

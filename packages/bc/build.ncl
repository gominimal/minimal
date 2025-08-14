let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let readline = import "../readline/build.ncl" in 
{
    name = "bc",
    inputs = [
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/make"} | HostPath,
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/usr/bin/xz"} | HostPath,
        {path = "/usr/bin/awk"} | HostPath,
        {path = "/usr/bin/gawk"} | HostPath,
        readline,
    ],
    cmd = "./build.sh",
    outputs = {
        bc_bin = { glob = "bin/bc" },
        dc_bin = { glob = "bin/dc" },
        bc_man = { glob = "share/man/man1/bc.1" },
        dc_man = { glob = "share/man/man1/dc.1" },
    },
} | BuildSpec

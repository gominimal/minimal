let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in 
let host_findutils = import "../host_findutils/build.ncl" in 
let readline = import "../readline/build.ncl" in 
{
    name = "bc",
    inputs = [
        host_bash,
        host_findutils,
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

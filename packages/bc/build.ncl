let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let findutils = import "../findutils/build.ncl" in 
let gawk = import "../gawk/build.ncl" in 
let grep = import "../grep/build.ncl" in 
let make = import "../make/build.ncl" in 
let readline = import "../readline/build.ncl" in
let sed = import "../sed/build.ncl" in 
let tar = import "../tar/build.ncl" in 
let toolchain = import "../toolchain/build.ncl" in
let xz = import "../xz/build.ncl" in 
{
    name = "bc",
    inputs = [
        {
            url = "gs://minimal-staging-archives/bc-7.0.3.tar.xz",
            sha256 = "91eb74caed0ee6655b669711a4f350c25579778694df248e28363318e03c7fc4"
        } | Source,
        {file = "build.sh"} | Local,
        bash,
        coreutils,
        diffutils,
        findutils,
        gawk,
        grep,
        make,
        readline,
        sed,
        tar,
        toolchain,
        xz,
    ],
    cmd = "./build.sh",
    outputs = {
        bc_bin = { glob = "usr/bin/bc" },
        dc_bin = { glob = "usr/bin/dc" },
        bc_man = { glob = "usr/share/man/man1/bc.1" },
        dc_man = { glob = "usr/share/man/man1/dc.1" },
    },
} | BuildSpec

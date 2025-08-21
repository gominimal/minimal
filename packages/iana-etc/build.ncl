let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let tar = import "../tar/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let coreutils  = import "../coreutils/build.ncl" in
{
    name = "iana-etc",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "iana-etc-20250618.tar.gz"} | Local,
        bash,
        glibc,
        tar,
        gzip,
        coreutils,
    ],
    cmd = "./build.sh",
    outputs = {
        protocols = { glob = "etc/protocols" } | OutputLib,
        services = { glob = "etc/services" } | OutputLib,
    },
} | BuildSpec

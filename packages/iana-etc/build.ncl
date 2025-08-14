let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
{
    name = "iana-etc",
    inputs = [
        host_bash,
    ],
    cmd = "./build.sh",
    outputs = {
        protocols = { glob = "etc/protocols" } | OutputLib,
        services = { glob = "etc/services" } | OutputLib,
    },
} | BuildSpec

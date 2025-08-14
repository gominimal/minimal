let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "iana-etc",
    inputs = [
        {path = "/usr"} | HostPath,
    ],
    cmd = "./build.sh",
    outputs = {
        protocols = { glob = "etc/protocols" } | OutputLib,
        services = { glob = "etc/services" } | OutputLib,
    },
} | BuildSpec

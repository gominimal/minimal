let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "iana-etc",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "iana-etc-20250618.tar.gz"} | Local,
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        protocols = { glob = "etc/protocols" } | OutputLib,
        services = { glob = "etc/services" } | OutputLib,
    },
} | BuildSpec

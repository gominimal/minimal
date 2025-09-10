let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let base = import "../base/build.ncl" in
{
    name = "ca-certificates",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/ssl-certs-complete.tar.gz",
            sha256 = "5e4ce79f2e24206f0aeedce802d8a654da2db7c70a76f841cfd1699d00e5f2c1"
        } | Source,
        base,
    ],
    cmd = "./build.sh",
    outputs = {
        certs = { glob = "etc/ssl/certs/*" } | OutputLib,
    },
} | BuildSpec

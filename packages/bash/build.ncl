let {BuildSpec, HostPath, OutputLib, Local, Prebuilt, ..} = import "minimal.ncl" in
{
    name = "bash",
    inputs = [
        {package = "bash"} | Prebuilt,
    ],
    cmd = "",
    outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
    },
} | BuildSpec

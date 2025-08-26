let {BuildSpec, HostPath, OutputLib, Local, Source, Prebuilt, ..} = import "minimal.ncl" in
{
    name = "coreutils",
    inputs = [
        {package = "bash"} | Prebuilt,
    ],
    cmd = "",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_libexec = { glob = "usr/libexec/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec

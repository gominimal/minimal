let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "readline",
    inputs = [
        {path = "/usr"} | HostPath,
    ],
    cmd = "./build.sh",
    outputs = {
        readline_lib = { glob = "lib/libreadline.so*" } | OutputLib,
        history_lib = { glob = "lib/libhistory.so*" } | OutputLib,
        headers = { glob = "include/readline/*.h" } | OutputLib,
        pkgconfig = { glob = "lib/pkgconfig/*.pc" } | OutputLib,
    },
} | BuildSpec

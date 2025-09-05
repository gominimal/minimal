let {BuildSpec, HostPath, OutputLib, Local, Prebuilt, ..} = import "minimal.ncl" in
let pcre2 = import "../pcre2/build.ncl" in
{
    name = "grep",
    inputs = [
        {package = "grep"} | Prebuilt,
    ],
    runtime_deps = [
        pcre2,
    ],
    cmd = "",
    outputs = {
        grep_bin = { glob = "usr/bin/grep" } | OutputLib,
        egrep_bin = { glob = "usr/bin/egrep" } | OutputLib,
        fgrep_bin = { glob = "usr/bin/fgrep" } | OutputLib,
    },
} | BuildSpec

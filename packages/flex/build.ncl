let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "flex",
    inputs = [
        {path = "/bin"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/make"} | HostPath,
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/usr/bin/gzip"} | HostPath,
        {path = "/usr/bin/awk"} | HostPath,
        {path = "/usr/bin/gawk"} | HostPath,
        {path = "/usr/bin/file"} | HostPath,
        {path = "/lib/cpp"} | HostPath,
        {path = "/usr/bin/cpp"} | HostPath,
        {path = "/usr/lib"} | HostPath,
        {path = "/lib"} | HostPath,
    ],
    cmd = "build.sh",
    outputs = {
        flex_bin = { glob = "bin/flex" } | OutputLib,
        flex_pp = { glob = "bin/flex++" } | OutputLib,
        lex_link = { glob = "bin/lex" } | OutputLib,
        flex_lib = { glob = "lib/libfl.so*" } | OutputLib,
        flex_man = { glob = "share/man/man1/flex.1" } | OutputLib,
        lex_man = { glob = "share/man/man1/lex.1" } | OutputLib,
        flex_includes = { glob = "include/FlexLexer.h" } | OutputLib,
    },
} | BuildSpec

let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "bison",
    inputs = [
        {path = "/bin"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/make"} | HostPath,
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/usr/bin/xz"} | HostPath,
        {path = "/usr/bin/unxz"} | HostPath,
        {path = "/usr/bin/sed"} | HostPath,
        {path = "/usr/bin/install"} | HostPath,
        {path = "/usr/bin/m4"} | HostPath,
    ],
    cmd = "build.sh",
    outputs = {
        bison_bin = { glob = "bin/bison" } | OutputLib,
        yacc_bin = { glob = "bin/yacc" } | OutputLib,
        liby = { glob = "lib/liby.a" } | OutputLib,
        bison_share = { glob = "share/bison/**/*" } | OutputLib,
        bison_man = { glob = "share/man/man1/bison.1" } | OutputLib,
        yacc_man = { glob = "share/man/man1/yacc.1" } | OutputLib,
        bison_info = { glob = "share/info/bison.info*" } | OutputLib,
        bison_locale = { glob = "share/locale/*/LC_MESSAGES/bison.mo" } | OutputLib,
        bison_aclocal = { glob = "share/aclocal/bison*.m4" } | OutputLib,
    },
} | BuildSpec

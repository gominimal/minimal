let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let m4 = import "../m4/build.ncl" in
let make_static = import "../make_static/build.ncl" in
{
    name = "bison",
    inputs = [  
        {file = "bison-3.8.2.tar.xz"} | Local,
        {file = "build.sh"} | Local,
        busybox_static,
        m4,
        make_static,
     ],
    cmd = "./build.sh",
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

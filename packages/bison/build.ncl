let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let m4 = import "../m4/build.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let texinfo = import "../texinfo/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "bison",
    inputs = [  
        {file = "bison-3.8.2.tar.xz"} | Local,
        {file = "build.sh"} | Local,
        bash,
        coreutils,
        diffutils,
        gawk,
        grep,
        m4,
        make,
        perl,
        sed,
        tar,
        texinfo,
        xz,
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

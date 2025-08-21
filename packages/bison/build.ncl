let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let m4 = import "../m4/build.ncl" in
let make = import "../make/build.ncl" in
#let perl = import "../perl/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
# let texinfo = import "../texinfo/build.ncl" in
let xz = import "../xz/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
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
#        perl,
        sed,
        tar,
        # texinfo,
        xz,
        glibc,
        gcc,
        binutils,
        linux_headers,
     ],
    cmd = "./build.sh",
    outputs = {
        bison_bin = { glob = "usr/bin/bison" } | OutputLib,
        yacc_bin = { glob = "usr/bin/yacc" } | OutputLib,
        liby = { glob = "usr/lib/liby.a" } | OutputLib,
        bison_share = { glob = "usr/share/bison/**/*" } | OutputLib,
        bison_man = { glob = "usr/share/man/man1/bison.1" } | OutputLib,
        yacc_man = { glob = "usr/share/man/man1/yacc.1" } | OutputLib,
        bison_info = { glob = "usr/share/info/bison.info*" } | OutputLib,
        bison_locale = { glob = "usr/share/locale/*/LC_MESSAGES/bison.mo" } | OutputLib,
        bison_aclocal = { glob = "usr/share/aclocal/bison*.m4" } | OutputLib,
    },
} | BuildSpec

let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let binutils = import "../binutils/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
let sed = import "../sed/build.ncl" in
let grep = import "../grep/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "texinfo",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "texinfo-7.2.tar.xz"} | Local,
        binutils,
        bash,
        coreutils,
        gawk,
        gcc,
        glibc,
        grep,
        linux_headers,
        make,
        perl,
        sed,
        tar,
        xz,
    ],
    cmd = "./build.sh",
    outputs = {
        install_info = { glob = "usr/bin/install-info" } | OutputLib,
        makeinfo = { glob = "usr/bin/makeinfo" } | OutputLib,
        pdftexi2dvi = { glob = "usr/bin/pdftexi2dvi" } | OutputLib,
        pod2texi = { glob = "usr/bin/pod2texi" } | OutputLib,
        texi2any = { glob = "usr/bin/texi2any" } | OutputLib,
        texi2dvi = { glob = "usr/bin/texi2dvi" } | OutputLib,
        texi2pdf = { glob = "usr/bin/texi2pdf" } | OutputLib,
        texindex = { glob = "usr/bin/texindex" } | OutputLib,
        texinfo_data = { glob = "usr/share/texinfo/*" } | OutputLib,
        texi2any_js = { glob = "usr/share/texi2any/**/*" } | OutputLib,
        locale_data = { glob = "usr/share/locale/**/*.mo" } | OutputLib,
        manpages = { glob = "usr/share/man/man*/*" } | OutputLib,
        info_docs = { glob = "usr/share/info/*" } | OutputLib,
    },
} | BuildSpec

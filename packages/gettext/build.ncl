let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let acl = import "../acl/build.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let findutils = import "../findutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "gettext",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/gettext-0.26.tar.xz",
            sha256 = "d1fb86e260cfe7da6031f94d2e44c0da55903dbae0a2fa0fae78c91ae1b56f00"
        } | Source,
        acl,
        bash,
        binutils, 
        coreutils,
        diffutils,
        findutils,
        gawk,
        gcc,
        glibc,
        grep,
        linux_headers,
        make,
        ncurses,
        sed,
        tar,
        xz,
    ],
    cmd = "./build.sh",
    outputs = {
        bin = { glob = "usr/bin/*" } | OutputLib,
        lib = { glob = "usr/lib/*" } | OutputLib,
        libexec = { glob = "usr/libexec/gettext*" } | OutputLib,
        include = { glob = "usr/include/**/*" } | OutputLib,
        man = { glob = "usr/share/man/**/*" } | OutputLib,
        info = { glob = "usr/share/info/*" } | OutputLib,
        locale = { glob = "usr/share/locale/**/*" } | OutputLib,
        gettext = { glob = "usr/share/gettext/**/*" } | OutputLib,
        aclocal = { glob = "usr/share/aclocal/*" } | OutputLib,
    },
} | BuildSpec

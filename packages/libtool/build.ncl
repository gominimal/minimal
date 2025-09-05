let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let findutils = import "../findutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let m4 = import "../m4/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "libtool",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/libtool-2.5.4.tar.xz",
            sha256 = "f81f5860666b0bc7d84baddefa60d1cb9fa6fceb2398cc3baca6afaa60266675"
        } | Source,
        bash,
        coreutils,
        diffutils,
        findutils,
        gawk,
        grep,
        m4,
        make,
        sed,
        tar,
        toolchain,
        xz,
    ],
    cmd = "./build.sh",
    outputs = {
        bin = { glob = "usr/bin/*" } | OutputLib,
        lib = { glob = "usr/lib/*" } | OutputLib,
        include = { glob = "usr/include/**/*" } | OutputLib,
        share = { glob = "usr/share/libtool/**/*" } | OutputLib,
        aclocal = { glob = "usr/share/aclocal/*.m4" } | OutputLib,
        man = { glob = "usr/share/man/**/*" } | OutputLib,
    },
} | BuildSpec
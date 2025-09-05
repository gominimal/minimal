let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let findutils = import "../findutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let libxcrypt = import "../libxcrypt/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "shadow",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/shadow-4.18.0.tar.xz",
            sha256 = "add4604d3bc410344433122a819ee4154b79dd8316a56298c60417e637c07608"
        } | Source,
        bash,
        coreutils,
        diffutils,
        findutils,
        gawk,
        grep,
        libxcrypt,
        make,
        sed,
        tar,
        toolchain,
        xz,
    ],
    cmd = "./build.sh",
    outputs = {
        bin = { glob = "usr/bin/*" } | OutputLib,
        sbin = { glob = "usr/sbin/*" } | OutputLib,
        lib = { glob = "usr/lib/*" } | OutputLib,
        include = { glob = "usr/include/**/*" } | OutputLib,
        etc = { glob = "etc/**/*" } | OutputLib,
        locale = { glob = "usr/share/locale/**/*" } | OutputLib,
    },
} | BuildSpec

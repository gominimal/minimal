let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "libxcrypt",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/libxcrypt-4.4.38.tar.xz",
            sha256 = "80304b9c306ea799327f01d9a7549bdb28317789182631f1b54f4511b4206dd6"
        } | Source,
        bash,
        coreutils,
        diffutils,
        gawk,
        grep,
        make,
        perl,
        sed,
        tar,
        toolchain,
        xz,
    ],
    cmd = "./build.sh",
    outputs = {
        lib = { glob = "usr/lib/*" } | OutputLib,
        include = { glob = "usr/include/**/*" } | OutputLib,
        man = { glob = "usr/share/man/**/*" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/*" } | OutputLib,
    },
} | BuildSpec

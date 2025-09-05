let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let attr = import "../attr/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let bash = import "../bash/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
{
    name = "patch",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/patch-2.8.tar.xz",
            sha256 = "f87cee69eec2b4fcbf60a396b030ad6aa3415f192aa5f7ee84cad5e11f7f5ae3"
        } | Source,
        attr,
        bash,
        coreutils,
        gawk,
        grep,
        make,
        sed,
        tar,
        xz,
        glibc,
        gcc,
        binutils,
        linux_headers,
    ],
    cmd = "./build.sh",
    outputs = {
        patch = { glob = "usr/bin/patch" } | OutputLib,
        man = { glob = "usr/share/man/man1/patch.1" } | OutputLib,
    },
} | BuildSpec

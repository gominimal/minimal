let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let acl = import "../acl/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "sed",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/sed-4.9.tar.xz",
            sha256 = "6e226b732e1cd739464ad6862bd1a1aba42d7982922da7a53519631d24975181"
        } | Source,
        acl,
        binutils,
        bash,
        coreutils,
        gawk,
        gcc,
        grep,
        linux_headers,
        make,
        sed,
        tar,
        xz,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec

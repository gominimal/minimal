let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
# TODO depend on attr once runtime deps are functional
# otherwise every usage of patch requires importing attr
# let attr = import "../attr/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "patch",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "patch-2.8.tar.xz"} | Local,
        coreutils,
        bash,
        gawk,
        grep,
        make,
        sed,
        tar,
        xz,
    ],
    cmd = "./build.sh",
    outputs = {
        patch = { glob = "usr/bin/patch" } | OutputLib,
        man = { glob = "usr/share/man/man1/patch.1" } | OutputLib,
    },
} | BuildSpec

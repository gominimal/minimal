let {BuildSpec, HostPath, OutputLib, Local, Source, Prebuilt, ..} = import "minimal.ncl" in
let attr = import "../attr/build.ncl" in
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
    name = "acl",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/acl-2.3.2.tar.xz",
            sha256 = "97203a72cae99ab89a067fe2210c1cbf052bc492b479eca7d226d9830883b0bd"
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
    runtime_deps = [
        attr,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec

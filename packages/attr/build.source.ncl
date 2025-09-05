let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
    name = "attr",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/attr-2.5.2.tar.gz",
            sha256 = "39bf67452fa41d0948c2197601053f48b3d78a029389734332a6309a680c6c87"
        } | Source,
        bash,
        coreutils,
        diffutils,
        gawk,
        grep,
        gzip,
        make,
        perl,
        sed,
        tar,
        toolchain,
    ],
    cmd = "./build.source.sh",
    outputs = {
        etc = { glob = "etc/**/*" } | OutputLib,
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec

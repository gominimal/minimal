let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "../binutils/build.ncl" in
# let bison = import "../bison/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
# let file = import "../file/build.ncl" in
# let findutils = import "../diffutils/build.ncl" in
# let flex = import "../flex/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
# let perl = import "../perl/build.ncl" in
# let python = import "../python/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
# let zlib = import "../zlib/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "gcc",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/gcc-15.2.0.tar.xz", 
            sha256 = "438fd996826b0c82485a29da03a72d71d6e3541a83ec702df4271f6fe025d24e"
        } | Source,
        bash,
        binutils,
        coreutils,
        diffutils,
        # file,
        # findutils,
        gawk,
        gcc,
        glibc,
        gmp,
        grep,
        linux_headers,
        make,
        mpc,
        mpfr,
        # perl,
        # python,
        sed,
        tar,
        xz,
        zstd,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
    },
} | BuildSpec

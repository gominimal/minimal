let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let file = import "../file/build.ncl" in
let findutils = import "../findutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let perl = import "../perl/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "gcc",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/gcc-15.2.0.tar.xz", 
            sha256 = "438fd996826b0c82485a29da03a72d71d6e3541a83ec702df4271f6fe025d24e"
        } | Source,
        # {
        #     url = "gs://minimal-staging-archives/gcc-14.3.0.tar.xz", 
        #     sha256 = "e0dc77297625631ac8e50fa92fffefe899a4eb702592da5c32ef04e2293aca3a"
        # } | Source,
        bash,
        binutils,
        coreutils,
        diffutils,
        file,
        findutils,
        gawk,
        gcc,
        glibc,
        gmp,
        grep,
        linux_headers,
        make,
        mpc,
        mpfr,
        perl,
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

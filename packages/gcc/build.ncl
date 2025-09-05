let {BuildSpec, HostPath, OutputLib, Local, Prebuilt, ..} = import "minimal.ncl" in
let gmp = import "../gmp/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let zlib = import "../zlib/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "gcc",
    inputs = [
        {package = "gcc"} | Prebuilt,
    ],
    runtime_deps = [
        gmp,
        mpc,
        mpfr,
        zlib,
        zstd,
    ],
    cmd = "",
    outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
    },
} | BuildSpec

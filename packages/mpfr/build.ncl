let { BuildSpec, Local, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
# base
let bash = import "../bash/build.ncl" in
let bzip2 = import "../bzip2/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let file = import "../file/build.ncl" in
let findutils = import "../findutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
# toolchain
let binutils = import "../binutils/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
# other
let m4 = import "../m4/build.ncl" in
let gmp = import "../gmp/build.ncl" in
{
  name = "mpfr",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/mpfr-4.2.2.tar.xz",
      sha256 = "b67ba0383ef7e8a8563734e2e889ef5ec3c3b898a01d00fa0a6869ad81c6ce01"
    } | Source,
    # base
    bash,
    bzip2,
    coreutils,
    diffutils,
    file,
    findutils,
    gawk,
    grep,
    gzip,
    make,
    perl,
    sed,
    tar,
    xz,
    # toolchain
    binutils,
    gcc,
    glibc,
    linux_headers,
    # other
    m4,
  ],
  runtime_deps = [
    glibc,
    gmp,
  ],

  cmd = "./build.sh",
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },
  replace_on_cycle =
    {
      name = "mpfr (prebuilt)",
      inputs = [
        { package = "mpfr" } | Prebuilt,
      ],
      cmd = "",
      outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
      },
    } | BuildSpec,
} | BuildSpec

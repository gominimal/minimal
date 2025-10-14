let { BuildSpec, Local, OutputBin, OutputData, Prebuilt, Source, .. } = import "minimal.ncl" in
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
let pcre2 = import "../pcre2/build.ncl" in
{
  name = "grep",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/grep-3.12.tar.xz",
      sha256 = "2649b27c0e90e632eadcd757be06c6e9a4f48d941de51e7c0f83ff76408a07b9"
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
    linux_headers,
    # other
  ],
  runtime_deps = [
    pcre2,
    glibc,
  ],

  cmd = "./build.sh",
  outputs = {
    grep_bin = { glob = "usr/bin/grep" } | OutputBin,
    egrep_bin = { glob = "usr/bin/egrep" } | OutputBin,
    fgrep_bin = { glob = "usr/bin/fgrep" } | OutputBin,

    locales = { glob = "usr/share/locale/**" } | OutputData,
  },
  replace_on_cycle =
    {
      name = "grep (prebuilt)",
      inputs = [
        { package = "grep" } | Prebuilt,
      ],
      runtime_deps = [
        pcre2,
      ],
      cmd = "",
      outputs = {
        grep_bin = { glob = "usr/bin/grep" } | OutputBin,
        egrep_bin = { glob = "usr/bin/egrep" } | OutputBin,
        fgrep_bin = { glob = "usr/bin/fgrep" } | OutputBin,
      },
    } | BuildSpec,
} | BuildSpec

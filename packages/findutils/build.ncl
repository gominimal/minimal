let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let bash = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../bash/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let make = import "../make/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
{
  name = "findutils",
  inputs = [
    {
      url = "gs://minimal-staging-archives/findutils-4.10.0.tar.xz",
      sha256 = "1387e0b67ff247d2abde998f90dfbf70c1491391a59ddfecb8ae698789f0a4f5"
    } | Source,
    { file = "build.sh" } | Local,
    bash,
    binutils,
    coreutils,
    diffutils,
    gawk,
    gcc,
    glibc,
    grep,
    make,
    linux_headers,
    sed,
    tar,
  ],
  cmd = "./build.sh",
  runtime_deps = [
    glibc,
  ],
  outputs = {
    find = { glob = "usr/bin/find" } | OutputBin,
    locate = { glob = "usr/bin/locate" } | OutputBin,
    updatedb = { glob = "usr/bin/updatedb" } | OutputBin,
    xargs = { glob = "usr/bin/xargs" } | OutputBin,

    libexec_frcode = { glob = "usr/libexec/frcode" } | OutputLib,

    mans = { glob = "usr/share/man/**" } | OutputData,
    infos = { glob = "usr/share/info/*.info" } | OutputData,
    locales = { glob = "usr/share/locale/**" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "findutils (prebuilt)",
      inputs = [
        { package = "findutils" } | Prebuilt,
      ],
      cmd = "",
      outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
      },
    } | BuildSpec,
} | BuildSpec

let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let bash = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let findutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../bash/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let make = import "../make/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let sed = import "../sed/build.ncl" in
{
  name = "attr",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/attr-2.5.2.tar.gz",
      sha256 = "39bf67452fa41d0948c2197601053f48b3d78a029389734332a6309a680c6c87",
      extract = true,
      strip_prefix = "attr-2.5.2",
    } | Source,
    bash,
    binutils,
    coreutils,
    findutils,
    gawk,
    gcc,
    glibc,
    grep,
    make,
    linux_headers,
    sed,
  ],
  runtime_deps = [
    glibc,
  ],

  cmd = "./build.sh",
  outputs = {
    bins = { glob = "usr/bin/*" } | OutputBin,
    libs = { glob = "usr/lib/*.{a,so*}" } | OutputLib,

    ltconfigs = { glob = "usr/lib/libattr.la" } | OutputData,
    pkgconfigs = { glob = "usr/lib/pkgconfig/**" } | OutputData,

    etcs = { glob = "etc/*" } | OutputData,
    mans = { glob = "usr/share/man/**" } | OutputData,
    includes = { glob = "usr/include/**" } | OutputData,
    locales = { glob = "usr/share/locale/**" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "attr (prebuilt)",
      inputs = [
        { package = "attr" } | Prebuilt,
      ],
      cmd = "",
      outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
      },
    } | BuildSpec,
} | BuildSpec

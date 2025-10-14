let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let attr = import "../attr/build.ncl" in
let bash = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../bash/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let make = import "../make/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let sed = import "../sed/build.ncl" in
{
  name = "acl",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/acl-2.3.2.tar.xz",
      sha256 = "97203a72cae99ab89a067fe2210c1cbf052bc492b479eca7d226d9830883b0bd",
      extract = true,
      strip_prefix = "acl-2.3.2",
    } | Source,
    bash,
    binutils,
    coreutils,
    gawk,
    gcc,
    grep,
    make,
    linux_headers,
    sed,
  ],
  runtime_deps = [
    attr,
    glibc,
  ],
  cmd = "./build.sh",
  outputs = {
    bins = { glob = "usr/bin/*" } | OutputBin,
    libs = { glob = "usr/lib/*.{a,so*}" } | OutputLib,

    ltconfigs = { glob = "usr/lib/libacl.la" } | OutputData,
    pkgconfigs = { glob = "usr/lib/pkgconfig/**" } | OutputData,

    mans = { glob = "usr/share/man/**" } | OutputData,
    includes = { glob = "usr/include/**" } | OutputData,
    locales = { glob = "usr/share/locale/**" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "acl (prebuilt)",
      inputs = [
        { package = "acl", sha256 = "42491a1408cedbb0716b278c3cd88bb788b00de547fc2d6cb583ed94f9495edb" } | Prebuilt,
      ],
      cmd = "",
      outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
      },
    } | BuildSpec,
} | BuildSpec

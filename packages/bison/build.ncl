let { BuildSpec, Local, OutputBin, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in

let base = import "../base/build.ncl" in
let flex = import "../flex/build.ncl" in
let m4 = import "../m4/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "bison",
  inputs = [
    {
      url = "gs://minimal-staging-archives/bison-3.8.2.tar.xz",
      sha256 = "9bba0214ccf7f1079c5d59210045227bcf619519840ebfa80cd3849cff5a5bf2"
    } | Source,
    { file = "build.sh" } | Local,
    base,
    flex,
    m4,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    bison_bin = { glob = "usr/bin/bison" } | OutputBin,
    yacc_bin = { glob = "usr/bin/yacc" } | OutputBin,
    liby = { glob = "usr/lib/liby.a" } | OutputLib,
    bison_share = { glob = "usr/share/bison/**/*" } | OutputLib,
    bison_man = { glob = "usr/share/man/man1/bison.1" } | OutputLib,
    yacc_man = { glob = "usr/share/man/man1/yacc.1" } | OutputLib,
    bison_info = { glob = "usr/share/info/bison.info*" } | OutputLib,
    bison_locale = { glob = "usr/share/locale/**/*" } | OutputLib,
    bison_aclocal = { glob = "usr/share/aclocal/bison*.m4" } | OutputLib,
  },

  replace_on_cycle =
    {
      name = "bison (prebuilt)",
      inputs = [
        { package = "bison" } | Prebuilt,
      ],
      cmd = "",
      outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
      },
    } | BuildSpec,
} | BuildSpec

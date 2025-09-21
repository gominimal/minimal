let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let tcl = import "../tcl/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "dejagnu",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/dejagnu-1.6.3.tar.gz",
      sha256 = "87daefacd7958b4a69f88c6856dbd1634261963c414079d0c371f589cd66a2e3"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    usr_bin = { glob = "usr/bin/*" } | OutputLib,
    usr_include = { glob = "usr/include/*" } | OutputLib,
    usr_share_dejagnu = { glob = "usr/share/dejagnu/**/*" } | OutputLib,
  },
} | BuildSpec

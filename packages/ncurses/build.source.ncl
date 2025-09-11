let { BuildSpec, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "ncurses",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/ncurses-6.5-20250830.tgz",
      sha256 = "519ec9f748d7f2873cf763394fc766a701967439610125ad0fbf76ab2c7510a5"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    bin = { glob = "usr/bin/*" } | OutputLib,
    form_lib = { glob = "usr/lib/libform*.so*" } | OutputLib,
    usr_include = { glob = "usr/include/*" } | OutputLib,
    libraries = { glob = "usr/lib/libncurses*.so*" } | OutputLib,
    menu_lib = { glob = "usr/lib/libmenu*.so*" } | OutputLib,
    panel_lib = { glob = "usr/lib/libpanel*.so*" } | OutputLib,
    pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
    tabset = { glob = "usr/share/tabset/*" } | OutputLib,
    terminfo_lib = { glob = "usr/lib/terminfo/**/*" } | OutputLib,
    terminfo_share = { glob = "usr/share/terminfo/**/*" } | OutputLib,
  },
} | BuildSpec

let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let attr = import "../attr/build.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "ncurses",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/ncurses-6.5-20250830.tgz",
      sha256 = "519ec9f748d7f2873cf763394fc766a701967439610125ad0fbf76ab2c7510a5"
    } | Source,
    base,
    toolchain,
  ],
  runtime_deps = [
    attr,
  ],
  cmd = "./build.sh",
  outputs = {
    bin = { path = "usr/bin/*" } | OutputBin,
    form_lib = { glob = "usr/lib/libform*.so*" } | OutputLib,
    usr_include = { data = "usr/include/*" } | OutputData,
    libraries = { glob = "usr/lib/libncurses*.so*" } | OutputLib,
    menu_lib = { glob = "usr/lib/libmenu*.so*" } | OutputLib,
    panel_lib = { glob = "usr/lib/libpanel*.so*" } | OutputLib,
    pkgconfig = { data = "usr/lib/pkgconfig/*.pc" } | OutputData,
    tabset = { data = "usr/share/tabset/*" } | OutputData,
    terminfo_lib = { glob = "usr/lib/terminfo/**/*" } | OutputLib,
    terminfo_share = { data = "usr/share/terminfo/**/*" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "ncurses (prebuilt)",
      inputs = [
        { package = "ncurses" } | Prebuilt,
      ],
      runtime_deps = [
        attr,
      ],
      cmd = "",
      outputs = {
        bin = { path = "usr/bin/*" } | OutputBin,
        form_lib = { glob = "usr/lib/libform*.so*" } | OutputLib,
        usr_include = { data = "usr/include/*" } | OutputData,
        libraries = { glob = "usr/lib/libncurses*.so*" } | OutputLib,
        menu_lib = { glob = "usr/lib/libmenu*.so*" } | OutputLib,
        panel_lib = { glob = "usr/lib/libpanel*.so*" } | OutputLib,
        pkgconfig = { data = "usr/lib/pkgconfig/*.pc" } | OutputData,
        tabset = { data = "usr/share/tabset/*" } | OutputData,
        terminfo_lib = { glob = "usr/lib/terminfo/**/*" } | OutputLib,
        terminfo_share = { data = "usr/share/terminfo/**/*" } | OutputData,
      },
    } | BuildSpec,
} | BuildSpec

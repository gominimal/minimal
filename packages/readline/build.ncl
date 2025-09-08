let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
let ncurses = import "../ncurses/build.ncl" in
{
  name = "readline",
  inputs = [
    { package = "readline" } | Prebuilt,
  ],
  runtime_deps = [
    ncurses,
  ],
  cmd = "",
  outputs = {
    usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
    usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
  },
} | BuildSpec

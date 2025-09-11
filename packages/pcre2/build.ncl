let { BuildSpec, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "pcre2",
  inputs = [
    { package = "pcre2" } | Prebuilt,
  ],
  cmd = "",
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },
} | BuildSpec

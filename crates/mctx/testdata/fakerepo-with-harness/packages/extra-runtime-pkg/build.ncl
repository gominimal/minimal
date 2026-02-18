let { BuildSpec, .. } = import "minimal.ncl" in
{
  name = "extra-runtime-pkg",
  inputs = [],
  runtime_deps = [],
  outputs = {},
} | BuildSpec

let { BuildSpec, .. } = import "minimal.ncl" in
{
  name = "harness-runtime-pkg",
  inputs = [],
  runtime_deps = [],
  outputs = {},
} | BuildSpec

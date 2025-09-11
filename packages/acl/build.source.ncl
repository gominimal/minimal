let { BuildSpec, OutputLib, Local, Source, Prebuilt, .. } = import "minimal.ncl" in
let attr = import "../attr/build.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in

let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
let zlib = import "../zlib/build.ncl" in
let bzip2 = import "../bzip2/build.ncl" in
{
    name = "perl",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "perl-5.42.0.tar.xz"} | Local,
        busybox_static,
        make,
        zlib,
        bzip2,
    ],
    cmd = "./build.sh",
    outputs = {
        perl_bin = { glob = "bin/perl" } | OutputLib,
        perl5_bin = { glob = "bin/perl5.42.0" } | OutputLib,
        perl_modules = { glob = "lib/perl5/**/*" } | OutputLib,
        man_pages = { glob = "share/man/man*/*" } | OutputLib,
        all_binaries = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
{
    name = "gawk",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "gawk-5.3.2.tar.xz"} | Local,
        busybox_static,
        make,
    ],
    cmd = "./build.sh",
    outputs = {
        gawk = { glob = "bin/gawk" } | OutputLib,
        gawk_versioned = { glob = "bin/gawk-5.3.2" } | OutputLib,
        awk = { glob = "bin/awk" } | OutputLib,
        libexec = { glob = "libexec/awk/*" } | OutputLib,
        includes = { glob = "include/*.h" } | OutputLib,
        man = { glob = "share/man/man1/*.1" } | OutputLib,
        man3 = { glob = "share/man/man3/*.3am" } | OutputLib,
        info = { glob = "share/info/*.info*" } | OutputLib,
    },
} | BuildSpec
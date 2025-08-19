let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
{
    name = "attr",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "attr-2.5.2.tar.gz"} | Local,
        busybox_static,
        make,
    ],
    cmd = "./build.sh",
    outputs = {
        attr = { glob = "usr/bin/attr" } | OutputLib,
        getfattr = { glob = "usr/bin/getfattr" } | OutputLib,
        setfattr = { glob = "usr/bin/setfattr" } | OutputLib,
        libattr = { glob = "usr/lib/libattr.so*" } | OutputLib,
        headers = { glob = "usr/include/attr/*.h" } | OutputLib,
        manpages = { glob = "usr/share/man/man*/*" } | OutputLib,
        docs = { glob = "usr/share/doc/attr-*/*" } | OutputLib,
    },
} | BuildSpec
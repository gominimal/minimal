let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
    name = "bzip2",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/bzip2-1.0.8.tar.gz",
            sha256 = "ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269"
        } | Source,
        bash,
        coreutils,
        diffutils,
        gzip,
        make,
        sed,
        tar,
        toolchain,
    ],
    cmd = "./build.sh",
    outputs = {
        bunzip2 = { glob = "usr/bin/bunzip2" } | OutputLib,
        bzcat = { glob = "usr/bin/bzcat" } | OutputLib,
        bzcmp = { glob = "usr/bin/bzcmp" } | OutputLib,
        bzdiff = { glob = "usr/bin/bzdiff" } | OutputLib,
        bzegrep = { glob = "usr/bin/bzegrep" } | OutputLib,
        bzfgrep = { glob = "usr/bin/bzfgrep" } | OutputLib,
        bzgrep = { glob = "usr/bin/bzgrep" } | OutputLib,
        bzip2 = { glob = "usr/bin/bzip2" } | OutputLib,
        bzip2recover = { glob = "usr/bin/bzip2recover" } | OutputLib,
        bzless = { glob = "usr/bin/bzless" } | OutputLib,
        bzmore = { glob = "usr/bin/bzmore" } | OutputLib,
        
        libbz2 = { glob = "usr/lib/libbz2.so*" } | OutputLib,
        
        headers = { glob = "usr/include/bzlib.h" } | OutputLib,
    },
} | BuildSpec

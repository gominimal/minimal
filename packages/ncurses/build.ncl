let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let binutils = import "../binutils/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "ncurses",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/ncurses-6.5.tar.gz",
            sha256 = "136d91bc269a9a5785e5f9e980bc76ab57428f604ce3e5a5a90cebc767971cc6"
        } | Source,
        binutils,
        bash,
        coreutils,
        gawk,
        gcc,
        glibc,
        grep,
        gzip,
        linux_headers,
        make,
        sed,
        tar,
        mpc,
        mpfr,
        gmp,
        zstd,
    ],
    cmd = "./build.sh",
    outputs = {
        # binaries = { glob = "usr/bin/*" } | OutputLib,

        libraries = { glob = "usr/lib/libncurses*.so*" } | OutputLib,
        form_lib = { glob = "usr/lib/libform*.so*" } | OutputLib,
        panel_lib = { glob = "usr/lib/libpanel*.so*" } | OutputLib,
        menu_lib = { glob = "usr/lib/libmenu*.so*" } | OutputLib,
        # pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
        terminfo_lib = { glob = "usr/lib/terminfo/**/*" } | OutputLib,

        # headers = { glob = "usr/include/*.h" } | OutputLib,

        # manpages = { glob = "usr/share/man/man*/*" } | OutputLib,
        # tabset_share = { glob = "usr/share/tabset/*" } | OutputLib,
        terminfo_share = { glob = "usr/share/terminfo/**/*" } | OutputLib,
    },
} | BuildSpec

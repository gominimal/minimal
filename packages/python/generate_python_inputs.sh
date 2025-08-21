#!/bin/bash

echo "let {BuildSpec, HostPath, OutputLib, Local, ..} = import \"minimal.ncl\" in"
echo "let busybox_static = import \"../busybox_static/build.ncl\" in"
echo "{"
echo "    name = \"python\","
echo "    inputs = ["
echo "        {file = \"build.sh\"} | Local,"

# All files and symlinks in the prebuilt directory, including everything in usr/lib
find prebuilt/usr \( -type f -o -type l \) | sort | while read f; do
    echo "        {file = \"$f\"} | Local,"
done

echo "        busybox_static,"
echo "    ],"
echo "    cmd = \"./build.sh\","
echo "    outputs = {"
echo "        # Python binaries"
echo "        python3 = { glob = \"usr/bin/python3\" } | OutputLib,"
echo "        python3_11 = { glob = \"usr/bin/python3.13\" } | OutputLib,"
echo "        python_config = { glob = \"usr/bin/python3.13-config\" } | OutputLib,"
echo "        python3_config = { glob = \"usr/bin/python3-config\" } | OutputLib,"
echo "        # Python library"
echo "        libpython = { glob = \"usr/lib/libpython3.13.a\" } | OutputLib,"
echo "        # Python standard library"
echo "        stdlib = { glob = \"usr/lib/python3.13/**/*\" } | OutputLib,"
echo "        # pkg-config files"
echo "        pkgconfig = { glob = \"usr/lib/pkgconfig/*.pc\" } | OutputLib,"
echo "        # Python headers"
echo "        headers = { glob = \"usr/include/python3.13/**/*\" } | OutputLib,"
echo "    },"
echo "} | BuildSpec"

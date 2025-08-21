#!/bin/bash

echo "let {BuildSpec, HostPath, OutputLib, Local, ..} = import \"minimal.ncl\" in"
echo "let busybox_static = import \"../busybox_static/build.ncl\" in"
echo "{"
echo "    name = \"glibc\","
echo "    inputs = ["
echo "        {file = \"build.sh\"} | Local,"

# All files and symlinks in the prebuilt directory
find prebuilt \( -type f -o -type l \) | sort | while read f; do
    echo "        {file = \"$f\"} | Local,"
done

echo "        busybox_static,"
echo "    ],"
echo "    cmd = \"./build.sh\","
echo "    outputs = {"
echo "        etc = { glob = \"etc/**/*\" } | OutputLib,"
echo "        lib64 = { glob = \"lib64/**/*\" } | OutputLib,"
echo "        sbin = { glob = \"sbin/**/*\" } | OutputLib,"
echo "        usr = { glob = \"usr/**/*\" } | OutputLib,"
echo "        var = { glob = \"var/**/*\" } | OutputLib,"
echo "    },"
echo "} | BuildSpec"

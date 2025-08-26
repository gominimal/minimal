#!/bin/bash

echo "let {BuildSpec, HostPath, OutputLib, Local, ..} = import \"minimal.ncl\" in"
echo "let busybox_static = import \"../busybox_static/build.ncl\" in"
echo "{"
echo "    name = \"m4\","
echo "    inputs = ["
echo "        {file = \"build.sh\"} | Local,"

find prebuilt/ \( -type f -o -type l \) | sort | while read f; do
    echo "        {file = \"$f\"} | Local,"
done

echo "        busybox_static,"
echo "    ],"
echo "    cmd = \"./build.sh\","
echo "    outputs = {"
echo "        usr = { glob = \"usr/**/*\" } | OutputLib,"
echo "    },"
echo "} | BuildSpec"

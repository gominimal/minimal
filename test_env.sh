#!/bin/bash
echo "=== Environment Test ==="
echo "Number of environment variables: $(env | wc -l)"
echo
echo "Environment variables:"
env | sort
echo
echo "=== Test complete ==="
exit
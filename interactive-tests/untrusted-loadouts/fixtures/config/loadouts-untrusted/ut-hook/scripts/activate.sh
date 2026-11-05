#!/bin/sh
echo "ut-hook-external kind=$MINIMAL_HOOK_SOURCE_KIND name=$MINIMAL_HOOK_SOURCE_NAME" | tee -a "$HOME/untrusted-loadout-test.log"

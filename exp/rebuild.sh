#!/bin/bash

set -o nounset
set -o errexit

if [ $# == 0 ]; then
  echo "Supply arg, dest for rebuild"
  exit 1
fi

for DST in $*; do
#scp ~/src/go/src/github.com/kevinawalsh/profiling/*.go $DST:src/go/src/github.com/kevinawalsh/profiling
ssh -f $DST 'bash -lc "cd ~/src/go/src/github.com/jlmucb/cloudproxy/go/ && git reset --hard && git pull && ./scripts/build_static.sh && ./scripts/build_docker.sh && ./scripts/build_linux_host.sh; echo DONE"'
done

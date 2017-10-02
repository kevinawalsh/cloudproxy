#!/bin/bash

set -o nounset
set -o errexit

DST="$1"

if [ "$DST" != "local" ]; then

source ~/cloudchan2/machines.sh

for m in eb1 eb2 eb3 ec1 ed1 va1; do
  echo updating $m
  scp ~/cloudchan2/update.sh $m:
  ssh $m 'bash -lc "./update.sh local"'
done

else

cd ~/src/go/src/github.com/jlmucb/cloudproxy/go
git pull
./scripts/build_static.sh
#./scripts/set_up_domain.sh AllowAll Soft
#sudo mv /tmp/domain.* /etc/tao
./scripts/build_docker.sh
./scripts/build_linux_host.sh

fi

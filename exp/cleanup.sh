#!/bin/bash

DST="$1"

if [ "$DST" != "local" ]; then

source ~/cloudchan2/machines.sh

for m in eb1 eb2 eb3 ec1 ed1 va1; do
  echo cleaning $m
  scp ~/cloudchan2/cleanup.sh $m:
  ssh $m 'bash -lc "./cleanup.sh local"'
done

else

echo "Killing zombie tao processes..."
sudo pkill -9 -f tao

if [ -e "$TAO_DOMAIN/linux_tao_host/admin_socket" ]; then
  echo "Shutting down tao host..."
  sudo tao host stop -tao_domain "$TAO_DOMAIN"
fi

echo "Killing zombie tao hosts and hosted programs..."
sudo pgrep -a linux_host 
sudo pkill -9 linux_host
sudo pgrep -a tao_launch
sudo pkill -9 tao_launch
for f in `ls ./src/go/bin`; do
  sudo pkill $f
  sudo pkill -9 $f
done

if [ -e "$TAO_DOMAIN/linux_tao_host/admin_socket" ]; then
  echo "Force-removing admin socket..."
  sudo rm -f "$TAO_DOMAIN/linux_tao_host/admin_socket"
fi

echo "Removing temp and log files..."
sudo rm -rf /tmp/kvm_linux_host.* /tmp/tao_log/* /tmp/coreos*

fi

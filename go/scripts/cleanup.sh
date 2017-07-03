#!/bin/bash

if [ "$#" -ge 1 ]; then
  export TAO_DOMAIN="$1"
elif [ "$TAO_DOMAIN" == "" ]; then
	echo "Must supply the path to an initialized domain, or set \$TAO_DOMAIN."
	exit 1
fi

# echo "Killing zombie tao processes..."
# sudo pkill -9 -f tao

if [ -e "$TAO_DOMAIN/linux_tao_host/admin_socket" ]; then
  echo "Shutting down tao host..."
  sudo tao host stop -tao_domain "$TAO_DOMAIN"
fi

echo "Killing zombie tao hosts and hosted programs..."
sudo pgrep -a linux_host 
sudo pkill -9 linux_host
sudo pgrep -a tao_launch
sudo pkill -9 tao_launch

if [ -e "$TAO_DOMAIN/linux_tao_host/admin_socket" ]; then
  echo "Force-removing admin socket..."
  sudo rm -f "$TAO_DOMAIN/linux_tao_host/admin_socket"
fi

echo "Removing temp and log files..."
sudo rm -rf /tmp/kvm_linux_host.* /tmp/tao_log/* /tmp/coreos*


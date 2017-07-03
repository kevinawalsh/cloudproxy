#!/bin/bash

if [ "$#" -ge 1 ]; then
  export TAO_DOMAIN="$1"
elif [ "$TAO_DOMAIN" == "" ]; then
	echo "Must supply the path to an initialized domain, or set \$TAO_DOMAIN."
	exit 1
fi

echo "Killing zombie tao processes..."
sudo pkill -9 -f tao

echo "Removing admin socket..."
sudo rm -f "$TAO_DOMAIN/linux_tao_host/admin_socket"

echo "Removing temp and log files..."
sudo rm -rf /tmp/kvm_linux_host.* /tmp/tao_log/* /tmp/coreos*


#!/bin/bash

# This script assumes that the binary for linux_host has been built and
# installed into a bin path in $GOPATH. For the purposes of KVM/CoreOS, this
# binary must be executable on the virtual machine. One way to make this easier
# is to build the binary statically. E.g., see run/scripts/build_standalone.sh.

set -o nounset
set -o errexit

# This script assumes that the code for running linux_host has already been
# built in static (or "standalone") mode using build_static.sh.
if [ "$#" -ge 1 ]; then
	export TAO_DOMAIN="$1"
elif [ "$TAO_DOMAIN" == "" ]; then
	echo "Must supply the path to an initialized domain, or set \$TAO_DOMAIN."
	exit 1
fi

WHICH=$(which which)
APP_BIN="$(PATH="${GOPATH//://bin:}/bin" $WHICH linux_host)"
TEMP_DIR=$(mktemp -d)
cp "$APP_BIN" ${TEMP_DIR}/linux_host
mkdir ${TEMP_DIR}/policy_keys
mkdir ${TEMP_DIR}/linux_tao_host
chmod 755 ${TEMP_DIR}/linux_tao_host
echo 'type: "stacked"' >> ${TEMP_DIR}/linux_tao_host/host.config
echo 'hosting: "process"' >> ${TEMP_DIR}/linux_tao_host/host.config
chmod 444 ${TEMP_DIR}/linux_tao_host/host.config
cp "$TAO_DOMAIN/policy_keys/cert.der" ${TEMP_DIR}/policy_keys/cert.der
cp "$TAO_DOMAIN/tao.config" ${TEMP_DIR}/tao.config


tar -C ${TEMP_DIR} -czf "$APP_BIN".img.tgz $(ls ${TEMP_DIR})
rm -fr ${TEMP_DIR}

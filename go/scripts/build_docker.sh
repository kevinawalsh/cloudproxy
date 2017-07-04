#!/bin/bash

set -o nounset
set -o errexit

# This script assumes that the code for running the demo server and demo client
# has already been built in static (or "standalone") mode using build_static.sh.
if [ "$#" -ge 1 ]; then
	export TAO_DOMAIN="$1"
elif [ "$TAO_DOMAIN" == "" ]; then
	echo "Must supply the path to an initialized domain, or set \$TAO_DOMAIN."
	exit 1
fi

# arguments: build_docker <script path> <local relative app path> <policy cert # path> <tao.config path>
# e.g., build_docker $0 demo_server $1 $2
function build_docker() {
	# This script currently only supports Linux (or any system that has a working
	# readlink -e)

	script_name="$1"
	app_name="$2"
	policy_cert="$3"
	tao_config="$4"

	APPS_DIR="$(readlink -e "$(dirname "$script_name")")"/../apps
	TEMP_DIR=$(mktemp -d)
	cp `find "${APPS_DIR}" -name ${app_name}`/Dockerfile ${TEMP_DIR}/Dockerfile
	mkdir ${TEMP_DIR}/tmp
	mkdir ${TEMP_DIR}/bin
	WHICH=$(which which)
	APP_BIN="$(PATH="${GOPATH//://bin:}/bin" $WHICH ${app_name})"
	if ldd "$APP_BIN" >/dev/null 2>&1; then
		echo "Found dynamic executable: $APP_BIN"
		echo "Docker requires static executables."
		echo "See build_static.sh for static build instructions."
		exit 1
	fi
	cp "$APP_BIN" ${TEMP_DIR}/bin/${app_name}
	mkdir ${TEMP_DIR}/policy_keys
	cp $policy_cert ${TEMP_DIR}/policy_keys/cert.der
	cp $tao_config ${TEMP_DIR}/tao.config

	tar -C ${TEMP_DIR} -czf "$APP_BIN".img.tgz $(ls ${TEMP_DIR})
	rm -rf ${TEMP_DIR}
  echo "built: $APP_BIN".img.tgz
}

build_docker "$0" demo_server "$TAO_DOMAIN/policy_keys/cert.der" "$TAO_DOMAIN/tao.config"
build_docker "$0" demo_client "$TAO_DOMAIN/policy_keys/cert.der" "$TAO_DOMAIN/tao.config"
build_docker "$0" hosted_psk_server "$TAO_DOMAIN/policy_keys/cert.der" "$TAO_DOMAIN/tao.config"

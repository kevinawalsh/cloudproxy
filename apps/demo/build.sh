#!/bin/bash
# This script assumes that the code for running the demo server and demo client
# has already been built in standalone mode using build_standalone.
if [ "$#" != "1" ]; then
	echo "Must supply a policy certificate for the demo code"
	exit 1
fi

# arguments: build_docker <script path> <local relative app path> <policy cert path>
# e.g., build_docker $0 demo_server $1
function build_docker() {
	# This script currently only supports Linux (or any system that has a working
	# readlink -e)

	script_name=$1
	app_name=$2
	policy_cert=$3

	DEMO_DIR=$(readlink -e $(dirname $script_name))
	TEMP_DIR=`mktemp -d`
	cp ${DEMO_DIR}/${app_name}/Dockerfile ${TEMP_DIR}/Dockerfile
	mkdir ${TEMP_DIR}/tmp
	mkdir ${TEMP_DIR}/bin
	cp ${GOPATH}/bin/${app_name} ${TEMP_DIR}/bin/${app_name}
	mkdir ${TEMP_DIR}/policy_keys
	cp $policy_cert ${TEMP_DIR}/policy_keys/cert

	cat >${TEMP_DIR}/tao.config <<EOF
# Tao Domain Configuration file

[Domain]
Name = testing
PolicyKeysPath = policy_keys
GuardType = AllowAll

[X509Details]
CommonName = testing	
EOF

	touch ${TEMP_DIR}/rules

	tar -C ${TEMP_DIR} -czf ${DEMO_DIR}/${app_name}/docker.img.tgz `ls ${TEMP_DIR}`
}

build_docker $0 demo_server $1
build_docker $0 demo_client $1
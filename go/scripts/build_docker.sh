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

  docker_name="$1"
  dockerfile="$2"

  IMG="${docker_name}.img.tgz"
  echo "Building: $IMG"

	TEMP_DIR=$(mktemp -d)

  # common direictories
	mkdir ${TEMP_DIR}/tmp
	mkdir ${TEMP_DIR}/etc
	mkdir ${TEMP_DIR}/bin

  # copy dockerfile
  cp "$dockerfile" ${TEMP_DIR}/Dockerfile

  # copy binaries mentioned in Dockerfile
  WHICH=$(which which)
  IMGDIR="."
  for prog in `awk -e '/^# build_docker.sh copies: / { print $4}' $dockerfile`; do
    APP_BIN="$(PATH="${GOPATH//://bin:}/bin" $WHICH ${prog})"
    if [ "$IMGDIR" == "." ]; then
      IMGDIR=`dirname "$APP_BIN"`
    fi
    if ldd "$APP_BIN" >/dev/null 2>&1; then
      echo "Found dynamic executable: $APP_BIN"
      echo "Docker requires static executables."
      echo "See build_static.sh for static build instructions."
      exit 1
    fi
    cp "$APP_BIN" ${TEMP_DIR}/bin/
    echo "... copied binary $APP_BIN"
  done
  for dom in `awk -e '/^# build_docker.sh copies domain: / { print $5}' $dockerfile`; do
    cp -r "$dom" ${TEMP_DIR}/etc/tao
    echo "... copied domain $dom"
  done

  # copy policy cert (kwalsh: why?)
	mkdir ${TEMP_DIR}/policy_keys
	cp $TAO_DOMAIN/policy_keys/cert.der ${TEMP_DIR}/policy_keys/cert.der

  # copy tao config (kwalsh: why?)
	cp $TAO_DOMAIN/tao.config ${TEMP_DIR}/tao.config

	tar -C ${TEMP_DIR} -czf "$IMGDIR/$IMG" $(ls ${TEMP_DIR})
	rm -rf ${TEMP_DIR}
}
	
APPS="$(readlink -e "$(dirname "$0")")"/../apps

# build_docker demo_server "$APPS/demo/demo_server/Dockerfile"
# build_docker demo_client "$APPS/demo/demo_client/Dockerfile"
# build_docker hosted_psk_server "$APPS/perf/hosted_psk/hosted_psk_server/Dockerfile"
# build_docker standalone_client "$APPS/perf/standalone/standalone_client/Dockerfile"
for dockerfile in `find "$APPS" -name Dockerfile`; do
  name=$(basename $(dirname "$dockerfile"))
  build_docker "$name" "$dockerfile"
done

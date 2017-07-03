#!/bin/bash

# This script requires you to have already run get_coreos_stable.sh or have
# obtained a coreos image.
# This script assumes you have run build_static.sh
# This script assumes you have run build_linux_host.sh

if [ "$#" != "3" -a "$#" != "2" ]; then
  echo "Must supply a CoreOS image, an SSH auth keys file, and (optionally) a domain path."
	exit 1
fi

set -o nounset
set -o errexit

gowhich() {
	WHICH=$(which which)
	echo -n "$(PATH="${GOPATH//://bin:}/bin" $WHICH "$1")"
}

IMG="$1"
KEYS="$2"
if [ "$#" -ge 3 ]; then
  export TAO_DOMAIN="$3"
elif [ "$TAO_DOMAIN" == "" ]; then
	echo "Must supply the path to an initialized domain, or set \$TAO_DOMAIN."
	exit 1
fi

TAO="$(gowhich tao)"
FAKE_PASS=BogusPass
LINUXHOST="$(gowhich linux_host).img.tgz"

# Make sure we have sudo privileges before running anything.
sudo test true

sudo "$TAO" host start -tao_domain "$TAO_DOMAIN" -pass $FAKE_PASS \
	-kvm_coreos_img $IMG -kvm_coreos_ssh_auth_keys $KEYS \
	-hosting kvm_coreos_linuxhost & # daemon
echo "Waiting for hypervisor linux_host to start"
sleep 5

echo "About to start a virtual machine with linux_host as a hosted program"
# Start the VM with linux_host.
LHTEMP=$(mktemp -d /tmp/kvm_linux_host.XXXXXXXX)
SSHPORT=2222
"$TAO" run "kvm_coreos_linuxhost:${LINUXHOST}" -- ${LINUXHOST} ${LHTEMP} ${SSHPORT} &

echo "Waiting for the virtual machine to start"
sleep 45

# Move the binaries to the temporary directory, which is mounted using Plan9P on
# the virtual machine.
cp "$(gowhich demo_server)" "$(gowhich demo_client)" "$(gowhich tao_launch)" ${LHTEMP}

# Ensure docker / CoreOS user, e.g. id=500(core), can access these binaries.
# TODO(kwalsh) Mounting host directories seems to be discouraged... use scp?
chmod a+rx ${LHTEMP}/{demo_server,demo_client,tao_launch}

# Run tao_launch twice across SSH to start the demo programs. For the ssh
# command to work, this session must have an ssh agent with the keys from
# ${KEYS}.
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -x -l core -p ${SSHPORT} localhost /media/tao/tao_launch run \
	-host /etc/tao/linux_tao_host /media/tao/demo_server \
	-tao_domain /etc/tao &
echo Waiting for the server to start
sleep 2

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -x -l core -p ${SSHPORT} localhost /media/tao/tao_launch run \
	-host /etc/tao/linux_tao_host /media/tao/demo_client \
	-tao_domain /etc/tao -host 127.0.0.1 &
echo Waiting for the client to run
sleep 4

#echo -e "\n\nCleaning up"
## ssh -x -l core -p ${SSHPORT} localhost sudo shutdown -h now
#sudo "$TAO" host stop -tao_domain "$TAO_DOMAIN"

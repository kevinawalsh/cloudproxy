#!/bin/bash

set -o nounset
set -o errexit

gowhich() {
	WHICH=$(which which)
	echo -n "$(PATH="${GOPATH//://bin:}/bin" $WHICH "$1")"
}

if [ "$#" -ge 3 ]; then
  export TAO_DOMAIN="$3"
elif [ "$TAO_DOMAIN" == "" ]; then
  TAO_DOMAIN=/etc/tao
fi

IMG=/home/kwalsh/coreos2017/coreos_production_qemu_image.img
KEYS=/home/kwalsh/.ssh/authorized_keys

SCRIPTS=/home/kwalsh/src/go/src/github.com/jlmucb/cloudproxy/go/scripts

$SCRIPTS/cleanup.sh
$SCRIPTS/build_static.sh
$SCRIPTS/build_docker.sh
$SCRIPTS/build_linux_host.sh

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
sleep 30

# Move the binaries to the temporary directory, which is mounted using Plan9P on
# the virtual machine.
cp "$(gowhich hosted_psk_server)" "$(gowhich tao_launch)" ${LHTEMP}

# Ensure docker / CoreOS user, e.g. id=500(core), can access these binaries.
# TODO(kwalsh) Mounting host directories seems to be discouraged... use scp?
chmod a+rx ${LHTEMP}/{hosted_psk_server,tao_launch}

tao run hosted_psk_client -show_subprin >${LHTEMP}/hosted_psk_client-subprin
chmod a+r ${LHTEMP}/*-subprin

SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -x -l core -p ${SSHPORT} localhost"
KVM_RUN="$SSH /media/tao/tao_launch run \
	-host /etc/tao/linux_tao_host -tao_domain /etc/tao"
# Run tao_launch across SSH to start the server program. For the ssh
# command to work, this session must have an ssh agent with the keys from
# ${KEYS}.
$KVM_RUN /media/tao/hosted_psk_server -save_subprin /tmp/hosted_psk_server-subprin
$SSH sudo cp /tmp/hosted_psk_server-subprin /media/tao/
$SSH sudo chmod a+r '/media/tao/*-subprin'

$KVM_RUN /media/tao/hosted_psk_server -host 0.0.0.0 -n 1001 -peer_subprin "\"`cat $LHTEMP/*-subprin`\"" &
echo Waiting for the server to start
sleep 2

tao run hosted_psk_client -port 18123 -n 1001 -peer_subprin "`cat $LHTEMP/*-subprin`"

echo -e "\n\nCleaning up"
$SSH sudo shutdown -h now
sudo "$TAO" host stop -tao_domain "$TAO_DOMAIN"

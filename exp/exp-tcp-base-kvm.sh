#!/bin/bash

echo
date
echo "plain tcp, base server, kvm client"
echo $0

ulimit -n 4096

echo "starting base host"
IMG=/home/$USER/coreos2017/coreos_production_qemu_image.img
KEYS=/home/$USER/.ssh/authorized_keys
sudo tao host start -daemon -hosting docker,process,kvm_coreos_linuxhost \
	-kvm_coreos_img $IMG -kvm_coreos_ssh_auth_keys $KEYS
sleep 15

LHTEMP=$(mktemp -d /tmp/kvm_linux_host.XXXXXXXX)
cp /home/$USER/src/go/bin/{standalone_client,tao_launch} ${LHTEMP}
chmod a+rx ${LHTEMP}/{standalone_client,tao_launch}

echo "starting kvm"
LHOST=/home/$USER/src/go/bin/linux_host.img.tgz
tao run "kvm_coreos_linuxhost:${LHOST}" -- ${LHOST} ${LHTEMP} 2222 &
echo "waiting for virtual machine to start"
sleep 30

echo "running base server"
tao run standalone_server -host 172.27.35.103 -n 1001 &
sleep 2

SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -x -l core -p 2222 localhost"
KVM_RUN="$SSH /media/tao/tao_launch run -host /etc/tao/linux_tao_host -tao_domain /etc/tao"

echo "starting kvm client"
$KVM_RUN /media/tao/standalone_client -host 172.27.35.103 -n 1001

# echo "shutting down kvm"
# $SSH sudo shutdown -h now
# 
# sudo tao host stop
# sudo rm -rf ${LHTEMP}

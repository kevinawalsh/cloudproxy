#!/bin/bash

echo
date
echo "hosted psk, base server, kvm client"
echo $0

ulimit -n 4096

echo "starting base host"
IMG=/home/$USER/coreos2017/coreos_production_qemu_image.img
KEYS=/home/$USER/.ssh/authorized_keys
sudo tao host start -hosting docker,process,kvm_coreos_linuxhost \
	-kvm_coreos_img $IMG -kvm_coreos_ssh_auth_keys $KEYS &
sleep 3

LHTEMP=$(mktemp -d /tmp/kvm_linux_host.XXXXXXXX)
cp /home/$USER/src/go/bin/{hosted_psk_client.img.tgz,tao_launch} ${LHTEMP}
chmod a+rx ${LHTEMP}/tao_launch

echo "starting kvm"
LHOST=/home/$USER/src/go/bin/linux_host.img.tgz
tao run "kvm_coreos_linuxhost:${LHOST}" -- ${LHOST} ${LHTEMP} 2222 &
echo "waiting for virtual machine to start"
sleep 30

SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -x -l core -p 2222 localhost"
KVM_RUN="$SSH /media/tao/tao_launch run -host /etc/tao/linux_tao_host -tao_domain /etc/tao"


echo "getting server and client names"
sudo rm -rf ${LHTEMP}/prin-*
tao run hosted_psk_server -save_name ${LHTEMP}/prin-server
$KVM_RUN docker:/media/tao/hosted_psk_client.img.tgz -- -show_name >/tmp/preprin-client
echo "fixing client name"
$SSH 'grep -v "^[0-9\*]*>" /tmp/preprin-client >/tmp/prin-client'
$SSH 'sudo cp /tmp/prin-client /media/tao/'

sudo chmod a+r ${LHTEMP}/prin-*

echo "running base server"
tao run hosted_psk_server -level 0 -host 172.27.35.103 -n 1001 -peer_prins "`cat ${LHTEMP}/prin-*`" &
sleep 2

echo "starting kvm client"
$KVM_RUN docker:/media/tao/hosted_psk_client.img.tgz -- -level 2 -host 172.27.35.103 -n 1001 -peer_prins "`cat ${LHTEMP}/prin-*`"

# echo "shutting down kvm"
# $SSH sudo shutdown -h now
# 
# sudo tao host stop
# sudo rm -rf ${LHTEMP}

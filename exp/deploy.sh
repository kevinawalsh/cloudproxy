#!/bin/bash

set -o nounset
set -o errexit


DST="$1"

if [ "$DST" == "" ]; then
  echo "Supply arg, dest for deploy"
  exit 1
fi

if [ "$DST" != "local" ]; then

# PROGS="app_ca attested_client attested_psk_client attested_psk_server attested_server centralized_client centralized_server hosted_psk_client hosted_psk_server hosted_psk_server.img.tgz linux_host linux_host.img.tgz offline_ca_client psk_ka standalone_ca standalone_ca_client standalone_ca_server standalone_client standalone_psk_client standalone_psk_server standalone_server tao tao_admin tao_launch tpm_aa "
#scp $PROG $DST:
#scp -r ~/src/go/bin $DST:

ssh $DST sudo apt-get update -y
ssh $DST sudo apt-get upgrade -y
ssh $DST sudo apt-get install -y git # golang-1.8
ssh $DST wget https://storage.googleapis.com/golang/go1.8.3.linux-amd64.tar.gz
scp -r ~/.ssh $DST:
scp -r ~/src/go/src/github.com/kevinawalsh/profiling $DST:
scp -r ~/go/share/src/github.com/mordyovits/golang-crypto-tls $DST:

scp ~/cloudchan2/deploy.sh $DST:
ssh $DST ./deploy.sh local

scp -r policy_keys $DST:/etc/tao/

# echo "Generating offline attestation for root host"
# ssh -t -f $DST "bash -lc \"sudo tao host start -hosting process -pass BogusPass\""
# ssh $DST -t "tao run tpm_aa -keys /etc/tao/policy_keys -attestation /etc/tao/aa-attestation -id 42"
# ssh $DST -t "sudo tao host stop"
# echo "DONE"

else # ------------------ rest on $DST ----------------------

echo 'export GOROOT=/home/$USER/go' >> ~/.profile
echo 'export GOPATH=/home/$USER/src/go' >> ~/.profile
echo 'export PATH=/home/$USER/src/go/bin:$GOROOT/bin:$PATH' >> ~/.profile
echo 'export TAO_DOMAIN=/etc/tao' >> ~/.profile
echo 'export EDITOR=vim' >> ~/.bashrc
source ~/.profile
tar xvfz go1.8.3.linux-amd64.tar.gz
go version

mkdir -p ~/src/go/src/github.com/kevinawalsh
mv ~/profiling ~/src/go/src/github.com/kevinawalsh/

mkdir -p ~/src/go/src/github.com/mordyovits
mv ~/golang-crypto-tls ~/src/go/src/github.com/mordyovits/


mkdir -p ~/src/go/src/github.com/jlmucb
cd ~/src/go/src/github.com/jlmucb

yes | git clone git@github.com:kevinawalsh/cloudproxy.git
cd cloudproxy/go
ln -s ~/src/go/src/github.com/jlmucb/cloudproxy ~/cloudproxy
git checkout $USER-master
go get ./...
go install ./...


cd ~/src/go/src/github.com/jlmucb/cloudproxy/go
./scripts/build_static.sh
./scripts/set_up_domain.sh AllowAll Soft
sudo mv /tmp/domain.* /etc/tao
./scripts/build_docker.sh
./scripts/build_linux_host.sh

fi


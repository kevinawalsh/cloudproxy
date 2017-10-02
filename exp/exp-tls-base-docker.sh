#!/bin/bash

echo
date
echo "plain tls, base server, docker client"
echo $0

sudo tao host start -daemon -hosting docker,process
sleep 2

tao run standalone_ca -sappcahost 172.27.35.103 -n 1002 &
sleep 2

tao run standalone_ca_server -host 172.27.35.103 -sappcahost 172.27.35.103 -n 1001 &
sleep 2

tao run docker:/home/$USER/src/go/bin/offline_ca_client.img.tgz -- -host 172.27.35.103 -sappcahost 172.27.35.103 -n 1001

sudo tao host stop

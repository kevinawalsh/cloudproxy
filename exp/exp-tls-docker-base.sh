#!/bin/bash

echo
date
echo "plain tcp, docker server, base client"
echo $0

sudo tao host start -daemon -hosting docker,process
sleep 2

tao run standalone_ca -sappcahost 172.27.35.103 -n 1002 &
sleep 2

tao run -disown docker:/home/$USER/src/go/bin/standalone_ca_server.img.tgz -p 8123:8123/tcp -- -host 172.17.0.2 -sappcahost 172.27.35.103 -n 1001
sleep 5

tao run offline_ca_client -host localhost -sappcahost 172.27.35.103 -n 1001

sudo tao host stop

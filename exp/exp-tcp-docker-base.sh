#!/bin/bash

echo
date
echo "plain tcp, docker server, base client"
echo $0

sudo tao host start -daemon -hosting docker,process
sleep 2

tao run -disown docker:/home/$USER/src/go/bin/standalone_server.img.tgz -p 8123:8123/tcp -- -host 172.17.0.2 -n 1001
sleep 5

tao run standalone_client -host localhost -n 1001

sudo tao host stop

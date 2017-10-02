#!/bin/bash

echo
date
echo "hosted psk, docker server, base client"
echo $0

sudo tao host start -daemon -hosting docker,process
sleep 2

rm -f /tmp/prin-* /tmp/preprin-*
tao run docker:/home/$USER/src/go/bin/hosted_psk_server.img.tgz -- -show_name >/tmp/preprin-server
grep -v "^[0-9\*]*>" /tmp/preprin-server >/tmp/prin-server
tao run hosted_psk_client -save_name /tmp/prin-client

tao run docker:/home/$USER/src/go/bin/hosted_psk_server.img.tgz -p 8123:8123/tcp -- -level 1 -host 172.17.0.2 -n 1001 -peer_prins "`cat /tmp/prin-*`" &
sleep 15

tao run hosted_psk_client -level 0 -host 172.27.35.103 -n 1001 -peer_prins "`cat /tmp/prin-*`"

sudo tao host stop

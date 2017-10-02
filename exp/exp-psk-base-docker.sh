#!/bin/bash

echo
date
echo "hosted psk, base server, docker client"
echo $0

echo "starting base host"
sudo tao host start -daemon -hosting docker,process
sleep 2

echo "cleaning up"
rm -f /tmp/prin-* /tmp/preprin-*
echo "getting server name"
tao run hosted_psk_server -save_name /tmp/prin-server
echo "getting client name"
tao run docker:/home/$USER/src/go/bin/hosted_psk_client.img.tgz -- -show_name >/tmp/preprin-client
echo "fixing client name"
grep -v "^[0-9\*]*>" /tmp/preprin-client >/tmp/prin-client

echo "starting server"
tao run hosted_psk_server -level 0 -host 172.27.35.103 -n 1001 -peer_prins "`cat /tmp/prin-*`" &
sleep 2

echo "starting client"
tao run docker:/home/$USER/src/go/bin/hosted_psk_client.img.tgz -- -level 1 -host 172.27.35.103 -n 1001 -peer_prins "`cat /tmp/prin-*`"

echo "stopping"
sudo tao host stop

#!/bin/bash

echo
date
echo "hosted psk, base server, base client"
echo $0

sudo tao host start -daemon -hosting docker,process
sleep 2

rm -f /tmp/prin-*
tao run hosted_psk_server -save_name /tmp/prin-server
tao run hosted_psk_client -save_name /tmp/prin-client

tao run hosted_psk_server -level 0 -host 172.27.35.103 -n 1001 -peer_prins "`cat /tmp/prin-*`" &
sleep 2

tao run hosted_psk_client -level 0 -host 172.27.35.103 -n 1001 -peer_prins "`cat /tmp/prin-*`"

sudo tao host stop

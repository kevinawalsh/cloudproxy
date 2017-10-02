#!/bin/bash

echo
date
echo "plain tcp, base server, base client"
echo $0

sudo tao host start -daemon -hosting docker,process
sleep 2

tao run standalone_server -host 172.27.35.103 -n 1001 &
sleep 2

tao run standalone_client -host 172.27.35.103 -n 1001

sudo tao host stop

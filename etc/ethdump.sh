#!/bin/bash

# tcpdump -nX -i lo0 port 2389 &
tcpdump -nX -i lo0 port 2389 -w capture.pcap &

sleep 1

nc -l 2389 &
echo 'test' | nc localhost 2389
# ruby -e "print '0' * 2048" | nc localhost 2389

wait # on tcpdump

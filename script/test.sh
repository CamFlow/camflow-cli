#!/bin/bash

camflow -s
sudo camflow -e false
sudo camflow -a true
sudo camflow -a false
sudo camflow --compress-node true
sudo camflow --compress-node false
sudo camflow --compress-edge true
sudo camflow --compress-edge false
echo "===="
echo "FILE"
echo "===="
camflow --file .
sudo camflow --track-file . true
sudo camflow --track-file . false
sudo camflow --label-file . test
sudo camflow --opaque-file . true
sudo camflow --opaque-file . false
echo "======="
echo "PROCESS"
echo "======="
camflow --process 1
sudo camflow --track-process 1 true
sudo camflow --track-process 1 false
sudo camflow --track-process 1 false
sudo camflow --opaque-process 1 true
sudo camflow --opaque-process 1 false
echo "======="
echo "NETWORK"
echo "======="
sudo camflow --track-ipv4-ingress 0.0.0.0/32:0 track
camflow -s
sudo camflow --track-ipv4-ingress 0.0.0.0/32:0 delete
sudo camflow --track-ipv4-egress 0.0.0.0/32:0 track
camflow -s
sudo camflow --track-ipv4-egress 0.0.0.0/32:0 delete
echo "===="
echo "USER"
echo "===="
sudo camflow --track-user root track
camflow -s
sudo camflow --track-user root delete
echo "====="
echo "GROUP"
echo "====="
sudo camflow --track-group root track
camflow -s
sudo camflow --track-group root delete
echo "===="
echo "NODE"
echo "===="
sudo camflow --node-filter file true
camflow -s
sudo camflow --node-filter file false
sudo camflow --node-propagate-filter file true
camflow -s
sudo camflow --node-propagate-filter file false
echo "===="
echo "EDGE"
echo "===="
sudo camflow --edge-filter mmap_read true
camflow -s
sudo camflow --edge-filter mmap_read false
sudo camflow --edge-propagate-filter mmap_read true
camflow -s
sudo camflow --edge-propagate-filter mmap_read false
echo "====="
echo "RESET"
echo "====="
sudo camflow --reset-filter
camflow -s
echo "======="
echo "CHANNEL"
echo "======="
sudo camflow --channel test
echo "===="
echo "LOGS"
echo "===="
echo "Save kernel logs to /tmp/camflow-cli-dmesg.txt"
dmesg > /tmp/camflow-cli-dmesg.txt

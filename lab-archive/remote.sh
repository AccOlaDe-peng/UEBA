#!/bin/bash
# Retry-robust remote exec: remote.sh '<command>'
SSHOPTS="-o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
for i in 1 2 3 4 5 6; do
  sshpass -p 'SA@test11' ssh $SSHOPTS root@10.6.69.21 "$1" && exit 0
  sleep 15
done
exit 1

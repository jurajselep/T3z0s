#!/usr/bin/env sh

set -xeo pipefail

TSHARK_READY=/tmp/tshark.ready
TEZOS_NETWORK=carthagenet

whoami
counter=0
until [ "$counter" -gt 1000 -o -f "$TSHARK_READY" ]; do sleep 1; done
cp -vf /usr/local/T3z0s/configs/identity.json /var/run/tezos/node/data

find / -name identity.json

( sleep 180; ip link set eth0 down ) &
( sleep 300; killall tezos-node ) &
(
    sleep 240;
    wget -O /root/connections.json 'http://localhost:8732/network/connections';
    wget -O /root/points.json 'http://localhost:8732/network/points';
    wget -O /root/peers.json 'http://localhost:8732/network/peers';
) &
/usr/local/bin/entrypoint.sh tezos-node --net-addr :19732 --network "$TEZOS_NETWORK"
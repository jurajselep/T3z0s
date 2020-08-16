#!/usr/bin/env sh

set -xeo pipefail

TSHARK_READY=/tmp/tshark.ready
TEZOS_NETWORK=carthagenet

counter=0
until [ "$counter" -gt 1000 -o -f "$TSHARK_READY" ]; do sleep 1; done
cp -vf /usr/local/Tezos/configs/identity.json /var/run/tezos/node/data

( sleep 180; ip link set eth0 down ) &
( sleep 300; killall tezos-node ) &
(
    sleep 240;

    wget -O /root/connections.json 'http://localhost:8732/network/connections' &&
    cp -v /root/connections.json /tmp/connections.json.tmp &&
    mv -v /tmp/connections.json.tmp /tmp/connections.json;

    wget -O /root/points.json 'http://localhost:8732/network/points' &&
    cp -v /root/points.json /tmp/points.json.tmp &&
    mv -v /tmp/points.json.tmp /tmp/points.json;

    wget -O /root/peers.json 'http://localhost:8732/network/peers' &&
    cp -v /root/peers.json /tmp/peers.json.tmp &&
    mv -v /tmp/peers.json.tmp /tmp/peers.json;
) &
/usr/local/bin/entrypoint.sh tezos-node --net-addr :19732 --network "$TEZOS_NETWORK"

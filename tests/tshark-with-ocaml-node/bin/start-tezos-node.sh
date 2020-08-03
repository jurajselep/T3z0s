#!/usr/bin/env sh

set -xeo pipefail

TSHARK_READY=/tmp/tshark.ready
TEZOS_NETWORK=carthagenet

whoami
counter=0
until [ "$counter" -gt 1000 -o -f "$TSHARK_READY" ]; do sleep 1; done
cp -vf /usr/local/T3z0s/configs/identity.json /var/run/tezos/node/data

find / -name identity.json

( sleep 180; killall tezos-node ) &
/usr/local/bin/entrypoint.sh tezos-node --net-addr :19732 --network "$TEZOS_NETWORK"

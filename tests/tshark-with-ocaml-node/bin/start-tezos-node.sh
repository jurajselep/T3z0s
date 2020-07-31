#!/bin/sh

set -eo pipefail

TSHARK_READY=/tmp/tshark.ready
TEZOS_NETWORK=carthagenet

counter=0
until [ "$counter" -gt 100 -o -f "$TSHARK_READY" ]; do sleep 1; done

/usr/local/bin/entrypoint.sh tezos-node --net-addr :19732 --network "$TEZOS_NETWORK"
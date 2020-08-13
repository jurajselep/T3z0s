#!/usr/bin/env bash

set -xeo pipefail

PATH_TMP="$PWD/tmp/tests/listen-to-tezos-node"
PATH_LOG="$PATH_TMP/logs"

TSHARK_LOG="$PATH_LOG/tshark.err"
TSHARK_OUT="$PATH_LOG/tshark.out"
TEZOS_IDENTITY_FILE=$(realpath tests/configs/identity.json)

TSHARK_BIN=$(realpath 'opt/bin/tshark')

failed_cnt=0

function msg... {
    echo -n "$@" '... '
}

function ok {
    echo OK
}

function fail {
    echo FAILED
    ((failed_cnt++))
}

function try... {
    "$@" >/dev/null 2>/dev/null && ok || fail
}

function wait4file {
    local counter=0
    while [ ! -e "$1" -a "$counter" -lt 120 ]; do
        counter=$((counter+1))
        sleep 1
    done
}

function run_tshark {
    "$TSHARK_BIN" -o tezos.identity_json_file:"$TEZOS_IDENTITY_FILE" -i any -V >"$TSHARK_OUT" 2>"$TSHARK_LOG"&
    local pid="$!"

    local counter=0
    while [ "$counter" -lt 100 ]; do
        check_pid_exists "$pid" || return 1
        grep 2>/dev/null >/dev/null 'Capturing on' "$TSHARK_LOG" && break
        counter=$((counter+1))
        sleep .1
    done

    # tshark needs some time to load modules
    local counter=0
    local prev_md5=invalidmd5
    while [ "$counter" -lt 100 ]; do
        check_pid_exists "$pid"
        local md5=$(cat "/proc/$pid/maps" | awk '{print$6}' | md5sum | awk '{print$1}')
        [ "$md5" == "$prev_md5" ] && grep >/dev/null 'tezos[.]so' "/proc/$pid/maps" && break
        prev_md5="$md5"
        counter=$((counter+1))
        sleep .1
    done

    return 0
}

function check_pid_exists {
    if kill -0 "$1" >/dev/null 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Init

mkdir -p "$PATH_TMP"
mkdir -p "$PATH_LOG"

# Wait until identity.json appears
cp -v "$TEZOS_IDENTITY_FILE" /var/run/tezos/node/identity.json 
counter=0
while [ ! -e "$TEZOS_IDENTITY_FILE" -a "$counter" -lt 100 ]; do
    counter=$((counter+1))
    sleep 1
done

# Run tshark
run_tshark
: >/tmp/tshark.ready
minutes=5
echo >&2 "Will listen to network for $minutes minutes"
sleep $((60*minutes))

# Check that there are expected peer responses in the tshark output.
msg... 'Looking for Tezos replies in tshark output'
try... grep 'Tezos Decrypted Msg: "peerresponse:PeerMessageResponse' "$TSHARK_OUT"

cp -v "$TSHARK_OUT" '/tmp/tshark.out'
wait4file '/tmp/peers.json'
wait4file '/tmp/connections.json'
if ! tests/tshark-with-ocaml-node/bin/cmp-json-and-tshark; then
    ((failed_cnt++))
fi

if [ "$failed_cnt" -eq 0 ]; then
    echo "$0: Tests passed :-)"
else
    echo "$0: Tests failed :-("
    exit 1
fi
#!/usr/bin/env bash

# Links:
#   - How to kill all subprocesses of a shell:
#     https://stackoverflow.com/questions/2618403/how-to-kill-all-subprocesses-of-shell
#   - How to run a command before a Bash script exits:
#     https://stackoverflow.com/questions/2129923/how-to-run-a-command-before-a-bash-script-exits

set -eo pipefail

PATH_TMP="$PWD/tmp/tests/tshark-over-pcap"
PATH_LOG="$PATH_TMP/logs"

TSHARK_LOG="$PATH_LOG/tshark.err"
TSHARK_OUT="$PATH_LOG/tshark.out"
TEZOS_IDENTITY_FILE=$(realpath tests/configs/identity.json)

PATH_PCAP=$(realpath "tests/data/cap-09.pcap")

TSHARK_BIN=$(realpath 'opt/bin/tshark')

function msg... {
    echo -n "$@" '... '
}

function ok {
    echo OK
}

function fail {
    echo FAILED
    exit 1
}

function try... {
    "$@" >/dev/null 2>/dev/null && ok || fail
}

function run_tshark {
    "$TSHARK_BIN" -o \
        tezos.identity_json_file:"$TEZOS_IDENTITY_FILE" \
        -Vr "$PATH_PCAP" >"$TSHARK_OUT" 2>"$TSHARK_LOG"
}

# Init

mkdir -p "$PATH_TMP"
mkdir -p "$PATH_LOG"

run_tshark

# Check that there is peer response in the tshark output.

msg... 'Looking for Tezos replies in tshark output'
try... grep 'Tezos Decrypted Msg: "peerresponse:PeerMessageResponse' "$TSHARK_OUT"

msg... 'Looking for Tezos replies at the end of the tshark output'
try... grep 'Tezos Decrypted Msg: "peerresponse:PeerMessageResponse' <(tail "$TSHARK_OUT")

echo "$0: Tests passed :-)"
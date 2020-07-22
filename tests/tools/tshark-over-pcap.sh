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
T3Z0S_IDENTITY_FILE=$(realpath tests/configs/identity.json)

PATH_PCAP=$(realpath "tests/data/cap-09.pcap")

TSHARK_BIN=$(realpath 'opt/bin/tshark')

function run_tshark {
    "$TSHARK_BIN" -o \
        t3z0s.identity_json_file:"$T3Z0S_IDENTITY_FILE" \
        -Vr "$PATH_PCAP" >"$TSHARK_OUT" 2>"$TSHARK_LOG"
}

# Init

mkdir -p "$PATH_TMP"
mkdir -p "$PATH_LOG"

run_tshark

# Check that there is peer response in the tshatrk output.
grep 'T3z0s Decrypted Msg: "peerresponse:PeerMessageResponse' "$TSHARK_OUT" >/dev/null 2>/dev/null
tail "$TSHARK_OUT" | grep 'T3z0s Decrypted Msg: "peerresponse:PeerMessageResponse' >/dev/null 2>/dev/null

echo "$0: Tests passed :-)"
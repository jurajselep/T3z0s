#!/usr/bin/env bash

# Links:
#   - How to kill all subprocesses of a shell:
#     https://stackoverflow.com/questions/2618403/how-to-kill-all-subprocesses-of-shell
#   - How to run a command before a Bash script exits:
#     https://stackoverflow.com/questions/2129923/how-to-run-a-command-before-a-bash-script-exits

# FIXME: It is necessary to run script as a root or as a member of a wireshark group.

set -eo pipefail

PATH_LOG="$PWD/tmp/tests/srv-cli-tshark/logs"

DRONE_SRV_PID=0
DRONE_SRV_LOG="$PATH_LOG/drone-srv.err"
DRONE_SRV_OUT="$PATH_LOG/drone-srv.out"

DRONE_CLI_PID=0
DRONE_CLI_LOG="$PATH_LOG/drone-cli.err"
DRONE_CLI_OUT="$PATH_LOG/drone-cli.out"

TSHARK_SRV_PID=0
TSHARK_SRV_LOG="$PATH_LOG/tshark-srv.err"
TSHARK_SRV_OUT="$PATH_LOG/tshark-srv.out"

TSHARK_CLI_PID=0
TSHARK_CLI_LOG="$PATH_LOG/tshark-cli.err"
TSHARK_CLI_OUT="$PATH_LOG/tshark-cli.out"

DRONE_SERVER_BIN=$(realpath 'tezedge-debugger/bin/drone-server')
DRONE_CLIENT_BIN=$(realpath 'tezedge-debugger/bin/drone-client')
TSHARK_BIN=$(realpath 'wireshark/build/run/tshark')

T3Z0S_IDENTITY_FILE_SRV=$(realpath tests/configs/identity-server.json)
T3Z0S_IDENTITY_FILE_CLI=$(realpath tests/configs/identity-client.json)

function cleanup {
    counter=0
    while
        local pids="$(jobs -p | tr '\n' ' ')"
        [ ! -z "$pids" ]
    do
        if [ "$counter" -gt 3 ]; then
            kill -9 "$pids" || true
        else
            kill "$pids" || true
        fi
        wait "$pids"

        counter=$((counter + 1))
    done
}

function start_srv {
    local -n ret="$1"

    "$DRONE_SERVER_BIN" >"$DRONE_SRV_OUT" 2>"$DRONE_SRV_LOG"&
    ret="$!"
}

function stop_srv {
    local srv_pid="$1"
    kill "$srv_pid"
    ! wait "$srv_pid" # FIXME: Why does drone-server exit with error?
}

function start_cli {
    local -n ret="$1"

    "$DRONE_CLIENT_BIN" -c 100 -m 1000 >"$DRONE_CLI_OUT" 2>"$DRONE_CLI_LOG"&
    ret="$!"
}

function wait_for_client {
    local client_pid="$1"

    local prev_size
    wait "$client_pid"

    for tshark_out in "$TSHARK_SRV_OUT" "$TSHARK_CLI_OUT"; do
        file_size prev_size "$tshark_out"

        while
            local size
            file_size size "$tshark_out"
            [ "$prev_size" -lt "$size" ]
        do
            prev_size="$size"
            sleep .5
        done
    done
}

function start_tshark {
    local -n ret="$1"
    local role=$([[ "$1" == *CLI* ]] && echo -n 'client' || echo -n 'server')

    local identity_file="$T3Z0S_IDENTITY_FILE_SRV"
    local out_file="$TSHARK_SRV_OUT"
    local err_file="$TSHARK_SRV_LOG"
    if [ "$role" == 'client' ]; then
        identity_file="$T3Z0S_IDENTITY_FILE_CLI"
        out_file="$TSHARK_CLI_OUT"
        err_file="$TSHARK_CLI_LOG"
    fi

    "$TSHARK_BIN" -o t3z0s.identity_json_file:"$identity_file" -i lo -V >"$out_file" 2>"$err_file"&
    local pid="$!"

    local counter=0
    while [ "$counter" -lt 100 ]; do
        check_pid_exists "$pid" || return 1
        grep 2>/dev/null >/dev/null 'Capturing on' "$err_file" && break
        counter=$((counter+1))
        sleep .1
    done
    ret="$pid"
    return 0
}

function stop_tshark {
    local tshark_pid="$1"
    kill "$tshark_pid"
    wait "$tshark_pid"
}

function check_pid_exists {
    if kill -0 "$1" >/dev/null 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

function file_size {
    local -n ret="$1"
    local file_path="$2"

    ret=$(stat -c%s "$file_path")
}

# Init

trap cleanup EXIT
mkdir -p "$PATH_LOG"

start_tshark TSHARK_SRV_PID
start_tshark TSHARK_CLI_PID
start_srv DRONE_SRV_PID
start_cli DRONE_CLI_PID

wait_for_client "$DRONE_CLI_PID"
stop_tshark "$TSHARK_SRV_PID"
stop_tshark "$TSHARK_CLI_PID"
stop_srv "$DRONE_SRV_PID"

for out_file in "$TSHARK_SRV_OUT" "$TSHARK_CLI_OUT"; do
    # Check that there is peer response in the tsharks outputs.
    grep 'T3z0s Decrypted Msg: "peerresponse:PeerMessageResponse' "$out_file" >/dev/null 2>/dev/null
    tail "$out_file" | grep 'T3z0s Decrypted Msg: "peerresponse:PeerMessageResponse' >/dev/null 2>/dev/null
done

echo "$0: Tests passed :-)"
#!/bin/bash

usage() {
    echo "Usage: ./banhammer.sh [ban|unban] [-p, --port PORT] [-w, --word WORD]
       ./banhammer.sh list"
    exit 2
}

parse_args() {
    while [[ "$#" -gt 0 ]]; do case $1 in
        -p | --port)
            PORT="$2"
            shift 2
            ;;
        -w | --word)
            WORD="$2"
            shift 2
            ;;
        -n)
            NUMBER="$2"
            shift 2
            ;;
        *) usage "Unknown parameter passed: $1" ;;
        esac done
}

ban() {
    parse_args "$@"
    iptables -A INPUT -m string --algo bm --string "$WORD" -p tcp --dport "$PORT" -j DROP
}

unban() {
    parse_args "$@"

    if [ "$NUMBER" -gt 0 ]; then
        sed_line=$(("$NUMBER"+1))
        port_and_word=($(list | sed -n "$sed_line"p | awk -F\| '{print $2, $3}' | xargs))
        PORT="${port_and_word[0]}"
        WORD="${port_and_word[1]}"
    fi

    iptables -D INPUT -m string --algo bm --string "$WORD" -p tcp --dport "$PORT" -j DROP
}

list() {
    iptables -L | grep "STRING match" | awk 'BEGIN {print " № port word" }; {gsub(/"/, "", $8); gsub(/dpt:/, "", $15); print ((++n)), $15, $8}' | column -t -o ' | '
}

ACTION="$1"

case "$ACTION" in
ban)
    shift
    ban "$@"
    ;;

unban)
    shift
    unban "$@"
    ;;

list)
    list
    ;;

*)
    usage
    ;;
esac

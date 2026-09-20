#!/bin/bash
# Title: Home WiFi Watch
# Description: Passive beacon monitor for new APs and changed WiFi identities/security
# Author: Jan / Codex
# Version: 1.5
# Category: Reconnaissance

# Pager may execute a temporary copy as /tmp/payload.sh. Locate companion files
# from the launch directory first, then from the standard Pager install paths.
RUNNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_DIR=""
for CANDIDATE_DIR in \
    "$PWD" \
    "$RUNNER_DIR" \
    "/mmc/root/payloads/user/reconnaissance/home_wifi_watch" \
    "/root/payloads/user/reconnaissance/home_wifi_watch"; do
    if [ -f "$CANDIDATE_DIR/watch.py" ] && [ -f "$CANDIDATE_DIR/config.sh" ]; then
        SCRIPT_DIR="$CANDIDATE_DIR"
        break
    fi
done
if [ -z "$SCRIPT_DIR" ]; then
    LOG red "Cannot locate watch.py and config.sh; runner=$RUNNER_DIR pwd=$PWD"
    ERROR_DIALOG "Cannot locate Home WiFi Watch companion files. Recopy the complete payload directory."
    exit 1
fi
. "$SCRIPT_DIR/config.sh"
umask 077
cleanup() {
    if [ -n "${WORKER_PID:-}" ]; then
        kill "$WORKER_PID" 2>/dev/null
        wait "$WORKER_PID" 2>/dev/null
    fi
    LED OFF
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for dependency in python3 tcpdump iw; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        ERROR_DIALOG "Missing $dependency. See Home WiFi Watch README."
        exit 1
    fi
done
find_monitor_interface() {
    # Respect an explicit setting when it really is a monitor interface.
    if [ -n "$INTERFACE" ] && iw dev "$INTERFACE" info 2>/dev/null |
        awk '$1 == "type" && tolower($2) == "monitor" {found=1} END {exit !found}'; then
        printf '%s\n' "$INTERFACE"
        return 0
    fi

    # Interface numbering differs between firmware/radio configurations.
    iw dev 2>/dev/null | awk '
        $1 == "Interface" {interface=$2}
        $1 == "type" && tolower($2) == "monitor" {print interface; exit}
    '
}

DETECTED_INTERFACE=$(find_monitor_interface)
if [ -z "$DETECTED_INTERFACE" ]; then
    AVAILABLE_INTERFACES=$(iw dev 2>/dev/null | awk '
        $1 == "Interface" {interface=$2}
        $1 == "type" {list=list interface " (" $2 "), "}
        END {sub(/, $/, "", list); print list}
    ')
    [ -z "$AVAILABLE_INTERFACES" ] && AVAILABLE_INTERFACES="none reported by iw"
    LOG red "No monitor interface. iw reports: $AVAILABLE_INTERFACES"
    ERROR_DIALOG "No monitor interface found. Start passive Recon, then retry. See payload log for interfaces."
    exit 1
fi
INTERFACE="$DETECTED_INTERFACE"
if [ -z "${STATE_DIR:-}" ]; then
    STATE_DIR="/root/loot/home_wifi_watch"
fi
MKDIR_ERROR=$(mkdir -p "$STATE_DIR" 2>&1)
if [ $? -ne 0 ]; then
    PRIMARY_STATE_DIR="$STATE_DIR"
    STATE_DIR="$SCRIPT_DIR/data"
    FALLBACK_ERROR=$(mkdir -p "$STATE_DIR" 2>&1)
    if [ $? -ne 0 ]; then
        DETAIL="$PRIMARY_STATE_DIR: $MKDIR_ERROR; $STATE_DIR: $FALLBACK_ERROR"
        DETAIL=$(printf '%s' "$DETAIL" | cut -c1-180)
        LOG red "Cannot create state directory: $DETAIL"
        ERROR_DIALOG "Cannot create data directory: $DETAIL"
        exit 1
    fi
    LOG yellow "Cannot use $PRIMARY_STATE_DIR; saving data in $STATE_DIR"
fi
RUNTIME_LOG="$STATE_DIR/runtime.log"
if ! python3 -c 'import argparse, collections, fcntl, json, os, pathlib, queue, selectors, signal, struct, subprocess, threading, time' >"$RUNTIME_LOG" 2>&1; then
    DETAIL=$(tail -n 2 "$RUNTIME_LOG" 2>/dev/null | tr '\n' ' ' | cut -c1-180)
    [ -z "$DETAIL" ] && DETAIL="Python standard-library import failed"
    LOG red "$DETAIL"
    ERROR_DIALOG "Python is incomplete: $DETAIL"
    exit 1
fi
LED SETUP
LOG cyan "Home WiFi Watch: $INTERFACE, threshold $MIN_RSSI dBm"
LOG yellow "Coverage follows this radio's channel. Use passive Recon hopping for multiple channels."
LOG "First run learns for 60s. Saved baseline is reused. Stop via payload controls."
python3 "$SCRIPT_DIR/watch.py" --interface "$INTERFACE" --directory "$STATE_DIR" \
    --threshold "$MIN_RSSI" --confirm-window "$CONFIRM_WINDOW" \
    --confirm-count "$CONFIRM_COUNT" --cooldown "$ALERT_COOLDOWN" >"$RUNTIME_LOG" 2>&1 &
WORKER_PID=$!
wait "$WORKER_PID"
result=$?
WORKER_PID=""
if [ "$result" -ne 0 ]; then
    DETAIL=$(tail -n 3 "$RUNTIME_LOG" 2>/dev/null | tr '\n' ' ' | cut -c1-180)
    [ -z "$DETAIL" ] && DETAIL="unknown error (exit $result)"
    LOG red "WiFi Watch failed: $DETAIL"
    ERROR_DIALOG "WiFi Watch failed: $DETAIL"
fi
exit "$result"

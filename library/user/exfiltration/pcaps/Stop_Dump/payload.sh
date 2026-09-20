#!/bin/bash
# Title: Stop Full Dump PCAP Capture
# Author: Janek
# Description: Stops full dump PCAP capture and reports the file location, interface, size, and tcpdump stats.
# Version: 1.1

PID_FILE="/tmp/pcap_full.pid"
PATH_FILE="/tmp/pcap_full.path"
IFACE_FILE="/tmp/pcap_full.iface"
LOG_FILE="/tmp/pcap_full.log"

if [ ! -f "$PID_FILE" ]; then
    ERROR_DIALOG "Brak aktywnego capture!\n(brak $PID_FILE)"
    exit 1
fi

TCPDUMP_PID=$(cat "$PID_FILE" 2>/dev/null)
PCAP_FILE=$(cat "$PATH_FILE" 2>/dev/null)
CAP_IFACE=$(cat "$IFACE_FILE" 2>/dev/null)
[ -z "$CAP_IFACE" ] && CAP_IFACE="unknown"

stop_tcpdump() {
    local pid="$1"
    local signal="$2"
    local tries="$3"
    local delay="$4"

    kill "-$signal" "$pid" 2>/dev/null || return 1

    while [ "$tries" -gt 0 ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        sleep "$delay"
        tries=$((tries - 1))
    done

    return 1
}

if [ -n "$TCPDUMP_PID" ] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    stop_tcpdump "$TCPDUMP_PID" "INT" 3 1 || \
        stop_tcpdump "$TCPDUMP_PID" "TERM" 2 1 || \
        kill -KILL "$TCPDUMP_PID" 2>/dev/null
    wait "$TCPDUMP_PID" 2>/dev/null || true
else
    LOG yellow "tcpdump PID nie jest aktywny: $TCPDUMP_PID"
fi

CAPTURED=$(grep -i "packets captured" "$LOG_FILE" 2>/dev/null | tail -n 1)
RECEIVED=$(grep -i "packets received by filter" "$LOG_FILE" 2>/dev/null | tail -n 1)
DROPPED=$(grep -i "packets dropped by kernel" "$LOG_FILE" 2>/dev/null | tail -n 1)

# Raport
if [ -f "$PCAP_FILE" ]; then
    SIZE=$(du -sh "$PCAP_FILE" | cut -f1)
    [ -f "$LOG_FILE" ] && cp "$LOG_FILE" "${PCAP_FILE}.log" 2>/dev/null

    ALERT_MSG="FULL PCAP STOP\nInterface: $CAP_IFACE\nPlik: $PCAP_FILE\nRozmiar: $SIZE"
    [ -n "$DROPPED" ] && ALERT_MSG="$ALERT_MSG\n$DROPPED"

    ALERT "$ALERT_MSG"
    LOG red "tcpdump zatrzymany. Interface=$CAP_IFACE Plik=$PCAP_FILE ($SIZE)"
    [ -n "$CAPTURED" ] && LOG yellow "$CAPTURED"
    [ -n "$RECEIVED" ] && LOG yellow "$RECEIVED"
    [ -n "$DROPPED" ] && LOG yellow "$DROPPED"
    [ -f "${PCAP_FILE}.log" ] && LOG yellow "tcpdump log: ${PCAP_FILE}.log"
else
    TCPDUMP_ERROR=$(tail -n 5 "$LOG_FILE" 2>/dev/null)
    ERROR_DIALOG "Plik PCAP nie istnieje!\nCoś poszło nie tak.\n$TCPDUMP_ERROR"
fi

# Cleanup
rm -f "$PID_FILE" "$PATH_FILE" "$IFACE_FILE" "$LOG_FILE"

#!/bin/bash
# Title: Start Full Dump PCAP Capture
# Author: Janek
# Description: Starts full dump PCAP capture and saves the file location and PID for later stopping.
# Version: 1.2

LOOT_DIR="/root/loot/pcap"
PID_FILE="/tmp/pcap_full.pid"
PATH_FILE="/tmp/pcap_full.path"
IFACE_FILE="/tmp/pcap_full.iface"
LOG_FILE="/tmp/pcap_full.log"

mkdir -p "$LOOT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="$LOOT_DIR/full_traffic_${TIMESTAMP}.pcap"

is_tcpdump_running() {
    local pid="$1"

    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null || return 1

    (ps w 2>/dev/null || ps 2>/dev/null) | awk -v pid="$pid" '
        $1 == pid && /[t]cpdump/ { found = 1 }
        END { exit(found ? 0 : 1) }
    '
}

iface_exists() {
    local iface="$1"

    [ "$iface" = "any" ] && return 0
    [ -d "/sys/class/net/$iface" ] || ip link show "$iface" >/dev/null 2>&1
}

iface_is_up() {
    local iface="$1"

    [ "$iface" = "any" ] && return 0
    ip link show "$iface" 2>/dev/null | grep -q "UP"
}

iface_has_ipv4() {
    local iface="$1"

    ip -4 addr show dev "$iface" 2>/dev/null | grep -q "inet " && return 0
    ifconfig "$iface" 2>/dev/null | grep -q "inet " && return 0
    return 1
}

tcpdump_supports_iface_any() {
    tcpdump -D 2>/dev/null | grep -Eq '(^|[0-9]+\.)any([[:space:]]|$|\()'
}

tcpdump_supports_option() {
    local option="$1"

    tcpdump -h 2>&1 | grep -Fq -- "$option"
}

add_candidate() {
    local iface="$1"
    local label="$2"

    CANDIDATE_IFACES+=("$iface")
    CANDIDATE_LABELS+=("$label")
}

if ! command -v tcpdump >/dev/null 2>&1; then
    ERROR_DIALOG "tcpdump nie jest zainstalowany!"
    exit 1
fi

if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null)
    if is_tcpdump_running "$OLD_PID"; then
        OLD_PATH=$(cat "$PATH_FILE" 2>/dev/null)
        OLD_IFACE=$(cat "$IFACE_FILE" 2>/dev/null)
        [ -z "$OLD_IFACE" ] && OLD_IFACE="unknown"
        ALERT "FULL PCAP ACTIVE\nInterface: $OLD_IFACE\nPlik:\n$OLD_PATH\nPID: $OLD_PID"
        LOG yellow "PCAP capture juz dziala PID=$OLD_PID -> $OLD_PATH"
        exit 0
    fi

    rm -f "$PID_FILE" "$PATH_FILE" "$IFACE_FILE" "$LOG_FILE"
fi

CANDIDATE_IFACES=()
CANDIDATE_LABELS=()

if iface_exists "br-evil" && iface_is_up "br-evil"; then
    add_candidate "br-evil" "br-evil (MITM / evil bridge)"
fi

if iface_exists "br-lan" && iface_is_up "br-lan"; then
    add_candidate "br-lan" "br-lan (LAN / client bridge)"
fi

if iface_exists "wlan0cli" && iface_has_ipv4 "wlan0cli"; then
    add_candidate "wlan0cli" "wlan0cli (client uplink)"
fi

if tcpdump_supports_iface_any; then
    add_candidate "any" "any (all L3 interfaces)"
fi

if [ "${#CANDIDATE_IFACES[@]}" -eq 0 ]; then
    ERROR_DIALOG "Brak aktywnego interfejsu do PCAP!\nUruchom MITM/bridge albo polacz wlan0cli."
    exit 1
fi

MENU="Wybierz interface PCAP:\n"
for i in "${!CANDIDATE_LABELS[@]}"; do
    MENU="${MENU}\n$((i + 1))) ${CANDIDATE_LABELS[$i]}"
done
MENU="${MENU}\n\nUwaga: ten tryb pasywny widzi tylko ruch do/z/przez Pineapple. Ruch innego klienta tej samej zewnetrznej sieci WiFi wymaga MITM Dump."

PROMPT "$MENU"
SELECTION=$(NUMBER_PICKER "Interface number" "1")
PICKER_STATUS=$?
case "$PICKER_STATUS" in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
        LOG yellow "PCAP capture cancelled"
        exit 0
        ;;
esac

case "$SELECTION" in
    ''|*[!0-9]*)
        SELECTION=1
        ;;
esac

if [ "$SELECTION" -lt 1 ] || [ "$SELECTION" -gt "${#CANDIDATE_IFACES[@]}" ]; then
    SELECTION=1
fi

CAP_IFACE="${CANDIDATE_IFACES[$((SELECTION - 1))]}"
PCAP_FILE="$LOOT_DIR/full_traffic_${CAP_IFACE}_${TIMESTAMP}.pcap"

TCPDUMP_ARGS=(-i "$CAP_IFACE" -s 0)
if tcpdump_supports_option "-B"; then
    TCPDUMP_ARGS+=(-B 4096)
fi
if tcpdump_supports_option "-U"; then
    TCPDUMP_ARGS+=(-U)
fi
TCPDUMP_ARGS+=(-w "$PCAP_FILE" -n)

: > "$LOG_FILE"
tcpdump "${TCPDUMP_ARGS[@]}" 2>"$LOG_FILE" &
TCPDUMP_PID=$!
sleep 1

if ! is_tcpdump_running "$TCPDUMP_PID"; then
    TCPDUMP_ERROR=$(tail -n 5 "$LOG_FILE" 2>/dev/null)
    rm -f "$PID_FILE" "$PATH_FILE" "$IFACE_FILE"
    ERROR_DIALOG "tcpdump nie wystartowal!\n$TCPDUMP_ERROR"
    LOG red "tcpdump failed on $CAP_IFACE: $TCPDUMP_ERROR"
    exit 1
fi

echo "$TCPDUMP_PID" > "$PID_FILE"
echo "$PCAP_FILE" > "$PATH_FILE"
echo "$CAP_IFACE" > "$IFACE_FILE"

ALERT "FULL PCAP START\nInterface: $CAP_IFACE\nPlik:\n$PCAP_FILE\nPID: $TCPDUMP_PID"
LOG green "tcpdump uruchomiony PID=$TCPDUMP_PID -> $PCAP_FILE"

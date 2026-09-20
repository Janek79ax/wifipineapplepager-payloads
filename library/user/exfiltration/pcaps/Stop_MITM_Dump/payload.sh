#!/bin/bash
# Title: Stop MITM Dump PCAP Capture
# Author: Janek
# Description: Stops ARP MITM PCAP capture and restores forwarding/QUIC state.
# Version: 1.0

STATE_PREFIX="/tmp/pcap_mitm"

TCPDUMP_PID_FILE="${STATE_PREFIX}.tcpdump.pid"
ARP_TARGET_PID_FILE="${STATE_PREFIX}.arp_target.pid"
ARP_GATEWAY_PID_FILE="${STATE_PREFIX}.arp_gateway.pid"
PATH_FILE="${STATE_PREFIX}.path"
IFACE_FILE="${STATE_PREFIX}.iface"
TARGET_FILE="${STATE_PREFIX}.target"
GATEWAY_FILE="${STATE_PREFIX}.gateway"
IP_FORWARD_FILE="${STATE_PREFIX}.ip_forward"
QUIC_FILE="${STATE_PREFIX}.quic"
FORWARD_RULES_FILE="${STATE_PREFIX}.forward_rules"
POISON_TOOL_FILE="${STATE_PREFIX}.poison_tool"
TCPDUMP_LOG="${STATE_PREFIX}.tcpdump.log"
ARP_TARGET_LOG="${STATE_PREFIX}.arp_target.log"
ARP_GATEWAY_LOG="${STATE_PREFIX}.arp_gateway.log"

if [ ! -f "$TCPDUMP_PID_FILE" ] && [ ! -f "$ARP_TARGET_PID_FILE" ] && [ ! -f "$ARP_GATEWAY_PID_FILE" ]; then
    ERROR_DIALOG "Brak aktywnego MITM capture!\n(brak /tmp/pcap_mitm.* pid)"
    exit 1
fi

TCPDUMP_PID=$(cat "$TCPDUMP_PID_FILE" 2>/dev/null)
PCAP_FILE=$(cat "$PATH_FILE" 2>/dev/null)
IFACE=$(cat "$IFACE_FILE" 2>/dev/null)
TARGET_LIST=$(cat "$TARGET_FILE" 2>/dev/null)
GATEWAY_IP=$(cat "$GATEWAY_FILE" 2>/dev/null)
POISON_TOOL=$(cat "$POISON_TOOL_FILE" 2>/dev/null)

[ -z "$IFACE" ] && IFACE="wlan0cli"
[ -z "$TARGET_LIST" ] && TARGET_LIST="unknown"
TARGET_COUNT=$(printf "%s\n" "$TARGET_LIST" | grep -c . 2>/dev/null)
TARGET_DISPLAY=$(printf "%s\n" "$TARGET_LIST" | tr '\n' ',' | sed 's/,$//')
[ -z "$GATEWAY_IP" ] && GATEWAY_IP="unknown"
[ -z "$POISON_TOOL" ] && POISON_TOOL="unknown"

stop_pid() {
    local pid="$1"
    local signal="$2"
    local tries="$3"

    [ -n "$pid" ] || return 0
    kill -0 "$pid" 2>/dev/null || return 0
    kill "-$signal" "$pid" 2>/dev/null || return 0

    while [ "$tries" -gt 0 ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        sleep 1
        tries=$((tries - 1))
    done

    return 1
}

stop_pid_file() {
    local pid_file="$1"
    local signal="$2"
    local tries="$3"
    local pid

    [ -f "$pid_file" ] || return 0
    while IFS= read -r pid; do
        [ -n "$pid" ] || continue
        stop_pid "$pid" "$signal" "$tries" || kill -KILL "$pid" 2>/dev/null
    done < "$pid_file"
}

remove_quic_block() {
    [ -f "$QUIC_FILE" ] || return 0
    QUIC_METHOD=$(cat "$QUIC_FILE" 2>/dev/null)
    local target_ip

    case "$QUIC_METHOD" in
        nft)
            nft delete table inet pcap_mitm_quic 2>/dev/null || true
            LOG green "Removed nft QUIC block"
            ;;
        iptables)
            [ -f "$TARGET_FILE" ] || return 0
            while IFS= read -r target_ip; do
                [ -n "$target_ip" ] || continue
                iptables -D FORWARD -s "$target_ip" -p udp --dport 443 -j DROP 2>/dev/null || true
            done < "$TARGET_FILE"
            LOG green "Removed iptables QUIC block"
            ;;
    esac
}

remove_forward_rules() {
    [ -f "$FORWARD_RULES_FILE" ] || return 0
    FW_METHOD=$(cat "$FORWARD_RULES_FILE" 2>/dev/null)
    local target_ip

    case "$FW_METHOD" in
        iptables)
            [ -f "$TARGET_FILE" ] || return 0
            while IFS= read -r target_ip; do
                [ -n "$target_ip" ] || continue
                iptables -D FORWARD -o "$IFACE" -d "$target_ip" -j ACCEPT 2>/dev/null || true
                iptables -D FORWARD -i "$IFACE" -s "$target_ip" -j ACCEPT 2>/dev/null || true
            done < "$TARGET_FILE"
            LOG green "Removed temporary FORWARD rules"
            ;;
    esac
}

restore_ip_forward() {
    [ -f "$IP_FORWARD_FILE" ] || return 0
    OLD_FORWARD=$(cat "$IP_FORWARD_FILE" 2>/dev/null)

    case "$OLD_FORWARD" in
        0|1)
            echo "$OLD_FORWARD" > /proc/sys/net/ipv4/ip_forward 2>/dev/null
            LOG green "Restored ip_forward=$OLD_FORWARD"
            ;;
    esac
}

LOG "Stopping MITM poisoning ($POISON_TOOL)..."
stop_pid_file "$ARP_TARGET_PID_FILE" TERM 2
stop_pid_file "$ARP_GATEWAY_PID_FILE" TERM 2
sleep 1

LOG "Stopping tcpdump..."
stop_pid "$TCPDUMP_PID" INT 3 || stop_pid "$TCPDUMP_PID" TERM 2 || kill -KILL "$TCPDUMP_PID" 2>/dev/null
wait "$TCPDUMP_PID" 2>/dev/null || true

remove_quic_block
remove_forward_rules
restore_ip_forward

CAPTURED=$(grep -i "packets captured" "$TCPDUMP_LOG" 2>/dev/null | tail -n 1)
RECEIVED=$(grep -i "packets received by filter" "$TCPDUMP_LOG" 2>/dev/null | tail -n 1)
DROPPED=$(grep -i "packets dropped by kernel" "$TCPDUMP_LOG" 2>/dev/null | tail -n 1)

if [ -f "$PCAP_FILE" ]; then
    SIZE=$(du -sh "$PCAP_FILE" | cut -f1)
    [ -f "$TCPDUMP_LOG" ] && cp "$TCPDUMP_LOG" "${PCAP_FILE}.log" 2>/dev/null
    [ -f "$ARP_TARGET_LOG" ] && cp "$ARP_TARGET_LOG" "${PCAP_FILE}.arp_target.log" 2>/dev/null
    [ -f "$ARP_GATEWAY_LOG" ] && cp "$ARP_GATEWAY_LOG" "${PCAP_FILE}.arp_gateway.log" 2>/dev/null

    ALERT_MSG="MITM PCAP STOP\nTargets: $TARGET_COUNT\nGateway: $GATEWAY_IP\nPoison: $POISON_TOOL\nPlik: $PCAP_FILE\nRozmiar: $SIZE"
    [ -n "$DROPPED" ] && ALERT_MSG="$ALERT_MSG\n$DROPPED"

    ALERT "$ALERT_MSG"
    LOG red "MITM Dump stopped. targets=$TARGET_DISPLAY gateway=$GATEWAY_IP poison=$POISON_TOOL pcap=$PCAP_FILE ($SIZE)"
    [ -n "$CAPTURED" ] && LOG yellow "$CAPTURED"
    [ -n "$RECEIVED" ] && LOG yellow "$RECEIVED"
    [ -n "$DROPPED" ] && LOG yellow "$DROPPED"
else
    TCPDUMP_ERROR=$(tail -n 5 "$TCPDUMP_LOG" 2>/dev/null)
    ERROR_DIALOG "MITM PCAP file missing!\n$TCPDUMP_ERROR"
fi

rm -f "$TCPDUMP_PID_FILE" "$ARP_TARGET_PID_FILE" "$ARP_GATEWAY_PID_FILE"
rm -f "$PATH_FILE" "$IFACE_FILE" "$TARGET_FILE" "$GATEWAY_FILE"
rm -f "$IP_FORWARD_FILE" "$QUIC_FILE" "$FORWARD_RULES_FILE" "$POISON_TOOL_FILE"
rm -f "$TCPDUMP_LOG" "$ARP_TARGET_LOG" "$ARP_GATEWAY_LOG"

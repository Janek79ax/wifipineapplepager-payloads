#!/bin/bash
# Title: Start Full Dump PCAP Capture
# Author: Janek
# Description: Starts full dump PCAP capture and saves the file location and PID for later stopping.
# Version: 1.0

LOOT_DIR="/root/loot/pcap"
mkdir -p "$LOOT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="$LOOT_DIR/full_traffic_${TIMESTAMP}.pcap"

# Sprawdź czy wlan0cli jest aktywny (client mode)
if ! ifconfig wlan0cli 2>/dev/null | grep -q "inet "; then
    ERROR_DIALOG "wlan0cli nie ma IP!\nPodłącz się najpierw do sieci WiFi."
    exit 1
fi

# Uruchom tcpdump w tle
tcpdump -i wlan0cli -w "$PCAP_FILE" -n &
TCPDUMP_PID=$!

# Zapisz PID do pliku żeby payload stop mógł go zabić
echo "$TCPDUMP_PID" > /tmp/pcap_full.pid
echo "$PCAP_FILE" > /tmp/pcap_full.path

ALERT "FULL PCAP START\nInterface: wlan0cli\nPlik:\n$PCAP_FILE\nPID: $TCPDUMP_PID"
LOG green "tcpdump uruchomiony PID=$TCPDUMP_PID -> $PCAP_FILE"

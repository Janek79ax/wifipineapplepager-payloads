#!/bin/bash
# Title: Stop Full Dump PCAP Capture
# Author: Janek
# Description: Stops full dump PCAP capture started by startDump.sh and reports the file location and size.
# Version: 1.0

if [ ! -f /tmp/pcap_full.pid ]; then
    ERROR_DIALOG "Brak aktywnego capture!\n(brak /tmp/pcap_full.pid)"
    exit 1
fi

TCPDUMP_PID=$(cat /tmp/pcap_full.pid)
PCAP_FILE=$(cat /tmp/pcap_full.path)

# Zatrzymaj tcpdump
kill "$TCPDUMP_PID" 2>/dev/null
sleep 1

# Cleanup
rm -f /tmp/pcap_full.pid /tmp/pcap_full.path

# Raport
if [ -f "$PCAP_FILE" ]; then
    SIZE=$(du -sh "$PCAP_FILE" | cut -f1)
    ALERT "FULL PCAP STOP\nPlik: $PCAP_FILE\nRozmiar: $SIZE"
    LOG red "tcpdump zatrzymany. Plik: $PCAP_FILE ($SIZE)"
else
    ERROR_DIALOG "Plik PCAP nie istnieje!\nCoś poszło nie tak."
fi

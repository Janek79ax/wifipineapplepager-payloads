#!/bin/bash
# Title: Start Recon Dump PCAP Capture
# Author: Janek
# Description: Starts recon dump PCAP capture and saves the file location and PID for later stopping.
# Version: 1.0

PCAP_FILE=$(WIFI_PCAP_START)

if [ -z "$PCAP_FILE" ]; then
    ERROR_DIALOG "Nie udało się uruchomić PCAP!"
    exit 1
fi

ALERT "PCAP START\nZapis do:\n$PCAP_FILE"
LOG green "PCAP capture uruchomiony: $PCAP_FILE"

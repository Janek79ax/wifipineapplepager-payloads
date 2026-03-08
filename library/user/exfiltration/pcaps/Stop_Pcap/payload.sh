#!/bin/bash
# Title: Stop Recon Dump PCAP Capture
# Author: Janek
# Description: Stops recon dump PCAP capture started by startDump.sh and reports the file location and size.
# Version: 1.0

WIFI_PCAP_STOP

ALERT " PCAP STOP\nCapture zatrzymany.\nPlik w /root/loot/pcap/"
LOG red "PCAP capture zatrzymany"

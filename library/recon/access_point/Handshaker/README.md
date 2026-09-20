# Handshaker

Force a handshake capture for the access point selected in Recon.

## Description

Handshaker is a Recon access-point payload. It does not ask for an SSID in the editor. Launch it from a selected AP in Recon; it reads `_RECON_SELECTED_AP_SSID`, `_RECON_SELECTED_AP_BSSID`, and `_RECON_SELECTED_AP_CHANNEL`, locks the radio to that BSSID, deauths clients, and waits until a handshake file appears under `/root/loot/handshakes`.

Monitor interface order:

1. `wlan2mon` if the interface exists
2. `wlan1mon` otherwise

## Requirements

- Enable PineAP handshake collection: **PineAP > Collect Handshakes**
- Run from **Recon → Access Points** with an AP selected
- `wlan2mon` (external radio) or built-in `wlan1mon`

## Usage

1. Run a Recon scan
2. Select the target access point
3. Launch **Handshaker**
4. Wait until the payload reports the captured handshake path

If a matching `.22000` (or handshake `.pcap` / `.pcapng`) file already exists for that BSSID, the payload reports it immediately and does not deauth.

Pressing stop / exiting the payload resets examine mode so channel hopping can resume.

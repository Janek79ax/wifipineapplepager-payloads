# Handshaker

Force a handshake capture for the access point selected in Recon.

## Description

Handshaker launches from **Recon → Access Points**. It does not ask for an SSID in the editor. It uses the selected AP (`_RECON_SELECTED_AP_SSID`, `_RECON_SELECTED_AP_BSSID`, `_RECON_SELECTED_AP_CHANNEL`) and splits the radios:

- **`wlan1mon` listens** on the AP channel for EAPOL / PineAP handshake loot
- **`wlan2mon` deauths** on that same channel (broadcast deauth, then a quiet window so the client can reconnect)

That split matters: deauth and capture on one radio often miss the 4-way handshake when the phone reconnects.

If `wlan2mon` is missing, deauth falls back to `wlan1mon` and capture is less reliable.

**Press B to stop.** The payload stays in a timed button wait during listen, so it can be cancelled. Examine/channel lock is reset on exit.

## Requirements

- Enable PineAP handshake collection: **PineAP > Collect Handshakes**
- Run from **Recon → Access Points** with an AP selected
- `wlan1mon` (listen). `wlan2mon` recommended for deauth
- `tcpdump` (stock on the Pager). Optional: `hcxpcapngtool` to write a `.22000` from the listen pcap

## Usage

1. Run a Recon scan
2. Select the target access point
3. Launch **Handshaker**
4. Wait until it reports the handshake path, or press **B** to stop

If a matching `.22000` (or handshake `.pcap` / `.pcapng`) already exists for that BSSID, it reports that file and does not deauth.

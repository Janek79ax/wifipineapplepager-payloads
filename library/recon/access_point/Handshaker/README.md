# Handshaker

Force a handshake capture for the access point selected in Recon.

## Description

Handshaker launches from **Recon → Access Points**. It does not ask for an SSID in the editor. It uses the selected AP (`_RECON_SELECTED_AP_SSID`, `_RECON_SELECTED_AP_BSSID`, `_RECON_SELECTED_AP_CHANNEL`) and works only on **`wlan1mon`**.

Channel lock is PineAP Examine, not `iw`:

```bash
PINEAPPLE_EXAMINE_CHANNEL <channel> 0
```

That parks `wlan1mon` on the AP channel until the payload exits and calls `PINEAPPLE_EXAMINE_RESET`.

On the parked radio it:

- burst-deauths through `PINEAPPLE_DEAUTH_CLIENT` (PineAP inject on `wlan1mon`)
- waits 15 seconds so the client can reconnect
- listens for EAPOL (`tcpdump`) and PineAP handshake loot

Repeat until a handshake file appears or you press a hardware button (**B**, or any key). Stop is read from `/dev/input/event0` (non-blocking), not `WAIT_FOR_INPUT`, so the 15-second listen window actually elapses.

## Requirements

- Enable PineAP handshake collection: **PineAP > Collect Handshakes**
- Run from **Recon → Access Points** with an AP selected
- `wlan1mon` (PineAP/Recon running)
- `tcpdump` (stock on the Pager). Optional: `hcxpcapngtool` to write a `.22000` from the listen pcap

## Usage

1. Run a Recon scan
2. Select the target access point
3. Launch **Handshaker**
4. Wait until it reports the handshake path, or press **B** (hardware) to stop. The deauth/listen cycle repeats on its own every 15 seconds.

If a matching `.22000` (or handshake `.pcap` / `.pcapng`) already exists for that BSSID, it reports that file and does not deauth.

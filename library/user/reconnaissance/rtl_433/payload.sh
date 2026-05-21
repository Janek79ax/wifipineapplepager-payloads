#!/bin/bash
# Title: RTL-SDR 433 Sniffer
# Description: Sniff 433 MHz sensors (weather stations, remotes) via RTL-SDR + rtl_433
# Author: Jan
# Version: 1.0
# Category: Reconnaissance

PAYLOAD_NAME="rtl_433"
LOOTDIR="/root/loot/rtl_433"
mkdir -p "$LOOTDIR"

RTL_PID=""
RAW_LOG="$(mktemp -t rtl_433.XXXXXX 2>/dev/null || echo /tmp/rtl_433.$$.log)"

cleanup() {
    [ -n "$RTL_PID" ] && kill "$RTL_PID" 2>/dev/null
    sleep 0.3
    [ -n "$RTL_PID" ] && kill -9 "$RTL_PID" 2>/dev/null
    killall rtl_433 2>/dev/null
    killall tail 2>/dev/null
    rm -f "$RAW_LOG"
    LED OFF
}
trap cleanup EXIT INT TERM

LED SETUP

# --- Faza 2: Instalacja pakietow (idempotentna) ---
NEEDED=""
opkg list-installed 2>/dev/null | grep -q "^librtlsdr " || NEEDED="$NEEDED librtlsdr"
opkg list-installed 2>/dev/null | grep -q "^rtl_433 "   || NEEDED="$NEEDED rtl_433"

if [ -n "$NEEDED" ]; then
    LOG yellow "Brakuje pakietow:$NEEDED"

    if ! ping -c1 -W2 8.8.8.8 >/dev/null 2>&1; then
        ERROR_DIALOG "Brak internetu - nie moge zainstalowac:$NEEDED"
        LED FAIL
        exit 1
    fi

    resp=$(CONFIRMATION_DIALOG "Brakuje pakietow:$NEEDED. Zainstalowac przez opkg?")
    case $? in
        $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
            LOG red "Anulowano"
            LED FAIL
            exit 1
            ;;
    esac
    case "$resp" in
        $DUCKYSCRIPT_USER_DENIED)
            LOG red "Uzytkownik odmowil instalacji"
            LED FAIL
            exit 1
            ;;
    esac

    sid=$(START_SPINNER "Instalowanie rtl-sdr...")
    opkg update >/dev/null 2>&1
    opkg install librtlsdr >/dev/null 2>&1
    opkg install rtl_433  >/dev/null 2>&1
    STOP_SPINNER "$sid"
fi

if ! command -v rtl_433 >/dev/null 2>&1; then
    ERROR_DIALOG "rtl_433 nadal nie zainstalowany - sprawdz repo opkg"
    LED FAIL
    exit 1
fi

# --- Faza 3: Sprawdzenie sprzetu (best-effort) ---
if command -v lsusb >/dev/null 2>&1; then
    if ! lsusb 2>/dev/null | grep -iE "RTL2832|RTL2838|Realtek.*DVB" >/dev/null; then
        LOG yellow "Ostrzezenie: nie wykryto dongla RTL-SDR przez lsusb"
        LOG yellow "(czasem stare dongle nie sa rozpoznawane - probuje dalej)"
    else
        LOG green "Wykryto dongle RTL-SDR"
    fi
fi

# --- Faza 4: Uruchomienie i parsowanie outputu ---
LED ATTACK
RINGTONE "alert"
LOG cyan "===== RTL-SDR 433 Sniffer ====="
LOG "Nasluchuje na 433.92 MHz..."
LOG "Wyjscie zabija proces rtl_433"
LOG ""

CSV="$LOOTDIR/rtl_433_$(date +%Y%m%d_%H%M%S).log"
echo "=== rtl_433 capture started $(date) ===" > "$CSV"

rtl_433 2>/dev/null > "$RAW_LOG" &
RTL_PID=$!

sleep 1
if ! kill -0 "$RTL_PID" 2>/dev/null; then
    ERROR_DIALOG "rtl_433 nie wystartowal - czy dongle podlaczony?"
    LED FAIL
    exit 1
fi

LOG green "rtl_433 dziala (PID $RTL_PID)"
LOG ""

tail -n0 -F "$RAW_LOG" 2>/dev/null | while IFS= read -r line; do
    echo "$line" >> "$CSV"

    if [ -z "$line" ]; then
        LOG ""
        continue
    fi

    case "$line" in
        *:*)
            key="${line%%:*}"
            val="${line#*:}"
            key_trim="$(echo "$key" | xargs)"
            val_trim="$(echo "$val" | sed 's/^[[:space:]]*//')"
            ;;
        *)
            key_trim=""
            val_trim="$line"
            ;;
    esac

    case "$key_trim" in
        time)
            LOG gray "[$val_trim]"
            ;;
        model)
            LOG green "model: $val_trim"
            VIBRATE 50
            ;;
        Temperature|Temperature_C|Temperature_F)
            LOG cyan "T: $val_trim"
            ;;
        Humidity)
            LOG cyan "H: $val_trim"
            ;;
        Battery|Battery_OK|Battery_mV)
            LOG yellow "Bat: $val_trim"
            ;;
        Channel)
            LOG "Ch: $val_trim"
            ;;
        "")
            LOG "$val_trim"
            ;;
        *)
            LOG "$key_trim: $val_trim"
            ;;
    esac
done

LED FINISH
exit 0

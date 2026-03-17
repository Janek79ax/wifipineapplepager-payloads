# WiFi Pineapple Pager — Payload Development Skills

> **Purpose:** AI assistant reference for writing new payloads for the Hak5 WiFi Pineapple Pager.
> This document covers the complete API, conventions, patterns, and examples discovered across 150+ community payloads.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Payload Anatomy](#2-payload-anatomy)
3. [Payload Categories](#3-payload-categories)
4. [DuckyScript UI Commands](#4-duckyscript-ui-commands)
5. [Response Constants & Error Handling](#5-response-constants--error-handling)
6. [Hardware Commands](#6-hardware-commands)
7. [PineAP WiFi Engine Commands](#7-pineap-wifi-engine-commands)
8. [GPS & WiGLE Commands](#8-gps--wigle-commands)
9. [Persistence API](#9-persistence-api)
10. [Alert Environment Variables](#10-alert-environment-variables)
11. [Recon Environment Variables](#11-recon-environment-variables)
12. [Key Filesystem Paths](#12-key-filesystem-paths)
13. [Common Code Patterns](#13-common-code-patterns)
14. [Background Services (init.d)](#14-background-services-initd)
15. [Framebuffer Display](#15-framebuffer-display)
16. [Contribution Rules](#16-contribution-rules)
17. [Canonical Examples](#17-canonical-examples)
18. [Advanced Patterns](#18-advanced-patterns)

---

## 1. Project Overview

The **WiFi Pineapple Pager** is a Hak5 portable penetration testing device running OpenWrt. Payloads are **bash scripts enhanced with DuckyScript™ commands** — special ALL-CAPS executables available in the system PATH that control the Pager's UI, LEDs, buzzer, vibration motor, WiFi engine (PineAP), and GPS.

**Language:** Bash + DuckyScript (ALL-CAPS commands mixed naturally with standard shell)
**No compilation required** — place `payload.sh` in the correct category directory.
**Target OS:** OpenWrt 24.10.x (ash/bash, busybox utilities, opkg package manager, UCI config system, nftables firewall)

### Repository Structure

```
library/
├── alerts/                    # Auto-triggered by WiFi events
│   ├── deauth_flood_detected/
│   ├── handshake_captured/
│   ├── pineapple_auth_captured/
│   └── pineapple_client_connected/
├── recon/                     # Run from Recon screen on selected target
│   ├── access_point/          # AP context payloads
│   └── client/                # Client context payloads
└── user/                      # Manually launched from Payloads menu
    ├── examples/              # Official DuckyScript command demos
    ├── evil_portal/           # Captive portal suite
    ├── exfiltration/          # Data capture & upload
    ├── games/                 # Entertainment
    ├── general/               # Utilities & tools (~65 payloads)
    ├── incident_response/     # IR tools (placeholder)
    ├── interception/          # MITM / portal interception
    ├── known_unstable/        # Payloads with known issues
    ├── prank/                 # Social engineering fun
    ├── reconnaissance/        # Active recon tools (~25 payloads)
    ├── remote_access/         # Tunneling & remote management (~13 payloads)
    └── virtual_pager/         # Pager UI customization
```

---

## 2. Payload Anatomy

### Minimum Required: `payload.sh`

Every payload is a **directory** containing at minimum a `payload.sh` file with a standard header:

```bash
#!/bin/bash
# Title: My Payload Name
# Description: Brief description of what this payload does
# Author: YourName
# Version: 1.0
# Category: General
```

### Optional Files

| File | Purpose |
|------|---------|
| `README.md` | Documentation, usage instructions, requirements |
| `config.sh` | External configuration (sourced by payload.sh) |
| `payload.json` | Metadata (rare — only used by graphical payloads like games) |
| `*.raw` | Raw framebuffer images (222×480, RGB565) |
| `*.py`, `*.php` | Companion scripts |

### Header Fields

| Field | Required | Notes |
|-------|----------|-------|
| `Title` | Yes | Human-readable name |
| `Description` | Yes | One-line summary |
| `Author` | Yes | Attribution |
| `Version` | Yes | Semantic version |
| `Category` | Yes | Must match existing subcategory name |

---

## 3. Payload Categories

### Alert Payloads (alerts)

**Trigger:** Automatic — fired by the Pager when a WiFi event occurs.
**Environment:** Pre-populated `$_ALERT_*` variables with event data.
**Typical complexity:** Low (5–50 lines). Usually display a notification and optionally process event data.
**Subcategories & triggers:**

| Directory | Trigger Event |
|-----------|---------------|
| `deauth_flood_detected/` | Deauthentication/disassociation flood detected |
| `handshake_captured/` | WPA handshake (EAPOL or PMKID) captured |
| `pineapple_auth_captured/` | Enterprise auth captured (MSCHAPv2, EAP-TTLS) |
| `pineapple_client_connected/` | Client connects to Evil AP (WPA or Open) |

### Recon Payloads (recon)

**Trigger:** Manual — user selects a target in the Recon screen and runs the payload.
**Environment:** Pre-populated `$_RECON_SELECTED_AP_*` and/or `$_RECON_SELECTED_CLIENT_*` variables.
**Typical complexity:** Medium (20–100 lines). Inspect, analyze, or act on the selected target.
**Subcategories:**

| Directory | Context Available |
|-----------|-------------------|
| `access_point/` | AP info (`$_RECON_SELECTED_AP_*`) |
| `client/` | Client info (`$_RECON_SELECTED_CLIENT_*`) + parent AP info (`$_RECON_SELECTED_AP_*`) |

### User Payloads (user)

**Trigger:** Manual — user selects from the Payloads menu.
**Environment:** No special variables — fully interactive via DuckyScript dialogs.
**Typical complexity:** High (50–3000+ lines). Full interactive workflows with dialogs, pickers, and loops.
**Subcategories:** `general`, `reconnaissance`, `remote_access`, `exfiltration`, `interception`, `games`, `prank`, `evil_portal`, `virtual_pager`, `incident_response`, `known_unstable`

---

## 4. DuckyScript UI Commands

All DuckyScript commands are **ALL CAPS** and available as executables in the Pager's PATH.

### Display & Logging

| Command | Signature | Returns | Description |
|---------|-----------|---------|-------------|
| `LOG` | `LOG [color] "message"` | void | Write colored message to payload log. Colors: `red`, `green`, `blue`, `yellow`, `cyan`, `magenta`, `orange`, `gray`, `white`. No color = default. |
| `ALERT` | `ALERT "message"` | void | Show popup alert dialog on Pager screen |
| `ERROR_DIALOG` | `ERROR_DIALOG "message"` | void | Show error popup dialog |
| `PROMPT` | `PROMPT "message"` | void | Display message and wait for any button press |

### Input Dialogs (Pickers)

All pickers return the user's input via stdout. Check `$?` for error/cancel codes.

| Command | Signature | Returns | Description |
|---------|-----------|---------|-------------|
| `TEXT_PICKER` | `resp=$(TEXT_PICKER "prompt" "default_value")` | User-entered text | Free text input with on-screen keyboard |
| `NUMBER_PICKER` | `resp=$(NUMBER_PICKER "prompt" default_num)` | Number | Numeric input |
| `IP_PICKER` | `resp=$(IP_PICKER "prompt" "127.0.0.1")` | IP address string | IP address input with validation |
| `MAC_PICKER` | `resp=$(MAC_PICKER "prompt" "DE:AD:BE:EF:CA:FE")` | MAC address string | MAC address input with validation |
| `CONFIRMATION_DIALOG` | `resp=$(CONFIRMATION_DIALOG "question?")` | `$DUCKYSCRIPT_USER_CONFIRMED` or `$DUCKYSCRIPT_USER_DENIED` | Yes/No dialog |

### Spinner (Loading Indicator)

```bash
id=$(START_SPINNER "Processing...")
# ... do work ...
STOP_SPINNER $id
```

### Button Input

| Command | Signature | Returns | Description |
|---------|-----------|---------|-------------|
| `WAIT_FOR_INPUT` | `btn=$(WAIT_FOR_INPUT)` | Button name: `UP`, `DOWN`, `LEFT`, `RIGHT`, `A`, `B` | Wait for any button press |
| `WAIT_FOR_BUTTON_PRESS` | `WAIT_FOR_BUTTON_PRESS UP` | void | Wait for a specific button press |

Available buttons: `UP`, `DOWN`, `LEFT`, `RIGHT`, `A`, `B`

---

## 5. Response Constants & Error Handling

### Exit Code Constants

| Variable | Meaning |
|----------|---------|
| `$DUCKYSCRIPT_CANCELLED` | User cancelled the dialog |
| `$DUCKYSCRIPT_REJECTED` | Dialog was rejected |
| `$DUCKYSCRIPT_ERROR` | An error occurred |
| `$DUCKYSCRIPT_USER_CONFIRMED` | User selected Yes (value: `1`) |
| `$DUCKYSCRIPT_USER_DENIED` | User selected No |

### Standard Error Handling Pattern

**Every picker command MUST be followed by error handling:**

```bash
resp=$(TEXT_PICKER "Enter value" "default")
case $? in
    $DUCKYSCRIPT_CANCELLED)
        LOG red "User cancelled"
        exit 1
        ;;
    $DUCKYSCRIPT_REJECTED)
        LOG red "Dialog rejected"
        exit 1
        ;;
    $DUCKYSCRIPT_ERROR)
        LOG red "An error occurred"
        exit 1
        ;;
esac
# Safe to use $resp here
LOG green "User entered: $resp"
```

### CONFIRMATION_DIALOG Pattern (two-stage check)

```bash
resp=$(CONFIRMATION_DIALOG "Are you sure?")
case $? in
    $DUCKYSCRIPT_CANCELLED)  LOG red "Cancelled"; exit 1 ;;
    $DUCKYSCRIPT_REJECTED)   LOG red "Rejected"; exit 1 ;;
    $DUCKYSCRIPT_ERROR)      LOG red "Error"; exit 1 ;;
esac
case "$resp" in
    $DUCKYSCRIPT_USER_CONFIRMED) LOG green "User confirmed" ;;
    $DUCKYSCRIPT_USER_DENIED)    LOG yellow "User denied"; exit 0 ;;
esac
```

---

## 6. Hardware Commands

### LED States

```bash
LED SETUP       # Indicates setup/boot phase (typically blue/cyan)
LED ATTACK      # Indicates attack in progress (typically red/amber)
LED FINISH      # Indicates completion (typically green)
LED FAIL        # Indicates failure (typically red blink)
LED OFF         # Turn LED off
```

### LED Colors & Modes

```bash
LED WHITE       # Solid white
LED RED         # Solid red
LED GREEN       # Solid green
LED CYAN        # Solid cyan
LED MAGENTA     # Solid magenta
LED AMBER       # Solid amber

# With brightness (0-255)
LED R 255       # Red at full brightness
LED G 128       # Green at half
LED B 50        # Blue at low

# With mode
LED cyan pulse  # Pulsing cyan
LED red solid   # Solid red
LED Y SOLID     # Solid yellow
```

### D-Pad LED

```bash
DPADLED "cyan"   # Set D-pad LED color
DPADLED off      # Turn off D-pad LED
```

### Direct LED sysfs access (advanced)

```bash
echo 1 > /sys/class/leds/a-button-led/brightness   # A-button LED on
echo 0 > /sys/class/leds/a-button-led/brightness   # A-button LED off
echo 1 > /sys/class/leds/b-button-led/brightness   # B-button LED on
echo 0 > /sys/class/leds/b-button-led/brightness   # B-button LED off
```

### Low-level LED API

```bash
. /lib/hak5/commands.sh
HAK5_API_POST "system/led" "\"green\"" >/dev/null 2>&1
```

### Ringtone

```bash
# Built-in named ringtones
RINGTONE "alert"
RINGTONE "warning"
RINGTONE "success"
RINGTONE "error"
RINGTONE "getmachine"
RINGTONE "bonus"
RINGTONE "xp"
RINGTONE "getkey"

# Custom RTTTL format
RINGTONE "MySong:d=4,o=5,c=32:8c,8e,8g,4c6"
```

### Vibration

```bash
VIBRATE                       # Default single vibration
VIBRATE "alert"               # Named vibration pattern
VIBRATE 50                    # Single 50ms vibration
VIBRATE 100                   # Single 100ms vibration
VIBRATE 200 100 200           # Pattern: 200ms on, 100ms off, 200ms on
VIBRATE 100 50 100 50 100     # Pattern: rapid triple pulse
```

---

## 7. PineAP WiFi Engine Commands

### SSID Pool Management

```bash
PINEAPPLE_SSID_POOL_ADD "FreeWiFi"           # Add single SSID
PINEAPPLE_SSID_POOL_ADD_FILE /path/to/list   # Add SSIDs from file (one per line)
PINEAPPLE_SSID_POOL_LIST                     # List current SSID pool
PINEAPPLE_SSID_POOL_CLEAR                    # Clear entire pool
PINEAPPLE_SSID_POOL_COLLECT_START            # Auto-collect SSIDs from probes
PINEAPPLE_SSID_POOL_COLLECT_STOP             # Stop auto-collection
```

### Recon Scanner Control

```bash
PINEAPPLE_RECON_NEW "$duration_seconds"                  # Start new recon scan
PINEAPPLE_EXAMINE_BSSID "$bssid" "$seconds"              # Focus on specific BSSID
PINEAPPLE_EXAMINE_CHANNEL "$channel" "$seconds"          # Focus on specific channel
PINEAPPLE_EXAMINE_RESET                                  # Reset to scan all
PINEAPPLE_SET_BANDS "both"                               # Set bands: "2.4", "5", "both"
```

### Deauthentication

```bash
PINEAPPLE_DEAUTH_CLIENT "$ap_mac" "$client_mac" "$channel"
# Use "FF:FF:FF:FF:FF:FF" as client_mac for broadcast deauth
```

### Low-Level PineAP API (`_pineap`)

```bash
_pineap RECON APS limit=30 format=json       # Get scanned APs as JSON
_pineap RECON CLIENTS limit=50 format=json   # Get scanned clients as JSON
_pineap MONITOR "$mac" any rate=1 timeout=10 # Monitor specific MAC signal
_pineap EXAMINE CANCEL                       # Cancel examination
```

### Low-Level HTTP API

```bash
. /lib/hak5/commands.sh
HAK5_API_POST "endpoint/path" "$json_body"
```

---

## 8. GPS & WiGLE Commands

### GPS Setup

```bash
# List connected GPS serial devices
devices=$(GPS_LIST)    # Returns: /dev/ttyACM0, /dev/ttyUSB0, etc.

# Configure GPS device
GPS_CONFIGURE "/dev/ttyACM0" "9600"

# Restart GPS daemon after configuration
/etc/init.d/gpsd restart

# Verify GPS data flow
gpspipe -r    # Stream raw NMEA sentences
```

### WiGLE Wardriving

```bash
# Authenticate with WiGLE
WIGLE_LOGIN "$username" "$password"

# Start wardriving (returns CSV file path)
csv_file=$(WIGLE_START)

# Upload results to wigle.net
WIGLE_UPLOAD "$csv_file"                    # Upload only
WIGLE_UPLOAD --archive "$csv_file"          # Upload and archive
WIGLE_UPLOAD --remove "$csv_file"           # Upload and delete local file

# Logout
WIGLE_LOGOUT
```

> **Firmware 1.0.4 bug workaround:** Before `WIGLE_UPLOAD`, copy `authname` to `apiname`:
> `PAYLOAD_SET_CONFIG wigle apiname "$(PAYLOAD_GET_CONFIG wigle authname)"`

---

## 9. Persistence API

Persists key-value data across payload updates and reboots. Data is stored separately from payload files.

```bash
# Write a value
PAYLOAD_SET_CONFIG "$namespace" "$key" "$value"

# Read a value
value=$(PAYLOAD_GET_CONFIG "$namespace" "$key")

# Delete a value
PAYLOAD_DEL_CONFIG "$namespace" "$key"
```

### Convention

Define `PAYLOAD_NAME` and use it as namespace to avoid collisions:

```bash
PAYLOAD_NAME="my_payload"
PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "api_key" "$key"
api_key=$(PAYLOAD_GET_CONFIG "$PAYLOAD_NAME" "api_key")
```

### Indexed Array Pattern (for storing lists)

```bash
PAYLOAD_NAME="my_wifi_manager"
count=3
PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "count" "$count"
PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "ssid_1" "NetworkA"
PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "ssid_2" "NetworkB"
PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "ssid_3" "NetworkC"

# Read back
count=$(PAYLOAD_GET_CONFIG "$PAYLOAD_NAME" "count")
for i in $(seq 1 $count); do
    ssid=$(PAYLOAD_GET_CONFIG "$PAYLOAD_NAME" "ssid_$i")
    echo "$ssid"
done
```

---

## 10. Alert Environment Variables

### Deauth Flood Detected (deauth_flood_detected)

| Variable | Description |
|----------|-------------|
| `$_ALERT` | Always `"deauth_flood_detected"` |
| `$_ALERT_DENIAL_MESSAGE` | Human-readable summary |
| `$_ALERT_DENIAL_SOURCE_MAC_ADDRESS` | Source MAC of deauth frames |
| `$_ALERT_DENIAL_DESTINATION_MAC_ADDRESS` | Destination MAC |
| `$_ALERT_DENIAL_AP_MAC_ADDRESS` | Access point MAC |
| `$_ALERT_DENIAL_CLIENT_MAC_ADDRESS` | Client MAC |

### Handshake Captured (handshake_captured)

| Variable | Description |
|----------|-------------|
| `$_ALERT_HANDSHAKE_SUMMARY` | Human-readable summary |
| `$_ALERT_HANDSHAKE_AP_MAC_ADDRESS` | AP MAC address |
| `$_ALERT_HANDSHAKE_CLIENT_MAC_ADDRESS` | Client MAC address |
| `$_ALERT_HANDSHAKE_TYPE` | `eapol` or `pmkid` |
| `$_ALERT_HANDSHAKE_COMPLETE` | Boolean — EAPOL only |
| `$_ALERT_HANDSHAKE_CRACKABLE` | Boolean — EAPOL only |
| `$_ALERT_HANDSHAKE_PCAP_PATH` | Path to captured `.pcap` file |
| `$_ALERT_HANDSHAKE_HASHCAT_PATH` | Path to `.22000` hashcat file |

### Auth Captured (pineapple_auth_captured)

| Variable | Description |
|----------|-------------|
| `$_ALERT_AUTH_SUMMARY` | Human-readable summary |
| `$_ALERT_AUTH_TYPE` | `mschapv2`, `eap-ttls/chap`, or `eap-ttls/mschapv2` |
| `$_ALERT_AUTH_USERNAME` | Captured username |
| `$_ALERT_AUTH_CHALLENGE_IDENTITY` | Challenge identity string |

### Client Connected (pineapple_client_connected)

| Variable | Description |
|----------|-------------|
| `$_ALERT_CLIENT_CONNECTED_SUMMARY` | Human-readable summary |
| `$_ALERT_CLIENT_CONNECTED_AP_MAC_ADDRESS` | AP MAC the client connected to |
| `$_ALERT_CLIENT_CONNECTED_CLIENT_MAC_ADDRESS` | Client's MAC address |
| `$_ALERT_CLIENT_CONNECTED_SSID` | SSID the client connected to |
| `$_ALERT_CLIENT_CONNECTED_SSID_LENGTH` | Length of SSID string |

---

## 11. Recon Environment Variables

### Access Point Context (access_point)

| Variable | Description |
|----------|-------------|
| `$_RECON_SELECTED_AP_OUI` | Manufacturer OUI |
| `$_RECON_SELECTED_AP_BSSID` | AP BSSID (MAC address) |
| `$_RECON_SELECTED_AP_MAC_ADDRESS` | AP MAC address |
| `$_RECON_SELECTED_AP_SSID` | AP SSID (network name) |
| `$_RECON_SELECTED_AP_HIDDEN` | Whether SSID is hidden |
| `$_RECON_SELECTED_AP_CHANNEL` | Operating channel |
| `$_RECON_SELECTED_AP_FREQ` | Operating frequency |
| `$_RECON_SELECTED_AP_ENCRYPTION_TYPE` | Encryption type (WPA2, WPA3, Open, etc.) |
| `$_RECON_SELECTED_AP_CLIENT_COUNT` | Number of connected clients |
| `$_RECON_SELECTED_AP_RSSI` | Signal strength (dBm) |
| `$_RECON_SELECTED_AP_PACKETS` | Packet count |
| `$_RECON_SELECTED_AP_TIMESTAMP` | Last seen timestamp |
| `$_RECON_SELECTED_AP_BEACONED_SSIDS` | SSIDs advertised via beacons |
| `$_RECON_SELECTED_AP_RESPONDED_SSIDS` | SSIDs responded to probes |

### Client Context (client)

Includes ALL `$_RECON_SELECTED_AP_*` variables (parent AP) PLUS:

| Variable | Description |
|----------|-------------|
| `$_RECON_SELECTED_CLIENT_OUI` | Client manufacturer OUI |
| `$_RECON_SELECTED_CLIENT_MAC_ADDRESS` | Client MAC address |
| `$_RECON_SELECTED_CLIENT_SSID` | Connected SSID |
| `$_RECON_SELECTED_CLIENT_BSSID` | Connected AP BSSID |
| `$_RECON_SELECTED_CLIENT_CHANNEL` | Channel |
| `$_RECON_SELECTED_CLIENT_FREQ` | Frequency |
| `$_RECON_SELECTED_CLIENT_ENCRYPTION_TYPE` | Encryption type |
| `$_RECON_SELECTED_CLIENT_PACKETS` | Packet count |
| `$_RECON_SELECTED_CLIENT_RSSI` | Signal strength (dBm) |
| `$_RECON_SELECTED_CLIENT_TIMESTAMP` | Last seen timestamp |
| `$_RECON_SELECTED_CLIENT_PROBED_SSID` | Last probed SSID |
| `$_RECON_SELECTED_CLIENT_PROBED_SSIDS` | All probed SSIDs |

---

## 12. Key Filesystem Paths

| Path | Purpose |
|------|---------|
| `/root/loot/` | Standard loot directory for all captures |
| `/root/loot/handshakes/` | Captured handshakes (`.22000`, `.pcap`) |
| `/root/loot/wigle/` | WiGLE wardriving CSV files |
| `/root/portals/` | Evil Portal HTML/PHP files |
| `/root/logs/` | Application logs (e.g., `credentials.json`) |
| `/mmc/root/payloads/user/` | User payload storage on MMC card |
| `/mmc/root/ringtones/` | Custom RTTTL ringtone files |
| `/pineapple/ui/modules/` | Pineapple web UI modules |
| `/lib/hak5/commands.sh` | Hak5 helper library (source for low-level API) |
| `/dev/fb0` | Framebuffer device for raw image display |
| `/dev/input/event0` | Input device for non-blocking button reads |
| `/sys/class/leds/a-button-led/` | A-button LED sysfs control |
| `/sys/class/leds/b-button-led/` | B-button LED sysfs control |
| `/sys/class/backlight/backlight_pwm/brightness` | LCD brightness control |
| `/sys/class/net/$iface/address` | Network interface MAC address |
| `/tmp/` | Temporary runtime files |
| `/etc/init.d/` | OpenWrt init scripts (services) |
| `/etc/rc.d/` | Service startup symlinks |
| `/usr/bin/` | System binaries / payload daemons |

### Network Conventions

| Network | Purpose |
|---------|---------|
| `172.16.52.0/24` | Management subnet (do NOT use for testing) |
| `10.0.0.0/24` | Evil Portal isolated subnet (optional `br-evil` bridge) |

---

## 13. Common Code Patterns

### Pattern 1: Script Directory Self-Reference

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
```

### Pattern 2: Loot Directory

```bash
LOOTDIR="/root/loot/my_payload"
mkdir -p "$LOOTDIR"
```

### Pattern 3: Internet Connectivity Check

```bash
if ! ping -c1 google.com &>/dev/null; then
    ERROR_DIALOG "No internet connectivity"
    exit 1
fi
```

### Pattern 4: LED State Machine

Follow the standard progression throughout your payload:

```bash
LED SETUP       # Beginning of payload
# ... setup work ...
LED ATTACK      # Active operation
# ... main work ...
LED FINISH      # Success
# or
LED FAIL        # Failure
```

### Pattern 5: Trap-Based Cleanup

```bash
cleanup() {
    LED OFF
    # Kill background processes, remove temp files, etc.
}
trap cleanup EXIT INT TERM
```

### Pattern 6: Idempotent Package Installation

```bash
PACKAGES_NEEDED=""
if ! opkg list-installed | grep -q "^nmap "; then
    PACKAGES_NEEDED="$PACKAGES_NEEDED nmap"
fi
if [ -n "$PACKAGES_NEEDED" ]; then
    opkg update
    opkg install $PACKAGES_NEEDED
fi
```

### Pattern 7: Scrollable Menu with Button Navigation

```bash
options=("Option A" "Option B" "Option C")
selected=0
while true; do
    LOG "------- MENU -------"
    for i in "${!options[@]}"; do
        if [ $i -eq $selected ]; then
            LOG green "> ${options[$i]}"
        else
            LOG "  ${options[$i]}"
        fi
    done

    btn=$(WAIT_FOR_INPUT)
    case "$btn" in
        UP)    ((selected > 0)) && ((selected--)) ;;
        DOWN)  ((selected < ${#options[@]}-1)) && ((selected++)) ;;
        A)     break ;;  # Select
        B)     exit 0 ;; # Cancel
    esac
done
LOG green "Selected: ${options[$selected]}"
```

### Pattern 8: Toggle UI (Install/Uninstall Service)

```bash
if [ -f /etc/init.d/myservice ]; then
    if /etc/init.d/myservice status 2>/dev/null | grep -q "running"; then
        resp=$(CONFIRMATION_DIALOG "Service is running. Stop and uninstall?")
        # ... handle response, stop and remove ...
    else
        resp=$(CONFIRMATION_DIALOG "Service installed but stopped. Start or uninstall?")
        # ... handle response ...
    fi
else
    resp=$(CONFIRMATION_DIALOG "Install service?")
    # ... handle response, install ...
fi
```

### Pattern 9: Configuration with Persistence

```bash
PAYLOAD_NAME="my_payload"

# Load saved config or prompt user
saved_host=$(PAYLOAD_GET_CONFIG "$PAYLOAD_NAME" "host")
if [ -z "$saved_host" ]; then
    saved_host="example.com"
fi

host=$(TEXT_PICKER "Enter host" "$saved_host")
case $? in
    $DUCKYSCRIPT_CANCELLED) exit 1 ;;
    $DUCKYSCRIPT_REJECTED)  exit 1 ;;
    $DUCKYSCRIPT_ERROR)     exit 1 ;;
esac

PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "host" "$host"
```

### Pattern 10: Graceful Feature Detection

```bash
if ! command -v nmap >/dev/null 2>&1; then
    resp=$(CONFIRMATION_DIALOG "nmap not installed. Install now?")
    # ... handle install ...
fi
```

---

## 14. Background Services (init.d)

### OpenWrt procd Service Pattern

```bash
cat > /etc/init.d/myservice << 'INITEOF'
#!/bin/sh /etc/rc.common
START=51
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/myservice_daemon
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
INITEOF
chmod +x /etc/init.d/myservice
/etc/init.d/myservice enable   # Create /etc/rc.d/S51myservice symlink
/etc/init.d/myservice start    # Start now
```

### OpenWrt rc.common Pattern (simpler)

```bash
cat > /etc/init.d/myservice << 'INITEOF'
#!/bin/sh /etc/rc.common
START=99
STOP=10

start() {
    /usr/bin/myservice_daemon &
}

stop() {
    killall myservice_daemon 2>/dev/null
}
INITEOF
chmod +x /etc/init.d/myservice
```

### Cleanup/Uninstall Pattern

```bash
/etc/init.d/myservice stop 2>/dev/null
/etc/init.d/myservice disable 2>/dev/null
rm -f /etc/init.d/myservice
rm -f /usr/bin/myservice_daemon
```

### Key Conventions

- Payloads must be **idempotent** — check if service exists before reinstalling
- Offer toggle UI: running → stop/uninstall; stopped → start/uninstall; not installed → install
- Remove both `/etc/init.d/` script and bin binary on uninstall
- Use `START=51` for background daemons, `START=99` for late-boot services

---

## 15. Framebuffer Display

The Pager has a 222×480 pixel LCD accessible via `/dev/fb0`.

### Specifications

| Property | Value |
|----------|-------|
| Resolution | 222×480 pixels |
| Pixel format | RGB565, little-endian (16 bits/pixel) |
| Device | `/dev/fb0` |
| Orientation | Images must be rotated 90° clockwise |
| File size | 222 × 480 × 2 = 213,120 bytes per frame |

### Display a Raw Image

```bash
# Disable console to prevent overwriting
echo 0 > /sys/class/vtconsole/vtcon1/bind

# Display image (loop to persist on screen)
while true; do
    cat image.raw > /dev/fb0
    sleep 0.5
done &
DISPLAY_PID=$!

# Restore on exit
cleanup() {
    kill $DISPLAY_PID 2>/dev/null
    echo 1 > /sys/class/vtconsole/vtcon1/bind
}
trap cleanup EXIT
```

### Convert Images (Python, on host machine)

```python
from PIL import Image
import struct

img = Image.open("input.png").convert("RGB")
img = img.rotate(-90, expand=True).resize((222, 480))
with open("output.raw", "wb") as f:
    for y in range(480):
        for x in range(222):
            r, g, b = img.getpixel((x, y))
            rgb565 = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            f.write(struct.pack('<H', rgb565))
```

---

## 16. Contribution Rules

1. **Submit via Pull Request** to the official Hak5 repository
2. **Naming:** Use `-` or `_` instead of spaces in directory names
3. **Categories:** Use existing subcategories only — do not create new ones
4. **Required:** `payload.sh` with header comments (Title, Author, Description, Version, Category)
5. **Configuration:** Use placeholders like `YOUR_API_KEY_HERE`, `example.com` — never include real credentials
6. **No purely destructive payloads** will be accepted
7. **No staged payloads via GitHub CDN** — host external resources elsewhere and include all source code
8. **Test thoroughly** before submitting
9. **Credit others** when building on their work
10. **Optional but recommended:** Include `README.md` for complex payloads, `config.sh` for user-configurable options

---

## 17. Canonical Examples

### Minimal Alert Payload

```bash
#!/bin/bash
# Title: Custom Handshake Alert
# Description: Vibrate and log when a crackable handshake is captured
# Author: YourName
# Version: 1.0
# Category: Handshake-Captured

if [ "$_ALERT_HANDSHAKE_CRACKABLE" = "true" ]; then
    VIBRATE 200 100 200
    RINGTONE "getkey"
    LOG green "Crackable handshake: $_ALERT_HANDSHAKE_AP_MAC_ADDRESS"
    LOG green "Type: $_ALERT_HANDSHAKE_TYPE"
    LOG green "Hashcat file: $_ALERT_HANDSHAKE_HASHCAT_PATH"
    ALERT "Crackable handshake captured!\n$_ALERT_HANDSHAKE_SUMMARY"
else
    LOG yellow "Non-crackable handshake: $_ALERT_HANDSHAKE_SUMMARY"
fi
```

### Minimal Recon Payload (Access Point)

```bash
#!/bin/bash
# Title: AP Quick Info
# Description: Display detailed info about selected access point
# Author: YourName
# Version: 1.0
# Category: Access-Point

LOG cyan "===== AP INFO ====="
LOG green "SSID:       $_RECON_SELECTED_AP_SSID"
LOG green "BSSID:      $_RECON_SELECTED_AP_BSSID"
LOG green "Channel:    $_RECON_SELECTED_AP_CHANNEL"
LOG green "Encryption: $_RECON_SELECTED_AP_ENCRYPTION_TYPE"
LOG green "Clients:    $_RECON_SELECTED_AP_CLIENT_COUNT"
LOG green "RSSI:       $_RECON_SELECTED_AP_RSSI dBm"
LOG green "OUI:        $_RECON_SELECTED_AP_OUI"

if [ -n "$_RECON_SELECTED_AP_BEACONED_SSIDS" ]; then
    LOG yellow "Beaconed SSIDs: $_RECON_SELECTED_AP_BEACONED_SSIDS"
fi

PROMPT "Press any button to exit"
```

### Minimal User Payload

```bash
#!/bin/bash
# Title: Network Scanner
# Description: Scan local network and save results to loot
# Author: YourName
# Version: 1.0
# Category: Reconnaissance

LED SETUP
LOOTDIR="/root/loot/network_scanner"
mkdir -p "$LOOTDIR"

# Check dependencies
if ! command -v nmap >/dev/null 2>&1; then
    resp=$(CONFIRMATION_DIALOG "nmap not found. Install?")
    case $? in
        $DUCKYSCRIPT_CANCELLED) exit 1 ;;
        $DUCKYSCRIPT_REJECTED)  exit 1 ;;
        $DUCKYSCRIPT_ERROR)     exit 1 ;;
    esac
    case "$resp" in
        $DUCKYSCRIPT_USER_DENIED) LOG red "Aborted"; exit 1 ;;
    esac
    id=$(START_SPINNER "Installing nmap...")
    opkg update && opkg install nmap
    STOP_SPINNER $id
fi

# Get target
target=$(IP_PICKER "Target subnet" "192.168.1.0/24")
case $? in
    $DUCKYSCRIPT_CANCELLED) exit 1 ;;
    $DUCKYSCRIPT_REJECTED)  exit 1 ;;
    $DUCKYSCRIPT_ERROR)     exit 1 ;;
esac

# Scan
LED ATTACK
LOG cyan "Scanning $target ..."
id=$(START_SPINNER "Scanning network...")
timestamp=$(date +%Y%m%d_%H%M%S)
outfile="$LOOTDIR/scan_${timestamp}.txt"
nmap -sn "$target" > "$outfile" 2>&1
STOP_SPINNER $id

# Display results
while IFS= read -r line; do
    LOG green "$line"
done < "$outfile"

LED FINISH
RINGTONE "success"
LOG cyan "Results saved to: $outfile"
PROMPT "Press any button to exit"
```

### Full Interactive User Payload (with persistence, cleanup, menu)

```bash
#!/bin/bash
# Title: WiFi Profile Manager
# Description: Save, load, and manage WiFi profiles with persistence
# Author: YourName
# Version: 1.0
# Category: General

PAYLOAD_NAME="wifi_profile_mgr"

cleanup() {
    LED OFF
}
trap cleanup EXIT INT TERM

LED SETUP

load_profiles() {
    PROFILE_COUNT=$(PAYLOAD_GET_CONFIG "$PAYLOAD_NAME" "count")
    [ -z "$PROFILE_COUNT" ] && PROFILE_COUNT=0
}

save_new_profile() {
    ssid=$(TEXT_PICKER "SSID" "")
    case $? in $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR) return ;; esac

    pass=$(TEXT_PICKER "Password" "")
    case $? in $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR) return ;; esac

    ((PROFILE_COUNT++))
    PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "count" "$PROFILE_COUNT"
    PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "ssid_$PROFILE_COUNT" "$ssid"
    PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "pass_$PROFILE_COUNT" "$pass"

    LOG green "Profile saved: $ssid"
    RINGTONE "success"
}

list_profiles() {
    if [ "$PROFILE_COUNT" -eq 0 ]; then
        LOG yellow "No saved profiles"
        return
    fi
    LOG cyan "===== Saved Profiles ====="
    for i in $(seq 1 $PROFILE_COUNT); do
        ssid=$(PAYLOAD_GET_CONFIG "$PAYLOAD_NAME" "ssid_$i")
        LOG green "  $i. $ssid"
    done
}

# Main menu loop
load_profiles
while true; do
    LOG cyan "====== MENU ======"
    LOG "  UP   = List profiles"
    LOG "  DOWN = Add profile"
    LOG "  B    = Exit"

    btn=$(WAIT_FOR_INPUT)
    case "$btn" in
        UP)   list_profiles ;;
        DOWN) save_new_profile; load_profiles ;;
        B)    break ;;
    esac
done

LED FINISH
LOG green "Goodbye!"
```

---

## 18. Advanced Patterns

### Non-Blocking Button Read (for game loops / attack loops)

```bash
# Read from /dev/input/event0 for real-time button polling
check_button() {
    timeout 0.1 cat /dev/input/event0 2>/dev/null | xxd -p | head -c 48
}
# Note: Parsing evdev requires binary interpretation — prefer WAIT_FOR_INPUT when possible
```

### UCI Configuration System (OpenWrt)

```bash
# Read UCI values
current_color=$(uci get system.@pager[0].led_color)
dim_brightness=$(uci get system.@pager[0].dim_brightness)

# Write UCI values
uci set network.mynet=interface
uci set network.mynet.proto='static'
uci set network.mynet.ipaddr='10.0.0.1'
uci commit network
/etc/init.d/network reload
```

### nftables Firewall (OpenWrt 24.10+)

```bash
# Create a new nftables table
nft add table ip mytable
nft add chain ip mytable mychain '{ type filter hook forward priority 0; policy drop; }'
nft add rule ip mytable mychain ip saddr 10.0.0.0/24 accept

# Cleanup
nft delete table ip mytable
```

### Background Process Management

```bash
# Start background capture
tcpdump -i wlan0mon -w /tmp/capture.pcap &
CAPTURE_PID=$!

# Cleanup on exit
cleanup() {
    [ -n "$CAPTURE_PID" ] && kill $CAPTURE_PID 2>/dev/null
    wait $CAPTURE_PID 2>/dev/null
}
trap cleanup EXIT

# Wait for user to stop
PROMPT "Press any button to stop capture"
```

### External API Calls

```bash
# Use curl for HTTP APIs
response=$(curl -s -X POST "https://api.example.com/endpoint" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "{\"data\": \"$value\"}")

# Parse JSON with jq (install via opkg if needed)
result=$(echo "$response" | jq -r '.result')
```

### Monitor Interface Creation (for packet capture)

```bash
# Create monitor mode interface
iw phy phy0 interface add wlan0mon type monitor
ip link set wlan0mon up

# Cleanup
ip link set wlan0mon down
iw dev wlan0mon del
```

### Python Notification API (from Evil Portal)

```bash
# Send notification to Pager UI from a daemon/service
PYTHONPATH=/usr/lib/pineapple /usr/bin/python3 /usr/bin/notify info "New credential captured" evilportal
```

### Excluding Management Subnet

When scanning local networks, always exclude the management subnet:

```bash
# Get non-management IPs
ip -4 addr show | grep inet | grep -v "172.16.52" | awk '{print $2}'
```

---

## Quick Reference Card

```
┌──────────────────────────────────────────────────────────────────┐
│                  WiFi Pineapple Pager — Quick Ref                │
├──────────────────────────────────────────────────────────────────┤
│ UI:          LOG  ALERT  PROMPT  ERROR_DIALOG                    │
│ Pickers:     TEXT_PICKER  NUMBER_PICKER  IP_PICKER  MAC_PICKER   │
│ Confirm:     CONFIRMATION_DIALOG → $DUCKYSCRIPT_USER_CONFIRMED   │
│ Buttons:     WAIT_FOR_INPUT → UP DOWN LEFT RIGHT A B             │
│ Spinner:     id=$(START_SPINNER "msg")  ...  STOP_SPINNER $id    │
│ LED:         LED SETUP → LED ATTACK → LED FINISH / LED FAIL     │
│ Sound:       RINGTONE "alert|success|error|warning|xp|getkey"    │
│ Vibrate:     VIBRATE 200 100 200                                 │
│ Persist:     PAYLOAD_SET_CONFIG "ns" "key" "val"                 │
│ WiFi:        PINEAPPLE_SSID_POOL_ADD  PINEAPPLE_DEAUTH_CLIENT   │
│ GPS:         GPS_LIST  GPS_CONFIGURE  WIGLE_START  WIGLE_UPLOAD  │
│ Loot:        /root/loot/your_payload/                            │
│ Error:       case $? in $DUCKYSCRIPT_CANCELLED) ... esac         │
│ Cleanup:     trap cleanup EXIT INT TERM                          │
└──────────────────────────────────────────────────────────────────┘
```
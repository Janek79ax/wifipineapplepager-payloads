#!/bin/bash
# Title: Burp Redirect Remove
# Description: Remove Burp Suite redirect and restore normal client traffic flow
# Author: Janek
# Version: 2.0
# Category: Interception

PAYLOAD_NAME="burp_redirect"
BRIDGE_MASTER="br-lan"
EVIL_BRIDGE="br-evil"

LOG "Stopping Burp Redirect services..."

# ============================================================
# Kill DNS hijacking
# ============================================================
if [ -f /tmp/burp_redirect-dns.pid ]; then
    OLD_PID=$(cat /tmp/burp_redirect-dns.pid)
    if kill -0 $OLD_PID 2>/dev/null; then
        kill -9 $OLD_PID 2>/dev/null
        LOG "  Stopped DNS hijacking (PID: $OLD_PID)"
    fi
    rm -f /tmp/burp_redirect-dns.pid
fi

DNSMASQ_PIDS=$(netstat -plant 2>/dev/null | grep ':1053' | awk '{print $NF}' | sed 's/\/dnsmasq//g' | grep -E '^[0-9]+$')
if [ -n "$DNSMASQ_PIDS" ]; then
    for pid in $DNSMASQ_PIDS; do
        kill -9 $pid 2>/dev/null
        LOG "  Killed dnsmasq PID: $pid"
    done
fi

pkill -9 -f "dnsmasq.*1053" 2>/dev/null
sleep 1

# ============================================================
# Kill pcap capture (passive mode)
# ============================================================
if [ -f /tmp/burp_redirect-pcap.pid ]; then
    PCAP_PID=$(cat /tmp/burp_redirect-pcap.pid)
    if kill -0 $PCAP_PID 2>/dev/null; then
        kill $PCAP_PID 2>/dev/null
        wait $PCAP_PID 2>/dev/null
        PCAP_FILE=$(PAYLOAD_GET_CONFIG "$PAYLOAD_NAME" "pcap_file")
        LOG "  Stopped packet capture (PID: $PCAP_PID)"
        [ -n "$PCAP_FILE" ] && LOG "  Pcap saved: $PCAP_FILE"
    fi
    rm -f /tmp/burp_redirect-pcap.pid
fi

# ============================================================
# Remove UCI firewall redirect rules
# ============================================================
LOG "Removing firewall redirect rules..."

RULES_REMOVED=0
while true; do
    LAST_INDEX=""
    LAST_NAME=""

    for section in $(uci show firewall | grep "@redirect\[" | cut -d'.' -f2 | cut -d'=' -f1 | sort -u); do
        rule_name=$(uci get firewall.$section.name 2>/dev/null)
        if [ -n "$rule_name" ] && echo "$rule_name" | grep -qi "burpredirect"; then
            idx=$(echo "$section" | sed 's/@redirect\[\([0-9]*\)\].*/\1/')
            if [ -n "$idx" ]; then
                if [ -z "$LAST_INDEX" ] || [ "$idx" -gt "$LAST_INDEX" ]; then
                    LAST_INDEX="$idx"
                    LAST_NAME="$rule_name"
                fi
            fi
        fi
    done

    [ -z "$LAST_INDEX" ] && break

    uci delete firewall.@redirect[$LAST_INDEX] 2>/dev/null
    LOG "  Removed: $LAST_NAME"
    RULES_REMOVED=$((RULES_REMOVED + 1))
done

if [ "$RULES_REMOVED" -gt 0 ]; then
    uci commit firewall
    LOG "  Removed $RULES_REMOVED firewall rule(s)"
else
    LOG "  No firewall rules found to remove"
fi

# ============================================================
# Re-enable IPv6
# ============================================================
LOG "Re-enabling IPv6..."
sysctl -w net.ipv6.conf.${BRIDGE_MASTER}.disable_ipv6=0 2>/dev/null || true
sysctl -w net.ipv6.conf.${EVIL_BRIDGE}.disable_ipv6=0 2>/dev/null || true

# ============================================================
# Cleanup temp files
# ============================================================
LOG "Cleaning up..."
rm -f /tmp/burp_redirect-dns.pid
rm -f /tmp/burp_redirect-pcap.pid
rm -f /tmp/burp_whitelist.txt
rm -f /tmp/burp_redirect_dns.log

# ============================================================
# Restart firewall (also removes runtime nft rules: QUIC block, whitelist)
# ============================================================
LOG "Restarting firewall..."
/etc/init.d/firewall restart
LOG "  Firewall restarted"

# ============================================================
# Verify cleanup
# ============================================================
LOG "Verifying..."

if netstat -plant 2>/dev/null | grep -q ':1053'; then
    LOG red "DNS hijacking still active on port 1053"
else
    LOG green "DNS hijacking stopped"
fi

RULE_COUNT=$(uci show firewall | grep -c "BurpRedirect" || true)
if [ "$RULE_COUNT" -eq 0 ]; then
    LOG green "All firewall rules removed"
else
    LOG red "$RULE_COUNT BurpRedirect rules still present"
fi

IPV6_LAN=$(sysctl -n net.ipv6.conf.${BRIDGE_MASTER}.disable_ipv6 2>/dev/null)
IPV6_EVIL=$(sysctl -n net.ipv6.conf.${EVIL_BRIDGE}.disable_ipv6 2>/dev/null)
if [ "$IPV6_LAN" = "0" ] && [ "$IPV6_EVIL" = "0" ]; then
    LOG green "IPv6 re-enabled"
else
    LOG yellow "IPv6 may still be disabled (lan=$IPV6_LAN evil=$IPV6_EVIL)"
fi

LOG green "Burp Redirect removed. Normal traffic restored."

exit 0

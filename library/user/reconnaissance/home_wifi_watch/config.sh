# Optional override. Empty means: detect the first interface whose real type is monitor.
# Example: INTERFACE="wlan1mon"
INTERFACE=""
MIN_RSSI=-80
# At least 3 strong observations in distinct seconds within 15 seconds.
CONFIRM_COUNT=3
CONFIRM_WINDOW=15
# Minimum interval between repeats of the same event (seconds).
ALERT_COOLDOWN=300
STATE_DIR="/root/loot/home_wifi_watch"

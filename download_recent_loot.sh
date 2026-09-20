#!/bin/bash

set -u

PINEAPPLE_IP="172.16.52.1"
REMOTE_LOOT_DIR="/mmc/root/loot"
LOCAL_LOOT_DIR="./loot"

read -r -s -p "Podaj hasło do Pineapple: " HASLO
echo

mkdir -p "$LOCAL_LOOT_DIR"

sshpass -p "$HASLO" ssh -o StrictHostKeyChecking=no "root@$PINEAPPLE_IP" \
  "find '$REMOTE_LOOT_DIR' -type f -mmin -1440 -print" |
while IFS= read -r remote_file; do
  relative_file="${remote_file#"$REMOTE_LOOT_DIR"/}"
  local_file="$LOCAL_LOOT_DIR/$relative_file"
  local_dir="$(dirname "$local_file")"

  mkdir -p "$local_dir"
  echo "Ściąganie: $remote_file"
  sshpass -p "$HASLO" scp -o StrictHostKeyChecking=no \
    "root@$PINEAPPLE_IP:$remote_file" "$local_file"
done

unset HASLO
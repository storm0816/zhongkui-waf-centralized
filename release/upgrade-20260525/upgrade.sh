#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="${1:-/opt/openresty/zhongkui-waf}"
NGINX_BIN="${NGINX_BIN:-/opt/openresty/nginx/sbin/nginx}"
OWNER="${OWNER:-webuser:users}"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/openresty/zhongkui-waf-backup}"
TS="$(date +%Y%m%d_%H%M%S)"
PKG_DIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD_DIR="$PKG_DIR/payload"
FILES_LIST="$PKG_DIR/FILES.list"
BACKUP_DIR="$BACKUP_ROOT/upgrade_$TS"

if [[ ! -d "$BASE_DIR" ]]; then
  echo "[ERROR] BASE_DIR not found: $BASE_DIR"
  exit 1
fi
if [[ ! -x "$NGINX_BIN" ]]; then
  echo "[ERROR] nginx binary not executable: $NGINX_BIN"
  exit 1
fi
if [[ ! -f "$FILES_LIST" ]]; then
  echo "[ERROR] FILES.list missing"
  exit 1
fi

echo "[1/6] backup old files -> $BACKUP_DIR"
sudo mkdir -p "$BACKUP_DIR"
while IFS= read -r rel; do
  [[ -z "$rel" ]] && continue
  src="$BASE_DIR/$rel"
  dst="$BACKUP_DIR/$rel"
  sudo mkdir -p "$(dirname "$dst")"
  if [[ -f "$src" ]]; then
    sudo cp -a "$src" "$dst"
  fi
done < "$FILES_LIST"

echo "[2/6] copy new files"
while IFS= read -r rel; do
  [[ -z "$rel" ]] && continue
  src="$PAYLOAD_DIR/$rel"
  dst="$BASE_DIR/$rel"
  if [[ ! -f "$src" ]]; then
    echo "[ERROR] payload missing: $rel"
    exit 1
  fi
  sudo mkdir -p "$(dirname "$dst")"
  sudo cp -f "$src" "$dst"
done < "$FILES_LIST"

echo "[3/6] fix owner and perms"
while IFS= read -r rel; do
  [[ -z "$rel" ]] && continue
  dst="$BASE_DIR/$rel"
  sudo chown "$OWNER" "$dst"
  sudo chmod 644 "$dst"
done < "$FILES_LIST"

echo "[4/6] nginx config test"
sudo "$NGINX_BIN" -t

echo "[5/6] reload nginx"
sudo "$NGINX_BIN" -s reload

echo "[6/6] done"
echo "backup saved at: $BACKUP_DIR"

#!/usr/bin/env bash

set -Eeuo pipefail

TARGET_DIR="/opt/openresty/zhongkui-waf"
STATE_DIR="$TARGET_DIR/conf/.cluster"
COMMAND_FILE="$STATE_DIR/geoip-update.task"
STATUS_FILE="$STATE_DIR/geoip-update-status.json"
NGINX_BIN="/opt/openresty/nginx/sbin/nginx"

[[ -s "$COMMAND_FILE" ]] || exit 0

declare -A task=()
while IFS='=' read -r key value; do
    case "$key" in task_id|version|base_url|token|checksum|target_file) task[$key]="$value" ;; esac
done < "$COMMAND_FILE"

TASK_ID="${task[task_id]:-}"
VERSION="${task[version]:-}"
BASE_URL="${task[base_url]:-}"
TOKEN="${task[token]:-}"
EXPECTED_CHECKSUM="${task[checksum]:-}"
TARGET_FILE="${task[target_file]:-}"

[[ "$TASK_ID" =~ ^[A-Za-z0-9-]+$ ]] || exit 2
[[ "$VERSION" =~ ^[A-Za-z0-9.-]+$ ]] || exit 2
[[ "$BASE_URL" =~ ^http://[A-Za-z0-9.:-]+$ ]] || exit 2
[[ "$TOKEN" =~ ^[A-Za-z0-9-]+$ ]] || exit 2
[[ "$EXPECTED_CHECKSUM" =~ ^[a-f0-9]{64}$ ]] || exit 2
[[ "$TARGET_FILE" =~ ^/opt/openresty/share/GeoIP/[A-Za-z0-9_.-]+\.mmdb$ ]] || exit 2

WORK_FILE="${TARGET_FILE}.download.$TASK_ID"
BACKUP_FILE="${TARGET_FILE}.bak.$(date +%Y%m%d%H%M%S)"
ROLLED_BACK="off"

write_status() {
    local status="$1" progress="$2" message="$3"
    mkdir -p "$STATE_DIR"
    printf '{"task_id":"%s","target_version":"%s","status":"%s","progress":%s,"message":"%s","updated_at":"%s"}\n' \
        "$TASK_ID" "$VERSION" "$status" "$progress" "${message//\"/}" "$(date '+%F %T')" > "$STATUS_FILE"
}

rollback() {
    [[ "$ROLLED_BACK" == "on" ]] && return
    ROLLED_BACK="on"
    rm -f -- "$WORK_FILE" 2>/dev/null || true
    if [[ -f "$BACKUP_FILE" ]]; then
        cp -a -- "$BACKUP_FILE" "$TARGET_FILE" || true
        "$NGINX_BIN" -t && "$NGINX_BIN" -s reload || true
        write_status "rolled_back" 0 "GeoIP update failed and previous database was restored"
    else
        write_status "failed" 0 "GeoIP update failed before database switch"
    fi
}
trap rollback ERR

command -v mmdblookup >/dev/null 2>&1
mkdir -p "$(dirname "$TARGET_FILE")"
write_status "downloading" 15 "downloading GeoIP database"
curl -fsS --retry 3 --connect-timeout 5 --max-time 300 \
    --get --data-urlencode "version=$VERSION" --data-urlencode "token=$TOKEN" \
    "$BASE_URL/node-geoip/file" -o "$WORK_FILE"
[[ "$(sha256sum -- "$WORK_FILE" | awk '{print $1}')" == "$EXPECTED_CHECKSUM" ]]

write_status "validating" 60 "validating checksum and fixed IP lookup"
mmdblookup --file "$WORK_FILE" --ip 8.8.8.8 country iso_code >/dev/null
[[ -s "$WORK_FILE" ]]

if [[ -f "$TARGET_FILE" ]]; then cp -a -- "$TARGET_FILE" "$BACKUP_FILE"; fi
write_status "switching" 80 "switching GeoIP database"
mv -f -- "$WORK_FILE" "$TARGET_FILE"
chown webuser:users "$TARGET_FILE" 2>/dev/null || true
chmod 644 "$TARGET_FILE"
"$NGINX_BIN" -t
"$NGINX_BIN" -s reload
write_status "success" 100 "GeoIP update completed"
rm -f -- "$COMMAND_FILE" "$BACKUP_FILE"
trap - ERR

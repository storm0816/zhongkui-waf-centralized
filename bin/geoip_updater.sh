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
CURRENT_STEP="初始化"
FAILURE_DETAIL=""

compact_output() {
    tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g' | cut -c1-600
}

write_status() {
    local status="$1" progress="$2" message="$3"
    message="${message//$'\n'/ }"
    message="${message//\\/\\\\}"
    message="${message//\"/\\\"}"
    mkdir -p "$STATE_DIR"
    printf '{"task_id":"%s","target_version":"%s","status":"%s","progress":%s,"message":"%s","updated_at":"%s"}\n' \
        "$TASK_ID" "$VERSION" "$status" "$progress" "$message" "$(date '+%F %T')" > "$STATUS_FILE"
}

validate_nginx_config() {
    local output
    if ! output="$("$NGINX_BIN" -t 2>&1)"; then
        FAILURE_DETAIL="Nginx 配置校验失败：$(printf '%s' "$output" | compact_output)"
        return 1
    fi
}

reload_nginx() {
    local output
    if ! output="$("$NGINX_BIN" -s reload 2>&1)"; then
        FAILURE_DETAIL="Nginx 重载失败：$(printf '%s' "$output" | compact_output)"
        return 1
    fi
}

rollback() {
    [[ "$ROLLED_BACK" == "on" ]] && return
    ROLLED_BACK="on"
    local detail="${FAILURE_DETAIL:-$CURRENT_STEP 失败}"
    rm -f -- "$WORK_FILE" 2>/dev/null || true
    if [[ -f "$BACKUP_FILE" ]]; then
        cp -a -- "$BACKUP_FILE" "$TARGET_FILE" || true
        if validate_nginx_config && reload_nginx; then
            write_status "rolled_back" 0 "$detail；已回滚到上一份 GeoIP 数据"
        else
            write_status "failed" 0 "$detail；回滚后验证失败：${FAILURE_DETAIL:-未知错误}"
        fi
    else
        write_status "failed" 0 "$detail；切换前失败，未修改当前 GeoIP 数据"
    fi
}
trap rollback ERR

CURRENT_STEP="检查 mmdblookup 工具"
command -v mmdblookup >/dev/null 2>&1
mkdir -p "$(dirname "$TARGET_FILE")"
write_status "downloading" 15 "downloading GeoIP database"
CURRENT_STEP="下载 GeoIP 数据"
curl -fsS --retry 3 --connect-timeout 5 --max-time 300 \
    --get --data-urlencode "version=$VERSION" --data-urlencode "token=$TOKEN" \
    "$BASE_URL/node-geoip/file" -o "$WORK_FILE"
CURRENT_STEP="校验 GeoIP 文件 SHA-256"
[[ "$(sha256sum -- "$WORK_FILE" | awk '{print $1}')" == "$EXPECTED_CHECKSUM" ]]

write_status "validating" 60 "validating checksum and fixed IP lookup"
CURRENT_STEP="校验 GeoIP 数据可读性"
mmdblookup --file "$WORK_FILE" --ip 8.8.8.8 country iso_code >/dev/null
[[ -s "$WORK_FILE" ]]

if [[ -f "$TARGET_FILE" ]]; then cp -a -- "$TARGET_FILE" "$BACKUP_FILE"; fi
CURRENT_STEP="切换 GeoIP 数据"
write_status "switching" 80 "switching GeoIP database"
mv -f -- "$WORK_FILE" "$TARGET_FILE"
chown webuser:users "$TARGET_FILE" 2>/dev/null || true
chmod 644 "$TARGET_FILE"
CURRENT_STEP="Nginx 配置校验"
validate_nginx_config
CURRENT_STEP="Nginx 重载"
reload_nginx
write_status "success" 100 "GeoIP update completed"
rm -f -- "$COMMAND_FILE" "$BACKUP_FILE"
trap - ERR

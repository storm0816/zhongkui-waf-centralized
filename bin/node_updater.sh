#!/usr/bin/env bash

set -Eeuo pipefail

TARGET_DIR="/opt/openresty/zhongkui-waf"
STATE_DIR="$TARGET_DIR/conf/.cluster"
COMMAND_FILE="$STATE_DIR/program-update.task"
STATUS_FILE="$STATE_DIR/program-update-status.json"
NGINX_BIN="/opt/openresty/nginx/sbin/nginx"

[[ -s "$COMMAND_FILE" ]] || exit 0

declare -A task=()
while IFS='=' read -r key value; do
    case "$key" in task_id|version|base_url|token|manifest_checksum) task[$key]="$value" ;; esac
done < "$COMMAND_FILE"

TASK_ID="${task[task_id]:-}"
VERSION="${task[version]:-}"
BASE_URL="${task[base_url]:-}"
TOKEN="${task[token]:-}"
EXPECTED_MANIFEST="${task[manifest_checksum]:-}"

[[ "$TASK_ID" =~ ^[A-Za-z0-9-]+$ ]] || exit 2
[[ "$VERSION" =~ ^[A-Za-z0-9.-]+$ ]] || exit 2
[[ "$BASE_URL" =~ ^http://[A-Za-z0-9.:-]+$ ]] || exit 2
[[ "$TOKEN" =~ ^[A-Za-z0-9-]+$ ]] || exit 2
[[ "$EXPECTED_MANIFEST" =~ ^[a-f0-9]{64}$ ]] || exit 2

WORK_DIR="/opt/openresty/.zhongkui-update-$TASK_ID"
STAGE_DIR="${TARGET_DIR}.program.stage.$TASK_ID"
BACKUP_DIR="${TARGET_DIR}.program.bak.$(date +%Y%m%d%H%M%S)"
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
    if [[ -d "$BACKUP_DIR" ]]; then
        [[ -d "$TARGET_DIR" ]] && mv -- "$TARGET_DIR" "${TARGET_DIR}.program.failed.$TASK_ID" || true
        mv -- "$BACKUP_DIR" "$TARGET_DIR" || true
        if validate_nginx_config && reload_nginx; then
            write_status "rolled_back" 0 "$detail；已回滚到上一版本"
        else
            write_status "failed" 0 "$detail；回滚后验证失败：${FAILURE_DETAIL:-未知错误}"
        fi
    else
        write_status "failed" 0 "$detail；切换前失败，未修改当前版本"
    fi
    rm -rf -- "$WORK_DIR" "$STAGE_DIR" 2>/dev/null || true
}
trap rollback ERR

rm -rf -- "$WORK_DIR" "$STAGE_DIR"
mkdir -p "$WORK_DIR/files"
write_status "downloading" 10 "downloading release manifest"

CURRENT_STEP="下载发布清单"
curl -fsS --retry 3 --connect-timeout 5 --max-time 60 \
    --get --data-urlencode "version=$VERSION" --data-urlencode "token=$TOKEN" \
    "$BASE_URL/node-release/manifest" -o "$WORK_DIR/manifest.txt"

CURRENT_STEP="校验发布清单"
actual_manifest="$(sha256sum -- "$WORK_DIR/manifest.txt" | awk '{print $1}')"
[[ "$actual_manifest" == "$EXPECTED_MANIFEST" ]]

file_total="$(wc -l < "$WORK_DIR/manifest.txt" | tr -d ' ')"
file_index=0
while IFS=$'\t' read -r checksum size relative; do
    [[ "$relative" != /* && "$relative" != *..* && -n "$relative" ]]
    mkdir -p "$WORK_DIR/files/$(dirname "$relative")"
    if [[ -f "$TARGET_DIR/$relative" ]] && [[ "$(sha256sum -- "$TARGET_DIR/$relative" | awk '{print $1}')" == "$checksum" ]]; then
        cp -a -- "$TARGET_DIR/$relative" "$WORK_DIR/files/$relative"
    else
        CURRENT_STEP="下载发布文件：$relative"
        curl -fsS --retry 3 --connect-timeout 5 --max-time 300 \
            --get --data-urlencode "version=$VERSION" --data-urlencode "token=$TOKEN" \
            --data-urlencode "path=$relative" "$BASE_URL/node-release/file" -o "$WORK_DIR/files/$relative"
    fi
    CURRENT_STEP="校验发布文件：$relative"
    [[ "$(sha256sum -- "$WORK_DIR/files/$relative" | awk '{print $1}')" == "$checksum" ]]
    file_index=$((file_index + 1))
    progress=$((10 + (file_index * 65 / (file_total > 0 ? file_total : 1))))
    write_status "downloading" "$progress" "verified $file_index/$file_total files"
done < "$WORK_DIR/manifest.txt"

CURRENT_STEP="准备程序目录切换"
write_status "switching" 80 "preparing atomic switch"
cp -a -- "$TARGET_DIR" "$STAGE_DIR"
mkdir -p "$WORK_DIR/preserve/admin/conf" "$WORK_DIR/preserve/admin/admin/data"
[[ -f "$STAGE_DIR/admin/conf/sites.conf" ]] && cp -a "$STAGE_DIR/admin/conf/sites.conf" "$WORK_DIR/preserve/admin/conf/"
[[ -f "$STAGE_DIR/admin/admin/data/user.json" ]] && cp -a "$STAGE_DIR/admin/admin/data/user.json" "$WORK_DIR/preserve/admin/admin/data/"
rm -rf -- "$STAGE_DIR/admin" "$STAGE_DIR/lib" "$STAGE_DIR/html" "$STAGE_DIR/waf" "$STAGE_DIR/bin" "$STAGE_DIR/deploy"
rm -f -- "$STAGE_DIR/body_filter.lua" "$STAGE_DIR/config.lua" "$STAGE_DIR/header_filter.lua" \
    "$STAGE_DIR/init.lua" "$STAGE_DIR/init_worker.lua" "$STAGE_DIR/log_and_traffic.lua" \
    "$STAGE_DIR/waf.lua" "$STAGE_DIR/upgrade.sh"
cp -a -- "$WORK_DIR/files/." "$STAGE_DIR/"
if [[ -f "$WORK_DIR/preserve/admin/conf/sites.conf" ]]; then
    mkdir -p "$STAGE_DIR/admin/conf"
    cp -a "$WORK_DIR/preserve/admin/conf/sites.conf" "$STAGE_DIR/admin/conf/"
fi
if [[ -f "$WORK_DIR/preserve/admin/admin/data/user.json" ]]; then
    mkdir -p "$STAGE_DIR/admin/admin/data"
    cp -a "$WORK_DIR/preserve/admin/admin/data/user.json" "$STAGE_DIR/admin/admin/data/"
fi
chmod +x "$STAGE_DIR/bin/node_updater.sh" "$STAGE_DIR/bin/program_release.sh" \
    "$STAGE_DIR/bin/geoip_updater.sh" "$STAGE_DIR/bin/geoip_release.sh" "$STAGE_DIR/upgrade.sh" 2>/dev/null || true

CURRENT_STEP="切换程序目录"
mv -- "$TARGET_DIR" "$BACKUP_DIR"
mv -- "$STAGE_DIR" "$TARGET_DIR"
CURRENT_STEP="加载升级服务配置"
cp -f "$TARGET_DIR/deploy/systemd/zhongkui-node-updater.service" /etc/systemd/system/
cp -f "$TARGET_DIR/deploy/systemd/zhongkui-node-updater.timer" /etc/systemd/system/
systemctl daemon-reload
CURRENT_STEP="Nginx 配置校验"
validate_nginx_config
CURRENT_STEP="Nginx 重载"
reload_nginx
write_status "success" 100 "upgrade completed"
rm -f -- "$COMMAND_FILE"
rm -rf -- "$WORK_DIR"
trap - ERR

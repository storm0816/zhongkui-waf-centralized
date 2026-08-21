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

write_status() {
    local status="$1" progress="$2" message="$3"
    mkdir -p "$STATE_DIR"
    printf '{"task_id":"%s","target_version":"%s","status":"%s","progress":%s,"message":"%s","updated_at":"%s"}\n' \
        "$TASK_ID" "$VERSION" "$status" "$progress" "${message//\"/}" "$(date '+%F %T')" > "$STATUS_FILE"
}

rollback() {
    [[ "$ROLLED_BACK" == "on" ]] && return
    ROLLED_BACK="on"
    if [[ -d "$BACKUP_DIR" ]]; then
        [[ -d "$TARGET_DIR" ]] && mv -- "$TARGET_DIR" "${TARGET_DIR}.program.failed.$TASK_ID" || true
        mv -- "$BACKUP_DIR" "$TARGET_DIR" || true
        "$NGINX_BIN" -t && "$NGINX_BIN" -s reload || true
        write_status "rolled_back" 0 "upgrade failed and previous version was restored"
    else
        write_status "failed" 0 "upgrade failed before program switch"
    fi
    rm -rf -- "$WORK_DIR" "$STAGE_DIR" 2>/dev/null || true
}
trap rollback ERR

rm -rf -- "$WORK_DIR" "$STAGE_DIR"
mkdir -p "$WORK_DIR/files"
write_status "downloading" 10 "downloading release manifest"

curl -fsS --retry 3 --connect-timeout 5 --max-time 60 \
    --get --data-urlencode "version=$VERSION" --data-urlencode "token=$TOKEN" \
    "$BASE_URL/node-release/manifest" -o "$WORK_DIR/manifest.txt"

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
        curl -fsS --retry 3 --connect-timeout 5 --max-time 300 \
            --get --data-urlencode "version=$VERSION" --data-urlencode "token=$TOKEN" \
            --data-urlencode "path=$relative" "$BASE_URL/node-release/file" -o "$WORK_DIR/files/$relative"
    fi
    [[ "$(sha256sum -- "$WORK_DIR/files/$relative" | awk '{print $1}')" == "$checksum" ]]
    file_index=$((file_index + 1))
    progress=$((10 + (file_index * 65 / (file_total > 0 ? file_total : 1))))
    write_status "downloading" "$progress" "verified $file_index/$file_total files"
done < "$WORK_DIR/manifest.txt"

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

mv -- "$TARGET_DIR" "$BACKUP_DIR"
mv -- "$STAGE_DIR" "$TARGET_DIR"
cp -f "$TARGET_DIR/deploy/systemd/zhongkui-node-updater.service" /etc/systemd/system/
cp -f "$TARGET_DIR/deploy/systemd/zhongkui-node-updater.timer" /etc/systemd/system/
systemctl daemon-reload
"$NGINX_BIN" -t
"$NGINX_BIN" -s reload
write_status "success" 100 "upgrade completed"
rm -f -- "$COMMAND_FILE"
rm -rf -- "$WORK_DIR"
trap - ERR

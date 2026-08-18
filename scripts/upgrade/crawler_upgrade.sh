#!/usr/bin/env bash

set -Eeuo pipefail

PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="/opt/openresty/zhongkui-waf"
NGINX_BIN="${OPENRESTY_NGINX:-/opt/openresty/nginx/sbin/nginx}"

usage() {
    echo "用法: sudo ./upgrade.sh [--project-root PATH] [--nginx-bin PATH]"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --project-root)
            PROJECT_ROOT="${2:?--project-root 需要填写路径}"
            shift 2
            ;;
        --project-root=*)
            PROJECT_ROOT="${1#*=}"
            shift
            ;;
        --nginx-bin)
            NGINX_BIN="${2:?--nginx-bin 需要填写路径}"
            shift 2
            ;;
        --nginx-bin=*)
            NGINX_BIN="${1#*=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "未知参数: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

PAYLOAD_DIR="$PACKAGE_DIR/payload"
MERGE_SCRIPT="$PACKAGE_DIR/merge_crawler_config.lua"
GLOBAL_CONFIG="$PROJECT_ROOT/conf/global.json"
FILES=(
    "admin/lua/cluster_node.lua"
    "admin/lua/bot.lua"
    "admin/view/cluster-nodes.html"
    "admin/view/defense/bot.html"
    "admin/view/defense/ip-filter.html"
    "admin/view/system/system.html"
    "config.lua"
    "lib/constants.lua"
    "lib/bot_uri.lua"
    "lib/captcha.lua"
    "lib/crawler.lua"
    "lib/lib.lua"
    "lib/sql.lua"
    "log_and_traffic.lua"
)

if [ "$(id -u)" -ne 0 ]; then
    echo "请使用 sudo 或 root 执行升级。" >&2
    exit 1
fi

if [ ! -d "$PROJECT_ROOT" ] || [ ! -f "$GLOBAL_CONFIG" ]; then
    echo "未找到 Zhongkui-WAF 或 conf/global.json: $PROJECT_ROOT" >&2
    exit 1
fi

if [ ! -x "$NGINX_BIN" ]; then
    echo "未找到可执行的 Nginx: $NGINX_BIN" >&2
    exit 1
fi

for relative_path in "${FILES[@]}"; do
    if [ ! -f "$PAYLOAD_DIR/$relative_path" ]; then
        echo "升级包缺少文件: payload/$relative_path" >&2
        exit 1
    fi
done

if [ ! -f "$MERGE_SCRIPT" ] || [ ! -f "$PACKAGE_DIR/SHA256SUMS" ]; then
    echo "升级包不完整，缺少配置合并脚本或 SHA256SUMS。" >&2
    exit 1
fi

echo "[0/5] 校验升级包完整性"
(
    cd "$PACKAGE_DIR"
    sha256sum -c SHA256SUMS
)

RESTY_BIN="/opt/openresty/bin/resty"
LUAJIT_BIN="/opt/openresty/luajit/bin/luajit"
if [ ! -x "$RESTY_BIN" ] && [ ! -x "$LUAJIT_BIN" ]; then
    echo "未找到 resty 或 luajit，无法安全合并 global.json。" >&2
    exit 1
fi

BACKUP_DIR="$PROJECT_ROOT/.upgrade-backup/1.4.3-$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR/conf"
cp -a "$GLOBAL_CONFIG" "$BACKUP_DIR/conf/global.json"

for relative_path in "${FILES[@]}"; do
    if [ -f "$PROJECT_ROOT/$relative_path" ]; then
        mkdir -p "$BACKUP_DIR/$(dirname "$relative_path")"
        cp -a "$PROJECT_ROOT/$relative_path" "$BACKUP_DIR/$relative_path"
    fi
done

rollback() {
    local exit_code=$?
    trap - ERR
    set +e
    echo "升级失败，正在从 $BACKUP_DIR 自动恢复。" >&2
    cp -a "$BACKUP_DIR/conf/global.json" "$GLOBAL_CONFIG"
    for relative_path in "${FILES[@]}"; do
        if [ -f "$BACKUP_DIR/$relative_path" ]; then
            cp -a "$BACKUP_DIR/$relative_path" "$PROJECT_ROOT/$relative_path"
        else
            rm -f "$PROJECT_ROOT/$relative_path"
        fi
    done
    "$NGINX_BIN" -t >/dev/null 2>&1 && "$NGINX_BIN" -s reload >/dev/null 2>&1
    echo "已恢复升级前文件。" >&2
    exit "$exit_code"
}
trap rollback ERR

echo "[1/5] 备份完成: $BACKUP_DIR"

for relative_path in "${FILES[@]}"; do
    mkdir -p "$PROJECT_ROOT/$(dirname "$relative_path")"
    cp -a "$PAYLOAD_DIR/$relative_path" "$PROJECT_ROOT/$relative_path"
done
echo "[2/5] 1.4.2 累积更新和 1.4.3 修复文件复制完成"

if [ -x "$RESTY_BIN" ]; then
    "$RESTY_BIN" "$MERGE_SCRIPT" "$GLOBAL_CONFIG"
else
    LUA_PATH="/opt/openresty/lualib/?.lua;;" \
    LUA_CPATH="/opt/openresty/lualib/?.so;;" \
        "$LUAJIT_BIN" "$MERGE_SCRIPT" "$GLOBAL_CONFIG"
fi
chown --reference="$BACKUP_DIR/conf/global.json" "$GLOBAL_CONFIG"
chmod --reference="$BACKUP_DIR/conf/global.json" "$GLOBAL_CONFIG"
echo "[3/5] crawler/robots 配置合并完成，原配置已保留"

"$NGINX_BIN" -t
echo "[4/5] Nginx 配置校验通过"

"$NGINX_BIN" -s reload
trap - ERR
echo "[5/5] Nginx 重载完成"
echo
echo "升级成功，当前版本: 1.4.3"
echo "所有 Worker 将在约 40 秒内完成集群规则同步。"
echo "备份目录: $BACKUP_DIR"

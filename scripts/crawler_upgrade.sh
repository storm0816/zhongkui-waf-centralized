#!/usr/bin/env bash

set -Eeuo pipefail

PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="/opt/openresty/zhongkui-waf"
NGINX_BIN="${OPENRESTY_NGINX:-/opt/openresty/nginx/sbin/nginx}"

usage() {
    echo "Usage: sudo ./upgrade.sh [--project-root PATH] [--nginx-bin PATH]"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --project-root)
            PROJECT_ROOT="${2:?--project-root requires a path}"
            shift 2
            ;;
        --project-root=*)
            PROJECT_ROOT="${1#*=}"
            shift
            ;;
        --nginx-bin)
            NGINX_BIN="${2:?--nginx-bin requires a path}"
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
    "admin/lua/bot.lua"
    "admin/view/defense/bot.html"
    "config.lua"
    "lib/lib.lua"
    "lib/crawler.lua"
)

if [ "$(id -u)" -ne 0 ]; then
    echo "请使用 sudo 或 root 执行升级。" >&2
    exit 1
fi

if [ ! -d "$PROJECT_ROOT" ] || [ ! -f "$GLOBAL_CONFIG" ]; then
    echo "未找到 Zhongkui-WAF 目录或 conf/global.json: $PROJECT_ROOT" >&2
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

if [ ! -f "$MERGE_SCRIPT" ]; then
    echo "升级包缺少配置合并脚本。" >&2
    exit 1
fi

if [ ! -f "$PACKAGE_DIR/SHA256SUMS" ]; then
    echo "升级包缺少 SHA256SUMS。" >&2
    exit 1
fi

echo "[0/4] 校验升级包完整性"
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

BACKUP_DIR="$PROJECT_ROOT/.upgrade-backup/crawler-$(date +%Y%m%d%H%M%S)"
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
    echo "升级失败，正在恢复备份: $BACKUP_DIR" >&2
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

echo "[1/4] 备份完成: $BACKUP_DIR"

for relative_path in "${FILES[@]}"; do
    mkdir -p "$PROJECT_ROOT/$(dirname "$relative_path")"
    cp -a "$PAYLOAD_DIR/$relative_path" "$PROJECT_ROOT/$relative_path"
done
echo "[2/4] 反爬虫代码更新完成"

if [ -x "$RESTY_BIN" ]; then
    "$RESTY_BIN" "$MERGE_SCRIPT" "$GLOBAL_CONFIG"
else
    LUA_PATH="/opt/openresty/lualib/?.lua;;" \
    LUA_CPATH="/opt/openresty/lualib/?.so;;" \
        "$LUAJIT_BIN" "$MERGE_SCRIPT" "$GLOBAL_CONFIG"
fi
chown --reference="$BACKUP_DIR/conf/global.json" "$GLOBAL_CONFIG"
chmod --reference="$BACKUP_DIR/conf/global.json" "$GLOBAL_CONFIG"
echo "[3/4] crawler/robots 配置合并完成"

"$NGINX_BIN" -t
"$NGINX_BIN" -s reload
trap - ERR

echo "[4/4] Nginx 校验和重载完成"
echo
echo "升级成功。"
echo "反爬虫默认关闭，请在后台确认阈值后再开启。"
echo "robots.txt 默认开启，默认内容为允许全部抓取。"
echo "备份目录: $BACKUP_DIR"

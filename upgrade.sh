#!/usr/bin/env bash

set -Eeuo pipefail

ROLE=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="/opt/openresty/zhongkui-waf"
NGINX_BIN="/opt/openresty/nginx/sbin/nginx"
BACKUP_DIR=""
ROLLED_BACK="off"
MMDB_SOURCE="$SCRIPT_DIR/waf/GeoLite2-City.mmdb"
MMDB_TARGET="/opt/openresty/share/GeoIP/GeoLite2-City.mmdb"
MMDB_BACKUP=""

usage() {
    cat <<'EOF'
Usage: sudo ./upgrade.sh --role master|node

Upgrade an existing Zhongkui WAF instance without replacing its runtime
configuration. The current project is backed up before code is switched.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --role) ROLE="${2:?--role requires master or node}"; shift 2 ;;
        --role=*) ROLE="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [ "$ROLE" != "master" ] && [ "$ROLE" != "node" ]; then
    echo "--role must be master or node" >&2
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run with sudo" >&2
    exit 1
fi
if [ "$SCRIPT_DIR" = "$TARGET_DIR" ]; then
    echo "Run upgrade.sh from the extracted release package, not the installed directory" >&2
    exit 1
fi
if [ ! -f "$SCRIPT_DIR/conf/system-${ROLE}.json" ]; then
    echo "This is not a ${ROLE} release package" >&2
    exit 1
fi
if [ -f "$SCRIPT_DIR/conf/system-$([ "$ROLE" = master ] && echo node || echo master).json" ]; then
    echo "Release package contains the wrong role template" >&2
    exit 1
fi
if [ ! -d "$TARGET_DIR" ] || [ ! -f "$TARGET_DIR/conf/system.json" ]; then
    echo "No existing WAF installation found at $TARGET_DIR; use install.sh for a new server" >&2
    exit 1
fi
if [ ! -x "$NGINX_BIN" ]; then
    echo "OpenResty nginx binary not found: $NGINX_BIN" >&2
    exit 1
fi

timestamp="$(date +%Y%m%d%H%M%S)"
BACKUP_DIR="${TARGET_DIR}.upgrade.bak.${timestamp}"

rollback() {
    [ "$ROLLED_BACK" = "on" ] && return
    ROLLED_BACK="on"
    echo "[upgrade] validation failed, rolling back to $BACKUP_DIR" >&2
    if [ -d "$TARGET_DIR" ]; then
        mv "$TARGET_DIR" "${TARGET_DIR}.upgrade.failed.${timestamp}" || true
    fi
    mv "$BACKUP_DIR" "$TARGET_DIR"
    if [ -n "$MMDB_BACKUP" ] && [ -f "$MMDB_BACKUP" ]; then
        mkdir -p "$(dirname "$MMDB_TARGET")"
        mv -f "$MMDB_BACKUP" "$MMDB_TARGET"
    fi
    "$NGINX_BIN" -t && "$NGINX_BIN" -s reload || true
}
trap rollback ERR

# Per-server state must survive package upgrades. Rules are also retained so a
# node remains protected until its next successful cluster pull.
PRESERVE_PATHS=(
    "conf/system.json"
    "conf/global.json"
    "conf/intel_sources.json"
    "conf/ipgroup.json"
    "conf/website.json"
    "conf/certificate.json"
    "conf/global_rules"
    "admin/conf/sites.conf"
    "admin/admin/data/user.json"
)

echo "[upgrade] backing up current project to $BACKUP_DIR"
mv "$TARGET_DIR" "$BACKUP_DIR"
cp -a "$SCRIPT_DIR" "$TARGET_DIR"

for relative_path in "${PRESERVE_PATHS[@]}"; do
    source_path="$BACKUP_DIR/$relative_path"
    target_path="$TARGET_DIR/$relative_path"
    if [ -e "$source_path" ]; then
        rm -rf "$target_path"
        mkdir -p "$(dirname "$target_path")"
        cp -a "$source_path" "$target_path"
    fi
done

chown -R webuser:users "$TARGET_DIR" 2>/dev/null || true

if [ -f "$MMDB_SOURCE" ]; then
    mkdir -p "$(dirname "$MMDB_TARGET")"
    if [ -f "$MMDB_TARGET" ]; then
        MMDB_BACKUP="${MMDB_TARGET}.upgrade.bak.${timestamp}"
        cp -a "$MMDB_TARGET" "$MMDB_BACKUP"
    fi
    mmdb_tmp="${MMDB_TARGET}.upgrade.tmp.${timestamp}"
    cp -a "$MMDB_SOURCE" "$mmdb_tmp"
    mv -f "$mmdb_tmp" "$MMDB_TARGET"
fi

echo "[upgrade] validating nginx configuration"
"$NGINX_BIN" -t
"$NGINX_BIN" -s reload
trap - ERR

if [ -n "$MMDB_BACKUP" ] && [ -f "$MMDB_BACKUP" ]; then
    rm -f "$MMDB_BACKUP"
fi

echo "[upgrade] complete"
echo "[upgrade] backup retained at $BACKUP_DIR"

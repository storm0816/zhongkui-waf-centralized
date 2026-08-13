#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/dist"
VERSION=""
RELEASE_PROFILE="${RELEASE_PROFILE:-$PROJECT_ROOT/.zhongkui.release.env}"

usage() {
    cat <<'EOF'
Usage: ./scripts/build_release.sh [--version VERSION] [--output-dir DIR] [--profile FILE]

Creates role-specific release archives:
  zhongkui-waf-master-VERSION.tar.gz
  zhongkui-waf-node-VERSION.tar.gz

The Git templates stay masked. Production database and Redis values are read
only from the local, ignored release profile.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version requires a value}"; shift 2 ;;
        --version=*) VERSION="${1#*=}"; shift ;;
        --output-dir) OUTPUT_DIR="${2:?--output-dir requires a value}"; shift 2 ;;
        --output-dir=*) OUTPUT_DIR="${1#*=}"; shift ;;
        --profile) RELEASE_PROFILE="${2:?--profile requires a value}"; shift 2 ;;
        --profile=*) RELEASE_PROFILE="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [ -z "$VERSION" ]; then
    VERSION="$(sed -n "s/^[[:space:]]*_\?M\.APP_VERSION[[:space:]]*=[[:space:]]*['\"]\([^'\"]*\)['\"].*/\1/p" "$PROJECT_ROOT/lib/constants.lua" | head -n 1)"
fi
[ -n "$VERSION" ] || { echo "Unable to determine project version" >&2; exit 1; }

for command_name in tar sha256sum node; do
    command -v "$command_name" >/dev/null 2>&1 || { echo "Required command not found: $command_name" >&2; exit 1; }
done

[ -f "$RELEASE_PROFILE" ] || { echo "Release profile not found: $RELEASE_PROFILE" >&2; exit 1; }
# The profile is local and ignored by Git. It supplies production package values only.
# shellcheck disable=SC1090
source "$RELEASE_PROFILE"

require_value() {
    local name="$1"
    [ -n "${!name:-}" ] || { echo "Missing $name in $RELEASE_PROFILE" >&2; exit 1; }
}

for name in RELEASE_MYSQL_HOST RELEASE_MYSQL_PORT RELEASE_MYSQL_USER RELEASE_MYSQL_PASSWORD RELEASE_REDIS_HOST RELEASE_REDIS_PORT RELEASE_REDIS_PASSWORD; do
    require_value "$name"
done

validate_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "Invalid IPv4 address: $1" >&2; exit 1; }
}
validate_ipv4 "$RELEASE_MYSQL_HOST"
validate_ipv4 "$RELEASE_REDIS_HOST"

mkdir -p "$OUTPUT_DIR"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zhongkui-release.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

update_json_connection() {
    local file="$1"
    local role="$2"
    node - "$file" "$role" <<'NODE'
const fs = require("fs");
const [path, role] = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(path, "utf8"));

config.redis = {
    ...(config.redis || {}),
    host: process.env.RELEASE_REDIS_HOST,
    port: Number(process.env.RELEASE_REDIS_PORT),
    password: process.env.RELEASE_REDIS_PASSWORD,
};
if (role === "master") {
    config.mysql = {
        ...(config.mysql || {}),
        host: process.env.RELEASE_MYSQL_HOST,
        port: Number(process.env.RELEASE_MYSQL_PORT),
        user: process.env.RELEASE_MYSQL_USER,
        password: process.env.RELEASE_MYSQL_PASSWORD,
    };
}
fs.writeFileSync(path, `${JSON.stringify(config, null, 4)}\n`, "utf8");
NODE
}

build_role_package() {
    local role="$1"
    local package_name="zhongkui-waf-${role}-${VERSION}"
    local stage_dir="$WORK_DIR/$package_name"
    local archive_path="$OUTPUT_DIR/$package_name.tar.gz"

    mkdir -p "$stage_dir"
    cp -a "$PROJECT_ROOT/." "$stage_dir/"

    update_json_connection "$stage_dir/conf/system-${role}.json" "$role"
    rm -f "$stage_dir/conf/system-$([ "$role" = master ] && echo node || echo master).json"
    rm -rf "$stage_dir/.git" "$stage_dir/.github" "$stage_dir/dist" "$stage_dir/release" \
        "$stage_dir/.release-work" "$stage_dir/docs/superpowers" 2>/dev/null || true
    rm -f "$stage_dir/ssh" "$stage_dir/.zhongkui.private.env" "$stage_dir/.zhongkui.release.env" \
        "$stage_dir/conf/system.json" "$stage_dir"/*.sha256

    # DingTalk credentials must always be configured after deployment, never in an archive.
    if grep -q '"webhook"[[:space:]]*:[[:space:]]*"[^" ]' "$stage_dir/conf/system-${role}.json"; then
        echo "Refusing to package a DingTalk webhook" >&2
        exit 1
    fi

    rm -f "$archive_path" "$archive_path.sha256"
    tar -C "$WORK_DIR" -czf "$archive_path" "$package_name"
    (
        cd "$OUTPUT_DIR"
        sha256sum "$(basename "$archive_path")" > "$(basename "$archive_path").sha256"
    )
    echo "Release created: $archive_path"
}

export RELEASE_MYSQL_HOST RELEASE_MYSQL_PORT RELEASE_MYSQL_USER RELEASE_MYSQL_PASSWORD
export RELEASE_REDIS_HOST RELEASE_REDIS_PORT RELEASE_REDIS_PASSWORD
build_role_package master
build_role_package node

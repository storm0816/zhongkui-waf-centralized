#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/dist"
VERSION=""

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="${2:?--version requires a value}"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="${2:?--output-dir requires a path}"
            shift 2
            ;;
        -h|--help)
            echo "Usage: ./scripts/build_crawler_upgrade.sh [--version VERSION] [--output-dir PATH]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [ -z "$VERSION" ]; then
    VERSION="$(sed -n "s/^[[:space:]]*_\?M\.APP_VERSION[[:space:]]*=[[:space:]]*['\"]\([^'\"]*\)['\"].*/\1/p" "$PROJECT_ROOT/lib/constants.lua" | head -n 1)"
fi

if [ -z "$VERSION" ]; then
    echo "Unable to determine project version" >&2
    exit 1
fi

PACKAGE_NAME="zhongkui-waf-upgrade-$VERSION"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zhongkui-upgrade.XXXXXX")"
STAGE_DIR="$WORK_DIR/$PACKAGE_NAME"
ARCHIVE_PATH="$OUTPUT_DIR/$PACKAGE_NAME.tar.gz"
FILES=(
    "admin/lua/bot.lua"
    "admin/view/defense/bot.html"
    "admin/view/defense/ip-filter.html"
    "admin/view/system/system.html"
    "config.lua"
    "lib/constants.lua"
    "lib/crawler.lua"
    "lib/lib.lua"
    "lib/sql.lua"
    "log_and_traffic.lua"
)

trap 'rm -rf "$WORK_DIR"' EXIT
mkdir -p "$STAGE_DIR/payload" "$OUTPUT_DIR"

for relative_path in "${FILES[@]}"; do
    if [ ! -f "$PROJECT_ROOT/$relative_path" ]; then
        echo "Missing source file: $relative_path" >&2
        exit 1
    fi
    mkdir -p "$STAGE_DIR/payload/$(dirname "$relative_path")"
    cp -a "$PROJECT_ROOT/$relative_path" "$STAGE_DIR/payload/$relative_path"
done

cp "$SCRIPT_DIR/crawler_upgrade.sh" "$STAGE_DIR/upgrade.sh"
cp "$SCRIPT_DIR/merge_crawler_config.lua" "$STAGE_DIR/merge_crawler_config.lua"
cp "$PROJECT_ROOT/docs/CRAWLER_UPGRADE.md" "$STAGE_DIR/README.md"
chmod +x "$STAGE_DIR/upgrade.sh"

(
    cd "$STAGE_DIR"
    find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort | while IFS= read -r file; do
        sha256sum "$file"
    done > SHA256SUMS
)

rm -f "$ARCHIVE_PATH" "$ARCHIVE_PATH.sha256"
tar -C "$WORK_DIR" -czf "$ARCHIVE_PATH" "$PACKAGE_NAME"
(
    cd "$OUTPUT_DIR"
    sha256sum "$(basename "$ARCHIVE_PATH")" > "$(basename "$ARCHIVE_PATH").sha256"
)

echo "Upgrade package created: $ARCHIVE_PATH"
echo "Checksum created: $ARCHIVE_PATH.sha256"

echo "Building matching full release package..."
"$SCRIPT_DIR/build_release.sh" --version "$VERSION" --output-dir "$OUTPUT_DIR"

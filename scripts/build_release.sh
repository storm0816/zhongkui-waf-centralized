#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/dist"
VERSION=""

usage() {
    cat <<'EOF'
Usage: ./scripts/build_release.sh [--version VERSION] [--output-dir DIR]

Creates a self-contained Linux release archive and SHA256 checksum.
Runtime configuration, credentials, SSH files, Git metadata, and build output
are excluded from the archive.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="${2:?--version requires a value}"
            shift 2
            ;;
        --version=*)
            VERSION="${1#*=}"
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="${2:?--output-dir requires a value}"
            shift 2
            ;;
        --output-dir=*)
            OUTPUT_DIR="${1#*=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
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

for command_name in tar sha256sum; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Required command not found: $command_name" >&2
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zhongkui-release.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

PACKAGE_NAME="zhongkui-waf-${VERSION}"
STAGE_DIR="$WORK_DIR/$PACKAGE_NAME"
ARCHIVE_PATH="$OUTPUT_DIR/$PACKAGE_NAME.tar.gz"

mkdir -p "$STAGE_DIR"
cp -a "$PROJECT_ROOT/." "$STAGE_DIR/"

rm -rf \
    "$STAGE_DIR/.git" \
    "$STAGE_DIR/.github" \
    "$STAGE_DIR/dist" \
    "$STAGE_DIR/release" \
    "$STAGE_DIR/.release-work" \
    "$STAGE_DIR/docs/superpowers" 2>/dev/null || true
rm -f \
    "$STAGE_DIR/ssh" \
    "$STAGE_DIR/conf/system.json" \
    "$STAGE_DIR"/*.sha256

if grep -R -n -E '10\.33\.1\.' \
    "$STAGE_DIR/conf" "$STAGE_DIR/install.sh" >/dev/null 2>&1; then
    echo "Release contains credential-like configuration; review templates before publishing." >&2
fi

tar -C "$WORK_DIR" -czf "$ARCHIVE_PATH" "$PACKAGE_NAME"
sha256sum "$ARCHIVE_PATH" > "$ARCHIVE_PATH.sha256"

echo "Release created: $ARCHIVE_PATH"
echo "Checksum created: $ARCHIVE_PATH.sha256"

#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="${1:-}"
RELEASE_ROOT="${2:-}"
VERSION="${3:-}"

if [[ -z "$ROOT_DIR" || -z "$RELEASE_ROOT" || ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)?$ ]]; then
    echo "usage: program_release.sh ROOT_DIR RELEASE_ROOT VERSION" >&2
    exit 2
fi

ROOT_DIR="$(cd "$ROOT_DIR" && pwd)"
mkdir -p "$RELEASE_ROOT"
RELEASE_ROOT="$(cd "$RELEASE_ROOT" && pwd)"
FINAL_DIR="$RELEASE_ROOT/$VERSION"
TEMP_DIR="$RELEASE_ROOT/.tmp-$VERSION-$$"

if [[ -e "$FINAL_DIR" ]]; then
    echo "release already exists" >&2
    exit 3
fi

cleanup() { rm -rf -- "$TEMP_DIR"; }
trap cleanup EXIT
mkdir -p "$TEMP_DIR/files"

is_managed_file() {
    local relative="$1"
    case "$relative" in
        conf/*|dist/*|scripts/*|.git/*|.program-releases/*) return 1 ;;
        admin/admin/data/user.json|admin/conf/sites.conf) return 1 ;;
        *.zip|*.tar|*.tar.gz|*.tgz|*.bak|*.log|*.pid|*.mmdb) return 1 ;;
    esac
    case "$relative" in
        admin/*|lib/*|html/*|waf/*|bin/*|deploy/*|body_filter.lua|config.lua|header_filter.lua|init.lua|init_worker.lua|log_and_traffic.lua|waf.lua|upgrade.sh) return 0 ;;
    esac
    return 1
}

while IFS= read -r -d '' source_file; do
    relative="${source_file#"$ROOT_DIR"/}"
    if is_managed_file "$relative"; then
        mkdir -p "$TEMP_DIR/files/$(dirname "$relative")"
        cp -a -- "$source_file" "$TEMP_DIR/files/$relative"
    fi
done < <(find "$ROOT_DIR" -type f -print0)

manifest="$TEMP_DIR/manifest.txt"
: > "$manifest"
while IFS= read -r -d '' release_file; do
    relative="${release_file#"$TEMP_DIR/files/"}"
    checksum="$(sha256sum -- "$release_file" | awk '{print $1}')"
    size="$(stat -c '%s' -- "$release_file")"
    printf '%s\t%s\t%s\n' "$checksum" "$size" "$relative" >> "$manifest"
done < <(find "$TEMP_DIR/files" -type f -print0 | sort -z)

file_count="$(wc -l < "$manifest" | tr -d ' ')"
total_bytes="$(awk -F '\t' '{sum += $2} END {print sum + 0}' "$manifest")"
manifest_checksum="$(sha256sum -- "$manifest" | awk '{print $1}')"
printf '%s\n' "$manifest_checksum" > "$TEMP_DIR/manifest.sha256"
chmod -R a+rX "$TEMP_DIR"
mv -- "$TEMP_DIR" "$FINAL_DIR"
trap - EXIT

printf '%s|%s|%s\n' "$manifest_checksum" "$file_count" "$total_bytes"

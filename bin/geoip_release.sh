#!/usr/bin/env bash

set -Eeuo pipefail

SOURCE_FILE="${1:?source MMDB is required}"
RELEASE_ROOT="${2:?release root is required}"

[[ -s "$SOURCE_FILE" ]] || { echo "GeoIP source file is missing or empty" >&2; exit 1; }
command -v mmdblookup >/dev/null 2>&1 || { echo "mmdblookup is required" >&2; exit 1; }
mmdblookup --file "$SOURCE_FILE" --ip 8.8.8.8 country iso_code >/dev/null

checksum="$(sha256sum -- "$SOURCE_FILE" | awk '{print $1}')"
size="$(stat -c %s -- "$SOURCE_FILE")"
build_epoch="$(stat -c %Y -- "$SOURCE_FILE")"
version="$(date -d "@$build_epoch" +%Y%m%d)-${checksum:0:12}"
target="$RELEASE_ROOT/$version"

[[ ! -e "$target" ]] || { echo "GeoIP release $version already exists" >&2; exit 2; }
mkdir -p "$target"
cp -a -- "$SOURCE_FILE" "$target/GeoLite2-City.mmdb"
printf '%s  %s\n' "$checksum" "GeoLite2-City.mmdb" > "$target/SHA256SUMS"
printf '%s|%s|%s|%s\n' "$version" "$checksum" "$size" "$build_epoch"

#!/usr/bin/env bash

set -euo pipefail

ROLE=""
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_PATH=""
REDIS_CLI="${REDIS_CLI:-}"
MYSQL_BIN="${MYSQL_BIN:-}"

usage() {
  cat <<'EOF'
Usage: ./scripts/post_deploy_check.sh --role master|node [--project-root PATH] [--config PATH] [--redis-cli PATH]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)
      ROLE="${2:-}"
      shift 2
      ;;
    --project-root)
      PROJECT_ROOT="${2:-}"
      shift 2
      ;;
    --config)
      CONFIG_PATH="${2:-}"
      shift 2
      ;;
    --redis-cli)
      REDIS_CLI="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[FAIL] unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$ROLE" ]]; then
  echo "[FAIL] --role is required"
  usage
  exit 1
fi

if [[ "$ROLE" != "master" && "$ROLE" != "node" ]]; then
  echo "[FAIL] --role must be master or node"
  exit 1
fi

if [[ -z "$CONFIG_PATH" ]]; then
  CONFIG_PATH="$PROJECT_ROOT/conf/system.json"
fi

if [[ -z "$REDIS_CLI" ]]; then
  if command -v redis-cli >/dev/null 2>&1; then
    REDIS_CLI="$(command -v redis-cli)"
  elif [[ -x /opt/redis16381/redis-cli ]]; then
    REDIS_CLI="/opt/redis16381/redis-cli"
  else
    REDIS_CLI=""
  fi
fi

if [[ -z "$MYSQL_BIN" ]]; then
  if command -v mysql >/dev/null 2>&1; then
    MYSQL_BIN="$(command -v mysql)"
  elif [[ -x /opt/mysql/bin/mysql ]]; then
    MYSQL_BIN="/opt/mysql/bin/mysql"
  else
    MYSQL_BIN="mysql"
  fi
fi

PASS_COUNT=0
FAIL_COUNT=0

pass() {
  echo "[PASS] $1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
  echo "[FAIL] $1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

json_field() {
  local file="$1"
  local block="$2"
  local field="$3"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$file" "$block" "$field" <<'PY'
import json
import sys

path, block, field = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
value = data.get(block, {})
if isinstance(value, dict):
    result = value.get(field, "")
    print("" if result is None else result)
PY
    return
  fi

  awk -v block="\"$block\"" -v field="\"$field\"" '
    $0 ~ block"[[:space:]]*:[[:space:]]*\\{" { in_block=1; next }
    in_block && $0 ~ field"[[:space:]]*:" {
      line=$0
      gsub(/,/, "", line)
      gsub(/.*:[[:space:]]*/, "", line)
      gsub(/^"/, "", line)
      gsub(/"$/, "", line)
      print line
      exit
    }
    in_block && $0 ~ /^\s*\}/ { in_block=0 }
  ' "$file"
}

echo "== ZhongKui-WAF post-deploy check =="
echo "role: $ROLE"
echo "project_root: $PROJECT_ROOT"
echo "config: $CONFIG_PATH"
echo

if [[ ! -f "$CONFIG_PATH" ]]; then
  fail "config missing: $CONFIG_PATH"
  exit 1
fi

redis_host="$(json_field "$CONFIG_PATH" "redis" "host" || true)"
redis_port="$(json_field "$CONFIG_PATH" "redis" "port" || true)"
redis_password="$(json_field "$CONFIG_PATH" "redis" "password" || true)"
mysql_host="$(json_field "$CONFIG_PATH" "mysql" "host" || true)"
mysql_port="$(json_field "$CONFIG_PATH" "mysql" "port" || true)"
mysql_user="$(json_field "$CONFIG_PATH" "mysql" "user" || true)"
mysql_password="$(json_field "$CONFIG_PATH" "mysql" "password" || true)"
mysql_db="$(json_field "$CONFIG_PATH" "mysql" "database" || true)"

redis_get() {
  local key="$1"
  if [[ -z "$REDIS_CLI" ]]; then
    return 1
  fi
  "$REDIS_CLI" -h "$redis_host" -p "$redis_port" -a "$redis_password" GET "$key" 2>/dev/null
}

redis_exists() {
  local key="$1"
  if [[ -z "$REDIS_CLI" ]]; then
    return 1
  fi
  "$REDIS_CLI" -h "$redis_host" -p "$redis_port" -a "$redis_password" EXISTS "$key" 2>/dev/null
}

if [[ -n "$REDIS_CLI" ]]; then
  pass "redis-cli ready: $REDIS_CLI"
else
  fail "redis-cli not found"
fi

if [[ -n "$REDIS_CLI" ]]; then
  if [[ "$(redis_exists "waf:rules:ip_whitelist" || echo 0)" -ge 1 ]]; then
    pass "redis key exists: waf:rules:ip_whitelist"
  else
    fail "redis key missing: waf:rules:ip_whitelist"
  fi

  if [[ "$(redis_exists "waf:rules:ip_blacklist" || echo 0)" -ge 1 ]]; then
    pass "redis key exists: waf:rules:ip_blacklist"
  else
    fail "redis key missing: waf:rules:ip_blacklist"
  fi

  if [[ "$ROLE" == "master" ]]; then
    if [[ "$(redis_exists "waf:cluster:rules:snapshot:version" || echo 0)" -ge 1 ]]; then
      pass "redis key exists: waf:cluster:rules:snapshot:version"
    else
      fail "redis key missing: waf:cluster:rules:snapshot:version"
    fi
  fi
fi

if command -v "$MYSQL_BIN" >/dev/null 2>&1 && [[ -n "$mysql_host" && -n "$mysql_user" && -n "$mysql_db" ]]; then
  if MYSQL_PWD="$mysql_password" "$MYSQL_BIN" -h "$mysql_host" -P "$mysql_port" -u "$mysql_user" -D "$mysql_db" \
    -e "SELECT ip,rules_version,last_seen FROM waf_cluster_node ORDER BY last_seen DESC LIMIT 3;" >/dev/null 2>&1; then
    pass "mysql query ok: waf_cluster_node"
  else
    fail "mysql query failed: waf_cluster_node"
  fi
else
  if [[ "$ROLE" == "master" ]]; then
    fail "mysql client or mysql config missing"
  else
    pass "mysql check skipped for node"
  fi
fi

echo
echo "summary: pass=$PASS_COUNT fail=$FAIL_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi

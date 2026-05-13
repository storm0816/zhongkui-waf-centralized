#!/usr/bin/env bash

set -euo pipefail

ROLE=""
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_PATH=""
OPENRESTY_BIN="${OPENRESTY_BIN:-/opt/openresty/nginx/sbin/nginx}"

usage() {
  cat <<'EOF'
Usage: ./scripts/preflight_check.sh --role master|node [--project-root PATH] [--config PATH]
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

json_block_state() {
  local file="$1"
  local block="$2"
  awk -v block="\"$block\"" '
    $0 ~ block"[[:space:]]*:[[:space:]]*\\{" { in_block=1; next }
    in_block && $0 ~ /"state"[[:space:]]*:/ {
      if (match($0, /"(on|off)"/, m)) {
        print m[1]
        exit
      }
    }
    in_block && $0 ~ /^\s*\}/ { in_block=0 }
  ' "$file"
}

check_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    pass "file exists: $path"
  else
    fail "file missing: $path"
  fi
}

echo "== ZhongKui-WAF preflight check =="
echo "role: $ROLE"
echo "project_root: $PROJECT_ROOT"
echo "config: $CONFIG_PATH"
echo

check_file "$CONFIG_PATH"
check_file "$PROJECT_ROOT/conf/global.json"
check_file "$PROJECT_ROOT/conf/global_rules/ipWhiteList"
check_file "$PROJECT_ROOT/conf/global_rules/ipBlackList"
check_file "$PROJECT_ROOT/init.lua"
check_file "$PROJECT_ROOT/init_worker.lua"
check_file "$PROJECT_ROOT/waf.lua"

if [[ -x "$OPENRESTY_BIN" ]]; then
  pass "openresty binary exists: $OPENRESTY_BIN"
else
  fail "openresty binary missing or not executable: $OPENRESTY_BIN"
fi

if [[ -f "$CONFIG_PATH" ]]; then
  redis_state="$(json_block_state "$CONFIG_PATH" "redis" || true)"
  mysql_state="$(json_block_state "$CONFIG_PATH" "mysql" || true)"
  master_state="$(json_block_state "$CONFIG_PATH" "master" || true)"
  centralized_state="$(json_block_state "$CONFIG_PATH" "centralized" || true)"

  [[ "$redis_state" == "on" ]] && pass "redis.state=on" || fail "redis.state is not on"

  if [[ "$ROLE" == "master" ]]; then
    [[ "$master_state" == "on" ]] && pass "master.state=on" || fail "master.state should be on"
    [[ "$centralized_state" == "on" ]] && pass "centralized.state=on" || fail "centralized.state should be on"
    [[ "$mysql_state" == "on" ]] && pass "mysql.state=on" || fail "mysql.state should be on for master"
  else
    [[ "$master_state" == "off" ]] && pass "master.state=off" || fail "master.state should be off for node"
    [[ "$centralized_state" == "on" ]] && pass "centralized.state=on" || fail "centralized.state should be on for node"
    [[ "$mysql_state" == "off" ]] && pass "mysql.state=off" || fail "mysql.state should be off for node"
  fi
fi

if grep -q '"whiteIP"[[:space:]]*:' "$PROJECT_ROOT/conf/global.json"; then
  pass "global whiteIP config found"
else
  fail "global whiteIP config missing"
fi

if grep -q '"state"[[:space:]]*:[[:space:]]*"on"' "$PROJECT_ROOT/conf/global.json"; then
  pass "global.json contains enabled modules"
else
  fail "global.json seems abnormal: no enabled module found"
fi

if [[ -x "$OPENRESTY_BIN" ]]; then
  if "$OPENRESTY_BIN" -t >/dev/null 2>&1; then
    pass "nginx -t passed"
  else
    fail "nginx -t failed"
  fi
fi

echo
echo "summary: pass=$PASS_COUNT fail=$FAIL_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi

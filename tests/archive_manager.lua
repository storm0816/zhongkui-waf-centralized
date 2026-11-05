package.path = "admin/lua/?.lua;lib/?.lua;" .. package.path
ngx = {quote_sql_str=function(s) return "'" .. tostring(s):gsub("'", "''") .. "'" end}
local dropped, locked, audit_ok = false, true, true
local db = {}
function db:query(sql)
    if sql:find("INFORMATION_SCHEMA",1,true) then return {{TABLE_NAME="attack_log_archive_20261019_20261025"}} end
    if sql:find("COUNT",1,true) then return {{total=3}} end
    if sql:find("DROP TABLE",1,true) then dropped=true; return {} end
    error("unexpected query: " .. sql)
end
function db:close() end
package.preload.mysql_cli = function()
    return {query=function(sql)
        if sql:find("SHOW COLUMNS",1,true) then return {{Field="id"},{Field="occurred_at"},{Field="domain"}} end
        if sql:find("SELECT TABLE_ROWS AS total",1,true) then return {{total=7}} end
        if sql:find("INFORMATION_SCHEMA",1,true) then return {
            {TABLE_NAME="attack_log_archive_20261019_20261025",TABLE_ROWS=3,DATA_LENGTH=1024,INDEX_LENGTH=0},
            {TABLE_NAME="attack_log_archive_20261102_20261108",TABLE_ROWS=1,DATA_LENGTH=0,INDEX_LENGTH=0},
            {TABLE_NAME="attack_log_archive",TABLE_ROWS=2,DATA_LENGTH=0,INDEX_LENGTH=0},
            {TABLE_NAME="attack_log",TABLE_ROWS=100},
            {TABLE_NAME="sensitive_discovery",TABLE_ROWS=20},
            {TABLE_NAME="ip_block_log",TABLE_ROWS=10},
            {TABLE_NAME="waf_dingtalk_failure_log",TABLE_ROWS=7},
            {TABLE_NAME="waf_admin_audit_log",TABLE_ROWS=4},
            {TABLE_NAME="dingtalk_notification_archive_20261019_20261025",TABLE_ROWS=3},
            {TABLE_NAME="attack_log_archive_20261019_20261025_extra",TABLE_ROWS=100}
        } end
        if sql:find("FROM `waf_dingtalk_failure_log`",1,true) then
            assert(not sql:find("COUNT",1,true), "current table must not be fully counted")
            return {{id="1",domain="demo.test"}}
        end
        error("unexpected query: " .. sql)
    end, get_connection=function() return db end, close_connection=function() end}
end
package.preload.archive_batch = function()
    return {current_week=function() return "20261102", "20261108" end,
        current_week_on_connection=function() return "20261102", "20261108" end,
        acquire_lock=function() return locked, "busy" end, release_lock=function() return true end}
end
package.preload.auth_store = function() return {audit=function() return audit_ok and {} or nil end} end
package.preload.ip_utils = function() return {get_client_ip=function() return "127.0.0.1" end} end
local manager = require "archive_manager"
local list = assert(manager.list(1,20,""))
assert(list.total == 9)
for i, name in ipairs({"attack_log", "sensitive_discovery", "ip_block_log", "waf_dingtalk_failure_log", "waf_admin_audit_log"}) do
    assert(list.items[i].name == name and list.items[i].base and list.items[i].protected)
end
local attack = assert(manager.list(1,20,"attack"))
assert(attack.total == 4 and attack.items[1].name == "attack_log" and attack.items[4].legacy)
local dingtalk = assert(manager.list(1,20,"dingtalk"))
assert(dingtalk.total == 2 and dingtalk.items[1].name == "waf_dingtalk_failure_log")
local preview = assert(manager.preview("waf_dingtalk_failure_log",1,20))
assert(preview.estimated and preview.total == 7 and preview.items[1].domain == "demo.test")
local audit = assert(manager.list(1,20,"audit"))
assert(audit.total == 1 and audit.items[1].base)
local sensitive = assert(manager.list(1,20,"sensitive"))
assert(sensitive.total == 1 and sensitive.items[1].name == "sensitive_discovery")
local historical = "attack_log_archive_20261019_20261025"
assert(not manager.delete("attack_log", "attack_log", {}))
assert(not manager.delete("waf_dingtalk_failure_log", "waf_dingtalk_failure_log", {}))
assert(not manager.delete("waf_admin_audit_log", "waf_admin_audit_log", {}))
assert(not manager.delete("attack_log_archive", "attack_log_archive", {}))
assert(not manager.delete(historical .. ";DROP", historical .. ";DROP", {}))
assert(not manager.delete(historical, "wrong", {}))
assert(not manager.delete("attack_log_archive_20261102_20261108", "attack_log_archive_20261102_20261108", {}))
assert(not dropped)
locked=false
assert(not manager.delete(historical, historical, {}))
assert(not dropped)
locked=true; audit_ok=false
assert(not manager.delete(historical, historical, {}))
assert(not dropped)
audit_ok=true
local result = assert(manager.delete(historical, historical, {}))
assert(dropped and result.records == 3)
print("ARCHIVE_MANAGER_OK")

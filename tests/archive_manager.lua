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
        if sql:find("INFORMATION_SCHEMA",1,true) then return {
            {TABLE_NAME="attack_log_archive_20261019_20261025",TABLE_ROWS=3,DATA_LENGTH=1024,INDEX_LENGTH=0},
            {TABLE_NAME="attack_log_archive_20261102_20261108",TABLE_ROWS=1,DATA_LENGTH=0,INDEX_LENGTH=0},
            {TABLE_NAME="attack_log_archive",TABLE_ROWS=2,DATA_LENGTH=0,INDEX_LENGTH=0},
            {TABLE_NAME="attack_log",TABLE_ROWS=100},
            {TABLE_NAME="attack_log_archive_20261019_20261025_extra",TABLE_ROWS=100}
        } end
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
assert(list.total == 3 and list.items[1].protected and not list.items[2].protected and list.items[3].protected and list.items[3].legacy)
local historical = "attack_log_archive_20261019_20261025"
assert(not manager.delete("attack_log", "attack_log", {}))
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

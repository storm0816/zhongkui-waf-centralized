-- Run only on a test server: creates and removes a dedicated temporary database.
require "init"
local mysql = require "mysql_cli"
local base_connect = mysql.get_connection
local base_close = mysql.close_connection
local bootstrap = assert(base_connect())
local name = "waf_archive_verify_" .. tostring(ngx.time()) .. "_" .. tostring(ngx.worker.pid())
assert(name:match("^waf_archive_verify_%d+_%d+$"))
local created = bootstrap:query("CREATE DATABASE `" .. name .. "` CHARACTER SET utf8mb4")
assert(created, "test database creation failed; no existing database was modified")
local function query(db, sql)
    local result, err = db:query(sql)
    assert(result, err or sql)
    return result
end
local ok, err = xpcall(function()
    query(bootstrap, "USE `" .. name .. "`")
    query(bootstrap, "CREATE TABLE attack_log (id BIGINT UNSIGNED NOT NULL PRIMARY KEY, request_time DATETIME NOT NULL, payload VARCHAR(50) NOT NULL UNIQUE) ENGINE=InnoDB")
    query(bootstrap, "INSERT INTO attack_log VALUES (1,DATE_SUB(NOW(),INTERVAL 150 DAY),'old1'),(2,DATE_SUB(NOW(),INTERVAL 60 DAY),'old2'),(3,NOW(),'new')")
    mysql.get_connection = function()
        local db, connect_err = base_connect()
        if not db then return nil, connect_err end
        local selected, select_err = db:query("USE `" .. name .. "`")
        if not selected then db:close(); return nil, select_err end
        return db
    end
    mysql.close_connection = function(db) return db:close() end
    package.loaded.archive_batch = nil
    local archive = require "archive_batch"
    local result = archive.run("attack",30,2)
    assert(result.code == 0 and result.inserted == 2 and result.deleted == 2, result.error or result.msg)
    local current = query(bootstrap, "SELECT id FROM attack_log ORDER BY id")
    assert(#current == 1 and tonumber(current[1].id) == 3, "retention or ID ordering incorrect")
    assert(#query(bootstrap, "SELECT id FROM `" .. result.archive_table .. "` ORDER BY id") == 2)
    query(bootstrap, "INSERT INTO attack_log VALUES (4,DATE_SUB(NOW(),INTERVAL 90 DAY),'conflict')")
    query(bootstrap, "INSERT INTO `" .. result.archive_table .. "` VALUES (5,NOW(),'conflict')")
    local failed = archive.run("attack",30,2)
    assert(failed.code == 500, "unique-key conflict must fail")
    assert(#query(bootstrap, "SELECT id FROM attack_log WHERE id=4") == 1, "failed copy deleted source")
    query(bootstrap, "SELECT GET_LOCK('zk:waf:archive:attack',0)")
    local busy = archive.run("attack",30,2)
    assert(busy.code == 500, "held lock must stop concurrent archiving")
    query(bootstrap, "SELECT RELEASE_LOCK('zk:waf:archive:attack')")
    local historical = "attack_log_archive_20200106_20200112"
    query(bootstrap, "CREATE TABLE `" .. historical .. "` LIKE attack_log")
    query(bootstrap, "INSERT INTO `" .. historical .. "` VALUES (10,NOW(),'history')")
    local audit_enabled = true
    package.loaded.auth_store = {audit=function() return audit_enabled and {} or nil end}
    package.loaded.ip_utils = {get_client_ip=function() return "127.0.0.1" end}
    package.loaded.archive_manager = nil
    local manager = require "archive_manager"
    local listing = assert(manager.list(1,20,"attack"))
    assert(listing.total == 2, "current and historical tables should be listed")
    local preview = assert(manager.preview(historical,1,20))
    assert(preview.total == 1 and #preview.items == 1, "archive preview must paginate real records")
    assert(not manager.delete(result.archive_table, result.archive_table, {}), "current week must be protected")
    assert(not manager.delete(historical .. ";DROP", historical .. ";DROP", {}), "invalid table must be rejected")
    query(bootstrap, "SELECT GET_LOCK('zk:waf:archive:attack',0)")
    assert(not manager.delete(historical, historical, {}), "held lock must stop deletion")
    query(bootstrap, "SELECT RELEASE_LOCK('zk:waf:archive:attack')")
    assert(#query(bootstrap, "SELECT id FROM `" .. historical .. "`") == 1, "locked delete modified archive")
    audit_enabled = false
    assert(not manager.delete(historical, historical, {}), "failed audit must stop deletion")
    assert(#query(bootstrap, "SELECT id FROM `" .. historical .. "`") == 1, "audit failure modified archive")
    audit_enabled = true
    local deleted = assert(manager.delete(historical, historical, {}))
    assert(deleted.records == 1, "archive delete count incorrect")
    print("ARCHIVE_MYSQL_INTEGRATION_OK")
end, debug.traceback)
mysql.get_connection, mysql.close_connection = base_connect, base_close
local removed, remove_err = bootstrap:query("DROP DATABASE `" .. name .. "`")
bootstrap:close()
assert(removed, "test database cleanup failed: " .. tostring(remove_err))
assert(ok, err)

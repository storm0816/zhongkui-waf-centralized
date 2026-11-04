local mysql = require "mysql_cli"

local sources = {
    attack = {table_name="attack_log", time_column="request_time", prefix="attack_log_archive_"},
    sensitive = {table_name="sensitive_discovery", time_column="last_seen", prefix="sensitive_discovery_archive_"},
    blocking = {table_name="ip_block_log", time_column="start_time", prefix="ip_block_log_archive_"},
    dingtalk = {table_name="waf_dingtalk_failure_log", time_column="occurred_at", prefix="dingtalk_notification_archive_"},
    audit = {table_name="waf_admin_audit_log", time_column="created_at", prefix="waf_admin_audit_archive_"}
}

local _M = {}

local WEEK_SQL = [[SELECT DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL WEEKDAY(CURDATE()) DAY), '%Y%m%d') AS week_start,
    DATE_FORMAT(DATE_ADD(DATE_SUB(CURDATE(), INTERVAL WEEKDAY(CURDATE()) DAY), INTERVAL 6 DAY), '%Y%m%d') AS week_end]]

local function parse_week(rows)
    local row = rows and rows[1]
    local start_date, end_date = row and tostring(row.week_start or ""), row and tostring(row.week_end or "")
    if not start_date or not start_date:match("^%d%d%d%d%d%d%d%d$") or not end_date:match("^%d%d%d%d%d%d%d%d$") then
        return nil, "数据库归档周期不可用"
    end
    return start_date, end_date
end

function _M.current_week() return parse_week(mysql.query(WEEK_SQL)) end
function _M.current_week_on_connection(db) return parse_week(db:query(WEEK_SQL)) end

function _M.acquire_lock(db, kind)
    if not sources[kind] then return nil, "invalid archive type" end
    local rows, err = db:query("SELECT GET_LOCK(" .. ngx.quote_sql_str("zk:waf:archive:" .. kind) .. ",0) AS acquired")
    if not rows or not rows[1] or tonumber(rows[1].acquired) ~= 1 then return nil, err or "归档任务正在执行，请稍后重试" end
    return true
end

function _M.release_lock(db, kind)
    local rows = db:query("SELECT RELEASE_LOCK(" .. ngx.quote_sql_str("zk:waf:archive:" .. kind) .. ") AS released")
    return rows and rows[1] and tonumber(rows[1].released) == 1
end

function _M.run(kind, days, batch)
    local source = sources[kind]
    days, batch = tonumber(days), tonumber(batch)
    if not source or not days or days < 1 or days ~= math.floor(days)
        or not batch or batch < 1 or batch > 50000 or batch ~= math.floor(batch) then
        return {code=500, msg="invalid archive parameters"}
    end
    local db, connect_err = mysql.get_connection(8 * 1024 * 1024)
    if not db then return {code=500, msg="archive database unavailable", error=connect_err} end
    local locked, lock_err = _M.acquire_lock(db, kind)
    if not locked then db:close(); return {code=500, msg="archive lock unavailable", error=lock_err} end
    local active = false
    local function execute(sql)
        local result, err = db:query(sql)
        if not result then error(err or "database query failed") end
        return result
    end
    local ok, result = xpcall(function()
        local start_date, end_date = _M.current_week_on_connection(db)
        if not start_date then error(end_date or "archive week unavailable") end
        local archive = source.prefix .. start_date .. "_" .. end_date
        local pending = execute("SELECT CAST(id AS CHAR) AS id FROM `" .. source.table_name .. "` WHERE `" .. source.time_column
            .. "` < NOW() - INTERVAL " .. days .. " DAY ORDER BY id ASC LIMIT 1")
        if #pending == 0 then
            return {code=0, msg="no archive rows", inserted=0, deleted=0, archive_table=archive}
        end
        execute("CREATE TABLE IF NOT EXISTS `" .. archive .. "` LIKE `" .. source.table_name .. "`")
        local engines = execute("SELECT TABLE_NAME, ENGINE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE()"
            .. " AND TABLE_NAME IN (" .. ngx.quote_sql_str(source.table_name) .. "," .. ngx.quote_sql_str(archive) .. ")")
        local found = {}
        for _, row in ipairs(engines) do
            if tostring(row.ENGINE or ""):lower() ~= "innodb" then error("archive tables must use InnoDB") end
            found[row.TABLE_NAME] = true
        end
        if not found[source.table_name] or not found[archive] then error("archive table metadata unavailable") end
        execute("START TRANSACTION")
        active = true
        local rows = execute("SELECT CAST(id AS CHAR) AS id FROM `" .. source.table_name .. "` WHERE `" .. source.time_column
            .. "` < NOW() - INTERVAL " .. days .. " DAY ORDER BY id ASC LIMIT " .. batch .. " FOR UPDATE")
        if #rows == 0 then
            execute("COMMIT")
            active = false
            return {code=0, msg="no archive rows", inserted=0, deleted=0, archive_table=archive}
        end
        local ids = {}
        for _, row in ipairs(rows) do
            local id = tostring(row.id)
            if not id:match("^%d+$") then error("invalid archive record id") end
            ids[#ids + 1] = id
        end
        local selection = table.concat(ids, ",")
        local inserted = execute("INSERT INTO `" .. archive .. "` SELECT * FROM `" .. source.table_name .. "` WHERE id IN (" .. selection .. ")")
        if tonumber(inserted.affected_rows) ~= #ids then error("archive insert count mismatch") end
        local deleted = execute("DELETE FROM `" .. source.table_name .. "` WHERE id IN (" .. selection .. ")")
        if tonumber(deleted.affected_rows) ~= #ids then error("archive delete count mismatch") end
        execute("COMMIT")
        active = false
        return {code=0, msg="ok", inserted=#ids, deleted=#ids, archive_table=archive,
            archive_range=start_date .. "_" .. end_date, days=days, batch=batch}
    end, debug.traceback)
    if not ok then
        if active then
            local rolled_back = db:query("ROLLBACK")
            if not rolled_back then db:close(); return {code=500, msg="archive failed; rollback failed", error=result} end
        end
        if _M.release_lock(db, kind) then mysql.close_connection(db) else db:close() end
        ngx.log(ngx.ERR, "archive batch failed for ", kind, ": ", result)
        return {code=500, msg="archive batch failed", error=result}
    end
    if _M.release_lock(db, kind) then mysql.close_connection(db) else db:close() end
    return result
end

return _M

local mysql = require "mysql_cli"
local archive = require "archive_batch"
local auth_store = require "auth_store"
local ip_utils = require "ip_utils"

local _M = {}
local types = {
    {kind="attack", prefix="attack_log_archive_", legacy="attack_log_archive", title="攻击事件", columns={"id","request_time","server_name","ip","attack_type","action","request_uri"}},
    {kind="sensitive", prefix="sensitive_discovery_archive_", legacy="sensitive_discovery_archive", title="敏感数据发现", columns={"id","last_seen","server_name","node_ip","request_uri","rule_name","matched_sample","match_count","status"}},
    {kind="blocking", prefix="ip_block_log_archive_", title="IP封禁日志", columns={"id","start_time","server_name","ip","block_reason","action","block_duration","end_time"}},
    {kind="dingtalk", prefix="dingtalk_notification_archive_", title="钉钉发送记录", columns={"id","occurred_at","domain","ip","block_reason","action","send_status","error_message"}},
    {kind="audit", prefix="waf_admin_audit_archive_", title="账号审计", columns={"id","created_at","username","action","target","client_ip","result","detail"}}
}

local function classify(name)
    name = tostring(name or "")
    for _, item in ipairs(types) do
        if name == item.legacy then return item, "", "", true end
        if name:sub(1, #item.prefix) == item.prefix then
            local start_date, end_date = name:sub(#item.prefix + 1):match("^(%d%d%d%d%d%d%d%d)_(%d%d%d%d%d%d%d%d)$")
            if start_date and end_date and start_date <= end_date then return item, start_date, end_date end
        end
    end
end

local function exists(name)
    local rows = mysql.query("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=" .. ngx.quote_sql_str(name) .. " AND TABLE_TYPE='BASE TABLE'")
    if not rows then return nil, "查询归档表失败" end
    return rows[1] ~= nil
end

local function pagination(page, limit)
    page = math.floor(math.max(tonumber(page) or 1, 1))
    limit = math.floor(math.min(math.max(tonumber(limit) or 20, 1), 100))
    return page, limit
end

function _M.list(page, limit, kind)
    page, limit = pagination(page, limit)
    local rows = mysql.query([[SELECT TABLE_NAME, TABLE_ROWS, DATA_LENGTH, INDEX_LENGTH, CREATE_TIME
        FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE']])
    if not rows then return nil, "查询归档表失败" end
    local items = {}
    local current = archive.current_week()
    if not current then return nil, "无法确定当前归档周期" end
    for _, row in ipairs(rows) do
        local item, start_date, end_date, legacy = classify(row.TABLE_NAME)
        if item and (not kind or kind == "" or kind == item.kind) then
            items[#items+1] = {name=row.TABLE_NAME, kind=item.kind, title=item.title, start_date=start_date, end_date=end_date,
                estimated_rows=tonumber(row.TABLE_ROWS) or 0, bytes=(tonumber(row.DATA_LENGTH) or 0)+(tonumber(row.INDEX_LENGTH) or 0),
                created_at=row.CREATE_TIME, protected=legacy or end_date >= current, legacy=not not legacy}
        end
    end
    table.sort(items, function(a,b) if a.start_date == b.start_date then return a.name < b.name end return a.start_date > b.start_date end)
    local total, result = #items, {}
    for i=(page-1)*limit+1, math.min(page*limit,total) do result[#result+1]=items[i] end
    return {items=result, total=total, page=page, limit=limit}
end

function _M.preview(name, page, limit)
    local item = classify(name)
    if not item then return nil, "归档表名无效" end
    local found, err = exists(name)
    if not found then return nil, err or "归档表不存在" end
    page, limit = pagination(page, limit)
    local columns = mysql.query("SHOW COLUMNS FROM `" .. name .. "`")
    if not columns then return nil, "读取归档结构失败" end
    local available, selected = {}, {}
    for _, row in ipairs(columns) do available[row.Field] = true end
    for _, field in ipairs(item.columns) do if available[field] then selected[#selected+1] = field end end
    if #selected == 0 or not available.id then return nil, "归档表结构不受支持" end
    local quoted = {}
    for _, field in ipairs(selected) do
        quoted[#quoted+1] = field == "id" and "CAST(`id` AS CHAR) AS `id`" or "`" .. field .. "`"
    end
    local count = mysql.query("SELECT COUNT(*) AS total FROM `" .. name .. "`")
    local rows = mysql.query("SELECT " .. table.concat(quoted, ",") .. " FROM `" .. name .. "` ORDER BY id DESC LIMIT " .. ((page-1)*limit) .. "," .. limit)
    if not count or not rows then return nil, "读取归档内容失败" end
    return {columns=selected, items=rows, total=tonumber(count[1].total) or 0, page=page, limit=limit}
end

function _M.delete(name, confirmation, identity)
    local item, _, end_date, legacy = classify(name)
    if not item or confirmation ~= name then return nil, "归档表名或确认内容无效" end
    if legacy then return nil, "基础归档表受保护，不能删除" end
    local current = archive.current_week()
    if not current then return nil, "无法确定当前归档周期" end
    if end_date >= current then return nil, "当前或未来归档周期不能删除" end
    local db, err = mysql.get_connection()
    if not db then return nil, err or "数据库连接失败" end
    local locked, lock_err = archive.acquire_lock(db, item.kind)
    if not locked then db:close(); return nil, lock_err end
    local function release()
        if archive.release_lock(db, item.kind) then mysql.close_connection(db) else db:close() end
    end
    local locked_week = archive.current_week_on_connection(db)
    if not locked_week then release(); return nil, "无法确定当前归档周期" end
    if end_date >= locked_week then release(); return nil, "当前或未来归档周期不能删除" end
    local rows = db:query("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=" .. ngx.quote_sql_str(name) .. " AND TABLE_TYPE='BASE TABLE'")
    if not rows or not rows[1] then release(); return nil, "归档表不存在或查询失败" end
    local count = db:query("SELECT COUNT(*) AS total FROM `" .. name .. "`")
    if not count then release(); return nil, "统计归档记录失败" end
    local detail = "删除前记录数=" .. tostring(count[1].total)
    if not auth_store.audit(identity, "archive.delete.request", name, "success", detail, ip_utils.get_client_ip()) then
        release(); return nil, "无法写入审计日志，删除已取消"
    end
    local dropped, drop_err = db:query("DROP TABLE `" .. name .. "`")
    local audited = auth_store.audit(identity, "archive.delete", name, dropped and "success" or "failed", detail, ip_utils.get_client_ip())
    if not audited then ngx.log(ngx.ERR, "failed to record archive deletion result: ", name) end
    release()
    if not dropped then
        ngx.log(ngx.ERR, "archive deletion failed for ", name, ": ", drop_err or "unknown")
        return nil, "删除归档表失败，请查看服务日志"
    end
    return {deleted=name, records=tonumber(count[1].total) or 0, audit_recorded=not not audited}
end

return _M

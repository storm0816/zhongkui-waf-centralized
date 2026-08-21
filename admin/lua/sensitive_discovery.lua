-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)

local cjson = require "cjson"
local mysql = require "mysql_cli"
local pager = require "lib.pager"
local user = require "user"

local tonumber = tonumber
local quote_sql_str = ngx.quote_sql_str

local DEFAULT_PAGE = 1
local DEFAULT_LIMIT = 20
local MAX_LIMIT = 100

local function list_events()
    local args = ngx.req.get_uri_args() or {}
    local page = tonumber(args.page) or DEFAULT_PAGE
    local limit = tonumber(args.limit) or DEFAULT_LIMIT
    if page < 1 then page = DEFAULT_PAGE end
    if limit < 1 then limit = DEFAULT_LIMIT elseif limit > MAX_LIMIT then limit = MAX_LIMIT end

    local where = " WHERE 1=1 "
    local server_name = tostring(args.serverName or "")
    local status = tostring(args.status or "")
    local detection_type = tostring(args.detectionType or "")
    if server_name ~= "" then
        where = where .. " AND server_name LIKE " .. quote_sql_str("%" .. server_name .. "%")
    end
    if status == "open" or status == "acknowledged" or status == "ignored" then
        where = where .. " AND status=" .. quote_sql_str(status)
    end
    if detection_type == "regex" or detection_type == "word" then
        where = where .. " AND detection_type=" .. quote_sql_str(detection_type)
    end

    local count_rows, count_err = mysql.query("SELECT COUNT(*) AS total FROM sensitive_discovery" .. where)
    if not count_rows or not count_rows[1] then
        return {code = 500, msg = count_err or "query sensitive discovery count failed", data = {}}
    end

    local total = tonumber(count_rows[1].total) or 0
    local rows = {}
    if total > 0 then
        local offset = pager.get_begin(page, limit)
        local sql = [[SELECT id,node_ip,server_name,request_uri,http_method,content_type,
            rule_id,rule_name,detection_type,matched_sample,match_count,status,first_seen,last_seen
            FROM sensitive_discovery]] .. where .. " ORDER BY last_seen DESC,id DESC LIMIT " .. offset .. "," .. limit
        local query_rows, query_err = mysql.query(sql)
        if not query_rows then
            return {code = 500, msg = query_err or "query sensitive discovery failed", data = {}}
        end
        rows = query_rows
    end
    return {code = 0, msg = "", count = total, data = rows}
end

local function summary()
    local rows, err = mysql.query([[SELECT
        COALESCE(SUM(match_count),0) AS total_hits,
        COALESCE(SUM(CASE WHEN status='open' THEN 1 ELSE 0 END),0) AS open_events,
        COUNT(DISTINCT server_name) AS domain_count,
        MAX(last_seen) AS last_seen
        FROM sensitive_discovery WHERE last_seen >= NOW() - INTERVAL 24 HOUR]])
    if not rows then return {code = 500, msg = err or "query summary failed", data = {}} end
    return {code = 0, msg = "", data = rows[1] or {}}
end

local function do_request()
    if user.check_auth_token() == false then
        ngx.status = 401
        ngx.say(cjson.encode({code = 401, msg = "User not logged in"}))
        return
    end

    local response = {code = 404, msg = "not found", data = {}}
    if ngx.var.uri == "/sensitive-discovery/list" then
        response = list_events()
    elseif ngx.var.uri == "/sensitive-discovery/summary" then
        response = summary()
    end
    ngx.say(cjson.encode(response))
end

do_request()

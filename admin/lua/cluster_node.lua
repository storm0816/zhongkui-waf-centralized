local cjson = require "cjson"
local mysql = require "mysql_cli"
local pager = require "lib.pager"
local quote_sql_str = ngx.quote_sql_str
local tonumber = tonumber
local format = string.format
local config = require "config"
local get_system_config = config.get_system_config
local ngx_log = ngx.log
local ERR = ngx.ERR

local _M = {}

local DEFAULT_EXPIRE = 120
local MAX_LIMIT = 100

local function safe_get_expire()
    local sys_conf = get_system_config("system") or {}
    local expire = tonumber(sys_conf.expire)
    if not expire or expire <= 0 then
        expire = DEFAULT_EXPIRE
    end
    return expire
end

-- 节点列表
local function listNodes()
    local response = { code = 0, msg = "", count = 0, data = {} }
    local args = ngx.req.get_uri_args()
    local page = tonumber(args.page) or 1
    local limit = tonumber(args.limit) or 10

    if page < 1 then page = 1 end
    if limit < 1 then limit = 10 end
    if limit > MAX_LIMIT then limit = MAX_LIMIT end

    local offset = pager.get_begin(page, limit)
    local expire = safe_get_expire()

    local filter = ""
    if tostring(args.offline) == "1" then
        filter = string.format("WHERE last_seen < NOW() - INTERVAL %d SECOND", expire)
    end

    local sql_count = "SELECT COUNT(*) AS total FROM waf_cluster_node " .. filter
    local res, err = mysql.query(sql_count)
    if not res or not res[1] then
        ngx_log(ERR, "listNodes count query error: ", err or "nil")
        response.code = 500
        response.msg = "count query error"
        return response
    end
    response.count = tonumber(res[1].total) or 0

    if response.count > 0 then
        local sql_data = string.format([[
            SELECT ip, version, hostname, last_seen
            FROM waf_cluster_node
            %s
            ORDER BY last_seen DESC
            LIMIT %d OFFSET %d
        ]], filter, limit, offset)

        res, err = mysql.query(sql_data)
        if res then
            response.data = res
        else
            ngx_log(ERR, "listNodes select query error: ", err or "nil")
            response.code = 500
            response.msg = "select query error"
        end
    end

    return response
end

-- 节点统计
local function get_node_stats()
    local expire = safe_get_expire()
    local sql = string.format([[
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN last_seen >= NOW() - INTERVAL %d SECOND THEN 1 ELSE 0 END) AS online
        FROM waf_cluster_node
    ]], expire)

    local res, err = mysql.query(sql)
    if not res or not res[1] then
        ngx_log(ERR, "get_node_stats query error: ", err or "nil")
        return { code = 500, msg = "stats query error", data = {} }
    end

    local total = tonumber(res[1].total) or 0
    local online = tonumber(res[1].online) or 0

    return {
        code = 0,
        msg = "",
        data = {
            total = total,
            online = online,
            offline = math.max(total - online, 0)
        }
    }
end

-- 删除节点（仅允许离线节点）
local function delete_node(ip)
    local expire = safe_get_expire()
    local sql_check = format("SELECT last_seen FROM waf_cluster_node WHERE ip = %s", quote_sql_str(ip))
    local res = mysql.query(sql_check)
    if not res or not res[1] then
        return { code = 404, msg = "节点不存在" }
    end

    local last_seen = res[1].last_seen
    local last_ts

    -- 正确解析 MySQL 的 datetime 格式为时间戳
    local y, m, d, H, M, S = string.match(last_seen, "(%d+)%-(%d+)%-(%d+) (%d+):(%d+):(%d+)")
    if y then
        last_ts = os.time({ year = y, month = m, day = d, hour = H, min = M, sec = S })
    end

    local now_ts = ngx.time()

    if not last_ts or now_ts - last_ts <= expire then
        return { code = 403, msg = "仅允许删除离线节点" }
    end

    local sql_del = format("DELETE FROM waf_cluster_node WHERE ip = %s", quote_sql_str(ip))
    local del_res, err = mysql.query(sql_del)
    if del_res then
        return { code = 0, msg = "删除成功" }
    else
        ngx_log(ERR, "delete_node(): delete error: ", err or "nil")
        return { code = 500, msg = "删除失败：" .. (err or "") }
    end
end

-- 路由入口
function _M.do_request()
    ngx.header.content_type = "application/json; charset=utf-8"
    local uri = ngx.var.uri
    local response = {}

    if uri == "/clusternode/list" then
        response = listNodes()
    elseif uri == "/clusternode/stat" then
        response = get_node_stats()
    elseif uri == "/clusternode/delete" and ngx.req.get_method() == "POST" then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        local ok, data = pcall(cjson.decode, body or "")
        if ok and data and data.ip then
            response = delete_node(data.ip)
        else
            response = { code = 400, msg = "请求参数无效" }
        end
    else
        response = { code = 404, msg = "无效接口路径" }
    end

    ngx.say(cjson.encode(response))
end

_M.do_request()
return _M

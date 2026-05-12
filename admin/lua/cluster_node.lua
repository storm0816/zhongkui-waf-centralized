local cjson = require "cjson"
local mysql = require "mysql_cli"
local pager = require "lib.pager"
local user = require "user"
local quote_sql_str = ngx.quote_sql_str
local tonumber = tonumber
local format = string.format
local ipairs = ipairs
local config = require "config"
local get_system_config = config.get_system_config
local ngx_log = ngx.log
local ERR = ngx.ERR
local CLUSTER_RULES_VERSION_DICT_KEY = "cluster:rules:snapshot:version"
local CLUSTER_WHITELIST_VERSION_DICT_KEY = "cluster:ip_whitelist:version"
local CLUSTER_BLACKLIST_VERSION_DICT_KEY = "cluster:master:blacklist:version"

local _M = {}

local DEFAULT_EXPIRE = 120
local DEFAULT_OFFLINE_GRACE = 120
local MAX_LIMIT = 100

local function safe_get_expire()
    local sys_conf = get_system_config("system") or {}
    local expire = tonumber(sys_conf.expire)
    if not expire or expire <= 0 then
        expire = DEFAULT_EXPIRE
    end
    return expire
end

local function safe_get_offline_grace()
    local sys_conf = get_system_config("system") or {}
    local grace = tonumber(sys_conf.node_offline_grace)
    if not grace or grace < 0 then
        grace = DEFAULT_OFFLINE_GRACE
    end
    return grace
end

local function get_online_window()
    local expire = safe_get_expire()
    local grace = safe_get_offline_grace()
    return expire + grace, expire, grace
end

local function get_local_ip()
    local f = io.popen("hostname -I 2>/dev/null || hostname -i 2>/dev/null")
    if not f then
        return "unknown"
    end
    local line = f:read("*l")
    f:close()
    if not line then
        return "unknown"
    end
    local ip = line:match("(%d+%.%d+%.%d+%.%d+)")
    return ip or "unknown"
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
    local online_window, expire, grace = get_online_window()

    local filter = ""
    if tostring(args.offline) == "1" then
        filter = string.format("WHERE last_seen < NOW() - INTERVAL %d SECOND", online_window)
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

    local master_rules_version = "unknown"
    local master_whitelist_version = "unknown"
    local master_blacklist_version = "unknown"
    local master_ip = get_local_ip()
    local dict_config = ngx.shared.dict_config
    if dict_config then
        local v = dict_config:get(CLUSTER_RULES_VERSION_DICT_KEY)
        if v then
            master_rules_version = tostring(v)
        end
        v = dict_config:get(CLUSTER_WHITELIST_VERSION_DICT_KEY)
        if v then
            master_whitelist_version = tostring(v)
        end
        v = dict_config:get(CLUSTER_BLACKLIST_VERSION_DICT_KEY)
        if v then
            master_blacklist_version = tostring(v)
        end
    end

    if response.count > 0 then
        local sql_data = string.format([[
            SELECT ip,
                   COALESCE(NULLIF(rules_version, ''), 'unknown') AS rules_version,
                   COALESCE(NULLIF(whitelist_version, ''), 'unknown') AS whitelist_version,
                   COALESCE(NULLIF(blacklist_version, ''), 'unknown') AS blacklist_version,
                   COALESCE(NULLIF(rules_sync_status, ''), 'unknown') AS rules_sync_status,
                   rules_sync_at,
                   COALESCE(NULLIF(whitelist_sync_status, ''), 'unknown') AS whitelist_sync_status,
                   whitelist_sync_at,
                   COALESCE(NULLIF(blacklist_sync_status, ''), 'unknown') AS blacklist_sync_status,
                   blacklist_sync_at,
                   COALESCE(NULLIF(last_sync_status, ''), 'unknown') AS last_sync_status,
                   last_sync_at,
                   hostname,
                   last_seen,
                   CASE WHEN last_seen >= NOW() - INTERVAL %d SECOND THEN 1 ELSE 0 END AS is_online
            FROM waf_cluster_node
            %s
            ORDER BY CASE WHEN ip = %s THEN 0 ELSE 1 END ASC, last_seen DESC
            LIMIT %d OFFSET %d
        ]], online_window, filter, quote_sql_str(master_ip), limit, offset)

        res, err = mysql.query(sql_data)
        if res then
            for _, row in ipairs(res) do
                row.node_role = (row.ip == master_ip) and "master" or "node"
            end
            response.data = res
        else
            ngx_log(ERR, "listNodes select query error: ", err or "nil")
            response.code = 500
            response.msg = "select query error"
        end
    end

    response.expire = online_window
    response.base_expire = expire
    response.offline_grace = grace
    response.master_rules_version = master_rules_version
    response.master_whitelist_version = master_whitelist_version
    response.master_blacklist_version = master_blacklist_version
    response.master_ip = master_ip
    return response
end

-- 节点统计
local function get_node_stats()
    local online_window, expire, grace = get_online_window()
    local sql = string.format([[
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN last_seen >= NOW() - INTERVAL %d SECOND THEN 1 ELSE 0 END) AS online
        FROM waf_cluster_node
    ]], online_window)

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
            offline = math.max(total - online, 0),
            expire = online_window,
            base_expire = expire,
            offline_grace = grace
        }
    }
end

-- 近期受攻击节点概览
local function get_attack_summary()
    local response = { code = 0, msg = "", data = {} }
    local args = ngx.req.get_uri_args()
    local window_minutes = tonumber(args.windowMinutes) or 30
    if window_minutes < 5 then
        window_minutes = 5
    elseif window_minutes > 1440 then
        window_minutes = 1440
    end

    local master_ip = get_local_ip()
    local sql = format([[
        SELECT
            n.ip AS node_ip,
            COALESCE(NULLIF(n.hostname, ''), '-') AS hostname,
            COALESCE(NULLIF(n.rules_version, ''), 'unknown') AS rules_version,
            COALESCE(a.attack_count, 0) AS attack_count,
            COALESCE(a.attacker_count, 0) AS attacker_count,
            COALESCE(a.attack_type_count, 0) AS attack_type_count,
            COALESCE(a.block_count, 0) AS block_count,
            a.last_attack_time,
            n.last_seen
        FROM waf_cluster_node n
        LEFT JOIN (
            SELECT
                node_ip,
                COUNT(*) AS attack_count,
                COUNT(DISTINCT ip) AS attacker_count,
                COUNT(DISTINCT attack_type) AS attack_type_count,
                SUM(CASE WHEN UPPER(action) IN ('DENY','REDIRECT','CAPTCHA') THEN 1 ELSE 0 END) AS block_count,
                MAX(request_time) AS last_attack_time
            FROM attack_log
            WHERE request_time >= NOW() - INTERVAL %d MINUTE
              AND node_ip IS NOT NULL
              AND node_ip <> ''
            GROUP BY node_ip
        ) a ON a.node_ip = n.ip
        ORDER BY attack_count DESC, n.last_seen DESC
        LIMIT 500
    ]], window_minutes)

    local res, err = mysql.query(sql)
    if not res then
        ngx_log(ERR, "get_attack_summary query error: ", err or "nil")
        return { code = 500, msg = "summary query error", data = {} }
    end

    response.window_minutes = window_minutes
    response.master_ip = master_ip
    response.data = res
    return response
end

-- 删除节点（仅允许离线节点）
local function delete_node(ip)
    local online_window = get_online_window()
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

    if not last_ts or now_ts - last_ts <= online_window then
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

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson.encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/clusternode/list" then
        response = listNodes()
    elseif uri == "/clusternode/stat" then
        response = get_node_stats()
    elseif uri == "/clusternode/attack/summary" then
        response = get_attack_summary()
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

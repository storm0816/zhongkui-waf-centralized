local cjson = require "cjson"
local config = require "config"
local file_utils = require "file_utils"
local mysql = require "mysql_cli"
local sql = require "sql"
local user = require "user"

local tonumber = tonumber
local format = string.format
local floor = math.floor
local random = math.random
local ngx_log = ngx.log
local ERR = ngx.ERR

local cjson_encode = cjson.encode
local cjson_decode = cjson.decode
local get_system_config = config.get_system_config
local read_file_to_string = file_utils.read_file_to_string

local _M = {}

-- Share links are intended for long-running wall displays, so by default
-- we issue non-expiring tokens. Old expiring tokens remain valid until expiry.
local TOKEN_TTL_SECONDS = 0
local TOKEN_SIGN_VERSION = "v1"
local SCREEN_PAGE_PATH = config.ZHONGKUI_PATH .. "/admin/view/node-attack-global.html"
local SCREEN_LIGHT_PAGE_PATH = config.ZHONGKUI_PATH .. "/admin/view/node-attack-global-light.html"
local SCREEN_CHINA_PAGE_PATH = config.ZHONGKUI_PATH .. "/admin/view/node-attack-china.html"
local SCREEN_CHINA_LIGHT_PAGE_PATH = config.ZHONGKUI_PATH .. "/admin/view/node-attack-china-light.html"
local DEFAULT_EXPIRE = 120
local DEFAULT_OFFLINE_GRACE = 120

local secret = tostring((get_system_config("secret") or "zhongkui_screen_secret"))

local function b64url_encode(s)
    local b64 = ngx.encode_base64(s)
    b64 = b64:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
    return b64
end

local function b64url_decode(s)
    if not s or s == "" then
        return nil
    end
    local b64 = s:gsub("-", "+"):gsub("_", "/")
    local pad = #b64 % 4
    if pad == 2 then
        b64 = b64 .. "=="
    elseif pad == 3 then
        b64 = b64 .. "="
    elseif pad == 1 then
        return nil
    end
    return ngx.decode_base64(b64)
end

local function token_sign(expire_at, nonce)
    return ngx.md5(secret .. "|" .. tostring(expire_at) .. "|" .. tostring(nonce) .. "|" .. TOKEN_SIGN_VERSION)
end

local function issue_screen_token()
    local now = ngx.time()
    local payload = {
        exp = TOKEN_TTL_SECONDS > 0 and (now + TOKEN_TTL_SECONDS) or 0,
        nonce = tostring(now) .. tostring(random(100000, 999999)),
        ver = TOKEN_SIGN_VERSION
    }
    payload.sign = token_sign(payload.exp, payload.nonce)
    return b64url_encode(cjson_encode(payload)), payload.exp
end

local function verify_screen_token(token)
    local decoded = b64url_decode(token)
    if not decoded then
        return false, "invalid token encoding"
    end

    local ok, payload = pcall(cjson_decode, decoded)
    if not ok or type(payload) ~= "table" then
        return false, "invalid token payload"
    end

    local exp = tonumber(payload.exp) or 0
    local nonce = tostring(payload.nonce or "")
    local sign = tostring(payload.sign or "")
    if exp > 0 and exp <= ngx.time() then
        return false, "token expired"
    end
    if nonce == "" or sign == "" then
        return false, "token fields missing"
    end

    local expected = token_sign(exp, nonce)
    if expected ~= sign then
        return false, "token signature mismatch"
    end

    return true, payload
end

local function get_online_window()
    local sys_conf = get_system_config("system") or {}
    local expire = tonumber(sys_conf.expire)
    if not expire or expire <= 0 then
        expire = DEFAULT_EXPIRE
    end
    local grace = tonumber(sys_conf.node_offline_grace)
    if not grace or grace < 0 then
        grace = DEFAULT_OFFLINE_GRACE
    end
    return expire + grace
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

local function build_traffic_rows()
    local res, err = sql.get_request_traffic_by_hour()
    if not res then
        ngx_log(ERR, "screen data get_request_traffic_by_hour error: ", err or "nil")
        return {}
    end

    local rows = {}
    for _, row in ipairs(res) do
        rows[#rows + 1] = {
            row.hour,
            tonumber(row.traffic) or 0,
            tonumber(row.attack_traffic) or 0,
            tonumber(row.blocked_traffic) or 0
        }
    end
    return rows
end

local function build_node_stats()
    local online_window = get_online_window()
    local sql_stats = format([[
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN last_seen >= NOW() - INTERVAL %d SECOND THEN 1 ELSE 0 END) AS online
        FROM waf_cluster_node
    ]], online_window)
    local res, err = mysql.query(sql_stats)
    if not res or not res[1] then
        ngx_log(ERR, "screen data node stats query error: ", err or "nil")
        return { total = 0, online = 0, offline = 0 }
    end
    local total = tonumber(res[1].total) or 0
    local online = tonumber(res[1].online) or 0
    return {
        total = total,
        online = online,
        offline = total - online
    }
end

local function build_node_summary(window_minutes)
    local master_ip = get_local_ip()
    local sql_summary = format([[
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

    local res, err = mysql.query(sql_summary)
    if not res then
        ngx_log(ERR, "screen data node summary query error: ", err or "nil")
        return {}, master_ip
    end
    return res, master_ip
end

local function build_china_fallback_from_attack_log()
    local sql_china = [[
        SELECT
            COALESCE(NULLIF(ip_province_code, ''), NULLIF(ip_province_cn, ''), NULLIF(ip_province_en, '')) AS iso_code,
            COALESCE(NULLIF(ip_province_cn, ''), NULLIF(ip_province_en, ''), '未知') AS name_cn,
            COALESCE(NULLIF(ip_province_en, ''), NULLIF(ip_province_cn, ''), 'Unknown') AS name_en,
            COUNT(*) AS attack_times,
            SUM(CASE WHEN UPPER(action) IN ('DENY','REDIRECT','CAPTCHA') THEN 1 ELSE 0 END) AS block_times
        FROM attack_log
        WHERE request_time >= NOW() - INTERVAL 30 DAY
          AND COALESCE(ip_province_cn, ip_province_en, ip_province_code, '') <> ''
        GROUP BY ip_province_code, ip_province_cn, ip_province_en
        ORDER BY attack_times DESC
        LIMIT 200
    ]]
    local res, err = mysql.query(sql_china)
    if not res then
        ngx_log(ERR, "screen data china fallback query error: ", err or "nil")
        return {}
    end
    return res
end

local function build_china_intranet_from_traffic_stats()
    local sql_china = [[
        SELECT
            '' AS iso_code,
            '内网' AS name_cn,
            'intranet' AS name_en,
            SUM(request_times) AS request_times,
            SUM(attack_times) AS attack_times,
            SUM(block_times) AS block_times,
            SUM(block_times_attack) AS block_times_attack,
            SUM(block_times_captcha) AS block_times_captcha,
            SUM(block_times_cc) AS block_times_cc,
            SUM(captcha_pass_times) AS captcha_pass_times
        FROM traffic_stats
        WHERE DATE(request_date) >= CURDATE() - INTERVAL 30 DAY
          AND (
            COALESCE(ip_country_cn, '') = '内网'
            OR COALESCE(ip_province_cn, '') = '内网'
            OR COALESCE(ip_country_en, '') = 'intranet'
            OR COALESCE(ip_province_en, '') = 'intranet'
          )
    ]]
    local res, err = mysql.query(sql_china)
    if not res or not res[1] then
        ngx_log(ERR, "screen data china intranet query error: ", err or "nil")
        return nil
    end
    if (tonumber(res[1].attack_times) or 0) <= 0 and (tonumber(res[1].request_times) or 0) <= 0 then
        return nil
    end
    return res[1]
end

local function build_screen_payload()
    local waf_status = {}
    local world = {}
    local china = {}

    local waf_res, waf_err = sql.get_today_waf_status()
    if waf_res and waf_res[1] then
        waf_status = waf_res[1]
    elseif waf_err then
        ngx_log(ERR, "screen data waf_status query error: ", waf_err)
    end

    local world_res, world_err = sql.get_30days_world_traffic_stats()
    if world_res then
        world = world_res
    elseif world_err then
        ngx_log(ERR, "screen data world traffic query error: ", world_err)
    end

    local china_res, china_err = sql.get_30days_china_traffic_stats()
    if china_res then
        china = china_res
    elseif china_err then
        ngx_log(ERR, "screen data china traffic query error: ", china_err)
    end
    if (not china) or (#china == 0) then
        china = build_china_fallback_from_attack_log()
    end
    local intranet = build_china_intranet_from_traffic_stats()
    if intranet then
        china[#china + 1] = intranet
    end

    local traffic_rows = build_traffic_rows()
    local node_stat = build_node_stats()

    local args = ngx.req.get_uri_args()
    local window_minutes = tonumber(args.windowMinutes) or 30
    if window_minutes < 5 then
        window_minutes = 5
    elseif window_minutes > 1440 then
        window_minutes = 1440
    end
    local node_summary, master_ip = build_node_summary(window_minutes)

    return {
        wafStatus = waf_status,
        sourceRegion = { world = world, china = china },
        trafficRows = traffic_rows,
        nodeStat = node_stat,
        nodeSummary = node_summary,
        masterIp = master_ip,
        windowMinutes = window_minutes
    }
end

local function send_json(code, body)
    ngx.status = code
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.say(cjson_encode(body))
end

local function access_allowed_for_screen()
    if user.check_auth_token() then
        return true, "admin"
    end
    local args = ngx.req.get_uri_args()
    local token = tostring(args.token or "")
    if token == "" then
        return false, "token missing"
    end
    return verify_screen_token(token)
end

local function handle_create_url()
    if user.check_auth_token() == false then
        return send_json(401, { code = 401, msg = "User not logged in" })
    end

    local token, exp = issue_screen_token()
    local host = ngx.var.http_host or ngx.var.host or "localhost"
    local scheme = ngx.var.scheme or "http"
    local args = ngx.req.get_uri_args()
    local mode = tostring(args.mode or "")
    local page_path = "/screen/global"
    if mode == "light" then
        page_path = "/screen/global/light"
    elseif mode == "china" then
        page_path = "/screen/china"
    elseif mode == "china_light" then
        page_path = "/screen/china/light"
    end
    local url = scheme .. "://" .. host .. page_path .. "?token=" .. ngx.escape_uri(token)

    return send_json(200, {
        code = 0,
        msg = "",
        data = {
            url = url,
            token = token,
            expire_at = exp,
            expire_at_text = exp > 0 and os.date("%Y-%m-%d %H:%M:%S", exp) or "长期有效"
        }
    })
end

local function handle_global_page(page_path)
    local ok, err = access_allowed_for_screen()
    if not ok then
        ngx.status = 403
        ngx.header.content_type = "text/plain; charset=utf-8"
        ngx.say("screen access denied: " .. tostring(err))
        return
    end

    local html = read_file_to_string(page_path or SCREEN_PAGE_PATH)
    if not html then
        ngx.status = 500
        ngx.header.content_type = "text/plain; charset=utf-8"
        ngx.say("screen page not found")
        return
    end
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.say(html)
end

local function handle_global_data()
    local ok, err = access_allowed_for_screen()
    if not ok then
        return send_json(403, { code = 403, msg = tostring(err) })
    end

    local payload = build_screen_payload()
    return send_json(200, { code = 200, msg = "", data = payload })
end

function _M.do_request()
    user.deny_console_on_node()

    local uri = ngx.var.uri
    if uri == "/screen/url/create" then
        return handle_create_url()
    end
    if uri == "/screen/global/data" then
        return handle_global_data()
    end
    if uri == "/screen/global" then
        return handle_global_page(SCREEN_PAGE_PATH)
    end
    if uri == "/screen/global/light" then
        return handle_global_page(SCREEN_LIGHT_PAGE_PATH)
    end
    if uri == "/screen/china" then
        return handle_global_page(SCREEN_CHINA_PAGE_PATH)
    end
    if uri == "/screen/china/light" then
        return handle_global_page(SCREEN_CHINA_LIGHT_PAGE_PATH)
    end

    return send_json(404, { code = 404, msg = "invalid path" })
end

_M.do_request()
return _M

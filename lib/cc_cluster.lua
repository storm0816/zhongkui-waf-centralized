local cjson = require "cjson.safe"
local config = require "config"
local constants = require "constants"
local redis = require "redis_cli"

local _M = {}
local cached_policy
local cached_at = 0
local OBSERVED_DOMAIN_PREFIX = "cluster:cc:observed-domain:"
local OBSERVED_DOMAIN_TTL = 600
local MAX_OBSERVED_DOMAINS = 512
local HOURLY_METRIC_TTL = 90000 -- Keep 24 completed hours plus the current hour.
local REQUEST_METRICS_SCRIPT = [[
local minute = redis.call('INCR', KEYS[1])
if minute == 1 then redis.call('EXPIRE', KEYS[1], 600) end
local hour = redis.call('INCR', KEYS[2])
if hour == 1 then redis.call('EXPIRE', KEYS[2], ARGV[2]) end
if ARGV[1] ~= '' then
    local changed = redis.pcall('PFADD', KEYS[3], ARGV[1])
    if type(changed) == 'table' and changed.err then return -1 end
    if changed == 1 then redis.call('EXPIRE', KEYS[3], ARGV[2]) end
end
return 1
]]
local REQUEST_METRICS_SHA = require("resty.string").to_hex(ngx.sha1_bin(REQUEST_METRICS_SCRIPT))

local function normalize_host(host)
    host = tostring(host or "unknown"):lower():gsub("%.$", "")
    return host:match("^([^:]+)") or "unknown"
end

local function get_policy_snapshot()
    local now = ngx.time()
    if cached_policy and now - cached_at < 10 then
        return cached_policy
    end
    local raw = redis.get(constants.KEY_REDIS_CC_DOMAIN_POLICY)
    local parsed = raw and cjson.decode(raw) or nil
    if type(parsed) == "table" then
        cached_policy = parsed
        cached_at = now
    end
    return cached_policy
end

function _M.resolve(host, rule)
    host = normalize_host(host)
    local snapshot = get_policy_snapshot()
    local selected = snapshot and snapshot.domains and snapshot.domains[host]
    selected = selected or (snapshot and snapshot.default)
    return {
        host = host,
        duration = tonumber(selected and selected.duration) or tonumber(rule.duration) or 60,
        threshold = tonumber(selected and selected.threshold) or tonumber(rule.threshold) or 1000
    }
end

function _M.counter_key(host, ip, rule)
    local identity = tostring(rule.id or rule.rule or rule.pattern or rule.countType or "default")
    return "cc_req_count:v2:" .. ngx.md5(normalize_host(host) .. "|" .. tostring(ip) .. "|" .. identity)
end

local function metric_key(kind, host, minute)
    return "waf:cc:domain:metric:" .. kind .. ":" .. ngx.md5(normalize_host(host)) .. ":" .. minute
end

local function is_reportable_domain(host)
    host = normalize_host(host)
    return host ~= "" and host ~= "unknown" and host ~= "localhost" and host ~= "_"
        and #host <= 255 and host:find(".", 1, true)
        and not host:match("^[%d%.]+$")
        and host:match("^[a-z0-9][a-z0-9%.%-]*[a-z0-9]$") ~= nil
end

_M.is_reportable_domain = is_reportable_domain

-- The request Host distinguishes configured aliases that share one Nginx server block.
function _M.observe_domain(host)
    host = normalize_host(host)
    if not is_reportable_domain(host) then
        return
    end

    local dict = ngx.shared.dict_config
    if dict then
        dict:set(OBSERVED_DOMAIN_PREFIX .. host, ngx.time(), OBSERVED_DOMAIN_TTL)
    end
end

function _M.get_observed_domains()
    local dict = ngx.shared.dict_config
    if not dict then
        return {}
    end

    local domains = {}
    for _, key in ipairs(dict:get_keys(MAX_OBSERVED_DOMAINS)) do
        if key:sub(1, #OBSERVED_DOMAIN_PREFIX) == OBSERVED_DOMAIN_PREFIX and dict:get(key) then
            local domain = key:sub(#OBSERVED_DOMAIN_PREFIX + 1)
            if is_reportable_domain(domain) then domains[#domains + 1] = domain end
        end
    end
    table.sort(domains)
    return domains
end

function _M.count_request(host, client_ip)
    if not config.is_system_option_on("centralized") or not config.is_system_option_on("redis") then
        return
    end
    if not is_reportable_domain(host) then return end
    _M.observe_domain(host)
    local red, err = redis.get_connection()
    if not red then return nil, err end
    local hour = os.date("%Y%m%d%H")
    local ok
    local args = {3,
        metric_key("requests", host, os.date("%Y%m%d%H%M")),
        metric_key("requests_1h", host, hour), metric_key("uv_1h", host, hour),
        tostring(client_ip or ""):lower(), HOURLY_METRIC_TTL}
    ok, err = red:evalsha(REQUEST_METRICS_SHA, unpack(args))
    if not ok and err and err:find("NOSCRIPT", 1, true) then
        ok, err = red:eval(REQUEST_METRICS_SCRIPT, unpack(args))
    end
    redis.close_connection(red)
    if not ok or ok == -1 then
        ngx.log(ngx.ERR, "domain request/UV metrics failed: ", err or "invalid UV key")
        return nil, err or "invalid UV key"
    end
    return true
end

-- Bound each batch while avoiding one network round trip per metric.
function _M.read_metrics(keys)
    local red, err = redis.get_connection()
    if not red then return nil, err end
    local values = {}
    for start = 1, #keys, 128 do
        local batch = {}
        for i = start, math.min(start + 127, #keys) do batch[#batch + 1] = keys[i] end
        local result
        result, err = red:mget(unpack(batch))
        if not result then
            redis.close_connection(red)
            return nil, err
        end
        for i, key in ipairs(batch) do values[key] = tonumber(result[i]) or 0 end
    end
    redis.close_connection(red)
    return values
end

function _M.get_uv_24h(host, now)
    if not is_reportable_domain(host) then return nil end
    local cache = ngx.shared.dict_config
    local cache_key = "cluster:uv:24h:" .. ngx.md5(normalize_host(host)) .. ":" .. os.date("%Y%m%d%H", now)
    local cached = cache and cache:get(cache_key)
    if cached ~= nil then return cached end
    local red, err = redis.get_connection()
    if not red then return nil, err end
    local keys = {}
    for offset = 0, 23 do
        keys[#keys + 1] = metric_key("uv_1h", host, os.date("%Y%m%d%H", now - offset * 3600))
    end
    local value
    value, err = red:pfcount(unpack(keys))
    redis.close_connection(red)
    if value == nil then return nil, err end
    if cache then cache:safe_set(cache_key, value, 30) end
    return value
end

function _M.count_hit(host)
    if is_reportable_domain(host) and config.is_system_option_on("centralized")
        and config.is_system_option_on("redis") then
        redis.incr(metric_key("hits", host, os.date("%Y%m%d%H%M")), 600)
    end
end

function _M.get_metric_key(kind, host, minute)
    return metric_key(kind, host, minute)
end

function _M.get_hourly_request_metric_key(host, hour)
    return metric_key("requests_1h", host, hour)
end

function _M.normalize_host(host)
    return normalize_host(host)
end

return _M

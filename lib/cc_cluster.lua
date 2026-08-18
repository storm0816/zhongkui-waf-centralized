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
    return host ~= "" and host ~= "unknown" and host ~= "localhost" and host ~= "_"
        and #host <= 255 and host:find(".", 1, true)
        and host:match("^[a-z0-9][a-z0-9%.%-]*[a-z0-9]$") ~= nil
end

-- Keep only server names selected by Nginx, never the client supplied Host header.
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
            domains[#domains + 1] = key:sub(#OBSERVED_DOMAIN_PREFIX + 1)
        end
    end
    table.sort(domains)
    return domains
end

function _M.count_request(host)
    if not config.is_system_option_on("centralized") or not config.is_system_option_on("redis") then
        return
    end
    _M.observe_domain(host)
    redis.incr(metric_key("requests", host, os.date("%Y%m%d%H%M")), 600)
    redis.incr(metric_key("requests_1h", host, os.date("%Y%m%d%H")), HOURLY_METRIC_TTL)
end

function _M.count_hit(host)
    if config.is_system_option_on("centralized") and config.is_system_option_on("redis") then
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

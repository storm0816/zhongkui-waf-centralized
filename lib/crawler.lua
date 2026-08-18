-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local action = require "action"
local config = require "config"
local redis_cli = require "redis_cli"
local stringutf8 = require "stringutf8"
local bot_uri = require "bot_uri"

local tonumber = tonumber
local tostring = tostring
local trim = stringutf8.trim
local ngxfind = ngx.re.find
local md5 = ngx.md5

local block_ip = action.block_ip
local do_action = action.do_action
local get_site_config = config.get_site_config
local is_system_option_on = config.is_system_option_on

local _M = {}

local DEFAULT_USER_AGENT_PATTERN = [[(?:bot|spider|crawler|slurp|bingpreview|facebookexternalhit|headless|python-requests|scrapy|curl|wget|go-http-client|java/)]]
local DEFAULT_ROBOTS_CONTENT = "User-agent: *\nAllow: /"

_M.is_uri_excluded = bot_uri.is_excluded

local function is_crawler_request(crawler_config, user_agent)
    local allow_pattern = trim(crawler_config.allowUserAgentPattern or "")
    if allow_pattern ~= "" then
        local allowed, _, allow_err = ngxfind(user_agent or "", allow_pattern, "ijo")
        if allow_err then
            ngx.log(ngx.ERR, "invalid crawler allow user-agent pattern: ", allow_err)
        elseif allowed then
            return false
        end
    end

    if crawler_config.mode == "all" then
        return true
    end

    local pattern = trim(crawler_config.userAgentPattern or "")
    if pattern == "" then
        pattern = DEFAULT_USER_AGENT_PATTERN
    end

    local from, _, err = ngxfind(user_agent or "", pattern, "ijo")
    if err then
        ngx.log(ngx.ERR, "invalid crawler user-agent pattern: ", err)
        return false
    end

    return from ~= nil
end

local function increase_request_count(key, duration)
    if is_system_option_on("redis") then
        local count = redis_cli.incr(key, duration)
        if count then
            return tonumber(count)
        end
    end

    local limit = ngx.shared.dict_cclimit
    local count = limit:incr(key, 1, 0, duration)
    if not count then
        local ok = limit:set(key, 1, duration)
        if ok then
            return 1
        end
        return nil
    end

    return count
end

local function serve_robots(robots_config)
    if ngx.var.uri ~= "/robots.txt" or type(robots_config) ~= "table" or robots_config.state ~= "on" then
        return false
    end

    local content = trim(robots_config.content or "")
    if content == "" then
        content = DEFAULT_ROBOTS_CONTENT
    end

    ngx.header.content_type = "text/plain; charset=UTF-8"
    ngx.header["Cache-Control"] = "public, max-age=300"
    ngx.status = ngx.HTTP_OK
    ngx.print(content, "\n")
    return ngx.exit(ngx.HTTP_OK)
end

function _M.check()
    local bot_config = get_site_config("bot")
    if type(bot_config) ~= "table" then
        return false
    end

    if serve_robots(bot_config.robots) then
        return true
    end

    local crawler_config = bot_config.crawler
    if type(crawler_config) ~= "table" or crawler_config.state ~= "on" then
        return false
    end

    local uri = ngx.var.uri or "/"
    if _M.is_uri_excluded(uri, crawler_config.excludeUris) then
        return false
    end

    local user_agent = ngx.ctx.ua or ""
    if not is_crawler_request(crawler_config, user_agent) then
        return false
    end

    local ip = ngx.ctx.ip
    if not ip or ip == "unknown" then
        return false
    end

    local duration = tonumber(crawler_config.duration) or 60
    local threshold = tonumber(crawler_config.threshold) or 120
    duration = math.max(1, math.min(duration, 86400))
    threshold = math.max(1, math.min(threshold, 1000000))

    local server_name = ngx.ctx.server_name or ngx.var.server_name or "unknown"
    local key = "crawler_req_count:" .. md5(server_name .. "|" .. ip)
    local count = increase_request_count(key, duration)
    if not count or count <= threshold then
        return false
    end

    local rule = {
        action = crawler_config.action or "deny",
        attackType = "crawler",
        autoIpBlock = crawler_config.autoIpBlock or "off",
        ipBlockExpireInSeconds = tonumber(crawler_config.ipBlockExpireInSeconds) or 600,
        rule = "crawler_rate_limit",
        severityLevel = "medium"
    }

    ngx.ctx.is_crawler = true
    ngx.header["Retry-After"] = tostring(duration)
    block_ip(ip, rule)
    do_action("反爬虫", rule, user_agent, "crawler", ngx.HTTP_TOO_MANY_REQUESTS)
    return true
end

return _M

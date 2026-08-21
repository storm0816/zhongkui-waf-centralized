-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local ahocorasick = require "ahocorasick"
local stringutf8 = require "stringutf8"
local nkeys = require "table.nkeys"

local ipairs = ipairs
local pairs = pairs
local tonumber = tonumber

local insert = table.insert

local ngxgmatch = ngx.re.gmatch
local ngxgsub = ngx.re.gsub

local lower = string.lower
local sub = string.sub
local find = string.find
local utf8trim = stringutf8.trim
local utf8sub = stringutf8.sub
local utf8len = stringutf8.len

local get_site_security_modules = config.get_site_security_modules
local is_global_option_on = config.is_global_option_on
local is_site_option_on = config.is_site_option_on
local get_config_table = config.get_config_table
local get_sensitive_words = config.get_sensitive_words
local md5 = ngx.md5

local _M = {}

local STR_PREPROCESSING_REGEX = "[.,!?;:\"'()<>\\[\\]{}\\-_/\\|@#\\$%&\\*\\+=\\s]*"
local CLUSTER_RULES_VERSION_DICT_KEY = "cluster:rules:snapshot:version"

local acs = {}
local acs_version = nil

local function mask_generic(value)
    local length = utf8len(value)
    if length <= 1 then return "***" end
    if length == 2 then return utf8sub(value, 1, 1) .. "***" end
    return utf8sub(value, 1, 1) .. "***" .. utf8sub(value, length, length)
end

local function mask_match(value, rule_name)
    value = tostring(value or '')
    rule_name = tostring(rule_name or '')
    if value == '' then return '' end

    if find(rule_name, '密码', 1, true) then
        return '[已脱敏]'
    end

    if find(rule_name, '邮箱', 1, true) or find(rule_name, '邮件', 1, true) then
        local account, domain = value:match('^([^@]+)@(.+)$')
        if account and domain then return sub(account, 1, 1) .. '***@' .. domain end
    end

    local digits = value:gsub('%D', '')
    if find(rule_name, '手机', 1, true) and #digits >= 11 then
        digits = sub(digits, -11)
        return sub(digits, 1, 3) .. '****' .. sub(digits, -4)
    end
    if find(rule_name, '身份证', 1, true) and #value >= 10 then
        local normalized = value:gsub('[^%dXx]', '')
        if #normalized >= 10 then return sub(normalized, 1, 6) .. '********' .. sub(normalized, -4) end
    end
    if find(rule_name, '银行卡', 1, true) and #digits >= 8 then
        return sub(digits, 1, 4) .. ' **** **** ' .. sub(digits, -4)
    end
    return mask_generic(value)
end

local function init_ac(words)
    if words and nkeys(words) > 0 then
        local ac = ahocorasick:new()
        ac:add(words)
        return ac
    end
end

local function rebuild_sensitive_words_ac()
    acs = {}

    local ac_global = nil
    if is_global_option_on('sensitiveDataFilter') then
        ac_global = init_ac(get_sensitive_words("global"))
        acs["global"] = ac_global
    end

    local config_table = get_config_table() or {}
    for server_name, site_conf in pairs(config_table) do
        if server_name ~= "system" and server_name ~= "global" then
            local ac_site = nil
            if type(site_conf) == "table" and type(site_conf.config) == "table" and site_conf.config.sensitiveDataFilter and site_conf.config.sensitiveDataFilter.state == "on" then
                ac_site = init_ac(get_sensitive_words(server_name))
                if not ac_site then
                    ac_site = ac_global
                end
            end

            if ac_site then
                acs[server_name] = ac_site
            end
        end
    end

    local dict_config = ngx.shared and ngx.shared.dict_config or nil
    acs_version = dict_config and (dict_config:get(CLUSTER_RULES_VERSION_DICT_KEY) or "local") or "local"
end

local function ensure_sensitive_words_ac()
    local dict_config = ngx.shared and ngx.shared.dict_config or nil
    local current_version = dict_config and (dict_config:get(CLUSTER_RULES_VERSION_DICT_KEY) or "local") or "local"
    if acs_version ~= current_version then
        rebuild_sensitive_words_ac()
    end
end

rebuild_sensitive_words_ac()

function _M.textPreprocessing(text)
    if not text or text == '' then
        return text
    end

    text = utf8trim(text)
    text = lower(text)

    local temp, _, error = ngxgsub(text, STR_PREPROCESSING_REGEX, "", "jo")
    if temp then
        text = temp
    else
        ngx.log(ngx.ERR, "error: ", error)
    end

    return text
end

-- Detection is intentionally separate from masking. Sensitive discovery must
-- never alter an upstream response, because response rewriting can break APIs.
function _M.detect(content)
    if content == nil or content == '' then
        return {}
    end

    ensure_sensitive_words_ac()
    local detections = {}
    local rules = get_site_security_modules("sensitive").rules
    if rules then
        for _, rt in ipairs(rules) do
            local it = ngxgmatch(content, rt.rule, "isjo")
            if it then
                local count = 0
                local matched_sample = ''
                while true do
                    local match, err = it()
                    if err then
                        ngx.log(ngx.ERR, "sensitive regex match failed: ", err)
                        break
                    end
                    if not match then break end
                    count = count + 1
                    if matched_sample == '' then
                        local matched_value = match[1] or match[0] or ''
                        matched_sample = mask_match(matched_value, rt.description)
                    end
                end
                if count > 0 then
                    insert(detections, {
                        rule_id = tostring(rt.id or md5(rt.rule or 'regex')),
                        rule_name = tostring(rt.description or '自定义敏感规则'),
                        detection_type = 'regex',
                        match_count = count,
                        matched_sample = matched_sample
                    })
                end
            end
        end
    end

    local server_name = ngx.ctx.server_name
    local ac_site = acs[server_name] or acs['global']
    if ac_site then
        local matches = ac_site:match(_M.textPreprocessing(content), true)
        if matches and #matches > 0 then
            local counts = {}
            for _, word in ipairs(matches) do
                local key = md5(word)
                counts[key] = counts[key] or { count = 0, matched_sample = mask_match(word, '敏感词') }
                counts[key].count = counts[key].count + 1
            end
            for key, item in pairs(counts) do
                insert(detections, {
                    rule_id = key,
                    rule_name = '敏感词',
                    detection_type = 'word',
                    match_count = item.count,
                    matched_sample = item.matched_sample
                })
            end
        end
    end
    return detections
end

function _M.report(detections, content_type)
    if not detections or #detections == 0 then return end

    local ctx = ngx.ctx
    ctx.sensitive_discovery_seen = ctx.sensitive_discovery_seen or {}
    local server_name = ctx.server_name or ngx.var.server_name or ''
    local request_uri = ngx.var.uri or ''
    local hour = os.date('%Y%m%d%H')

    for _, detection in ipairs(detections) do
        local dedupe_key = tostring(detection.rule_id) .. ':' .. request_uri
        if not ctx.sensitive_discovery_seen[dedupe_key] then
            ctx.sensitive_discovery_seen[dedupe_key] = true
            local event = {
                event_key = md5(table.concat({ngx.var.server_addr or '', server_name, request_uri, detection.rule_id, hour}, '|')),
                node_ip = ngx.var.server_addr or '',
                server_name = server_name,
                request_uri = request_uri,
                http_method = ngx.req.get_method() or '',
                content_type = content_type or '',
                rule_id = detection.rule_id,
                rule_name = detection.rule_name,
                detection_type = detection.detection_type,
                match_count = detection.match_count,
                matched_sample = detection.matched_sample or '',
                status = 'open'
            }
            ngx.timer.at(0, function(premature, payload)
                if premature then return end
                local ok, err = require('sql').record_sensitive_discovery(payload)
                if not ok then ngx.log(ngx.ERR, 'failed to record sensitive discovery: ', err or 'unknown') end
            end, event)
        end
    end
end

function _M.data_filter(content)
    -- Compatibility entry point: detection may run, but the body is unchanged.
    if content and content ~= '' then _M.report(_M.detect(content), ngx.header.content_type or '') end
    return content
end

return _M

-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file = require "file_utils"
local user = require "user"
local nkeys = require "table.nkeys"
local stringutf8 = require "stringutf8"
local request = require "lib.request"
local ipmatcher = require "resty.ipmatcher"

local tonumber = tonumber
local trim = stringutf8.trim
local read_file_to_string = file.read_file_to_string
local read_file_to_table = file.read_file_to_table
local write_string_to_file = file.write_string_to_file

local get_site_config = config.get_site_config
local get_site_config_file = config.get_site_config_file
local update_site_config_file = config.update_site_config_file
local get_ip_whitelist_content = config.get_ip_whitelist_content
local update_ip_whitelist_content = config.update_ip_whitelist_content
local get_ip_blacklist_content = config.get_ip_blacklist_content
local update_ip_blacklist_content = config.update_ip_blacklist_content

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local get_request_body = request.get_request_body

local _M = {}

local IP_WHITELIST_PATH = config.CONF_PATH .. '/global_rules/ipWhiteList'
local IP_BLACKLIST_PATH = config.CONF_PATH .. '/global_rules/ipBlackList'
local DOMAIN_POLICY_PATH = config.CONF_PATH .. '/global_rules/domainIpPolicy.json'
local WEBSITE_PATH = config.CONF_PATH .. '/website.json'

local function read_domain_policies()
    local content = read_file_to_string(DOMAIN_POLICY_PATH)
    local data
    if content then
        local ok, decoded = pcall(cjson_decode, content)
        if ok then data = decoded end
    end
    if type(data) ~= "table" then data = { nextId = 1, rules = {} } end
    if type(data.rules) ~= "table" then data.rules = {} end
    data.nextId = tonumber(data.nextId) or 1
    return data
end

local function write_domain_policies(data)
    local temp = DOMAIN_POLICY_PATH .. ".tmp." .. tostring(ngx.worker.pid())
    local ok, err = write_string_to_file(temp, cjson_encode(data))
    if not ok then return nil, err end
    local renamed, rename_err = os.rename(temp, DOMAIN_POLICY_PATH)
    if not renamed then os.remove(temp); return nil, rename_err end
    return true
end

local function normalize_domain(value)
    return trim(tostring(value or "")):lower():gsub("%.$", "")
end

local function valid_domain(value)
    if value == "" or #value > 253 or value:find("..", 1, true)
        or not value:match("^[a-z0-9%.%-]+$") then return false end
    for label in value:gmatch("[^%.]+") do
        if #label > 63 or label:sub(1, 1) == "-" or label:sub(-1) == "-" then return false end
    end
    return true
end

local function configured_domains(site_id)
    local content = read_file_to_string(WEBSITE_PATH)
    local data = {}
    if content then
        local ok, decoded = pcall(cjson_decode, content)
        if ok and type(decoded) == "table" then data = decoded end
    end
    local result, seen = {}, {}
    for _, site in ipairs(type(data.rules) == "table" and data.rules or {}) do
        if not site_id or site_id == "0" or tostring(site.id) == tostring(site_id) then
            for _, domain in ipairs(type(site.serverNames) == "table" and site.serverNames or {}) do
                domain = normalize_domain(domain)
                if domain ~= "" and not seen[domain] then
                    seen[domain] = true
                    result[#result + 1] = domain
                end
            end
        end
    end
    table.sort(result)
    return result, seen
end

local function ip_kind_name(kind)
    return kind == "whitelist" and "白名单" or "黑名单"
end

local function parse_ip_entries(content, kind, scope, domain, state)
    local entries = {}
    for line in tostring(content or ""):gmatch("[^\r\n]+") do
        line = trim(line)
        if line ~= "" then
            local value, comment = line:match("^(%S+)%s*(.-)%s*$")
            local matcher, err = ipmatcher.new({ value })
            if not matcher then
                return nil, "IP或CIDR格式错误: " .. tostring(err)
            end
            entries[#entries + 1] = {
                value = value,
                normalized = value:lower(),
                address = value:match("^([^/]+)"),
                comment = comment or "",
                kind = kind,
                scope = scope,
                domain = domain,
                state = state or "on",
                matcher = matcher
            }
        end
    end
    return entries
end

local function domain_policy_ip_entries(exclude_id)
    local entries = {}
    for _, rule in ipairs(read_domain_policies().rules) do
        if tonumber(rule.id) ~= tonumber(exclude_id)
            and (rule.type == "whitelist" or rule.type == "blacklist") then
            local parsed = parse_ip_entries(rule.value, rule.type, "domain",
                normalize_domain(rule.domain), rule.state or "on")
            if parsed and parsed[1] then
                parsed[1].id = rule.id
                parsed[1].comment = tostring(rule.comment or "")
                entries[#entries + 1] = parsed[1]
            end
        end
    end
    return entries
end

local function global_ip_entries(kind)
    local content = kind == "whitelist" and get_ip_whitelist_content() or get_ip_blacklist_content()
    return parse_ip_entries(content or "", kind, "global")
end

local function ip_entries_overlap(left, right)
    return left.matcher:match(right.address) or right.matcher:match(left.address)
end

local function entry_source(entry)
    local scope = entry.scope == "global" and "全局" or ("域名 " .. tostring(entry.domain or ""))
    local suffix = entry.comment ~= "" and ("（备注：" .. entry.comment .. "）") or ""
    return scope .. ip_kind_name(entry.kind) .. " " .. entry.value .. suffix
end

local function conflict_response(response, message, can_force)
    response.code = 409
    response.msg = message
    response.data = { canForce = can_force == true }
    return false
end

local function validate_entry_against(candidate, existing, force, response)
    if not ip_entries_overlap(candidate, existing) then return true end

    local same_kind = candidate.kind == existing.kind
    local same_scope = candidate.scope == existing.scope
        and (candidate.scope == "global" or candidate.domain == existing.domain)
    local exact = candidate.normalized == existing.normalized

    if same_kind and same_scope and exact then
        return conflict_response(response, "规则已存在：" .. entry_source(existing), false)
    end

    -- Disabled child rules remain duplicate candidates, but do not currently
    -- conflict with a live rule of the opposite type.
    local both_active = candidate.state ~= "off" and existing.state ~= "off"
    if not same_kind and both_active then
        response.code = 422
        response.msg = "黑白名单冲突：" .. candidate.value .. " 与 " .. entry_source(existing)
            .. " 范围重叠。白名单优先，当前配置不会按预期生效。"
        response.data = { canForce = false }
        return false
    end

    if same_kind and (same_scope or candidate.scope == "global" or existing.scope == "global") then
        if force then return true end
        return conflict_response(response,
            "检测到重复或包含关系：" .. candidate.value .. " 与 " .. entry_source(existing)
                .. " 范围重叠，继续保存会产生冗余规则。",
            true)
    end

    return true
end

local function validate_global_ip_update(kind, content, force, response)
    local candidates, parse_err = parse_ip_entries(content, kind, "global")
    if not candidates then
        response.code = 500
        response.msg = parse_err
        return false
    end

    for index, candidate in ipairs(candidates) do
        for previous = 1, index - 1 do
            if not validate_entry_against(candidate, candidates[previous], force, response) then return false end
        end
    end

    local opposite = kind == "whitelist" and "blacklist" or "whitelist"
    local references = global_ip_entries(opposite) or {}
    for _, entry in ipairs(domain_policy_ip_entries()) do references[#references + 1] = entry end
    for _, candidate in ipairs(candidates) do
        for _, existing in ipairs(references) do
            if not validate_entry_against(candidate, existing, force, response) then return false end
        end
    end
    return true
end

local function validate_domain_ip_conflicts(candidate, id, force, response)
    for _, rule in ipairs(read_domain_policies().rules) do
        if tonumber(rule.id) ~= tonumber(id)
            and normalize_domain(rule.domain) == candidate.domain
            and tostring(rule.type) == candidate.type
            and tostring(rule.value):upper() == tostring(candidate.value):upper() then
            return conflict_response(response,
                "相同域名、类型和值的规则已存在：" .. candidate.domain .. " " .. candidate.value,
                false)
        end
    end
    if candidate.type == "region" then return true end
    local parsed = assert(parse_ip_entries(candidate.value, candidate.type, "domain", candidate.domain, candidate.state))
    local entry = parsed[1]
    entry.comment = candidate.comment

    local references = domain_policy_ip_entries(id)
    for _, global_kind in ipairs({ "whitelist", "blacklist" }) do
        for _, global_entry in ipairs(global_ip_entries(global_kind) or {}) do
            references[#references + 1] = global_entry
        end
    end
    for _, existing in ipairs(references) do
        -- Rules for separate child domains are intentionally independent.
        if existing.scope == "global" or existing.domain == entry.domain then
            if not validate_entry_against(entry, existing, force, response) then return false end
        end
    end
    return true
end

local function validate_domain_policy(args)
    local domain = normalize_domain(args.domain)
    local kind = tostring(args.type or "")
    local value = trim(tostring(args.value or ""))
    local comment = trim(tostring(args.comment or ""))
    local state = tostring(args.state or "on") == "off" and "off" or "on"
    if not valid_domain(domain) then return nil, "域名格式错误，仅支持精确域名" end
    if kind == "region" then
        value = value:upper()
        if not value:match("^[A-Z][A-Z]$") then return nil, "国家/地区代码格式错误" end
    elseif kind == "whitelist" or kind == "blacklist" then
        local matcher, err = ipmatcher.new({ value })
        if not matcher then return nil, "IP或CIDR格式错误: " .. tostring(err) end
    else
        return nil, "子名单类型错误"
    end
    if #comment > 255 then return nil, "备注不能超过255个字符" end
    return { domain=domain, type=kind, value=value, comment=comment, state=state }
end

local function save_or_fail(response, ...)
    local ok, err = ...
    if not ok then
        response.code = 500
        response.msg = err or 'write file failed'
        return false
    end
    return true
end

function _M.do_request()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri
    local reload = false

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson_encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/ip/filter/config/get" then
        local args, err = ngx.req.get_uri_args()
        if args then
            local site_id = tostring(args['siteId'])
            local _, content = get_site_config_file(site_id)

            local data = {}
            local site_config = cjson_decode(content)
            if site_config then
                data.whiteIP = site_config.whiteIP
                data.blackIP = site_config.blackIP
                data.disallowCountrys = site_config.geoip.disallowCountrys
            end

            response.data = cjson_encode(data)
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/ip/filter/config/state/update" then
        -- 修改IP黑白名单启用状态
         ngx.req.read_body()
         local args, err = ngx.req.get_post_args()

         if args then
            local site_id = tostring(args['siteId'])
            local state = args.state
            local _, content = get_site_config_file(site_id)

            if state and content then
                local config_table = cjson_decode(content)

                if args.whiteIP then
                    config_table.whiteIP.state = state
                end

                if args.blackIP then
                    config_table.blackIP.state = state
                end

                local new_config_json = cjson_encode(config_table)
                reload = save_or_fail(response, update_site_config_file(site_id, new_config_json))
            else
                response.code = 500
                response.msg = 'param error'
            end
         else
             response.code = 500
             response.msg = err
         end
    elseif uri == "/ip/filter/rule/list" then
        -- ip黑白名单列表
        local data = {}
        local content = ''

        local whitelist_content = get_ip_whitelist_content()
        local ip_white_list = {}
        if whitelist_content and whitelist_content ~= "" then
            for line in whitelist_content:gmatch("[^\r\n]+") do
                ip_white_list[#ip_white_list + 1] = line
            end
        end
        if ip_white_list then
            local len = nkeys(ip_white_list)
            if len > 1 then
                content = ip_white_list[1] .. '...'
            elseif len > 0 then
                content = ip_white_list[1]
            end
        end

        data[1] = {id = 1, state = get_site_config("whiteIP").state, content = content}

        content = ''
        local blacklist_content = get_ip_blacklist_content()
        local ip_black_list = {}
        if blacklist_content and blacklist_content ~= "" then
            for line in blacklist_content:gmatch("[^\r\n]+") do
                ip_black_list[#ip_black_list + 1] = line
            end
        end
        if ip_black_list then
            local len = nkeys(ip_black_list)
            if len > 1 then
                content = ip_black_list[1] .. '...'
            elseif len > 0 then
                content = ip_black_list[1]
            end
        end

        data[2] = {id = 2, state = get_site_config("blackIP").state, content = content}

        response.data = data
        response.count = 2
        response.code = 0
    elseif uri == "/ip/filter/rule/get" then
        -- ip黑白名单内容
        local args, err = ngx.req.get_uri_args()
        if args then
            local id = tonumber(args['id'])
            if id then
                local content = ''
                if id == 1 then
                    content = get_ip_whitelist_content() or ''
                elseif id == 2 then
                    content = get_ip_blacklist_content() or ''
                end
                response.data = {id = id, content = content}
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/ip/filter/rule/update" then
        -- 修改ip黑白名单内容
        local id = nil
        local content = nil
        local args = nil

        local body_raw = get_request_body()

        if body_raw and body_raw ~= "" then
            args = ngx.decode_args(body_raw, 0)
        end

        if args then
            id = tonumber(args['id'])
            content = args['content']

            if id and content then
                -- 黑白名单按“每行一条”解析，不允许逗号分隔，避免加载时报格式错误。
                if string.find(content, ",", 1, true) or string.find(content, "，", 1, true) then
                    response.code = 500
                    response.msg = "名单格式错误：请每行填写一条IP/网段，不要使用逗号分隔"
                    ngx.say(cjson_encode(response))
                    return
                end

                local kind = id == 1 and "whitelist" or (id == 2 and "blacklist" or nil)
                local normalized_content = trim(content)
                local force = tostring(args.force or "") == "1"
                if kind and validate_global_ip_update(kind, normalized_content, force, response) then
                    if id == 1 then
                        reload = save_or_fail(response, update_ip_whitelist_content(normalized_content))
                    elseif id == 2 then
                        reload = save_or_fail(response, update_ip_blacklist_content(normalized_content))
                    end
                end
            end
        end
    elseif uri == "/ip/filter/rule/geo/update" then
        -- 修改地域级IP黑名单配置
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
            local site_id = tostring(args['siteId'])
            local countries = tostring(args['countries'])

            if site_id and countries then
                local _, content = get_site_config_file(site_id)
                if content then
                    local t = cjson_decode(content)
                    local geoip = t.geoip
                    geoip.disallowCountrys = cjson_decode(countries)

                    local json = cjson_encode(t)
                    reload = save_or_fail(response, update_site_config_file(site_id, json))
                end
            else
                response.code = 500
                response.msg = 'param error'
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/ip/filter/domain/list" then
        local args = ngx.req.get_uri_args()
        local site_id = tostring(args.siteId or "0")
        local domain_filter = normalize_domain(args.domain)
        local type_filter = tostring(args.type or "")
        local state_filter = tostring(args.state or "")
        local page = math.max(tonumber(args.page) or 1, 1)
        local limit = math.min(math.max(tonumber(args.limit) or 20, 1), 200)
        local _, site_domains = configured_domains(site_id)
        local rows = {}
        for _, rule in ipairs(read_domain_policies().rules) do
            local domain = normalize_domain(rule.domain)
            if (site_id == "0" or site_domains[domain])
                and (domain_filter == "" or domain:find(domain_filter, 1, true))
                and (type_filter == "" or tostring(rule.type) == type_filter)
                and (state_filter == "" or tostring(rule.state or "on") == state_filter) then
                rows[#rows + 1] = rule
            end
        end
        table.sort(rows, function(a, b)
            if tostring(a.domain) == tostring(b.domain) then return (tonumber(a.id) or 0) < (tonumber(b.id) or 0) end
            return tostring(a.domain) < tostring(b.domain)
        end)
        local total, data, first = #rows, {}, (page - 1) * limit + 1
        for index = first, math.min(first + limit - 1, total) do data[#data + 1] = rows[index] end
        response = { code=0, msg="", count=total, data=data, domains=configured_domains(site_id) }
    elseif uri == "/ip/filter/domain/save" then
        ngx.req.read_body()
        local args = ngx.req.get_post_args() or {}
        local candidate, validation_err = validate_domain_policy(args)
        if not candidate then
            response.code = 500
            response.msg = validation_err
        else
            local policies = read_domain_policies()
            local id = tonumber(args.id)
            local found = false
            local force = tostring(args.force or "") == "1"
            if validate_domain_ip_conflicts(candidate, id, force, response) then
                for _, rule in ipairs(policies.rules) do
                    if tonumber(rule.id) == id then
                        candidate.id = id
                        for key, value in pairs(candidate) do rule[key] = value end
                        found = true
                    end
                end
                if not found then
                    candidate.id = policies.nextId
                    policies.nextId = policies.nextId + 1
                    policies.rules[#policies.rules + 1] = candidate
                end
                reload = save_or_fail(response, write_domain_policies(policies))
            end
        end
    elseif uri == "/ip/filter/domain/remove" then
        ngx.req.read_body()
        local args = ngx.req.get_post_args() or {}
        local id = tonumber(args.id)
        local policies = read_domain_policies()
        local kept, removed = {}, false
        for _, rule in ipairs(policies.rules) do
            if tonumber(rule.id) == id then removed = true else kept[#kept + 1] = rule end
        end
        if not removed then
            response.code = 404
            response.msg = "规则不存在"
        else
            policies.rules = kept
            reload = save_or_fail(response, write_domain_policies(policies))
        end
    elseif uri == "/ip/filter/domain/state/update" then
        ngx.req.read_body()
        local args = ngx.req.get_post_args() or {}
        local id, state = tonumber(args.id), tostring(args.state) == "off" and "off" or "on"
        local policies, found, target = read_domain_policies(), false, nil
        for _, rule in ipairs(policies.rules) do
            if tonumber(rule.id) == id then target = rule; found = true; break end
        end
        if not found then
            response.code = 404
            response.msg = "规则不存在"
        elseif state == "on" and not validate_domain_ip_conflicts({
            domain = normalize_domain(target.domain),
            type = target.type,
            value = target.value,
            comment = target.comment or "",
            state = "on"
        }, id, false, response) then
            -- Keep the rule disabled when enabling it would create a conflict.
        else
            target.state = state
            reload = save_or_fail(response, write_domain_policies(policies))
        end
    end

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if (response.code == 200 or response.code == 0) and reload == true then
        local ok, reload_err = config.reload_config_file()
        if not ok then response.code = 500; response.msg = "集群发布失败: " .. tostring(reload_err) end
    end
    ngx.say(cjson_encode(response))
end

_M.do_request()

return _M

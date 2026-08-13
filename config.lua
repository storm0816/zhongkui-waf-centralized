-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local file_utils = require "file_utils"
local ip_utils = require "ip_utils"
local constants = require "constants"
local stringutf8 = require "stringutf8"
local nkeys = require "table.nkeys"
local isarray = require "table.isarray"
local ffi = require "ffi"
local lfs = require "lfs"
local ipmatcher = require "resty.ipmatcher"

local read_rule = file_utils.read_rule
local read_file_to_string = file_utils.read_file_to_string
local read_file_to_table = file_utils.read_file_to_table
local write_string_to_file = file_utils.write_string_to_file
local is_file_exists = file_utils.is_file_exists
local is_directory = file_utils.is_directory
local mkdir = file_utils.mkdir

local sub = string.sub
local default_if_blank = stringutf8.default_if_blank
local trim = stringutf8.trim

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local pairs = pairs
local ipairs = ipairs
local tonumber = tonumber
local type = type
local getenv = os.getenv
local md5 = ngx.md5
local sort = table.sort
local insert = table.insert
local concat = table.concat

local _M = {}
local RULE_SOURCE_ROOT_FILES = { "global.json", "website.json", "ipgroup.json" }

local function collect_rule_source_files()
    local files = {}

    local function collect_file(relative_path)
        if relative_path:find(".restore.", 1, true)
            or relative_path:find(".tmp.", 1, true)
            or relative_path:match("%.bak$") then
            return
        end
        local content = read_file_to_string(_M.CONF_PATH .. "/" .. relative_path)
        if content ~= nil then
            files[relative_path] = content
        end
    end

    local function walk(relative_dir)
        local full_dir = _M.CONF_PATH .. "/" .. relative_dir
        if not is_directory(full_dir) then
            return
        end
        for entry in lfs.dir(full_dir) do
            if entry ~= "." and entry ~= ".." then
                local relative_path = relative_dir .. "/" .. entry
                local mode = lfs.attributes(_M.CONF_PATH .. "/" .. relative_path, "mode")
                if mode == "directory" then
                    walk(relative_path)
                elseif mode == "file" then
                    collect_file(relative_path)
                end
            end
        end
    end

    for _, relative_path in ipairs(RULE_SOURCE_ROOT_FILES) do
        collect_file(relative_path)
    end
    walk("global_rules")
    walk("sites")
    return files
end

local function ensure_parent_directory(file_path)
    local parent = file_path:match("^(.*)/[^/]+$")
    if not parent or parent == "" or is_directory(parent) then
        return true
    end
    local current = ""
    if sub(parent, 1, 1) == "/" then
        current = "/"
    end
    for part in parent:gmatch("[^/]+") do
        current = current == "/" and (current .. part) or (current == "" and part or current .. "/" .. part)
        if not is_directory(current) then
            local ok, err = mkdir(current)
            if not ok and not is_directory(current) then
                return nil, err
            end
        end
    end
    return true
end

local function is_safe_rule_source_path(relative_path)
    if type(relative_path) ~= "string" or relative_path == "" or relative_path:find("..", 1, true)
        or sub(relative_path, 1, 1) == "/" or sub(relative_path, 1, 1) == "\\" then
        return false
    end
    if relative_path == "system.json" or relative_path:match("^system[^/]*%.json$") then
        return false
    end
    return relative_path == "global.json" or relative_path == "website.json"
        or relative_path == "ipgroup.json" or relative_path:match("^global_rules/") ~= nil
        or relative_path:match("^sites/") ~= nil
end

local function restore_rule_source_file(relative_path, content, force)
    if type(content) ~= "string" or not is_safe_rule_source_path(relative_path) then
        return nil, "unsafe rule source path"
    end

    local target = _M.CONF_PATH .. "/" .. relative_path
    local existing = read_file_to_string(target)
    if not force and existing ~= nil and not (existing == "" and content ~= "") then
        return false
    end
    local dir_ok, dir_err = ensure_parent_directory(target)
    if not dir_ok then
        return nil, dir_err
    end
    local temp = target .. ".restore." .. tostring(ngx.worker.pid())
    local written, write_err = write_string_to_file(temp, content)
    if not written then
        return nil, write_err
    end
    local renamed, rename_err = os.rename(temp, target)
    if not renamed then
        os.remove(temp)
        return nil, rename_err
    end
    return true
end

local config = { system = {}, global = {} }
local CLUSTER_RULES_VERSION_DICT_KEY = "cluster:rules:snapshot:version"
local CLUSTER_RULES_HASH_PLACEHOLDER = "__SNAPSHOT_HASH__"
-- Lua module state is private to each Nginx worker, unlike ngx.shared dictionaries.
local worker_rules_snapshot_version
local storage_security_modules

_M.ipgroups = {}

local function canonical_encode(v)
    local vt = type(v)
    if vt == "nil" then
        return "null"
    end
    if vt == "boolean" or vt == "number" or vt == "string" then
        return cjson_encode(v)
    end
    if vt ~= "table" then
        return cjson_encode(tostring(v))
    end

    if isarray(v) then
        local parts = {}
        for i = 1, #v do
            parts[i] = canonical_encode(v[i])
        end
        return "[" .. concat(parts, ",") .. "]"
    end

    local keys = {}
    for k, _ in pairs(v) do
        insert(keys, tostring(k))
    end
    sort(keys)

    local parts = {}
    for _, k in ipairs(keys) do
        insert(parts, cjson_encode(k) .. ":" .. canonical_encode(v[k]))
    end
    return "{" .. concat(parts, ",") .. "}"
end

local function calculate_rule_source_hash(files)
    local canonical = canonical_encode(files or {})
    if not canonical then
        return nil, "failed to encode rule source files"
    end
    return md5(canonical)
end

local function write_rule_restore_status(status)
    local dir = _M.CONF_PATH .. "/.cluster"
    if not is_directory(dir) then
        local ok, err = mkdir(dir)
        if not ok and not is_directory(dir) then
            return nil, err
        end
    end
    status.updated_at = ngx.localtime()
    return write_string_to_file(dir .. "/rule-restore-status.json", cjson_encode(status))
end

function _M.get_rule_restore_status()
    local value = read_file_to_string(_M.CONF_PATH .. "/.cluster/rule-restore-status.json")
    if not value or value == "" then
        return {}
    end
    local ok, status = pcall(cjson_decode, value)
    return ok and type(status) == "table" and status or {}
end

local function backup_rule_source_files(files, backup_dir)
    for relative_path, content in pairs(files or {}) do
        if is_safe_rule_source_path(relative_path) then
            local target = backup_dir .. "/" .. relative_path
            local dir_ok, dir_err = ensure_parent_directory(target)
            if not dir_ok then
                return nil, dir_err
            end
            local written, write_err = write_string_to_file(target, content)
            if not written then
                return nil, write_err
            end
        end
    end
    return true
end

local function is_option_on(options, option)
    local item = options and options[option]
    return type(item) == "table" and item.state == "on"
end

-- Returns true if the global config option is "on",otherwise false
function _M.is_global_option_on(option)
    return is_option_on(config.global.config, option)
end

function _M.is_system_option_on(option)
    return is_option_on(config.system, option)
end

-- 集群角色由 system.json 中 redis、centralized、master 三个开关共同决定。
function _M.is_centralized_mode()
    return _M.is_system_option_on("centralized") and _M.is_system_option_on("redis")
end

-- master 节点负责发布集群黑名单，并汇总 Redis 数据写入 MySQL。
function _M.is_master_node()
    return _M.is_centralized_mode() and _M.is_system_option_on("master")
end

-- node 节点负责本机拦截、上报统计、拉取 master 下发的数据。
function _M.is_cluster_node()
    return _M.is_centralized_mode() and not _M.is_master_node()
end

-- 未启用 Redis 集中模式时，按单机模式直接处理本地队列和 MySQL 写入。
function _M.is_standalone_mode()
    return not _M.is_centralized_mode()
end

function _M.is_site_option_on(option)
    local server_name = ngx.ctx.server_name or default_if_blank(ngx.var.server_name, 'unknown')
    if not config[server_name] then
        return _M.is_global_option_on(option)
    end
    return config[server_name].config[option].state == "on"
end

function _M.get_system_config(option)
    if option then
        return config.system[option]
    end
    return config.system
end

function _M.set_system_config(option, value)
    config.system[option] = value
end

function _M.get_global_config(option)
    if option then
        return config.global.config[option]
    end
    return config.global.config
end

function _M.get_site_config(option)
    local server_name = ngx.ctx.server_name or default_if_blank(ngx.var.server_name, 'unknown')
    if not config[server_name] then
        return _M.get_global_config(option)
    end
    if option then
        return config[server_name].config[option]
    end
    return config[server_name].config
end

function _M.get_global_security_modules(module)
    if module then
        return config.global.security_modules[module]
    end
    return config.global.security_modules
end

function _M.get_site_security_modules(module)
    local server_name = ngx.ctx.server_name or default_if_blank(ngx.var.server_name, 'unknown')
    if not config[server_name] then
        return _M.get_global_security_modules(module)
    end
    if module then
        return config[server_name].security_modules[module]
    end
    return config[server_name].security_modules
end

function _M.get_site_config_file(site_id)
    local config_file = ''

    if site_id == '0' then
        config_file = _M.CONF_PATH .. '/global.json'
    else
        config_file = _M.CONF_PATH .. '/sites/' .. site_id .. '/config.json'
        if not is_file_exists(config_file) then
            config_file = _M.CONF_PATH .. '/global.json'
        end
    end
    return config_file, read_file_to_string(config_file)
end

function _M.update_site_config_file(site_id, str)
    local config_file = ''

    if site_id == '0' then
        config_file = _M.CONF_PATH .. '/global.json'
    else
        local site_dir = _M.CONF_PATH .. '/sites/' .. site_id
        config_file = site_dir .. '/config.json'
        if not is_directory(site_dir) then
            mkdir(site_dir)
        end
    end
    return write_string_to_file(config_file, str)
end

function _M.get_site_module_rule_file(site_id, module_id)
    local file_name = module_id .. '.json'
    local rule_file = ''

    if site_id == '0' then
        rule_file = _M.CONF_PATH .. '/global_rules/' .. file_name
    else
        rule_file = _M.CONF_PATH .. '/sites/' .. site_id .. '/rules/' .. file_name
        if not is_file_exists(rule_file) then
            rule_file = _M.CONF_PATH .. '/global_rules/' .. file_name
        end
    end

    return rule_file, read_file_to_string(rule_file)
end

function _M.update_site_module_rule_file(site_id, module_id, str)
    local file_name = module_id .. '.json'
    local rule_file = ''

    if site_id == '0' then
        rule_file = _M.CONF_PATH .. '/global_rules/' .. file_name
    else
        local site_dir = _M.CONF_PATH .. '/sites/' .. site_id
        if not is_directory(site_dir) then
            mkdir(site_dir)
        end

        local rules_dir = site_dir .. '/rules'
        if not is_directory(rules_dir) then
            mkdir(rules_dir)
        end

        rule_file = rules_dir .. '/' .. file_name
    end

    return write_string_to_file(rule_file, str)
end

local function build_ip_matcher_items(items)
    local matcher_items = {}
    if type(items) ~= "table" then
        return matcher_items
    end

    for _, item in ipairs(items) do
        if type(item) == "string" then
            local value = trim(item)
            if value ~= "" then
                local ip = value:match("^(%S+)")
                if ip and ip ~= "" then
                    insert(matcher_items, ip)
                end
            end
        end
    end

    return matcher_items
end

local function add_ip_group(group, ips)
    if type(ips) ~= "table" or nkeys(ips) == 0 then
        _M.ipgroups[group] = nil
        return
    end

    local matcher_items = build_ip_matcher_items(ips)

    if nkeys(matcher_items) == 0 then
        _M.ipgroups[group] = nil
        return
    end

    local matcher, err = ipmatcher.new(matcher_items)
    if not matcher then
        ngx.log(ngx.ERR, 'error to add ip group ' .. group, err)
        return
    end
    _M.ipgroups[group] = matcher
end

local function clear_custom_ip_groups()
    for group, _ in pairs(_M.ipgroups) do
        if type(group) == "number" then
            _M.ipgroups[group] = nil
        end
    end
end

local function load_custom_ip_groups(groups)
    clear_custom_ip_groups()
    if type(groups) ~= "table" then
        return
    end

    for _, g in pairs(groups) do
        local id = tonumber(g.id)
        if id then
            add_ip_group(id, g.ips)
        end
    end
end

local function read_json_file(file_path, default)
    local json = read_file_to_string(file_path)
    if not json or json == "" then
        return default
    end

    local ok, data = pcall(cjson_decode, json)
    if not ok or type(data) ~= "table" then
        return default
    end
    return data
end

local function normalize_ip_items(items)
    local normalized = {}
    if type(items) ~= "table" then
        return normalized
    end

    for _, item in ipairs(items) do
        if type(item) == "string" then
            local value = trim(item)
            if value ~= "" then
                insert(normalized, value)
            end
        end
    end
    return normalized
end

local function split_multiline_ips(content)
    local items = {}
    if type(content) ~= "string" or content == "" then
        return items
    end

    local normalized = content:gsub("\r\n", "\n"):gsub("\r", "\n")
    for line in normalized:gmatch("[^\n]+") do
        local value = trim(line)
        if value ~= "" then
            insert(items, value)
        end
    end
    return items
end

local function join_multiline_ips(items)
    return concat(normalize_ip_items(items), "\n")
end

local function parse_cluster_ip_group_payload(redis_value)
    if not redis_value then
        return nil, nil, nil, "empty payload"
    end

    local ok, data = pcall(cjson_decode, redis_value)
    if not ok or type(data) ~= "table" then
        return nil, nil, nil, "invalid json payload"
    end

    if type(data.items) == "table" then
        local version = data.version and tostring(data.version) or ""
        if version == "" then
            version = "legacy-" .. md5(redis_value)
        end
        return normalize_ip_items(data.items), version, data.updated_at, data.source
    end

    if data[1] ~= nil then
        return normalize_ip_items(data), "legacy-" .. md5(redis_value), nil, "legacy"
    end

    return {}, "legacy-" .. md5(redis_value), nil, "legacy"
end

local function build_cluster_ip_group_payload(items)
    local normalized = normalize_ip_items(items)
    local payload = {
        version = tostring((ngx.now and math.floor(ngx.now() * 1000)) or os.time()),
        updated_at = ngx.localtime(),
        source = getenv("HOSTNAME") or "master",
        items = normalized
    }
    local json = cjson_encode(payload)
    if not json then
        return nil, "failed to encode ip group payload"
    end
    return json, payload
end

local function get_cluster_rules_snapshot_payload()
    local source_files = collect_rule_source_files()
    local payload = {
        version = "",
        updated_at = "",
        source = getenv("HOSTNAME") or "master",
        hash = "",
        global = config.global,
        sites = {},
        ip_groups = {
            ip_blacklist = read_file_to_table(_M.CONF_PATH .. "/global_rules/ipBlackList") or {},
            ip_whitelist = read_file_to_table(_M.CONF_PATH .. "/global_rules/ipWhiteList") or {},
            custom_groups = (read_json_file(_M.CONF_PATH .. "/ipgroup.json", { rules = {} }).rules or {})
        },
        source_files = source_files,
        source_hash = select(1, calculate_rule_source_hash(source_files))
    }

    for server_name, site_conf in pairs(config) do
        if server_name ~= "system" and server_name ~= "global" then
            payload.sites[server_name] = site_conf
        end
    end

    return payload
end

local function calculate_snapshot_content_version(payload)
    local content = {
        global = payload.global,
        sites = payload.sites,
        ip_groups = payload.ip_groups,
        -- Include the complete source set so comments, disabled rules and
        -- other file-only changes always produce an immutable new release.
        source_hash = payload.source_hash
    }
    local canonical = canonical_encode(content)
    if not canonical then
        return nil, "failed to encode snapshot content for version"
    end
    return md5(canonical)
end

local function apply_cluster_rules_snapshot_hash(payload)
    payload.hash = CLUSTER_RULES_HASH_PLACEHOLDER
    local canonical = canonical_encode(payload)
    if not canonical then
        return nil, "failed to encode payload for hash"
    end

    local hash = md5(canonical)
    payload.hash = hash
    return hash
end

local function verify_cluster_rules_snapshot_hash(payload)
    local expected = payload.hash and tostring(payload.hash) or ""
    if expected == "" then
        return nil, "missing hash"
    end

    payload.hash = CLUSTER_RULES_HASH_PLACEHOLDER
    local canonical = canonical_encode(payload)
    payload.hash = expected
    if not canonical then
        return nil, "failed to encode payload for hash verify"
    end

    local actual = md5(canonical)
    if actual ~= expected then
        return nil, "snapshot hash mismatch"
    end

    return true
end

local function apply_cluster_rules_snapshot(payload)
    if type(payload) ~= "table" or type(payload.global) ~= "table" or type(payload.sites) ~= "table" then
        return nil, "invalid payload"
    end

    config.global = payload.global
    for server_name, _ in pairs(config) do
        if server_name ~= "system" and server_name ~= "global" then
            config[server_name] = nil
        end
    end
    for server_name, site_conf in pairs(payload.sites) do
        config[server_name] = site_conf
    end

    if config.global and config.global.security_modules then
        storage_security_modules("global", config.global.security_modules)
    end
    for server_name, site_conf in pairs(payload.sites) do
        if type(site_conf) == "table" and type(site_conf.security_modules) == "table" then
            storage_security_modules(server_name, site_conf.security_modules)
        end
    end

    local ip_groups = payload.ip_groups or {}
    add_ip_group(constants.KEY_IP_GROUPS_BLACKLIST, ip_groups.ip_blacklist or {})
    add_ip_group(constants.KEY_IP_GROUPS_WHITELIST, ip_groups.ip_whitelist or {})
    load_custom_ip_groups(ip_groups.custom_groups or {})

    return true
end

function _M.get_config_table()
    return config
end

function _M.get_ip_whitelist_content()
    if _M.is_centralized_mode() and _M.is_system_option_on("redis") then
        local ok, redis_cli = pcall(require, "redis_cli")
        if ok and redis_cli and redis_cli.is_available() then
            local redis_value = redis_cli.get(constants.KEY_REDIS_IP_WHITELIST)
            if redis_value and redis_value ~= ngx.null and redis_value ~= "" then
                local items = select(1, parse_cluster_ip_group_payload(redis_value))
                if items then
                    return join_multiline_ips(items)
                end
            end
        end
    end

    return read_file_to_string(_M.CONF_PATH .. "/global_rules/ipWhiteList") or ""
end

function _M.get_ip_blacklist_content()
    if _M.is_centralized_mode() and _M.is_system_option_on("redis") then
        local payload = _M.load_ip_blacklist_from_redis()
        if payload and type(payload.content) == "string" then
            return payload.content
        end
    end

    return read_file_to_string(_M.CONF_PATH .. "/global_rules/ipBlackList") or ""
end

function _M.update_ip_whitelist_content(content)
    local value = trim(content or "")
    local items = split_multiline_ips(value)
    local matcher_items = build_ip_matcher_items(items)
    if nkeys(items) > 0 then
        local matcher, err = ipmatcher.new(matcher_items)
        if not matcher then
            return nil, err or "invalid ip whitelist entry"
        end
    end
    if nkeys(items) > 0 and nkeys(matcher_items) == 0 then
        return nil, "invalid ip whitelist entry"
    end

    local ok, err = write_string_to_file(_M.CONF_PATH .. "/global_rules/ipWhiteList", value)
    if not ok then
        return ok, err
    end

    return true
end

function _M.update_ip_blacklist_content(content)
    local value = trim(content or "")
    local items = split_multiline_ips(value)
    local matcher_items = build_ip_matcher_items(items)
    if nkeys(items) > 0 then
        local matcher, err = ipmatcher.new(matcher_items)
        if not matcher then
            return nil, err or "invalid ip blacklist entry"
        end
    end
    if nkeys(items) > 0 and nkeys(matcher_items) == 0 then
        return nil, "invalid ip blacklist entry"
    end

    local ok, err = write_string_to_file(_M.CONF_PATH .. "/global_rules/ipBlackList", value)
    if not ok then
        return ok, err
    end

    return true
end

function _M.sync_ip_whitelist_to_redis(items)
    if not _M.is_centralized_mode() or not _M.is_master_node() or not _M.is_system_option_on("redis") then
        return nil, "not master node"
    end

    local ok, redis_cli = pcall(require, "redis_cli")
    if not ok or not redis_cli then
        return nil, "failed to load redis_cli"
    end

    local normalized = items
    if type(normalized) ~= "table" then
        normalized = read_file_to_table(_M.CONF_PATH .. "/global_rules/ipWhiteList") or {}
    end

    local redis_value, payload_or_err = build_cluster_ip_group_payload(normalized)
    if not redis_value then
        return nil, payload_or_err
    end

    local ok_set, set_err = redis_cli.set(constants.KEY_REDIS_IP_WHITELIST, redis_value, -1)
    if not ok_set then
        return nil, set_err
    end
    return true
end

function _M.sync_ip_blacklist_to_redis(items)
    if not _M.is_centralized_mode() or not _M.is_master_node() or not _M.is_system_option_on("redis") then
        return nil, "not master node"
    end

    local ok, redis_cli = pcall(require, "redis_cli")
    if not ok or not redis_cli then
        return nil, "failed to load redis_cli"
    end

    local normalized = items
    if type(normalized) ~= "table" then
        normalized = read_file_to_table(_M.CONF_PATH .. "/global_rules/ipBlackList") or {}
    end

    local redis_value, payload_or_err = build_cluster_ip_group_payload(normalized)
    if not redis_value then
        return nil, payload_or_err
    end

    local ok_set, set_err = redis_cli.set(constants.KEY_REDIS_IP_BLACKLIST, redis_value, -1)
    if not ok_set then
        return nil, set_err
    end

    return true
end

function _M.load_ip_whitelist_from_redis()
    if not _M.is_centralized_mode() or not _M.is_system_option_on("redis") then
        return nil, "redis centralized mode disabled"
    end

    local ok, redis_cli = pcall(require, "redis_cli")
    if not ok or not redis_cli then
        return nil, "failed to load redis_cli"
    end

    local redis_value, err = redis_cli.get(constants.KEY_REDIS_IP_WHITELIST)
    if not redis_value then
        return nil, err or "empty redis value"
    end

    local items, version, updated_at, source = parse_cluster_ip_group_payload(redis_value)
    if not items then
        return nil, version
    end

    add_ip_group(constants.KEY_IP_GROUPS_WHITELIST, items)
    return {
        items = items,
        version = version,
        updated_at = updated_at,
        source = source,
        content = join_multiline_ips(items)
    }
end

function _M.load_ip_blacklist_from_redis()
    if not _M.is_centralized_mode() or not _M.is_system_option_on("redis") then
        return nil, "redis centralized mode disabled"
    end

    local ok, redis_cli = pcall(require, "redis_cli")
    if not ok or not redis_cli then
        return nil, "failed to load redis_cli"
    end

    local redis_value, err = redis_cli.get(constants.KEY_REDIS_IP_BLACKLIST)
    if not redis_value then
        return nil, err or "empty redis value"
    end

    local items, version, updated_at, source = parse_cluster_ip_group_payload(redis_value)
    if not items then
        return nil, version
    end

    add_ip_group(constants.KEY_MASTER_IP_GROUPS_BLACKLIST, items)
    return {
        items = items,
        version = version,
        updated_at = updated_at,
        source = source,
        content = join_multiline_ips(items)
    }
end

function _M.get_sensitive_words(server_name)
    if not server_name or server_name == "global" then
        return (config.global and config.global.sensitive_words) or {}
    end

    local site_conf = config[server_name]
    if site_conf and type(site_conf.sensitive_words) == "table" then
        return site_conf.sensitive_words
    end
    return (config.global and config.global.sensitive_words) or {}
end

local function load_security_modules(rulePath, site_config)
    local security_modules = {}
    security_modules.blackUrl = read_rule(rulePath, "blackUrl")
    security_modules.args = read_rule(rulePath, "args")
    security_modules.whiteUrl = read_rule(rulePath, "whiteUrl")
    security_modules.ruleException = read_rule(rulePath, "ruleException")
    security_modules.post = read_rule(rulePath, "post")
    security_modules.cookie = read_rule(rulePath, "cookie")
    security_modules.headers = read_rule(rulePath, "headers")
    security_modules.httpMethod = read_rule(rulePath, "httpMethod")
    security_modules.fileExt = read_rule(rulePath, "fileExt")
    security_modules.cc = read_rule(rulePath, "cc")
    security_modules.acl = read_rule(rulePath, "acl")
    security_modules.sensitive = read_rule(rulePath, "sensitive")
    security_modules["user-agent"] = read_rule(rulePath, "user-agent")

    security_modules.sqli = { moduleName = "SQL注入检测", rules = { { attackType = "sqli", rule = "sqli", action = "DENY", severityLevel = "high" } } }
    security_modules.xss = { moduleName = "XSS检测", rules = { { attackType = "xss", rule = "xss", action = "DENY", severityLevel = "low" } } }
    security_modules.whiteIp = { moduleName = "IP白名单检测", rules = { { attackType = "whiteip", rule = "whiteip", action = "ALLOW", severityLevel = "low" } } }
    security_modules.blackIp = { moduleName = "IP黑名单检测", rules = { { attackType = "blackip", rule = "blackip", action = "REDIRECT", severityLevel = "high" } } }

    local trap = site_config.bot.trap
    local rule_trap = { attackType = "bot_trap", rule = "bot_trap", severityLevel = "low" }
    rule_trap.action = trap.action
    rule_trap.autoIpBlock = trap.autoIpBlock
    rule_trap.ipBlockExpireInSeconds = tonumber(trap.ipBlockExpireInSeconds)
    rule_trap.uri = trap.uri
    security_modules.botTrap = { moduleName = "Bot识别", rules = { rule_trap } }

    local captcha = site_config.bot.captcha
    local rule_captcha = { attackType = "captcha", rule = "captcha", severityLevel = "low" }
    rule_captcha.action = captcha.action
    rule_captcha.autoIpBlock = captcha.autoIpBlock
    rule_captcha.ipBlockExpireInSeconds = tonumber(captcha.ipBlockExpireInSeconds)
    rule_captcha.verifyInSeconds = tonumber(captcha.verifyInSeconds)
    rule_captcha.maxFailTimes = tonumber(captcha.maxFailTimes)
    rule_captcha.expireInSeconds = tonumber(captcha.expireInSeconds)
    rule_captcha.type = captcha.type
    security_modules.captcha = { moduleName = "人机验证", rules = { rule_captcha } }

    return security_modules
end

storage_security_modules = function(server_name, security_modules)
    local json = cjson_encode(security_modules)
    local dict_config = ngx.shared.dict_config
    dict_config:set(server_name, json)
end

local function load_system_config()
    local system_path = _M.CONF_PATH .. '/system.json'
    local json = read_file_to_string(system_path)
    local system = {}
    if json then
        system = cjson_decode(json)
    end

    local log_path = system.attackLog.logPath
    if log_path and #log_path > 0 then
        local last = sub(log_path, -1)
        if last ~= "/" and last ~= "\\" then
            log_path = log_path .. "/"
        end
    end

    _M.LOG_PATH = log_path or _M.ZHONGKUI_PATH .. "/logs/hack/"
    system.attackLog.logPath = _M.LOG_PATH
    system.html = read_file_to_string(_M.ZHONGKUI_PATH .. "/html/redirect.html")
    system.challenge_html = read_file_to_string(_M.ZHONGKUI_PATH .. "/html/challenge.html")

    config.system = system
end

local function load_global_config()
    local global_path = _M.CONF_PATH .. '/global.json'
    local global_config = {}
    local security_modules = {}
    local json = read_file_to_string(global_path)

    if json then
        global_config = cjson_decode(json)
        if global_config.waf.state == 'on' then
            security_modules = load_security_modules(_M.CONF_PATH .. '/global_rules/', global_config)
            storage_security_modules('global', security_modules)
        end
    end

    local global_sensitive_words = read_file_to_table(_M.CONF_PATH .. '/global_rules/sensitiveWords') or {}
    config.global = { config = global_config, security_modules = security_modules, sensitive_words = global_sensitive_words }

    local ip_blacklist = read_file_to_table(_M.CONF_PATH .. "/global_rules/ipBlackList")
    local ip_whitelist = read_file_to_table(_M.CONF_PATH .. "/global_rules/ipWhiteList")
    add_ip_group(constants.KEY_IP_GROUPS_BLACKLIST, ip_blacklist)
    add_ip_group(constants.KEY_IP_GROUPS_WHITELIST, ip_whitelist)
end

local function load_site_config()
    local website_path = _M.CONF_PATH .. '/website.json'
    local json = read_file_to_string(website_path)
    if json then
        local global = config.global
        local global_config = global.config
        local t = cjson_decode(json)
        local sites = t.rules

        if sites then
            local global_sensitive_words = config.global.sensitive_words or {}
            for _, site in pairs(sites) do
                local site_config = {}

                local id = site.id
                local site_dir = _M.CONF_PATH .. '/sites/' .. tostring(id)
                local config_file = site_dir .. '/config.json'
                local config_str = read_file_to_string(config_file)
                if config_str then
                    site_config = cjson_decode(config_str)
                end

                -- 站点有独立设置则使用独立设置，否则使用全局设置
                for k, v in pairs(global_config) do
                    site_config[k] = site_config[k] or v
                end

                -- Bot 子配置按功能继承，兼容升级前没有 crawler/robots 字段的站点配置。
                if type(global_config.bot) == "table" then
                    site_config.bot = site_config.bot or {}
                    for k, v in pairs(global_config.bot) do
                        site_config.bot[k] = site_config.bot[k] or v
                    end
                end

                -- waf全局关闭则关闭站点waf
                if global_config.waf.state == 'off' then
                    site_config.waf.state = 'off'
                end

                local security_modules = load_security_modules(site_dir .. '/rules/', site_config)
                local site_sensitive_words = read_file_to_table(site_dir .. '/rules/sensitiveWords') or global_sensitive_words

                -- 站点有独立安全模块设置则使用独立设置，否则使用全局设置
                for k, v in pairs(global.security_modules) do
                    security_modules[k] = security_modules[k] or v
                end

                local serverNames = site.serverNames
                for _, server_name in pairs(serverNames) do
                    config[server_name] = { config = site_config, security_modules = security_modules, sensitive_words = site_sensitive_words }
                    storage_security_modules(server_name, security_modules)
                end
            end
        end
    end
end

local function load_ip_groups()
    local path = _M.CONF_PATH .. '/ipgroup.json'
    local table_rule = read_json_file(path, { rules = {} })
    if table_rule then
        load_custom_ip_groups(table_rule.rules)
    end
end

-- 加载配置文件
function _M.load_config_file()
    load_system_config()
    load_global_config()
    load_site_config()
    load_ip_groups()
end

-- 获取nginx安装目录
local function get_nginx_command_path()
    local path = ''
    -- 获取当前 Lua 脚本的文件路径
    local script_path = debug.getinfo(1, "S").source:sub(2)
    -- 获取 OpenResty 安装目录（假设 OpenResty 在 "/usr/local/openresty" 目录下）
    local openresty_path = script_path:match("(.*/openresty/)")
    if openresty_path then
        path = openresty_path .. 'nginx/sbin/'
    end
    return path
end

-- 是否Linux系统
local function is_linux()
    return ffi.os == "Linux"
end

-- 重新加载nginx配置
function _M.reload_nginx()
    -- Nginx重新加载配置文件的系统命令
    local command = get_nginx_command_path() .. "nginx -s reload"
    if is_linux() then
        command = "sudo " .. command
    end

    local success = os.execute(command)
    if success then
        ngx.log(ngx.INFO, "nginx configuration has been successfully reloaded.")
    else
        ngx.log(ngx.ERR, "failed to reload Nginx configuration.")
    end
end

-- 如果配置文件正确，则重载nginx
-- A cluster release must be durable before it becomes active on any node.
function _M.reload_config_file()
    if _M.is_centralized_mode() and _M.is_master_node() then
        local ok, err = _M.publish_cluster_rules_snapshot(true, true)
        if not ok then
            ngx.log(ngx.ERR, "cluster config reload aborted: ", err)
            -- Admin handlers currently assemble the candidate in the master
            -- source tree.  It is never activated before MySQL/Redis publish;
            -- on failure, immediately put the authoritative published copy back.
            local restored, restore_err = _M.restore_master_rule_sources(false)
            if not restored and restore_err ~= "published release not found" then
                ngx.log(ngx.ERR, "failed to roll back unpublished rule candidate: ", restore_err)
                return nil, tostring(err) .. "; rollback failed: " .. tostring(restore_err)
            end
            return nil, err
        end

        -- Redis is active and MySQL has marked this version published.  Persist
        -- exactly that database snapshot to local files before reloading nginx.
        local restored, restore_err = _M.restore_master_rule_sources(false)
        if not restored then
            ngx.log(ngx.ERR, "failed to materialize published rules locally: ", restore_err)
            return nil, restore_err
        end
    end
    _M.reload_nginx()
    return true
end

function _M.file_ip_blacklist()
    local ip_blacklist = read_file_to_table(_M.CONF_PATH .. "/global_rules/ipBlackList")
    return ip_blacklist
end

local function build_legacy_ip_group_json(items, version, updated_at, source)
    return cjson_encode({
        version = version,
        updated_at = updated_at,
        source = source,
        items = normalize_ip_items(items)
    })
end

local function persist_node_lkg_snapshot(json)
    if not _M.CONF_PATH then
        return nil, "missing conf path"
    end
    local dir = _M.CONF_PATH .. "/.cluster"
    if not is_directory(dir) then
        local ok, err = mkdir(dir)
        if not ok and not is_directory(dir) then
            return nil, err or "failed to create cluster cache directory"
        end
    end
    local target = dir .. "/rules-lkg.json"
    local temp = target .. ".tmp." .. tostring(ngx.worker.pid())
    local written, write_err = write_string_to_file(temp, json)
    if not written then
        return nil, write_err
    end
    local renamed, rename_err = os.rename(temp, target)
    if not renamed then
        os.remove(temp)
        return nil, rename_err or "failed to replace last-known-good snapshot"
    end
    return true
end

function _M.load_cluster_rules_lkg()
    if not _M.is_cluster_node() or not _M.CONF_PATH then
        return nil, "not node"
    end
    local json = read_file_to_string(_M.CONF_PATH .. "/.cluster/rules-lkg.json")
    if not json or json == "" then
        return nil, "last-known-good snapshot not found"
    end
    local decoded, payload = pcall(cjson_decode, json)
    if not decoded or type(payload) ~= "table" then
        return nil, "invalid last-known-good snapshot"
    end
    local hash_ok, hash_err = verify_cluster_rules_snapshot_hash(payload)
    if not hash_ok then
        return nil, hash_err
    end
    local applied, apply_err = apply_cluster_rules_snapshot(payload)
    if not applied then
        return nil, apply_err
    end
    worker_rules_snapshot_version = tostring(payload.version)
    local dict_config = ngx.shared.dict_config
    if dict_config then
        dict_config:set(CLUSTER_RULES_VERSION_DICT_KEY, worker_rules_snapshot_version)
    end
    return true
end

function _M.load_master_published_rules()
    if not _M.is_master_node() then
        return nil, "not master node"
    end
    local ok, store = pcall(require, "cluster_rules_store")
    if not ok or not store then
        return nil, "failed to load cluster rule release store"
    end
    local release, err = store.get_latest_published()
    if not release then
        return nil, err or "published release not found"
    end
    local decoded, payload = pcall(cjson_decode, release.snapshot)
    if not decoded or type(payload) ~= "table" then
        return nil, "invalid published snapshot"
    end
    local verified, verify_err = verify_cluster_rules_snapshot_hash(payload)
    if not verified or tostring(payload.version) ~= tostring(release.version) then
        return nil, verify_err or "published release version mismatch"
    end
    local applied, apply_err = apply_cluster_rules_snapshot(payload)
    if not applied then
        return nil, apply_err
    end
    worker_rules_snapshot_version = tostring(payload.version)
    local dict_config = ngx.shared.dict_config
    if dict_config then
        dict_config:set(CLUSTER_RULES_VERSION_DICT_KEY, worker_rules_snapshot_version)
    end
    return true
end

function _M.restore_master_rule_sources(reload_after_restore)
    if not _M.is_master_node() then
        return nil, "not master node"
    end
    local ok, store = pcall(require, "cluster_rules_store")
    if not ok or not store then
        return nil, "failed to load cluster rule release store"
    end
    local release, err = store.get_latest_published()
    if not release then
        return nil, err or "published release not found"
    end
    local decoded, payload = pcall(cjson_decode, release.snapshot)
    if not decoded or type(payload) ~= "table" then
        return nil, "invalid published snapshot"
    end
    local verified, verify_err = verify_cluster_rules_snapshot_hash(payload)
    if not verified then
        return nil, verify_err
    end

    local source_files = payload.source_files
    if type(source_files) ~= "table" then
        source_files = {
            ["global_rules/ipWhiteList"] = concat(normalize_ip_items(
                ((payload.ip_groups or {}).ip_whitelist or {})), "\n"),
            ["global_rules/ipBlackList"] = concat(normalize_ip_items(
                ((payload.ip_groups or {}).ip_blacklist or {})), "\n")
        }
        local restored = 0
        for relative_path, content in pairs(source_files) do
            local changed, restore_err = restore_rule_source_file(relative_path, content, false)
            if changed == nil then
                return nil, "failed to restore " .. tostring(relative_path) .. ": " .. tostring(restore_err)
            end
            if changed then
                restored = restored + 1
            end
        end
        write_rule_restore_status({
            status = restored > 0 and "legacy_restored" or "legacy_compatible",
            release_version = release.version,
            restored_files = restored
        })
        if restored > 0 then
            ngx.log(ngx.WARN, "restored ", restored, " IP list files from legacy release ", release.version)
            if reload_after_restore ~= false then
                _M.reload_nginx()
            end
        end
        return true, restored
    end

    local expected_hash, expected_hash_err = calculate_rule_source_hash(source_files)
    if not expected_hash then
        return nil, expected_hash_err
    end
    if payload.source_hash and tostring(payload.source_hash) ~= expected_hash then
        return nil, "published rule source hash mismatch"
    end

    local local_files = collect_rule_source_files()
    local local_hash, local_hash_err = calculate_rule_source_hash(local_files)
    if not local_hash then
        return nil, local_hash_err
    end
    if local_hash == expected_hash then
        write_rule_restore_status({
            status = "consistent",
            release_version = release.version,
            local_hash = local_hash,
            source_hash = expected_hash,
            restored_files = 0
        })
        return true, 0
    end

    local timestamp = ngx.localtime():gsub("[- :]+", "")
    local backup_dir = _M.CONF_PATH .. "/.cluster/conflicts/" .. timestamp
    local parent_ok, parent_err = ensure_parent_directory(backup_dir .. "/.keep")
    if not parent_ok then
        return nil, "failed to create conflict backup: " .. tostring(parent_err)
    end
    local backed_up, backup_err = backup_rule_source_files(local_files, backup_dir)
    if not backed_up then
        return nil, "failed to backup conflicting rules: " .. tostring(backup_err)
    end

    local restored = 0
    for relative_path, content in pairs(source_files) do
        local changed, restore_err = restore_rule_source_file(relative_path, content, true)
        if changed == nil then
            write_rule_restore_status({ status = "failed", release_version = release.version,
                backup_dir = backup_dir, error = tostring(restore_err) })
            return nil, "failed to restore " .. tostring(relative_path) .. ": " .. tostring(restore_err)
        end
        if changed then
            restored = restored + 1
        end
    end

    for relative_path, _ in pairs(local_files) do
        if source_files[relative_path] == nil and is_safe_rule_source_path(relative_path) then
            local removed, remove_err = os.remove(_M.CONF_PATH .. "/" .. relative_path)
            if not removed and is_file_exists(_M.CONF_PATH .. "/" .. relative_path) then
                write_rule_restore_status({ status = "failed", release_version = release.version,
                    backup_dir = backup_dir, error = tostring(remove_err) })
                return nil, "failed to remove conflicting file " .. relative_path .. ": " .. tostring(remove_err)
            end
        end
    end

    write_rule_restore_status({
        status = "conflict_restored",
        release_version = release.version,
        local_hash = local_hash,
        source_hash = expected_hash,
        backup_dir = backup_dir,
        restored_files = restored
    })
    ngx.log(ngx.WARN, "rule source conflict restored from release ", release.version,
        ", backup_dir=", backup_dir, ", restored_files=", restored)
    if reload_after_restore ~= false then
        _M.reload_nginx()
    end
    return true, restored
end

local function publish_cluster_rules_snapshot_unlocked(reload_from_file, create_release, redis_cli, allow_prepared)
    if not _M.is_centralized_mode() or not _M.is_master_node() then
        return nil, "not master node"
    end

    if reload_from_file then
        local loaded, load_err = pcall(_M.load_config_file)
        if not loaded then
            return nil, "failed to reload config before publish: " .. tostring(load_err)
        end
    end

    local store_ok, store = pcall(require, "cluster_rules_store")
    if not store_ok or not store then
        return nil, "failed to load cluster rule release store"
    end
    local table_ok, table_err = store.ensure_table()
    if not table_ok then
        return nil, "failed to initialize cluster rule release table: " .. tostring(table_err)
    end

    local payload, json, hash
    if create_release then
        payload = get_cluster_rules_snapshot_payload()
        local version, ver_err = calculate_snapshot_content_version(payload)
        if not version then
            return nil, ver_err
        end
        payload.version = version
        payload.updated_at = ngx.localtime()
        hash = select(1, apply_cluster_rules_snapshot_hash(payload))
        if not hash then
            return nil, "failed to hash rules snapshot"
        end
        json = cjson_encode(payload)
        if not json then
            return nil, "failed to encode rules snapshot"
        end
        local prepared, prepare_err = store.prepare(payload.version, hash, json, payload.source)
        if not prepared then
            return nil, "failed to persist rule release: " .. tostring(prepare_err)
        end
    else
        local release, release_err
        if allow_prepared then
            -- Explicit retry path for a candidate already durable in MySQL.
            release, release_err = store.get_latest_releasable()
        else
            -- Restart and integrity reconciliation only trust published data.
            release, release_err = store.get_latest_published()
        end
        if not release then
            if allow_prepared then
                -- The only local-to-MySQL path: first cluster initialization.
                return publish_cluster_rules_snapshot_unlocked(true, true, redis_cli, false)
            end
            return nil, release_err or "published release not found"
        end
        json = release.snapshot
        local decoded
        decoded, payload = pcall(cjson_decode, json)
        if not decoded or type(payload) ~= "table" then
            return nil, "invalid snapshot stored in mysql"
        end
        local verified, verify_err = verify_cluster_rules_snapshot_hash(payload)
        if not verified or tostring(payload.version) ~= tostring(release.version) then
            return nil, verify_err or "mysql release version mismatch"
        end
        hash = payload.hash
    end

    local dict_config = ngx.shared.dict_config
    local local_version = dict_config and dict_config:get(CLUSTER_RULES_VERSION_DICT_KEY) or nil
    local redis_version = redis_cli.get(constants.KEY_REDIS_CLUSTER_RULES_SNAPSHOT_VERSION)
    if local_version and tostring(local_version) == tostring(payload.version)
        and redis_version and tostring(redis_version) == tostring(payload.version) then
        local marked, mark_err = store.mark_published(payload.version)
        if not marked then
            return nil, "rules are active but mysql publish status failed: " .. tostring(mark_err)
        end
        return true
    end

    local redis_expire = (_M.get_system_config("redis") or {}).expire_time or 1800
    local snapshot_expire = redis_expire * 2
    if snapshot_expire < 86400 then
        snapshot_expire = 86400
    end

    local whitelist_json = build_legacy_ip_group_json(payload.ip_groups.ip_whitelist,
        payload.version, payload.updated_at, payload.source)
    local blacklist_json = build_legacy_ip_group_json(payload.ip_groups.ip_blacklist,
        payload.version, payload.updated_at, payload.source)
    local set_ok, err = redis_cli.publish_cluster_rules(
        constants.KEY_REDIS_CLUSTER_RULES_SNAPSHOT, json,
        constants.KEY_REDIS_CLUSTER_RULES_SNAPSHOT_VERSION, payload.version,
        constants.KEY_REDIS_IP_WHITELIST, whitelist_json,
        constants.KEY_REDIS_IP_BLACKLIST, blacklist_json,
        snapshot_expire)
    if not set_ok then
        store.mark_publish_error(payload.version, err)
        return nil, err
    end

    local marked, mark_err = store.mark_published(payload.version)
    if not marked then
        return nil, "rules reached redis but mysql publish status failed: " .. tostring(mark_err)
    end

    if dict_config then
        dict_config:set(CLUSTER_RULES_VERSION_DICT_KEY, payload.version)
    end
    return true
end

function _M.publish_cluster_rules_snapshot(reload_from_file, create_release, allow_prepared)
    if not _M.is_centralized_mode() or not _M.is_master_node() then
        return nil, "not master node"
    end
    local ok, redis_cli = pcall(require, "redis_cli")
    if not ok or not redis_cli then
        return nil, "failed to load redis_cli"
    end

    local token = (getenv("HOSTNAME") or "master") .. ":" .. ngx.worker.pid() .. ":" .. ngx.now()
    local locked, lock_err = redis_cli.acquire_lock(
        constants.KEY_REDIS_CLUSTER_RULES_PUBLISH_LOCK, token, 60)
    if not locked then
        return nil, lock_err or "cluster rule publish is already in progress"
    end

    local called, publish_ok, publish_err = pcall(
        publish_cluster_rules_snapshot_unlocked, reload_from_file, create_release, redis_cli, allow_prepared == true)
    redis_cli.release_lock(constants.KEY_REDIS_CLUSTER_RULES_PUBLISH_LOCK, token)
    if not called then
        return nil, publish_ok
    end
    return publish_ok, publish_err
end

function _M.pull_cluster_rules_snapshot()
    if not _M.is_centralized_mode() or _M.is_master_node() then
        return nil, "not node"
    end

    local ok, redis_cli = pcall(require, "redis_cli")
    if not ok or not redis_cli then
        return nil, "failed to load redis_cli"
    end

    local dict_config = ngx.shared.dict_config
    local redis_version, version_err = redis_cli.get(constants.KEY_REDIS_CLUSTER_RULES_SNAPSHOT_VERSION)
    if redis_version and redis_version ~= ngx.null and redis_version ~= "" then
        redis_version = tostring(redis_version)
        if worker_rules_snapshot_version == redis_version then
            return true
        end
    end

    local redis_value, err = redis_cli.get(constants.KEY_REDIS_CLUSTER_RULES_SNAPSHOT)
    if not redis_value then
        return nil, err or version_err
    end

    local payload = cjson_decode(redis_value)
    if type(payload) ~= "table" then
        return nil, "invalid json payload"
    end

    local version = payload.version and tostring(payload.version) or ""
    if version == "" then
        return nil, "missing version"
    end
    if redis_version and redis_version ~= "" and version ~= redis_version then
        return nil, "snapshot version mismatch"
    end
    local hash_ok, hash_err = verify_cluster_rules_snapshot_hash(payload)
    if not hash_ok then
        return nil, hash_err
    end

    if worker_rules_snapshot_version == version then
        return true
    end

    local applied, apply_err = apply_cluster_rules_snapshot(payload)
    if not applied then
        return nil, apply_err
    end

    worker_rules_snapshot_version = version
    dict_config:set(CLUSTER_RULES_VERSION_DICT_KEY, version)
    local saved, save_err = persist_node_lkg_snapshot(redis_value)
    if not saved then
        ngx.log(ngx.WARN, "failed to save cluster last-known-good snapshot: ", save_err)
    end
    return true
end

return _M

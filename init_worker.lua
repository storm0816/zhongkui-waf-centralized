-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local redis_cli = require "redis_cli"
local isarray = require "table.isarray"
local sql = require "sql"
local utils = require "utils"
local constants = require "constants"
local file_utils = require "file_utils"
local ipmatcher = require "resty.ipmatcher"
local nkeys = require "table.nkeys"

local md5 = ngx.md5
local pairs = pairs
local tonumber = tonumber

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local dict_config = ngx.shared.dict_config
local dict_hits = ngx.shared.dict_config_rules_hits

local is_global_option_on = config.is_global_option_on
local is_system_option_on = config.is_system_option_on
local get_system_config = config.get_system_config
local read_file_to_table = file_utils.read_file_to_table

local prefix = "waf_rules_hits:"

local function sort(key_str, t)
    for _, rt in pairs(t) do
        local rule_md5 = md5(rt.rule)
        local key = key_str .. '_' .. rule_md5
        local key_total = key_str .. '_total_' .. rule_md5

        local hits = nil
        local totalHits = nil

        if is_system_option_on("redis") then
            hits = redis_cli.get(prefix .. key)
            totalHits = redis_cli.get(prefix .. key_total)
        else
            hits = dict_hits:get(key)
            totalHits = dict_hits:get(key_total)
        end

        rt.hits = tonumber(hits) or 0
        rt.totalHits = tonumber(totalHits) or 0
    end

    table.sort(t, function(a, b)
        if a.hits > b.hits then
            return true
        elseif a.hits == b.hits then
            if a.totalHits > b.totalHits then
                return true
            end
        end
        return false
    end)
    return t
end

local sort_timer_handler = function(premature)
    if premature then
        return
    end

    local config_table = config.get_config_table()
    if config_table then
        for server_name, _ in pairs(config_table) do
            local json = dict_config:get(server_name)
            if json then
                local security_modules = cjson_decode(json)
                for _, module in pairs(security_modules) do
                    local rules = module.rules
                    if isarray(rules) then
                        rules = sort(server_name .. module['moduleName'], rules)
                    end
                end

                local json_new = cjson_encode(security_modules)
                dict_config:set(server_name, json_new)
            end
        end
    end
end

local get_rules_timer_handler = function(premature)
    if premature then
        return
    end

    local config_table = config.get_config_table()
    if config_table then
        for key, conf in pairs(config_table) do
            local json = dict_config:get(key)
            if json then
                local security_modules = cjson_decode(json)
                conf.security_modules = security_modules
            end
        end
    end
end

-- 初始化 Redis 黑名单的函数
local function init_redis_blacklist()
    local redis_key = "waf:" .. constants.KEY_MASTER_IP_GROUPS_BLACKLIST

    -- 加载黑名单数据
    local ip_blacklist = config.file_ip_blacklist()
    local redis_value, err = cjson_encode(ip_blacklist)

    if not redis_value then
        ngx.log(4, "failed to encode json for redis: ", err)
        return
    end
    -- 设置key 不过期，  -1长期有效
    local ok, err = redis_cli.set(redis_key, redis_value, -1)
    if not ok then
        ngx.log(4, "failed to write attack log to redis: ", err)
    end
end

local function add_ip_group(group, ips)
    if ips and nkeys(ips) > 0 then
        local matcher, err = ipmatcher.new(ips)
        if not matcher then
            ngx.log(4, 'error to add ip group ' .. group, err)
            return
        end
        config.ipgroups[group] = matcher
        -- ngx.log(8, "Successfully added ip group: ", group)
    end
end

local function load_ip_blacklist_from_redis()
    local ip_blacklist = {}
    local i = 1
    local redis_key = "waf:" .. constants.KEY_MASTER_IP_GROUPS_BLACKLIST

    local redis_value, err = redis_cli.get(redis_key)
    if not redis_value then
        ngx.log(4, "failed to get redis_value from redis: ", err)
        return
    end

    local ip_list, err = cjson.decode(redis_value)
    if not ip_list then
        ngx.log(4, "failed to decode json from redis: ", err)
        return
    end

    if type(ip_list) == "table" then
        for _, ip in ipairs(ip_list) do
            ip_blacklist[i] = ip
            i = i + 1
        end
    else
        ngx.log(4, "Invalid ip_list format: ", type(ip_list))
    end

    -- 在这里调用 add_ip_group 函数，将 IP 黑名单添加到 ipmatcher 中
    -- ngx.log(8, "ip_blacklist: ", cjson_encode(ip_blacklist))
    add_ip_group(constants.KEY_MASTER_IP_GROUPS_BLACKLIST, ip_blacklist)
end

if is_global_option_on("waf") then
    local worker_id = ngx.worker.id()

    if is_system_option_on('rulesSort') then
        local delay = get_system_config('rulesSort').period

        if worker_id == 0 then
            utils.start_timer_every(delay, sort_timer_handler)
        end

        utils.start_timer_every(delay, get_rules_timer_handler)
    end

    if is_system_option_on("mysql") then
        if worker_id == 0 then
            utils.start_timer(0, sql.check_table)
            if is_system_option_on("master") and is_system_option_on("centralized") then
                utils.start_timer_every(2, sql.write_attack_log_redis_to_mysql)
                utils.start_timer_every(120, sql.write_waf_status_redis_to_mysql)
            else
                utils.start_timer_every(2, sql.write_sql_queue_to_mysql, constants.KEY_ATTACK_LOG)
                utils.start_timer_every(2, sql.write_sql_queue_to_mysql, constants.KEY_IP_BLOCK_LOG)
            end
            utils.start_timer_every(2, sql.update_waf_status)
            utils.start_timer_every(2, sql.update_traffic_stats)
        end
    end

    -- 将 文件中 blacklist 导入到 Redis
    if is_system_option_on("master") then
        ngx.timer.at(0.5, init_redis_blacklist)
    end

    -- 将 Redis blacklist 导入到 ipmatcher
    if is_system_option_on("redis") and is_system_option_on('centralized') then
        ngx.timer.at(1, load_ip_blacklist_from_redis)
        utils.start_timer_every(2, load_ip_blacklist_from_redis)
    end
end

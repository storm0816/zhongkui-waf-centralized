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
local type = type
local floor = math.floor
local getenv = os.getenv
local random = math.random

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local dict_config = ngx.shared.dict_config
local dict_hits = ngx.shared.dict_config_rules_hits

local is_global_option_on = config.is_global_option_on
local is_system_option_on = config.is_system_option_on
local is_centralized_mode = config.is_centralized_mode
local is_master_node = config.is_master_node
local is_standalone_mode = config.is_standalone_mode
local get_system_config = config.get_system_config
local publish_cluster_rules_snapshot = config.publish_cluster_rules_snapshot
local pull_cluster_rules_snapshot = config.pull_cluster_rules_snapshot
local read_file_to_table = file_utils.read_file_to_table

local prefix = "waf_rules_hits:"
local master_blacklist_redis_key = "waf:" .. constants.KEY_MASTER_IP_GROUPS_BLACKLIST
local master_blacklist_version_dict_key = "cluster:master:blacklist:version"
local cluster_rules_publish_interval = 10
local cluster_rules_pull_interval_base = 30
local cluster_rules_pull_jitter_max = 10
local node_report_interval_base = 30
local node_report_jitter_max = 10

local function run_with_redis_lock(lock_name, lock_ttl, callback, premature, ...)
    if premature then
        return
    end

    local token = (getenv("HOSTNAME") or "unknown") .. ":" .. ngx.worker.pid() .. ":" .. ngx.now() .. ":" .. random()
    local ok, err = redis_cli.acquire_lock(lock_name, token, lock_ttl)
    if not ok then
        if err then
            ngx.log(ngx.ERR, "failed to acquire timer lock: ", lock_name, " err=", err)
        end
        return
    end

    local success, run_err = pcall(callback, false, ...)
    if not success then
        ngx.log(ngx.ERR, "timer callback failed: ", lock_name, " err=", run_err)
    end

    redis_cli.release_lock(lock_name, token)
end

local function start_master_timer(name, interval, first_delay, lock_ttl, callback)
    utils.start_timer_every_after(first_delay, interval, function(premature)
        run_with_redis_lock("waf:lock:master_timer:" .. name, lock_ttl, callback, premature)
    end)
end

local function start_timer_every_with_jitter(base_interval, jitter_max, callback, ...)
    local interval = base_interval
    if jitter_max and jitter_max > 0 then
        interval = base_interval + random() * jitter_max
    end
    local initial_delay = 1 + (interval - base_interval)
    return utils.start_timer_every_after(initial_delay, interval, callback, ...)
end

local function safe_publish_cluster_rules_snapshot(premature)
    if premature then
        return
    end
    local ok, err = publish_cluster_rules_snapshot()
    if not ok and err and err ~= "not master node" then
        ngx.log(ngx.ERR, "failed to publish cluster rules snapshot: ", err)
    end
end

local function safe_pull_cluster_rules_snapshot(premature)
    if premature then
        return
    end
    local ok, err = pull_cluster_rules_snapshot()
    if not ok and err and err ~= "not node" then
        ngx.log(ngx.ERR, "failed to pull cluster rules snapshot: ", err)
    end
end

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
    -- 加载黑名单数据
    local ip_blacklist = config.file_ip_blacklist()
    local version = tostring(floor(ngx.now() * 1000))
    local payload = {
        version = version,
        updated_at = ngx.localtime(),
        source = getenv("HOSTNAME") or "master",
        items = ip_blacklist or {}
    }
    local redis_value, err = cjson_encode(payload)

    if not redis_value then
        ngx.log(4, "failed to encode json for redis: ", err)
        return
    end
    -- 设置key 不过期，  -1长期有效
    local ok, err = redis_cli.set(master_blacklist_redis_key, redis_value, -1)
    if not ok then
        ngx.log(4, "failed to write attack log to redis: ", err)
        return
    end

    dict_config:set(master_blacklist_version_dict_key, version)
end

local function add_ip_group(group, ips)
    if type(ips) ~= "table" then
        return false
    end

    -- 过滤无效或空的 IP 地址
    local valid_ips = {}
    for _, ip in ipairs(ips) do
        if type(ip) == "string" and #ip > 0 then
            table.insert(valid_ips, ip)
        end
    end

    -- 空黑名单时清理 matcher，避免保留旧数据。
    if nkeys(valid_ips) == 0 then
        config.ipgroups[group] = nil
        return true
    end

    local matcher, err = ipmatcher.new(valid_ips)
    if not matcher then
        ngx.log(4, 'error to add ip group ' .. group, err)
        return false
    end

    config.ipgroups[group] = matcher
    return true
end

local function parse_master_blacklist_payload(redis_value)
    local ok, data = pcall(cjson_decode, redis_value)
    if not ok or type(data) ~= "table" then
        return nil, nil, nil, "invalid json payload"
    end

    -- 新格式: { version, updated_at, source, items }
    if type(data.items) == "table" then
        local version = data.version and tostring(data.version) or ''
        if version == '' then
            version = "legacy-" .. md5(redis_value)
        end

        return data.items, version, data.updated_at, data.source
    end

    -- 兼容旧格式: 直接存储 IP 数组
    if data[1] ~= nil then
        return data, "legacy-" .. md5(redis_value), nil, "legacy"
    end
    if next(data) == nil then
        return {}, "legacy-" .. md5(redis_value), nil, "legacy"
    end

    return nil, nil, nil, "missing items field"
end

local function load_ip_blacklist_from_redis()
    local redis_value, err = redis_cli.get(master_blacklist_redis_key)
    if not redis_value then
        ngx.log(4, "failed to get redis_value from redis: ", err)
        return
    end

    local ip_blacklist, version, updated_at, source = parse_master_blacklist_payload(redis_value)
    if not ip_blacklist then
        ngx.log(4, "failed to parse master blacklist payload")
        return
    end

    local local_version = dict_config:get(master_blacklist_version_dict_key)
    if local_version and tostring(local_version) == tostring(version) then
        return
    end

    local ok = add_ip_group(constants.KEY_MASTER_IP_GROUPS_BLACKLIST, ip_blacklist)
    if not ok then
        ngx.log(4, "failed to refresh master blacklist matcher")
        return
    end

    dict_config:set(master_blacklist_version_dict_key, tostring(version))
    if updated_at then
        ngx.log(ngx.INFO, "master blacklist updated, version=", version, ", source=", source or "unknown", ", updated_at=", updated_at)
    else
        ngx.log(ngx.INFO, "master blacklist updated, version=", version, ", source=", source or "unknown")
    end
end

if is_global_option_on("waf") then
    local worker_id = ngx.worker.id()
    -- 后台汇总、落库、上报类定时任务只允许 worker 0 执行，避免多 worker 重复处理。
    local is_timer_owner = worker_id == 0
    local centralized_mode = is_centralized_mode()
    local master_node = is_master_node()
    local standalone_mode = is_standalone_mode()

    if is_system_option_on('rulesSort') then
        local delay = get_system_config('rulesSort').period

        if is_timer_owner then
            utils.start_timer_every(delay, sort_timer_handler)
        end

        utils.start_timer_every(delay, get_rules_timer_handler)
    end

    if is_timer_owner then
        if is_system_option_on("mysql") and (master_node or standalone_mode) then
            utils.start_timer(0, sql.check_table)

            if master_node then
                -- master 聚合任务做错峰和 Redis 锁保护，避免多任务同时压 Redis/MySQL。
                start_master_timer("attack_log_to_mysql", 120, 10, 110, sql.write_attack_log_redis_to_mysql)
                start_master_timer("waf_status_to_mysql", 120, 30, 110, sql.write_waf_status_redis_to_mysql)
                start_master_timer("traffic_stats_to_mysql", 120, 50, 110, sql.write_traffic_stats_redis_to_mysql)
                start_master_timer("ip_block_log_to_mysql", 120, 70, 110, sql.write_ip_block_log_redis_to_mysql)
                start_master_timer("attack_type_traffic_to_mysql", 120, 90, 110, sql.write_attack_type_traffic_redis_to_mysql)
                start_master_timer("waf_traffic_stats_to_mysql", 120, 110, 110, sql.write_waf_traffic_stats_redis_to_mysql)
                start_master_timer("replay_retry_markers", 120, 115, 110, sql.replay_retry_markers)
                start_master_timer("attack_log_retention_auto", 60, 20, 50, sql.archive_attack_log_auto)
                -- 节点心跳每 30s 上报一次，这里也按 30s 落库，避免 120s 边界抖动导致页面误判离线。
                start_master_timer("cluster_nodes_to_mysql", 30, 5, 25, sql.write_cluster_nodes_to_mysql)
                -- 清理长期离线节点，避免节点表持续膨胀。
                start_master_timer("cleanup_offline_cluster_nodes", 300, 150, 280, sql.cleanup_offline_cluster_nodes)
            elseif standalone_mode then
                -- 如果是单机模式，则定时将 内存中的 中的攻击日志、WAF 状态、流量统计、IP 阻断日志写入 MySQL
                utils.start_timer_every(2, sql.write_sql_queue_to_mysql, constants.KEY_ATTACK_LOG)
                utils.start_timer_every(2, sql.write_sql_queue_to_mysql, constants.KEY_IP_BLOCK_LOG)
            end
        end

        if (standalone_mode and is_system_option_on("mysql")) or centralized_mode then
            utils.start_timer_every(2, sql.update_waf_status)
            utils.start_timer_every(2, sql.update_traffic_stats)
        end
    end

    -- 异步加载 落地文件ipblacklist 导入到 Redis，启动时的初始化
    if is_timer_owner and master_node then
        ngx.timer.at(0.5, init_redis_blacklist)
    end

    -- 将 Redis blacklist 导入到 ipmatcher
    if centralized_mode then
        if master_node and is_timer_owner then
            -- master 定时发布规则快照，node 按版本增量拉取。
            ngx.timer.at(0.5, safe_publish_cluster_rules_snapshot)
            utils.start_timer_every(cluster_rules_publish_interval, safe_publish_cluster_rules_snapshot)
        end

        if not master_node then
            -- 规则缓存在 worker 内存中，node 的每个 worker 都要拉取最新快照。
            -- 使用 30s + 0-10s 随机偏移，避免集群节点同一时刻集中拉取。
            start_timer_every_with_jitter(
                cluster_rules_pull_interval_base,
                cluster_rules_pull_jitter_max,
                safe_pull_cluster_rules_snapshot
            )
        end

        -- 黑名单 matcher 存在 worker 内存中，每个 worker 都需要定时拉取 master 黑名单。
        ngx.timer.at(1, load_ip_blacklist_from_redis)
        -- 定时将文件加载到redis中
        utils.start_timer_every(10, load_ip_blacklist_from_redis)

        if is_timer_owner then
            -- 定时将攻击拦击名单加载到redis中
            utils.start_timer_every(10, sql.write_sql_queue_to_redis)
            -- 定时将攻击类型流量统计写入 Redis中
            utils.start_timer_every(10, sql.write_attack_type_traffic_to_redis)
            utils.start_timer_every(10, sql.write_waf_traffic_stats_to_redis)
            -- 定时将节点信息写入 Redis 中（30s + 0-10s 随机偏移，避免同秒写入）。
            start_timer_every_with_jitter(node_report_interval_base, node_report_jitter_max, sql.report_node_info)
        end
    end
end

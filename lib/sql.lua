-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local mysql = require "mysql_cli"
local config = require "config"
local utils = require "utils"
local constants = require "constants"
local cjson = require "cjson.safe"
local time = require "time"

local ipairs = ipairs
local pairs = pairs
local newtab = table.new
local concat = table.concat
local insert = table.insert
local ngxmatch = ngx.re.match
local quote_sql_str = ngx.quote_sql_str
local floor = math.floor
local format = string.format
local get_system_config = config.get_system_config
local is_system_option_on = config.is_system_option_on
local ngxfind = ngx.re.find

local redis_cli = require "redis_cli"


local _M = {}

local database = get_system_config('mysql').database

local BATCH_SIZE = 300
local DEFAULT_NODE_EXPIRE = 120
local DEFAULT_NODE_RETENTION = 86400
local RETRY_SET_EXPIRE = 86400
local DEFAULT_ATTACK_LOG_RETENTION_DAYS = 90
local DEFAULT_ATTACK_LOG_RETENTION_BATCH = 5000
local MAX_ATTACK_LOG_RETENTION_BATCH = 50000
local DEFAULT_ATTACK_LOG_RETENTION_INTERVAL = 300
local MIN_ATTACK_LOG_RETENTION_INTERVAL = 60
local ATTACK_LOG_RETENTION_LAST_RUN_KEY = "attack_log_retention:last_run"

local SQL_CHECK_TABLE =
[[SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='%s' AND table_name='%s']]

local SQL_CHECK_INDEX = [[
    SELECT COUNT(*) AS c
    FROM INFORMATION_SCHEMA.STATISTICS
    WHERE table_schema = %s AND table_name = %s AND index_name = %s
]]

local SQL_CREATE_TABLE_WAF_STATUS = [[
    CREATE TABLE `waf_status` (
        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        `http4xx` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'http状态码4xx数',
        `http5xx` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'http状态码5xx数',
        `request_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '请求数',
        `attack_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击请求数',
        `block_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '总拦截数',
        `block_times_attack` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击拦截数',
        `block_times_captcha` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '触发人机验证数',
        `block_times_cc` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'cc拦截数',
        `captcha_pass_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '人机验证通过数',
        `request_date` CHAR(10) NOT NULL COMMENT '日期',

        `update_time` datetime NULL,
        `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;
    CREATE UNIQUE INDEX idx_unique_waf_status_request_date ON waf_status (request_date);
]]

local SQL_INSERT_WAF_STATUS = [[
    INSERT INTO waf_status (
        request_date, http4xx, http5xx, request_times, attack_times, block_times,
        block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times,
        update_time
    ) VALUES (
        %s, %d, %d, %d, %d, %d, %d, %d, %d, %d, NOW()
    )
    ON DUPLICATE KEY UPDATE
        http4xx = VALUES(http4xx),
        http5xx = VALUES(http5xx),
        request_times = VALUES(request_times),
        attack_times = VALUES(attack_times),
        block_times = VALUES(block_times),
        block_times_attack = VALUES(block_times_attack),
        block_times_captcha = VALUES(block_times_captcha),
        block_times_cc = VALUES(block_times_cc),
        captcha_pass_times = VALUES(captcha_pass_times),
        update_time = NOW();
]]

local SQL_GET_TODAY_WAF_STATUS =
[[SELECT * FROM waf_status WHERE DATE(request_date) = CURDATE() ORDER BY id DESC LIMIT 1;]]

local SQL_CREATE_TABLE_TRAFFIC_STATS = [[
    CREATE TABLE `traffic_stats` (
        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

        `ip_country_code` CHAR(2) NULL COMMENT 'ip所属国家代码',
        `ip_country_cn` VARCHAR(255) NULL COMMENT 'ip所属国家_中文',
        `ip_country_en` VARCHAR(255) NULL COMMENT 'ip所属国家_英文',
        `ip_province_code` VARCHAR(50) NULL COMMENT 'ip所属省份代码',
        `ip_province_cn` VARCHAR(255) NULL COMMENT 'ip所属省份_中文',
        `ip_province_en` VARCHAR(255) NULL COMMENT 'ip所属省份_英文',
        `ip_city_code` VARCHAR(50) NULL COMMENT 'ip所属城市代码',
        `ip_city_cn` VARCHAR(255) NULL COMMENT 'ip所属城市_中文',
        `ip_city_en` VARCHAR(255) NULL COMMENT 'ip所属城市_英文',

        `request_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '请求数',
        `attack_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击请求数',
        `block_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '拦截数',
        `block_times_attack` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击拦截数',
        `block_times_captcha` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '触发人机验证数',
        `block_times_cc` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'cc拦截数',
        `captcha_pass_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '人机验证通过数',

        `request_date` CHAR(10) NOT NULL COMMENT '日期',

        `update_time` datetime NULL,
        `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
    CREATE UNIQUE INDEX idx_unique_traffic_stats_request_date ON traffic_stats (ip_country_code, ip_province_en, ip_city_en, request_date);
]]

local SQL_INSERT_TRAFFIC_STATS = [[
    INSERT INTO traffic_stats (ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en, request_times, attack_times, block_times,
    block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times, request_date)
    VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %u, %u, %u, %u, %u, %u, %u, %s) ON DUPLICATE KEY UPDATE request_times = request_times + VALUES(request_times),
    attack_times = attack_times + VALUES(attack_times),block_times = block_times + VALUES(block_times),
    block_times_attack = block_times_attack + VALUES(block_times_attack),
    block_times_captcha = block_times_captcha + VALUES(block_times_captcha),
    block_times_cc = block_times_cc + VALUES(block_times_cc),
    captcha_pass_times = captcha_pass_times + VALUES(captcha_pass_times),
    update_time = NOW();
]]

local SQL_GET_30DAYS_WORLD_TRAFFIC_STATS = [[
    SELECT ip_country_code AS 'iso_code',ip_country_cn AS 'name_cn', ip_country_en AS 'name_en',
        SUM(request_times) AS request_times,SUM(attack_times) AS attack_times,SUM(block_times) AS block_times,
        SUM(block_times_attack) AS block_times_attack, SUM(block_times_captcha) AS block_times_captcha, SUM(block_times_cc) AS block_times_cc, SUM(captcha_pass_times) AS captcha_pass_times
    FROM traffic_stats WHERE DATE(request_date) >= CURDATE() - INTERVAL 30 DAY GROUP BY ip_country_code, ip_country_cn, ip_country_en;
]]

local SQL_GET_30DAYS_CHINA_TRAFFIC_STATS = [[
    SELECT ip_province_code AS 'iso_code',ip_province_cn AS 'name_cn', ip_province_en AS 'name_en',
        SUM(request_times) AS request_times,SUM(attack_times) AS attack_times,SUM(block_times) AS block_times,
        SUM(block_times_attack) AS block_times_attack, SUM(block_times_captcha) AS block_times_captcha, SUM(block_times_cc) AS block_times_cc, SUM(captcha_pass_times) AS captcha_pass_times
    FROM traffic_stats WHERE ip_country_code='CN' AND DATE(request_date) >= CURDATE() - INTERVAL 30 DAY GROUP BY ip_province_code, ip_province_cn, ip_province_en;
]]


local SQL_CREATE_TABLE_ATTACK_LOG = [[
    CREATE TABLE `attack_log` (
        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        `request_id` CHAR(20) NOT NULL COMMENT '请求id',

        `ip` varchar(39) NOT NULL COMMENT 'ip地址',
        `ip_country_code` CHAR(2) NULL COMMENT 'ip所属国家代码',
        `ip_country_cn` VARCHAR(255) NULL COMMENT 'ip所属国家_中文',
        `ip_country_en` VARCHAR(255) NULL COMMENT 'ip所属国家_英文',
        `ip_province_code` VARCHAR(50) NULL COMMENT 'ip所属省份代码',
        `ip_province_cn` VARCHAR(255) NULL COMMENT 'ip所属省份_中文',
        `ip_province_en` VARCHAR(255) NULL COMMENT 'ip所属省份_英文',
        `ip_city_code` VARCHAR(50) NULL COMMENT 'ip所属城市代码',
        `ip_city_cn` VARCHAR(255) NULL COMMENT 'ip所属城市_中文',
        `ip_city_en` VARCHAR(255) NULL COMMENT 'ip所属城市_英文',
        `ip_longitude` DECIMAL(10, 7) NULL COMMENT 'ip地理位置经度',
        `ip_latitude` DECIMAL(10, 7) NULL COMMENT 'ip地理位置纬度',

        `http_method` VARCHAR(20) NULL COMMENT '请求http方法',
        `server_name` VARCHAR(100) NULL COMMENT '请求域名',
        `user_agent` VARCHAR(2048) NULL COMMENT '请求客户端ua',
        `referer` VARCHAR(2048) NULL COMMENT 'referer',

        `request_protocol` VARCHAR(50) NULL COMMENT '请求协议',
        `request_uri` VARCHAR(2048) NULL COMMENT '请求uri',
        `request_body` MEDIUMTEXT NULL COMMENT '请求体',
        `http_status` SMALLINT UNSIGNED NOT NULL COMMENT 'http响应状态码',
        `response_body` MEDIUMTEXT NULL COMMENT '响应体',
        `request_time` datetime NOT NULL,

        `attack_type` VARCHAR(200) NULL COMMENT '攻击类型',
        `severity_level` VARCHAR(20) NULL COMMENT '危险级别',
        `security_module` VARCHAR(255) NULL COMMENT '安全模块',
        `hit_rule` VARCHAR(500) NULL COMMENT '命中规则',
        `action` VARCHAR(100) NULL COMMENT '处置动作',

        `update_time` datetime NULL,
        `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;
    CREATE UNIQUE INDEX idx_unique_attack_log_request_id ON attack_log (request_id);
]]

local SQL_INSERT_ATTACK_LOG = [[
    INSERT INTO attack_log (
        request_id, ip, ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en,
        ip_longitude, ip_latitude, http_method, server_name, user_agent, referer, request_protocol, request_uri,
        request_body, http_status, response_body, request_time, attack_type, severity_level, security_module, hit_rule, action)
    VALUES
]]

local SQL_CREATE_TABLE_ATTACK_LOG_ARCHIVE = [[
    CREATE TABLE IF NOT EXISTS `attack_log_archive` LIKE `attack_log`;
]]

local SQL_CREATE_TABLE_IP_BLOCK_LOG = [[
    CREATE TABLE `ip_block_log` (
        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        `request_id` CHAR(20) NULL COMMENT '请求id',

        `ip` varchar(39) NOT NULL COMMENT 'ip地址',
        `ip_country_code` CHAR(2) NULL COMMENT 'ip所属国家代码',
        `ip_country_cn` VARCHAR(255) NULL COMMENT 'ip所属国家_中文',
        `ip_country_en` VARCHAR(255) NULL COMMENT 'ip所属国家_英文',
        `ip_province_code` VARCHAR(50) NULL COMMENT 'ip所属省份代码',
        `ip_province_cn` VARCHAR(255) NULL COMMENT 'ip所属省份_中文',
        `ip_province_en` VARCHAR(255) NULL COMMENT 'ip所属省份_英文',
        `ip_city_code` VARCHAR(50) NULL COMMENT 'ip所属城市代码',
        `ip_city_cn` VARCHAR(255) NULL COMMENT 'ip所属城市_中文',
        `ip_city_en` VARCHAR(255) NULL COMMENT 'ip所属城市_英文',
        `ip_longitude` DECIMAL(10, 7) NULL COMMENT 'ip地理位置经度',
        `ip_latitude` DECIMAL(10, 7) NULL COMMENT 'ip地理位置纬度',

        `block_reason` VARCHAR(200) NULL COMMENT '封禁原因',
        `start_time` datetime NOT NULL COMMENT '封禁开始时间',
        `block_duration` INT NULL COMMENT '封禁时长',
        `end_time` datetime NULL COMMENT '封禁结束时间',
        `block_times` INT NULL COMMENT '封禁请求次数',
        `action` VARCHAR(100) NULL COMMENT '处置动作',
        `unblock_time` datetime  NULL COMMENT '解封时间',

        `update_time` datetime NULL,
        `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;
    CREATE UNIQUE INDEX idx_unique_ip_block_log_ip_start_time ON ip_block_log (ip, start_time);
]]

local SQL_INSERT_IP_BLOCK_LOG = [[
    INSERT INTO ip_block_log (
        request_id, ip, ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en,
        ip_longitude, ip_latitude, block_reason, start_time, block_duration, end_time, action)
    VALUES
]]

local SQL_GET_ATTACK_TYPE_TRAFFIC = [[
    SELECT attack_type, attack_count
    FROM attack_type_traffic
    WHERE request_date = CURDATE()
]]

local SQL_CREATE_TABLE_ATTACK_TYPE_TRAFFIC = [[
    CREATE TABLE `attack_type_traffic` (
    `attack_type` varchar(255) NOT NULL,
    `attack_count` int(11) NOT NULL DEFAULT '0',
    `request_date` date NOT NULL,
    PRIMARY KEY (`attack_type`,`request_date`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
]]

local SQL_CREATE_TABLE_WAF_TRAFFIC_STATS = [[
    CREATE TABLE waf_traffic_stats (
        id INT AUTO_INCREMENT PRIMARY KEY,
        access_time DATETIME NOT NULL COMMENT '时间',
        total_requests INT UNSIGNED DEFAULT 0 COMMENT '总请求数',
        blocked_requests INT UNSIGNED DEFAULT 0 COMMENT '拦截数',
        attack_requests INT UNSIGNED DEFAULT 0 COMMENT '攻击数',
        website_id VARCHAR(64) NOT NULL DEFAULT 'global' COMMENT '站点ID',
        create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        update_time DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_time_website (access_time, website_id),
        INDEX idx_access_time (access_time)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE UNIQUE INDEX uniq_access_time ON waf_traffic_stats (access_time);
]]

local SQL_INSERT_WAF_TRAFFIC_STATS = [[
    INSERT INTO waf_traffic_stats (
        access_time, total_requests, blocked_requests, attack_requests
    ) VALUES (%s, %d, %d, %d)
        ON DUPLICATE KEY UPDATE
        total_requests = VALUES(total_requests),
        blocked_requests = VALUES(blocked_requests),
        attack_requests = VALUES(attack_requests)
]]

local function is_duplicate_entry_error(err)
    if not err then
        return false
    end
    return string.find(err, "Duplicate entry", 1, true) ~= nil
end

local function normalize_hour_to_datetime(access_time)
    if not access_time then
        return nil
    end

    if string.match(access_time, "^%d%d%d%d%-%d%d%-%d%d %d%d$") then
        return access_time .. ":00:00"
    end

    return access_time
end

local function get_cluster_node_expire_seconds()
    local system_cfg = get_system_config("system") or {}
    local expire = tonumber(system_cfg.expire)
    if not expire or expire <= 0 then
        expire = DEFAULT_NODE_EXPIRE
    end
    return floor(expire)
end

local function get_cluster_node_retention_seconds()
    local system_cfg = get_system_config("system") or {}
    local retention = tonumber(system_cfg.node_retention)
    if not retention or retention <= 0 then
        retention = DEFAULT_NODE_RETENTION
    end

    local min_retention = get_cluster_node_expire_seconds() * 2
    if retention < min_retention then
        retention = min_retention
    end
    return floor(retention)
end

local function get_attack_log_retention_config()
    local conf = get_system_config("attackLogRetention") or {}
    local state = tostring(conf.state or "on")

    local days = tonumber(conf.days) or DEFAULT_ATTACK_LOG_RETENTION_DAYS
    if days < 1 then
        days = DEFAULT_ATTACK_LOG_RETENTION_DAYS
    end

    local batch = tonumber(conf.batch_size or conf.batchSize) or DEFAULT_ATTACK_LOG_RETENTION_BATCH
    if batch < 100 then
        batch = 100
    elseif batch > MAX_ATTACK_LOG_RETENTION_BATCH then
        batch = MAX_ATTACK_LOG_RETENTION_BATCH
    end

    local interval = tonumber(conf.interval_seconds or conf.intervalSeconds) or DEFAULT_ATTACK_LOG_RETENTION_INTERVAL
    if interval < MIN_ATTACK_LOG_RETENTION_INTERVAL then
        interval = MIN_ATTACK_LOG_RETENTION_INTERVAL
    end

    return state == "on", floor(days), floor(batch), floor(interval)
end

local SQL_GET_REQUEST_TRAFFIC_BY_HOUR = [[
    SELECT DATE_FORMAT(access_time, '%Y-%m-%d %H') AS hour,
           SUM(total_requests) AS traffic,
           SUM(attack_requests) AS attack_traffic,
           SUM(blocked_requests) AS blocked_traffic
    FROM waf_traffic_stats
    WHERE access_time BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 1 DAY)
    GROUP BY hour
    ORDER BY hour ASC
]]

local SQL_CREATE_TABLE_WAF_CLUSTER_NODE = [[
    CREATE TABLE waf_cluster_node (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip VARCHAR(64) NOT NULL COMMENT '节点IP',
        version VARCHAR(32) COMMENT '节点版本',
        hostname VARCHAR(128) COMMENT '节点主机名',
        last_seen DATETIME COMMENT '最近活跃时间',
        create_time DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
        UNIQUE KEY uniq_ip (ip),
        INDEX idx_last_seen (last_seen)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
]]


local SQL_INSERT_CLUSTER_NODE = [[
    INSERT INTO waf_cluster_node (ip, version, hostname, last_seen)
    VALUES (%s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        version = VALUES(version),
        hostname = VALUES(hostname),
        last_seen = VALUES(last_seen)
]]

local SQL_DELETE_STALE_CLUSTER_NODES = [[
    DELETE FROM waf_cluster_node
    WHERE last_seen < NOW() - INTERVAL %d SECOND
]]

local SQL_INSERT_ATTACK_LOG_ARCHIVE = [[
    INSERT IGNORE INTO attack_log_archive
    SELECT *
    FROM attack_log
    WHERE request_time < NOW() - INTERVAL %d DAY
    LIMIT %d
]]

local SQL_DELETE_ATTACK_LOG_ARCHIVE_SOURCE = [[
    DELETE FROM attack_log
    WHERE request_time < NOW() - INTERVAL %d DAY
    LIMIT %d
]]



local function yesterday()
    local now = os.time()
    local one_day = 24 * 60 * 60
    local yesterday_time = now - one_day
    return os.date("%Y-%m-%d", yesterday_time)
end

local function reset_traffic_stats(dict, prefix)
    utils.dict_set(dict, prefix .. constants.KEY_REQUEST_TIMES, 0)
    utils.dict_set(dict, prefix .. constants.KEY_ATTACK_TIMES, 0)
    utils.dict_set(dict, prefix .. constants.KEY_BLOCK_TIMES_ATTACK, 0)
    utils.dict_set(dict, prefix .. constants.KEY_BLOCK_TIMES_CAPTCHA, 0)
    utils.dict_set(dict, prefix .. constants.KEY_BLOCK_TIMES_CC, 0)
    utils.dict_set(dict, prefix .. constants.KEY_CAPTCHA_PASS_TIMES, 0)
end

function _M.check_table(premature)
    if premature then
        return
    end

    local tables = {
        { name = 'waf_status',          sql = SQL_CREATE_TABLE_WAF_STATUS },
        { name = 'traffic_stats',       sql = SQL_CREATE_TABLE_TRAFFIC_STATS },
        { name = 'attack_log',          sql = SQL_CREATE_TABLE_ATTACK_LOG },
        { name = 'attack_log_archive',  sql = SQL_CREATE_TABLE_ATTACK_LOG_ARCHIVE },
        { name = 'ip_block_log',        sql = SQL_CREATE_TABLE_IP_BLOCK_LOG },
        { name = 'attack_type_traffic', sql = SQL_CREATE_TABLE_ATTACK_TYPE_TRAFFIC },
        { name = 'waf_traffic_stats',   sql = SQL_CREATE_TABLE_WAF_TRAFFIC_STATS },
        { name = 'waf_cluster_node',    sql = SQL_CREATE_TABLE_WAF_CLUSTER_NODE },
    }

    for _, t in pairs(tables) do
        local name = t.name
        local sql = t.sql

        local res, err = mysql.query(format(SQL_CHECK_TABLE, database, name))
        if res and res[1] and res[1].c == '0' then
            res, err = mysql.query(sql)
            if not res then
                ngx.log(4, 'failed to create table ' .. name .. ' ', err)
            end
        end
    end

    local function ensure_index(table_name, index_name, ddl)
        local idx_res, idx_err = mysql.query(format(SQL_CHECK_INDEX,
            quote_sql_str(database), quote_sql_str(table_name), quote_sql_str(index_name)))
        if idx_res and idx_res[1] and idx_res[1].c == '0' then
            local ok = mysql.query(ddl)
            if not ok then
                ngx.log(ngx.ERR, "failed to add index ", index_name, " on ", table_name)
            end
        elseif not idx_res then
            ngx.log(ngx.ERR, "failed to check index ", index_name, " on ", table_name, ": ", idx_err)
        end
    end

    -- 兼容老版本表结构：attack_log 可能没有 request_id 唯一索引，这里补齐一次。
    ensure_index("attack_log", "idx_unique_attack_log_request_id",
        "ALTER TABLE attack_log ADD UNIQUE INDEX idx_unique_attack_log_request_id (request_id)")

    -- attack_log 常用查询维度索引（按时间、IP、攻击类型、站点、动作），减少大表查询和清理扫描压力。
    ensure_index("attack_log", "idx_attack_log_request_time",
        "ALTER TABLE attack_log ADD INDEX idx_attack_log_request_time (request_time)")
    ensure_index("attack_log", "idx_attack_log_ip_time",
        "ALTER TABLE attack_log ADD INDEX idx_attack_log_ip_time (ip, request_time)")
    ensure_index("attack_log", "idx_attack_log_type_time",
        "ALTER TABLE attack_log ADD INDEX idx_attack_log_type_time (attack_type, request_time)")
    ensure_index("attack_log", "idx_attack_log_server_time",
        "ALTER TABLE attack_log ADD INDEX idx_attack_log_server_time (server_name, request_time)")
    ensure_index("attack_log", "idx_attack_log_action_time",
        "ALTER TABLE attack_log ADD INDEX idx_attack_log_action_time (action, request_time)")
    ensure_index("attack_log_archive", "idx_attack_log_archive_request_time",
        "ALTER TABLE attack_log_archive ADD INDEX idx_attack_log_archive_request_time (request_time)")
    ensure_index("attack_log_archive", "idx_attack_log_archive_ip_time",
        "ALTER TABLE attack_log_archive ADD INDEX idx_attack_log_archive_ip_time (ip, request_time)")
    ensure_index("attack_log_archive", "idx_attack_log_archive_type_time",
        "ALTER TABLE attack_log_archive ADD INDEX idx_attack_log_archive_type_time (attack_type, request_time)")
    ensure_index("attack_log_archive", "idx_attack_log_archive_server_time",
        "ALTER TABLE attack_log_archive ADD INDEX idx_attack_log_archive_server_time (server_name, request_time)")
    ensure_index("attack_log_archive", "idx_attack_log_archive_action_time",
        "ALTER TABLE attack_log_archive ADD INDEX idx_attack_log_archive_action_time (action, request_time)")
    -- 兼容老版本表结构：waf_cluster_node 可能没有 last_seen 索引，这里补齐一次。
    ensure_index("waf_cluster_node", "idx_last_seen",
        "ALTER TABLE waf_cluster_node ADD INDEX idx_last_seen (last_seen)")
end

function _M.update_traffic_stats()
    local dict = ngx.shared.dict_req_count_citys

    if not redis_cli then
        ngx.log(4, "failed to load redis_cli module")
        return
    end

    if not cjson then
        ngx.log(4, "failed to load cjson module")
        return
    end

    local keys = dict:get_keys()

    if keys then
        local key_table = {}

        for _, key in ipairs(keys) do
            local m, err = ngxmatch(key, '(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?):', 'isjo')
            if m then
                local prefix = m[0]

                local countryCode = m[1] or ''
                local countryCN = m[2] or ''
                local countryEN = m[3] or ''

                local provinceCode = m[4] or ''
                local provinceCN = m[5] or ''
                local provinceEN = m[6] or ''

                local cityCode = m[7] or ''
                local cityCN = m[8] or ''
                local cityEN = m[9] or ''

                insert(key_table, {
                    prefix = prefix,
                    countryCode = countryCode,
                    countryCN = countryCN,
                    countryEN = countryEN,
                    provinceCode = provinceCode,
                    provinceCN = provinceCN,
                    provinceEN = provinceEN,
                    cityCode = cityCode,
                    cityCN = cityCN,
                    cityEN = cityEN
                })
            end
        end

        for _, t in pairs(key_table) do
            local prefix = t.prefix

            local request_times = utils.dict_get(dict, prefix .. constants.KEY_REQUEST_TIMES) or 0
            local attack_times = utils.dict_get(dict, prefix .. constants.KEY_ATTACK_TIMES) or 0
            local block_times_attack = utils.dict_get(dict, prefix .. constants.KEY_BLOCK_TIMES_ATTACK) or 0
            local block_times_captcha = utils.dict_get(dict, prefix .. constants.KEY_BLOCK_TIMES_CAPTCHA) or 0
            local block_times_cc = utils.dict_get(dict, prefix .. constants.KEY_BLOCK_TIMES_CC) or 0
            local captcha_pass_times = utils.dict_get(dict, prefix .. constants.KEY_CAPTCHA_PASS_TIMES) or 0

            if request_times > 0 or attack_times > 0 or block_times_attack > 0 or block_times_captcha > 0 or block_times_cc > 0 or captcha_pass_times > 0 then
                -- 判断是否是集群
                if is_system_option_on("centralized") then
                    local traffic_stats = {
                        countryCode = t.countryCode,
                        countryCN = t.countryCN,
                        countryEN = t.countryEN,
                        provinceCode = t.provinceCode,
                        provinceCN = t.provinceCN,
                        provinceEN = t.provinceEN,
                        cityCode = t.cityCode,
                        cityCN = t.cityCN,
                        cityEN = t.cityEN,
                        request_times = request_times,
                        attack_times = attack_times,
                        block_times_attack = block_times_attack,
                        block_times_captcha = block_times_captcha,
                        block_times_cc = block_times_cc,
                        captcha_pass_times = captcha_pass_times,
                        date = ngx.today()
                    }

                    local traffic_stats_json, err = cjson.encode(traffic_stats)
                    if not traffic_stats_json then
                        ngx.log(4, "failed to encode traffic stats json: ", err)
                        goto continue
                    end

                    local redis_key = "waf:traffic_stats:" .. prefix .. ngx.today()

                    -- 尝试从 Redis 中获取已有的数据
                    local redis_value, err = redis_cli.get(redis_key)
                    if redis_value then
                        local old_traffic_stats, err = cjson.decode(redis_value)
                        if old_traffic_stats then
                            -- 将新的数据累加到已有的数据上
                            traffic_stats.request_times = traffic_stats.request_times +
                                (old_traffic_stats.request_times or 0)
                            traffic_stats.attack_times = traffic_stats.attack_times +
                                (old_traffic_stats.attack_times or 0)
                            traffic_stats.block_times_attack = traffic_stats.block_times_attack +
                                (old_traffic_stats.block_times_attack or 0)
                            traffic_stats.block_times_captcha = traffic_stats.block_times_captcha +
                                (old_traffic_stats.block_times_captcha or 0)
                            traffic_stats.block_times_cc = traffic_stats.block_times_cc +
                                (old_traffic_stats.block_times_cc or 0)
                            traffic_stats.captcha_pass_times = traffic_stats.captcha_pass_times +
                                (old_traffic_stats.captcha_pass_times or 0)
                        end
                    end

                    traffic_stats_json, err = cjson.encode(traffic_stats)
                    if not traffic_stats_json then
                        ngx.log(4, "failed to encode traffic stats json: ", err)
                        goto continue
                    end

                    local ok, err = redis_cli.set(redis_key, traffic_stats_json, get_system_config('redis').expire_time)
                    if not ok then
                        ngx.log(4, "failed to write traffic stats to redis: ", err)
                    else
                        redis_cli.sadd(constants.KEY_REDIS_DIRTY_TRAFFIC_STATS, redis_key, get_system_config('redis').expire_time)
                    end

                    reset_traffic_stats(dict, prefix)
                else
                    reset_traffic_stats(dict, prefix)

                    local block_times = block_times_attack + block_times_captcha + block_times_cc

                    local sql = format(SQL_INSERT_TRAFFIC_STATS,
                        quote_sql_str(t.countryCode), quote_sql_str(t.countryCN), quote_sql_str(t.countryEN),
                        quote_sql_str(t.provinceCode), quote_sql_str(t.provinceCN), quote_sql_str(t.provinceEN),
                        quote_sql_str(t.cityCode), quote_sql_str(t.cityCN), quote_sql_str(t.cityEN),
                        request_times, attack_times, block_times, block_times_attack, block_times_captcha, block_times_cc,
                        captcha_pass_times,
                        quote_sql_str(ngx.today()))

                    mysql.query(sql)
                end
            end
            ::continue::
        end
    end
end

function _M.write_traffic_stats_redis_to_mysql()
    local traffic_stats_keys, err = redis_cli.smembers(constants.KEY_REDIS_DIRTY_TRAFFIC_STATS)

    if not traffic_stats_keys then
        ngx.log(4, "failed to get dirty traffic stats keys from redis: ", err)
        return
    end

    for _, redis_key in ipairs(traffic_stats_keys) do
        local redis_value, err = redis_cli.get(redis_key)

        if not redis_value then
            redis_cli.srem(constants.KEY_REDIS_DIRTY_TRAFFIC_STATS, redis_key)
            redis_cli.srem(constants.KEY_REDIS_RETRY_TRAFFIC_STATS, redis_key)
            goto continue
        end

        local traffic_stats, err = cjson.decode(redis_value)
        if not traffic_stats then
            ngx.log(4, "failed to decode traffic stats json: ", err)
            goto continue
        end

        local countryCode = traffic_stats.countryCode or ''
        local countryCN = traffic_stats.countryCN or ''
        local countryEN = traffic_stats.countryEN or ''
        local provinceCode = traffic_stats.provinceCode or ''
        local provinceCN = traffic_stats.provinceCN or ''
        local provinceEN = traffic_stats.provinceEN or ''
        local cityCode = traffic_stats.cityCode or ''
        local cityCN = traffic_stats.cityCN or ''
        local cityEN = traffic_stats.cityEN or ''
        local request_times = traffic_stats.request_times or 0
        local attack_times = traffic_stats.attack_times or 0
        local block_times_attack = traffic_stats.block_times_attack or 0
        local block_times_captcha = traffic_stats.block_times_captcha or 0
        local block_times_cc = traffic_stats.block_times_cc or 0
        local captcha_pass_times = traffic_stats.captcha_pass_times or 0
        local block_times = block_times_attack + block_times_captcha + block_times_cc

        local sql = format(SQL_INSERT_TRAFFIC_STATS,
            quote_sql_str(countryCode), quote_sql_str(countryCN), quote_sql_str(countryEN),
            quote_sql_str(provinceCode), quote_sql_str(provinceCN), quote_sql_str(provinceEN),
            quote_sql_str(cityCode), quote_sql_str(cityCN), quote_sql_str(cityEN),
            request_times, attack_times, block_times, block_times_attack, block_times_captcha, block_times_cc,
            captcha_pass_times,
            quote_sql_str(ngx.today()))

        local res, err = mysql.query(sql)
        if not res then
            ngx.log(4, "failed to write traffic stats to mysql: ", err)
            redis_cli.sadd(constants.KEY_REDIS_RETRY_TRAFFIC_STATS, redis_key, RETRY_SET_EXPIRE)
            goto continue
        end

        local ok, err = redis_cli.del(redis_key)
        if not ok then
            ngx.log(4, "failed to delete traffic stats key from redis: ", err)
        else
            redis_cli.srem(constants.KEY_REDIS_DIRTY_TRAFFIC_STATS, redis_key)
            redis_cli.srem(constants.KEY_REDIS_RETRY_TRAFFIC_STATS, redis_key)
        end
        ::continue::
    end
end

function _M.update_waf_status()
    local dict = ngx.shared.dict_req_count

    local function pop(key)
        local val = dict:incr(key, 0) or 0
        dict:incr(key, -val)
        return val
    end

    -- 获取各类统计值，并原子清零
    local http4xx = pop(constants.KEY_HTTP_4XX)
    local http5xx = pop(constants.KEY_HTTP_5XX)
    local request_times = pop(constants.KEY_REQUEST_TIMES)
    local attack_times = pop(constants.KEY_ATTACK_TIMES)
    local block_times_attack = pop(constants.KEY_BLOCK_TIMES_ATTACK)
    local block_times_captcha = pop(constants.KEY_BLOCK_TIMES_CAPTCHA)
    local block_times_cc = pop(constants.KEY_BLOCK_TIMES_CC)
    local captcha_pass_times = pop(constants.KEY_CAPTCHA_PASS_TIMES)

    -- 所有指标都为 0 时直接跳过
    if http4xx == 0 and http5xx == 0 and request_times == 0 and attack_times == 0
        and block_times_attack == 0 and block_times_captcha == 0 and block_times_cc == 0 and captcha_pass_times == 0 then
        return
    end

    local block_times = block_times_attack + block_times_captcha + block_times_cc

    if is_system_option_on("centralized") then
        -- ✅ 集群模式：Redis Hash 累加
        local function hincr(key, field, val)
            if val and val > 0 then
                local ok, err = redis_cli.hincrby(key, field, val)
                if not ok then
                    ngx.log(ngx.ERR, "hincrby failed: ", field, " err: ", err)
                end
            end
        end

        local redis_key = "waf:waf_status_hmap:" .. ngx.today()
        hincr(redis_key, "http4xx", http4xx)
        hincr(redis_key, "http5xx", http5xx)
        hincr(redis_key, "request_times", request_times)
        hincr(redis_key, "attack_times", attack_times)
        hincr(redis_key, "block_times", block_times)
        hincr(redis_key, "block_times_attack", block_times_attack)
        hincr(redis_key, "block_times_captcha", block_times_captcha)
        hincr(redis_key, "block_times_cc", block_times_cc)
        hincr(redis_key, "captcha_pass_times", captcha_pass_times)

        redis_cli.expire(redis_key, get_system_config("redis").expire_time)
    else
        -- ✅ 单节点模式：直接写入 MySQL
        local sql = string.format(SQL_INSERT_WAF_STATUS,
            http4xx, http5xx, request_times, attack_times, block_times,
            block_times_attack, block_times_captcha, block_times_cc,
            captcha_pass_times, quote_sql_str(ngx.today())
        )

        local res, err = mysql.query(sql)
        if not res then
            ngx.log(ngx.ERR, "failed to insert waf_status: ", err)
        end
    end
end

function _M.write_waf_status_redis_to_mysql()
    local today = ngx.today()
    local redis_key = "waf:waf_status_hmap:" .. today

    local hash_data, err = redis_cli.hgetall(redis_key)
    if not hash_data then
        ngx.log(ngx.ERR, "failed to hgetall from redis key: ", redis_key, " err: ", err)
        return
    end

    -- Redis 返回扁平数组：{ "field1", "val1", "field2", "val2", ... }
    local data = {}
    for i = 1, #hash_data, 2 do
        local k = tostring(hash_data[i])
        local v = tonumber(hash_data[i + 1]) or 0
        data[k] = v
    end

    -- 字段赋值，默认0
    local http4xx = data.http4xx or 0
    local http5xx = data.http5xx or 0
    local request_times = data.request_times or 0
    local attack_times = data.attack_times or 0
    local block_times = data.block_times or 0
    local block_times_attack = data.block_times_attack or 0
    local block_times_captcha = data.block_times_captcha or 0
    local block_times_cc = data.block_times_cc or 0
    local captcha_pass_times = data.captcha_pass_times or 0

    -- 全部为0，跳过写入
    if http4xx == 0 and http5xx == 0 and request_times == 0 and attack_times == 0
        and block_times == 0 and block_times_attack == 0 and block_times_captcha == 0
        and block_times_cc == 0 and captcha_pass_times == 0 then
        ngx.log(ngx.INFO, "all WAF status fields are 0, skip insert.")
        return
    end

    -- 使用 ON DUPLICATE KEY UPDATE 实现累积写入（需确保表中 date 列为唯一键）
    local sql = string.format(SQL_INSERT_WAF_STATUS,
        quote_sql_str(today),
        http4xx, http5xx, request_times, attack_times, block_times,
        block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times)

    local res, err = mysql.query(sql)
    if not res then
        ngx.log(ngx.ERR, "failed to write waf_status from redis to mysql: ", err)
        return
    end

    -- 不删除 Redis key，保留数据，避免集群模式数据丢失
    ngx.log(ngx.INFO, "write_waf_status_redis_to_mysql succeeded for date: ", today)
end

function _M.get_today_waf_status()
    return mysql.query(SQL_GET_TODAY_WAF_STATUS)
end

function _M.get_30days_world_traffic_stats()
    return mysql.query(SQL_GET_30DAYS_WORLD_TRAFFIC_STATS)
end

function _M.get_30days_china_traffic_stats()
    return mysql.query(SQL_GET_30DAYS_CHINA_TRAFFIC_STATS)
end

function _M.write_sql_queue_to_mysql(premature, key)
    if premature or not key then
        return
    end

    local dict_sql_queue = ngx.shared.dict_sql_queue

    local len = dict_sql_queue:llen(key) or 0
    if len == 0 then
        return
    end

    local sql_str = ''
    if key == constants.KEY_ATTACK_LOG then
        sql_str = SQL_INSERT_ATTACK_LOG
    elseif key == constants.KEY_IP_BLOCK_LOG then
        sql_str = SQL_INSERT_IP_BLOCK_LOG
    end

    local insert_time_total = floor(len / BATCH_SIZE) + 1
    local insert_time = 0

    local buffer = newtab(BATCH_SIZE, 0)

    local index = 1
    local value = dict_sql_queue:lpop(key)

    while (insert_time <= insert_time_total and value) do
        buffer[index] = value
        value = dict_sql_queue:lpop(key)

        if index == BATCH_SIZE or value == nil then
            local sql_values = concat(buffer, ',')

            if sql_values then
                mysql.query(sql_str .. sql_values)
                insert_time = insert_time + 1
            end

            index = 1
            buffer = newtab(BATCH_SIZE, 0)
        else
            index = index + 1
        end
    end
end

function _M.write_sql_queue_to_redis()
    local key = constants.KEY_IP_BLOCK_LOG

    local dict_sql_queue = ngx.shared.dict_sql_queue

    local len = dict_sql_queue:llen(key) or 0
    if len == 0 then
        return
    end

    local buffer = newtab(BATCH_SIZE, 0)

    local index = 1
    local value = dict_sql_queue:lpop(key)

    while value do
        buffer[index] = value
        value = dict_sql_queue:lpop(key)

        if index == BATCH_SIZE or value == nil then
            local ok, err = redis_cli.bath_rpush(constants.KEY_REDIS_QUEUE_IP_BLOCK_LOG, buffer, get_system_config('redis').expire_time)
            if not ok then
                ngx.log(4, "failed to push ip block log to redis queue: ", err)
                for _, item in ipairs(buffer) do
                    dict_sql_queue:rpush(key, item)
                end
            end

            index = 1
            buffer = newtab(BATCH_SIZE, 0)
        else
            index = index + 1
        end
    end
end

local function getRequestTraffic()
    local hours = time.get_hours()
    local dict = ngx.shared.dict_req_count
    local dataStr = '[["hour", "traffic","attack_traffic","blocked_traffic"],'
    for _, hour in ipairs(hours) do
        local count = dict:get(hour) or 0
        local attack_count = dict:get(constants.KEY_ATTACK_PREFIX .. hour) or 0
        local blocked_count = dict:get(constants.KEY_BLOCKED_PREFIX .. hour) or 0
        dataStr = concat({ dataStr, '["', hour, '", ', count, ',', attack_count, ',', blocked_count, '],' })
    end

    dataStr = string.sub(dataStr, 1, -2) .. ']'
    -- ngx.log(8, "getRequestTraffic dataStr: ", dataStr)
    return dataStr
end

function _M.write_ip_block_log_redis_to_mysql()
    local queue_values = redis_cli.batch_lpop(constants.KEY_REDIS_QUEUE_IP_BLOCK_LOG, BATCH_SIZE)

    if queue_values and queue_values[1] then
        local sql_str = SQL_INSERT_IP_BLOCK_LOG .. concat(queue_values, ',') .. " ON DUPLICATE KEY UPDATE update_time = NOW()"
        local res, err = mysql.query(sql_str)
        if not res and not is_duplicate_entry_error(err) then
            ngx.log(4, "failed to write ip block log queue to mysql: ", err)
            redis_cli.bath_rpush(constants.KEY_REDIS_QUEUE_IP_BLOCK_LOG, queue_values, get_system_config('redis').expire_time)
            return
        end
    end

end

function _M.write_attack_type_traffic_to_redis()
    local redis_key = "waf:attack_type_traffic_map:" .. ngx.today()
    local dict = ngx.shared.dict_req_count
    local keys = dict:get_keys()
    local prefix = constants.KEY_ATTACK_TYPE_PREFIX .. ngx.today()
    local touched = false

    if not keys or #keys == 0 then
        return
    end

    for _, key in ipairs(keys) do
        local from = ngxfind(key, prefix)
        if from then
            local count = dict:get(key) or 0
            if count > 0 then
                local attack_type = "attack_type_" .. ngx.today() .. string.sub(key, #prefix + 1) -- 提取攻击类型
                local ok, err = redis_cli.hincrby(redis_key, attack_type, count)
                if not ok then
                    ngx.log(ngx.ERR, "failed to hincrby attack_type: ", attack_type, " err: ", err)
                else
                    touched = true
                end
            end
        end
    end

    -- 设置过期时间（可配置）
    local expire = 86400
    local ok, err = redis_cli.expire(redis_key, expire)
    if not ok then
        ngx.log(ngx.ERR, "failed to expire attack_type_traffic redis_key: ", err)
    end

    if touched then
        redis_cli.sadd(constants.KEY_REDIS_DIRTY_ATTACK_TYPE_DATES, ngx.today(), expire)
    end

    -- ✅ 清空 ngx.shared.dict_req_count 中该前缀的所有键
    for _, key in ipairs(keys) do
        if ngxfind(key, prefix) then
            dict:delete(key)
        end
    end
end

function _M.write_attack_type_traffic_redis_to_mysql()
    local dates, err = redis_cli.smembers(constants.KEY_REDIS_DIRTY_ATTACK_TYPE_DATES)
    if not dates then
        ngx.log(ngx.ERR, "failed to read dirty attack_type dates from redis: ", err)
        return
    end

    for _, request_date in ipairs(dates) do
        local redis_key = "waf:attack_type_traffic_map:" .. request_date

        local hash_data, hgetall_err = redis_cli.hgetall(redis_key)
        if not hash_data then
            ngx.log(ngx.ERR, "failed to hgetall attack_type_traffic from redis key ", redis_key, ": ", hgetall_err)
            redis_cli.sadd(constants.KEY_REDIS_RETRY_ATTACK_TYPE_DATES, request_date, RETRY_SET_EXPIRE)
            goto continue
        end

        local write_failed = false
        -- Redis 返回的是扁平数组：{ "type1", "count1", "type2", "count2", ... }
        for i = 1, #hash_data, 2 do
            local attack_type = tostring(hash_data[i])
            local attack_count = tonumber(hash_data[i + 1]) or 0

            if attack_count > 0 then
                local sql = string.format(
                    "INSERT INTO attack_type_traffic (attack_type, attack_count, request_date) " ..
                    "VALUES (%s, %d, %s) " ..
                    "ON DUPLICATE KEY UPDATE attack_count = VALUES(attack_count)",
                    quote_sql_str(attack_type), attack_count, quote_sql_str(request_date)
                )

                local res, insert_err = mysql.query(sql)
                if not res then
                    ngx.log(ngx.ERR, "failed to insert attack_type_traffic into mysql: ", insert_err)
                    write_failed = true
                end
            end
        end

        if not write_failed then
            redis_cli.srem(constants.KEY_REDIS_DIRTY_ATTACK_TYPE_DATES, request_date)
            redis_cli.srem(constants.KEY_REDIS_RETRY_ATTACK_TYPE_DATES, request_date)
        else
            redis_cli.sadd(constants.KEY_REDIS_RETRY_ATTACK_TYPE_DATES, request_date, RETRY_SET_EXPIRE)
        end

        ::continue::
    end
end

function _M.replay_retry_markers()
    local redis_expire = get_system_config('redis').expire_time or RETRY_SET_EXPIRE

    local traffic_retry_keys, traffic_retry_err = redis_cli.smembers(constants.KEY_REDIS_RETRY_TRAFFIC_STATS)
    if not traffic_retry_keys then
        ngx.log(ngx.ERR, "failed to get retry traffic stats keys: ", traffic_retry_err)
    else
        for _, redis_key in ipairs(traffic_retry_keys) do
            local value = redis_cli.get(redis_key)
            if value then
                redis_cli.sadd(constants.KEY_REDIS_DIRTY_TRAFFIC_STATS, redis_key, redis_expire)
            else
                redis_cli.srem(constants.KEY_REDIS_RETRY_TRAFFIC_STATS, redis_key)
            end
        end
    end

    local attack_retry_dates, attack_retry_err = redis_cli.smembers(constants.KEY_REDIS_RETRY_ATTACK_TYPE_DATES)
    if not attack_retry_dates then
        ngx.log(ngx.ERR, "failed to get retry attack_type dates: ", attack_retry_err)
    else
        for _, request_date in ipairs(attack_retry_dates) do
            local redis_key = "waf:attack_type_traffic_map:" .. request_date
            local hash_data = redis_cli.hgetall(redis_key)
            if hash_data and hash_data[1] then
                redis_cli.sadd(constants.KEY_REDIS_DIRTY_ATTACK_TYPE_DATES, request_date, RETRY_SET_EXPIRE)
            else
                redis_cli.srem(constants.KEY_REDIS_RETRY_ATTACK_TYPE_DATES, request_date)
            end
        end
    end
end

function _M.get_attack_type_traffic()
    return mysql.query(SQL_GET_ATTACK_TYPE_TRAFFIC)
end

local lock = require "resty.lock"

function _M.write_waf_traffic_stats_to_redis()
    local l = lock:new("waf_lock_dict") -- 需要先定义 ngx.shared.waf_lock_dict 共享内存字典

    local elapsed, err = l:lock("waf_traffic_stats_lock")
    if not elapsed then
        ngx.log(ngx.ERR, "failed to acquire lock: ", err)
        return
    end

    -- 原有代码开始
    local redis_key = "waf:waf_traffic_stats:" .. ngx.today()
    local new_data_str = getRequestTraffic()

    local redis_value, err = redis_cli.get(redis_key)
    local old_data = {}

    if redis_value then
        local ok, result = pcall(cjson.decode, redis_value)
        if ok and type(result) == "table" then
            for i = 2, #result do
                local row = result[i]
                old_data[row[1]] = { traffic = row[2], attack = row[3], blocked = row[4] }
            end
        else
            ngx.log(4, "waf_traffic_stats Redis 旧值解析失败: ", err)
        end
    end

    local ok, new_data = pcall(cjson.decode, new_data_str)
    if not ok or not new_data then
        ngx.log(4, "waf_traffic_stats 新值解析失败: ", new_data_str)
        l:unlock()
        return
    end

    local result = {}
    result[1] = { "hour", "traffic", "attack_traffic", "blocked_traffic" }

    for i = 2, #new_data do
        local row = new_data[i]
        local hour = row[1]
        local traffic = row[2]
        local attack = row[3]
        local blocked = row[4]

        local old = old_data[hour] or { traffic = 0, attack = 0, blocked = 0 }

        table.insert(result, {
            hour,
            old.traffic + traffic,
            old.attack + attack,
            old.blocked + blocked
        })
    end

    local merged_str = cjson.encode(result)
    local ok, err = redis_cli.set(redis_key, merged_str, 3600)
    if not ok then
        ngx.log(4, "写入 waf_traffic_stats Redis 失败: ", err)
        l:unlock()
        return
    end

    local dict = ngx.shared.dict_req_count
    local hours = time.get_hours()
    for _, hour in ipairs(hours) do
        dict:delete(hour)
        dict:delete(constants.KEY_ATTACK_PREFIX .. hour)
        dict:delete(constants.KEY_BLOCKED_PREFIX .. hour)
    end

    l:unlock()
end

function _M.write_waf_traffic_stats_redis_to_mysql()
    local redis_key = "waf:waf_traffic_stats:" .. ngx.today()
    local redis_value, err = redis_cli.get(redis_key)

    if not redis_value then
        ngx.log(4, "failed to get waf_traffic_stats from redis: ", err)
        return
    end

    local ok, data = pcall(cjson.decode, redis_value)
    if not ok or not data or #data <= 1 then
        ngx.log(4, "invalid waf_traffic_stats redis data: ", redis_value)
        return
    end

    for i = 2, #data do -- 跳过 header 行
        local row = data[i]
        local access_time = normalize_hour_to_datetime(row[1])
        local total_requests = tonumber(row[2]) or 0
        local attack_requests = tonumber(row[3]) or 0
        local blocked_requests = tonumber(row[4]) or 0

        -- 只写入有效时间且有数据的记录
        if access_time and (total_requests > 0 or attack_requests > 0 or blocked_requests > 0) then
            local sql = format(SQL_INSERT_WAF_TRAFFIC_STATS,
                quote_sql_str(access_time),
                total_requests,
                blocked_requests,
                attack_requests
            )

            local res, err = mysql.query(sql)
            if not res then
                ngx.log(4, "failed to insert waf_traffic_stats into mysql: ", err)
            end
        end
    end

    -- -- 删除 Redis 中的数据，避免重复
    -- local ok, err = redis_cli.del(redis_key)
    -- if not ok then
    --     ngx.log(4, "failed to delete waf_traffic_stats redis key: ", err)
    -- end
end

-- 获取每小时请求流量
function _M.get_request_traffic_by_hour()
    return mysql.query(SQL_GET_REQUEST_TRAFFIC_BY_HOUR)
end

function _M.write_sql_to_queue(key, sql)
    local dict_sql_queue = ngx.shared.dict_sql_queue
    dict_sql_queue:rpush(key, sql)
end

local function build_attack_log_sql_value(redis_value)
    local log_data, err = cjson.decode(redis_value)
    if not log_data then
        return nil, err
    end

    local request_id = log_data.request_id or ""
    local ip = log_data.ip or ""
    local ip_country_code = log_data.ip_country_code or ""
    local ip_country_cn = log_data.ip_country_cn or ""
    local ip_country_en = log_data.ip_country_en or ""
    local ip_province_code = log_data.ip_province_code or ""
    local ip_province_cn = log_data.ip_province_cn or ""
    local ip_province_en = log_data.ip_province_en or ""
    local ip_city_code = log_data.ip_city_code or ""
    local ip_city_cn = log_data.ip_city_cn or ""
    local ip_city_en = log_data.ip_city_en or ""
    local ip_longitude = tonumber(log_data.ip_longitude) or 0
    local ip_latitude = tonumber(log_data.ip_latitude) or 0
    local http_method = log_data.http_method or ""
    local server_name = log_data.server or ""
    local user_agent = log_data.user_agent or ""
    local referer = log_data.referer or ""
    local request_protocol = log_data.request_protocol or ""
    local request_uri = log_data.request_uri or ""
    local request_body = log_data.request_body or ""
    local http_status = tonumber(log_data.http_status) or 0
    local response_body = log_data.response_body or ""
    local request_time = log_data.attack_time or nil
    local attack_type = log_data.attack_type or ""
    local severity_level = log_data.severity_level or ""
    local security_module = log_data.securityModule or ""
    local hit_rule = log_data.hit_rule or ""
    local action = log_data.action or ""

    return format(
        '(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %.7f, %.7f, %s, %s, %s, %s, %s, %s, %s, %u, %s, %s, %s, %s, %s, %s, %s)',
        quote_sql_str(request_id), quote_sql_str(ip), quote_sql_str(ip_country_code), quote_sql_str(ip_country_cn),
        quote_sql_str(ip_country_en),
        quote_sql_str(ip_province_code), quote_sql_str(ip_province_cn), quote_sql_str(ip_province_en),
        quote_sql_str(ip_city_code), quote_sql_str(ip_city_cn), quote_sql_str(ip_city_en),
        ip_longitude, ip_latitude, quote_sql_str(http_method), quote_sql_str(server_name), quote_sql_str(user_agent),
        quote_sql_str(referer), quote_sql_str(request_protocol), quote_sql_str(request_uri),
        quote_sql_str(request_body), http_status, quote_sql_str(response_body), quote_sql_str(request_time),
        quote_sql_str(attack_type), quote_sql_str(severity_level), quote_sql_str(security_module),
        quote_sql_str(hit_rule), quote_sql_str(action))
end

function _M.write_attack_log_redis_to_mysql()
    local raw_values = redis_cli.batch_lpop(constants.KEY_REDIS_QUEUE_ATTACK_LOG, BATCH_SIZE)
    local sql_values = newtab(BATCH_SIZE, 0)
    local index = 1

    for _, value in ipairs(raw_values or {}) do
        local sql_value, err = build_attack_log_sql_value(value)
        if sql_value then
            sql_values[index] = sql_value
            index = index + 1
        else
            ngx.log(4, "failed to decode attack log queue json: ", err)
        end
    end

    if sql_values[1] then
        local sql_str = SQL_INSERT_ATTACK_LOG .. concat(sql_values, ',') .. " ON DUPLICATE KEY UPDATE update_time = NOW()"
        local res, err = mysql.query(sql_str)
        if not res then
            ngx.log(4, "failed to write attack log queue to mysql: ", err)
            redis_cli.bath_rpush(constants.KEY_REDIS_QUEUE_ATTACK_LOG, raw_values, get_system_config('redis').expire_time)
            return
        end
    end

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

local function get_hostname()
    local f = io.popen("hostname")
    if not f then return "unknown" end
    local h = f:read("*l")
    f:close()
    return h or "unknown"
end

function _M.report_node_info()
    local node_id = get_local_ip()
    local key = "waf:cluster:nodes:" .. node_id
    local cfg = get_system_config("system") or {}
    local expire = get_cluster_node_expire_seconds()

    local info = {
        ip = node_id,
        version = cfg.version or "unknown",
        hostname = get_hostname(),
        timestamp = tostring(os.time())
    }
    -- ngx.log(8, "node_id hmset node info: ", cjson.encode(info))

    local ok, err = redis_cli.hmset(key, info, expire)
    if not ok then
        ngx.log(ngx.ERR, "failed to hmset node info: ", err)
        return
    end
end

function _M.get_all_online_nodes()
    local keys = redis_cli.scan("waf:cluster:nodes:*")
    local node_list = {}

    for _, key in ipairs(keys or {}) do
        local data = redis_cli.hgetall(key)
        if data and type(data) == "table" then
            local node = {}
            for i = 1, #data, 2 do
                node[data[i]] = data[i + 1]
            end
            node.last_seen = os.date("%Y-%m-%d %H:%M:%S", tonumber(node.timestamp) or 0)
            table.insert(node_list, node)
        end
    end

    return node_list
end

function _M.write_cluster_nodes_to_mysql()
    local nodes = _M.get_all_online_nodes()

    for _, node in ipairs(nodes) do
        local sql = format(SQL_INSERT_CLUSTER_NODE,
            quote_sql_str(node.ip),
            quote_sql_str(node.version),
            quote_sql_str(node.hostname),
            quote_sql_str(node.last_seen)
        )
        local res, err = mysql.query(sql)
        if not res then
            ngx.log(ngx.ERR, "failed to insert node info: ", err)
        end
    end
end

function _M.cleanup_offline_cluster_nodes()
    local retention = get_cluster_node_retention_seconds()
    local sql = format(SQL_DELETE_STALE_CLUSTER_NODES, retention)
    local res = mysql.query(sql)
    if not res then
        ngx.log(ngx.ERR, "failed to cleanup stale cluster nodes, retention=", retention)
        return
    end

    local affected = res.affected_rows or 0
    if affected > 0 then
        ngx.log(ngx.INFO, "cleanup stale cluster nodes success, affected=", affected, ", retention=", retention)
    end
end

function _M.archive_attack_log_once(force)
    if not is_system_option_on("mysql") then
        return { code = 0, msg = "mysql is off, skip", skipped = true }
    end

    local enabled, days, batch = get_attack_log_retention_config()
    if not force and not enabled then
        return { code = 0, msg = "attackLogRetention is off, skip", skipped = true }
    end

    local create_res, create_err = mysql.query(SQL_CREATE_TABLE_ATTACK_LOG_ARCHIVE)
    if not create_res then
        ngx.log(ngx.ERR, "failed to ensure attack_log_archive table: ", create_err)
        return { code = 500, msg = "ensure archive table failed", error = create_err }
    end

    local insert_sql = format(SQL_INSERT_ATTACK_LOG_ARCHIVE, days, batch)
    local insert_res, insert_err = mysql.query(insert_sql)
    if not insert_res then
        ngx.log(ngx.ERR, "failed to archive attack_log to attack_log_archive: ", insert_err)
        return { code = 500, msg = "archive insert failed", error = insert_err }
    end

    local delete_sql = format(SQL_DELETE_ATTACK_LOG_ARCHIVE_SOURCE, days, batch)
    local delete_res, delete_err = mysql.query(delete_sql)
    if not delete_res then
        ngx.log(ngx.ERR, "failed to delete archived attack_log rows: ", delete_err)
        return { code = 500, msg = "archive delete failed", error = delete_err }
    end

    local inserted = insert_res.affected_rows or 0
    local deleted = delete_res.affected_rows or 0
    if inserted > 0 or deleted > 0 then
        ngx.log(ngx.INFO, "attack_log retention run success, days=", days, ", batch=", batch,
            ", inserted=", inserted, ", deleted=", deleted)
    end

    return {
        code = 0,
        msg = "ok",
        inserted = inserted,
        deleted = deleted,
        days = days,
        batch = batch
    }
end

function _M.archive_attack_log_auto()
    local enabled, _, _, interval = get_attack_log_retention_config()
    if not enabled then
        return
    end

    local dict = ngx.shared.dict_config
    if not dict then
        _M.archive_attack_log_once(false)
        return
    end

    local now = ngx.time()
    local last_run = tonumber(dict:get(ATTACK_LOG_RETENTION_LAST_RUN_KEY)) or 0
    if now - last_run < interval then
        return
    end

    dict:set(ATTACK_LOG_RETENTION_LAST_RUN_KEY, now)
    _M.archive_attack_log_once(false)
end

-- 在适当的地方调用 write_sql_redis_to_mysql 函数，例如定时任务
-- ngx.timer.at(delay, write_sql_redis_to_mysql)

return _M

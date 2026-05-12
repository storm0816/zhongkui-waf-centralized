-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local mysql = require "mysql_cli"
local config = require "config"
local utils = require "utils"
local constants = require "constants"
local cjson = require "cjson.safe"
local time = require "time"
local file_utils = require "file_utils"

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
local md5 = ngx.md5
local read_file_to_string = file_utils.read_file_to_string
local write_string_to_file = file_utils.write_string_to_file

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
local CLUSTER_RULES_VERSION_DICT_KEY = "cluster:rules:snapshot:version"
local CLUSTER_WHITELIST_VERSION_DICT_KEY = "cluster:ip_whitelist:version"
local CLUSTER_BLACKLIST_VERSION_DICT_KEY = "cluster:master:blacklist:version"
local CLUSTER_RULES_SYNC_STATUS_DICT_KEY = "cluster:sync:rules:status"
local CLUSTER_RULES_SYNC_AT_DICT_KEY = "cluster:sync:rules:at"
local CLUSTER_WHITELIST_SYNC_STATUS_DICT_KEY = "cluster:sync:whitelist:status"
local CLUSTER_WHITELIST_SYNC_AT_DICT_KEY = "cluster:sync:whitelist:at"
local CLUSTER_BLACKLIST_SYNC_STATUS_DICT_KEY = "cluster:sync:blacklist:status"
local CLUSTER_BLACKLIST_SYNC_AT_DICT_KEY = "cluster:sync:blacklist:at"
local CLUSTER_LAST_SYNC_STATUS_DICT_KEY = "cluster:sync:last:status"
local CLUSTER_LAST_SYNC_AT_DICT_KEY = "cluster:sync:last:at"
local DEFAULT_RULE_CANDIDATE_LOOKBACK_HOURS = 24
local DEFAULT_RULE_CANDIDATE_MIN_HITS = 20
local DEFAULT_RULE_CANDIDATE_LIMIT = 200
local MAX_RULE_CANDIDATE_LIMIT = 500
local RULE_CANDIDATE_SOURCE_ATTACK_LOG = "attack_log_agg"
local RULE_CANDIDATE_RUN_STATUS_SUCCESS = "success"
local RULE_CANDIDATE_RUN_STATUS_FAILED = "failed"
local RULE_CANDIDATE_PUBLISH_STATUS_PENDING = "pending"
local RULE_CANDIDATE_PUBLISH_STATUS_PUBLISHED = "published"
local RULE_CANDIDATE_PUBLISH_STATUS_FAILED = "failed"
local INTEL_SOURCES_PATH = config.CONF_PATH .. "/intel_sources.json"
local CACHED_NODE_ID

local SQL_CHECK_TABLE =
[[SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='%s' AND table_name='%s']]

local SQL_CHECK_INDEX = [[
    SELECT COUNT(*) AS c
    FROM INFORMATION_SCHEMA.STATISTICS
    WHERE table_schema = %s AND table_name = %s AND index_name = %s
]]

local SQL_CHECK_COLUMN = [[
    SELECT COUNT(*) AS c
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE table_schema = %s AND table_name = %s AND column_name = %s
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

local SQL_INSERT_WAF_STATUS_INCREMENT = [[
    INSERT INTO waf_status (
        request_date, http4xx, http5xx, request_times, attack_times, block_times,
        block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times,
        update_time
    ) VALUES (
        %s, %d, %d, %d, %d, %d, %d, %d, %d, %d, NOW()
    )
    ON DUPLICATE KEY UPDATE
        http4xx = http4xx + VALUES(http4xx),
        http5xx = http5xx + VALUES(http5xx),
        request_times = request_times + VALUES(request_times),
        attack_times = attack_times + VALUES(attack_times),
        block_times = block_times + VALUES(block_times),
        block_times_attack = block_times_attack + VALUES(block_times_attack),
        block_times_captcha = block_times_captcha + VALUES(block_times_captcha),
        block_times_cc = block_times_cc + VALUES(block_times_cc),
        captcha_pass_times = captcha_pass_times + VALUES(captcha_pass_times),
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
        `node_ip` varchar(39) NULL COMMENT '节点IP',
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
        request_id, ip, node_ip, ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en,
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

local function get_intel_sources_config()
    local defaults = {
        attack_log_agg = {
            state = "on",
            lookback_hours = DEFAULT_RULE_CANDIDATE_LOOKBACK_HOURS,
            min_hits = DEFAULT_RULE_CANDIDATE_MIN_HITS,
            limit = DEFAULT_RULE_CANDIDATE_LIMIT
        }
    }

    local content = read_file_to_string(INTEL_SOURCES_PATH)
    if not content or content == "" then
        return defaults
    end

    local parsed = cjson.decode(content)
    if type(parsed) ~= "table" then
        return defaults
    end

    if type(parsed.attack_log_agg) ~= "table" then
        parsed.attack_log_agg = {}
    end

    local merged = {
        attack_log_agg = {
            state = tostring(parsed.attack_log_agg.state or defaults.attack_log_agg.state),
            lookback_hours = tonumber(parsed.attack_log_agg.lookback_hours) or defaults.attack_log_agg.lookback_hours,
            min_hits = tonumber(parsed.attack_log_agg.min_hits) or defaults.attack_log_agg.min_hits,
            limit = tonumber(parsed.attack_log_agg.limit) or defaults.attack_log_agg.limit
        }
    }

    if merged.attack_log_agg.lookback_hours < 1 then
        merged.attack_log_agg.lookback_hours = defaults.attack_log_agg.lookback_hours
    end
    if merged.attack_log_agg.min_hits < 1 then
        merged.attack_log_agg.min_hits = defaults.attack_log_agg.min_hits
    end
    if merged.attack_log_agg.limit < 1 then
        merged.attack_log_agg.limit = defaults.attack_log_agg.limit
    elseif merged.attack_log_agg.limit > MAX_RULE_CANDIDATE_LIMIT then
        merged.attack_log_agg.limit = MAX_RULE_CANDIDATE_LIMIT
    end

    return merged
end

local function build_rule_candidate_key(source, rule_type, rule_content)
    return md5((source or "") .. "|" .. (rule_type or "") .. "|" .. (rule_content or ""))
end

local function calc_risk_score(hit_count, attack_type)
    local score = floor((tonumber(hit_count) or 0) * 2)
    if score > 100 then
        score = 100
    end
    if score < 1 then
        score = 1
    end

    local attack = string.lower(tostring(attack_type or ""))
    if string.find(attack, "sql", 1, true) or string.find(attack, "rce", 1, true) then
        score = score + 10
    elseif string.find(attack, "xss", 1, true) then
        score = score + 5
    end

    if score > 100 then
        score = 100
    end
    return score
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
        rules_version VARCHAR(32) COMMENT '规则版本',
        whitelist_version VARCHAR(32) COMMENT '白名单版本',
        blacklist_version VARCHAR(32) COMMENT '黑名单版本',
        rules_sync_status VARCHAR(32) COMMENT '规则同步结果',
        rules_sync_at DATETIME NULL COMMENT '规则同步时间',
        whitelist_sync_status VARCHAR(32) COMMENT '白名单同步结果',
        whitelist_sync_at DATETIME NULL COMMENT '白名单同步时间',
        blacklist_sync_status VARCHAR(32) COMMENT '黑名单同步结果',
        blacklist_sync_at DATETIME NULL COMMENT '黑名单同步时间',
        last_sync_status VARCHAR(32) COMMENT '最近同步结果',
        last_sync_at DATETIME NULL COMMENT '最近同步时间',
        hostname VARCHAR(128) COMMENT '节点主机名',
        last_seen DATETIME COMMENT '最近活跃时间',
        create_time DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
        UNIQUE KEY uniq_ip (ip),
        INDEX idx_last_seen (last_seen)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
]]


local SQL_INSERT_CLUSTER_NODE = [[
    INSERT INTO waf_cluster_node (
        ip, rules_version, whitelist_version, blacklist_version,
        rules_sync_status, rules_sync_at,
        whitelist_sync_status, whitelist_sync_at,
        blacklist_sync_status, blacklist_sync_at,
        last_sync_status, last_sync_at, hostname, last_seen
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        rules_version = VALUES(rules_version),
        whitelist_version = VALUES(whitelist_version),
        blacklist_version = VALUES(blacklist_version),
        rules_sync_status = VALUES(rules_sync_status),
        rules_sync_at = VALUES(rules_sync_at),
        whitelist_sync_status = VALUES(whitelist_sync_status),
        whitelist_sync_at = VALUES(whitelist_sync_at),
        blacklist_sync_status = VALUES(blacklist_sync_status),
        blacklist_sync_at = VALUES(blacklist_sync_at),
        last_sync_status = VALUES(last_sync_status),
        last_sync_at = VALUES(last_sync_at),
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

local SQL_CREATE_TABLE_RULE_CANDIDATE = [[
    CREATE TABLE waf_rule_candidate (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        candidate_key VARCHAR(64) NOT NULL COMMENT '候选规则唯一标识',
        source VARCHAR(64) NOT NULL COMMENT '候选来源',
        rule_type VARCHAR(64) NOT NULL COMMENT '规则类型',
        rule_target VARCHAR(64) NULL COMMENT '规则目标',
        rule_content VARCHAR(1024) NOT NULL COMMENT '规则内容',
        risk_score INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '风险分',
        hit_count INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '命中次数',
        sample_node_ip VARCHAR(39) NULL COMMENT '样本节点IP',
        sample_attack_type VARCHAR(255) NULL COMMENT '样本攻击类型',
        sample_uri VARCHAR(1024) NULL COMMENT '样本URI',
        first_seen DATETIME NULL COMMENT '首次发现时间',
        last_seen DATETIME NULL COMMENT '最近发现时间',
        status VARCHAR(16) NOT NULL DEFAULT 'pending' COMMENT '候选状态',
        review_note VARCHAR(255) NULL COMMENT '审核备注',
        review_by VARCHAR(64) NULL COMMENT '审核人',
        review_time DATETIME NULL COMMENT '审核时间',
        publish_status VARCHAR(16) NOT NULL DEFAULT 'pending' COMMENT '发布状态',
        publish_module VARCHAR(64) NULL COMMENT '发布目标模块',
        published_rule_id INT NULL COMMENT '发布后的规则ID',
        published_time DATETIME NULL COMMENT '发布时间',
        publish_note VARCHAR(255) NULL COMMENT '发布备注',
        update_time DATETIME NULL,
        create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uniq_candidate_key (candidate_key),
        INDEX idx_rule_candidate_status_last_seen (status, last_seen),
        INDEX idx_rule_candidate_source_last_seen (source, last_seen)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
]]

local SQL_CREATE_TABLE_RULE_CANDIDATE_RUN = [[
    CREATE TABLE waf_rule_candidate_run (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        run_date CHAR(10) NOT NULL COMMENT '运行日期',
        source VARCHAR(64) NOT NULL COMMENT '候选来源',
        status VARCHAR(16) NOT NULL COMMENT '运行状态',
        generated_count INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '本次产出数量',
        message VARCHAR(255) NULL COMMENT '运行信息',
        update_time DATETIME NULL,
        create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uniq_run_date_source (run_date, source),
        INDEX idx_run_date_status (run_date, status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
]]

local SQL_SELECT_RULE_CANDIDATE_FROM_ATTACK_LOG = [[
    SELECT
        request_uri,
        attack_type,
        COUNT(*) AS hit_count,
        MIN(request_time) AS first_seen,
        MAX(request_time) AS last_seen,
        MAX(node_ip) AS sample_node_ip
    FROM attack_log
    WHERE request_time >= NOW() - INTERVAL %d HOUR
      AND request_uri IS NOT NULL
      AND request_uri <> ''
    GROUP BY request_uri, attack_type
    HAVING COUNT(*) >= %d
    ORDER BY hit_count DESC
    LIMIT %d
]]

local SQL_UPSERT_RULE_CANDIDATE = [[
    INSERT INTO waf_rule_candidate
        (candidate_key, source, rule_type, rule_target, rule_content, risk_score, hit_count, sample_node_ip,
         sample_attack_type, sample_uri, first_seen, last_seen, status, update_time)
    VALUES
        (%s, %s, %s, %s, %s, %d, %d, %s, %s, %s, %s, %s, 'pending', NOW())
    ON DUPLICATE KEY UPDATE
        risk_score = GREATEST(risk_score, VALUES(risk_score)),
        hit_count = GREATEST(hit_count, VALUES(hit_count)),
        sample_node_ip = VALUES(sample_node_ip),
        sample_attack_type = VALUES(sample_attack_type),
        sample_uri = VALUES(sample_uri),
        first_seen = LEAST(first_seen, VALUES(first_seen)),
        last_seen = GREATEST(last_seen, VALUES(last_seen)),
        update_time = NOW()
]]

local SQL_COUNT_RULE_CANDIDATE = [[
    SELECT COUNT(*) AS total FROM waf_rule_candidate
]]

local SQL_SELECT_RULE_CANDIDATE = [[
    SELECT id, candidate_key, source, rule_type, rule_target, rule_content, risk_score, hit_count, sample_node_ip,
           sample_attack_type, sample_uri, first_seen, last_seen, status, review_note, review_by, review_time,
           publish_status, publish_module, published_rule_id, published_time, publish_note,
           create_time, update_time
    FROM waf_rule_candidate
]]

local SQL_SELECT_RULE_CANDIDATE_BY_ID = [[
    SELECT id, source, rule_type, rule_target, rule_content, risk_score, hit_count, sample_node_ip, sample_attack_type,
           sample_uri, status, publish_status
    FROM waf_rule_candidate
    WHERE id = %u
]]

local SQL_UPDATE_RULE_CANDIDATE_REVIEW = [[
    UPDATE waf_rule_candidate
    SET status = %s,
        review_note = %s,
        review_by = %s,
        review_time = NOW(),
        update_time = NOW()
    WHERE id = %u
]]

local SQL_UPDATE_RULE_CANDIDATE_PUBLISH = [[
    UPDATE waf_rule_candidate
    SET publish_status = %s,
        publish_module = %s,
        published_rule_id = %s,
        published_time = NOW(),
        publish_note = %s,
        update_time = NOW()
    WHERE id = %u
]]

local SQL_COUNT_RULE_CANDIDATE_SUCCESS_RUN = [[
    SELECT COUNT(*) AS total
    FROM waf_rule_candidate_run
    WHERE run_date = %s
      AND source = %s
      AND status = %s
]]

local SQL_UPSERT_RULE_CANDIDATE_RUN = [[
    INSERT INTO waf_rule_candidate_run
        (run_date, source, status, generated_count, message, update_time)
    VALUES
        (%s, %s, %s, %d, %s, NOW())
    ON DUPLICATE KEY UPDATE
        status = VALUES(status),
        generated_count = VALUES(generated_count),
        message = VALUES(message),
        update_time = NOW()
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

local function is_rule_candidate_success_today(source)
    local sql = format(
        SQL_COUNT_RULE_CANDIDATE_SUCCESS_RUN,
        quote_sql_str(ngx.today()),
        quote_sql_str(source),
        quote_sql_str(RULE_CANDIDATE_RUN_STATUS_SUCCESS)
    )
    local res, err = mysql.query(sql)
    if not res or not res[1] then
        return false, err
    end

    return (tonumber(res[1].total) or 0) > 0, nil
end

local function upsert_rule_candidate_run(source, status, generated_count, message)
    local sql = format(
        SQL_UPSERT_RULE_CANDIDATE_RUN,
        quote_sql_str(ngx.today()),
        quote_sql_str(source),
        quote_sql_str(status),
        tonumber(generated_count) or 0,
        quote_sql_str(message or "")
    )
    return mysql.query(sql)
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
        { name = 'waf_rule_candidate',  sql = SQL_CREATE_TABLE_RULE_CANDIDATE },
        { name = 'waf_rule_candidate_run', sql = SQL_CREATE_TABLE_RULE_CANDIDATE_RUN },
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

    local function ensure_column(table_name, column_name, ddl, backfill_ddl)
        local col_res, col_err = mysql.query(format(SQL_CHECK_COLUMN,
            quote_sql_str(database), quote_sql_str(table_name), quote_sql_str(column_name)))
        if col_res and col_res[1] and col_res[1].c == '0' then
            local ok = mysql.query(ddl)
            if not ok then
                ngx.log(ngx.ERR, "failed to add column ", column_name, " on ", table_name)
                return
            end

            if backfill_ddl then
                local backfill_ok, backfill_err = mysql.query(backfill_ddl)
                if not backfill_ok then
                    ngx.log(ngx.ERR, "failed to backfill column ", column_name, " on ", table_name, ": ", backfill_err)
                end
            end
        elseif not col_res then
            ngx.log(ngx.ERR, "failed to check column ", column_name, " on ", table_name, ": ", col_err)
        end
    end

    -- 兼容老版本表结构：attack_log 可能没有 request_id 唯一索引，这里补齐一次。
    ensure_index("attack_log", "idx_unique_attack_log_request_id",
        "ALTER TABLE attack_log ADD UNIQUE INDEX idx_unique_attack_log_request_id (request_id)")
    -- 兼容老版本表结构：attack_log 可能没有 node_ip 列，这里补齐一次。
    ensure_column("attack_log", "node_ip",
        "ALTER TABLE attack_log ADD COLUMN node_ip VARCHAR(39) NULL COMMENT '节点IP' AFTER ip")
    ensure_column("attack_log_archive", "node_ip",
        "ALTER TABLE attack_log_archive ADD COLUMN node_ip VARCHAR(39) NULL COMMENT '节点IP' AFTER ip")

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
    ensure_index("attack_log", "idx_attack_log_node_time",
        "ALTER TABLE attack_log ADD INDEX idx_attack_log_node_time (node_ip, request_time)")
    ensure_index("attack_log_archive", "idx_attack_log_archive_node_time",
        "ALTER TABLE attack_log_archive ADD INDEX idx_attack_log_archive_node_time (node_ip, request_time)")
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
    -- 兼容老版本表结构：waf_cluster_node 可能没有 rules_version 列，这里补齐并从 version 回填一次。
    ensure_column("waf_cluster_node", "rules_version",
        "ALTER TABLE waf_cluster_node ADD COLUMN rules_version VARCHAR(32) NULL COMMENT '规则版本' AFTER ip",
        "UPDATE waf_cluster_node SET rules_version = version WHERE (rules_version IS NULL OR rules_version = '') AND version IS NOT NULL")
    ensure_column("waf_cluster_node", "whitelist_version",
        "ALTER TABLE waf_cluster_node ADD COLUMN whitelist_version VARCHAR(32) NULL COMMENT '白名单版本' AFTER rules_version")
    ensure_column("waf_cluster_node", "blacklist_version",
        "ALTER TABLE waf_cluster_node ADD COLUMN blacklist_version VARCHAR(32) NULL COMMENT '黑名单版本' AFTER whitelist_version")
    ensure_column("waf_cluster_node", "rules_sync_status",
        "ALTER TABLE waf_cluster_node ADD COLUMN rules_sync_status VARCHAR(32) NULL COMMENT '规则同步结果' AFTER blacklist_version")
    ensure_column("waf_cluster_node", "rules_sync_at",
        "ALTER TABLE waf_cluster_node ADD COLUMN rules_sync_at DATETIME NULL COMMENT '规则同步时间' AFTER rules_sync_status")
    ensure_column("waf_cluster_node", "whitelist_sync_status",
        "ALTER TABLE waf_cluster_node ADD COLUMN whitelist_sync_status VARCHAR(32) NULL COMMENT '白名单同步结果' AFTER rules_sync_at")
    ensure_column("waf_cluster_node", "whitelist_sync_at",
        "ALTER TABLE waf_cluster_node ADD COLUMN whitelist_sync_at DATETIME NULL COMMENT '白名单同步时间' AFTER whitelist_sync_status")
    ensure_column("waf_cluster_node", "blacklist_sync_status",
        "ALTER TABLE waf_cluster_node ADD COLUMN blacklist_sync_status VARCHAR(32) NULL COMMENT '黑名单同步结果' AFTER whitelist_sync_at")
    ensure_column("waf_cluster_node", "blacklist_sync_at",
        "ALTER TABLE waf_cluster_node ADD COLUMN blacklist_sync_at DATETIME NULL COMMENT '黑名单同步时间' AFTER blacklist_sync_status")
    ensure_column("waf_cluster_node", "last_sync_status",
        "ALTER TABLE waf_cluster_node ADD COLUMN last_sync_status VARCHAR(32) NULL COMMENT '最近同步结果' AFTER blacklist_sync_at")
    ensure_column("waf_cluster_node", "last_sync_at",
        "ALTER TABLE waf_cluster_node ADD COLUMN last_sync_at DATETIME NULL COMMENT '最近同步时间' AFTER last_sync_status")
    ensure_column("waf_rule_candidate", "publish_status",
        "ALTER TABLE waf_rule_candidate ADD COLUMN publish_status VARCHAR(16) NOT NULL DEFAULT 'pending' COMMENT '发布状态' AFTER review_time")
    ensure_column("waf_rule_candidate", "publish_module",
        "ALTER TABLE waf_rule_candidate ADD COLUMN publish_module VARCHAR(64) NULL COMMENT '发布目标模块' AFTER publish_status")
    ensure_column("waf_rule_candidate", "published_rule_id",
        "ALTER TABLE waf_rule_candidate ADD COLUMN published_rule_id INT NULL COMMENT '发布后的规则ID' AFTER publish_module")
    ensure_column("waf_rule_candidate", "published_time",
        "ALTER TABLE waf_rule_candidate ADD COLUMN published_time DATETIME NULL COMMENT '发布时间' AFTER published_rule_id")
    ensure_column("waf_rule_candidate", "publish_note",
        "ALTER TABLE waf_rule_candidate ADD COLUMN publish_note VARCHAR(255) NULL COMMENT '发布备注' AFTER published_time")
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
            quote_sql_str(ngx.today()),
            http4xx, http5xx, request_times, attack_times, block_times,
            block_times_attack, block_times_captcha, block_times_cc,
            captcha_pass_times
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
    local sync_key = "waf:waf_status_synced_hmap:" .. today

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

    local fields = {
        "http4xx",
        "http5xx",
        "request_times",
        "attack_times",
        "block_times",
        "block_times_attack",
        "block_times_captcha",
        "block_times_cc",
        "captcha_pass_times"
    }

    local current = {}
    local has_current = false
    for _, field in ipairs(fields) do
        local v = tonumber(data[field]) or 0
        current[field] = v
        if v > 0 then
            has_current = true
        end
    end

    if not has_current then
        return
    end

    -- 增量同步：每次只写入比上次同步新增的部分，避免重复覆盖导致统计回退。
    local synced_hash_data = redis_cli.hgetall(sync_key) or {}
    local synced = {}
    for i = 1, #synced_hash_data, 2 do
        local k = tostring(synced_hash_data[i])
        synced[k] = tonumber(synced_hash_data[i + 1]) or 0
    end

    local delta = {}
    local has_delta = false
    for _, field in ipairs(fields) do
        local cur = current[field] or 0
        local old = synced[field] or 0
        local d

        if cur >= old then
            d = cur - old
        else
            -- Redis key 过期/重建后会从小值重新增长，这里按“新快照增量”继续累加。
            d = cur
        end

        delta[field] = d
        if d > 0 then
            has_delta = true
        end
    end

    if not has_delta then
        return
    end

    local sql = string.format(SQL_INSERT_WAF_STATUS_INCREMENT,
        quote_sql_str(today),
        delta.http4xx, delta.http5xx, delta.request_times, delta.attack_times, delta.block_times,
        delta.block_times_attack, delta.block_times_captcha, delta.block_times_cc, delta.captcha_pass_times)

    local res, err = mysql.query(sql)
    if not res then
        ngx.log(ngx.ERR, "failed to write waf_status from redis to mysql: ", err)
        return
    end

    local redis_expire = get_system_config("redis").expire_time or 1800
    local sync_expire = redis_expire * 2
    if sync_expire < 86400 then
        sync_expire = 86400
    end
    local ok, sync_err = redis_cli.hmset(sync_key, current, sync_expire)
    if not ok then
        ngx.log(ngx.ERR, "failed to update waf_status sync snapshot key: ", sync_key, " err: ", sync_err)
        return
    end
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
    local node_ip = log_data.node_ip or ""
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
        '(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %.7f, %.7f, %s, %s, %s, %s, %s, %s, %s, %u, %s, %s, %s, %s, %s, %s, %s)',
        quote_sql_str(request_id), quote_sql_str(ip), quote_sql_str(node_ip), quote_sql_str(ip_country_code), quote_sql_str(ip_country_cn),
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

local function detect_local_ip()
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

function _M.get_node_id()
    if CACHED_NODE_ID and CACHED_NODE_ID ~= "" then
        return CACHED_NODE_ID
    end

    local env_ip = os.getenv("ZHONGKUI_NODE_IP") or os.getenv("NODE_IP")
    if env_ip and env_ip ~= "" then
        CACHED_NODE_ID = tostring(env_ip)
        return CACHED_NODE_ID
    end

    CACHED_NODE_ID = detect_local_ip()
    return CACHED_NODE_ID
end

local function get_hostname()
    local f = io.popen("hostname")
    if not f then return "unknown" end
    local h = f:read("*l")
    f:close()
    return h or "unknown"
end

function _M.report_node_info()
    local node_id = _M.get_node_id()
    local key = "waf:cluster:nodes:" .. node_id
    local expire = get_cluster_node_expire_seconds()
    local dict_config = ngx.shared.dict_config
    local rules_version = "unknown"
    local whitelist_version = "unknown"
    local blacklist_version = "unknown"
    local rules_sync_status = "unknown"
    local rules_sync_at = ngx.localtime()
    local whitelist_sync_status = "unknown"
    local whitelist_sync_at = ngx.localtime()
    local blacklist_sync_status = "unknown"
    local blacklist_sync_at = ngx.localtime()
    local last_sync_status = "unknown"
    local last_sync_at = ngx.localtime()
    if dict_config then
        local v = dict_config:get(CLUSTER_RULES_VERSION_DICT_KEY)
        if v then
            rules_version = tostring(v)
        end
        v = dict_config:get(CLUSTER_WHITELIST_VERSION_DICT_KEY)
        if v then
            whitelist_version = tostring(v)
        end
        v = dict_config:get(CLUSTER_BLACKLIST_VERSION_DICT_KEY)
        if v then
            blacklist_version = tostring(v)
        end
        v = dict_config:get(CLUSTER_RULES_SYNC_STATUS_DICT_KEY)
        if v then
            rules_sync_status = tostring(v)
        end
        v = dict_config:get(CLUSTER_RULES_SYNC_AT_DICT_KEY)
        if v then
            rules_sync_at = tostring(v)
        end
        v = dict_config:get(CLUSTER_WHITELIST_SYNC_STATUS_DICT_KEY)
        if v then
            whitelist_sync_status = tostring(v)
        end
        v = dict_config:get(CLUSTER_WHITELIST_SYNC_AT_DICT_KEY)
        if v then
            whitelist_sync_at = tostring(v)
        end
        v = dict_config:get(CLUSTER_BLACKLIST_SYNC_STATUS_DICT_KEY)
        if v then
            blacklist_sync_status = tostring(v)
        end
        v = dict_config:get(CLUSTER_BLACKLIST_SYNC_AT_DICT_KEY)
        if v then
            blacklist_sync_at = tostring(v)
        end
        v = dict_config:get(CLUSTER_LAST_SYNC_STATUS_DICT_KEY)
        if v then
            last_sync_status = tostring(v)
        end
        v = dict_config:get(CLUSTER_LAST_SYNC_AT_DICT_KEY)
        if v then
            last_sync_at = tostring(v)
        end
    end

    local info = {
        ip = node_id,
        rules_version = rules_version,
        whitelist_version = whitelist_version,
        blacklist_version = blacklist_version,
        rules_sync_status = rules_sync_status,
        rules_sync_at = rules_sync_at,
        whitelist_sync_status = whitelist_sync_status,
        whitelist_sync_at = whitelist_sync_at,
        blacklist_sync_status = blacklist_sync_status,
        blacklist_sync_at = blacklist_sync_at,
        last_sync_status = last_sync_status,
        last_sync_at = last_sync_at,
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
        local rules_version = node.rules_version or node.version or "unknown"
        local sql = format(SQL_INSERT_CLUSTER_NODE,
            quote_sql_str(node.ip),
            quote_sql_str(rules_version),
            quote_sql_str(node.whitelist_version or "unknown"),
            quote_sql_str(node.blacklist_version or "unknown"),
            quote_sql_str(node.rules_sync_status or "unknown"),
            quote_sql_str(node.rules_sync_at or node.last_seen),
            quote_sql_str(node.whitelist_sync_status or "unknown"),
            quote_sql_str(node.whitelist_sync_at or node.last_seen),
            quote_sql_str(node.blacklist_sync_status or "unknown"),
            quote_sql_str(node.blacklist_sync_at or node.last_seen),
            quote_sql_str(node.last_sync_status or "unknown"),
            quote_sql_str(node.last_sync_at or node.last_seen),
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

function _M.generate_rule_candidates_from_attack_log()
    local intel_conf = get_intel_sources_config()
    local source_conf = intel_conf.attack_log_agg or {}
    if tostring(source_conf.state or "on") ~= "on" then
        return { code = 0, skipped = true, msg = "attack_log_agg is off", generated = 0 }
    end

    local lookback_hours = floor(tonumber(source_conf.lookback_hours) or DEFAULT_RULE_CANDIDATE_LOOKBACK_HOURS)
    if lookback_hours < 1 then
        lookback_hours = DEFAULT_RULE_CANDIDATE_LOOKBACK_HOURS
    end

    local min_hits = floor(tonumber(source_conf.min_hits) or DEFAULT_RULE_CANDIDATE_MIN_HITS)
    if min_hits < 1 then
        min_hits = DEFAULT_RULE_CANDIDATE_MIN_HITS
    end

    local candidate_limit = floor(tonumber(source_conf.limit) or DEFAULT_RULE_CANDIDATE_LIMIT)
    if candidate_limit < 1 then
        candidate_limit = DEFAULT_RULE_CANDIDATE_LIMIT
    elseif candidate_limit > MAX_RULE_CANDIDATE_LIMIT then
        candidate_limit = MAX_RULE_CANDIDATE_LIMIT
    end

    local query_sql = format(SQL_SELECT_RULE_CANDIDATE_FROM_ATTACK_LOG, lookback_hours, min_hits, candidate_limit)
    local rows, err = mysql.query(query_sql)
    if not rows then
        return { code = 500, msg = "query attack_log failed", error = err, generated = 0 }
    end

    local generated = 0
    for _, row in ipairs(rows) do
        local request_uri = tostring(row.request_uri or "")
        if request_uri ~= "" then
            local attack_type = tostring(row.attack_type or "unknown")
            local hit_count = tonumber(row.hit_count) or 0
            local first_seen = row.first_seen or ngx.localtime()
            local last_seen = row.last_seen or ngx.localtime()
            local sample_node_ip = row.sample_node_ip or ""
            local rule_type = "uri_exact"
            local rule_target = "request_uri"
            local candidate_key = build_rule_candidate_key(RULE_CANDIDATE_SOURCE_ATTACK_LOG, rule_type, request_uri)
            local risk_score = calc_risk_score(hit_count, attack_type)

            local upsert_sql = format(
                SQL_UPSERT_RULE_CANDIDATE,
                quote_sql_str(candidate_key),
                quote_sql_str(RULE_CANDIDATE_SOURCE_ATTACK_LOG),
                quote_sql_str(rule_type),
                quote_sql_str(rule_target),
                quote_sql_str(request_uri),
                risk_score,
                hit_count,
                quote_sql_str(sample_node_ip),
                quote_sql_str(attack_type),
                quote_sql_str(request_uri),
                quote_sql_str(first_seen),
                quote_sql_str(last_seen)
            )

            local ok, upsert_err = mysql.query(upsert_sql)
            if ok then
                generated = generated + 1
            else
                ngx.log(ngx.ERR, "failed to upsert rule candidate, uri=", request_uri, " err=", upsert_err)
            end
        end
    end

    return {
        code = 0,
        msg = "ok",
        generated = generated,
        lookback_hours = lookback_hours,
        min_hits = min_hits,
        limit = candidate_limit
    }
end

function _M.generate_rule_candidates_daily_auto()
    if not is_system_option_on("mysql") then
        return
    end

    local source = RULE_CANDIDATE_SOURCE_ATTACK_LOG
    local success_today, err = is_rule_candidate_success_today(source)
    if err then
        ngx.log(ngx.ERR, "failed to check rule candidate run state: ", err)
        return
    end
    if success_today then
        return
    end

    local result = _M.generate_rule_candidates_from_attack_log()
    local status = RULE_CANDIDATE_RUN_STATUS_SUCCESS
    local message = "ok"
    local generated = 0
    if result and result.code == 0 then
        generated = result.generated or 0
    else
        status = RULE_CANDIDATE_RUN_STATUS_FAILED
        message = (result and (result.msg or result.error)) or "unknown error"
    end

    local ok, run_err = upsert_rule_candidate_run(source, status, generated, message)
    if not ok then
        ngx.log(ngx.ERR, "failed to update rule candidate run table: ", run_err)
    end
end

function _M.run_rule_candidates_once()
    local source = RULE_CANDIDATE_SOURCE_ATTACK_LOG
    local result = _M.generate_rule_candidates_from_attack_log()

    local status = RULE_CANDIDATE_RUN_STATUS_SUCCESS
    local message = "manual run success"
    local generated = 0
    if result and result.code == 0 then
        generated = result.generated or 0
    else
        status = RULE_CANDIDATE_RUN_STATUS_FAILED
        message = (result and (result.msg or result.error)) or "unknown error"
    end

    local ok, err = upsert_rule_candidate_run(source, status, generated, message)
    if not ok then
        ngx.log(ngx.ERR, "failed to write manual rule candidate run result: ", err)
    end

    return result
end

function _M.list_rule_candidates(page, limit, filters)
    page = tonumber(page) or 1
    limit = tonumber(limit) or 10
    if page < 1 then
        page = 1
    end
    if limit < 1 then
        limit = 10
    elseif limit > 200 then
        limit = 200
    end
    local offset = (page - 1) * limit

    local where = " WHERE 1=1 "
    filters = filters or {}

    local status = filters.status
    if status and status ~= "" then
        where = where .. " AND status = " .. quote_sql_str(status)
    end

    local source = filters.source
    if source and source ~= "" then
        where = where .. " AND source = " .. quote_sql_str(source)
    end

    local publish_status = filters.publish_status
    if publish_status and publish_status ~= "" then
        where = where .. " AND publish_status = " .. quote_sql_str(publish_status)
    end

    local keyword = filters.keyword
    if keyword and keyword ~= "" then
        local kw = "%" .. tostring(keyword) .. "%"
        where = where .. " AND (rule_content LIKE " .. quote_sql_str(kw)
            .. " OR sample_uri LIKE " .. quote_sql_str(kw)
            .. " OR sample_attack_type LIKE " .. quote_sql_str(kw) .. ")"
    end

    local count_sql = SQL_COUNT_RULE_CANDIDATE .. where
    local count_res, count_err = mysql.query(count_sql)
    if not count_res or not count_res[1] then
        return nil, 0, count_err or "count failed"
    end

    local total = tonumber(count_res[1].total) or 0
    local rows = {}
    if total > 0 then
        local list_sql = SQL_SELECT_RULE_CANDIDATE .. where
            .. " ORDER BY (CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END), risk_score DESC, last_seen DESC, id DESC"
            .. format(" LIMIT %d,%d", offset, limit)
        rows, count_err = mysql.query(list_sql)
        if not rows then
            return nil, total, count_err or "query failed"
        end
    end

    return rows, total, nil
end

function _M.review_rule_candidate(id, status, note, reviewer)
    local rid = tonumber(id)
    if not rid then
        return nil, "invalid id"
    end

    status = tostring(status or "")
    if status ~= "approved" and status ~= "rejected" then
        return nil, "invalid status"
    end

    local sql = format(
        SQL_UPDATE_RULE_CANDIDATE_REVIEW,
        quote_sql_str(status),
        quote_sql_str(note or ""),
        quote_sql_str(reviewer or ""),
        rid
    )
    return mysql.query(sql)
end

local function to_severity_by_score(score)
    local v = tonumber(score) or 0
    if v >= 80 then
        return "critical"
    elseif v >= 50 then
        return "high"
    elseif v >= 20 then
        return "medium"
    end
    return "low"
end

local function escape_regex_literal(str)
    return (tostring(str or ""):gsub("([%(%)%.%%%+%-%*%?%[%]%^%$])", "%%%1"))
end

local function normalize_candidate_uri(raw_uri)
    local uri = tostring(raw_uri or "")
    if uri == "" then
        return ""
    end
    local qpos = string.find(uri, "?", 1, true)
    if qpos then
        uri = string.sub(uri, 1, qpos - 1)
    end
    local hpos = string.find(uri, "#", 1, true)
    if hpos then
        uri = string.sub(uri, 1, hpos - 1)
    end
    if uri == "" then
        uri = "/"
    end
    if string.sub(uri, 1, 1) ~= "/" then
        uri = "/" .. uri
    end
    return uri
end

local function append_global_blackurl_rule(candidate)
    local rule_file = config.CONF_PATH .. "/global_rules/blackUrl.json"
    local content = read_file_to_string(rule_file)
    if not content or content == "" then
        return nil, "read blackUrl.json failed"
    end

    local data, err = cjson.decode(content)
    if type(data) ~= "table" then
        return nil, err or "decode blackUrl.json failed"
    end
    if type(data.rules) ~= "table" then
        data.rules = {}
    end

    local raw_uri = candidate.rule_content or candidate.sample_uri
    local normalized_uri = normalize_candidate_uri(raw_uri)
    if normalized_uri == "" then
        return nil, "candidate uri is empty"
    end
    local exact_regex = "^" .. escape_regex_literal(normalized_uri) .. "$"

    for _, rule in ipairs(data.rules) do
        if tostring(rule.rule or "") == exact_regex then
            return {
                published_rule_id = tonumber(rule.id),
                changed = false,
                normalized_uri = normalized_uri,
                exact_regex = exact_regex
            }, nil
        end
    end

    local next_id = tonumber(data.nextId) or (#data.rules + 1)
    local ip_blacklist_cfg = get_system_config("ipBlacklist") or {}
    local expire_seconds = tonumber(ip_blacklist_cfg.expire_time) or 600

    local new_rule = {
        id = next_id,
        state = "on",
        action = "redirect",
        attackType = tostring(candidate.sample_attack_type or "backdoor"),
        severityLevel = to_severity_by_score(candidate.risk_score),
        autoIpBlock = "on",
        ipBlockExpireInSeconds = expire_seconds,
        rule = exact_regex
    }

    insert(data.rules, new_rule)
    data.nextId = next_id + 1

    local new_content, encode_err = cjson.encode(data)
    if not new_content then
        return nil, encode_err or "encode blackUrl.json failed"
    end

    write_string_to_file(rule_file, new_content)
    return {
        published_rule_id = next_id,
        changed = true,
        normalized_uri = normalized_uri,
        exact_regex = exact_regex
    }, nil
end

function _M.publish_rule_candidate(id, publisher)
    local rid = tonumber(id)
    if not rid then
        return { code = 400, msg = "invalid id" }
    end

    local candidate_res, err = mysql.query(format(SQL_SELECT_RULE_CANDIDATE_BY_ID, rid))
    if not candidate_res or not candidate_res[1] then
        return { code = 404, msg = "candidate not found", error = err }
    end
    local candidate = candidate_res[1]

    if tostring(candidate.status or "") ~= "approved" then
        return { code = 400, msg = "candidate not approved" }
    end

    if tostring(candidate.publish_status or "") == RULE_CANDIDATE_PUBLISH_STATUS_PUBLISHED then
        return { code = 0, msg = "already published", changed = false }
    end

    local publish_result, publish_err = append_global_blackurl_rule(candidate)
    if not publish_result then
        local fail_sql = format(
            SQL_UPDATE_RULE_CANDIDATE_PUBLISH,
            quote_sql_str(RULE_CANDIDATE_PUBLISH_STATUS_FAILED),
            quote_sql_str("blackUrl"),
            "NULL",
            quote_sql_str(publish_err or "publish failed"),
            rid
        )
        mysql.query(fail_sql)
        return { code = 500, msg = publish_err or "publish failed" }
    end

    local published_rule_id_sql = "NULL"
    if publish_result.published_rule_id then
        published_rule_id_sql = tostring(tonumber(publish_result.published_rule_id))
    end

    local note = "published to global blackUrl"
    if not publish_result.changed then
        note = "duplicate rule exists in global blackUrl"
    end

    local update_sql = format(
        SQL_UPDATE_RULE_CANDIDATE_PUBLISH,
        quote_sql_str(RULE_CANDIDATE_PUBLISH_STATUS_PUBLISHED),
        quote_sql_str("blackUrl"),
        published_rule_id_sql,
        quote_sql_str(note .. ", by=" .. tostring(publisher or "")),
        rid
    )
    local ok, update_err = mysql.query(update_sql)
    if not ok then
        return { code = 500, msg = "update publish status failed", error = update_err }
    end

    return {
        code = 0,
        msg = "published",
        changed = publish_result.changed,
        publish_module = "blackUrl",
        published_rule_id = publish_result.published_rule_id,
        normalized_uri = publish_result.normalized_uri,
        regex = publish_result.exact_regex
    }
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

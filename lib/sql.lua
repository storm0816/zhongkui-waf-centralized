-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local mysql = require "mysql_cli"
local config = require "config"
local utils = require "utils"
local constants = require "constants"
local cjson = require "cjson.safe"

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

local _M = {}

local database = get_system_config('mysql').database

local BATCH_SIZE = 300

local SQL_CHECK_TABLE =
[[SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='%s' AND table_name='%s']]

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
    INSERT INTO waf_status (http4xx, http5xx, request_times, attack_times, block_times, block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times, request_date)
    VALUES(%u, %u, %u, %u, %u, %u, %u, %u, %u, %s) ON DUPLICATE KEY UPDATE http4xx = http4xx + VALUES(http4xx),
    http5xx = http5xx + VALUES(http5xx),request_times = request_times + VALUES(request_times),
    attack_times = attack_times + VALUES(attack_times),block_times = block_times + VALUES(block_times),
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
        `user_agent` VARCHAR(255) NULL COMMENT '请求客户端ua',
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
]]

local SQL_INSERT_ATTACK_LOG = [[
    INSERT INTO attack_log (
        request_id, ip, ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en,
        ip_longitude, ip_latitude, http_method, server_name, user_agent, referer, request_protocol, request_uri,
        request_body, http_status, response_body, request_time, attack_type, severity_level, security_module, hit_rule, action)
    VALUES
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

function _M.check_table(premature)
    if premature then
        return
    end

    local tables = {
        { name = 'waf_status',    sql = SQL_CREATE_TABLE_WAF_STATUS },
        { name = 'traffic_stats', sql = SQL_CREATE_TABLE_TRAFFIC_STATS },
        { name = 'attack_log',    sql = SQL_CREATE_TABLE_ATTACK_LOG },
        { name = 'ip_block_log',  sql = SQL_CREATE_TABLE_IP_BLOCK_LOG },
    }

    for _, t in pairs(tables) do
        local name = t.name
        local sql = t.sql

        local res, err = mysql.query(format(SQL_CHECK_TABLE, database, name))
        if res and res[1] and res[1].c == '0' then
            res, err = mysql.query(sql)
            if not res then
                ngx.log(ngx.ERR, 'failed to create table ' .. name .. ' ', err)
            end
        end
    end
end

function _M.update_traffic_stats()
    local dict = ngx.shared.dict_req_count_citys
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
                utils.dict_set(dict, prefix .. constants.KEY_REQUEST_TIMES, 0)
                utils.dict_set(dict, prefix .. constants.KEY_ATTACK_TIMES, 0)
                utils.dict_set(dict, prefix .. constants.KEY_BLOCK_TIMES_ATTACK, 0)
                utils.dict_set(dict, prefix .. constants.KEY_BLOCK_TIMES_CAPTCHA, 0)
                utils.dict_set(dict, prefix .. constants.KEY_BLOCK_TIMES_CC, 0)
                utils.dict_set(dict, prefix .. constants.KEY_CAPTCHA_PASS_TIMES, 0)

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
    end
end

function _M.update_waf_status()
    local dict = ngx.shared.dict_req_count

    local http4xx = utils.dict_get(dict, constants.KEY_HTTP_4XX) or 0
    local http5xx = utils.dict_get(dict, constants.KEY_HTTP_5XX) or 0
    local request_times = utils.dict_get(dict, constants.KEY_REQUEST_TIMES) or 0
    local attack_times = utils.dict_get(dict, constants.KEY_ATTACK_TIMES) or 0
    local block_times_attack = utils.dict_get(dict, constants.KEY_BLOCK_TIMES_ATTACK) or 0
    local block_times_captcha = utils.dict_get(dict, constants.KEY_BLOCK_TIMES_CAPTCHA) or 0
    local block_times_cc = utils.dict_get(dict, constants.KEY_BLOCK_TIMES_CC) or 0
    local captcha_pass_times = utils.dict_get(dict, constants.KEY_CAPTCHA_PASS_TIMES) or 0

    if http4xx == 0 and http5xx == 0 and request_times == 0 and attack_times == 0 and block_times_attack == 0 and block_times_captcha == 0 and block_times_cc == 0 and captcha_pass_times == 0 then
        return
    end

    utils.dict_set(dict, constants.KEY_HTTP_4XX, 0)
    utils.dict_set(dict, constants.KEY_HTTP_5XX, 0)
    utils.dict_set(dict, constants.KEY_REQUEST_TIMES, 0)
    utils.dict_set(dict, constants.KEY_ATTACK_TIMES, 0)
    utils.dict_set(dict, constants.KEY_BLOCK_TIMES_ATTACK, 0)
    utils.dict_set(dict, constants.KEY_BLOCK_TIMES_CAPTCHA, 0)
    utils.dict_set(dict, constants.KEY_BLOCK_TIMES_CC, 0)
    utils.dict_set(dict, constants.KEY_CAPTCHA_PASS_TIMES, 0)

    local block_times = block_times_attack + block_times_captcha + block_times_cc

    local sql = format(SQL_INSERT_WAF_STATUS, http4xx, http5xx, request_times, attack_times, block_times,
        block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times, quote_sql_str(ngx.today()))

    mysql.query(sql)
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

function _M.write_sql_to_queue(key, sql)
    local dict_sql_queue = ngx.shared.dict_sql_queue
    dict_sql_queue:rpush(key, sql)
end

function _M.write_attack_log_redis_to_mysql()
    local redis_cli = require "redis_cli"

    if not redis_cli then
        ngx.log(ngx.ERR, "failed to load redis_cli module")
        return
    end

    local redis_pattern = "waf:attack_log:*"

    -- 使用 scan 命令代替 keys 命令
    local attack_log_keys, err = redis_cli.scan(redis_pattern)

    if not attack_log_keys then
        ngx.log(ngx.ERR, "failed to get attack log keys from redis: ", err)
        return
    end

    for _, redis_key in ipairs(attack_log_keys) do
        local redis_value, err = redis_cli.get(redis_key)

        if not redis_value then
            ngx.log(ngx.ERR, "failed to get attack log from redis: ", err)
            goto continue
        end

        local log_data, err = cjson.decode(redis_value)
        if not log_data then
            ngx.log(ngx.ERR, "failed to decode attack log json: ", err)
            goto continue
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
        local ip_longitude = log_data.ip_longitude or ""
        local ip_latitude = log_data.ip_latitude or ""
        local http_method = log_data.http_method or ""
        local server_name = log_data.server or "" -- 修改：使用 log_data.server
        local user_agent = log_data.user_agent or ""
        local referer = log_data.referer or ""
        local request_protocol = log_data.request_protocol or ""
        local request_uri = log_data.request_uri or ""
        local request_body = log_data.request_data or "" -- 修改：使用 log_data.request_data
        local http_status = log_data.http_status or ""
        local response_body = log_data.response_body or ""
        local request_time = log_data.attack_time or nil -- 修改：使用 log_data.attack_time
        local attack_type = log_data.attack_type or ""
        local severity_level = log_data.severity_level or ""
        local security_module = log_data.securityModule or "" -- 修改：使用 log_data.securityModule
        local hit_rule = log_data.hit_rule or ""
        local action = log_data.action or ""

        local sql_str = format(
            SQL_INSERT_ATTACK_LOG ..
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

        local res, err = mysql.query(sql_str)
        if not res then
            ngx.log(ngx.ERR, "failed to write attack log to mysql: ", err)
            goto continue
        end

        -- 删除 Redis key
        local ok, err = redis_cli.del(redis_key)
        if not ok then
            ngx.log(ngx.ERR, "failed to delete attack log key from redis: ", err)
        end

        ::continue::
    end
end

-- 在适当的地方调用 write_sql_redis_to_mysql 函数，例如定时任务
-- ngx.timer.at(delay, write_sql_redis_to_mysql)

return _M

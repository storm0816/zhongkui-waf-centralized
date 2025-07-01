-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local cjson = require "cjson"
local user = require "user"
local time = require "time"
local sql = require "sql"
local utils = require "utils"
local constants = require "constants"

local ipairs = ipairs
local concat = table.concat
local ngxfind = ngx.re.find

local cjson_encode = cjson.encode
local is_system_option_on = config.is_system_option_on

local _M = {}

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

local function getRequestTrafficMysql()
    local res, err = sql.get_request_traffic_by_hour()
    if not res then
        ngx.log(4, "failed to get request traffic from mysql: ", err)
        return '[]'
    end

    -- 初始化小时映射
    local hours = time.get_hours()
    local hour_map = {}
    for _, h in ipairs(hours) do
        hour_map[h] = { h, 0, 0, 0 }
    end

    for _, row in ipairs(res) do
        local hour = row.hour
        hour_map[hour] = {
            hour,
            tonumber(row.traffic) or 0,
            tonumber(row.attack_traffic) or 0,
            tonumber(row.blocked_traffic) or 0
        }
    end

    local data = { { "hour", "traffic", "attack_traffic", "blocked_traffic" } }
    for _, h in ipairs(hours) do
        table.insert(data, hour_map[h])
    end

    local dataStr = cjson.encode(data)
    -- ngx.log(8, "getRequestTrafficMysql: ", dataStr)
    return dataStr
end


local function getAttackTypeTraffic()
    local dict = ngx.shared.dict_req_count
    local keys = dict:get_keys()
    local dataStr = ''

    if keys then
        local today = ngx.today()
        local prefix = constants.KEY_ATTACK_TYPE_PREFIX .. today

        for _, key in ipairs(keys) do
            local from = ngxfind(key, prefix)
            if from then
                local count = dict:get(key) or 0
                dataStr = concat({ dataStr, '{"name":"', key, '","value": ', count, '},' })
            end
        end
    end

    if #dataStr > 0 then
        dataStr = '[' .. string.sub(dataStr, 1, -2) .. ']'
    else
        dataStr = '[]'
    end

    return dataStr
end

local function getAttackTypeTrafficMysql()
    local res, err = sql.get_attack_type_traffic()
    if not res then
        ngx.log(ngx.ERR, "failed to get attack type traffic from mysql: ", err)
        return '[]'
    end

    local attack_type_traffic = {}
    for _, row in ipairs(res) do
        table.insert(attack_type_traffic, { name = row.attack_type, value = row.attack_count })
    end

    -- 打印转换后的数据，用于调试
    -- ngx.log(ngx.INFO, "Transformed data from MySQL: ", cjson.encode(attack_type_traffic))

    return cjson.encode(attack_type_traffic) -- 暂时返回空数组，避免影响其他功能
end

function _M.do_request()
    local response = { code = 200, data = {}, msg = "" }
    local uri = ngx.var.uri

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson_encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/dashboard" then
        local trafficDataStr
        local attackTypeDataStr
        if is_system_option_on("centralized") then
            attackTypeDataStr = getAttackTypeTrafficMysql()
            trafficDataStr = getRequestTrafficMysql()
        else
            attackTypeDataStr = getAttackTypeTraffic()
            trafficDataStr = getRequestTraffic()
        end
        local data = {}
        data.trafficData = trafficDataStr
        data.attackTypeData = attackTypeDataStr

        local wafStatus = {}
        local world = {}
        local china = {}

        if is_system_option_on("mysql") then
            local res, err = sql.get_today_waf_status()
            if res then
                wafStatus = res[1]
            else
                ngx.log(ngx.ERR, err)
            end

            res, err = sql.get_30days_world_traffic_stats()
            if res then
                world = res
            else
                ngx.log(ngx.ERR, err)
            end

            res, err = sql.get_30days_china_traffic_stats()
            if res then
                china = res
            else
                ngx.log(ngx.ERR, err)
            end
        else
            local dict = ngx.shared.dict_req_count

            local http4xx = utils.dict_get(dict, constants.KEY_HTTP_4XX) or 0
            local http5xx = utils.dict_get(dict, constants.KEY_HTTP_5XX) or 0
            local request_times = utils.dict_get(dict, constants.KEY_REQUEST_TIMES) or 0
            local attack_times = utils.dict_get(dict, constants.KEY_ATTACK_TIMES) or 0
            local block_times_attack = utils.dict_get(dict, constants.KEY_BLOCK_TIMES_ATTACK) or 0
            local block_times_captcha = utils.dict_get(dict, constants.KEY_BLOCK_TIMES_CAPTCHA) or 0
            local block_times_cc = utils.dict_get(dict, constants.KEY_BLOCK_TIMES_CC) or 0
            local captcha_pass_times = utils.dict_get(dict, constants.KEY_CAPTCHA_PASS_TIMES) or 0

            local block_times = block_times_attack + block_times_captcha + block_times_cc

            wafStatus = {
                http4xx = http4xx,
                http5xx = http5xx,
                request_times = request_times,
                attack_times = attack_times,
                block_times = block_times,
                block_times_attack = block_times_attack,
                block_times_captcha = block_times_captcha,
                block_times_cc = block_times_cc,
                captcha_pass_times = captcha_pass_times
            }
        end

        data.sourceRegion = { world = world, china = china }
        data.wafStatus = wafStatus
        response.data = data
    end

    ngx.say(cjson_encode(response))
end

_M.do_request()

return _M

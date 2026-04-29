-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local redis = require "resty.redis"
local config = require "config"
-- register the module prefix "bf" for RedisBloom
-- redis.register_module_prefix("bf")

local tonumber = tonumber
local tostring = tostring
local ipairs = ipairs
local lower = string.lower
local concat = table.concat
local ngxmatch = ngx.re.match
local get_system_config = config.get_system_config

local _M = {}

local redis_config = get_system_config("redis")
local host = redis_config.host
local port = redis_config.port
local password = redis_config.password
local poolSize = redis_config.poolSize
local ssl = lower(redis_config.ssl) == 'on' and true or false

local redis_timeouts = redis_config.timeouts
local connect_timeout, send_timeout, read_timeout = 1000, 1000, 1000
local redis_status_dict = ngx.shared and ngx.shared.dict_config or nil
local status_prefix = "waf:redis:status:"
local failure_threshold = tonumber(redis_config.failure_threshold) or 3
local failure_window_seconds = tonumber(redis_config.failure_window_seconds) or 30
local degrade_seconds = tonumber(redis_config.degrade_seconds) or 10

local function status_key(suffix)
    return status_prefix .. suffix
end

local function now()
    return ngx.now and ngx.now() or os.time()
end

local function get_status_number(suffix, default)
    if not redis_status_dict then
        return default
    end
    local v = redis_status_dict:get(status_key(suffix))
    if v == nil then
        return default
    end
    return tonumber(v) or default
end

local local_status = {
    fail_count = 0,
    first_fail_ts = 0,
    degrade_until = 0,
    last_error = nil,
    last_ok_ts = 0,
}

local function set_status_fields(fields)
    if redis_status_dict then
        for suffix, value in pairs(fields) do
            redis_status_dict:set(status_key(suffix), value)
        end
    else
        for suffix, value in pairs(fields) do
            local_status[suffix] = value
        end
    end
end

local function get_fail_count()
    if redis_status_dict then
        return get_status_number("fail_count", 0)
    end
    return local_status.fail_count
end

local function get_first_fail_ts()
    if redis_status_dict then
        return get_status_number("first_fail_ts", 0)
    end
    return local_status.first_fail_ts
end

local function get_degrade_until()
    if redis_status_dict then
        return get_status_number("degrade_until", 0)
    end
    return local_status.degrade_until
end

local function mark_failure(err)
    local ts = now()
    local first_fail_ts = get_first_fail_ts()
    local fail_count = get_fail_count()

    if ts - first_fail_ts > failure_window_seconds then
        first_fail_ts = ts
        fail_count = 1
    else
        if first_fail_ts == 0 then
            first_fail_ts = ts
        end
        fail_count = fail_count + 1
    end

    local fields = {
        first_fail_ts = first_fail_ts,
        fail_count = fail_count,
        last_error = tostring(err or "unknown"),
        last_fail_ts = ts,
    }
    if fail_count >= failure_threshold then
        fields.degrade_until = ts + degrade_seconds
    end
    set_status_fields(fields)
end

local function mark_success()
    local ts = now()
    if get_fail_count() == 0 and get_degrade_until() <= ts then
        return
    end
    set_status_fields({
        fail_count = 0,
        first_fail_ts = 0,
        degrade_until = 0,
        last_ok_ts = ts,
    })
end

local function should_skip_connect()
    return now() < get_degrade_until()
end

if redis_timeouts then
    local m, err = ngxmatch(tostring(redis_timeouts), "(\\d+),(\\d+),(\\d+)")
    if m then
        connect_timeout = tonumber(m[1]) or 1000
        send_timeout = tonumber(m[2]) or 1000
        read_timeout = tonumber(m[3]) or 1000
    else
        ngx.log(ngx.ERR, "failed to read redis timeouts config:", err)
    end
end

--local filterName = "blackIpFilter"

function _M.get_connection()
    if should_skip_connect() then
        return nil, "redis degrade window active"
    end

    local red, err1 = redis:new()
    if not red then
        ngx.log(ngx.ERR, "failed to new redis:", err1)
        mark_failure(err1)
        return nil, err1
    end

    red:set_timeouts(connect_timeout, send_timeout, read_timeout)

    local ok, err = red:connect(host, port or 6379, { ssl = ssl, pool_size = poolSize })

    if not ok then
        ngx.log(ngx.ERR, "failed to connect: ", err .. "\n")
        mark_failure(err)
        return nil, err
    end

    if password ~= nil and #password ~= 0 then
        local times = 0
        times, err = red:get_reused_times()

        if times == 0 then
            local res, err2 = red:auth(password)
            if not res then
                ngx.log(ngx.ERR, "failed to authenticate: ", err2)
                mark_failure(err2)
                return nil, err2
            end
        end
    end

    mark_success()
    return red, err
end

function _M.close_connection(red)
    -- put it into the connection pool of size 100,
    -- with 10 seconds max idle time
    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        ngx.log(ngx.ERR, "failed to set keepalive: ", err)
    end

    return ok, err
end

function _M.is_available()
    return not should_skip_connect()
end

function _M.get_status()
    local status = {}
    if redis_status_dict then
        status.fail_count = get_status_number("fail_count", 0)
        status.first_fail_ts = get_status_number("first_fail_ts", 0)
        status.degrade_until = get_status_number("degrade_until", 0)
        status.last_fail_ts = get_status_number("last_fail_ts", 0)
        status.last_ok_ts = get_status_number("last_ok_ts", 0)
        status.last_error = redis_status_dict:get(status_key("last_error"))
    else
        status.fail_count = local_status.fail_count
        status.first_fail_ts = local_status.first_fail_ts
        status.degrade_until = local_status.degrade_until
        status.last_fail_ts = local_status.last_fail_ts
        status.last_ok_ts = local_status.last_ok_ts
        status.last_error = local_status.last_error
    end
    status.available = not should_skip_connect()
    return status
end

function _M.set(key, value, expire_time)
    local red, _ = _M.get_connection()
    local ok, err = nil, nil
    if red then
        ok, err = red:set(key, value)
        if not ok then
            ngx.log(ngx.ERR, "failed to set key: " .. key .. " ", err)
        elseif expire_time and expire_time > 0 then
            red:expire(key, expire_time)
        end

        _M.close_connection(red)
    end

    return ok, err
end

function _M.bath_set(key_table, value, key_prefix)
    local red, _ = _M.get_connection()
    local results, err = nil, nil
    if red then
        red:init_pipeline()

        if key_prefix then
            for _, k in ipairs(key_table) do
                red:set(key_prefix .. k, value)
            end
        else
            for _, k in ipairs(key_table) do
                red:set(k, value)
            end
        end

        results, err = red:commit_pipeline()
        if not results then
            ngx.log(ngx.ERR, "failed to set keys: ", err)
        end

        _M.close_connection(red)
    end

    return results, err
end

function _M.get(key)
    local red, err = _M.get_connection()
    local value = nil
    if red then
        value, err = red:get(key)
        if not value then
            ngx.log(ngx.ERR, "failed to get key: " .. key, err)
            return value, err
        end
        if value == ngx.null then
            value = nil
        end

        _M.close_connection(red)
    end

    return value, err
end

function _M.incr(key, expire_time)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        res, err = red:incr(key)
        if not res then
            ngx.log(ngx.ERR, "failed to incr key: " .. key, err)
        elseif res == 1 and expire_time and expire_time > 0 then
            red:expire(key, expire_time)
        end

        _M.close_connection(red)
    end

    return res, err
end

function _M.del(key)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        res, err = red:del(key)
        if not res then
            ngx.log(ngx.ERR, "failed to delete key: " .. key, err)
        end

        _M.close_connection(red)
    end

    return res, err
end

function _M.bath_del(key_table, key_prefix)
    local red, _ = _M.get_connection()
    local results, err = nil, nil
    if red then
        red:init_pipeline()

        if key_prefix then
            for _, k in ipairs(key_table) do
                red:del(key_prefix .. k)
            end
        else
            for _, k in ipairs(key_table) do
                red:del(k)
            end
        end

        results, err = red:commit_pipeline()
        if not results then
            ngx.log(ngx.ERR, "failed to delete keys: ", err)
        end

        _M.close_connection(red)
    end

    return results, err
end

function _M.rpush(key, value, expire_time)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        res, err = red:rpush(key, value)
        if not res then
            ngx.log(ngx.ERR, "failed to rpush key: ", key, " err=", err)
        elseif expire_time and expire_time > 0 then
            red:expire(key, expire_time)
        end

        _M.close_connection(red)
    end

    return res, err
end

function _M.bath_rpush(key, values, expire_time)
    local red, _ = _M.get_connection()
    local results, err = nil, nil
    if red then
        red:init_pipeline()

        for _, value in ipairs(values) do
            red:rpush(key, value)
        end
        if expire_time and expire_time > 0 then
            red:expire(key, expire_time)
        end

        results, err = red:commit_pipeline()
        if not results then
            ngx.log(ngx.ERR, "failed to batch rpush key: ", key, " err=", err)
        end

        _M.close_connection(red)
    end

    return results, err
end

function _M.lpop(key)
    local red, err = _M.get_connection()
    local value = nil
    if red then
        value, err = red:lpop(key)
        if value == ngx.null then
            value = nil
        elseif not value then
            ngx.log(ngx.ERR, "failed to lpop key: ", key, " err=", err)
        end

        _M.close_connection(red)
    end

    return value, err
end

function _M.sadd(key, member, expire_time)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        res, err = red:sadd(key, member)
        if not res then
            ngx.log(ngx.ERR, "failed to sadd key: ", key, " err=", err)
        elseif expire_time and expire_time > 0 then
            red:expire(key, expire_time)
        end
        _M.close_connection(red)
    end
    return res, err
end

function _M.smembers(key)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        res, err = red:smembers(key)
        if not res then
            ngx.log(ngx.ERR, "failed to smembers key: ", key, " err=", err)
        end
        _M.close_connection(red)
    end
    return res, err
end

function _M.srem(key, member)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        res, err = red:srem(key, member)
        if not res then
            ngx.log(ngx.ERR, "failed to srem key: ", key, " err=", err)
        end
        _M.close_connection(red)
    end
    return res, err
end

function _M.batch_lpop(key, count)
    local red, _ = _M.get_connection()
    local values, err = {}, nil
    if red then
        red:init_pipeline()
        for _ = 1, count do
            red:lpop(key)
        end

        local results
        results, err = red:commit_pipeline()
        if not results then
            ngx.log(ngx.ERR, "failed to batch lpop key: ", key, " err=", err)
            _M.close_connection(red)
            return nil, err
        end

        for _, value in ipairs(results) do
            if value ~= ngx.null then
                values[#values + 1] = value
            end
        end

        _M.close_connection(red)
    end

    return values, err
end

function _M.hmset(key, tbl, expire_time)
    local red, _ = _M.get_connection()
    local ok, err = nil, nil
    if red then
        ok, err = red:hmset(key, tbl)
        if not ok then
            ngx.log(ngx.ERR, "failed to hmset key: ", key, err)
        elseif expire_time and expire_time > 0 then
            red:expire(key, expire_time)
        end
        _M.close_connection(red)
    end
    return ok, err
end

function _M.hgetall(key)
    local red, _ = _M.get_connection()
    local res, err = nil, nil
    if red then
        res, err = red:hgetall(key)
        if not res then
            ngx.log(ngx.ERR, "failed to hgetall key: ", key, err)
        end
        _M.close_connection(red)
    else
        ngx.log(ngx.ERR, "failed to get redis connection for key: ", key)
    end
    return res, err
end

--[[
function _M.bf_add(value)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        -- call BF.ADD command with the prefix 'bf'
        res, err = red:bf():add(filterName, value)
        if not res then
            ngx.log(ngx.ERR, "bf():add value: " .. value, err)
            return res, err
        end

        _M.close_connection(red)
    end
    return res, err
end

function _M.bf_exists(value)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        -- call BF.EXISTS command
        res, err = red:bf():exists(filterName, value)
        if not res then
            ngx.log(ngx.ERR, "bf():exists value: " .. value, err)
            return res, err
        elseif res == 1 then
            _M.close_connection(red)
            return true
        else
            _M.close_connection(red)
            return false
        end
    end
    return false
end
]]

function _M.scan(pattern, count)
    local red, err = _M.get_connection()
    if not red then
        return nil, err
    end

    local cursor = "0"
    local keys = {}
    local insert = table.insert -- 添加 local insert 声明

    repeat
        local res, err = red:scan(cursor, "MATCH", pattern, "COUNT", count or 100)
        if not res then
            ngx.log(ngx.ERR, "failed to scan keys: ", err)
            _M.close_connection(red)
            return nil, err
        end

        cursor = res[1]
        local new_keys = res[2]
        for _, key in ipairs(new_keys) do
            insert(keys, key)
        end
    until cursor == "0"

    _M.close_connection(red)
    return keys, nil
end

function _M.hincrby(key, field, value)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        res, err = red:hincrby(key, field, value)
        if not res then
            ngx.log(ngx.ERR, "failed to hincrby: key=", key, " field=", field, " err=", err)
        end
        _M.close_connection(red)
    end
    return res, err
end

function _M.expire(key, seconds)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        res, err = red:expire(key, seconds)
        if not res then
            ngx.log(ngx.ERR, "failed to expire key: ", key, err)
        end
        _M.close_connection(red)
    end
    return res, err
end

function _M.acquire_lock(key, token, ttl)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        res, err = red:set(key, token, "NX", "EX", ttl)
        if not res or res == ngx.null then
            res = nil
        end
        if not res and err then
            ngx.log(ngx.ERR, "failed to acquire redis lock: ", key, " err=", err)
        end
        _M.close_connection(red)
    end
    return res == "OK", err
end

function _M.release_lock(key, token)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        res, err = red:eval(concat({
            "if redis.call('get', KEYS[1]) == ARGV[1] then",
            "return redis.call('del', KEYS[1])",
            "else",
            "return 0",
            "end",
        }, " "), 1, key, token)
        if not res then
            ngx.log(ngx.ERR, "failed to release redis lock: ", key, " err=", err)
        end
        _M.close_connection(red)
    end
    return res, err
end

return _M

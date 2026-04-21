-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local mysql = require "resty.mysql"
local config = require "config"

local _M = {}

local mysql_config = config.get_system_config("mysql")
local host = mysql_config.host
local port = mysql_config.port
local user = mysql_config.user
local password = mysql_config.password
local database = mysql_config.database
local poolSize = mysql_config.poolSize
local timeout = mysql_config.timeout or 1000

function _M.get_connection()
    local db, err = mysql:new()
    if not db then
        ngx.log(ngx.ERR, "failed to instantiate mysql: ", err)
        return nil, err
    end

    db:set_timeout(timeout)

    local ok, err, errcode, sql_state = db:connect {
        host = host,
        port = port or 3306,
        database = database,
        user = user,
        password = password,
        charset = "utf8mb4",
        max_packet_size = 1024 * 1024,
        pool_size = poolSize or 10
    }

    if not ok then
        ngx.log(ngx.ERR, "failed to connect: ", err, ": ", errcode, " ", sql_state)
        return nil, err
    end

    return db, err
end

function _M.query(sql, rows)
    local res, err, errcode, sql_state
    local db = _M.get_connection()
    if db then
        res, err, errcode, sql_state = db:query(sql, rows)
        if not res then
            ngx.log(ngx.ERR, "bad result: ", err, ": ", errcode, ": ", sql_state, ".")
            return
        end

        _M.close_connection(db)
    end

    return res
end

function _M.close_connection(db)
    if not db then
        return nil, "db is nil"
    end

    -- 先尝试放回连接池
    local ok, err = db:set_keepalive(10000, poolSize or 10)
    if ok then
        return ok, nil
    end

    -- 当前连接状态不可复用时，直接关闭，别再报错污染日志
    ngx.log(ngx.WARN, "failed to set keepalive, fallback to close: ", err)

    local ok2, err2 = db:close()
    if not ok2 then
        ngx.log(ngx.ERR, "failed to close mysql connection: ", err2)
        return nil, err2
    end

    return true, nil
end

return _M

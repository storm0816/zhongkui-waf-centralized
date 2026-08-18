-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file = require "file_utils"
local user = require "user"
local request = require "request"
local sql = require "sql"
local constants = require "constants"

local get_post_args = request.get_post_args
local cjson_encode = cjson.encode
local cjson_decode = cjson.decode
local read_file_to_string = file.read_file_to_string
local write_string_to_file = file.write_string_to_file

local type = type
local APP_VERSION = constants.APP_VERSION or "unknown"

local _M = {}

local SYSTEM_PATH = config.CONF_PATH .. '/system.json'

local function save_or_fail(response, ...)
    local ok, err = ...
    if not ok then
        response.code = 500
        response.msg = err or 'write file failed'
        return false
    end
    return true
end

local function parse_ldap_server(value)
    local scheme, host, port = tostring(value or ""):match("^(ldaps?)://([^:/]+):?(%d*)/?$")
    if not scheme or not host then return nil end
    return { host = host, port = tonumber(port) or (scheme == "ldaps" and 636 or 389), ldaps = scheme == "ldaps" }
end

local function test_ldap_connection(values)
    local current = config.get_system_config("ldap") or {}
    local ldap = cjson_decode(cjson_encode(current)) or {}
    for key, value in pairs(values or {}) do
        ldap[key] = value
    end
    if not ldap.bind_password or ldap.bind_password == "" then
        ldap.bind_password = current.bind_password
    end

    if type(ldap.servers) ~= "table" or #ldap.servers == 0 then
        return nil, "请填写 LDAP 服务器地址"
    end
    if not ldap.bind_user or ldap.bind_user == "" or not ldap.bind_password or ldap.bind_password == "" then
        return nil, "请填写 LDAP 连接账号和密码"
    end
    if not ldap.search_base or ldap.search_base == "" then
        return nil, "请填写 LDAP 查询基准"
    end

    local client_module = require "resty.ldap.client"
    local last_error = "LDAP 连接失败"
    for _, value in ipairs(ldap.servers) do
        local server = parse_ldap_server(value)
        if server then
            local client = client_module:new(server.host, server.port, {
                socket_timeout = tonumber(ldap.timeout) or 5000,
                keepalive_timeout = 60000,
                start_tls = ldap.start_tls == true or ldap.start_tls == "on",
                ldaps = server.ldaps,
                ssl_verify = ldap.tls_verify ~= false and ldap.tls_verify ~= "off"
            })
            local bound, bind_error = client:simple_bind(ldap.bind_user, ldap.bind_password)
            if bound then
                local filter = { item_type = "present", attribute_description = "objectClass", attribute_value = "*" }
                local entries, search_error = client:search(ldap.search_base, 0, 0, 1, 5, false, filter, { "objectClass" })
                client:close()
                if entries and entries[1] and entries[1].entry_dn then
                    return true, "LDAP 连接和查询测试成功（" .. tostring(value) .. "）"
                end
                last_error = search_error or "查询基准不存在或无权读取"
            else
                client:close()
                last_error = bind_error or "连接账号认证失败"
            end
        else
            last_error = "LDAP 地址格式错误：" .. tostring(value)
        end
    end
    return nil, last_error
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

    if uri == "/system/get" then
        -- 查询配置信息
        local system = cjson_decode(cjson_encode(config.get_system_config()))
        if system then
            -- 清空用户名和密码，避免返回给前端
            local redis = system.redis
            local mysql = system.mysql
            if redis then
                redis.user = nil
                redis.password = nil
            end
            if mysql then
                mysql.user = nil
                mysql.password = nil
            end
            if system.ldap then
                system.ldap.bind_password = nil
            end
            response.data = cjson_encode(system)
            response.app_version = APP_VERSION
        end
    elseif uri == "/system/ldap/test" and ngx.req.get_method() == "POST" then
        local args, err = get_post_args()
        local ldap_values = args and cjson_decode(args.ldap or "")
        if type(ldap_values) ~= "table" then
            response.code = 400
            response.msg = err or "LDAP 配置格式错误"
        else
            local ok, test_message = test_ldap_connection(ldap_values)
            response.code = ok and 200 or 500
            response.msg = test_message
        end
    elseif uri == "/system/update" then
        local args, err = get_post_args()
        if args then
            local json = read_file_to_string(SYSTEM_PATH)
            local system = cjson_decode(json)

            for key, val in pairs(args) do
                local option = system[key]

                if key == 'secret' then
                    option = val
                else
                    local t = cjson_decode(val)
                    if type(t) == 'table' then
                        if type(option) ~= 'table' then
                            option = {}
                        end
                        for k, v in pairs(t) do
                            option[k] = v
                        end
                    else
                        option = val
                    end
                end

                system[key] = option
                config.set_system_config(key, option)
            end

            reload = save_or_fail(response, write_string_to_file(SYSTEM_PATH, cjson_encode(system)))
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/system/attacklog/archive/run" and ngx.req.get_method() == "POST" then
        local result = sql.archive_attack_log_once(true)
        if result and result.code == 0 then
            response.code = 0
            response.data = result
            response.msg = "执行成功"
        else
            response.code = 500
            response.msg = result and (result.msg or result.error) or "执行失败"
            response.data = result or {}
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

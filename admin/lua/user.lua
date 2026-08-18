local cjson = require "cjson.safe"
local config = require "config"
local file = require "file_utils"
local ip_utils = require "ip_utils"
local auth_store = require "auth_store"

local _M = {}

local PASSWORD_PATH = config.ZHONGKUI_PATH .. "/admin/admin/data/user.json"
local COOKIE_NAME = "waf_admin_session"
local LEGACY_SALT_LENGTH = 20
local LOGIN_LIMIT_WINDOW = 300
local LOGIN_LIMIT_ATTEMPTS = 8

local function response_json(status, message, data)
    ngx.status = status >= 400 and status or ngx.HTTP_OK
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.say(cjson.encode({ code = status, msg = message or "", data = data or {} }))
end

local function cookie_flags(expires)
    local flags = "; Path=/; HttpOnly; SameSite=Strict"
    if ngx.var.scheme == "https" then
        flags = flags .. "; Secure"
    end
    if expires then
        flags = flags .. "; Expires=" .. expires
    end
    return flags
end

local function set_session_cookie(session_id)
    ngx.header["Set-Cookie"] = COOKIE_NAME .. "=" .. session_id .. cookie_flags(ngx.cookie_time(ngx.time() + 1800))
end

local function clear_session_cookie()
    ngx.header["Set-Cookie"] = COOKIE_NAME .. "=" .. cookie_flags("Thu, 01 Jan 1970 00:00:00 GMT")
end

local function current_session_id()
    return ngx.var["cookie_" .. COOKIE_NAME]
end

function _M.deny_console_on_node()
    if config.is_cluster_node() then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header.content_type = "text/plain; charset=utf-8"
        ngx.say("当前节点为 node，不提供控制台，请访问 master 节点。")
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

function _M.get_current_user()
    if ngx.ctx.admin_identity then
        return ngx.ctx.admin_identity
    end
    local identity = auth_store.get_session(current_session_id())
    ngx.ctx.admin_identity = identity
    return identity
end

function _M.check_auth_token()
    return _M.get_current_user() ~= nil
end

function _M.has_permission(permission)
    return auth_store.has_permission(_M.get_current_user(), permission)
end

function _M.require_permission(permission)
    if not _M.check_auth_token() then
        response_json(401, "User not logged in")
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
    if not _M.has_permission(permission) then
        response_json(403, "Permission denied")
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    return true
end

function _M.enforce_request_permission()
    _M.deny_console_on_node()
    local uri = ngx.var.uri or ""
    if uri == "/login" or uri == "/login.html" or uri == "/user/login" or uri == "/user/mfa/verify"
        or uri:find("^/component/") or uri:find("^/admin/css/") or uri:find("^/admin/images/")
        or uri:find("^/screen/") then
        return true
    end
    if not _M.check_auth_token() then
        if uri:find("%.html$") or uri == "/" or uri == "/index.html" then
            return ngx.redirect("/login")
        end
        response_json(401, "User not logged in")
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
    if uri:find("^/user/") then
        return true
    end
    local required = ngx.req.get_method() == "GET" and "read" or "manage"
    if uri:find("^/access/") then required = "user.manage" end
    if not _M.has_permission(required) then
        response_json(403, "Permission denied")
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    return true
end

local function legacy_password(password, salt)
    return string.upper(ngx.md5(ngx.md5(password .. salt)))
end

local function authenticate_local(username, password)
    local raw = file.read_file_to_string(PASSWORD_PATH)
    local legacy = raw and cjson.decode(raw) or nil
    if not legacy or username ~= legacy.username then
        return nil
    end
    if legacy_password(password, legacy.salt) ~= legacy.password then
        return nil
    end
    return auth_store.get_user(username)
end

local function parse_ldap_server(value)
    local scheme, host, port = tostring(value or ""):match("^(ldaps?)://([^:/]+):?(%d*)$")
    if not scheme then return nil end
    return {
        host = host,
        port = tonumber(port) or (scheme == "ldaps" and 636 or 389),
        ldaps = scheme == "ldaps"
    }
end

local function ldap_servers(ldap_config)
    local values = ldap_config.servers
    if type(values) ~= "table" then
        values = { ldap_config.server }
    end
    local servers = {}
    for _, value in ipairs(values) do
        local server = parse_ldap_server(value)
        if server then servers[#servers + 1] = server end
    end
    return servers
end

local function authenticate_ldap(username, password)
    local ldap_config = config.get_system_config("ldap") or {}
    if tostring(ldap_config.state or "off"):lower() ~= "on" then
        return nil, "LDAP is disabled"
    end
    if password == "" then
        return nil, "Invalid credentials"
    end

    local client_module = require "resty.ldap.client"
    if #username > 128 or not username:match("^[%w%._@%-]+$") then
        return nil, "Invalid username"
    end
    local bind_template = tostring(ldap_config.bind_template or "%s")
    local escaped_username = username:gsub("([,=+<>#;\\\"])", "\\%1")
    local bind_value = bind_template == "%s" and username or escaped_username
    local bind_dn = bind_template:gsub("%%s", bind_value, 1)
    local service_user = tostring(ldap_config.bind_user or "")
    local service_password = tostring(ldap_config.bind_password or "")
    local search_base = tostring(ldap_config.search_base or "")
    local user_attribute = tostring(ldap_config.user_attribute or "sAMAccountName")
    local search_mode = service_user ~= "" and service_password ~= "" and search_base ~= ""
    if search_mode and username:lower() == service_user:lower() then
        return nil, "LDAP service account cannot access the console"
    end
    if search_mode and not user_attribute:match("^[%a][%w%-]*$") then
        return nil, "Invalid LDAP user attribute"
    end

    local last_error
    for _, server in ipairs(ldap_servers(ldap_config)) do
        local client = client_module:new(server.host, server.port, {
            socket_timeout = tonumber(ldap_config.timeout) or 5000,
            keepalive_timeout = 60000,
            start_tls = ldap_config.start_tls == true or ldap_config.start_tls == "on",
            ldaps = server.ldaps,
            ssl_verify = ldap_config.tls_verify ~= false and ldap_config.tls_verify ~= "off"
        })

        if search_mode then
            local service_ok, service_err = client:simple_bind(service_user, service_password)
            if service_ok then
                local filter = {
                    item_type = "simple",
                    filter_type = "equal",
                    attribute_description = user_attribute,
                    attribute_value = username
                }
                local entries, search_err = client:search(search_base, 2, 0, 2, 5, false, filter,
                    { user_attribute, "displayName", "userPrincipalName" })
                if entries then
                    local entry
                    for _, candidate in ipairs(entries) do
                        if candidate.entry_dn and candidate.entry_dn ~= "" then
                            entry = candidate
                            break
                        end
                    end
                    if entry then
                        local ok, err = client:simple_bind(entry.entry_dn, password)
                        client:close()
                        if ok then
                            local display_values = entry.attributes and entry.attributes.displayName
                            local display_name = type(display_values) == "table" and display_values[1] or username
                            return auth_store.ensure_ldap_user(username, entry.entry_dn, display_name)
                        end
                        last_error = err
                        if ok == false then break end
                    else
                        last_error = "LDAP user not found"
                    end
                else
                    last_error = search_err
                end
            else
                last_error = service_err
            end
            client:close()
        else
            local ok, err = client:simple_bind(bind_dn, password)
            client:close()
            if ok then
                return auth_store.ensure_ldap_user(username, bind_dn)
            end
            last_error = err
            if ok == false then break end
        end
    end
    if last_error then
        ngx.log(ngx.WARN, "LDAP authentication failed: ", last_error)
    end
    return nil, "Invalid credentials"
end

local function mfa_required(user)
    local auth_config = config.get_system_config("auth") or {}
    if tonumber(user.mfa_required) == 1 then
        return true
    end
    return tostring(auth_config.mfa_required or "off"):lower() == "on"
end

local function finish_login(user)
    local client_ip = ip_utils.get_client_ip()
    local user_agent = ngx.var.http_user_agent or ""
    local session_id, err = auth_store.create_session(user, client_ip, user_agent)
    if not session_id then
        return nil, err
    end
    set_session_cookie(session_id)
    auth_store.audit({ user_id = user.id, username = user.username }, "login", user.auth_source, "success", "", client_ip)
    return true
end

local function begin_login(args)
    local username = tostring(args.username or "")
    local password = tostring(args.password or "")
    local auth_type = tostring(args.auth_type or "auto")
    local user, err
    if username == "" or password == "" then
        return response_json(201, "用户名或密码错误")
    end

    local client_ip = ip_utils.get_client_ip()
    local limit_key = "waf:admin:login:limit:" .. ngx.md5(client_ip .. ":" .. username:lower())
    local attempts = tonumber(require("redis_cli").get(limit_key)) or 0
    if attempts >= LOGIN_LIMIT_ATTEMPTS then
        return response_json(429, "登录失败次数过多，请5分钟后重试")
    end

    auth_store.ensure_schema()
    if auth_type == "local" or (auth_type == "auto" and username == "admin") then
        user = authenticate_local(username, password)
    else
        user, err = authenticate_ldap(username, password)
    end
    if not user or user.status ~= "enabled" then
        require("redis_cli").incr(limit_key, LOGIN_LIMIT_WINDOW)
        auth_store.audit(nil, "login", auth_type, "failed", err or "invalid credentials", client_ip)
        return response_json(201, "用户名、密码或认证方式错误")
    end
    require("redis_cli").del(limit_key)

    if mfa_required(user) then
        local setup_secret
        if tonumber(user.mfa_enabled) ~= 1 then
            setup_secret, err = auth_store.new_mfa_secret()
            if not setup_secret then return response_json(500, err) end
        end
        local pending_token, pending_err = auth_store.create_pending(user, ip_utils.get_client_ip(), ngx.var.http_user_agent or "", setup_secret)
        if not pending_token then return response_json(500, pending_err) end
        return response_json(202, setup_secret and "请绑定MFA" or "请输入MFA验证码", {
            pending_token = pending_token,
            mfa_setup_required = setup_secret ~= nil,
            secret = setup_secret,
            otpauth_uri = setup_secret and ("otpauth://totp/Zhongkui-WAF:" .. ngx.escape_uri(username)
                .. "?secret=" .. setup_secret .. "&issuer=Zhongkui-WAF") or nil
        })
    end

    local ok, login_err = finish_login(user)
    if not ok then return response_json(500, login_err) end
    return response_json(200, "登录成功")
end

local function verify_mfa(args)
    local token = tostring(args.pending_token or "")
    local code = tostring(args.code or "")
    local pending = auth_store.get_pending(token)
    if not pending or code == "" then
        return response_json(201, "MFA验证已失效，请重新登录")
    end
    local user = auth_store.get_user(pending.username)
    if not user or user.status ~= "enabled" then
        return response_json(201, "用户不可用")
    end
    local secret = pending.setup_secret or auth_store.load_mfa_secret(user)
    if not secret or not auth_store.verify_totp(secret, code) then
        auth_store.audit({ user_id = user.id, username = user.username }, "mfa.verify", "login", "failed", "invalid code", ip_utils.get_client_ip())
        return response_json(201, "MFA验证码错误")
    end
    if pending.setup_secret then
        auth_store.save_mfa_secret(user.id, secret)
        user.mfa_enabled = 1
        user.mfa_secret = nil
    end
    auth_store.delete_pending(token)
    local ok, err = finish_login(user)
    if not ok then return response_json(500, err) end
    return response_json(200, "登录成功")
end

local function update_legacy_password(args)
    local identity = _M.get_current_user()
    if not identity or identity.username ~= "admin" then
        return response_json(403, "仅本地管理员可修改本地密码")
    end
    local old_password = tostring(args.oldPassword or "")
    local new_password = tostring(args.newPassword or "")
    local raw = file.read_file_to_string(PASSWORD_PATH)
    local legacy = raw and cjson.decode(raw) or nil
    if not legacy or legacy_password(old_password, legacy.salt) ~= legacy.password then
        return response_json(201, "旧密码错误")
    end
    if #new_password < 12 then
        return response_json(201, "新密码至少需要12位")
    end
    local random = io.open("/dev/urandom", "rb")
    local salt_raw = random and random:read(LEGACY_SALT_LENGTH) or nil
    if random then random:close() end
    if not salt_raw then return response_json(500, "安全随机源不可用") end
    local salt = ngx.encode_base64(salt_raw):gsub("[^%w]", ""):sub(1, LEGACY_SALT_LENGTH)
    legacy.salt = salt
    legacy.password = legacy_password(new_password, salt)
    local ok, err = file.write_string_to_file(PASSWORD_PATH, cjson.encode(legacy))
    if not ok then return response_json(500, err) end
    return response_json(200, "密码已更新")
end

function _M.reset_local_password(user_id, new_password)
    local target = auth_store.get_user_by_id(user_id)
    if not target or target.auth_source ~= "local_legacy" then
        return nil, "仅支持重置本地用户密码"
    end
    new_password = tostring(new_password or "")
    if #new_password < 12 then return nil, "新密码至少需要12位" end

    local raw = file.read_file_to_string(PASSWORD_PATH)
    local legacy = raw and cjson.decode(raw) or nil
    if not legacy or legacy.username ~= target.username then
        return nil, "本地用户密码配置不存在"
    end
    local random = io.open("/dev/urandom", "rb")
    local salt_raw = random and random:read(LEGACY_SALT_LENGTH) or nil
    if random then random:close() end
    if not salt_raw then return nil, "安全随机源不可用" end
    local salt = ngx.encode_base64(salt_raw):gsub("[^%w]", ""):sub(1, LEGACY_SALT_LENGTH)
    legacy.salt = salt
    legacy.password = legacy_password(new_password, salt)
    local ok, err = file.write_string_to_file(PASSWORD_PATH, cjson.encode(legacy))
    if not ok then return nil, err end
    return true, target
end

function _M.do_request()
    _M.deny_console_on_node()
    ngx.req.read_body()
    local args = ngx.req.get_post_args() or {}
    local uri = ngx.var.uri

    if uri == "/user/login" then
        return begin_login(args)
    elseif uri == "/user/mfa/verify" then
        return verify_mfa(args)
    elseif uri == "/user/logout" then
        auth_store.delete_session(current_session_id())
        clear_session_cookie()
        return response_json(200, "已退出")
    elseif uri == "/user/me" then
        local identity = _M.get_current_user()
        if not identity then return response_json(401, "User not logged in") end
        return response_json(200, "", identity)
    elseif uri == "/user/password/update" then
        if not _M.check_auth_token() then return response_json(401, "User not logged in") end
        return update_legacy_password(args)
    end
    return response_json(404, "Not found")
end

return _M

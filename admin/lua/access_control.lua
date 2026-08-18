local cjson = require "cjson.safe"
local user = require "user"
local auth_store = require "auth_store"
local ip_utils = require "ip_utils"

local function respond(code, message, data)
    ngx.status = code >= 400 and code or ngx.HTTP_OK
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.header["Cache-Control"] = "no-cache, no-store, must-revalidate"
    ngx.header["Pragma"] = "no-cache"
    ngx.header["Expires"] = "0"
    ngx.say(cjson.encode({ code = code, msg = message or "", data = data or {} }))
end

local function split_ids(value)
    local ids = {}
    for item in tostring(value or ""):gmatch("[^,]+") do
        local id = tonumber(item)
        if id then ids[#ids + 1] = id end
    end
    return ids
end

local function args()
    if ngx.req.get_method() == "GET" then
        return ngx.req.get_uri_args()
    end
    ngx.req.read_body()
    return ngx.req.get_post_args() or {}
end

local function audit(action, target, detail)
    auth_store.audit(user.get_current_user(), action, target, "success", detail, ip_utils.get_client_ip())
end

local function has_role(identity, role_name)
    for _, role in ipairs(identity and identity.roles or {}) do
        if role.name == role_name then return true end
    end
    return false
end

local function require_local_admin()
    local identity = user.get_current_user()
    if not identity or identity.username ~= "admin" then
        respond(403, "仅 admin 管理员可以修改用户角色")
        return nil
    end
    return identity
end

local function handle()
    user.deny_console_on_node()
    if not user.require_permission("user.manage") then return end

    local uri = ngx.var.uri
    local values = args()
    local read_only_uri = uri == "/access/users"
        or uri == "/access/roles"
        or uri == "/access/permissions"
        or uri == "/access/audit"

    -- user.manage permits access-control viewing only. Mutations are limited to
    -- the local break-glass admin, even if a custom role gains user.manage.
    if not read_only_uri and not require_local_admin() then return end

    if uri == "/access/users" then
        return respond(200, "", auth_store.list_users())
    elseif uri == "/access/roles" then
        return respond(200, "", auth_store.list_roles())
    elseif uri == "/access/permissions" then
        return respond(200, "", auth_store.list_permissions())
    elseif uri == "/access/audit" then
        return respond(200, "", auth_store.list_audit(values.limit))
    elseif uri == "/access/user/create" then
        local username = tostring(values.username or ""):match("^%s*(.-)%s*$")
        local role_id = tonumber(values.role_id)
        if username == "" or not role_id then return respond(400, "用户名和角色不能为空") end
        if #username > 128 or not username:match("^[%w%._@%-]+$") then
            return respond(400, "用户名仅允许字母、数字、点、下划线、@ 和短横线")
        end
        if auth_store.get_user(username) then return respond(409, "用户已存在") end
        local created, err = auth_store.create_ldap_account(username, values.display_name, role_id)
        if not created then return respond(500, err) end
        audit("user.create", username, "source=ldap")
        return respond(200, "用户已创建", created)
    elseif uri == "/access/user/roles" then
        local identity = user.get_current_user()
        local user_id = tonumber(values.user_id)
        if not user_id then return respond(400, "用户ID无效") end
        ngx.log(ngx.NOTICE, "[access-control] recv user.roles user_id=", tostring(user_id),
            " role_ids=", tostring(values.role_ids or ""),
            " actor=", tostring(identity and identity.username or "-"))
        local ok, err = auth_store.set_user_roles(user_id, split_ids(values.role_ids))
        if not ok then
            ngx.log(ngx.WARN, "[access-control] user.roles failed user_id=", tostring(user_id),
                " role_ids=", tostring(values.role_ids or ""),
                " err=", tostring(err or "unknown"))
            return respond(400, err)
        end
        ngx.log(ngx.NOTICE, "[access-control] user.roles saved user_id=", tostring(user_id),
            " role_ids=", tostring(values.role_ids or ""))
        audit("user.roles", tostring(user_id), values.role_ids)
        return respond(200, "角色已更新")
    elseif uri == "/access/user/status" then
        local user_id = tonumber(values.user_id)
        local ok, err = auth_store.set_user_status(user_id, values.status)
        if not ok then return respond(400, err) end
        audit("user.status", tostring(user_id), values.status)
        return respond(200, "状态已更新")
    elseif uri == "/access/user/mfa/required" then
        local user_id = tonumber(values.user_id)
        if not user_id then return respond(400, "用户ID无效") end
        local required = tostring(values.required or "")
        local ok, err = auth_store.set_user_mfa_required(user_id, required)
        if not ok then return respond(400, err or "MFA策略更新失败") end
        audit("user.mfa.required", tostring(user_id), required)
        return respond(200, required == "on" and "已要求该用户使用 MFA" or "已取消该用户 MFA 要求")
    elseif uri == "/access/user/mfa/reset" then
        local user_id = tonumber(values.user_id)
        if not user_id then return respond(400, "用户ID无效") end
        local ok, err = auth_store.reset_mfa(user_id)
        if not ok then return respond(400, err or "MFA重置失败") end
        audit("user.mfa.reset", tostring(user_id), "")
        return respond(200, "MFA已重置")
    elseif uri == "/access/user/delete" then
        local identity = user.get_current_user()
        local user_id = tonumber(values.user_id)
        local ok, target_or_err = auth_store.delete_user(user_id, identity and identity.user_id)
        if not ok then return respond(400, target_or_err) end
        audit("user.delete", target_or_err.username, "source=" .. tostring(target_or_err.auth_source))
        return respond(200, "用户已删除")
    elseif uri == "/access/user/password/reset" then
        local identity = user.get_current_user()
        if not has_role(identity, "super_admin") then
            return respond(403, "仅超级管理员可以重置本地用户密码")
        end
        local user_id = tonumber(values.user_id)
        local ok, target_or_err = user.reset_local_password(user_id, values.new_password)
        if not ok then return respond(400, target_or_err) end
        audit("user.password.reset", target_or_err.username, "local admin reset")
        return respond(200, "本地用户密码已重置")
    elseif uri == "/access/role/create" then
        local name = tostring(values.name or ""):match("^%s*(.-)%s*$")
        if name == "" then return respond(400, "角色名称不能为空") end
        local role, err = auth_store.create_role(name, values.description, split_ids(values.permission_ids))
        if not role then return respond(500, err) end
        audit("role.create", name, values.permission_ids)
        return respond(200, "角色已创建", role)
    elseif uri == "/access/role/permissions" then
        local role_id = tonumber(values.role_id)
        if not role_id then return respond(400, "角色ID无效") end
        local ok, err = auth_store.set_role_permissions(role_id, split_ids(values.permission_ids))
        if not ok then return respond(400, err) end
        audit("role.permissions", tostring(role_id), values.permission_ids)
        return respond(200, "权限已更新")
    end
    return respond(404, "Not found")
end

handle()

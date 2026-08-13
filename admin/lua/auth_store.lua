local cjson = require "cjson.safe"
local config = require "config"
local mysql = require "mysql_cli"
local redis = require "redis_cli"
local aes = require "lib.aes"

local _M = {}

local SESSION_PREFIX = "waf:admin:session:"
local PENDING_PREFIX = "waf:admin:login:pending:"
local SESSION_TTL = 1800
local PENDING_TTL = 300
local schema_ready = false

local function quote(value)
    return ngx.quote_sql_str(tostring(value or ""))
end

local function random_bytes(length)
    local file = io.open("/dev/urandom", "rb")
    if not file then
        return nil, "secure random source unavailable"
    end
    local value = file:read(length)
    file:close()
    if not value or #value ~= length then
        return nil, "secure random source returned insufficient data"
    end
    return value
end

local function to_hex(value)
    return (value:gsub(".", function(char)
        return string.format("%02x", string.byte(char))
    end))
end

local function base32_encode(value)
    local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    local output, buffer, bits = {}, 0, 0
    for index = 1, #value do
        buffer = buffer * 256 + value:byte(index)
        bits = bits + 8
        while bits >= 5 do
            bits = bits - 5
            local position = math.floor(buffer / (2 ^ bits)) % 32
            output[#output + 1] = alphabet:sub(position + 1, position + 1)
        end
        buffer = buffer % (2 ^ bits)
    end
    if bits > 0 then
        local position = (buffer * (2 ^ (5 - bits))) % 32
        output[#output + 1] = alphabet:sub(position + 1, position + 1)
    end
    return table.concat(output)
end

local function base32_decode(value)
    local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    local output, buffer, bits = {}, 0, 0
    value = tostring(value or ""):upper():gsub("[^A-Z2-7]", "")
    for index = 1, #value do
        local position = alphabet:find(value:sub(index, index), 1, true)
        if not position then
            return nil
        end
        buffer = buffer * 32 + position - 1
        bits = bits + 5
        if bits >= 8 then
            bits = bits - 8
            output[#output + 1] = string.char(math.floor(buffer / (2 ^ bits)) % 256)
            buffer = buffer % (2 ^ bits)
        end
    end
    return table.concat(output)
end

local function constant_time_equals(left, right)
    left, right = tostring(left or ""), tostring(right or "")
    if #left ~= #right then
        return false
    end
    local different = 0
    for index = 1, #left do
        different = bit.bor(different, bit.bxor(left:byte(index), right:byte(index)))
    end
    return different == 0
end

local function totp_at(secret, counter)
    local key = base32_decode(secret)
    if not key then
        return nil
    end
    local bytes = {}
    for index = 8, 1, -1 do
        bytes[index] = string.char(counter % 256)
        counter = math.floor(counter / 256)
    end
    local digest = ngx.hmac_sha1(key, table.concat(bytes))
    local offset = bit.band(digest:byte(#digest), 0x0f)
    local value = bit.band(digest:byte(offset + 1), 0x7f) * 16777216
        + digest:byte(offset + 2) * 65536
        + digest:byte(offset + 3) * 256
        + digest:byte(offset + 4)
    return string.format("%06d", value % 1000000)
end

function _M.verify_totp(secret, code)
    local counter = math.floor(ngx.time() / 30)
    for drift = -1, 1 do
        if constant_time_equals(totp_at(secret, counter + drift), code) then
            return true
        end
    end
    return false
end

local SCHEMA = {
    [[CREATE TABLE IF NOT EXISTS waf_admin_user (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(128) NOT NULL,
        display_name VARCHAR(128) NOT NULL DEFAULT '',
        auth_source VARCHAR(32) NOT NULL DEFAULT 'ldap',
        external_id VARCHAR(255) NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'enabled',
        mfa_enabled TINYINT(1) NOT NULL DEFAULT 0,
        mfa_secret TEXT NULL,
        last_login_at DATETIME NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_admin_username (username)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4]],
    [[CREATE TABLE IF NOT EXISTS waf_admin_role (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(64) NOT NULL,
        description VARCHAR(255) NOT NULL DEFAULT '',
        builtin TINYINT(1) NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_admin_role_name (name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4]],
    [[CREATE TABLE IF NOT EXISTS waf_admin_permission (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        code VARCHAR(64) NOT NULL,
        description VARCHAR(255) NOT NULL DEFAULT '',
        UNIQUE KEY uniq_admin_permission_code (code)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4]],
    [[CREATE TABLE IF NOT EXISTS waf_admin_user_role (
        user_id BIGINT UNSIGNED NOT NULL,
        role_id BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY (user_id, role_id),
        INDEX idx_admin_user_role_role (role_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4]],
    [[CREATE TABLE IF NOT EXISTS waf_admin_role_permission (
        role_id BIGINT UNSIGNED NOT NULL,
        permission_id BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY (role_id, permission_id),
        INDEX idx_admin_role_permission_permission (permission_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4]],
    [[CREATE TABLE IF NOT EXISTS waf_admin_audit_log (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id BIGINT UNSIGNED NULL,
        username VARCHAR(128) NOT NULL DEFAULT '',
        action VARCHAR(128) NOT NULL,
        target VARCHAR(255) NOT NULL DEFAULT '',
        result VARCHAR(16) NOT NULL DEFAULT 'success',
        client_ip VARCHAR(64) NOT NULL DEFAULT '',
        detail TEXT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_admin_audit_created (created_at),
        INDEX idx_admin_audit_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4]]
}

function _M.ensure_schema()
    if schema_ready then
        return true
    end
    for _, statement in ipairs(SCHEMA) do
        if not mysql.query(statement) then
            return nil, "failed to initialize access-control tables"
        end
    end

    mysql.query([[INSERT IGNORE INTO waf_admin_permission (code, description) VALUES
        ('read', '只读'), ('manage', '管理'), ('user.manage', '用户与角色管理')]])
    mysql.query([[INSERT IGNORE INTO waf_admin_role (name, description, builtin) VALUES
        ('super_admin', '超级管理员', 1),
        ('manager', '安全管理员', 1),
        ('readonly', '只读审计员', 1)]])
    mysql.query([[INSERT IGNORE INTO waf_admin_role_permission (role_id, permission_id)
        SELECT r.id, p.id FROM waf_admin_role r JOIN waf_admin_permission p
        WHERE r.name='super_admin']])
    mysql.query([[INSERT IGNORE INTO waf_admin_role_permission (role_id, permission_id)
        SELECT r.id, p.id FROM waf_admin_role r JOIN waf_admin_permission p
        WHERE r.name='manager' AND p.code IN ('read', 'manage')]])
    mysql.query([[INSERT IGNORE INTO waf_admin_role_permission (role_id, permission_id)
        SELECT r.id, p.id FROM waf_admin_role r JOIN waf_admin_permission p
        WHERE r.name='readonly' AND p.code='read']])
    mysql.query([[INSERT IGNORE INTO waf_admin_user
        (username, display_name, auth_source, external_id, status)
        VALUES ('admin', 'Administrator', 'local_legacy', 'local:admin', 'enabled')]])
    mysql.query([[INSERT IGNORE INTO waf_admin_user_role (user_id, role_id)
        SELECT u.id, r.id FROM waf_admin_user u JOIN waf_admin_role r
        WHERE u.username='admin' AND r.name='super_admin']])
    schema_ready = true
    return true
end

function _M.get_user(username)
    _M.ensure_schema()
    local rows = mysql.query("SELECT * FROM waf_admin_user WHERE username=" .. quote(username) .. " LIMIT 1")
    return rows and rows[1] or nil
end

function _M.get_user_by_id(user_id)
    _M.ensure_schema()
    local id = tonumber(user_id)
    if not id then return nil end
    local rows = mysql.query("SELECT * FROM waf_admin_user WHERE id=" .. id .. " LIMIT 1")
    return rows and rows[1] or nil
end

function _M.ensure_ldap_user(username, external_id, display_name)
    _M.ensure_schema()
    local user = _M.get_user(username)
    if not user then
        mysql.query("INSERT IGNORE INTO waf_admin_user (username, display_name, auth_source, external_id, status) VALUES ("
            .. quote(username) .. "," .. quote(display_name or username) .. ",'ldap'," .. quote(external_id or username) .. ",'enabled')")
        user = _M.get_user(username)
    end
    if user then
        local role_rows = mysql.query("SELECT COUNT(*) AS total FROM waf_admin_user_role WHERE user_id=" .. tonumber(user.id)) or {}
        if tonumber(role_rows[1] and role_rows[1].total or 0) == 0 then
            mysql.query("INSERT IGNORE INTO waf_admin_user_role (user_id, role_id) SELECT u.id,r.id FROM waf_admin_user u JOIN waf_admin_role r WHERE u.username="
                .. quote(username) .. " AND r.name='readonly'")
        end
    end
    return _M.get_user(username)
end

function _M.get_permissions(user_id)
    local rows = mysql.query([[SELECT DISTINCT p.code FROM waf_admin_permission p
        JOIN waf_admin_role_permission rp ON rp.permission_id=p.id
        JOIN waf_admin_user_role ur ON ur.role_id=rp.role_id
        WHERE ur.user_id=]] .. tonumber(user_id)) or {}
    local permissions = {}
    for _, row in ipairs(rows) do
        permissions[#permissions + 1] = row.code
    end
    return permissions
end

function _M.get_roles(user_id)
    local rows = mysql.query([[SELECT r.id,r.name FROM waf_admin_role r
        JOIN waf_admin_user_role ur ON ur.role_id=r.id WHERE ur.user_id=]] .. tonumber(user_id)) or {}
    return rows
end

function _M.has_permission(identity, required)
    if not identity or not identity.permissions then
        return false
    end
    for _, permission in ipairs(identity.permissions) do
        if permission == required then
            return true
        end
        if permission == "manage" and required == "read" then
            return true
        end
    end
    return false
end

function _M.create_session(user, client_ip, user_agent)
    local random, err = random_bytes(32)
    if not random then
        return nil, err
    end
    local session_id = to_hex(random)
    local identity = {
        user_id = tonumber(user.id),
        username = user.username,
        display_name = user.display_name,
        auth_source = user.auth_source,
        permissions = _M.get_permissions(user.id),
        roles = _M.get_roles(user.id),
        client_ip = client_ip,
        user_agent = user_agent,
        mfa_verified = true,
        created_at = ngx.time()
    }
    local ok, set_err = redis.set(SESSION_PREFIX .. session_id, cjson.encode(identity), SESSION_TTL)
    if not ok then
        return nil, set_err
    end
    mysql.query("UPDATE waf_admin_user SET last_login_at=NOW() WHERE id=" .. tonumber(user.id))
    return session_id, identity
end

function _M.get_session(session_id)
    if not session_id or session_id == "" then
        return nil
    end
    local value = redis.get(SESSION_PREFIX .. session_id)
    if not value then
        return nil
    end
    local identity = cjson.decode(value)
    if not identity then
        return nil
    end
    local current_user = _M.get_user_by_id(identity.user_id)
    if not current_user or current_user.status ~= "enabled" then
        _M.delete_session(session_id)
        return nil
    end
    identity.display_name = current_user.display_name
    identity.auth_source = current_user.auth_source
    identity.permissions = _M.get_permissions(current_user.id)
    identity.roles = _M.get_roles(current_user.id)
    redis.set(SESSION_PREFIX .. session_id, cjson.encode(identity), SESSION_TTL)
    return identity
end

function _M.delete_session(session_id)
    if session_id and session_id ~= "" then
        redis.del(SESSION_PREFIX .. session_id)
    end
end

function _M.create_pending(user, client_ip, user_agent, setup_secret)
    local random, err = random_bytes(24)
    if not random then
        return nil, err
    end
    local token = to_hex(random)
    local pending = {
        user_id = tonumber(user.id), username = user.username,
        client_ip = client_ip, user_agent = user_agent,
        setup_secret = setup_secret, created_at = ngx.time()
    }
    local ok, set_err = redis.set(PENDING_PREFIX .. token, cjson.encode(pending), PENDING_TTL)
    if not ok then
        return nil, set_err
    end
    return token
end

function _M.get_pending(token)
    local value = token and redis.get(PENDING_PREFIX .. token) or nil
    return value and cjson.decode(value) or nil
end

function _M.delete_pending(token)
    if token then
        redis.del(PENDING_PREFIX .. token)
    end
end

local function mfa_salt(user_id)
    return tostring(ngx.md5("admin-mfa:" .. tostring(user_id))):sub(1, 8)
end

function _M.new_mfa_secret()
    local random, err = random_bytes(20)
    return random and base32_encode(random) or nil, err
end

function _M.save_mfa_secret(user_id, secret)
    local system_secret = config.get_system_config("secret")
    local encrypted = aes.encrypt(system_secret, secret, mfa_salt(user_id))
    return mysql.query("UPDATE waf_admin_user SET mfa_enabled=1,mfa_secret=" .. quote(encrypted)
        .. " WHERE id=" .. tonumber(user_id))
end

function _M.load_mfa_secret(user)
    if tonumber(user.mfa_enabled) ~= 1 or not user.mfa_secret or user.mfa_secret == "" then
        return nil
    end
    return aes.decrypt(config.get_system_config("secret"), user.mfa_secret, mfa_salt(user.id))
end

function _M.reset_mfa(user_id)
    user_id = tonumber(user_id)
    if not user_id then return nil, "invalid user" end
    return mysql.query("UPDATE waf_admin_user SET mfa_enabled=0,mfa_secret=NULL WHERE id=" .. user_id)
end

function _M.audit(identity, action, target, result, detail, client_ip)
    _M.ensure_schema()
    mysql.query("INSERT INTO waf_admin_audit_log (user_id,username,action,target,result,client_ip,detail) VALUES ("
        .. (identity and tonumber(identity.user_id) or "NULL") .. ","
        .. quote(identity and identity.username or "") .. "," .. quote(action) .. "," .. quote(target)
        .. "," .. quote(result or "success") .. "," .. quote(client_ip) .. "," .. quote(detail) .. ")")
end

function _M.list_users()
    _M.ensure_schema()
    return mysql.query([[SELECT u.id,u.username,u.display_name,u.auth_source,u.status,u.mfa_enabled,u.last_login_at,
        GROUP_CONCAT(DISTINCT r.name ORDER BY r.name SEPARATOR ',') AS roles
        FROM waf_admin_user u LEFT JOIN waf_admin_user_role ur ON ur.user_id=u.id
        LEFT JOIN waf_admin_role r ON r.id=ur.role_id GROUP BY u.id ORDER BY u.id]]) or {}
end

function _M.list_roles()
    _M.ensure_schema()
    return mysql.query([[SELECT r.id,r.name,r.description,r.builtin,
        GROUP_CONCAT(DISTINCT p.code ORDER BY p.code SEPARATOR ',') AS permissions
        FROM waf_admin_role r LEFT JOIN waf_admin_role_permission rp ON rp.role_id=r.id
        LEFT JOIN waf_admin_permission p ON p.id=rp.permission_id GROUP BY r.id ORDER BY r.id]]) or {}
end

function _M.list_permissions()
    _M.ensure_schema()
    return mysql.query("SELECT id,code,description FROM waf_admin_permission ORDER BY id") or {}
end

function _M.create_ldap_account(username, display_name, role_id)
    _M.ensure_schema()
    local role_rows = mysql.query("SELECT id FROM waf_admin_role WHERE id=" .. tonumber(role_id) .. " LIMIT 1") or {}
    if not role_rows[1] then return nil, "invalid role" end
    local ok = mysql.query("INSERT INTO waf_admin_user (username,display_name,auth_source,external_id,status) VALUES ("
        .. quote(username) .. "," .. quote(display_name or username) .. ",'ldap'," .. quote(username) .. ",'enabled')")
    if not ok then return nil, "failed to create user" end
    local user = _M.get_user(username)
    mysql.query("INSERT IGNORE INTO waf_admin_user_role (user_id,role_id) VALUES (" .. tonumber(user.id) .. "," .. tonumber(role_id) .. ")")
    return user
end

local function is_last_super_admin(user_id)
    local rows = mysql.query([[SELECT COUNT(DISTINCT ur.user_id) AS total
        FROM waf_admin_user_role ur
        JOIN waf_admin_role r ON r.id=ur.role_id AND r.name='super_admin'
        JOIN waf_admin_user u ON u.id=ur.user_id AND u.status='enabled']]) or {}
    local roles = _M.get_roles(user_id)
    local is_super_admin = false
    for _, role in ipairs(roles) do
        if role.name == "super_admin" then
            is_super_admin = true
            break
        end
    end
    return is_super_admin and tonumber(rows[1] and rows[1].total or 0) <= 1
end

function _M.set_user_roles(user_id, role_ids)
    user_id = tonumber(user_id)
    if not user_id then return nil, "invalid user" end
    if #(role_ids or {}) == 0 then return nil, "用户至少需要一个角色" end
    local user_rows = mysql.query("SELECT id,username FROM waf_admin_user WHERE id=" .. user_id .. " LIMIT 1") or {}
    if not user_rows[1] then return nil, "用户不存在" end
    for _, role_id in ipairs(role_ids) do
        local role_rows = mysql.query("SELECT id FROM waf_admin_role WHERE id=" .. tonumber(role_id) .. " LIMIT 1") or {}
        if not role_rows[1] then return nil, "角色不存在" end
    end
    if is_last_super_admin(user_id) then
        local keeps_super_admin = false
        for _, role_id in ipairs(role_ids) do
            local rows = mysql.query("SELECT name FROM waf_admin_role WHERE id=" .. tonumber(role_id) .. " LIMIT 1") or {}
            if rows[1] and rows[1].name == "super_admin" then
                keeps_super_admin = true
                break
            end
        end
        if not keeps_super_admin then return nil, "不能移除最后一个超级管理员" end
    end
    local deleted = mysql.query("DELETE FROM waf_admin_user_role WHERE user_id=" .. tonumber(user_id))
    if not deleted then return nil, "清理原角色失败，请检查数据库连接" end
    for _, role_id in ipairs(role_ids or {}) do
        local inserted = mysql.query("INSERT IGNORE INTO waf_admin_user_role (user_id,role_id) VALUES (" .. tonumber(user_id) .. "," .. tonumber(role_id) .. ")")
        if not inserted then return nil, "保存角色失败，请检查数据库连接" end
    end
    return true
end

function _M.set_user_status(user_id, status)
    if status ~= "enabled" and status ~= "disabled" then return nil, "invalid status" end
    if status == "disabled" and is_last_super_admin(user_id) then
        return nil, "不能禁用最后一个超级管理员"
    end
    return mysql.query("UPDATE waf_admin_user SET status=" .. quote(status) .. " WHERE id=" .. tonumber(user_id))
end

function _M.delete_user(user_id, actor_user_id)
    user_id = tonumber(user_id)
    actor_user_id = tonumber(actor_user_id)
    if not user_id then return nil, "用户ID无效" end
    local target = _M.get_user_by_id(user_id)
    if not target then return nil, "用户不存在" end
    if target.username == "admin" or target.auth_source == "local_legacy" then
        return nil, "内置本地管理员不能删除"
    end
    if actor_user_id and actor_user_id == user_id then
        return nil, "不能删除当前登录用户"
    end
    if is_last_super_admin(user_id) then
        return nil, "不能删除最后一个超级管理员"
    end
    mysql.query("DELETE FROM waf_admin_user_role WHERE user_id=" .. user_id)
    local deleted = mysql.query("DELETE FROM waf_admin_user WHERE id=" .. user_id .. " LIMIT 1")
    if not deleted then return nil, "删除用户失败" end
    return true, target
end

function _M.create_role(name, description, permission_ids)
    _M.ensure_schema()
    local ok = mysql.query("INSERT INTO waf_admin_role (name,description,builtin) VALUES ("
        .. quote(name) .. "," .. quote(description) .. ",0)")
    if not ok then return nil, "failed to create role" end
    local rows = mysql.query("SELECT id FROM waf_admin_role WHERE name=" .. quote(name) .. " LIMIT 1")
    local role = rows and rows[1]
    if role then _M.set_role_permissions(role.id, permission_ids) end
    return role
end

function _M.set_role_permissions(role_id, permission_ids)
    local rows = mysql.query("SELECT name FROM waf_admin_role WHERE id=" .. tonumber(role_id) .. " LIMIT 1") or {}
    if not rows[1] then return nil, "角色不存在" end
    if rows[1] and rows[1].name == "super_admin" then
        return nil, "超级管理员权限不可修改"
    end
    for _, permission_id in ipairs(permission_ids or {}) do
        local permission_rows = mysql.query("SELECT id FROM waf_admin_permission WHERE id=" .. tonumber(permission_id) .. " LIMIT 1") or {}
        if not permission_rows[1] then return nil, "权限不存在" end
    end
    mysql.query("DELETE FROM waf_admin_role_permission WHERE role_id=" .. tonumber(role_id))
    for _, permission_id in ipairs(permission_ids or {}) do
        mysql.query("INSERT IGNORE INTO waf_admin_role_permission (role_id,permission_id) VALUES ("
            .. tonumber(role_id) .. "," .. tonumber(permission_id) .. ")")
    end
    return true
end

function _M.list_audit(limit)
    limit = math.min(math.max(tonumber(limit) or 100, 1), 500)
    return mysql.query("SELECT id,username,action,target,result,client_ip,detail,created_at FROM waf_admin_audit_log ORDER BY id DESC LIMIT " .. limit) or {}
end

return _M

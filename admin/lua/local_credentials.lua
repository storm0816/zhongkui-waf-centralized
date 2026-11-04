local mysql = require "mysql_cli"
local password_policy = require "password_policy"

local _M = {}
local ITERATIONS = 100000
local quote = ngx.quote_sql_str
local hex = require("resty.string").to_hex
local sha256 = require "resty.sha256"
local schema_ready = false

local function digest(password, salt, iterations)
    local value = salt .. password
    local context = assert(sha256:new())
    for _ = 1, iterations do
        context:reset()
        assert(context:update(value))
        value = assert(context:final())
    end
    return hex(value)
end

local function random_salt()
    local source = io.open("/dev/urandom", "rb")
    if not source then return nil end
    local bytes = source:read(24)
    source:close()
    return bytes and #bytes == 24 and hex(bytes) or nil
end

local function same(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then return false end
    local difference = 0
    for i = 1, #a do difference = bit.bor(difference, bit.bxor(a:byte(i), b:byte(i))) end
    return difference == 0
end

function _M.ensure_schema()
    if schema_ready then return true end
    local created = mysql.query([[CREATE TABLE IF NOT EXISTS waf_admin_local_credential (
        user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
        salt VARCHAR(48) NOT NULL,
        password_hash CHAR(64) NOT NULL,
        iterations INT UNSIGNED NOT NULL,
        must_change_password TINYINT(1) NOT NULL DEFAULT 0,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4]])
    if not created then return nil end
    local columns = mysql.query([[SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='waf_admin_local_credential' AND COLUMN_NAME='must_change_password' LIMIT 1]])
    if not columns then return nil end
    if not columns[1] then
        if not mysql.query("ALTER TABLE waf_admin_local_credential ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 1") then return nil end
        if not mysql.query([[UPDATE waf_admin_local_credential c JOIN waf_admin_user u ON u.id=c.user_id
            SET c.must_change_password=0 WHERE u.auth_source='local' AND u.last_login_at IS NOT NULL]]) then return nil end
    end
    schema_ready = true
    return true
end

function _M.set_password(user_id, password, must_change)
    local valid, err = password_policy.validate(password)
    if not valid then return nil, err end
    if not _M.ensure_schema() then return nil, "本地密码表不可用" end
    local rows = mysql.query("SELECT salt,password_hash,iterations FROM waf_admin_local_credential WHERE user_id=" .. tonumber(user_id) .. " LIMIT 1")
    if not rows then return nil, "读取本地密码失败" end
    local previous = rows[1]
    if previous then
        local iterations = tonumber(previous.iterations)
        if not iterations or iterations < 100000 or iterations > 1000000 then return nil, "本地密码配置无效" end
        if same(digest(password, previous.salt, iterations), previous.password_hash) then return nil, "新密码不能与当前密码相同" end
    end
    local salt = random_salt()
    if not salt then return nil, "安全随机源不可用" end
    local hash = digest(password, salt, ITERATIONS)
    local result = mysql.query("INSERT INTO waf_admin_local_credential (user_id,salt,password_hash,iterations,must_change_password) VALUES ("
        .. tonumber(user_id) .. "," .. quote(salt) .. "," .. quote(hash) .. "," .. ITERATIONS .. "," .. (must_change and 1 or 0)
        .. ") ON DUPLICATE KEY UPDATE salt=VALUES(salt),password_hash=VALUES(password_hash),iterations=VALUES(iterations),must_change_password=VALUES(must_change_password)")
    if not result then return nil, "保存本地密码失败" end
    return true
end

function _M.must_change(user_id)
    if not _M.ensure_schema() then return nil end
    local rows = mysql.query("SELECT must_change_password FROM waf_admin_local_credential WHERE user_id=" .. tonumber(user_id) .. " LIMIT 1")
    if not rows or not rows[1] then return nil end
    return tonumber(rows[1].must_change_password) == 1
end

function _M.verify(user_id, password)
    if not _M.ensure_schema() then return false end
    local rows = mysql.query("SELECT salt,password_hash,iterations FROM waf_admin_local_credential WHERE user_id="
        .. tonumber(user_id) .. " LIMIT 1")
    local row = rows and rows[1]
    if not row then return false end
    local iterations = tonumber(row.iterations)
    if not iterations or iterations < 100000 or iterations > 1000000 then return false end
    return same(digest(password, row.salt, iterations), row.password_hash)
end

return _M

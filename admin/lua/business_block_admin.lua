local cjson = require "cjson.safe"
local config = require "config"
local files = require "file_utils"

local _M = {}
local path = config.CONF_PATH .. "/global_rules/businessBlock.json"
local lock_key = "business_block:editing"

local function respond(code, message, data, count)
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.say(cjson.encode({code = code, msg = message or "", data = data or {}, count = count}))
end

local function read_rules()
    local f, err, errno = io.open(path, "rb")
    if not f then
        if errno == 2 then return {moduleName = "业务屏蔽", nextId = 1, rules = {}} end
        return nil, err
    end
    local text = f:read("*a")
    f:close()
    local data = cjson.decode(text)
    if type(data) ~= "table" or type(data.rules) ~= "table" then return nil, "规则文件格式错误" end
    return data, nil, text
end

local function valid_domain(domain)
    if #domain == 0 or #domain > 253 or domain:find("..", 1, true) or domain:sub(1, 1) == "." or domain:sub(-1) == "." or not domain:match("^[a-z0-9.%-]+$") then return false end
    for label in domain:gmatch("[^.]+") do
        if #label > 63 or label:sub(1, 1) == "-" or label:sub(-1) == "-" then return false end
    end
    return true
end

local function write_rules(text)
    local tmp = path .. ".tmp." .. ngx.worker.pid()
    local ok, err = files.write_string_to_file(tmp, text)
    if not ok then return nil, err end
    ok, err = os.rename(tmp, path)
    if not ok then os.remove(tmp); return nil, err end
    return true
end

local function modify(uri)
    ngx.req.read_body()
    local args = ngx.req.get_post_args()
    local rules, err, previous = read_rules()
    if not rules then return 500, "读取规则失败: " .. tostring(err) end
    local id = tonumber(args.id)
    local found, pos
    for i, rule in ipairs(rules.rules) do
        if id and tonumber(rule.id) == id then found, pos = rule, i; break end
    end
    if uri == "/ip/business-block/delete" then
        if not found then return 404, "规则不存在" end
        table.remove(rules.rules, pos)
    elseif uri == "/ip/business-block/save" then
        if args.id and args.id ~= "" and not found then return 404, "规则不存在" end
        if type(args.domain) ~= "string" or type(args.key) ~= "string" or type(args.value) ~= "string" then return 400, "请填写域名、参数名和参数值" end
        local domain = args.domain:match("^%s*(.-)%s*$"):lower():gsub("%.$", "")
        local key, value = args.key, args.value
        if not valid_domain(domain) then return 400, "请输入有效的精确域名" end
        if #key == 0 or #key > 256 or #value == 0 or #value > 2048 or key:find("[%c]") or value:find("[%c]") then return 400, "参数名或参数值为空、过长或包含控制字符" end
        for _, rule in ipairs(rules.rules) do
            if rule ~= found and rule.domain == domain and rule.key == key and rule.value == value then return 400, "相同的规则已存在" end
        end
        if not found then
            id = tonumber(rules.nextId) or 1
            for _, rule in ipairs(rules.rules) do id = math.max(id, (tonumber(rule.id) or 0) + 1) end
            rules.nextId = id + 1
            found = {id = id, state = "on"}
            rules.rules[#rules.rules + 1] = found
        end
        found.domain, found.key, found.value = domain, key, value
        found.action, found.autoIpBlock = "DENY", "off"
        found.severityLevel = "low"
        found.rule = "business_block_" .. tostring(id)
    else
        return 404, "接口不存在"
    end
    local encoded, encode_err = cjson.encode(rules)
    if not encoded then return 500, "编码规则失败: " .. tostring(encode_err) end
    local ok, write_err = write_rules(encoded)
    if not ok then return 500, "保存规则失败: " .. tostring(write_err) end
    local reload_ok, reload_err = config.reload_config_file()
    if not reload_ok then
        if not (config.is_centralized_mode() and config.is_master_node()) then
            if previous then write_rules(previous) else os.remove(path) end
        end
        return 500, "规则发布失败: " .. tostring(reload_err)
    end
    return 200, "操作成功"
end

function _M.handle(uri)
    if uri == "/ip/business-block/list" and ngx.req.get_method() == "GET" then
        local rules, err = read_rules()
        if not rules then return respond(500, "读取规则失败: " .. tostring(err)) end
        local args = ngx.req.get_uri_args()
        local domain = type(args.domain) == "string" and args.domain:lower() or ""
        local filtered = {}
        for _, rule in ipairs(rules.rules) do
            if domain == "" or rule.domain:find(domain, 1, true) then filtered[#filtered + 1] = rule end
        end
        local page = math.max(1, tonumber(args.page) or 1)
        local limit = math.min(100, math.max(1, tonumber(args.limit) or 20))
        local rows = {}
        for i = (page - 1) * limit + 1, math.min(page * limit, #filtered) do rows[#rows + 1] = filtered[i] end
        return respond(0, "", rows, #filtered)
    end
    if ngx.req.get_method() ~= "POST" then return respond(405, "请求方法不允许") end
    local lock = ngx.shared.dict_config
    local acquired = lock and lock:add(lock_key, true, 60)
    if not acquired then return respond(409, "规则正在保存，请稍后重试") end
    local ok, code, message = pcall(modify, uri)
    lock:delete(lock_key)
    if not ok then ngx.log(ngx.ERR, "business block update failed: ", code); return respond(500, "保存失败，请检查服务器日志") end
    return respond(code, message)
end

return _M

local cjson = require "cjson.safe"
local user = require "user"
local store = require "dingtalk_notification_store"

local function response(data)
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.say(cjson.encode(data))
end

local function require_manage()
    if user.has_permission("manage") then return true end
    response({code = 403, msg = "permission denied", data = {}})
    return false
end

local function post_args()
    ngx.req.read_body()
    local values, err = ngx.req.get_post_args()
    if not values then return nil, err or "invalid request" end
    return values
end

local function list_policies()
    local rows, err, total = store.list_policies(ngx.req.get_uri_args() or {})
    if not rows then return {code = 500, msg = err or "query throttle policies failed", data = {}} end
    return {code = 0, msg = "", count = total or 0, data = rows}
end

local function list_records()
    local rows, err, total = store.list_records(ngx.req.get_uri_args() or {})
    if not rows then return {code = 500, msg = err or "query notification records failed", data = {}} end
    return {code = 0, msg = "", count = total or 0, data = rows}
end

local function save_policy()
    if not require_manage() then return nil end
    local values, err = post_args()
    if not values then return {code = 400, msg = err} end
    local ok, save_err = store.save_policy(values)
    if not ok then return {code = 400, msg = save_err or "save throttle policy failed"} end
    return {code = 0, msg = "saved"}
end

local function delete_policy()
    if not require_manage() then return nil end
    local values, err = post_args()
    if not values then return {code = 400, msg = err} end
    local ok, delete_err = store.delete_policy(values.domain)
    if not ok then return {code = 400, msg = delete_err or "delete throttle policy failed"} end
    return {code = 0, msg = "deleted"}
end

if not user.check_auth_token() then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    response({code = 401, msg = "User not logged in", data = {}})
    return
end

local uri = ngx.var.uri
local result = {code = 404, msg = "not found", data = {}}
if uri == "/dingtalk-notification/policies" then
    result = list_policies()
elseif uri == "/dingtalk-notification/records" or uri == "/dingtalk-notification/failures" then
    result = list_records()
elseif uri == "/dingtalk-notification/policy/save" and ngx.req.get_method() == "POST" then
    result = save_policy()
elseif uri == "/dingtalk-notification/policy/delete" and ngx.req.get_method() == "POST" then
    result = delete_policy()
end

if result then response(result) end

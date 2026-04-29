-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)

local cjson = require "cjson"
local user = require "user"
local sql = require "sql"
local config = require "config"
local request = require "request"

local tonumber = tonumber
local cjson_encode = cjson.encode
local get_post_args = request.get_post_args

local _M = {}
local DEFAULT_PAGE = 1
local DEFAULT_LIMIT = 10
local MAX_LIMIT = 200

local function list_candidates()
    local response = { code = 0, data = {}, count = 0, msg = "" }
    local args = ngx.req.get_uri_args() or {}

    local page = tonumber(args.page) or DEFAULT_PAGE
    local limit = tonumber(args.limit) or DEFAULT_LIMIT
    if page < 1 then
        page = DEFAULT_PAGE
    end
    if limit < 1 then
        limit = DEFAULT_LIMIT
    elseif limit > MAX_LIMIT then
        limit = MAX_LIMIT
    end

    local rows, total, err = sql.list_rule_candidates(page, limit, {
        status = args.status,
        source = args.source,
        publish_status = args.publish_status,
        keyword = args.keyword
    })
    if not rows then
        response.code = 500
        response.msg = err or "query failed"
        return response
    end

    response.data = rows
    response.count = total or 0
    return response
end

local function run_candidates_now()
    local response = { code = 0, data = {}, msg = "执行成功" }
    local result = sql.run_rule_candidates_once()
    if not result or result.code ~= 0 then
        response.code = 500
        response.msg = (result and (result.msg or result.error)) or "执行失败"
        response.data = result or {}
        return response
    end

    response.data = result
    return response
end

local function review_candidate()
    local response = { code = 0, data = {}, msg = "操作成功" }
    local args, err = get_post_args()
    if not args then
        response.code = 400
        response.msg = err or "bad request"
        return response
    end

    local id = tonumber(args.id)
    local status = args.status
    local note = args.note
    if not id then
        response.code = 400
        response.msg = "invalid id"
        return response
    end
    if status ~= "approved" and status ~= "rejected" then
        response.code = 400
        response.msg = "invalid status"
        return response
    end

    local reviewer = ngx.var.remote_addr or "admin"
    local ok, review_err = sql.review_rule_candidate(id, status, note, reviewer)
    if not ok then
        response.code = 500
        response.msg = review_err or "update failed"
        return response
    end

    return response
end

local function publish_candidate()
    local response = { code = 0, data = {}, msg = "发布成功" }
    local args, err = get_post_args()
    if not args then
        response.code = 400
        response.msg = err or "bad request"
        return response, false
    end

    local id = tonumber(args.id)
    if not id then
        response.code = 400
        response.msg = "invalid id"
        return response, false
    end

    local publisher = ngx.var.remote_addr or "admin"
    local result = sql.publish_rule_candidate(id, publisher)
    if not result or result.code ~= 0 then
        response.code = (result and result.code) or 500
        response.msg = (result and (result.msg or result.error)) or "publish failed"
        response.data = result or {}
        return response, false
    end

    response.data = result
    if result.changed == false then
        response.msg = "规则已存在，状态已标记为已发布"
    end
    return response, true
end

function _M.do_request()
    local response = { code = 200, data = {}, msg = "" }
    local uri = ngx.var.uri
    local reload = false

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = "User not logged in"
        ngx.status = 401
        ngx.say(cjson_encode(response))
        ngx.exit(401)
        return
    end

    if not config.is_master_node() then
        response.code = 403
        response.msg = "only master can operate rule candidates"
        ngx.status = 403
        ngx.say(cjson_encode(response))
        return
    end

    if uri == "/rulecandidate/list" then
        response = list_candidates()
    elseif uri == "/rulecandidate/run" and ngx.req.get_method() == "POST" then
        response = run_candidates_now()
    elseif uri == "/rulecandidate/review" and ngx.req.get_method() == "POST" then
        response = review_candidate()
    elseif uri == "/rulecandidate/publish" and ngx.req.get_method() == "POST" then
        response, reload = publish_candidate()
    else
        response.code = 404
        response.msg = "not found"
    end

    ngx.say(cjson_encode(response))

    if reload and (response.code == 0 or response.code == 200) then
        config.reload_config_file()
    end
end

_M.do_request()

return _M

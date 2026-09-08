local cjson = require "cjson.safe"
local config = require "config"
local constants = require "constants"
local redis_cli = require "redis_cli"
local random = require "resty.random"
local store = require "program_release_store"
local user = require "user"

local RELEASE_ROOT = "/opt/openresty/zhongkui-program-releases"
local _M = {}

local function shell_quote(value)
    return "'" .. tostring(value or ""):gsub("'", "'\\''") .. "'"
end

local function current_username()
    local identity = user.get_current_user() or {}
    return identity.username or identity.display_name or "unknown"
end

local function get_local_ip()
    local f = io.popen("hostname -I 2>/dev/null || hostname -i 2>/dev/null")
    local line = f and f:read("*l") or nil
    if f then f:close() end
    return line and line:match("(%d+%.%d+%.%d+%.%d+)") or "127.0.0.1"
end

local function secure_id(seed)
    local bytes = random.bytes(32, true)
    return ngx.md5((bytes or "") .. ":" .. tostring(seed or "") .. ":" .. ngx.now())
end

local function post_args()
    ngx.req.read_body()
    local content_type = ngx.var.content_type or ""
    if content_type:find("application/json", 1, true) then
        return cjson.decode(ngx.req.get_body_data() or "{}") or {}
    end
    return ngx.req.get_post_args() or {}
end

local function deployment_options(args, nodes)
    local batch_size = math.floor(tonumber(args.batch_size) or 2)
    local batch_interval = math.floor(tonumber(args.batch_interval) or 60)
    if batch_size < 1 then batch_size = 1 elseif batch_size > 50 then batch_size = 50 end
    if batch_interval < 30 then batch_interval = 30 elseif batch_interval > 3600 then batch_interval = 3600 end
    local gray = tostring(args.gray_release or "") == "1" and #nodes > 1
    local canary_ip = tostring(args.canary_ip or "")
    local canary_index
    if gray then
        for index, node in ipairs(nodes) do
            if node.ip == canary_ip then canary_index = index; break end
        end
        canary_index = canary_index or 1
        local canary = table.remove(nodes, canary_index)
        table.insert(nodes, 1, canary)
        canary_ip = canary.ip
    else
        canary_ip = ""
    end
    return gray, batch_size, batch_interval, canary_ip
end

local function create_release()
    if not user.has_permission("release.manage") then return { code=403, msg="permission denied" } end
    local args = post_args()
    local version = tostring(args.version or constants.APP_VERSION)
    if version ~= constants.APP_VERSION then
        return { code=400, msg="只能创建 Master 当前程序版本 " .. constants.APP_VERSION }
    end
    local existing = store.get_release(version)
    if existing then return { code=400, msg="版本 " .. version .. " 已存在且不可修改" } end

    local script = config.ZHONGKUI_PATH .. "/bin/program_release.sh"
    local command = "bash " .. shell_quote(script) .. " " .. shell_quote(config.ZHONGKUI_PATH)
        .. " " .. shell_quote(RELEASE_ROOT) .. " " .. shell_quote(version) .. " 2>&1"
    local handle = io.popen(command)
    local output = handle and handle:read("*a") or ""
    local ok = handle and handle:close()
    if not ok then return { code=500, msg="创建版本快照失败: " .. output } end
    local checksum, file_count, total_bytes = output:match("([a-f0-9]+)|(%d+)|(%d+)")
    if not checksum then return { code=500, msg="无法读取版本清单结果" } end
    local saved, save_err = store.create_release({
        version=version, manifest_checksum=checksum, file_count=file_count,
        total_bytes=total_bytes, notes=args.notes, created_by=current_username()
    })
    if not saved then return { code=500, msg="保存版本记录失败: " .. tostring(save_err) } end
    return { code=0, msg="版本快照创建成功" }
end

local function deploy_release()
    if not user.has_permission("release.manage") then return { code=403, msg="permission denied" } end
    local args = post_args()
    local version = tostring(args.version or "")
    local release = store.get_release(version)
    if not release then return { code=404, msg="发布版本不存在" } end

    local nodes = {}
    if tostring(args.all_online) == "1" then
        nodes = store.list_online_nodes(300) or {}
    else
        for ip in tostring(args.node_ips or ""):gmatch("[^,]+") do
            ip = ip:match("^%s*(.-)%s*$")
            if ip:match("^%d+%.%d+%.%d+%.%d+$") then nodes[#nodes+1] = {ip=ip} end
        end
    end
    local master_ip = get_local_ip()
    local eligible, seen = {}, {}
    for _, node in ipairs(nodes) do
        if node.ip ~= master_ip and tostring(node.app_version or "") ~= version and not seen[node.ip] then
            seen[node.ip] = true
            eligible[#eligible + 1] = node
        end
    end
    nodes = eligible
    if #nodes == 0 then return {code=400,msg="没有需要更新的 Node"} end

    local gray, batch_size, batch_interval, canary_ip = deployment_options(args, nodes)
    local plan_id = secure_id("program-plan:" .. version)
    local token = secure_id("release:" .. version)
    local token_ok, token_err = redis_cli.set(constants.KEY_REDIS_PROGRAM_RELEASE_PREFIX .. version .. ":token", token, 604800)
    if not token_ok then return {code=500,msg="创建发布令牌失败: " .. tostring(token_err)} end
    local count = 0
    for index, node in ipairs(nodes) do
        local is_canary = gray and index == 1
        local batch_no = is_canary and 0 or (gray
            and (math.floor((index - 2) / batch_size) + 1)
            or (math.floor((index - 1) / batch_size) + 1))
        local saved, save_err = store.create_deployment({
            task_id=secure_id("task:" .. version .. ":" .. node.ip), plan_id=plan_id,
            batch_no=batch_no, is_canary=is_canary, batch_interval_seconds=batch_interval,
            release_version=version, node_ip=node.ip, created_by=current_username()
        })
        if saved then
            count = count + 1
        else
            ngx.log(ngx.ERR, "failed to create program deployment for ", node.ip, ": ", save_err)
        end
    end
    if count == 0 then return {code=500,msg="创建发布计划失败"} end
    store.reconcile_deployments()
    return {
        code=0,
        msg=(gray and ("灰度节点 " .. canary_ip .. " 已开始，") or "")
            .. "已创建 " .. count .. " 个 Node 的分批发布计划",
        count=count, plan_id=plan_id, gray_release=gray, canary_ip=canary_ip,
        batch_size=batch_size, batch_interval=batch_interval
    }
end

local function ensure_release_token(version)
    local key = constants.KEY_REDIS_PROGRAM_RELEASE_PREFIX .. version .. ":token"
    local current, get_err = redis_cli.get(key)
    if current and current ~= ngx.null and current ~= "" then return true end
    local saved, save_err = redis_cli.set(key, secure_id("release:" .. version), 604800)
    return saved, save_err or get_err
end

local function update_deployment(action)
    if not user.has_permission("release.manage") then return {code=403,msg="permission denied"} end
    local args = post_args()
    local task_id = tostring(args.task_id or "")
    if not task_id:match("^[%w%-]+$") then return {code=400,msg="任务标识无效"} end
    local deployment, lookup_err = store.get_deployment(task_id)
    if not deployment then return {code=404,msg="发布任务不存在: " .. tostring(lookup_err or "")} end

    if action == "retry" then
        if deployment.status ~= "failed" and deployment.status ~= "rolled_back" then
            return {code=400,msg="仅失败或已回滚的任务可以重新下发"}
        end
        local token_ok, token_err = ensure_release_token(deployment.release_version)
        if not token_ok then return {code=500,msg="准备发布令牌失败: " .. tostring(token_err or "")} end
        local updated = store.retry_deployment(task_id)
        if not updated or tonumber(updated.affected_rows or 0) < 1 then return {code=500,msg="重新下发任务失败或任务状态已变化"} end
        store.reconcile_deployments()
        return {code=0,msg="已重新下发 " .. deployment.node_ip .. "，等待 Node 领取"}
    end

    if deployment.status == "success" or deployment.status == "cancelled" then
        return {code=400,msg="当前任务不能跳过"}
    end
    local updated = store.skip_deployment(task_id)
    if not updated or tonumber(updated.affected_rows or 0) < 1 then return {code=500,msg="跳过任务失败或任务状态已变化"} end
    store.reconcile_deployments()
    return {code=0,msg="已跳过 " .. deployment.node_ip .. "，后续批次将继续调度"}
end

function _M.do_request()
    local ok, err = store.ensure_tables()
    local response
    if not ok then
        response = { code=500, msg="发布中心数据表初始化失败: " .. tostring(err) }
    elseif ngx.var.uri == "/programrelease/list" then
        local rows, list_err = store.list_releases()
        response = rows and {code=0,msg="",count=#rows,data=rows,current_version=constants.APP_VERSION}
            or {code=500,msg=tostring(list_err),data={}}
    elseif ngx.var.uri == "/programrelease/deployments" then
        store.reconcile_deployments()
        local rows, list_err = store.list_deployments()
        response = rows and {code=0,msg="",count=#rows,data=rows}
            or {code=500,msg=tostring(list_err),data={}}
    elseif ngx.var.uri == "/programrelease/create" and ngx.req.get_method() == "POST" then
        response = create_release()
    elseif ngx.var.uri == "/programrelease/deploy" and ngx.req.get_method() == "POST" then
        response = deploy_release()
    elseif ngx.var.uri == "/programrelease/retry" and ngx.req.get_method() == "POST" then
        response = update_deployment("retry")
    elseif ngx.var.uri == "/programrelease/skip" and ngx.req.get_method() == "POST" then
        response = update_deployment("skip")
    else
        response = {code=404,msg="invalid endpoint"}
    end
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.say(cjson.encode(response))
end

_M.do_request()
return _M

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
    local token = secure_id("release:" .. version)
    redis_cli.set(constants.KEY_REDIS_PROGRAM_RELEASE_PREFIX .. version .. ":token", token, 604800)
    local count = 0
    for _, node in ipairs(nodes) do
        if node.ip ~= master_ip and tostring(node.app_version or "") ~= version then
            local task_id = secure_id("task:" .. version .. ":" .. node.ip)
            local task = cjson.encode({
                task_id=task_id, version=version, token=token,
                manifest_checksum=release.manifest_checksum,
                base_url="http://" .. master_ip .. ":1226"
            })
            local queued, queue_err = redis_cli.set(constants.KEY_REDIS_PROGRAM_UPDATE_TASK_PREFIX .. node.ip, task, 604800)
            if queued then
                store.create_deployment({task_id=task_id,release_version=version,node_ip=node.ip,created_by=current_username()})
                count = count + 1
            else
                ngx.log(ngx.ERR, "failed to queue program deployment for ", node.ip, ": ", queue_err)
            end
        end
    end
    return { code=0, msg="已向 " .. count .. " 个 Node 下发版本任务", count=count }
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
    else
        response = {code=404,msg="invalid endpoint"}
    end
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.say(cjson.encode(response))
end

_M.do_request()
return _M

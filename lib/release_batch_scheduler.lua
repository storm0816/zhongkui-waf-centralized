local cjson = require "cjson.safe"
local constants = require "constants"
local mysql = require "mysql_cli"
local redis = require "redis_cli"

local _M = {}
local quote = ngx.quote_sql_str

local kinds = {
    program = {
        deployment_table = "waf_program_deployment",
        release_table = "waf_program_release",
        release_checksum = "manifest_checksum",
        token_prefix = constants.KEY_REDIS_PROGRAM_RELEASE_PREFIX,
        task_prefix = constants.KEY_REDIS_PROGRAM_UPDATE_TASK_PREFIX
    },
    geoip = {
        deployment_table = "waf_geoip_deployment",
        release_table = "waf_geoip_release",
        release_checksum = "checksum",
        token_prefix = constants.KEY_REDIS_GEOIP_RELEASE_PREFIX,
        task_prefix = constants.KEY_REDIS_GEOIP_UPDATE_TASK_PREFIX
    }
}

local function local_ip()
    local handle = io.popen("hostname -I 2>/dev/null || hostname -i 2>/dev/null")
    local line = handle and handle:read("*l") or nil
    if handle then handle:close() end
    return line and line:match("(%d+%.%d+%.%d+%.%d+)") or "127.0.0.1"
end

local function terminal(status)
    return status == "success" or status == "failed" or status == "rolled_back" or status == "cancelled"
end

local function update_waiting(cfg, rows, status, message)
    for _, row in ipairs(rows) do
        mysql.query("UPDATE " .. cfg.deployment_table .. " SET status=" .. quote(status)
            .. ",message=" .. quote(message) .. " WHERE task_id=" .. quote(row.task_id)
            .. " AND status IN ('scheduled','waiting_canary')")
    end
end

local function elapsed_after_batch(cfg, plan_id, batch_no)
    local rows = mysql.query("SELECT TIMESTAMPDIFF(SECOND,"
        .. "MAX(COALESCE(finished_at,queued_at,created_at)),NOW()) elapsed FROM "
        .. cfg.deployment_table .. " WHERE plan_id=" .. quote(plan_id)
        .. " AND batch_no=" .. tonumber(batch_no))
    return rows and rows[1] and tonumber(rows[1].elapsed) or 0
end

local function build_task(kind, row, token, master_ip)
    local task = {
        task_id = row.task_id,
        version = row.release_version,
        token = token,
        base_url = "http://" .. master_ip .. ":1226"
    }
    if kind == "program" then
        task.manifest_checksum = row.release_checksum
    else
        task.checksum = row.release_checksum
    end
    return cjson.encode(task)
end

local function dispatch_batch(kind, cfg, rows)
    if #rows == 0 then return true end
    local version = tostring(rows[1].release_version or "")
    local token, token_err = redis.get(cfg.token_prefix .. version .. ":token")
    if not token or token == ngx.null or token == "" then
        update_waiting(cfg, rows, "scheduled", "发布令牌已失效，请重新发起发布")
        return nil, token_err or "release token missing"
    end

    local master_ip = local_ip()
    local queued = 0
    for _, row in ipairs(rows) do
        local payload = build_task(kind, row, tostring(token), master_ip)
        local ok, err = redis.set(cfg.task_prefix .. row.node_ip, payload, 604800)
        if ok then
            mysql.query("UPDATE " .. cfg.deployment_table
                .. " SET status='queued',message=" .. quote("批次 " .. tostring(row.batch_no) .. " 已下发，等待 Node 领取")
                .. ",queued_at=NOW() WHERE task_id=" .. quote(row.task_id)
                .. " AND status IN ('scheduled','waiting_canary')")
            queued = queued + 1
        else
            ngx.log(ngx.ERR, "failed to queue ", kind, " deployment for ", row.node_ip, ": ", err)
        end
    end
    return queued == #rows, queued
end

local function dispatch_plan(kind, cfg, rows)
    local pending_batch
    local batches = {}
    local canary = {}
    for _, row in ipairs(rows) do
        local batch_no = tonumber(row.batch_no) or 1
        batches[batch_no] = batches[batch_no] or {}
        batches[batch_no][#batches[batch_no] + 1] = row
        if tonumber(row.is_canary) == 1 then canary[#canary + 1] = row end
        if row.status == "scheduled" or row.status == "waiting_canary" then
            if not pending_batch or batch_no < pending_batch then pending_batch = batch_no end
        end
    end
    if not pending_batch then return true end

    local current = batches[pending_batch] or {}
    if #canary > 0 and pending_batch > 0 then
        local all_success, has_failure = true, false
        for _, row in ipairs(canary) do
            if row.status ~= "success" then all_success = false end
            if row.status == "failed" or row.status == "rolled_back" or row.status == "cancelled" then
                has_failure = true
            end
        end
        if not all_success then
            update_waiting(cfg, current, "waiting_canary", has_failure
                and "灰度节点失败，后续批次已暂停" or "等待灰度节点验证成功")
            return true
        end
    end

    if pending_batch > 0 then
        local previous = batches[pending_batch - 1]
        if previous then
            for _, row in ipairs(previous) do
                if not terminal(row.status) then
                    update_waiting(cfg, current, "scheduled", "等待上一批次执行完成")
                    return true
                end
            end
            local interval = tonumber(current[1].batch_interval_seconds) or 60
            local elapsed = elapsed_after_batch(cfg, current[1].plan_id, pending_batch - 1)
            if elapsed < interval then
                update_waiting(cfg, current, "scheduled",
                    "上一批次已完成，等待批次间隔 " .. tostring(interval - elapsed) .. " 秒")
                return true
            end
        end
    end

    return dispatch_batch(kind, cfg, current)
end

local function dispatch_locked(kind, cfg)
    local sql = "SELECT d.task_id,d.release_version,d.node_ip,d.status,d.plan_id,d.batch_no,"
        .. "d.is_canary,d.batch_interval_seconds,d.queued_at,d.finished_at,r."
        .. cfg.release_checksum .. " release_checksum FROM " .. cfg.deployment_table
        .. " d JOIN " .. cfg.release_table .. " r ON r.version=d.release_version"
        .. " WHERE d.plan_id<>'' AND d.created_at>=NOW()-INTERVAL 7 DAY"
        .. " AND d.status<>'cancelled' ORDER BY d.plan_id,d.batch_no,d.node_ip"
    local rows, err = mysql.query(sql)
    if not rows then return nil, err end

    local plans = {}
    for _, row in ipairs(rows) do
        plans[row.plan_id] = plans[row.plan_id] or {}
        plans[row.plan_id][#plans[row.plan_id] + 1] = row
    end
    for _, plan_rows in pairs(plans) do
        local ok, dispatch_err = dispatch_plan(kind, cfg, plan_rows)
        if not ok and dispatch_err then
            ngx.log(ngx.ERR, "failed to dispatch ", kind, " release batch: ", dispatch_err)
        end
    end
    return true
end

function _M.dispatch(kind)
    local cfg = kinds[kind]
    if not cfg then return nil, "unsupported release kind" end
    local lock_token = tostring(ngx.worker.pid()) .. ":" .. tostring(ngx.now())
    local locked, lock_err = redis.acquire_lock("waf:lock:release_batch:" .. kind, lock_token, 20)
    if not locked then
        if lock_err then return nil, lock_err end
        return true
    end
    local called, ok, err = pcall(dispatch_locked, kind, cfg)
    redis.release_lock("waf:lock:release_batch:" .. kind, lock_token)
    if not called then return nil, ok end
    return ok, err
end

return _M

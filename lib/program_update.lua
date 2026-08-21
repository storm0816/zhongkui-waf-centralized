local cjson = require "cjson.safe"
local config = require "config"
local constants = require "constants"
local file_utils = require "file_utils"
local redis_cli = require "redis_cli"

local _M = {}

local state_dir = config.CONF_PATH .. "/.cluster"
local command_path = state_dir .. "/program-update.task"
local status_path = state_dir .. "/program-update-status.json"
local cached_node_id

local function ensure_state_dir()
    if file_utils.is_directory(state_dir) then return true end
    local ok, err = file_utils.mkdir(state_dir)
    if not ok and not file_utils.is_directory(state_dir) then return nil, err end
    return true
end

local function atomic_write(path, value)
    local ok, err = ensure_state_dir()
    if not ok then return nil, err end
    local temp = path .. ".tmp." .. tostring(ngx.worker.pid())
    ok, err = file_utils.write_string_to_file(temp, value)
    if not ok then return nil, err end
    local renamed, rename_err = os.rename(temp, path)
    if not renamed then
        os.remove(temp)
        return nil, rename_err
    end
    return true
end

local function get_node_id()
    if cached_node_id then return cached_node_id end
    local handle = io.popen("hostname -I 2>/dev/null || hostname -i 2>/dev/null")
    local line = handle and handle:read("*l") or nil
    if handle then handle:close() end
    cached_node_id = line and line:match("(%d+%.%d+%.%d+%.%d+)") or "unknown"
    return cached_node_id
end

function _M.read_status()
    local raw = file_utils.read_file_to_string(status_path)
    local status = raw and cjson.decode(raw) or nil
    return type(status) == "table" and status or {
        status = "idle",
        target_version = "",
        message = ""
    }
end

function _M.write_status(status)
    status = status or {}
    status.updated_at = status.updated_at or ngx.localtime()
    return atomic_write(status_path, cjson.encode(status))
end

function _M.poll(premature)
    if premature or not config.is_cluster_node() then return end
    local node_id = get_node_id()
    if node_id == "unknown" then return end

    local key = constants.KEY_REDIS_PROGRAM_UPDATE_TASK_PREFIX .. node_id
    local raw, err = redis_cli.get(key)
    if not raw then
        if err then ngx.log(ngx.WARN, "failed to read program update task: ", err) end
        return
    end
    local task = cjson.decode(raw)
    if type(task) ~= "table" or not tostring(task.task_id or ""):match("^[%w%-]+$")
        or not tostring(task.version or ""):match("^%d+%.%d+%.%d+[%w%.%-]*$")
        or not tostring(task.base_url or ""):match("^http://[%w%.:%-]+$")
        or not tostring(task.token or ""):match("^[%w%-]+$") then
        _M.write_status({ status = "failed", message = "invalid update task" })
        return
    end

    if tostring(task.version) == tostring(constants.APP_VERSION) then
        _M.write_status({
            task_id = task.task_id,
            target_version = task.version,
            status = "success",
            progress = 100,
            message = "program version is active"
        })
        redis_cli.del(key)
        os.remove(command_path)
        return
    end

    local current = file_utils.read_file_to_string(command_path) or ""
    if current:find("task_id=" .. task.task_id, 1, true) then return end

    local command = table.concat({
        "task_id=" .. task.task_id,
        "version=" .. task.version,
        "base_url=" .. task.base_url,
        "token=" .. task.token,
        "manifest_checksum=" .. tostring(task.manifest_checksum or ""),
        ""
    }, "\n")
    local ok, write_err = atomic_write(command_path, command)
    if not ok then
        _M.write_status({
            task_id = task.task_id,
            target_version = task.version,
            status = "failed",
            message = "failed to queue update: " .. tostring(write_err)
        })
        return
    end
    _M.write_status({
        task_id = task.task_id,
        target_version = task.version,
        status = "queued",
        progress = 0,
        message = "waiting for local updater"
    })
end

return _M

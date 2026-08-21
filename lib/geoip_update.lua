local cjson = require "cjson.safe"
local config = require "config"
local constants = require "constants"
local file_utils = require "file_utils"
local geoip_version = require "geoip_version"
local redis_cli = require "redis_cli"

local _M = {}
local state_dir = config.CONF_PATH .. "/.cluster"
local command_path = state_dir .. "/geoip-update.task"
local status_path = state_dir .. "/geoip-update-status.json"
local cached_node_id

local function ensure_state_dir()
    if file_utils.is_directory(state_dir) then return true end
    local ok, err = file_utils.mkdir(state_dir)
    if not ok and not file_utils.is_directory(state_dir) then return nil, err end
    return true
end

local function atomic_write(path, value)
    local ready, ready_err = ensure_state_dir()
    if not ready then return nil, ready_err end
    local temp = path .. ".tmp." .. tostring(ngx.worker.pid())
    local ok, err = file_utils.write_string_to_file(temp, value)
    if not ok then return nil, err end
    local renamed, rename_err = os.rename(temp, path)
    if not renamed then os.remove(temp); return nil, rename_err end
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
    return type(status) == "table" and status or { status="idle", target_version="", message="" }
end

function _M.poll(premature)
    if premature or not config.is_cluster_node() then return end
    local node_id = get_node_id()
    if node_id == "unknown" then return end
    local key = constants.KEY_REDIS_GEOIP_UPDATE_TASK_PREFIX .. node_id
    local raw, err = redis_cli.get(key)
    if not raw then
        if err then ngx.log(ngx.WARN, "failed to read GeoIP update task: ", err) end
        return
    end
    local task = cjson.decode(raw)
    if type(task) ~= "table" or not tostring(task.task_id or ""):match("^[%w%-]+$")
        or not tostring(task.version or ""):match("^[%w%.%-]+$")
        or not tostring(task.base_url or ""):match("^http://[%w%.:%-]+$")
        or not tostring(task.token or ""):match("^[%w%-]+$")
        or not tostring(task.checksum or ""):match("^[a-f0-9]+$") then
        return
    end
    local local_geoip = geoip_version.get_local()
    if local_geoip.checksum == task.checksum then
        atomic_write(status_path, cjson.encode({task_id=task.task_id,target_version=task.version,
            status="success",progress=100,message="GeoIP version is active",updated_at=ngx.localtime()}))
        redis_cli.del(key)
        os.remove(command_path)
        return
    end
    local current = file_utils.read_file_to_string(command_path) or ""
    if current:find("task_id=" .. task.task_id, 1, true) then return end
    local geoip = config.get_system_config("geoip") or {}
    local target_file = tostring(geoip.file or "/opt/openresty/share/GeoIP/GeoLite2-City.mmdb")
    local command = table.concat({
        "task_id=" .. task.task_id, "version=" .. task.version, "base_url=" .. task.base_url,
        "token=" .. task.token, "checksum=" .. task.checksum, "target_file=" .. target_file, ""
    }, "\n")
    local ok, write_err = atomic_write(command_path, command)
    if not ok then
        atomic_write(status_path, cjson.encode({task_id=task.task_id,target_version=task.version,
            status="failed",progress=0,message="failed to queue GeoIP update: " .. tostring(write_err),updated_at=ngx.localtime()}))
    end
end

return _M

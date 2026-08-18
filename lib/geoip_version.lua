local config = require "config"
local lfs = require "lfs"

local _M = {}

local cached_signature
local cached_result

local function shell_quote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function unknown(status, path)
    return {
        checksum = "unknown",
        status = status,
        file = path or "",
        size = 0,
        mtime = 0
    }
end

-- Hash only when the configured database file changes. Node heartbeats reuse this result.
function _M.get_local()
    local geoip = config.get_system_config("geoip") or {}
    local path = tostring(geoip.file or "")
    if path == "" then
        return unknown("missing", path)
    end

    local attr = lfs.attributes(path)
    if not attr or attr.mode ~= "file" then
        return unknown("missing", path)
    end

    local signature = path .. ":" .. tostring(attr.size or 0) .. ":" .. tostring(attr.modification or 0)
    if cached_signature == signature and cached_result then
        return cached_result
    end

    local handle = io.popen("sha256sum -- " .. shell_quote(path) .. " 2>/dev/null")
    if not handle then
        return unknown("failed", path)
    end

    local output = handle:read("*l") or ""
    handle:close()
    local checksum = output:match("^([a-fA-F0-9]+)%s")
    if not checksum or #checksum ~= 64 then
        return unknown("failed", path)
    end

    cached_signature = signature
    cached_result = {
        checksum = checksum:lower(),
        status = "ok",
        file = path,
        size = tonumber(attr.size) or 0,
        mtime = tonumber(attr.modification) or 0
    }
    return cached_result
end

return _M

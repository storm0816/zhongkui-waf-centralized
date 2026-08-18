local stringutf8 = require "stringutf8"

local trim = stringutf8.trim

local _M = {}

function _M.is_excluded(uri, value)
    if type(value) ~= "string" or value == "" then
        return false
    end

    uri = tostring(uri or "/")
    local normalized = value:gsub("\r\n", "\n"):gsub("\r", "\n")
    for line in normalized:gmatch("[^\n]+") do
        local pattern = trim(line)
        if pattern ~= "" then
            if pattern:sub(1, 1) == "=" then
                if uri == trim(pattern:sub(2)) then
                    return true
                end
            elseif uri:sub(1, #pattern) == pattern then
                return true
            end
        end
    end

    return false
end

return _M

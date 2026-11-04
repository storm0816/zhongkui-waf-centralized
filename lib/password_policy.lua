local _M = {}

function _M.validate(password)
    password = tostring(password or "")
    if #password < 8 then return nil, "密码至少需要 8 个字符" end
    if not password:find("[A-Za-z]") then return nil, "密码至少需要 1 个字母" end
    if not password:find("%d") then return nil, "密码至少需要 1 个数字" end
    if not password:find("%p") then return nil, "密码至少需要 1 个特殊字符" end
    return true
end

return _M

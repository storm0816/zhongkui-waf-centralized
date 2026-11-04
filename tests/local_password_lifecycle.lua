package.path = "lib/?.lua;admin/lua/?.lua;" .. package.path
bit = {bxor=function(a,b) return a == b and 0 or 1 end, bor=function(a,b) return a + b end}
ngx = {quote_sql_str=function(value) return "'" .. value .. "'" end}
package.preload["resty.string"] = function()
    return {to_hex=function(value)
        return (value:gsub(".", function(char) return string.format("%02x", char:byte()) end))
    end}
end
package.preload["resty.sha256"] = function()
    return {new=function() return {
        reset=function(self) self.value = nil end,
        update=function(self, value) self.value = value; return true end,
        final=function(self) return self.value end
    } end}
end
local saved
package.preload.mysql_cli = function()
    return {query=function(sql)
        if sql:find("^CREATE") then return {} end
        if sql:find("INFORMATION_SCHEMA") then return {{1}} end
        if sql:find("^SELECT") then return saved and {saved} or {} end
        if sql:find("^INSERT") then
            local salt, hash, iterations, flag = sql:match("VALUES %(%d+,'([^']+)','([^']+)',(%d+),(%d+)%)")
            assert(salt and hash)
            saved = {salt=salt, password_hash=hash, iterations=iterations, must_change_password=flag}
            return {}
        end
        error("unexpected query: " .. sql)
    end}
end
local credentials = require "local_credentials"
assert(credentials.set_password(1, "Example1!", true))
assert(credentials.must_change(1) == true)
assert(credentials.verify(1, "Example1!"))
assert(not credentials.set_password(1, "Example1!", false))
assert(credentials.set_password(1, "Example2!", false))
assert(credentials.must_change(1) == false)
assert(not credentials.verify(1, "Example1!"))
assert(credentials.verify(1, "Example2!"))
print("LOCAL_PASSWORD_LIFECYCLE_OK")

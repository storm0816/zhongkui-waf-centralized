-- Run with: lua tests/domain_host.lua
unpack = unpack or table.unpack

local entries = {}
local calls = {connections = 0, requests = 0, hits = 0}
local dict = {
    set = function(_, key, value) entries[key] = value end,
    get = function(_, key) return entries[key] end,
    get_keys = function()
        local keys = {}
        for key in pairs(entries) do keys[#keys + 1] = key end
        return keys
    end
}
ngx = {
    shared = {dict_config = dict},
    time = os.time,
    sha1_bin = function() return "hash" end,
    md5 = function(value) return value end,
    log = function() end,
    ERR = 1
}
package.preload["cjson.safe"] = function() return {} end
package.preload["config"] = function()
    return {is_system_option_on = function() return true end}
end
package.preload["constants"] = function() return {} end
package.preload["resty.string"] = function()
    return {to_hex = function(value) return value end}
end
package.preload["redis_cli"] = function()
    return {
        get_connection = function()
            calls.connections = calls.connections + 1
            return {evalsha = function()
                calls.requests = calls.requests + 1
                return 1
            end}
        end,
        close_connection = function() end,
        incr = function() calls.hits = calls.hits + 1 end
    }
end

local cc = assert(loadfile("lib/cc_cluster.lua"))()
for _, host in ipairs({"100.100.74.192", "100.112.212.143:8080", "121.36.145.98"}) do
    assert(not cc.is_reportable_domain(host))
    assert(cc.count_request(host, "192.0.2.1") == nil)
    cc.count_hit(host)
end
assert(calls.connections == 0 and calls.hits == 0, "IP Host must not create domain metrics")
assert(#cc.get_observed_domains() == 0, "IP Host must not be discovered")
assert(cc.is_reportable_domain("SITE.EXAMPLE:443"))
assert(cc.count_request("site.example", "192.0.2.1"))
cc.count_hit("site.example")
assert(calls.connections == 1 and calls.requests == 1 and calls.hits == 1)
assert(cc.get_observed_domains()[1] == "site.example")
print("DOMAIN_HOST_OK")

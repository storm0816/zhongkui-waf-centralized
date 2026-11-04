package.path = "admin/lua/?.lua;lib/?.lua;" .. package.path
local identity, method, response, deleted = nil, "POST", nil, 0
ngx = {HTTP_OK=200, header={}, var={}, req={
    get_method=function() return method end,
    read_body=function() end,
    get_uri_args=function() return {} end,
    get_post_args=function() return {name="attack_log_archive_20200106_20200112", confirmation="attack_log_archive_20200106_20200112"} end
}, say=function(value) response=value end}
package.preload["cjson.safe"] = function() return {encode=function(value) return value end} end
package.preload.user = function() return {
    deny_console_on_node=function() end,
    require_permission=function() return true end,
    get_current_user=function() return identity end
} end
package.preload.auth_store = function() return {} end
package.preload.ip_utils = function() return {} end
package.preload.archive_manager = function() return {delete=function() deleted=deleted+1; return {} end} end
local function run(user, verb)
    identity, method, response = user, verb, nil
    ngx.var.uri = "/access/archive/delete"
    dofile("admin/lua/access_control.lua")
    return response
end
local super = {{name="super_admin"}}
assert(run({username="ldap-user",roles=super}, "POST").code == 403 and deleted == 0)
assert(run({username="admin",roles={{name="readonly"}}}, "POST").code == 403 and deleted == 0)
assert(run({username="admin",roles=super}, "GET").code == 403 and deleted == 0)
assert(run({username="admin",roles=super}, "POST").code == 200 and deleted == 1)
print("ARCHIVE_PERMISSIONS_OK")

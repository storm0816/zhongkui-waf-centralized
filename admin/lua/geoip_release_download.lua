local constants = require "constants"
local config = require "config"
local redis_cli = require "redis_cli"

local RELEASE_ROOT = "/opt/openresty/zhongkui-geoip-releases"

local function deny(status, message)
    ngx.status = status
    ngx.header.content_type = "text/plain; charset=utf-8"
    ngx.say(message)
    return ngx.exit(status)
end

if not config.is_master_node() then return deny(403, "master only") end
local args = ngx.req.get_uri_args()
local version = tostring(args.version or "")
local token = tostring(args.token or "")
if not version:match("^[%w%.%-]+$") or not token:match("^[%w%-]+$") then return deny(400, "invalid request") end
local expected = redis_cli.get(constants.KEY_REDIS_GEOIP_RELEASE_PREFIX .. version .. ":token")
if not expected or expected ~= token then return deny(403, "invalid or expired token") end
if ngx.var.uri ~= "/node-geoip/file" then return deny(404, "not found") end

local file = io.open(RELEASE_ROOT .. "/" .. version .. "/GeoLite2-City.mmdb", "rb")
if not file then return deny(404, "file not found") end
ngx.header.content_type = "application/octet-stream"
while true do
    local chunk = file:read(65536)
    if not chunk then break end
    ngx.print(chunk)
end
file:close()

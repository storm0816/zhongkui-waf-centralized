local config = require "config"
local constants = require "constants"
local redis_cli = require "redis_cli"

local RELEASE_ROOT = "/opt/openresty/zhongkui-program-releases"

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
if not version:match("^%d+%.%d+%.%d+[%w%.%-]*$") or not token:match("^[%w%-]+$") then
    return deny(400, "invalid request")
end
local expected = redis_cli.get(constants.KEY_REDIS_PROGRAM_RELEASE_PREFIX .. version .. ":token")
if not expected or expected ~= token then return deny(403, "invalid or expired token") end

local path
if ngx.var.uri == "/node-release/manifest" then
    path = RELEASE_ROOT .. "/" .. version .. "/manifest.txt"
    ngx.header.content_type = "text/plain"
elseif ngx.var.uri == "/node-release/file" then
    local relative = tostring(args.path or "")
    if relative == "" or relative:find("..", 1, true) or relative:sub(1,1) == "/" then
        return deny(400, "invalid path")
    end
    path = RELEASE_ROOT .. "/" .. version .. "/files/" .. relative
    ngx.header.content_type = "application/octet-stream"
else
    return deny(404, "not found")
end

local file = io.open(path, "rb")
if not file then return deny(404, "file not found") end
while true do
    local chunk = file:read(65536)
    if not chunk then break end
    ngx.print(chunk)
end
file:close()

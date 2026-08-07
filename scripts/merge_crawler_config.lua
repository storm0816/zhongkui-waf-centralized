local ok, cjson = pcall(require, "cjson.safe")
if not ok then
    cjson = require "cjson"
end

local config_path = arg[1]
if not config_path or config_path == "" then
    io.stderr:write("missing global.json path\n")
    os.exit(1)
end

local file, open_err = io.open(config_path, "rb")
if not file then
    io.stderr:write("failed to open " .. config_path .. ": " .. tostring(open_err) .. "\n")
    os.exit(1)
end

local raw = file:read("*a")
file:close()

local config, decode_err = cjson.decode(raw)
if type(config) ~= "table" then
    io.stderr:write("failed to decode " .. config_path .. ": " .. tostring(decode_err) .. "\n")
    os.exit(1)
end

local crawler_defaults = {
    state = "off",
    mode = "bot",
    duration = 60,
    threshold = 120,
    action = "deny",
    autoIpBlock = "off",
    ipBlockExpireInSeconds = 600,
    userAgentPattern = "(?:bot|spider|crawler|slurp|bingpreview|facebookexternalhit|headless|python-requests|scrapy|curl|wget|go-http-client|java/)",
    allowUserAgentPattern = "",
    excludeUris = "/favicon.ico\n/static/\n/assets/"
}

local robots_defaults = {
    state = "on",
    content = "User-agent: *\nAllow: /"
}

local function fill_missing(target, defaults)
    if type(target) ~= "table" then
        target = {}
    end
    for key, value in pairs(defaults) do
        if target[key] == nil then
            target[key] = value
        end
    end
    return target
end

if type(config.bot) ~= "table" then
    config.bot = { state = "on" }
end
config.bot.crawler = fill_missing(config.bot.crawler, crawler_defaults)
config.bot.robots = fill_missing(config.bot.robots, robots_defaults)

local encoded, encode_err = cjson.encode(config)
if not encoded then
    io.stderr:write("failed to encode " .. config_path .. ": " .. tostring(encode_err) .. "\n")
    os.exit(1)
end

local temp_path = config_path .. ".crawler-upgrade.tmp"
local output, write_err = io.open(temp_path, "wb")
if not output then
    io.stderr:write("failed to write " .. temp_path .. ": " .. tostring(write_err) .. "\n")
    os.exit(1)
end
output:write(encoded, "\n")
output:close()

local renamed, rename_err = os.rename(temp_path, config_path)
if not renamed then
    os.remove(temp_path)
    io.stderr:write("failed to replace " .. config_path .. ": " .. tostring(rename_err) .. "\n")
    os.exit(1)
end

print("crawler and robots configuration merged")

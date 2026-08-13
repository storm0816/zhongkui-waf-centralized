-- DingTalk notification module for OpenResty
local config = require "config"
local cjson = require "cjson.safe"

local _M = {}

local function send_request(webhook, body)
    local sock = ngx.socket.tcp()
    sock:settimeout(10000)

    local ok, err = sock:connect("oapi.dingtalk.com", 443)
    if not ok then
        ngx.log(ngx.ERR, "[dingtalk] connect failed: ", err)
        return false, err
    end

    local ok, ssl_err = sock:sslhandshake(nil, "oapi.dingtalk.com", false)
    if not ok then
        ngx.log(ngx.ERR, "[dingtalk] ssl handshake failed: ", ssl_err)
        sock:close()
        return false, ssl_err
    end

    -- Extract path and query string from webhook URL
    local path = webhook:match("https?://[^/]+(/.*)") or "/robot/send"

    local req = "POST " .. path .. " HTTP/1.1\r\n"
        .. "Host: oapi.dingtalk.com\r\n"
        .. "Content-Type: application/json\r\n"
        .. "Content-Length: " .. #body .. "\r\n"
        .. "Connection: close\r\n\r\n"
        .. body

    local ok, send_err = sock:send(req)
    if not ok then
        ngx.log(ngx.ERR, "[dingtalk] send failed: ", send_err)
        sock:close()
        return false, send_err
    end

    local response, recv_err = sock:receive("*a")
    sock:close()

    if not response then
        ngx.log(ngx.ERR, "[dingtalk] recv failed: ", recv_err)
        return false, recv_err
    end

    local resp_body = response:match("\r\n\r\n(.*)$")
    if resp_body then
        local resp_data = cjson.decode(resp_body)
        if resp_data and resp_data.errcode ~= 0 then
            ngx.log(ngx.WARN, "[dingtalk] send failed: errcode=", resp_data.errcode, " errmsg=", resp_data.errmsg)
            return false, resp_data.errmsg
        end
    end

    return true
end

function _M.notify_ip_block(block_info)
    local cfg = config.get_system_config("dingtalk")
    if not cfg or cfg.state ~= "on" then
        return
    end

    local webhook = cfg.webhook
    if not webhook or webhook == "" then
        return
    end

    local at_mobiles = cfg.at_mobiles or ""
    local at_list = {}
    for mobile in at_mobiles:gmatch("[%d]+") do
        table.insert(at_list, mobile)
    end

    local msg = "【钟馗WAF】IP 已自动封禁"
    if block_info and block_info.ip and block_info.ip ~= "" then
        msg = msg .. "\n来源IP: " .. block_info.ip
    end
    if block_info and block_info.attack_type and block_info.attack_type ~= "" then
        msg = msg .. "\n封禁原因: " .. block_info.attack_type
    end
    if block_info and block_info.duration then
        local duration = tonumber(block_info.duration) or 0
        msg = msg .. "\n封禁时长: " .. (duration > 0 and (duration .. " 秒") or "永久")
    end
    if block_info and block_info.server and block_info.server ~= "" then
        msg = msg .. "\n目标: " .. block_info.server
    end
    if block_info and block_info.uri and block_info.uri ~= "" then
        local uri = block_info.uri
        if #uri > 100 then uri = uri:sub(1, 100) .. "..." end
        msg = msg .. "\nURI: " .. uri
    end

    local body = cjson.encode({
        msgtype = "text",
        text = { content = msg },
        at = { atMobiles = at_list, isAtAll = false }
    })
    if not body then
        ngx.log(ngx.ERR, "[dingtalk] ip block json encode failed")
        return
    end

    ngx.log(ngx.NOTICE, "[dingtalk] sending ip block notification")
    local ok, err = send_request(webhook, body)
    if ok then
        ngx.log(ngx.NOTICE, "[dingtalk] ip block notification sent successfully")
    else
        ngx.log(ngx.ERR, "[dingtalk] ip block notification failed: ", err)
    end
end

return _M

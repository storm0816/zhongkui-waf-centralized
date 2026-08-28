-- DingTalk notification module for OpenResty
local config = require "config"
local cjson = require "cjson.safe"
local notification_store = require "dingtalk_notification_store"

local _M = {}

local function get_at_list(cfg)
    local at_list = {}
    for mobile in tostring(cfg.at_mobiles or ""):gmatch("[%d]+") do
        table.insert(at_list, mobile)
    end
    return at_list
end

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
        return false, "dingtalk disabled", "skipped"
    end

    local webhook = cfg.webhook
    if not webhook or webhook == "" then
        return false, "dingtalk webhook is empty", "skipped"
    end

    local at_list = get_at_list(cfg)

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
        notification_store.record_failure(block_info, "json encode failed")
        return false, "json encode failed", "failed"
    end

    local domain = notification_store.normalize_domain(block_info and block_info.server)
    local policy = notification_store.get_policy(domain)
    if policy and tostring(policy.state) == "on" then
        local add_summary = config.is_centralized_mode()
            and notification_store.add_summary_block
            or notification_store.add_local_summary_block
        local added, summary_err = add_summary(domain, policy.interval_minutes)
        if added then
            ngx.log(ngx.NOTICE, "[dingtalk] ip block added to summary, domain=", domain)
            return true, nil, "aggregated"
        end
        ngx.log(ngx.WARN, "[dingtalk] summary counter unavailable, fail open, domain=", domain, " err=", summary_err)
    end

    ngx.log(ngx.NOTICE, "[dingtalk] sending ip block notification")
    local ok, err = send_request(webhook, body)
    if ok then
        ngx.log(ngx.NOTICE, "[dingtalk] ip block notification sent successfully")
        notification_store.record_success(block_info)
        return true, nil, "sent"
    else
        notification_store.record_failure(block_info, err)
        ngx.log(ngx.ERR, "[dingtalk] ip block notification failed: ", err)
        return false, err, "failed"
    end
end

function _M.flush_block_summaries()
    local cfg = config.get_system_config("dingtalk")
    if not cfg or cfg.state ~= "on" or not cfg.webhook or cfg.webhook == "" then return end
    local policies, err = notification_store.list_enabled_policies()
    if not policies then ngx.log(ngx.ERR, "[dingtalk] load summary policies failed: ", err or "nil"); return end
    local policy_map = {}
    for _, policy in ipairs(policies) do
        policy_map[notification_store.normalize_domain(policy.domain)] = tonumber(policy.interval_minutes) or 0
    end

    local now = ngx.time()
    local rows, list_err
    if config.is_centralized_mode() then
        rows, list_err = notification_store.list_due_summary_blocks(now, 200)
    else
        rows, list_err = notification_store.list_due_local_summary_blocks(now, 200)
    end
    if not rows then
        ngx.log(ngx.ERR, "[dingtalk] list due summaries failed: ", list_err or "nil")
        return
    end

    for _, item in ipairs(rows) do
        local domain = notification_store.normalize_domain(item.domain)
        local interval = tonumber(item.interval_minutes) or 0
        local bucket = tonumber(item.bucket) or 0
        local count = tonumber(item.block_count) or 0
        local seconds = interval * 60
        local complete = config.is_centralized_mode()
            and notification_store.complete_summary_block
            or notification_store.complete_local_summary_block

        if policy_map[domain] ~= interval or interval <= 0 or bucket <= 0 or count <= 0 then
            local removed, remove_err = complete(item)
            if not removed then
                ngx.log(ngx.ERR, "[dingtalk] discard stale summary failed, domain=", domain,
                    " err=", remove_err or "nil")
            end
        else
            local event_key = string.format("summary:%d:%d", interval, bucket)
            if notification_store.was_summary_sent(domain, event_key) then
                local removed, remove_err = complete(item)
                if not removed then
                    ngx.log(ngx.ERR, "[dingtalk] cleanup delivered summary failed, domain=", domain,
                        " err=", remove_err or "nil")
                end
            else
                local msg = string.format("【钟馗WAF】封禁汇总\n域名：%s\n统计周期：%d 分钟\n累计封禁：%d 次\n统计时间：%s 至 %s",
                    domain, interval, count, os.date("%Y-%m-%d %H:%M:%S", bucket),
                    os.date("%Y-%m-%d %H:%M:%S", bucket + seconds))
                local body = cjson.encode({msgtype="text", text={content=msg},
                    at={atMobiles=get_at_list(cfg), isAtAll=false}})
                local ok, send_err = send_request(cfg.webhook, body)
                local info = {server=domain, attack_type="block_summary", action="SUMMARY", uri=event_key}
                if ok then
                    local recorded = notification_store.record_success(info)
                    if not recorded then
                        ngx.log(ngx.ERR, "[dingtalk] record summary success failed, domain=", domain)
                    end
                    local removed, remove_err = complete(item)
                    if not removed then
                        ngx.log(ngx.ERR, "[dingtalk] cleanup sent summary failed, domain=", domain,
                            " err=", remove_err or "nil")
                    end
                else
                    notification_store.record_failure(info, send_err)
                    local retried, retry_err = notification_store.retry_summary_block(item, send_err)
                    if not retried then
                        ngx.log(ngx.ERR, "[dingtalk] reschedule summary failed, domain=", domain,
                            " err=", retry_err or "nil")
                    end
                end
            end
        end
    end
end

return _M

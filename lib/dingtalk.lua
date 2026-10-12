-- DingTalk notification module for OpenResty
local config = require "config"
local cjson = require "cjson.safe"
local notification_store = require "dingtalk_notification_store"
local has_openssl_hmac, openssl_hmac = pcall(require, "openssl.hmac")

local _M = {}
-- Conservative application cap for one encoded summary request, not a DingTalk API limit.
local MAX_SUMMARY_BODY_BYTES = 3500

local function hmac_sha256(key, message)
    if not has_openssl_hmac then
        return nil, "openssl.hmac is unavailable"
    end
    local context, new_err = openssl_hmac.new(key, "sha256")
    if not context then
        return nil, new_err or "create HMAC context failed"
    end
    return context:final(message)
end

local function signed_webhook(webhook, secret)
    secret = tostring(secret or "")
    if secret == "" then
        return webhook
    end

    local timestamp = tostring(math.floor(ngx.now() * 1000))
    local digest, err = hmac_sha256(secret, timestamp .. "\n" .. secret)
    if not digest then
        return nil, err
    end
    local separator = webhook:find("?", 1, true) and "&" or "?"
    return webhook .. separator .. "timestamp=" .. timestamp .. "&sign=" .. ngx.escape_uri(ngx.encode_base64(digest))
end

local function append_at_mobiles(at_list, seen, mobiles)
    for mobile in tostring(mobiles or ""):gmatch("[%d]+") do
        if not seen[mobile] then
            seen[mobile] = true
            table.insert(at_list, mobile)
        end
    end
end

local function get_at_list(cfg, policy_mobile, notify_global)
    local at_list = {}
    local seen = {}
    local has_policy_mobile = tostring(policy_mobile or "") ~= ""
    if has_policy_mobile then
        append_at_mobiles(at_list, seen, policy_mobile)
    end
    if not has_policy_mobile or tostring(notify_global or "on") ~= "off" then
        append_at_mobiles(at_list, seen, cfg.at_mobiles)
    end
    return at_list
end

local function send_request(webhook, body, secret)
    local signed, sign_err = signed_webhook(webhook, secret)
    if not signed then
        ngx.log(ngx.ERR, "[dingtalk] sign request failed: ", sign_err or "nil")
        return false, sign_err or "sign request failed"
    end

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
    local path = signed:match("https?://[^/]+(/.*)") or "/robot/send"

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
    if block_info and block_info.domain and block_info.domain ~= "" then
        msg = msg .. "\n域名: " .. block_info.domain
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

    local domain = notification_store.normalize_domain(block_info and (block_info.domain or block_info.server))
    local policy = notification_store.get_policy(domain)
    if policy and tostring(policy.state) == "on" then
        local add_summary = config.is_centralized_mode()
            and notification_store.add_summary_block
            or notification_store.add_local_summary_block
        local added, summary_err = add_summary(domain, policy.interval_minutes, policy.summary_time)
        if added then
            ngx.log(ngx.NOTICE, "[dingtalk] ip block added to summary, domain=", domain)
            return true, nil, "aggregated"
        end
        ngx.log(ngx.WARN, "[dingtalk] summary counter unavailable, fail open, domain=", domain, " err=", summary_err)
    end

    ngx.log(ngx.NOTICE, "[dingtalk] sending ip block notification")
    local ok, err = send_request(webhook, body, cfg.secret)
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

local function summary_info(item)
    return {server=item.domain, attack_type="block_summary", action="SUMMARY", uri=item.event_key}
end

local function finish_summary_item(item, delivered, err, complete)
    local info = summary_info(item)
    if delivered then
        if notification_store.record_success(info) then
            local removed, remove_err = complete(item)
            if not removed then
                ngx.log(ngx.ERR, "[dingtalk] cleanup sent summary failed, domain=", item.domain,
                    " err=", remove_err or "nil")
            end
            return
        end
        err = "record summary success failed"
        ngx.log(ngx.ERR, "[dingtalk] ", err, ", domain=", item.domain)
    else
        notification_store.record_failure(info, err)
    end
    local retried, retry_err = notification_store.retry_summary_block(item, err)
    if not retried then
        ngx.log(ngx.ERR, "[dingtalk] reschedule summary failed, domain=", item.domain,
            " err=", retry_err or "nil")
    end
end

local function encode_summary_batch(group, items)
    local total = 0
    local lines = {}
    for _, item in ipairs(items) do
        total = total + item.block_count
        lines[#lines + 1] = string.format("%s：%d 次", item.domain, item.block_count)
    end
    local content = string.format("【钟馗WAF】封禁汇总\n统计周期：%d 分钟\n统计时间：%s 至 %s\n域名数：%d，累计封禁：%d 次\n%s",
        group.interval, os.date("%Y-%m-%d %H:%M:%S", group.bucket),
        os.date("%Y-%m-%d %H:%M:%S", group.due_at), #items, total, table.concat(lines, "\n"))
    return cjson.encode({msgtype="text", text={content=content},
        at={atMobiles=group.at_mobiles, isAtAll=false}})
end

local function send_summary_batch(cfg, group, items, complete)
    local body = encode_summary_batch(group, items)
    local ok, err
    if not body then
        ok, err = false, "encode summary batch failed"
    elseif #body > MAX_SUMMARY_BODY_BYTES then
        ok, err = false, "summary batch exceeds byte limit"
    else
        ok, err = send_request(cfg.webhook, body, cfg.secret)
    end
    for _, item in ipairs(items) do
        finish_summary_item(item, ok, err, complete)
    end
end

function _M.flush_block_summaries()
    local cfg = config.get_system_config("dingtalk")
    if not cfg or cfg.state ~= "on" or not cfg.webhook or cfg.webhook == "" then return end
    local policies, err = notification_store.list_enabled_policies()
    if not policies then ngx.log(ngx.ERR, "[dingtalk] load summary policies failed: ", err or "nil"); return end
    local policy_map = {}
    for _, policy in ipairs(policies) do
        policy_map[notification_store.normalize_domain(policy.domain)] = {
            interval_minutes = tonumber(policy.interval_minutes) or 0,
            summary_time = tostring(policy.summary_time or "00:00"),
            at_mobile = tostring(policy.at_mobile or ""),
            notify_global = tostring(policy.notify_global or "on")
        }
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

    local groups = {}
    local group_list = {}
    local complete = config.is_centralized_mode()
        and notification_store.complete_summary_block
        or notification_store.complete_local_summary_block
    for _, item in ipairs(rows) do
        local domain = notification_store.normalize_domain(item.domain)
        local interval = tonumber(item.interval_minutes) or 0
        local summary_time = tostring(item.summary_time or "00:00")
        local bucket = tonumber(item.bucket) or 0
        local count = tonumber(item.block_count) or 0
        local seconds = interval * 60
        local policy = policy_map[domain]
        if not policy or policy.interval_minutes ~= interval or policy.summary_time ~= summary_time
            or interval <= 0 or bucket <= 0 or count <= 0 then
            local removed, remove_err = complete(item)
            if not removed then
                ngx.log(ngx.ERR, "[dingtalk] discard stale summary failed, domain=", domain,
                    " err=", remove_err or "nil")
            end
        else
            local event_key = string.format("summary:%d:%s:%d", interval, summary_time, bucket)
            if notification_store.was_summary_sent(domain, event_key) then
                local removed, remove_err = complete(item)
                if not removed then
                    ngx.log(ngx.ERR, "[dingtalk] cleanup delivered summary failed, domain=", domain,
                        " err=", remove_err or "nil")
                end
            else
                local at_mobiles = get_at_list(cfg, policy.at_mobile, policy.notify_global)
                table.sort(at_mobiles)
                local due_at = bucket + seconds
                local group_key = table.concat({tostring(due_at), tostring(interval),
                    table.concat(at_mobiles, ",")}, ":")
                local group = groups[group_key]
                if not group then
                    group = {key=group_key, interval=interval, bucket=bucket,
                        due_at=due_at, at_mobiles=at_mobiles, items={}}
                    groups[group_key] = group
                    group_list[#group_list + 1] = group
                end
                item.domain = domain
                item.block_count = count
                item.event_key = event_key
                group.items[#group.items + 1] = item
            end
        end
    end

    table.sort(group_list, function(a, b) return a.key < b.key end)
    for _, group in ipairs(group_list) do
        table.sort(group.items, function(a, b) return a.domain < b.domain end)
        local batch = {}
        for _, item in ipairs(group.items) do
            local candidate = {}
            for index, queued in ipairs(batch) do candidate[index] = queued end
            candidate[#candidate + 1] = item
            local body = encode_summary_batch(group, candidate)
            if body and #body <= MAX_SUMMARY_BODY_BYTES then
                batch = candidate
            else
                if #batch > 0 then send_summary_batch(cfg, group, batch, complete) end
                batch = {item}
                local single_body = encode_summary_batch(group, batch)
                if not single_body or #single_body > MAX_SUMMARY_BODY_BYTES then
                    send_summary_batch(cfg, group, batch, complete)
                    batch = {}
                end
            end
        end
        if #batch > 0 then send_summary_batch(cfg, group, batch, complete) end
    end
end

return _M

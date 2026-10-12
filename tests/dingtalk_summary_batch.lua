-- Development regression test only; not loaded by the WAF runtime.
local requests, successes, failures, completed, retried = {}, {}, {}, {}, {}
local policies, due_rows, sent_keys = {}, {}, {}
local response_code = 0
local centralized = true
local cfg = {state="on", webhook="https://oapi.dingtalk.com/robot/send?access_token=test",
    at_mobiles="13800138000", secret=""}

local function escape(value)
    return tostring(value):gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n")
end

package.preload["cjson.safe"] = function()
    return {
        encode = function(value)
            local mobiles = {}
            for _, mobile in ipairs(value.at.atMobiles) do
                mobiles[#mobiles + 1] = '"' .. escape(mobile) .. '"'
            end
            return '{"msgtype":"text","text":{"content":"' .. escape(value.text.content)
                .. '"},"at":{"atMobiles":[' .. table.concat(mobiles, ",") .. '],"isAtAll":false}}'
        end,
        decode = function(value)
            return {errcode=tonumber(value:match('"errcode":(%d+)')),
                errmsg=value:match('"errmsg":"([^"]*)"')}
        end
    }
end
package.preload["config"] = function()
    return {get_system_config=function() return cfg end, is_centralized_mode=function() return centralized end}
end
package.preload["dingtalk_notification_store"] = function()
    return {
        normalize_domain=function(domain) return string.lower(domain or "") end,
        list_enabled_policies=function() return policies end,
        list_due_summary_blocks=function() return due_rows end,
        list_due_local_summary_blocks=function() return due_rows end,
        was_summary_sent=function(domain, key) return sent_keys[domain .. key] == true end,
        complete_summary_block=function(item) completed[#completed + 1] = item.domain; return true end,
        complete_local_summary_block=function(item) completed[#completed + 1] = item.domain; return true end,
        record_success=function(info) successes[#successes + 1] = info.server; return true end,
        record_failure=function(info) failures[#failures + 1] = info.server; return true end,
        retry_summary_block=function(item) retried[#retried + 1] = item.domain; return true end
    }
end

ngx = {
    ERR=1, WARN=2, NOTICE=3,
    log=function() end,
    time=function() return 1086410 end,
    socket={tcp=function()
        return {
            settimeout=function() end,
            connect=function() return true end,
            sslhandshake=function() return true end,
            send=function(_, request) requests[#requests + 1] = request:match("\r\n\r\n(.*)$"); return true end,
            receive=function()
                return 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"errcode":'
                    .. response_code .. ',"errmsg":"failed"}'
            end,
            close=function() end
        }
    end}
}

local dingtalk = dofile("lib/dingtalk.lua")
local function reset()
    requests, successes, failures, completed, retried = {}, {}, {}, {}, {}
    policies, due_rows, sent_keys = {}, {}, {}
    response_code = 0
    centralized = true
end
local function add(domain, mobile, notify_global, count)
    policies[#policies + 1] = {domain=domain, interval_minutes=1440,
        summary_time="10:00", at_mobile=mobile or "", notify_global=notify_global or "on"}
    due_rows[#due_rows + 1] = {domain=domain, interval_minutes=1440,
        summary_time="10:00", bucket=1000000, block_count=count or 1}
end
local function check(condition, message)
    assert(condition, message)
end

reset()
add("a.example.com", "", "on", 2)
add("b.example.com", "", "on", 3)
add("c.example.com", "13900139000", "off", 4)
dingtalk.flush_block_summaries()
check(#requests == 2, "different recipients must produce separate messages")
check(requests[1]:find("a.example.com", 1, true) and requests[1]:find("b.example.com", 1, true),
    "same recipients should share one message")
check(not requests[1]:find("c.example.com", 1, true), "recipient groups must not mix")
check(requests[2]:find("13900139000", 1, true), "policy recipient missing")
check(#successes == 3 and #completed == 3, "each domain must retain its delivery record")

reset()
cfg.at_mobiles = "13800138000,13900139000"
add("a.example.com", "13900139000", "on")
add("b.example.com", "13800138000", "on")
dingtalk.flush_block_summaries()
check(#requests == 1 and #successes == 2,
    "equivalent recipient sets in different order should share one message")
cfg.at_mobiles = "13800138000"

reset()
for index=1, 120 do add(string.format("%03d-%s.example.com", index, string.rep("x", 50))) end
dingtalk.flush_block_summaries()
check(#requests > 1, "large summary must be split")
for _, body in ipairs(requests) do check(#body <= 3500, "request body exceeded byte cap") end
check(#successes == 120 and #completed == 120, "split summary lost a domain")

reset()
add("a.example.com")
add("b.example.com")
response_code = 429
dingtalk.flush_block_summaries()
check(#requests == 1 and #failures == 2 and #retried == 2 and #completed == 0,
    "failed batch must retry every domain")

reset()
add("a.example.com")
add("b.example.com")
sent_keys["a.example.comsummary:1440:10:00:1000000"] = true
dingtalk.flush_block_summaries()
check(#requests == 1 and not requests[1]:find("a.example.com", 1, true),
    "previously delivered domain was sent again")
check(#completed == 2 and #successes == 1, "previous delivery cleanup failed")

reset()
centralized = false
add("a.example.com")
add("b.example.com")
dingtalk.flush_block_summaries()
check(#requests == 1 and #successes == 2 and #completed == 2,
    "standalone summary did not merge or complete")

print("DINGTALK_SUMMARY_BATCH_OK")

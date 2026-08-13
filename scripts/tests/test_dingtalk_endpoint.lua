-- test_dingtalk_endpoint.lua - 通过 HTTP endpoint 测试钉钉通知
-- 将此文件放在项目的某个路径，然后在 nginx.conf 中添加:
-- location /test-dingtalk {
--     content_by_lua_file /opt/openresty/zhongkui-waf/scripts/test_dingtalk_endpoint.lua;
-- }

local dingtalk = require "dingtalk"

local attack_info = {
    count = 1,
    ip = "192.168.1.1",
    attack_type = "测试攻击",
    server = ngx.var.host,
    uri = ngx.var.request_uri
}

ngx.header.content_type = "application/json"

local cfg = require("config").get_system_config("dingtalk")
if not cfg or cfg.state ~= "on" then
    ngx.say('{"status":"error","msg":"钉钉通知未开启，请在系统设置中开启"}')
    return
end

dingtalk.notify_attack(attack_info)
ngx.say('{"status":"ok","msg":"测试消息已发送，请查看 nginx error.log 中的 [dingtalk] 日志"}')

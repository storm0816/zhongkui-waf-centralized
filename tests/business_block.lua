package.path = "lib/?.lua;" .. package.path
local matcher = require "business_block"

local rule = {id = 1, domain = "detailpage.dzh.com.cn", key = "id", value = "gsxw-9481806", state = "on", action = "DENY"}
local disabled = {domain = "detailpage.dzh.com.cn", key = "id", value = "disabled", state = "off"}
local index = matcher.compile({rule, disabled})
assert(matcher.match(index, "DETAILPAGE.DZH.COM.CN", {id = "gsxw-9481806", DZHSPECIAL = "41"}) == rule)
assert(matcher.match(index, "detailpage.dzh.com.cn", {id = {"other", "gsxw-9481806"}}) == rule)
assert(not matcher.match(index, "other.dzh.com.cn", {id = "gsxw-9481806"}))
assert(not matcher.match(index, "detailpage.dzh.com.cn", {ID = "gsxw-9481806"}))
assert(not matcher.match(index, "detailpage.dzh.com.cn", {id = "gsxw-94818060"}))
assert(not matcher.match(index, "detailpage.dzh.com.cn", {id = "disabled"}))
assert(not matcher.match(index, "detailpage.dzh.com.cn", {id = true}))

local response
ngx = {
    ctx = {}, header = {}, HTTP_FORBIDDEN = 403,
    say = function(body) response = body end,
    exit = function(status) return status end
}
assert(matcher.reject(rule) == 403)
assert(ngx.status == 403)
assert(ngx.header.content_type == "text/html; charset=utf-8")
assert(ngx.ctx.business_block_rule_id == 1)
assert(ngx.ctx.is_attack == nil and ngx.ctx.is_blocked == nil and ngx.ctx.ip_blocked == nil)
assert(response:find("当前内容暂不可访问", 1, true))
print("business block matching: ok")

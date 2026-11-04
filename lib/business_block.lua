local _M = {}

function _M.normalize_domain(host)
    return tostring(host or ""):lower():gsub("%.$", "")
end

function _M.compile(rules)
    local index = {}
    for _, rule in ipairs(rules or {}) do
        if rule.state == "on" and type(rule.domain) == "string" and type(rule.key) == "string" and type(rule.value) == "string" then
            local domain = _M.normalize_domain(rule.domain)
            index[domain] = index[domain] or {}
            index[domain][rule.key] = index[domain][rule.key] or {}
            index[domain][rule.key][rule.value] = rule
        end
    end
    return index
end

function _M.match(index, domain, args)
    local keys = index[_M.normalize_domain(domain)]
    if not keys or type(args) ~= "table" then return nil end
    for key, values in pairs(keys) do
        local value = args[key]
        if type(value) == "string" and values[value] then return values[value] end
        if type(value) == "table" then
            for _, item in ipairs(value) do
                if type(item) == "string" and values[item] then return values[item] end
            end
        end
    end
end

function _M.reject(rule)
    ngx.ctx.business_block_rule_id = rule.id
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say([[<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>请求无法访问</title><style>body{margin:0;background:#f5f6f8;color:#1f2937;font:16px/1.7 sans-serif}main{box-sizing:border-box;max-width:520px;margin:12vh auto;padding:32px;background:#fff;border:1px solid #e5e7eb;border-radius:8px}h1{margin:0 0 12px;font-size:22px}p{margin:0 0 20px;color:#4b5563}a{color:#2563eb;text-decoration:none}@media(max-width:560px){main{margin:24px 16px}}</style></head><body><main><h1>当前内容暂不可访问</h1><p>该请求已根据业务规则限制访问。如需帮助，请联系网站管理员。</p><a href="javascript:history.back()">返回上一页</a></main></body></html>]])
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

return _M

-- Development-only integration test; uses temporary .invalid metric keys.
require 'init'
local redis = require 'redis_cli'
local cc = assert(loadfile(assert(os.getenv('UV_STAGE')) .. '/lib/cc_cluster.lua'))()
assert(cc.is_reportable_domain('site.example'), 'DNS names remain reportable')
assert(cc.is_reportable_domain('SITE.EXAMPLE:443'), 'Host with port remains reportable')
assert(not cc.is_reportable_domain('100.100.74.192'), 'ELB IPv4 is not a domain')
assert(not cc.is_reportable_domain('100.112.212.143:8080'), 'ELB IPv4 with port is not a domain')
assert(not cc.is_reportable_domain('121.36.145.98'), 'public IPv4 is not a domain')
local red = assert(redis.get_connection())
local now = ngx.time()
local domain = 'uv-test-' .. ngx.md5(tostring(ngx.now()) .. tostring({})) .. '.invalid'
local minute = os.date('%Y%m%d%H%M', now)
local hour = os.date('%Y%m%d%H', now)
local previous = os.date('%Y%m%d%H', now - 3600)
local keys = {
    cc.get_metric_key('requests', domain, minute),
    cc.get_metric_key('requests_1h', domain, hour),
    cc.get_metric_key('uv_1h', domain, hour),
    cc.get_metric_key('uv_1h', domain, previous)
}
local ok, err = xpcall(function ()
    assert(cc.count_request('100.100.74.192', '192.0.2.1') == nil, 'IP Host is not counted as domain traffic')
    cc.observe_domain('100.100.74.192')
    assert(not ngx.shared.dict_config:get('cluster:cc:observed-domain:100.100.74.192'),
        'IP Host is not discovered as a domain')
    assert(cc.count_request(domain, '192.0.2.1'))
    -- Independent Node module, sharing the same Redis but no worker state.
    local second = assert(loadfile(os.getenv('UV_STAGE') .. '/lib/cc_cluster.lua'))()
    assert(second.count_request(domain:upper(), '192.0.2.1'))
    assert(second.count_request(domain, '192.0.2.2'))
    assert(tonumber(red:get(keys[1])) == 3, 'PV should retain repeat visits')
    assert(red:pfcount(keys[3]) == 2, 'cross-node UV deduplication')
    assert(red:ttl(keys[3]) > 0, 'UV must expire')
    assert(red:pfadd(keys[4], '192.0.2.1', '192.0.2.3'))
    assert(red:expire(keys[4], 120))
    assert(cc.get_uv_24h(domain, now) == 3, 'cross-hour UV union')
    assert(cc.get_uv_24h('*', now) == nil, 'default row is not global UV')
    local batch = {}
    for i = 1, 130 do batch[i] = keys[1] end
    assert(cc.read_metrics(batch)[keys[1]] == 3, 'chunked metric reads')
    assert(red:set(keys[3], 'wrong-type', 'EX', 120))
    assert(not cc.count_request(domain, '192.0.2.4'), 'UV failure is reported')
    assert(tonumber(red:get(keys[1])) == 4, 'UV failure must preserve PV')
    local get_connection = redis.get_connection
    redis.get_connection = function () return nil, 'test unavailable' end
    local success = cc.count_request(domain, '192.0.2.4')
    redis.get_connection = get_connection
    assert(not success, 'Redis outage must return without terminating request')
    print('UV_INTEGRATION_OK')
end, debug.traceback)
red:del(unpack(keys))
redis.close_connection(red)
ngx.shared.dict_config:delete('cluster:cc:observed-domain:' .. domain)
assert(ok, err)
package.loaded.cc_cluster = cc
local sql = assert(loadfile(os.getenv('UV_STAGE') .. '/lib/sql.lua'))()
local rows, query_err, total = sql.list_cc_cluster_domains({page = 1, limit = 20})
assert(rows, query_err)
assert(#rows <= 20 and total >= #rows, 'pagination')
for _, row in ipairs(rows) do
    assert(row.uv_24h ~= nil, 'UV field must be present, including null')
    assert(type(row.attack_count_24h) == 'number', 'attack count unchanged')
    if row.domain ~= '*' then
        local ips = {}
        for ip in tostring(row.node_ips or ''):gmatch('[^,]+') do ips[#ips + 1] = ip end
        assert(#ips == tonumber(row.node_count), 'node IP list must be complete')
    end
end
print('DOMAIN_QUERY_OK rows=' .. #rows .. ' total=' .. total)

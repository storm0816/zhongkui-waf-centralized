package.path = '/work/lib/?.lua;/work/?.lua;' .. package.path

local redis_cfg = {
  host = 'zk-verify-redis',
  port = 6379,
  password = '',
  poolSize = 20,
  ssl = 'off',
  timeouts = '1000,1000,1000',
  expire_time = 300,
}

package.loaded['config'] = {
  get_system_config = function(name)
    if name == 'redis' then
      return redis_cfg
    end
    if name == 'mysql' then
      return { database = 'zhongkui_waf' }
    end
    if name == 'system' then
      return { expire = 120, node_retention = 86400 }
    end
    return {
      redis = redis_cfg,
      mysql = { database = 'zhongkui_waf' },
      system = { expire = 120, node_retention = 86400 }
    }
  end,
  is_system_option_on = function()
    return true
  end,
}

local captured_sql = {}
package.loaded['mysql_cli'] = {
  query = function(sql)
    captured_sql[#captured_sql + 1] = sql
    return { affected_rows = 1 }, nil
  end
}

package.loaded['time'] = {
  get_yesterday_date = function() return '2026-04-22' end,
  get_hours = function() return { '00' } end,
  get_date_hour = function() return '2026-04-23 00' end,
}

local redis_cli = require 'redis_cli'
local constants = require 'constants'
local sql = require 'sql'

redis_cli.del(constants.KEY_REDIS_QUEUE_ATTACK_LOG)
redis_cli.del(constants.KEY_REDIS_QUEUE_IP_BLOCK_LOG)

local attack_json = [[{"request_id":"rq1","ip":"10.0.0.1","ip_country_code":"CN","ip_country_cn":"China","ip_country_en":"China","ip_province_code":"CN-SH","ip_province_cn":"Shanghai","ip_province_en":"Shanghai","ip_city_code":"SHA","ip_city_cn":"Shanghai","ip_city_en":"Shanghai","ip_longitude":121.47,"ip_latitude":31.23,"http_method":"GET","server":"demo.local","user_agent":"curl","referer":"","request_protocol":"HTTP/1.1","request_uri":"/test?id=1","request_body":"","http_status":403,"response_body":"blocked","attack_time":"2026-04-23 12:00:00","attack_type":"sqli","severity_level":"high","securityModule":"sqlInject","hit_rule":"or 1=1","action":"deny"}]]
assert(redis_cli.rpush(constants.KEY_REDIS_QUEUE_ATTACK_LOG, attack_json, 300), 'push attack queue failed')

local ip_block_values = "('rq2','10.0.0.2','CN','China','China','CN-SH','Shanghai','Shanghai','SHA','Shanghai','Shanghai',121.47,31.23,'cc','2026-04-23 12:00:00',600,DATE_ADD('2026-04-23 12:00:00', INTERVAL 600 SECOND),'deny')"
assert(redis_cli.rpush(constants.KEY_REDIS_QUEUE_IP_BLOCK_LOG, ip_block_values, 300), 'push ipblock queue failed')

sql.write_attack_log_redis_to_mysql()
sql.write_ip_block_log_redis_to_mysql()

local attack_left = redis_cli.batch_lpop(constants.KEY_REDIS_QUEUE_ATTACK_LOG, 10)
local ipblock_left = redis_cli.batch_lpop(constants.KEY_REDIS_QUEUE_IP_BLOCK_LOG, 10)

assert(attack_left and #attack_left == 0, 'attack queue not consumed')
assert(ipblock_left and #ipblock_left == 0, 'ip block queue not consumed')
assert(#captured_sql >= 2, 'mysql query not called enough')

local joined = table.concat(captured_sql, '\n')
assert(joined:find('INSERT INTO attack_log', 1, true), 'attack insert SQL missing')
assert(joined:find('INSERT INTO ip_block_log', 1, true), 'ip block insert SQL missing')
assert(joined:find('ON DUPLICATE KEY UPDATE update_time = NOW()', 1, true), 'upsert clause missing')

print('OK: step2 docker verification passed')

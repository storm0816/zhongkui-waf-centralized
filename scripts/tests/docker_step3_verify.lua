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

local cjson = require 'cjson.safe'
local redis_cli = require 'redis_cli'
local constants = require 'constants'
local sql = require 'sql'

local traffic_key = 'waf:traffic_stats:CN_China_China_CN-SH_Shanghai_Shanghai_SHA_Shanghai_Shanghai:2026-04-23'
local attack_date = '2026-04-23'
local attack_hkey = 'waf:attack_type_traffic_map:' .. attack_date

redis_cli.del(traffic_key)
redis_cli.del(attack_hkey)
redis_cli.del(constants.KEY_REDIS_DIRTY_TRAFFIC_STATS)
redis_cli.del(constants.KEY_REDIS_DIRTY_ATTACK_TYPE_DATES)

local traffic_payload = cjson.encode({
  countryCode = 'CN',
  countryCN = 'China',
  countryEN = 'China',
  provinceCode = 'CN-SH',
  provinceCN = 'Shanghai',
  provinceEN = 'Shanghai',
  cityCode = 'SHA',
  cityCN = 'Shanghai',
  cityEN = 'Shanghai',
  request_times = 100,
  attack_times = 20,
  block_times_attack = 10,
  block_times_captcha = 3,
  block_times_cc = 2,
  captcha_pass_times = 5
})

assert(redis_cli.set(traffic_key, traffic_payload, 300), 'set traffic key failed')
assert(redis_cli.sadd(constants.KEY_REDIS_DIRTY_TRAFFIC_STATS, traffic_key, 300), 'sadd dirty traffic failed')
assert(redis_cli.hincrby(attack_hkey, 'attack_type_2026-04-23_sqli', 8), 'hincrby attack type failed')
assert(redis_cli.sadd(constants.KEY_REDIS_DIRTY_ATTACK_TYPE_DATES, attack_date, 300), 'sadd dirty attack date failed')

sql.write_traffic_stats_redis_to_mysql()
sql.write_attack_type_traffic_redis_to_mysql()

local traffic_deleted = redis_cli.get(traffic_key)
local dirty_traffic = redis_cli.smembers(constants.KEY_REDIS_DIRTY_TRAFFIC_STATS) or {}
local dirty_attack_dates = redis_cli.smembers(constants.KEY_REDIS_DIRTY_ATTACK_TYPE_DATES) or {}

assert(traffic_deleted == nil, 'traffic key should be deleted after sync')
assert(#dirty_traffic == 0, 'dirty traffic set should be empty')
assert(#dirty_attack_dates == 0, 'dirty attack_type date set should be empty')
assert(#captured_sql >= 2, 'mysql query count not enough')

local joined = table.concat(captured_sql, '\n')
assert(joined:find('INSERT INTO traffic_stats', 1, true), 'traffic_stats insert SQL missing')
assert(joined:find('INSERT INTO attack_type_traffic', 1, true), 'attack_type_traffic insert SQL missing')

print('OK: step3 docker verification passed')

-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local _M = {}

_M.KEY_HTTP_4XX = 'http4x'
_M.KEY_HTTP_5XX = 'http5x'
_M.KEY_REQUEST_TIMES = 'request_times'
_M.KEY_ATTACK_TIMES = 'attack_times'
_M.KEY_BLOCK_TIMES_ATTACK = 'block_times_attack'
_M.KEY_BLOCK_TIMES_CAPTCHA = 'block_times_captcha'
_M.KEY_BLOCK_TIMES_CC = 'block_times_cc'
_M.KEY_CAPTCHA_PASS_TIMES = 'captcha_pass_times'
_M.KEY_ATTACK_PREFIX = 'attack_'
_M.KEY_ATTACK_TYPE_PREFIX = 'attack_type_'
_M.KEY_BLOCKED_PREFIX = 'blocked_'
_M.KEY_ATTACK_LOG = 'attack_log'
_M.KEY_IP_BLOCK_LOG = 'ip_block_log'
_M.KEY_REDIS_QUEUE_ATTACK_LOG = 'waf:queue:attack_log'
_M.KEY_REDIS_QUEUE_IP_BLOCK_LOG = 'waf:queue:ip_block_log'
_M.KEY_REDIS_DIRTY_TRAFFIC_STATS = 'waf:dirty:traffic_stats'
_M.KEY_REDIS_DIRTY_ATTACK_TYPE_DATES = 'waf:dirty:attack_type_dates'
_M.KEY_REDIS_RETRY_TRAFFIC_STATS = 'waf:retry:traffic_stats'
_M.KEY_REDIS_RETRY_ATTACK_TYPE_DATES = 'waf:retry:attack_type_dates'
_M.KEY_REDIS_CLUSTER_RULES_SNAPSHOT = 'waf:cluster:rules:snapshot'
_M.KEY_REDIS_CLUSTER_RULES_SNAPSHOT_VERSION = 'waf:cluster:rules:snapshot:version'
_M.KEY_REDIS_IP_WHITELIST = 'waf:rules:ip_whitelist'
_M.KEY_REDIS_IP_BLACKLIST = 'waf:rules:ip_blacklist'
_M.KEY_BLACKIP_PREFIX = 'black_ip:'
_M.KEY_IP_GROUPS_WHITELIST = 'ipWhiteList'
_M.KEY_IP_GROUPS_BLACKLIST = 'ipBlackList'
_M.KEY_MASTER_IP_GROUPS_BLACKLIST = 'ipBlackListMaster'
_M.KEY_CAPTCHA_PREFIX = 'captcha:'
_M.KEY_CAPTCHA_ACCESSTOKEN_REDIS_PREFIX = 'captcha_accesstoken:'

return _M

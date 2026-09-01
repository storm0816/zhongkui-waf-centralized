local cjson = require "cjson.safe"
local mysql = require "mysql_cli"
local redis_cli = require "redis_cli"
local constants = require "constants"
local config = require "config"

local _M = {}

local tonumber = tonumber
local tostring = tostring
local format = string.format
local lower = string.lower
local quote = ngx.quote_sql_str

local schema_ready = false

local CREATE_POLICY_TABLE = [[
CREATE TABLE IF NOT EXISTS waf_dingtalk_throttle_policy (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain VARCHAR(255) NOT NULL,
    state VARCHAR(16) NOT NULL DEFAULT 'on',
    interval_minutes INT UNSIGNED NOT NULL DEFAULT 10,
    summary_time CHAR(5) NOT NULL DEFAULT '00:00',
    last_success_at DATETIME NULL,
    last_failure_at DATETIME NULL,
    last_failure_reason VARCHAR(1024) NULL,
    create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    update_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_dingtalk_throttle_domain (domain),
    KEY idx_dingtalk_throttle_state (state),
    KEY idx_dingtalk_throttle_update_time (update_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
]]

local CREATE_FAILURE_TABLE = [[
CREATE TABLE IF NOT EXISTS waf_dingtalk_failure_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain VARCHAR(255) NOT NULL DEFAULT '',
    ip VARCHAR(39) NOT NULL DEFAULT '',
    block_reason VARCHAR(200) NOT NULL DEFAULT '',
    action VARCHAR(100) NOT NULL DEFAULT '',
    request_uri VARCHAR(2048) NOT NULL DEFAULT '',
    send_status VARCHAR(16) NOT NULL DEFAULT 'failure',
    error_message VARCHAR(1024) NOT NULL DEFAULT '',
    occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_dingtalk_failure_time (occurred_at),
    KEY idx_dingtalk_failure_domain_time (domain, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
]]

local CREATE_SUMMARY_TABLE = [[
CREATE TABLE IF NOT EXISTS waf_dingtalk_summary_pending (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain VARCHAR(255) NOT NULL,
    interval_minutes INT UNSIGNED NOT NULL,
    summary_time CHAR(5) NOT NULL DEFAULT '00:00',
    bucket_epoch BIGINT UNSIGNED NOT NULL,
    block_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
    retry_at DATETIME NULL,
    attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
    last_error VARCHAR(1024) NULL,
    create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    update_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_dingtalk_summary_bucket (domain, interval_minutes, bucket_epoch),
    KEY idx_dingtalk_summary_due (retry_at, bucket_epoch)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
]]

local LOCAL_POLICY_CACHE_KEY = "dingtalk:summary:local:policies"
local SUMMARY_RETRY_SECONDS = 300
local SUMMARY_RETRY_TTL_SECONDS = 604800

local function normalize_summary_time(value)
    local raw = tostring(value or "00:00")
    if raw == "" then raw = "00:00" end
    local hour, minute = raw:match("^(%d%d?):(%d%d)$")
    hour, minute = tonumber(hour), tonumber(minute)
    if not hour or not minute or hour > 23 or minute > 59 then return nil end
    return format("%02d:%02d", hour, minute)
end

-- Anchor rolling windows to a local clock time. A 1440-minute policy with
-- 12:00 therefore groups events from one noon to the next noon.
local function summary_bucket(seconds, summary_time)
    local normalized = normalize_summary_time(summary_time)
    if not normalized then return nil end
    local hour, minute = normalized:match("^(%d%d):(%d%d)$")
    local now = ngx.time()
    local today = os.date("*t", now)
    local anchor = os.time({year=today.year, month=today.month, day=today.day,
        hour=tonumber(hour), min=tonumber(minute), sec=0})
    return math.floor((now - anchor) / seconds) * seconds + anchor, normalized
end

function _M.normalize_domain(value)
    local domain = lower(tostring(value or ""))
    domain = domain:gsub("^%s+", ""):gsub("%s+$", "")
    domain = domain:gsub("%.$", "")
    domain = domain:gsub(":%d+$", "")
    return domain
end

local function valid_domain(domain)
    if domain == "" or #domain > 255 or domain:find("/", 1, true) then
        return false
    end
    return domain:match("^[a-z0-9][a-z0-9%.%-]*[a-z0-9]$") ~= nil
end

function _M.ensure_schema()
    if schema_ready then return true end
    if not mysql.query(CREATE_POLICY_TABLE) then return nil, "create throttle policy table failed" end
    if not mysql.query(CREATE_FAILURE_TABLE) then return nil, "create notification failure table failed" end
    if not mysql.query(CREATE_SUMMARY_TABLE) then return nil, "create notification summary table failed" end

    local policy_time_column = mysql.query([[SELECT COUNT(*) AS total FROM information_schema.columns
        WHERE table_schema=DATABASE() AND table_name='waf_dingtalk_throttle_policy' AND column_name='summary_time']])
    if not policy_time_column or not policy_time_column[1] then return nil, "check throttle policy schema failed" end
    if tonumber(policy_time_column[1].total) == 0
        and not mysql.query("ALTER TABLE waf_dingtalk_throttle_policy ADD COLUMN summary_time CHAR(5) NOT NULL DEFAULT '00:00' AFTER interval_minutes") then
        return nil, "upgrade throttle policy schema failed"
    end

    local pending_time_column = mysql.query([[SELECT COUNT(*) AS total FROM information_schema.columns
        WHERE table_schema=DATABASE() AND table_name='waf_dingtalk_summary_pending' AND column_name='summary_time']])
    if not pending_time_column or not pending_time_column[1] then return nil, "check summary pending schema failed" end
    if tonumber(pending_time_column[1].total) == 0
        and not mysql.query("ALTER TABLE waf_dingtalk_summary_pending ADD COLUMN summary_time CHAR(5) NOT NULL DEFAULT '00:00' AFTER interval_minutes") then
        return nil, "upgrade summary pending schema failed"
    end

    -- The original table stored failures only. Keep its data and extend it into
    -- the unified delivery record table used by the management console.
    local columns = mysql.query([[SELECT COUNT(*) AS total FROM information_schema.columns
        WHERE table_schema=DATABASE() AND table_name='waf_dingtalk_failure_log' AND column_name='send_status']])
    if not columns or not columns[1] then return nil, "check notification record schema failed" end
    if tonumber(columns[1].total) == 0
        and not mysql.query("ALTER TABLE waf_dingtalk_failure_log ADD COLUMN send_status VARCHAR(16) NOT NULL DEFAULT 'failure' AFTER request_uri") then
        return nil, "upgrade notification record schema failed"
    end
    schema_ready = true
    return true
end

function _M.publish_policies()
    local ok, err = _M.ensure_schema()
    if not ok then return nil, err end
    local rows = mysql.query("SELECT domain,state,interval_minutes,summary_time FROM waf_dingtalk_throttle_policy")
    if not rows then return nil, "query throttle policies failed" end
    local policies = {}
    for _, row in ipairs(rows) do
        local domain = _M.normalize_domain(row.domain)
        if domain ~= "" then
            policies[domain] = {
                state = tostring(row.state or "off"),
                interval_minutes = tonumber(row.interval_minutes) or 10,
                summary_time = normalize_summary_time(row.summary_time) or "00:00"
            }
        end
    end
    local encoded = cjson.encode(policies)
    if not encoded then return nil, "encode throttle policies failed" end
    if config.is_centralized_mode() then
        return redis_cli.set(constants.KEY_REDIS_DINGTALK_THROTTLE_POLICY, encoded, -1)
    end
    local dict = ngx.shared and ngx.shared.dict_config
    if not dict then return nil, "local policy cache unavailable" end
    return dict:set(LOCAL_POLICY_CACHE_KEY, encoded)
end

function _M.get_policy(domain)
    domain = _M.normalize_domain(domain)
    if domain == "" then return nil end
    local raw
    if config.is_centralized_mode() then
        raw = redis_cli.get(constants.KEY_REDIS_DINGTALK_THROTTLE_POLICY)
    else
        local dict = ngx.shared and ngx.shared.dict_config
        raw = dict and dict:get(LOCAL_POLICY_CACHE_KEY) or nil
    end
    if raw then
        local policies = cjson.decode(raw)
        if type(policies) == "table" then return policies[domain] end
    end
    if not _M.ensure_schema() then return nil end
    local rows = mysql.query("SELECT state,interval_minutes,summary_time FROM waf_dingtalk_throttle_policy WHERE domain=" .. quote(domain) .. " LIMIT 1")
    return rows and rows[1] or nil
end

function _M.add_summary_block(domain, interval_minutes, summary_time)
    domain = _M.normalize_domain(domain)
    local seconds = math.floor((tonumber(interval_minutes) or 0) * 60)
    if domain == "" or seconds <= 0 then return nil, "invalid summary window" end
    local bucket, normalized_time = summary_bucket(seconds, summary_time)
    if not bucket then return nil, "invalid summary time" end
    local key = constants.KEY_REDIS_DINGTALK_SUMMARY_PREFIX .. ngx.md5(domain) .. ":" .. seconds .. ":" .. bucket
    local member = cjson.encode({domain=domain, interval_minutes=math.floor(seconds / 60),
        summary_time=normalized_time, bucket=bucket})
    if not member then return nil, "encode summary member failed" end
    local count, err = redis_cli.increment_summary(key, constants.KEY_REDIS_DINGTALK_SUMMARY_PENDING,
        member, math.max(seconds * 3, SUMMARY_RETRY_TTL_SECONDS), bucket + seconds)
    if not count then return nil, err end
    return true, nil, bucket, member
end

function _M.list_due_summary_blocks(now, limit)
    local members, err = redis_cli.list_due_summaries(constants.KEY_REDIS_DINGTALK_SUMMARY_PENDING,
        now, limit or 200)
    if not members then return nil, err end
    local rows = {}
    for _, member in ipairs(members) do
        local item = cjson.decode(member)
        if type(item) == "table" then
            item.member = member
            item.interval_minutes = tonumber(item.interval_minutes) or 0
            item.summary_time = normalize_summary_time(item.summary_time) or "00:00"
            item.bucket = tonumber(item.bucket) or 0
            item.domain = _M.normalize_domain(item.domain)
            item.key = constants.KEY_REDIS_DINGTALK_SUMMARY_PREFIX .. ngx.md5(item.domain)
                .. ":" .. (item.interval_minutes * 60) .. ":" .. item.bucket
            local value, get_err = redis_cli.get(item.key)
            if get_err then return nil, get_err end
            item.block_count = tonumber(value) or 0
            rows[#rows + 1] = item
        else
            redis_cli.remove_pending_summary(constants.KEY_REDIS_DINGTALK_SUMMARY_PENDING, member)
        end
    end
    return rows
end

function _M.complete_summary_block(item)
    return redis_cli.complete_summary(item.key, constants.KEY_REDIS_DINGTALK_SUMMARY_PENDING, item.member)
end

function _M.add_local_summary_block(domain, interval_minutes, summary_time)
    domain = _M.normalize_domain(domain)
    local seconds = math.floor((tonumber(interval_minutes) or 0) * 60)
    if domain == "" or seconds <= 0 then return nil, "invalid summary window" end
    local bucket, normalized_time = summary_bucket(seconds, summary_time)
    if not bucket then return nil, "invalid summary time" end
    local ok, err = _M.ensure_schema()
    if not ok then return nil, err end
    local sql = format([[INSERT INTO waf_dingtalk_summary_pending
        (domain,interval_minutes,summary_time,bucket_epoch,block_count) VALUES (%s,%d,%s,%d,1)
        ON DUPLICATE KEY UPDATE block_count=block_count+1,update_time=NOW()]],
        quote(domain), math.floor(seconds / 60), quote(normalized_time), bucket)
    if not mysql.query(sql) then return nil, "save local summary failed" end
    return true, nil, bucket
end

function _M.list_due_local_summary_blocks(now, limit)
    local ok, err = _M.ensure_schema()
    if not ok then return nil, err end
    return mysql.query(format([[SELECT id,domain,interval_minutes,summary_time,bucket_epoch AS bucket,block_count
        FROM waf_dingtalk_summary_pending
        WHERE bucket_epoch+(interval_minutes*60)<=%d AND (retry_at IS NULL OR retry_at<=NOW())
        ORDER BY bucket_epoch ASC LIMIT %d]], now, limit or 200))
end

function _M.complete_local_summary_block(item)
    return mysql.query("DELETE FROM waf_dingtalk_summary_pending WHERE id=" .. tonumber(item.id))
end

function _M.retry_summary_block(item, err)
    if config.is_centralized_mode() then
        return redis_cli.reschedule_summary(item.key, constants.KEY_REDIS_DINGTALK_SUMMARY_PENDING,
            item.member, ngx.time() + SUMMARY_RETRY_SECONDS, SUMMARY_RETRY_TTL_SECONDS)
    end
    return mysql.query("UPDATE waf_dingtalk_summary_pending SET attempt_count=attempt_count+1,retry_at="
        .. "DATE_ADD(NOW(),INTERVAL " .. SUMMARY_RETRY_SECONDS .. " SECOND),last_error="
        .. quote(tostring(err or "unknown error")) .. " WHERE id=" .. tonumber(item.id))
end

function _M.list_enabled_policies()
    local ok, err = _M.ensure_schema()
    if not ok then return nil, err end
    return mysql.query("SELECT domain,interval_minutes,summary_time FROM waf_dingtalk_throttle_policy WHERE state='on'")
end

local function record_delivery(block_info, send_status, err)
    if not _M.ensure_schema() then return nil, "schema unavailable" end
    block_info = block_info or {}
    local domain = _M.normalize_domain(block_info.server)
    local message = tostring(err or "")
    if tostring(block_info.attack_type or "") == "block_summary" and send_status == "failure" then
        local existing = mysql.query("SELECT id FROM waf_dingtalk_failure_log WHERE domain=" .. quote(domain)
            .. " AND send_status='failure' AND block_reason='block_summary' AND request_uri="
            .. quote(tostring(block_info.uri or "")) .. " LIMIT 1")
        if existing and existing[1] then
            return mysql.query("UPDATE waf_dingtalk_failure_log SET error_message=" .. quote(message)
                .. ",occurred_at=NOW() WHERE id=" .. tonumber(existing[1].id))
        end
    end
    local sql = format([[INSERT INTO waf_dingtalk_failure_log
        (domain,ip,block_reason,action,request_uri,send_status,error_message,occurred_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,NOW())]],
        quote(domain), quote(tostring(block_info.ip or "")),
        quote(tostring(block_info.attack_type or "")), quote(tostring(block_info.action or "")),
        quote(tostring(block_info.uri or "")), quote(send_status), quote(message))
    local inserted = mysql.query(sql)
    if domain ~= "" then
        if send_status == "success" then
            mysql.query("UPDATE waf_dingtalk_throttle_policy SET last_success_at=NOW() WHERE domain=" .. quote(domain))
        else
            mysql.query("UPDATE waf_dingtalk_throttle_policy SET last_failure_at=NOW(),last_failure_reason="
                .. quote(message) .. " WHERE domain=" .. quote(domain))
        end
    end
    return inserted
end

function _M.record_success(block_info)
    return record_delivery(block_info, "success", "")
end

function _M.record_failure(block_info, err)
    return record_delivery(block_info, "failure", err or "unknown error")
end

function _M.was_summary_sent(domain, event_key)
    domain = _M.normalize_domain(domain)
    local rows = mysql.query("SELECT id FROM waf_dingtalk_failure_log WHERE domain=" .. quote(domain)
        .. " AND send_status='success' AND block_reason='block_summary' AND request_uri="
        .. quote(tostring(event_key or "")) .. " LIMIT 1")
    return rows and rows[1] ~= nil
end

function _M.save_policy(values)
    local ok, err = _M.ensure_schema()
    if not ok then return nil, err end
    local domain = _M.normalize_domain(values.domain)
    if not valid_domain(domain) then return nil, "域名格式无效，只支持精确域名" end
    local state = tostring(values.state or "off") == "on" and "on" or "off"
    local interval = math.floor(tonumber(values.interval_minutes or values.intervalMinutes) or 0)
    if interval < 1 or interval > 10080 then return nil, "降频时间必须为 1-10080 分钟" end
    local summary_time = normalize_summary_time(values.summary_time or values.summaryTime)
    if not summary_time then return nil, "invalid summary time, use HH:mm" end
    local sql = format([[INSERT INTO waf_dingtalk_throttle_policy (domain,state,interval_minutes,summary_time)
        VALUES (%s,%s,%d,%s) ON DUPLICATE KEY UPDATE state=VALUES(state),
        interval_minutes=VALUES(interval_minutes),summary_time=VALUES(summary_time),update_time=NOW()]],
        quote(domain), quote(state), interval, quote(summary_time))
    if not mysql.query(sql) then return nil, "保存降频策略失败" end
    local published, publish_err = _M.publish_policies()
    if not published then return nil, publish_err or "发布降频策略失败" end
    return true
end

function _M.delete_policy(domain)
    local ok, err = _M.ensure_schema()
    if not ok then return nil, err end
    domain = _M.normalize_domain(domain)
    if domain == "" then return nil, "域名不能为空" end
    if not mysql.query("DELETE FROM waf_dingtalk_throttle_policy WHERE domain=" .. quote(domain)) then
        return nil, "删除降频策略失败"
    end
    return _M.publish_policies()
end

local function page_values(filters)
    local page = math.floor(tonumber(filters.page) or 1)
    local limit = math.floor(tonumber(filters.limit) or 20)
    if page < 1 then page = 1 end
    if limit < 1 then limit = 20 elseif limit > 100 then limit = 100 end
    return page, limit, (page - 1) * limit
end

function _M.list_policies(filters)
    local ok, err = _M.ensure_schema()
    if not ok then return nil, err end
    filters = filters or {}
    local where = " WHERE 1=1"
    local domain = _M.normalize_domain(filters.domain)
    local state = tostring(filters.state or "")
    local result = tostring(filters.result or "")
    if domain ~= "" then where = where .. " AND domain LIKE " .. quote("%" .. domain .. "%") end
    if state == "on" or state == "off" then where = where .. " AND state=" .. quote(state) end
    if result == "success" then
        where = where .. " AND last_success_at IS NOT NULL AND (last_failure_at IS NULL OR last_success_at>=last_failure_at)"
    elseif result == "failure" then
        where = where .. " AND last_failure_at IS NOT NULL AND (last_success_at IS NULL OR last_failure_at>last_success_at)"
    end
    local count_rows = mysql.query("SELECT COUNT(*) AS total FROM waf_dingtalk_throttle_policy" .. where)
    if not count_rows or not count_rows[1] then return nil, "查询策略数量失败" end
    local total = tonumber(count_rows[1].total) or 0
    local page, limit, offset = page_values(filters)
    local rows = mysql.query([[SELECT id,domain,state,interval_minutes,summary_time,last_success_at,last_failure_at,
        last_failure_reason,create_time,update_time,
        CASE WHEN last_failure_at IS NOT NULL AND (last_success_at IS NULL OR last_failure_at>last_success_at)
            THEN 'failure' WHEN last_success_at IS NOT NULL THEN 'success' ELSE 'none' END AS last_result
        FROM waf_dingtalk_throttle_policy]] .. where .. " ORDER BY id DESC LIMIT " .. offset .. "," .. limit) or {}
    return rows, nil, total, page, limit
end

function _M.list_records(filters)
    local ok, err = _M.ensure_schema()
    if not ok then return nil, err end
    filters = filters or {}
    local where = " WHERE 1=1"
    local domain = _M.normalize_domain(filters.domain)
    local keyword = tostring(filters.keyword or "")
    local send_status = tostring(filters.send_status or filters.sendStatus or "")
    local start_time = tostring(filters.start_time or filters.startTime or "")
    local end_time = tostring(filters.end_time or filters.endTime or "")
    if domain ~= "" then where = where .. " AND domain LIKE " .. quote("%" .. domain .. "%") end
    if keyword ~= "" then where = where .. " AND error_message LIKE " .. quote("%" .. keyword .. "%") end
    if send_status == "success" or send_status == "failure" then
        where = where .. " AND send_status=" .. quote(send_status)
    end
    if start_time:match("^%d%d%d%d%-%d%d%-%d%d %d%d:%d%d:%d%d$") then where = where .. " AND occurred_at>=" .. quote(start_time) end
    if end_time:match("^%d%d%d%d%-%d%d%-%d%d %d%d:%d%d:%d%d$") then where = where .. " AND occurred_at<=" .. quote(end_time) end
    local count_rows = mysql.query("SELECT COUNT(*) AS total FROM waf_dingtalk_failure_log" .. where)
    if not count_rows or not count_rows[1] then return nil, "查询异常数量失败" end
    local total = tonumber(count_rows[1].total) or 0
    local page, limit, offset = page_values(filters)
    local rows = mysql.query([[SELECT id,domain,ip,block_reason,action,request_uri,send_status,error_message,occurred_at
        FROM waf_dingtalk_failure_log]] .. where .. " ORDER BY id DESC LIMIT " .. offset .. "," .. limit) or {}
    return rows, nil, total, page, limit
end

-- Kept for callers upgraded from the first implementation.
function _M.list_failures(filters)
    return _M.list_records(filters)
end

local function archive_table_name(week_start, week_end)
    local start_label = tostring(week_start or ""):gsub("[^0-9]", ""):sub(1, 8)
    local end_label = tostring(week_end or ""):gsub("[^0-9]", ""):sub(1, 8)
    if #start_label ~= 8 or #end_label ~= 8 then return nil end
    return "dingtalk_notification_archive_" .. start_label .. "_" .. end_label
end

function _M.archive_records(days, batch)
    if not _M.ensure_schema() then return {code=500,msg="ensure dingtalk schema failed"} end
    local range = mysql.query(format([[SELECT
        DATE_FORMAT(DATE_SUB(DATE(MIN(occurred_at)),INTERVAL WEEKDAY(MIN(occurred_at)) DAY),'%%Y-%%m-%%d 00:00:00') AS week_start,
        DATE_FORMAT(DATE_ADD(DATE_SUB(DATE(MIN(occurred_at)),INTERVAL WEEKDAY(MIN(occurred_at)) DAY),INTERVAL 7 DAY),'%%Y-%%m-%%d 00:00:00') AS week_end
        FROM waf_dingtalk_failure_log WHERE occurred_at<NOW()-INTERVAL %d DAY]], days))
    if not range then return {code=500,msg="query dingtalk failure archive range failed"} end
    if not range[1] or not range[1].week_start or range[1].week_start == ngx.null
        or not range[1].week_end or range[1].week_end == ngx.null then
        return {code=0,msg="no archive rows",inserted=0,deleted=0}
    end
    local table_name = archive_table_name(range[1].week_start, range[1].week_end)
    if not table_name then return {code=500,msg="invalid dingtalk archive table name"} end
    if not mysql.query("CREATE TABLE IF NOT EXISTS `" .. table_name .. "` LIKE waf_dingtalk_failure_log") then
        return {code=500,msg="ensure dingtalk archive table failed"}
    end
    local start_value, end_value = quote(tostring(range[1].week_start)), quote(tostring(range[1].week_end))
    local inserted = mysql.query(format([[INSERT IGNORE INTO `%s` SELECT * FROM waf_dingtalk_failure_log
        WHERE occurred_at<NOW()-INTERVAL %d DAY AND occurred_at>=%s AND occurred_at<%s ORDER BY id LIMIT %d]],
        table_name, days, start_value, end_value, batch))
    if not inserted then return {code=500,msg="archive dingtalk failures failed"} end
    local deleted = mysql.query(format([[DELETE FROM waf_dingtalk_failure_log WHERE id IN
        (SELECT id FROM (SELECT s.id FROM waf_dingtalk_failure_log s INNER JOIN `%s` a ON a.id=s.id
        WHERE s.occurred_at<NOW()-INTERVAL %d DAY AND s.occurred_at>=%s AND s.occurred_at<%s ORDER BY s.id LIMIT %d) copied)]],
        table_name, days, start_value, end_value, batch))
    if not deleted then return {code=500,msg="delete archived dingtalk failures failed"} end
    return {code=0,msg="ok",inserted=inserted.affected_rows or 0,deleted=deleted.affected_rows or 0,archive_table=table_name}
end

function _M.archive_failures(days, batch)
    return _M.archive_records(days, batch)
end

return _M

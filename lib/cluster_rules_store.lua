-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)

local _M = {}
local table_ready = false

local CREATE_TABLE_SQL = [[
    CREATE TABLE IF NOT EXISTS waf_cluster_rule_release (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        version VARCHAR(64) NOT NULL,
        content_hash VARCHAR(64) NOT NULL,
        snapshot LONGTEXT NOT NULL,
        source VARCHAR(128) NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'prepared',
        last_error VARCHAR(1024) NULL,
        last_attempt_at DATETIME NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        published_at DATETIME NULL,
        PRIMARY KEY (id),
        UNIQUE KEY uniq_version (version),
        KEY idx_status_published (status, published_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
]]

local function mysql_client()
    -- Loaded lazily to avoid config -> mysql_cli -> config initialization cycles.
    return require "mysql_cli"
end

local function execute(sql)
    local mysql = mysql_client()
    local db, err = mysql.get_connection(16 * 1024 * 1024)
    if not db then
        return nil, err or "mysql connection failed"
    end

    local res, query_err = db:query(sql)
    mysql.close_connection(db)
    if not res then
        return nil, query_err or "mysql query failed"
    end
    return res
end

function _M.ensure_table()
    if table_ready then
        return true
    end
    local created, create_err = execute(CREATE_TABLE_SQL)
    if not created then
        return nil, create_err
    end

    local columns = {
        last_error = "ALTER TABLE waf_cluster_rule_release ADD COLUMN last_error VARCHAR(1024) NULL AFTER status",
        last_attempt_at = "ALTER TABLE waf_cluster_rule_release ADD COLUMN last_attempt_at DATETIME NULL AFTER last_error"
    }
    for name, ddl in pairs(columns) do
        local rows, check_err = execute(string.format([[
            SELECT COUNT(*) AS c
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'waf_cluster_rule_release'
              AND COLUMN_NAME = %s
        ]], ngx.quote_sql_str(name)))
        if not rows then
            return nil, check_err
        end
        if not rows[1] or tonumber(rows[1].c) == 0 then
            local altered, alter_err = execute(ddl)
            if not altered then
                return nil, alter_err
            end
        end
    end
    table_ready = true
    return true
end

function _M.prepare(version, content_hash, snapshot, source)
    local mysql = mysql_client()
    local db, err = mysql.get_connection(16 * 1024 * 1024)
    if not db then
        return nil, err or "mysql connection failed"
    end

    local quote = ngx.quote_sql_str
    local ok, begin_err = db:query("START TRANSACTION")
    if not ok then
        mysql.close_connection(db)
        return nil, begin_err or "failed to start transaction"
    end

    local sql = string.format([[
        INSERT INTO waf_cluster_rule_release
            (version, content_hash, snapshot, source, status, last_error, last_attempt_at, created_at)
        VALUES (%s, %s, %s, %s, 'prepared', NULL, NOW(), NOW())
        ON DUPLICATE KEY UPDATE
            content_hash = VALUES(content_hash),
            snapshot = VALUES(snapshot),
            source = VALUES(source),
            last_error = NULL,
            last_attempt_at = NOW()
    ]], quote(version), quote(content_hash), quote(snapshot), quote(source or "master"))

    local res, insert_err = db:query(sql)
    if not res then
        db:query("ROLLBACK")
        mysql.close_connection(db)
        return nil, insert_err or "failed to prepare rule release"
    end

    local committed, commit_err = db:query("COMMIT")
    if not committed then
        db:query("ROLLBACK")
        mysql.close_connection(db)
        return nil, commit_err or "failed to commit rule release"
    end
    mysql.close_connection(db)
    return true
end

function _M.mark_published(version)
    local sql = string.format([[
        UPDATE waf_cluster_rule_release
        SET status = 'published', published_at = NOW(), last_error = NULL, last_attempt_at = NOW()
        WHERE version = %s
    ]], ngx.quote_sql_str(version))
    return execute(sql)
end

function _M.mark_publish_error(version, message)
    local sql = string.format([[
        UPDATE waf_cluster_rule_release
        SET status = 'prepared', last_error = %s, last_attempt_at = NOW()
        WHERE version = %s
    ]], ngx.quote_sql_str(tostring(message or "publish failed")), ngx.quote_sql_str(version))
    return execute(sql)
end

function _M.get_latest_published()
    local rows, err = execute([[
        SELECT version, content_hash, snapshot, source, status, last_error, last_attempt_at,
               created_at, published_at
        FROM waf_cluster_rule_release
        WHERE status = 'published'
        ORDER BY published_at DESC, id DESC
        LIMIT 1
    ]])
    if not rows then
        return nil, err
    end
    return rows[1]
end


function _M.get_latest_status()
    local rows, err = execute([[
        SELECT version, content_hash, source, status, last_error, last_attempt_at,
               created_at, published_at
        FROM waf_cluster_rule_release
        ORDER BY id DESC
        LIMIT 1
    ]])
    if not rows then
        return nil, err
    end
    return rows[1]
end

function _M.get_latest_releasable()
    local rows, err = execute([[
        SELECT version, content_hash, snapshot, source, status, published_at
        FROM waf_cluster_rule_release
        WHERE status IN ('prepared', 'published')
        ORDER BY id DESC
        LIMIT 1
    ]])
    if not rows then
        return nil, err
    end
    return rows[1]
end

return _M

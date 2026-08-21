local mysql = require "mysql_cli"

local _M = {}
local quote = ngx.quote_sql_str

local CREATE_RELEASE_TABLE = [[
CREATE TABLE IF NOT EXISTS waf_geoip_release (
    version VARCHAR(64) NOT NULL PRIMARY KEY,
    checksum CHAR(64) NOT NULL,
    file_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
    build_time DATETIME NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ready',
    notes VARCHAR(512) NULL,
    created_by VARCHAR(128) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_geoip_release_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
]]

local CREATE_DEPLOYMENT_TABLE = [[
CREATE TABLE IF NOT EXISTS waf_geoip_deployment (
    task_id VARCHAR(64) NOT NULL PRIMARY KEY,
    release_version VARCHAR(64) NOT NULL,
    release_checksum CHAR(64) NOT NULL,
    node_ip VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'queued',
    message VARCHAR(1024) NULL,
    created_by VARCHAR(128) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    finished_at DATETIME NULL,
    INDEX idx_geoip_deployment_node (node_ip, created_at),
    INDEX idx_geoip_deployment_release (release_version, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
]]

function _M.ensure_tables()
    local ok, err = mysql.query(CREATE_RELEASE_TABLE)
    if not ok then return nil, err end
    ok, err = mysql.query(CREATE_DEPLOYMENT_TABLE)
    if not ok then return nil, err end
    return true
end

function _M.create_release(values)
    local sql = string.format([[INSERT INTO waf_geoip_release
        (version,checksum,file_size,build_time,status,notes,created_by)
        VALUES (%s,%s,%d,FROM_UNIXTIME(%d),'ready',%s,%s)]],
        quote(values.version), quote(values.checksum), tonumber(values.file_size) or 0,
        tonumber(values.build_epoch) or 0, quote(values.notes or ""), quote(values.created_by or ""))
    return mysql.query(sql)
end

function _M.get_release(version)
    local rows, err = mysql.query("SELECT * FROM waf_geoip_release WHERE version=" .. quote(version) .. " LIMIT 1")
    return rows and rows[1] or nil, err
end

function _M.list_releases()
    return mysql.query([[SELECT version,checksum,file_size,build_time,status,notes,created_by,created_at
        FROM waf_geoip_release ORDER BY created_at DESC LIMIT 100]])
end

function _M.list_online_nodes(window_seconds)
    local sql = string.format([[SELECT ip,hostname,app_version,mmdb_checksum,last_seen FROM waf_cluster_node
        WHERE last_seen >= NOW() - INTERVAL %d SECOND ORDER BY ip]], tonumber(window_seconds) or 300)
    return mysql.query(sql)
end

function _M.create_deployment(values)
    local sql = string.format([[INSERT INTO waf_geoip_deployment
        (task_id,release_version,release_checksum,node_ip,status,message,created_by)
        VALUES (%s,%s,%s,%s,'queued','waiting for node',%s)]],
        quote(values.task_id), quote(values.release_version), quote(values.release_checksum),
        quote(values.node_ip), quote(values.created_by or ""))
    return mysql.query(sql)
end

function _M.list_deployments()
    return mysql.query([[SELECT d.task_id,d.release_version,d.release_checksum,d.node_ip,d.status,d.message,
        d.created_by,d.created_at,d.updated_at,d.finished_at,n.hostname,n.mmdb_checksum,
        n.geoip_update_target,n.geoip_update_status,n.geoip_update_message,n.geoip_update_at,n.last_seen
        FROM waf_geoip_deployment d LEFT JOIN waf_cluster_node n ON n.ip=d.node_ip
        ORDER BY d.created_at DESC LIMIT 500]])
end

function _M.reconcile_deployments()
    return mysql.query([[UPDATE waf_geoip_deployment d JOIN waf_cluster_node n ON n.ip=d.node_ip
        SET d.status=CASE
            WHEN n.mmdb_checksum=d.release_checksum AND n.geoip_update_status='success' THEN 'success'
            WHEN n.geoip_update_target=d.release_version AND n.geoip_update_status<>'' THEN n.geoip_update_status
            ELSE d.status END,
            d.message=CASE WHEN n.geoip_update_target=d.release_version THEN n.geoip_update_message ELSE d.message END,
            d.finished_at=CASE WHEN n.mmdb_checksum=d.release_checksum AND n.geoip_update_status='success'
                THEN COALESCE(d.finished_at,NOW()) ELSE d.finished_at END
        WHERE d.status NOT IN ('success','cancelled')]])
end

return _M

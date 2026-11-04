package.path = "lib/?.lua;" .. package.path
ngx = {time=function() return os.time({year=2026,month=11,day=4,hour=12}) end, ERR=1, log=function() end,
    quote_sql_str=function(s) return "'" .. s .. "'" end}
local calls, fail, closed, empty = {}, nil, false, false
local db = {}
function db:query(sql)
    calls[#calls+1] = sql
    if fail and sql:find(fail, 1, true) then return nil, "simulated failure" end
    if sql:find("GET_LOCK", 1, true) then return {{acquired=1}} end
    if sql:find("RELEASE_LOCK", 1, true) then return {{released=1}} end
    if sql:find("WEEKDAY", 1, true) then return {{week_start="20261102",week_end="20261108"}} end
    if sql:find("INFORMATION_SCHEMA", 1, true) then
        local a,b = sql:match("IN %('([^']+)','([^']+)'%)")
        return {{TABLE_NAME=a,ENGINE="InnoDB"},{TABLE_NAME=b,ENGINE="InnoDB"}}
    end
    if sql:find("^SELECT") then return empty and {} or {{id="10"},{id="20"}} end
    if sql:find("^INSERT") or sql:find("^DELETE") then return {affected_rows=2} end
    return {}
end
function db:close() closed = true; return true end
package.preload.mysql_cli = function()
    return {get_connection=function() return db end, close_connection=function() closed=true end}
end
local archive = require "archive_batch"
for _, kind in ipairs({"attack", "sensitive", "blocking", "dingtalk", "audit"}) do
    calls, fail, closed = {}, nil, false
    local result = archive.run(kind, 30, 5000)
    assert(result.code == 0 and result.inserted == 2 and result.deleted == 2 and closed)
    assert(result.archive_table:find("20261102_20261108", 1, true))
    assert(calls[7]:find("ORDER BY id ASC LIMIT 5000 FOR UPDATE", 1, true))
    assert(calls[8]:find("id IN (10,20)", 1, true))
    assert(calls[9]:find("id IN (10,20)", 1, true))
    assert(calls[10] == "COMMIT")
end
for _, operation in ipairs({"INSERT INTO", "DELETE FROM"}) do
    calls, fail, closed = {}, operation, false
    assert(archive.run("attack", 30, 2).code == 500)
    assert(calls[#calls-1] == "ROLLBACK" and closed)
    for _, sql in ipairs(calls) do assert(sql ~= "COMMIT") end
end
assert(archive.run("unknown", 30, 10).code == 500)
assert(archive.run("attack", 30, 50001).code == 500)
calls, fail, empty = {}, nil, true
assert(archive.run("attack", 30, 10).code == 0)
for _, sql in ipairs(calls) do assert(not sql:find("CREATE TABLE", 1, true), "empty batches must not create tables") end
print("ARCHIVE_BATCH_OK")

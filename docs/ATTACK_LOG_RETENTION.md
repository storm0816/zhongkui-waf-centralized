## attack_log 大表治理（上线建议）

> 已集成到系统设置页面：`系统设置 -> 攻击日志归档清理（懒人模式）`。  
> 可直接配置自动任务，或点击“立即执行一次”。

### 背景

`attack_log`会持续增长。当前表包含唯一索引`request_id`，不建议直接改造成 MySQL 分区主表（会影响唯一约束设计和写入幂等语义）。

推荐方案：主表保留最近数据（热数据），历史数据归档到按月分区的归档表。

### 目标

- `attack_log` 主表只保留最近 `30~90` 天，保证查询和写入稳定。
- 历史日志进入 `attack_log_archive`，支持长期留存和低频查询。
- 自动化归档与清理，降低人工运维成本。

### 1) 创建归档分区表

```sql
CREATE TABLE IF NOT EXISTS attack_log_archive LIKE attack_log;

-- 归档表按月分区（示例：2026-01 到 2027-01）
ALTER TABLE attack_log_archive
PARTITION BY RANGE (TO_DAYS(request_time)) (
    PARTITION p202601 VALUES LESS THAN (TO_DAYS('2026-02-01')),
    PARTITION p202602 VALUES LESS THAN (TO_DAYS('2026-03-01')),
    PARTITION p202603 VALUES LESS THAN (TO_DAYS('2026-04-01')),
    PARTITION p202604 VALUES LESS THAN (TO_DAYS('2026-05-01')),
    PARTITION p202605 VALUES LESS THAN (TO_DAYS('2026-06-01')),
    PARTITION p202606 VALUES LESS THAN (TO_DAYS('2026-07-01')),
    PARTITION p202607 VALUES LESS THAN (TO_DAYS('2026-08-01')),
    PARTITION p202608 VALUES LESS THAN (TO_DAYS('2026-09-01')),
    PARTITION p202609 VALUES LESS THAN (TO_DAYS('2026-10-01')),
    PARTITION p202610 VALUES LESS THAN (TO_DAYS('2026-11-01')),
    PARTITION p202611 VALUES LESS THAN (TO_DAYS('2026-12-01')),
    PARTITION p202612 VALUES LESS THAN (TO_DAYS('2027-01-01')),
    PARTITION pmax VALUES LESS THAN MAXVALUE
);
```

说明：
- 新月份到来前，补下个月分区即可。
- 可按你业务量改为按周分区。

### 2) 一次归档任务（按保留 30 天示例）

```sql
-- 先归档（忽略重复 request_id）
INSERT IGNORE INTO attack_log_archive
SELECT *
FROM attack_log
WHERE request_time < NOW() - INTERVAL 30 DAY
LIMIT 50000;

-- 再删除主表已归档数据（与上面同条件同批次）
DELETE FROM attack_log
WHERE request_time < NOW() - INTERVAL 30 DAY
LIMIT 50000;
```

建议循环批量执行，直到受影响行数为 0，避免长事务。

### 3) 自动定时归档（MySQL EVENT）

```sql
SET GLOBAL event_scheduler = ON;

DELIMITER $$
CREATE EVENT IF NOT EXISTS ev_attack_log_archive_daily
ON SCHEDULE EVERY 1 DAY
STARTS (CURRENT_DATE + INTERVAL 1 DAY + INTERVAL 10 MINUTE)
DO
BEGIN
    -- 每天归档 90 天前的历史数据（批量上限可按实例性能调整）
    INSERT IGNORE INTO attack_log_archive
    SELECT *
    FROM attack_log
    WHERE request_time < NOW() - INTERVAL 90 DAY
    LIMIT 50000;

    DELETE FROM attack_log
    WHERE request_time < NOW() - INTERVAL 90 DAY
    LIMIT 50000;
END$$
DELIMITER ;
```

说明：
- 大流量场景建议改为每小时执行一次，小批次（如 `5000~20000`）。
- 归档和删除可以拆成两个 EVENT，减少单次锁持有。

### 4) 查询口径建议

- 控制台默认查主表`attack_log`（近 30~90 天）。
- 需要查历史时，提供专门“历史查询入口”查`attack_log_archive`。
- 如果要做统一查询，可用 `UNION ALL` 视图（注意性能和分页）。

### 5) 上线检查项

- 确认 `request_time` 有索引（项目初始化已补：`idx_attack_log_request_time`）。
- 先做一次离峰手工归档，观察 MySQL CPU/IO 与锁等待。
- 观察 3 天：主表行数趋势、慢 SQL、归档任务耗时。

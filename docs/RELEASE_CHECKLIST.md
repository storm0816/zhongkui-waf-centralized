# 上线前验收单（Master + Node）

## 1. 基础环境
- [ ] `master` 与 `node` 时间同步正常（NTP 正常）
- [ ] `openresty` 进程正常，`nginx -t` 通过
- [ ] `system.json` 角色正确（master: `master=on`，node: `master=off`）
- [ ] Redis/MySQL 连通正常（账号、端口、密码已确认）

## 2. 集群与规则同步
- [ ] Master 可写入规则快照 key：`waf:cluster:rules:snapshot`
- [ ] Master 可写入版本 key：`waf:cluster:rules:snapshot:version`
- [ ] Node 页面显示 `规则版本`，且与 master 一致
- [ ] Node 日志无 `snapshot hash mismatch` 报错

## 3. 防护生效验证
- [ ] 使用测试请求触发黑 URL 规则，前端可看到攻击日志
- [ ] 触发封禁后 Redis 出现 `black_ip:*`
- [ ] 封禁日志可从 Redis 队列落到 MySQL `ip_block_log`
- [ ] 管理后台“解除封禁”可正常执行，无 500 报错

## 4. 数据链路验证
- [ ] `attack_log` 持续入库（字段含 `node_ip`、`attack_type`、`action`）
- [ ] `waf_status` 持续更新（请求数/拦截数增长正常）
- [ ] 节点心跳正常（在线节点页面状态正确）
- [ ] 节点掉线判定符合预期（无误报频繁掉线）

## 5. 页面与功能验收
- [ ] 仪表盘数据正常显示（非全 0）
- [ ] IP 封禁日志页面可查询、可解封
- [ ] 在线节点页面显示 `规则版本/同步状态`
- [ ] 全球攻击态势页面可正常加载地图和数据
- [ ] 流量趋势图可见 X/Y 轴、时间和数量标注

## 6. 运维与回滚准备
- [ ] 已备份 `conf/system.json`、`conf/global.json`、`conf/global_rules/*`
- [ ] 已备份 MySQL 关键表（`attack_log`、`ip_block_log`、`waf_status`）
- [ ] 已确认回滚包或上一个 tag 可用
- [ ] 已记录本次发布版本号/时间/负责人

## 7. 建议压测前置（生产前）
- [ ] 至少做 30 分钟持续流量回放
- [ ] 观察 Redis 内存与 key 增长趋势
- [ ] 观察 MySQL 写入延迟与慢 SQL
- [ ] 确认归档策略参数（`days`/`batch_size`/`interval_seconds`）符合容量预期


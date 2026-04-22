## 私有化开发（集群模式）

### 功能概览

- 攻击日志进行汇总
- 黑名单通过 master，进行分发，节点黑名单过滤，新增 master 黑名单。
- dashboard 前端页面所有数据汇总

### 集群角色说明

集群角色由`conf/system.json`中的`redis`、`centralized`、`master`三个开关共同决定：

| `redis.state` | `centralized.state` | `master.state` | 角色/模式 |
|---|---|---|---|
| `on` | `on` | `on` | master 节点（集群） |
| `on` | `on` | `off` | node 节点（集群） |
| `off` 或 `on` | `off` | 任意 | 单机模式 |
| `off` | `on` | 任意 | 单机模式（未启用 Redis） |

### 黑名单同步机制

master 节点会将黑名单写入 Redis（key: `waf:masterIpBlackList`），采用结构化 payload：

```json
{
  "version": "1713686400123",
  "updated_at": "2026-04-21 16:00:00",
  "source": "master-hostname",
  "items": ["1.2.3.4", "10.0.0.0/24"]
}
```

node 节点定时拉取该 payload，并按`version`做增量更新：

- 若`version`未变化：跳过重载，避免频繁重建`ipmatcher`。
- 若`version`变化：更新本机 matcher，并记录最新版本。
- 仍兼容旧格式（仅 IP 数组）数据，平滑升级不需要停机迁移。

master 节点职责：

- 从本机`conf/global_rules/ipBlackList`发布 master 黑名单到 Redis，供所有节点拉取。
- 汇总 Redis 中的攻击日志、WAF 状态、流量统计、IP 阻断日志、攻击类型统计和节点心跳，并写入 MySQL。
- 负责集群 dashboard 所需的汇总数据落库。

node 节点职责：

- 执行本机 WAF 拦截逻辑。
- 从 Redis 拉取 master 下发的黑名单并加载到本机 worker 内存。
- 将本机攻击日志、阻断日志、流量统计、攻击类型统计和节点心跳上报到 Redis。
- 不执行 Redis 到 MySQL 的汇总落库任务。

master 节点配置示例：

```json
{
  "redis": {
    "state": "on"
  },
  "centralized": {
    "state": "on"
  },
  "master": {
    "state": "on"
  }
}
```

node 节点配置示例：

```json
{
  "redis": {
    "state": "on"
  },
  "centralized": {
    "state": "on"
  },
  "master": {
    "state": "off"
  }
}
```

单机模式配置示例：

```json
{
  "centralized": {
    "state": "off"
  }
}
```

注意：`conf/system.json`是标准 JSON 文件，不能直接写注释，否则 WAF 启动时会解析失败。部署时建议为 master 和 node 分别维护独立的`system.json`模板。

### 第三步（已完成）：汇总链路幂等与数据一致性

| 模块 | 调整点 | 作用 |
|---|---|---|
| 攻击日志落库 | `attack_log.request_id`增加唯一索引`idx_unique_attack_log_request_id`；写入时增加`ON DUPLICATE KEY UPDATE`；成功后删除 Redis 队列 key | 防止重复写入，重复消费时自动幂等 |
| 老环境迁移 | 启动初始化阶段自动检查`attack_log`唯一索引，缺失时补齐 | 兼容历史库，升级无需手工改表 |
| 攻击类型统计 | MySQL 同步时扫描`waf:attack_type_traffic_map:*`所有日期 key，并按 key 日期写入 | 修复仅同步当天数据导致的统计缺失 |
| IP 封禁日志 | 写库时识别并跳过重复键错误（Duplicate entry） | 减少重复数据导致的任务中断 |
| 流量按小时统计 | 将`YYYY-MM-DD HH`统一归一为`YYYY-MM-DD HH:00:00`后再写库 | 避免时间格式不一致导致统计异常 |

对应关键实现文件：`lib/sql.lua`（含建表、迁移检查、Redis->MySQL 同步逻辑）。

### 第四步（已完成）：节点在线判定统一与自动清理

| 模块 | 调整点 | 作用 |
|---|---|---|
| 在线判定统一 | 节点列表接口返回`is_online`（基于`last_seen >= NOW() - INTERVAL system.expire SECOND`） | 页面与后端统计使用同一判定口径，避免“看起来不一致” |
| 页面渲染 | `cluster-nodes.html`改为使用后端`is_online`标记离线行与删除按钮 | 去掉前端写死阈值（120 秒）导致的偏差 |
| 自动清理 | master 定时执行离线节点清理任务`sql.cleanup_offline_cluster_nodes` | 清理长期离线历史节点，避免`waf_cluster_node`持续膨胀 |
| 初始化迁移 | `check_table`补充`waf_cluster_node.idx_last_seen`索引检查与自动补齐 | 保证老环境升级后查询和清理性能稳定 |

新增/约定配置项（`conf/system.json -> system`）：

| 字段 | 默认值 | 说明 |
|---|---|---|
| `expire` | `120` | 节点在线超时阈值（秒） |
| `node_retention` | `86400` | 节点离线保留时长（秒），master 会清理超过该时长的离线节点 |

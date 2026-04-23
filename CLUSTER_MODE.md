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

### 配置文件模板

项目底层代码保持一套，master 和 node 通过配置文件区分角色。运行时程序只读取`conf/system.json`，部署时按角色选择模板复制为`conf/system.json`。

| 文件 | 用途 |
|---|---|
| `conf/system-master.json` | master 节点模板，开启`redis`、`centralized`、`master`，并开启 MySQL 汇总落库 |
| `conf/system-node.json` | node 节点模板，开启`redis`、`centralized`，关闭`master`；`mysql.state`为`off`，不配置 MySQL 连接信息 |
| `conf/system.json` | 当前实例实际运行配置，启动时只读取这个文件 |

master 节点部署时：

```bash
./install.sh --role master
```

如果 master 需要使用包内 Redis，可以额外添加`--init-local-redis`：

```bash
./install.sh --role master --init-local-redis --redis-password Push@789
```

node 节点部署时：

```bash
./install.sh --role node
```

安装脚本会优先安装当前目录中的代码，自动复制对应模板为`conf/system.json`，并生成 OpenResty 的`nginx.conf`。master 会 include `admin/conf/admin.conf`开放控制台，node 不会 include 控制台配置。

默认不会在本机安装和初始化 MySQL。master 使用`conf/system-master.json`中的 MySQL 配置连接数据库；如果需要在 master 机器上同时初始化本机 MySQL，可以执行：

```bash
./install.sh --role master --init-local-mysql
```

如果是手工部署，也可以直接复制模板：

```bash
cp conf/system-master.json conf/system.json
# 或
cp conf/system-node.json conf/system.json
```

推荐所有节点使用同一套代码版本，只在部署阶段选择角色配置。这样可以避免 master/node 代码分叉，也方便后续升级和回滚。

控制台只建议在 master 节点开放。node 节点只负责本机 WAF 拦截、拉取 master 黑名单、上报 Redis 数据，不建议 include `admin/conf/admin.conf`，避免在子节点误改配置。代码层也做了兜底：如果 node 误 include 了`admin.conf`，访问控制台会直接返回 403。

node 配置中保留`mysql.state = off`只是为了让代码按统一配置结构读取；node 不需要 MySQL 账号密码，也不会执行 Redis 到 MySQL 的汇总落库任务。

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

### Redis Key 规范

集群模式下，跨节点共享的 Redis key 统一使用`waf:`前缀。master 负责消费汇总类 key 并写入 MySQL，node 负责写入上报类 key。

| Key/Pattern | 类型 | 写入方 | 读取/消费方 | TTL | 用途 |
|---|---|---|---|---|---|
| `waf:masterIpBlackList` | String(JSON) | master | node | 不过期 | master 下发的全局黑名单，包含`version`、`updated_at`、`source`、`items` |
| `waf:cluster:nodes:<node_ip>` | Hash | master/node | master | `system.expire` | 节点心跳，上报`ip`、`version`、`hostname`、`timestamp` |
| `waf:attack_log:<ip><request_id>` | String(JSON) | node | master | `redis.expire_time` | 攻击日志队列，master 落库成功后删除 |
| `waf:traffic_stats:<region_prefix><yyyy-mm-dd>` | String(JSON) | node | master | `redis.expire_time` | 地域维度流量统计，master 汇总到`traffic_stats` |
| `waf:waf_status_hmap:<yyyy-mm-dd>` | Hash | node | master | `redis.expire_time` | WAF 总览指标，如请求数、攻击数、拦截数 |
| `waf:ip_balck_sql_values:<queue_name>:<timestamp>` | String(SQL values) | node | master | `redis.expire_time` | IP 封禁日志队列，保留历史拼写`balck`以兼容当前代码 |
| `waf:attack_type_traffic_map:<yyyy-mm-dd>` | Hash | node | master | `redis.expire_time` | 攻击类型统计，field 为攻击类型，value 为次数 |
| `waf:waf_traffic_stats:<yyyy-mm-dd>` | String(CSV) | node | master | 3600 秒 | 按小时请求/攻击/拦截统计 |

本地运行和安全能力相关 key：

| Key/Pattern | 类型 | 写入方 | 读取方 | TTL | 用途 |
|---|---|---|---|---|---|
| `black_ip:<ip>` | String/Number | WAF 动作模块 | WAF 访问控制 | 由封禁策略决定 | 自动拉黑 IP |
| `captcha:<hash>` | String/Number | 人机验证模块 | 人机验证模块 | 由验证码策略决定 | 验证码挑战状态 |
| `captcha_accesstoken:<hash>` | String | 人机验证模块 | 人机验证模块 | 由验证码策略决定 | 验证通过后的访问 token |

排查示例：

```bash
redis-cli --scan --pattern 'waf:cluster:nodes:*'
redis-cli --scan --pattern 'waf:attack_log:*'
redis-cli --scan --pattern 'waf:attack_type_traffic_map:*'
redis-cli GET waf:masterIpBlackList
```

约定：新增集群共享 key 时优先使用`waf:<module>:<biz_id>`或`waf:<module>:<yyyy-mm-dd>`格式，并在本节同步说明。已有线上 key 不轻易改名，避免 master/node 版本不一致时丢数据。

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
| 在线判定统一 | 节点列表接口返回`is_online`（基于`last_seen >= NOW() - INTERVAL (system.expire + system.node_offline_grace) SECOND`） | 页面与后端统计使用同一判定口径，并增加缓冲避免短暂抖动误判离线 |
| 页面渲染 | `cluster-nodes.html`改为使用后端`is_online`标记离线行与删除按钮 | 去掉前端写死阈值（120 秒）导致的偏差 |
| 自动清理 | master 定时执行离线节点清理任务`sql.cleanup_offline_cluster_nodes` | 清理长期离线历史节点，避免`waf_cluster_node`持续膨胀 |
| 初始化迁移 | `check_table`补充`waf_cluster_node.idx_last_seen`索引检查与自动补齐 | 保证老环境升级后查询和清理性能稳定 |

新增/约定配置项（`conf/system.json -> system`）：

| 字段 | 默认值 | 说明 |
|---|---|---|
| `expire` | `120` | 节点心跳 TTL（秒）与基础在线窗口（秒） |
| `node_offline_grace` | `180` | 在线判定额外缓冲（秒）；最终离线阈值=`expire + node_offline_grace` |
| `node_retention` | `86400` | 节点离线保留时长（秒），master 会清理超过该时长的离线节点 |

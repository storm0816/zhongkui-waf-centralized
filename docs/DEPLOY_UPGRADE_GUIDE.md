# 升级与部署手册

## 1. 适用范围

本手册适用于以下场景：

- 新部署 `master` / `node`
- 从旧版本升级到当前版本
- 清理旧版本后全量重部署

本文默认：

- 项目部署目录：`/opt/openresty/zhongkui-waf`
- OpenResty 二进制：`/opt/openresty/nginx/sbin/nginx`
- Redis 使用当前正式 key：
  - `waf:rules:ip_whitelist`
  - `waf:rules:ip_blacklist`

## 2. 发布前原则

发布前请先确认：

1. `master` 与 `node` 使用同一套代码版本。
2. 不再依赖旧黑名单 key `waf:masterIpBlackList`。
3. MySQL 账号具有建表、加列、加索引权限。
4. `conf/system.json` 角色与目标机器一致。

## 3. 发布前备份

### 代码与配置备份

```bash
cd /opt/openresty
cp -a zhongkui-waf zhongkui-waf.bak.$(date +%Y%m%d%H%M%S)
```

建议额外备份：

- `conf/system.json`
- `conf/global.json`
- `conf/global_rules/*`
- `conf/website.json`
- `conf/ipgroup.json`

### MySQL 备份

至少备份以下表：

- `attack_log`
- `ip_block_log`
- `waf_status`
- `traffic_stats`
- `waf_cluster_node`

示例：

```bash
mysqldump -h <mysql_host> -P <mysql_port> -u <mysql_user> -p'<mysql_password>' \
  <mysql_db> attack_log ip_block_log waf_status traffic_stats waf_cluster_node \
  > zhongkui_waf_backup_$(date +%Y%m%d%H%M%S).sql
```

### Redis 备份

重点确认以下 key：

- `waf:cluster:rules:snapshot`
- `waf:cluster:rules:snapshot:version`
- `waf:rules:ip_whitelist`
- `waf:rules:ip_blacklist`
- `waf:cluster:nodes:*`

## 4. 升级方式

### 方式 A：原地升级

适合：

- 保留现有部署目录
- 保留现有 MySQL 历史数据
- 保留现有 Redis 数据

步骤：

1. 备份旧目录与配置。
2. 替换代码目录。
3. 确认 `conf/system.json` 正确。
4. 执行上线前检查脚本。
5. 执行 `nginx -t`。
6. reload OpenResty。
7. 执行上线后检查脚本。

### 方式 B：清理后重部署

适合：

- 历史版本较乱
- 准备统一切换新 key / 新页面 / 新节点链路
- 所有 `node` 可以一起替换

步骤：

1. 先备份旧目录、MySQL、Redis。
2. 删除旧项目目录。
3. 重新部署 `master`。
4. 再部署所有 `node`。
5. 执行上线后检查脚本。

注意：

- 若保留 MySQL 历史表，则不要删数据库。
- 若保留 Redis 运行态，请确认不再依赖历史 key。

## 5. Master 部署步骤

### 5.1 同步代码

将当前版本同步到目标机，例如：

```bash
rsync -avz --delete ./ root@<master_ip>:/opt/openresty/zhongkui-waf/
```

### 5.2 确认配置

重点检查：

- `conf/system.json`
- `conf/global.json`
- `conf/global_rules/ipWhiteList`
- `conf/global_rules/ipBlackList`

### 5.3 执行上线前检查

```bash
cd /opt/openresty/zhongkui-waf
./scripts/preflight_check.sh --role master
```

### 5.4 校验并重载

```bash
/opt/openresty/nginx/sbin/nginx -t
/opt/openresty/nginx/sbin/nginx -s reload
```

### 5.5 执行上线后检查

```bash
cd /opt/openresty/zhongkui-waf
./scripts/post_deploy_check.sh --role master
```

## 6. Node 部署步骤

### 6.1 同步代码

```bash
rsync -avz --delete ./ root@<node_ip>:/opt/openresty/zhongkui-waf/
```

### 6.2 确认配置

重点检查：

- `conf/system.json`
- `master.state = off`
- `centralized.state = on`
- `redis.state = on`
- `mysql.state = off`

### 6.3 执行上线前检查

```bash
cd /opt/openresty/zhongkui-waf
./scripts/preflight_check.sh --role node
```

### 6.4 校验并重载

```bash
/opt/openresty/nginx/sbin/nginx -t
/opt/openresty/nginx/sbin/nginx -s reload
```

### 6.5 执行上线后检查

```bash
cd /opt/openresty/zhongkui-waf
./scripts/post_deploy_check.sh --role node
```

## 7. 本次版本重点变更提醒

### 黑白名单

- 白名单正式 key：`waf:rules:ip_whitelist`
- 黑名单正式 key：`waf:rules:ip_blacklist`

当前版本不再兼容：

- `waf:masterIpBlackList`

因此升级要求：

- `master` 与所有 `node` 必须整体升级

### 节点表结构

`waf_cluster_node` 可能自动补以下字段：

- `whitelist_version`
- `blacklist_version`
- `rules_sync_status`
- `rules_sync_at`
- `whitelist_sync_status`
- `whitelist_sync_at`
- `blacklist_sync_status`
- `blacklist_sync_at`
- `last_sync_status`
- `last_sync_at`

## 8. 上线后验证重点

### Master 必查

1. `waf:cluster:rules:snapshot:version` 存在
2. `waf:rules:ip_whitelist` 存在
3. `waf:rules:ip_blacklist` 存在
4. 后台可登录
5. 在线节点页正常
6. 全球/中国大屏可打开

### Node 必查

1. 心跳已进入 `waf:cluster:nodes:*`
2. 在线节点页能看到该节点
3. 规则版本与 master 一致
4. 白名单/黑名单同步状态正常

## 9. 回滚策略

### 代码回滚

```bash
mv /opt/openresty/zhongkui-waf /opt/openresty/zhongkui-waf.failed.$(date +%Y%m%d%H%M%S)
mv /opt/openresty/zhongkui-waf.bak.<backup_time> /opt/openresty/zhongkui-waf
/opt/openresty/nginx/sbin/nginx -t
/opt/openresty/nginx/sbin/nginx -s reload
```

### MySQL 回滚

按备份 SQL 恢复。

### Redis 回滚

若需要回滚运行态：

- 恢复规则快照 key
- 恢复黑白名单 key
- 清理异常节点心跳 key

## 10. 推荐执行顺序

1. 备份
2. `master` 升级
3. 验证 `master`
4. 全量 `node` 升级
5. 验证节点同步
6. 验证大屏与后台
7. 记录版本号、时间、负责人

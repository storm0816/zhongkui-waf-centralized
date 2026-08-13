## ZhongKui-WAF

`Zhongkui-WAF` 基于 `lua-nginx-module`，用于在 OpenResty 层对 Web 请求做实时检测、拦截、记录与可视化管理。项目支持单机和集群两种部署模式，适合从测试到生产逐步扩展。

当前版本：`Version 2.0.0`

### 2.0.0 发布说明

- 集群规则以 MySQL 为权威来源：首次初始化后，master 启动和定时校验都会将 MySQL 已发布版本恢复到本地与 Redis。
- 提供独立的 master、node 安装包，按节点角色直接部署。
- 新增 LDAP、MFA、角色权限、反爬虫、爬虫公约和规则例外白名单能力。
- 钉钉仅推送 IP 封禁事件；普通攻击日志仍会正常写入日志与 MySQL，不再产生通知噪声。

### 功能总览

基础防护能力：
- 三种运行模式：关闭、保护（拦截+记录）、监控（仅记录）
- 规则防护：URL/参数/Header/Cookie/Body、上传扩展名、HTTP Method
- 攻击检测：SQL 注入、XSS、SSRF、CC、Bot、反爬虫、人机验证、ACL、自定义规则
- 爬虫治理：访问频率限制、UA 强制规则、Bot 陷阱、动态 `robots.txt`
- IP 管控：黑白名单（支持 IPv6 与网段）
- 敏感数据过滤：身份证、手机号、银行卡、密码等脱敏与关键词过滤

平台与数据能力：
- 站点独立配置 + 全局配置
- 管理后台可视化（攻击日志、流量统计、节点状态）
- 管理台账号支持角色权限、LDAP 主备认证、TOTP MFA 与操作审计
- 支持 Redis + MySQL 的集群化架构
- 攻击日志归档清理（系统页面懒人模式，支持自动与手动执行）
- 规则情报候选池（每日自动生成候选，人工审核，默认不自动生效）

集群增强能力（当前版本）：
- master 集中发布规则快照，node 增量拉取并热更新
- 快照带 `hash`（md5）校验，node 校验通过后才应用
- 节点页面显示 `规则版本`、`规则发布时间`、`同步状态`
- 白名单 / 黑名单支持 Redis 集中同步（master 写入，node 拉取）
- 网站防护支持 `规则例外白名单`（按域名+方法+路径+模块定向放行）
- 统计/日志链路支持 dirty set、retry set、队列化落库，降低扫描与写库压力

### 安装与部署

推荐直接使用安装命令：

```bash
tar -xzf zhongkui-waf-node-2.0.0.tar.gz
cd zhongkui-waf-node-2.0.0
chmod +x install.sh
sudo ./install.sh --role node
```

master 节点：

```bash
tar -xzf zhongkui-waf-master-2.0.0.tar.gz
cd zhongkui-waf-master-2.0.0
chmod +x install.sh
sudo ./install.sh --role master
```

本机 Redis：

```bash
sudo ./install.sh --role node --init-local-redis --redis-port 16381 --redis-password '<your-redis-password>'
```

本机 MySQL 和 Redis：

```bash
sudo ./install.sh --role master --init-local-mysql --mysql-user zhongkui --mysql-password '<your-mysql-password>' --init-local-redis --redis-port 16381 --redis-password '<your-redis-password>'
```

密码直接通过命令参数传入，方便复制部署。外部 MySQL/Redis 的地址和账号仍需提前填写对应的 `conf/system-master.json` 或 `conf/system-node.json`。

高级安装和无人值守参数见：[安装包与发布流程](./docs/INSTALL_PACKAGING.md)。

账号、角色、LDAP 与 MFA 配置见：[管理台账号、LDAP 与 MFA](./docs/ACCESS_CONTROL.md)。

生成版本安装包：

```bash
chmod +x scripts/build_release.sh
./scripts/build_release.sh
```

安装包会生成到 `dist/`：`zhongkui-waf-master-2.0.0.tar.gz` 与 `zhongkui-waf-node-2.0.0.tar.gz`。构建使用本机忽略的 `.zhongkui.release.env` 注入生产 MySQL/Redis；Git 模板始终使用 `10.10.10.10` 占位，不包含钉钉 Webhook、LDAP 或数据库密码。完整说明见：[安装包与发布流程](./docs/INSTALL_PACKAGING.md)。

常用参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--role master\|node` | `master` | 指定当前机器部署为 master 或 node |
| `--fresh` | 关闭 | 清理重装模式：安装前将`/opt/openresty`整体备份后移走，再进行全新安装 |
| `--init-local-mysql` | 关闭 | master 机器上同时安装并初始化本机 MySQL |
| `--mysql-user USER` | 空 | 配合`--init-local-mysql`使用，指定要创建并写入配置的 MySQL 账号 |
| `--mysql-password PASSWORD` | 空 | 配合`--init-local-mysql`使用，指定新建 MySQL 账号密码 |
| `--init-local-redis` | 关闭 | 使用`waf/redis16381.zip`安装并启动本机 Redis |
| `--redis-port PORT` | `16381` | 配合`--init-local-redis`使用，指定本机 Redis 端口 |
| `--redis-password PASSWORD` | 空 | 配合`--init-local-redis`使用，指定本机 Redis 密码 |
| `--redis-db DB` | `0` | 配合`--init-local-redis`使用，指定本机 Redis 库号 |

常见部署场景：

| 场景 | 安装命令 | 安装前需要确认 |
|---|---|---|
| master 使用外部 MySQL 和外部 Redis | `sudo ./install.sh --role master` | 先修改`conf/system-master.json`中的`mysql`和`redis`连接信息 |
| master 清理重装（保留一份整目录备份） | `sudo ./install.sh --role master --fresh` | 适用于重建环境；会把`/opt/openresty`移动到`/opt/openresty.fresh.bak.<时间>` |
| master 使用外部 MySQL，本机 Redis | `sudo ./install.sh --role master --init-local-redis --redis-password '<strong-random-password>'` | MySQL 连接仍从`conf/system-master.json`读取；Redis 会自动切到`127.0.0.1:16381`，默认 `db=0` |
| master 同时初始化本机 MySQL 和本机 Redis | `sudo ./install.sh --role master --init-local-mysql --mysql-user zhongkui --mysql-password '<strong-random-password>' --init-local-redis --redis-password '<strong-random-password>'` | MySQL 会自动切到`127.0.0.1:3306`，Redis 会自动切到`127.0.0.1:16381`，默认 `db=0` |
| node 节点 | `sudo ./install.sh --role node` | 先修改`conf/system-node.json`中的 Redis 连接信息；node 不需要 MySQL |
| 单机模式 | `sudo ./install.sh --role master` | 先将`conf/system-master.json`中的`centralized.state`改为`off`，并按需配置 MySQL/Redis |

### 安装脚本行为说明

- `install.sh` 会安装 OpenResty 与依赖，并按角色生成 `conf/system.json`；部署前按实际环境检查对应角色模板中的连接信息。
- 默认不是全新清理安装，会尽量保留现网配置与数据；若需彻底重装请加`--fresh`。
- `--fresh` 会在安装前将`/opt/openresty`整体备份并移走，再执行全新安装（备份目录：`/opt/openresty.fresh.bak.<时间>`）。
- 脚本优先使用项目 `waf/` 下离线包，缺失时才尝试联网下载。
- 基于 `waf/nginx.conf.default` 覆盖 OpenResty 默认配置：
  - 保留默认 80 端口 `server`
  - 在 `http` 层挂载 ZhongKui-WAF 相关加载逻辑
  - 按角色决定是否 include 控制台配置
- `admin/conf/sites.conf` 默认留空，用于填写真实业务站点。

参数注意事项：

- `--init-local-mysql`：仅用于 master 本机初始化 MySQL。若使用外部 MySQL，不要添加。
- `--init-local-redis`：仅用于本机安装包内 Redis。若使用外部 Redis，不要添加。
- `waf/redis16381.zip` 当前为 Linux x86-64 构建，ARM 服务器不能直接使用。
- `luaossl` 模块文件名为 `_openssl.so`，默认路径 `/opt/openresty/lualib/_openssl.so`。

### 集群运行说明（重点）

- node 仅负责防护、上报 Redis，不直接做汇总落库。
- master 负责聚合 Redis 并落 MySQL（任务错峰 + 锁保护）。
- 节点离线判定窗口：`system.expire + system.node_offline_grace`（默认 `120 + 180 = 300` 秒）。
- 规则同步：
  - 后台保存后，master 立即异步发布规则快照
  - 同时保留定时发布兜底
  - node 按 `30s + 0~10s 随机偏移`拉取（先版本后正文）
  - 快照 `hash` 校验通过才应用

统计与落库策略：
- 攻击日志/封禁日志：Redis List 队列（`waf:queue:attack_log`、`waf:queue:ip_block_log`）
- 攻击日志归档：按 7 天落表到 `attack_log_archive_YYYYMMDD_YYYYMMDD`，避免单表无限增长
- 流量/攻击类型：dirty set 增量同步（`waf:dirty:traffic_stats`、`waf:dirty:attack_type_dates`）
- MySQL 异常时：retry set 回放补写（`waf:retry:*`）

Redis 故障降级（第 1 步）：
- 已内置“短时失败熔断”机制：Redis 在短时间连续失败后，会进入一个短暂降级窗口，减少连接风暴。
- 降级期间业务请求不会被 Redis 连接失败拖死；依赖 Redis 的能力会临时退化（如分布式同步/统计延后）。
- 可在`conf/system-master.json` / `conf/system-node.json`的`redis`下按需增加参数（不填则走默认值）：
  - `failure_threshold`：连续失败阈值（默认 `3`）
  - `failure_window_seconds`：失败统计窗口（默认 `30` 秒）
  - `degrade_seconds`：触发后降级时长（默认 `10` 秒）

规则情报候选（MVP）：
- master 每小时检查一次“当日是否已生成”，当日未生成则自动执行一次候选生成。
- 候选默认来源为`attack_log`聚合（按 URI + 攻击类型聚合）。
- 生成后进入“规则情报候选”页面人工审核（通过/驳回）。
- `通过`后仍不会立即生效，需执行下一步`发布规则`（页面按钮）：
  - 将候选写入`conf/global_rules/blackUrl.json`
  - 自动触发`reload`并由 master 发布快照，node 拉取后生效
- 可在页面点击“立即生成一次候选”手动执行。

候选生成参数文件：`conf/intel_sources.json`

```json
{
  "attack_log_agg": {
    "state": "on",
    "lookback_hours": 24,
    "min_hits": 20,
    "limit": 200
  }
}
```

参数说明：
- `state`：是否启用该来源。
- `lookback_hours`：回看攻击日志的小时窗口。
- `min_hits`：最小命中次数阈值。
- `limit`：单次最多生成/更新候选数量。

### 规则例外白名单（网站防护）

入口：
- `网站防护 -> 规则引擎 -> 规则例外白名单`

用途：
- 当某些业务接口会稳定触发特定检测模块（如 `xss`），但业务上确认是正常请求时，可按条件做“定向放行”。
- 放行只影响命中条件的请求，不会全局关闭 WAF。

当前匹配维度：
- `serverName`（域名）
- `method`（HTTP 方法）
- `uri`（路径正则）
- `module`（检测模块）

示例：

```json
{
  "serverName": "wfwfabioapi.gw.com.cn",
  "method": "POST",
  "uri": "^/inotes/(addMyStock|removeMyStock)$",
  "module": "xss"
}
```

说明：
- 当前实现为“按模块放行”（例如 `module=xss` 命中后跳过本次 xss 检测流程）。
- 这是有意的简化设计，降低配置和维护成本；如需更细粒度，可后续扩展“按规则标识放行”。

### 重部署后验收（建议）

在 master 上执行：

```bash
# 1) 查看规则版本 key 与快照是否存在
redis-cli -h <redis_host> -p <redis_port> -a '<redis_password>' GET waf:cluster:rules:snapshot:version
redis-cli -h <redis_host> -p <redis_port> -a '<redis_password>' GET waf:cluster:rules:snapshot | head -c 300

# 1.1) 查看白名单 / 黑名单集中化 key
redis-cli -h <redis_host> -p <redis_port> -a '<redis_password>' GET waf:rules:ip_whitelist | head -c 300
redis-cli -h <redis_host> -p <redis_port> -a '<redis_password>' GET waf:rules:ip_blacklist | head -c 300

# 2) 查看节点心跳中的规则版本字段（rules_version）
redis-cli -h <redis_host> -p <redis_port> -a '<redis_password>' --scan --pattern 'waf:cluster:nodes:*'
redis-cli -h <redis_host> -p <redis_port> -a '<redis_password>' HGETALL waf:cluster:nodes:<node_ip>

# 3) 验证 MySQL 节点表是否落库 rules_version
mysql -h <mysql_host> -P <mysql_port> -u <mysql_user> -p'<mysql_password>' -D <mysql_db> \
  -e "SELECT ip,rules_version,last_seen FROM waf_cluster_node ORDER BY last_seen DESC LIMIT 10;"

# 3.1) 验证白名单同步状态（node 应显示 ok）
mysql -h <mysql_host> -P <mysql_port> -u <mysql_user> -p'<mysql_password>' -D <mysql_db> \
  -e "SELECT ip,whitelist_version,whitelist_sync_status,whitelist_sync_at,last_sync_status,last_seen FROM waf_cluster_node ORDER BY last_seen DESC LIMIT 20;"

# 4) 打开在线节点页面，确认“规则版本 / 规则发布时间 / 同步状态”三列已更新
curl -I http://<master_ip>:1226/
```

推荐：上线前按统一勾选清单执行一次完整回归，见：

- [docs/RELEASE_CHECKLIST.md](./docs/RELEASE_CHECKLIST.md)
- [docs/DEPLOY_UPGRADE_GUIDE.md](./docs/DEPLOY_UPGRADE_GUIDE.md)

白名单同步状态判定建议：
- `ok`：节点已拉取并应用白名单。
- `unknown`：节点未上报同步状态（常见于节点版本未升级、节点离线、或 Redis 链路异常）。
- 若 master 为 `ok`、node 长期 `unknown`，优先检查：
  - node 是否已升级到当前版本；
  - `conf/system.json` 中 `centralized/redis/master` 角色配置是否正确；
  - node 到 Redis 的连通性与认证信息是否一致。

### 管理后台

安装完成后访问：`http://localhost:1226`  
默认账号：`admin`  
默认密码：`zhongkui`

从 `v1.2` 开始，部分统计依赖 MySQL，需先配置数据库（`zhongkui_waf`）。

可根据访问量大小适当调整`waf.conf`文件中配置的字典内存大小。

```nginx
lua_shared_dict dict_cclimit 10m;
lua_shared_dict dict_accesstoken 5m;
lua_shared_dict dict_blackip 10m;
lua_shared_dict dict_locks 100k;
lua_shared_dict dict_config 100k;
lua_shared_dict dict_config_rules_hits 100k;
lua_shared_dict dict_req_count 5m;
lua_shared_dict dict_req_count_citys 10m;
lua_shared_dict dict_sql_queue 10m;

lua_package_path "/opt/openresty/zhongkui-waf/?.lua;/opt/openresty/zhongkui-waf/lib/?.lua;/opt/openresty/zhongkui-waf/admin/lua/?.lua;;";
init_by_lua_file  /opt/openresty/zhongkui-waf/init.lua;
init_worker_by_lua_file /opt/openresty/zhongkui-waf/init_worker.lua;
access_by_lua_file /opt/openresty/zhongkui-waf/waf.lua;
body_filter_by_lua_file /opt/openresty/zhongkui-waf/body_filter.lua;
header_filter_by_lua_file /opt/openresty/zhongkui-waf/header_filter.lua;
log_by_lua_file /opt/openresty/zhongkui-waf/log_and_traffic.lua;
```

重启`OpenResty`：

```bash
systemctl restart openresty
```

使用测试命令验证安装：

```bash
curl http://localhost/?t=../../etc/passwd
```

看到拦截信息则说明安装成功。

#### Bot 管理

Bot 管理包含四类能力，它们互相补充，不建议混为同一种规则：

- **反爬虫**：按站点和客户端 IP 统计访问频率，超过阈值后返回 `429`、拦截页、人机验证或自动封禁。
- **User-Agent 管理**：命中特定 UA 后立即执行动作，适合明确的恶意工具特征，不负责频率判断。
- **Bot 陷阱**：在 HTML 中加入普通用户不可见的陷阱 URI，访问该 URI 的客户端会被视为 Bot。
- **爬虫公约**：由 WAF 直接响应 `/robots.txt`，用于向遵守协议的正规爬虫声明允许或禁止抓取的路径。

反爬虫默认关闭，建议先使用“仅爬虫特征 UA”模式和较高阈值，再根据日志逐步调整。`robots.txt` 只是自愿协议，不能代替反爬虫限制。

不要仅凭 `Googlebot`、`Baiduspider` 等 User-Agent 配置“允许访问”。UA 可以伪造，这类规则可能绕过后续 WAF 检测。正规搜索引擎放行应结合来源 IP 或正反向 DNS 验证。

##### Bot 陷阱与 robots.txt

开启 bot 陷阱后，将会在上游服务器返回的 HTML 页面中添加配置的陷阱 URL，这个 URL 隐藏在页面中，对普通正常用户不可见，访问此 URL 的请求被视为 bot。

可以在“爬虫公约”中禁止正规爬虫访问陷阱 URI。这样遵守协议的爬虫不会触发陷阱，不遵守协议且扫描隐藏链接的爬虫仍可能被识别。注意：把陷阱地址写进 `robots.txt` 也会公开该路径，应结合实际风险决定是否使用。

示例：

```text
User-agent: *
Disallow: /zhongkuiwaf/honey/trap
```

完整配置、原理、测试方法和上线建议见：[反爬虫与爬虫公约](./docs/CRAWLER_PROTECTION.md)。

#### 敏感数据过滤

开启敏感信息过滤后，`Zhongkui-WAF`将对响应数据进行过滤。

`Zhongkui-WAF`内置了对响应内容中的身份证号码、手机号码、银行卡号、密码信息进行脱敏处理。需要注意的是，内置的敏感信息脱敏功能目前仅支持处理中华人民共和国境内使用的数据格式（如身份证号、电话号码、银行卡号），暂不支持处理中国境外的身份证号、电话号码、银行卡号等数据格式。但你可以使用正则表达式配置不同的规则，以过滤请求响应内容中任何你想要过滤掉的数据。

### 常见问题

一个常见问题是：用安装脚本安装后无法产生日志，在管理界面修改配置项，无法保存或可以保存但必须手动执行`nginx -s reload`才能生效，这些都是因为`nginx`默认是用`nobody`用户启动的，而`nobody`用户没有对日志目录和钟馗目录下的文件读写权限。

请确保`Openresty`对`zhongkui-waf`目录和`OpenResty`日志目录（`\logs\hack`），有读、写权限，否则`WAF`会无法修改配置文件和生成日志文件。最佳实践是：新建一个`nginx`用户，并将这个`nginx`用户添加到 sudoers，允许其执行`nginx`命令，然后将`zhongkui-waf`目录所属用户改为`nginx`用户，最后修改`nginx`配置文件，以`nginx`用户启动`nginx`。

```shell
# 添加nginx用户
sudo useradd nginx
# 使用sudo visudo命令将下面这行规则添加进去，将nginx用户添加到sudoers，仅允许其执行nginx命令
# nginx ALL=NOPASSWD: /opt/openresty/nginx/sbin/nginx
# 修改zhongkui-waf和日志目录归属用户
sudo chown -R nginx:nginx /opt/openresty/zhongkui-waf
sudo chown -R nginx:nginx /opt/openresty/nginx/logs/hack
```

修改`nginx.conf`：

```nginx
user nginx;
```

你也可以用 root 用户启动 nginx，但不推荐。

## 私有化开发（集群模式）

详细说明请查看：[docs/CLUSTER_MODE.md](./docs/CLUSTER_MODE.md)。

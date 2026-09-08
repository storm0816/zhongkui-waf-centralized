## ZhongKui-WAF

`Zhongkui-WAF` 基于 `lua-nginx-module`，用于在 OpenResty 层对 Web 请求做实时检测、拦截、记录与可视化管理。项目支持单机和集群两种部署模式，适合从测试到生产逐步扩展。

当前版本：`Version 2.2.1`

### 2.2.1 发布说明

- 发布中心的程序版本与 GeoIP 版本对账仅更新进行中的任务；成功、失败、回滚和跳过任务不会因节点后续上报当前版本而被覆盖。管理员显式执行重新下发时，才会重新激活对应任务。

### 2.2.0 发布说明

- 修复 URL 黑名单中 phpMyAdmin 安装探测和静态目录 PHP/JSP 文件检测的 PCRE 正则，使规则能够按预期命中。
- 收紧参数与 POST 正文中的 SQL 注入、RCE 规则：减少普通文本中的 `select`、`having`、`echo`、`print`、`alert` 等关键词造成的误报，同时保留高风险攻击结构检测。

### 2.1.9 发布说明

- 新增 IP 封禁日志与钉钉封禁通报记录的独立归档策略；两类记录共用保留天数、批次大小和执行间隔，仅由 Master 自动执行。
- IP 封禁日志按 `start_time`、钉钉发送记录按 `occurred_at` 分周归档；确认归档写入成功后再清理源表。
- 系统设置新增独立的手动归档入口，可分别查看 IP 封禁日志和钉钉封禁通报记录的归档数量。
- 钉钉封禁通报支持按精确域名启用汇总降频，可配置汇总周期、每日发送时间、指定通知人手机号及是否同时通知全局人员；未配置域名仍逐条发送封禁通报。
- IP 黑白名单提供“全局黑白名单 / 子域名黑白名单”两个入口。子规则按精确域名生效，支持白名单、黑名单、地域黑名单和备注。

### 2.1.8 发布说明

- 攻击日志与敏感数据发现共用归档保留天数、批次大小和执行间隔配置，仅由 Master 自动执行。
- 敏感数据发现按 `last_seen` 按周归档到 `sensitive_discovery_archive_YYYYMMDD_YYYYMMDD`；确认归档写入成功后再删除源记录。
- 系统设置的手动归档入口会同时执行攻击日志和敏感数据发现归档，并分别反馈处理数量。

### 2.1.7 发布说明

- 程序与 GeoIP 发布增加灰度发布、批次大小和批次间隔设置。
- 灰度节点发布成功后再推进后续批次；失败或回滚时暂停发布计划。
- 发布计划持久化到 MySQL，Master 重启后可继续执行未完成的批次。
- Node 仅在所属批次到达执行时间后领取任务，降低集中升级对网络带宽和服务稳定性的影响。

### 2.1.6 发布说明

- IP 黑白名单增加精确域名子白名单和子黑名单，全局名单继续生效，子规则仅做追加。
- 增加精确域名地域子黑名单，使用 GeoIP MMDB 原始国家/地区代码进行匹配。
- 子规则进入现有集群规则快照，按 MySQL 持久化、Redis 发布、Node 校验加载链路同步。
- 支持按站点和域名管理、启停、编辑、删除及备注，历史站点级地域配置继续兼容。

### 2.1.5 发布说明

- 发布中心增加 GeoIP 数据版本管理，与程序版本独立发布。
- Master 可从当前 MMDB 创建不可变数据快照，并灰度或批量发布到在线 Node。
- Node 下载后执行 SHA-256 和固定 IP 查询校验，再原子替换并重载 OpenResty。
- GeoIP 更新失败自动恢复旧数据库，节点心跳持续上报目标版本、状态和错误信息。

### 2.1.4 发布说明

- 新增 Master 程序发布中心，可从当前已验证代码创建不可变版本快照。
- Node 通过 Redis 领取目标版本，并从 Master 主动拉取、逐文件校验和原子切换。
- 支持选择 Node 灰度发布、全部在线 Node 发布、任务状态追踪和历史版本回滚发布。
- 程序与 GeoIP 发布统一支持自动灰度、批次大小和批次间隔；灰度失败暂停后续批次，发布计划可在 Master 重启后继续。
- 程序发布不覆盖 `conf/system.json`、证书、日志和运行规则；规则同步链路保持不变。
- 2.1.4 是自动发布基线，现有节点首次升级到该版本仍需使用传统升级方式。

### 2.1.3 发布说明

- 敏感数据模块改为只检测和汇总，不再改写业务响应。
- 安全运营新增“敏感数据发现”和“集群域名”页面。
- 集群域名支持域名、状态筛选及 24 小时访问升降序；CC 配置页同步增加域名和状态筛选。

### 2.1.2 发布说明

- 集群 CC 域名列表新增最近 24 小时访问汇总。
- 连续 24 小时未上报的域名可手动删除，并同时移除其 CC 特例阈值。

### 2.1.1 发布说明

- 集群 CC 域名由 Node 最近命中的 Nginx `server_name` 自动发现并上报，不再依赖 `website.json`。
- 仅接受 Nginx 实际选中的合法域名，不使用客户端可伪造的 `Host` 请求头。

### 2.1.0 发布说明

- 集群 CC 按 `Host + 客户端IP + CC规则` 计数，单机模式保持原有逻辑。
- Node 自动上报防护域名，Master 汇总域名、来源节点和 CC 实时数据。
- 域名默认阈值与特例阈值持久化到 MySQL，并通过 Redis 发布到全部 Node。
- 在线节点增加 GeoIP MMDB SHA-256 一致性校验，并更新 GeoLite2 City 数据库。

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
- IP 管控：全局黑白名单、精确子域名黑白名单、地域黑名单（支持 IPv6 与网段）
- 敏感数据发现：识别身份证、手机号、银行卡、密码等敏感内容并汇总记录，不改写业务响应

平台与数据能力：
- 站点独立配置 + 全局配置
- 管理后台可视化（攻击日志、流量统计、节点状态）
- 管理台账号支持角色权限、LDAP 主备认证、TOTP MFA 与操作审计
- 支持 Redis + MySQL 的集群化架构
- 攻击日志与敏感数据发现归档清理（共享保留、批次和频率配置，支持自动与手动执行）
- IP 封禁日志与钉钉封禁通报记录独立归档（共享保留、批次和频率配置，支持自动与手动执行）
- 规则情报候选池（每日自动生成候选，人工审核，默认不自动生效）

集群增强能力（当前版本）：
- master 集中发布规则快照，node 增量拉取并热更新
- 快照带 `hash`（md5）校验，node 校验通过后才应用
- 节点页面显示 `规则版本`、`规则发布时间`、`同步状态`
- 白名单 / 黑名单支持 Redis 集中同步（master 写入，node 拉取）
- 网站防护支持 `规则例外白名单`（按域名+方法+路径+模块定向放行）
- 统计/日志链路支持 dirty set、retry set、队列化落库，降低扫描与写库压力

### 运行模式与数据边界

| 模式 | 判定条件 | 防护与数据写入 | 规则权威来源 | 适用场景 |
|---|---|---|---|---|
| 单机 | `centralized=off`，或 Redis 未启用 | 本机防护；本机队列直接写入 MySQL | 本地 `conf/` 规则文件 | 单台 WAF、开发和独立业务环境 |
| 集群 Master | `centralized=on`、`redis=on`、`master=on` | 汇总 Redis 队列写 MySQL；发布规则、程序与 GeoIP | 首次初始化可从本地创建快照；之后 MySQL 已发布快照为唯一权威 | 集群控制节点 |
| 集群 Node | `centralized=on`、`redis=on`、`master=off` | 本机实时拦截、写 Redis、上报节点信息；不直接汇总落 MySQL | Redis 快照，校验后落本地 LKG 缓存 | 集群防护节点 |

集群模式的规则、全局黑白名单、子域名黑白名单、地域子黑名单、规则例外和敏感数据发现规则均进入同一规则快照：

1. 管理台在 Master 生成候选规则文件。
2. Master 将完整快照写入 MySQL，并完成哈希校验。
3. MySQL 持久化成功后，Master 发布到 Redis；失败时恢复上一个已发布版本。
4. Node 先比较版本，再拉取、校验并应用快照；保留最近一次有效快照（LKG）以应对短时 Redis 异常。
5. Master 启动及每 60 秒完整性校验，都会以 MySQL 最近已发布快照修复本地文件并重新对齐 Redis。

因此，集群运行中不要直接手工修改 Master 的 `conf/global_rules/`。这类修改会在下一次完整性校验时备份到 `conf/.cluster/conflicts/`，然后被 MySQL 已发布版本覆盖。应通过管理台完成修改并触发发布。

> 安全前提：WAF 当前会优先读取 `X-Forwarded-For` 等转发头识别客户端 IP。因此 WAF 前面若有负载均衡或反向代理，必须只允许可信代理访问 WAF，并由代理覆盖这些请求头；不得让公网客户端绕过代理直连 WAF。否则攻击者可伪造来源 IP，影响 IP 黑白名单、CC 计数、封禁和审计归因。

### 安装与部署

推荐直接使用安装命令：

```bash
tar -xzf zhongkui-waf-node-2.2.1.tar.gz
cd zhongkui-waf-node-2.2.1
sudo ./install.sh --role node
```

master 节点：

```bash
tar -xzf zhongkui-waf-master-2.2.1.tar.gz
cd zhongkui-waf-master-2.2.1
sudo ./install.sh --role master
```

已运行的服务器升级（保留本机配置）：
```bash
sudo ./upgrade.sh --role master
# node 包内执行：sudo ./upgrade.sh --role node
```

`upgrade.sh` 不会执行重编译，也不会用包内配置覆盖服务器的 `conf/system.json`。

### 一键发布 Node（2.1.4 及以上）

当 Master 和目标 Node 均已升级到 `2.1.4` 或更高版本后，后续程序升级可在
“集群与大屏 → 发布中心”完成：

1. 先把新版本代码升级到 Master 并完成验证。
2. 在“程序版本”创建当前版本的不可变快照，例如 `2.2.1`。已存在的版本快照不能覆盖。
3. 点击“发布”，选择参与范围：`发布所选`只处理勾选的 Node；`发布全部`处理列表内全部版本不同的在线 Node。
4. 选择发布方式：关闭灰度时按批次大小直接发布；开启灰度时，先发布指定的 1 台 Node，成功后再按批次大小和批次间隔继续其余节点。
5. 在任务列表确认每台 Node 的下载、校验、重载和版本上报均成功。

发布计划保存在 MySQL。Master 重启后会继续未完成的计划；灰度节点失败或回滚时，后续批次会自动暂停。GeoIP 数据发布使用相同的灰度和批次机制，但需在“GeoIP 版本”单独创建数据快照。

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
首次部署、现网站点 `nginx.conf` / `conf.d` / `html` 保留方式见：[简明部署文档](./docs/QUICK_DEPLOY.md)。

账号、角色、LDAP 与 MFA 配置见：[管理台账号、LDAP 与 MFA](./docs/ACCESS_CONTROL.md)。

项目架构、数据权威边界、维护规范与长期风险见：[项目基线与维护标准](./docs/PROJECT_BASELINE.md)。

生成版本安装包：

```bash
chmod +x scripts/build_release.sh
./scripts/build_release.sh
```

Windows 构建机可执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_release_windows.ps1
```

安装包会生成到 `dist/`：`zhongkui-waf-master-2.2.1.tar.gz` 与 `zhongkui-waf-node-2.2.1.tar.gz`。构建使用本机忽略的 `.zhongkui.release.env` 注入生产 MySQL/Redis、LDAP 与钉钉配置；Node 包不包含 LDAP 配置。Git 模板始终使用 `10.10.10.10` 占位，不包含这些凭据；`scripts/`、Git 和私有环境文件不会进入压缩包。构建后应验证 SHA-256、`install.sh`/`upgrade.sh` 的 `755` 权限、角色 JSON 合法性与 Node 配置未包含 LDAP 字段。完整说明见：[安装包与发布流程](./docs/INSTALL_PACKAGING.md)。

### 发布记录与重试说明

- Node 心跳只反映当前版本，不能代表过去任意一次发布的执行结果。因此程序版本和 GeoIP 的被动对账只会推进 `queued`、`downloading`、`switching` 三种进行中状态。
- 已成功、失败、回滚、取消或跳过的历史任务保持原结果；节点之后升级成功不会改写旧失败记录。
- 管理员在发布中心显式执行“重新下发”时，属于一次主动重试，会重新激活所选任务。需要保留完整审计时，应在发布记录中以新的发布计划重新发起。
- `2.2.1` 是 Master 侧发布记录修复；部署 Master 后立即生效，Node 不需要为此功能单独升级。一键发布仅在需要将 Node 程序版本同步到新快照时使用。

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

规则恢复与故障边界：
- 首次集群初始化且 MySQL 尚无已发布快照时，Master 才会将本地规则创建为首个发布版本。
- 后续 Master 重启、本地规则缺失、截断为空或内容不一致时，均从 MySQL 的最近已发布版本恢复本地文件，再发布到 Redis。
- Node 不以本地规则反向覆盖 Master；Redis 不作为规则最终权威来源，Redis 丢失后可由 Master 从 MySQL 重建。
- MySQL 不可用时，集群规则不能安全发布或恢复；已加载到各 Node 内存/LKG 的规则仍按现有进程状态继续工作，恢复数据库后应检查发布与节点同步状态。

统计、封禁与落库策略：
- 攻击日志/封禁日志：Redis List 队列（`waf:queue:attack_log`、`waf:queue:ip_block_log`）
- 敏感数据发现：Node/单机写入队列，Master/单机落库；仅保留脱敏后的命中样例
- 安全记录归档：攻击日志按 `request_time`、敏感数据发现按 `last_seen` 共用一套策略，按周落表到 `attack_log_archive_YYYYMMDD_YYYYMMDD` 与 `sensitive_discovery_archive_YYYYMMDD_YYYYMMDD`
- 封禁记录归档：IP 封禁日志按 `start_time`、钉钉发送记录按 `occurred_at` 共用另一套策略，按周落表到 `ip_block_log_archive_YYYYMMDD_YYYYMMDD` 与 `dingtalk_notification_archive_YYYYMMDD_YYYYMMDD`
- 所有归档均先 `INSERT IGNORE` 到归档表，确认写入后才删除源表；自动任务仅由集群 Master 执行，单机环境可通过系统设置的手动入口执行
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

### 全局与子域名 IP 策略

入口：`防护策略 -> IP 黑白名单`。

| 策略 | 匹配范围 | 配置内容 | 使用建议 |
|---|---|---|---|
| 全局白名单 | 所有受保护站点 | IP / IPv6 / CIDR 与备注 | 仅用于可信运维、探针、出口网段；命中后会跳过后续 WAF 检测 |
| 全局黑名单 | 所有受保护站点 | IP / IPv6 / CIDR 与备注 | 用于明确恶意来源或临时封禁 |
| 子域名白名单 | 一个精确域名 | 域名 + IP / CIDR + 备注 | 只放行该业务域名的必要来源，不替代全局白名单 |
| 子域名黑名单 | 一个精确域名 | 域名 + IP / CIDR + 备注 | 只封禁该业务域名的恶意来源 |
| 子域名地域黑名单 | 一个精确域名 | 域名 + ISO 3166-1 Alpha-2 国家/地区代码 | 依赖各 Node 的 GeoIP MMDB，发布 GeoIP 后应检查校验结果 |

规则说明：
- 子域名仅支持精确域名，例如 `api.example.com`；不支持 `*.example.com`。
- 全局策略与子域名策略是追加关系：任一黑名单命中即可拦截；全局白名单和子域名白名单都可放行。
- 同一域名、同一类型、同一值不能重复保存；全局和子域名出现相同 IP 时，管理台会提示冲突，避免配置歧义。
- 集群模式下，保存后由 Master 进入规则快照并发布；单机模式下，保存后直接重载本机规则。
- 生产环境应让 Nginx 默认站点拒绝未知 `Host`，并仅为真实受保护域名创建子策略。否则在“未知 Host 落到默认业务站点”的反向代理配置中，伪造 `Host` 可能使子域名策略落到非预期请求上。

### 钉钉封禁通报与汇总降频

入口：`安全运营 -> 封禁通报`。

- 未配置降频策略的域名：每次 IP 封禁均按现有逻辑尝试发送钉钉通报。
- 已配置并启用策略的精确域名：封禁、攻击日志、封禁日志和统计照常执行；只是不重复发送逐条钉钉消息。
- 汇总消息按策略中的“汇总周期 + 发送时间”发送，例如 `30 分钟 / 12:00` 表示以每日 `12:00` 为锚点切分 30 分钟窗口；消息包含该窗口的封禁总次数、主要封禁原因和时间范围。
- 策略可填写一个“通知人手机号”。填写后汇总消息会 `@` 该人员；“同时全局通知”开启时，还会合并系统设置的全局 `@` 人员并自动去重。手机号留空时始终使用全局通知人。
- “发送记录”同时保存成功和失败。失败记录包含失败原因，可与 IP 封禁日志共用独立归档策略。
- 集群模式由 Master 从 Redis 汇总并发送；单机模式由本机从本地持久化队列汇总并发送。

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

#### 敏感数据发现

敏感数据功能当前采用“发现与汇总”模式：命中手机号、身份证号、银行卡号、密码字段或自定义敏感词时，WAF 记录命中的脱敏样例、规则、域名、路径和来源节点，供“安全运营 → 敏感数据发现”页面排查。

它不会替换或修改业务响应内容，避免因脱敏改写造成接口兼容性问题。规则配置仍通过集群规则快照发布到 Node；发现记录由 Node 写入 Redis，再由 Master 汇总到 MySQL。

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

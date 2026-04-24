## ZhongKui-WAF

`Zhongkui-WAF` 基于 `lua-nginx-module`，用于在 OpenResty 层对 Web 请求做实时检测、拦截、记录与可视化管理。项目支持单机和集群两种部署模式，适合从测试到生产逐步扩展。

### 功能总览

基础防护能力：
- 三种运行模式：关闭、保护（拦截+记录）、监控（仅记录）
- 规则防护：URL/参数/Header/Cookie/Body、上传扩展名、HTTP Method
- 攻击检测：SQL 注入、XSS、SSRF、CC、Bot、人机验证、ACL、自定义规则
- IP 管控：黑白名单（支持 IPv6 与网段）
- 敏感数据过滤：身份证、手机号、银行卡、密码等脱敏与关键词过滤

平台与数据能力：
- 站点独立配置 + 全局配置
- 管理后台可视化（攻击日志、流量统计、节点状态）
- 支持 Redis + MySQL 的集群化架构
- 攻击日志归档清理（系统页面懒人模式，支持自动与手动执行）

集群增强能力（当前版本）：
- master 集中发布规则快照，node 增量拉取并热更新
- 快照带 `hash`（md5）校验，node 校验通过后才应用
- 节点页面显示 `规则版本`、`规则发布时间`、`同步状态`
- 统计/日志链路支持 dirty set、retry set、队列化落库，降低扫描与写库压力

### 安装与部署

安装前：

```bash
chmod +x install.sh
```

常用参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--role master\|node` | `master` | 指定当前机器部署为 master 或 node |
| `--init-local-mysql` | 关闭 | master 机器上同时安装并初始化本机 MySQL |
| `--mysql-user USER` | `zhongkui_mac` | 配合`--init-local-mysql`使用，指定要创建并写入配置的 MySQL 账号 |
| `--init-local-redis` | 关闭 | 使用`waf/redis16381.zip`安装并启动本机 Redis |
| `--redis-port PORT` | `16381` | 配合`--init-local-redis`使用，指定本机 Redis 端口 |
| `--redis-password PASSWORD` | `Push@789` | 配合`--init-local-redis`使用，指定本机 Redis 密码 |

常见部署场景：

| 场景 | 安装命令 | 安装前需要确认 |
|---|---|---|
| master 使用外部 MySQL 和外部 Redis | `sudo ./install.sh --role master` | 先修改`conf/system-master.json`中的`mysql`和`redis`连接信息 |
| master 使用外部 MySQL，本机 Redis | `sudo ./install.sh --role master --init-local-redis --redis-password Push@789` | MySQL 连接仍从`conf/system-master.json`读取；Redis 会自动切到`127.0.0.1:16381` |
| master 同时初始化本机 MySQL 和本机 Redis | `sudo ./install.sh --role master --init-local-mysql --mysql-user zhongkui_mac --init-local-redis --redis-password Push@789` | MySQL 会自动切到`127.0.0.1:3306`，Redis 会自动切到`127.0.0.1:16381` |
| node 节点 | `sudo ./install.sh --role node` | 先修改`conf/system-node.json`中的 Redis 连接信息；node 不需要 MySQL |
| 单机模式 | `sudo ./install.sh --role master` | 先将`conf/system-master.json`中的`centralized.state`改为`off`，并按需配置 MySQL/Redis |

### 安装脚本行为说明

- `install.sh` 会安装 OpenResty 与依赖，并按角色生成 `conf/system.json`。
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
- 流量/攻击类型：dirty set 增量同步（`waf:dirty:traffic_stats`、`waf:dirty:attack_type_dates`）
- MySQL 异常时：retry set 回放补写（`waf:retry:*`）

### 重部署后验收（建议）

在 master 上执行：

```bash
# 1) 查看规则版本 key 与快照是否存在
redis-cli -h <redis_host> -p <redis_port> -a '<redis_password>' GET waf:cluster:rules:snapshot:version
redis-cli -h <redis_host> -p <redis_port> -a '<redis_password>' GET waf:cluster:rules:snapshot | head -c 300

# 2) 查看节点心跳中的规则版本字段（rules_version）
redis-cli -h <redis_host> -p <redis_port> -a '<redis_password>' --scan --pattern 'waf:cluster:nodes:*'
redis-cli -h <redis_host> -p <redis_port> -a '<redis_password>' HGETALL waf:cluster:nodes:<node_ip>

# 3) 验证 MySQL 节点表是否落库 rules_version
mysql -h <mysql_host> -P <mysql_port> -u <mysql_user> -p'<mysql_password>' -D <mysql_db> \
  -e "SELECT ip,rules_version,last_seen FROM waf_cluster_node ORDER BY last_seen DESC LIMIT 10;"

# 4) 打开在线节点页面，确认“规则版本 / 规则发布时间 / 同步状态”三列已更新
curl -I http://<master_ip>:1226/
```

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

##### bot 陷阱

开启 bot 陷阱后，将会在上游服务器返回的 HTML 页面中添加配置的陷阱 URL，这个 URL 隐藏在页面中，对普通正常用户不可见，访问此 URL 的请求被视为 bot。

建议 bot 陷阱结合`robots协议`使用，将陷阱 URI 配置为禁止所有 bot 访问，不听话的 bot 将访问陷阱 URL，从而被识别，而那些遵循`robots协议`的友好 bot 将不会被陷阱捕获。

你可以在 robots.txt 中这样配置：

```
User-agent: *
Disallow: /zhongkuiwaf/honey/trap
```

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

详细说明请查看：[CLUSTER_MODE.md](./CLUSTER_MODE.md)。

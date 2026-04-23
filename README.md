## ZhongKui-WAF

钟馗是中国传统文化中的一个神话人物，被誉为"捉鬼大师"，专门驱逐邪恶之物。`Zhongkui-WAF`的命名灵感来源于这一神话人物，寓意着该软件能够像钟馗一样，有效地保护 Web 应用免受各种恶意攻击和威胁。

`Zhongkui-WAF`基于`lua-nginx-module`，可以多维度检查和拦截恶意网络请求，具有简单易用、高性能、轻量级的特点。它的配置简单，你可以根据实际情况设置不同的安全规则和策略。

![dashboard](https://github.com/storm0816/zhongkui-waf-centralized/tree/master/images/dashboard.png)

### 主要特性

- 多种工作模式，可随时切换
  1. 关闭模式：放行所有网络请求
  2. 保护模式（protection）：拦截攻击请求并记录攻击日志
  3. 监控模式（monitor）：记录攻击日志但不拦截攻击请求
- 支持规则自动排序，开启后按规则命中次数降序排序，可提高拦截效率
- 支持 ACL 自定义规则，灵活配置拦截规则
- 支持站点独立配置
- IP 黑名单、白名单，支持 IPv6 及网段配置，"127.0.0.1/24"或"127.0.0.1/255.255.255.0"
- HTTP Method 白名单
- URL 黑名单、白名单
- URL 恶意参数拦截
- 恶意 Header 拦截
- 请求体检查
- 上传文件类型黑名单，防止 webshell 上传
- 恶意 Cookie 拦截
- CC 攻击拦截
- 人机验证，验证失败后可以自动限时或永久拉黑 IP 地址
- Sql 注入、XSS、SSRF 等攻击拦截
- 可设置仅允许指定国家的 IP 访问
- 敏感数据（身份证号码、手机号码、银行卡号、密码）脱敏及关键词过滤
- 支持 Redis，开启后 IP 请求频率、IP 黑名单等数据将从 Redis 中读写，实现集群效果
- 攻击日志记录，包含 IP 地址、IP 所属地区、攻击时间、防御动作、拦截规则等，支持 JSON 格式日志
- 流量统计可视化

### 安装

常用参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--role master\|node` | `master` | 指定当前机器部署为 master 或 node |
| `--init-local-mysql` | 关闭 | master 机器上同时安装并初始化本机 MySQL |
| `--mysql-user USER` | `zhongkui_mac` | 配合`--init-local-mysql`使用，指定要创建并写入配置的 MySQL 账号 |
| `--init-local-redis` | 关闭 | 使用`waf/redis16381.zip`安装并启动本机 Redis |
| `--redis-port PORT` | `16381` | 配合`--init-local-redis`使用，指定本机 Redis 端口 |
| `--redis-password PASSWORD` | `Push@789` | 配合`--init-local-redis`使用，指定本机 Redis 密码 |

使用 root 执行安装脚本`install.sh`，自动安装基础编译工具、`OpenResty`、`ZhongKui`、`libmaxminddb`、`luaossl`、`luafilesystem`、`libinjection`和`geoipupdate`，并按角色生成`conf/system.json`和`nginx.conf`。从项目目录执行时，脚本会优先安装当前目录中的代码，并自动把项目`waf/`目录下的离线安装包同步到`/usr/local/src`，缺失的包才会尝试联网下载。Redis 默认使用外部服务，只有显式添加`--init-local-redis`时才会安装包内 Redis。
安装脚本会基于项目内的`waf/nginx.conf.default`替换 OpenResty 默认`nginx.conf`：保留 OpenResty 默认 80 端口`server`内容，只在`http`层添加 ZhongKui-WAF 的加载配置，并按角色 include 控制台配置。仓库里的`admin/conf/sites.conf`默认保持为空，只用于填写真实业务站点；默认 80 端口请求也会先经过 WAF access 阶段。

安装前先赋予执行权限：

```bash
chmod +x install.sh
```

常见部署场景：

| 场景 | 安装命令 | 安装前需要确认 |
|---|---|---|
| master 使用外部 MySQL 和外部 Redis | `sudo ./install.sh --role master` | 先修改`conf/system-master.json`中的`mysql`和`redis`连接信息 |
| master 使用外部 MySQL，本机 Redis | `sudo ./install.sh --role master --init-local-redis --redis-password Push@789` | MySQL 连接仍从`conf/system-master.json`读取；Redis 会自动切到`127.0.0.1:16381` |
| master 同时初始化本机 MySQL 和本机 Redis | `sudo ./install.sh --role master --init-local-mysql --mysql-user zhongkui_mac --init-local-redis --redis-password Push@789` | MySQL 会自动切到`127.0.0.1:3306`，Redis 会自动切到`127.0.0.1:16381` |
| node 节点 | `sudo ./install.sh --role node` | 先修改`conf/system-node.json`中的 Redis 连接信息；node 不需要 MySQL |
| 单机模式 | `sudo ./install.sh --role master` | 先将`conf/system-master.json`中的`centralized.state`改为`off`，并按需配置 MySQL/Redis |

`--init-local-mysql`只用于 master 机器需要安装并初始化本机 MySQL 的场景。它会创建本机数据库`zhongkui_waf`和`--mysql-user`指定的账号，并把当前运行配置中的 MySQL 连接切换到`127.0.0.1:3306`。如果使用外部 MySQL，不要加这个参数。

`--init-local-redis`只用于当前机器需要启动包内 Redis 的场景。Redis 安装目录为`/opt/openresty/redis16381`，systemd 服务名为`redis16381`，默认端口`16381`。如果使用外部 Redis，不要加这个参数。当前`waf/redis16381.zip`中的 Redis 二进制为 Linux x86-64 版本，ARM 服务器不能直接使用该离线包。

`luaossl`安装后的核心二进制文件名是`_openssl.so`（不是`openssl.so`），默认应位于`/opt/openresty/lualib/_openssl.so`。

在线节点页面默认使用`system.expire + system.node_offline_grace`作为离线判定窗口（默认`120 + 180 = 300`秒），用于降低短暂抖动导致的误判离线。

生产集群建议保持 node 只写 Redis、master 汇总写 MySQL。master 汇总任务已做错峰和 Redis 锁保护，默认日志/统计类汇总周期为 120 秒，节点心跳落库周期为 30 秒；不要为了页面实时性把生产同步周期调得过短。

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

### 管理页面

安装配置完成后，浏览器访问`http://localhost:1226`，账号`admin`，默认密码为`zhongkui`。

`v1.2`版本开始，一些数据统计依赖`Mysql`数据库，因此需要配置`Mysql`数据库并自行创建 database(`zhongkui_waf`)，waf 启动后，表结构会自动创建。

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

### 私有化开发功能--集群模式

- 攻击日志进行汇总
- 黑名单通过 master，进行分发，节点黑名单过滤，新增 master 黑名单。
- dashboard 前端页面所有数据汇总

#### 集群角色说明

集群角色由`conf/system.json`中的`redis`、`centralized`、`master`三个开关共同决定：

| `redis.state` | `centralized.state` | `master.state` | 角色/模式 |
|---|---|---|---|
| `on` | `on` | `on` | master 节点（集群） |
| `on` | `on` | `off` | node 节点（集群） |
| `off` 或 `on` | `off` | 任意 | 单机模式 |
| `off` | `on` | 任意 | 单机模式（未启用 Redis） |

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

## ZhongKui-WAF

钟馗是中国传统文化中的一个神话人物，被誉为"捉鬼大师"，专门驱逐邪恶之物。`Zhongkui-WAF`的命名灵感来源于这一神话人物，寓意着该软件能够像钟馗一样，有效地保护 Web 应用免受各种恶意攻击和威胁。

`Zhongkui-WAF`基于`lua-nginx-module`，可以多维度检查和拦截恶意网络请求，具有简单易用、高性能、轻量级的特点。它的配置简单，你可以根据实际情况设置不同的安全规则和策略。

![dashboard](https://github.com/bukaleyang/zhongkui-waf/blob/master/images/dashboard.png)

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

执行安装脚本`install.sh`，自动安装`OpenResty`、`ZhongKui`、`libmaxminddb`、`luaossl`、`luafilesystem`、`libinjection`和`geoipupdate`：

```bash
chmod +x install.sh
./install.sh
```

安装完成后，修改`nginx.conf`，在`http`模块下添加`zhongkui-waf`相关配置：

```nginx
    include /opt/openresty/zhongkui-waf/admin/conf/waf.conf;
    include /opt/openresty/zhongkui-waf/admin/conf/admin.conf;
    include /opt/openresty/zhongkui-waf/admin/conf/sites.conf;
```

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

### 交流群

欢迎大家进群交流，如果遇到 bug 或有新的需求，请优先提交 Issues。

QQ 群：903430639

### 捐赠

如果你觉得这个项目还不错，点击[这里](https://afdian.net/a/bukale)或扫描下方二维码为作者买杯咖啡吧！

![donate_wechat](https://github.com/bukaleyang/zhongkui-waf/blob/master/images/donate_wechat.png)

### Copyright and License

ZhongKui-WAF is licensed under the Apache License, Version 2.

Copyright 2023 bukale bukale2022@163.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

需要同步的文件
conf/global_rules/

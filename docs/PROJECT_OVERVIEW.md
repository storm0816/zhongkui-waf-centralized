# 项目梳理

## 1. 项目定位

`Zhongkui-WAF` 是一套运行在 `OpenResty` 上的 WAF 与管理后台系统，当前已经形成两条主线：

- 防护主链路：`init.lua` / `init_worker.lua` / `waf.lua` / `log_and_traffic.lua`
- 管理主链路：`admin/conf/admin.conf` / `admin/lua/*.lua` / `admin/view/*.html`

项目支持：

- 单机模式
- 集群模式（master / node）
- 后台规则管理
- 节点同步与大屏展示

## 2. 目录分层

### 运行时核心

- `init.lua`
  - 初始化配置路径并加载配置。
- `init_worker.lua`
  - worker 级定时任务、集群同步、Redis / MySQL 汇总任务。
- `waf.lua`
  - 请求防护主入口。
- `log_and_traffic.lua`
  - 攻击日志、流量统计写入链路。
- `config.lua`
  - 配置加载、规则快照、黑白名单/IP组/敏感词集中化核心。

### 基础库

- `lib/`
  - Redis / MySQL / 请求 / GeoIP / captcha / 敏感词 / SQL 等基础能力。

### 管理后台

- `admin/conf/admin.conf`
  - 后台 Nginx 路由入口。
- `admin/lua/*.lua`
  - 后台接口逻辑。
- `admin/view/*.html`
  - 后台页面与大屏页面。

### 配置数据

- `conf/system.json`
  - 当前实例运行配置。
- `conf/system-master.json`
  - master 模板。
- `conf/system-node.json`
  - node 模板。
- `conf/global.json`
  - 全局模块开关。
- `conf/global_rules/*`
  - 规则文件、黑白名单、敏感词词库等。
- `conf/website.json`
  - 站点定义。

## 3. 当前主链路

### 防护链路

1. `init.lua` 读取配置。
2. `init_worker.lua` 启动定时任务、集群同步、节点心跳。
3. `waf.lua` 在请求阶段执行模块检测。
4. `log_and_traffic.lua` 记录攻击、封禁、流量统计。

### 集群链路

1. master 生成并发布规则快照。
2. node 定期拉取快照并热更新。
3. 黑名单、白名单通过 Redis 集中同步。
4. 节点上报心跳、版本与同步状态。
5. master 汇总 Redis 数据并落 MySQL。

### 后台链路

1. `admin/conf/admin.conf` 路由到 `admin/lua/*.lua`
2. `admin/lua/*.lua` 读写 `conf/*`
3. 配置更新后触发 `config.reload_config_file()`
4. master 模式下进一步同步 Redis / 规则快照

## 4. 本轮已完成的结构优化

### 集群集中化

- IP 白名单已集中化
- IP 黑名单管理链路已对齐白名单
- IP 组已纳入规则快照同步
- 敏感词词库已纳入集中化链路

### 节点可观测性

- 在线节点新增规则/白名单/黑名单版本
- 新增三条独立同步状态与同步时间
- 列表页改成“判断信息优先，详情展示完整信息”

### 大屏

- 新增全球/中国 深浅四张大屏
- URL 生成支持正式路由
- 中国页 mock 数据改为显式开关，仅 `?mock=1` 启用

## 5. 当前仍需持续优化的点

### 高优先级

1. 配置文件与敏感信息管理
- 当前 `conf/system*.json` 中包含真实连接信息。
- 建议后续补：
  - `.example` 模板
  - 部署时注入真实值
  - README 中明确“不要提交真实密码”

2. reload 执行机制
- `config.lua` 仍通过 `os.execute("sudo nginx -s reload")` 执行 reload。
- 该方式依赖 sudo 环境，属于“能用但偏脆弱”的实现。
- 后续建议统一为：
  - 明确的运维命令包装
  - 或后台任务队列触发

3. 后台接口返回规范
- 当前后台接口 `code` 存在 `0 / 200 / 401 / 500` 混用现象。
- 前端也有一部分按 `200` 判断，一部分按 `0` 判断。
- 后续建议统一：
  - 传输成功统一 `HTTP 200`
  - 业务成功统一 `code = 0`

### 中优先级

1. 后台 Lua 控制器可继续抽公共响应 helper
- 现在很多 `admin/lua/*.lua` 都在重复：
  - 鉴权
  - `ngx.say(cjson_encode(response))`
  - reload 判断

2. 页面脚本可逐步模块化
- 当前 `admin/view/*.html` 里内嵌 JS 较多。
- 随着页面增多，后续维护成本会上升。

3. 配置文件职责边界可以再清晰
- `global.json`
- `system.json`
- `website.json`
- `global_rules/*`

当前已经能跑，但对于新同事来说，第一次接手仍然需要花时间理解。

## 6. 建议的后续治理顺序

1. 统一接口返回规范
2. 抽后台 Lua 公共响应/鉴权 helper
3. 为配置文件增加 `.example` 模板与脱敏说明
4. 梳理 reload 执行机制
5. 逐步拆分大页面内联脚本

## 7. 结论

当前项目已经从“单机规则型 WAF”演进成了“带集群同步、节点观测、大屏展示”的完整系统。

核心主链路已经成型，最值得继续投入的方向不是“再堆功能”，而是：

- 统一规范
- 降低维护成本
- 提高可观测性
- 减少运维偶发风险

这会比继续零散加功能更有长期收益。

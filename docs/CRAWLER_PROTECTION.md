# 反爬虫与爬虫公约

## 1. 功能定位

Zhongkui-WAF 的爬虫治理由四层能力组成：

| 能力 | 判断依据 | 处置时机 | 适用场景 |
| --- | --- | --- | --- |
| 反爬虫 | 站点 + 客户端 IP 的请求频率，可结合 UA 特征 | 超过阈值后 | 高频抓取、伪装浏览器的爬虫 |
| User-Agent 管理 | UA 正则 | 命中后立即执行 | 已知恶意工具、脚本客户端 |
| Bot 陷阱 | 是否访问隐藏 URI | 访问陷阱时 | 自动遍历链接、不遵守约定的 Bot |
| 爬虫公约 | `/robots.txt` | 爬虫自行读取并遵守 | 正规搜索引擎和友好爬虫 |

`robots.txt` 不是访问控制。恶意爬虫可以忽略它，因此生产防护应以反爬虫、CC、防火墙和可信来源识别为主。

## 2. 请求处理顺序

请求进入 `waf.lua` 后，白名单和黑名单检查先执行，随后进入 Bot 模块：

1. 请求 `/robots.txt` 且爬虫公约已开启时，WAF 直接返回配置内容。
2. 反爬虫开启时，检查 URI 例外和 UA 例外。
3. 按检测模式判断该请求是否参与计数。
4. 使用 Redis 计数；Redis 不可用时降级到 `dict_cclimit` 本机共享字典。
5. 请求数超过阈值后执行配置动作，并写入 `Retry-After` 响应头。
6. 继续执行人机验证、Bot 陷阱和 User-Agent 强制规则。

计数 key 格式：

```text
crawler_req_count:<md5(server_name|client_ip)>
```

攻击日志中的类型为 `crawler`，规则名称为 `crawler_rate_limit`。

## 3. 反爬虫配置

入口：`防护策略 -> Bot管理 -> 反爬虫`。

| 配置项 | 说明 | 默认值 |
| --- | --- | --- |
| 状态 | 是否启用反爬虫 | 关闭 |
| 检测模式 | `bot` 仅统计命中爬虫 UA 的请求；`all` 统计全部请求 | `bot` |
| 访问阈值 | 一个统计周期内允许的请求数量 | `120` |
| 统计周期 | 固定计数窗口，单位秒 | `60` |
| 超限动作 | 返回 `429`、拦截页面或人机验证 | 返回 `429` |
| 自动屏蔽 IP | 超限后是否加入临时 IP 黑名单 | 关闭 |
| 屏蔽时长 | 单位秒，`0` 表示永久 | `600` |
| UA 正则 | 识别爬虫客户端的正则表达式 | 内置常见 Bot/脚本特征 |
| UA 例外正则 | 命中后不参与反爬虫计数 | 空 |
| Bot/captcha 例外 URI | 每行一个；普通路径按前缀匹配，`=` 开头按完整路径匹配 | 静态资源路径和 `=/token` |

数值范围：

- 统计周期：`1-86400` 秒
- 访问阈值：`1-1000000`
- 屏蔽时长：`0-31536000` 秒

例外 URI 命中后不会参与反爬虫计数，也不会触发或继续执行 captcha。接口建议使用精确写法，例如 `=/token` 只匹配 `/token`，不会匹配 `/tokenXXX`；静态目录可继续使用 `/static/` 前缀写法。查询参数不参与匹配。

### 检测模式选择

推荐先使用 `bot` 模式。该模式误伤风险较低，但伪装成普通浏览器 UA 的爬虫可能绕过识别。

`all` 模式会统计每个来源 IP 的所有请求，适合接口服务或遭受严重抓取的站点。开启前应确认 NAT、企业出口和反向代理场景，避免多个正常用户共用一个 IP 时误伤。

### UA 例外的安全边界

UA 例外只适合受信网络或临时兼容。不要仅凭以下字符串直接放行：

```text
Googlebot|Baiduspider|bingbot
```

攻击者可以伪造 User-Agent。搜索引擎可信放行应验证来源 IP，或执行反向 DNS 查询并再次正向解析确认结果。

## 4. User-Agent 强制规则

User-Agent 管理适合立即处置明确的恶意客户端，例如扫描器、压测工具或已知脚本库。它与反爬虫频率限制并不重复：

- UA 强制规则：一次请求命中即可处置。
- 反爬虫：累计请求超过阈值后处置。

不建议启用“搜索引擎 UA -> 允许访问”规则。`ALLOW` 动作会提前结束 WAF 检测，伪造 UA 的请求可能绕过其他防护模块。

## 5. robots.txt 爬虫公约

入口：`防护策略 -> Bot管理 -> 爬虫公约`。

开启后，WAF 在访问阶段直接响应 `/robots.txt`：

```text
Content-Type: text/plain; charset=UTF-8
Cache-Control: public, max-age=300
```

默认内容允许全部路径：

```text
User-agent: *
Allow: /
```

禁止抓取后台和私有目录的示例：

```text
User-agent: *
Disallow: /admin/
Disallow: /private/
Disallow: /api/internal/
```

部分爬虫支持非标准的 `Crawl-delay`，但 Google 等搜索引擎不一定采用该指令：

```text
User-agent: *
Allow: /
Crawl-delay: 5
```

## 6. 推荐上线步骤

1. 确认真实客户端 IP 获取方式正确，反向代理只允许可信入口传递 `X-Forwarded-For`。
2. 保持反爬虫关闭，先配置 UA、URI 例外和预期阈值。
3. 在测试站点启用 `bot` 模式，建议从 `120 次/60 秒` 或更宽松阈值开始。
4. 使用日志观察正常用户、API 客户端和正规爬虫的请求频率。
5. 优先使用 `429` 或人机验证，确认无误伤后再开启自动封禁。
6. 集群环境确认 Redis 可用，并检查 node 规则同步状态。
7. 最后根据业务需要启用 `all` 模式。

## 7. 验证命令

### 验证 robots.txt

```bash
curl -i -H 'Host: example.com' http://127.0.0.1/robots.txt
```

预期返回 `HTTP 200`、`text/plain` 和后台配置的公约内容。

### 验证反爬虫

先在测试站点设置较小阈值，例如 `3 次/60 秒`，然后执行：

```bash
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -A 'curl/8.0 crawler-test' \
    -H 'Host: example.com' \
    http://127.0.0.1/test-page
done
```

超过阈值后，`deny` 动作应返回 `429`。测试完成后恢复生产阈值。

### 检查配置和日志

```bash
/opt/openresty/nginx/sbin/nginx -t
grep -E 'crawler|crawler_rate_limit' /opt/openresty/nginx/logs/error.log
```

## 8. 已知限制

- 当前计数使用固定时间窗口，不是滑动窗口。
- 当前没有自动验证搜索引擎正反向 DNS。
- 当前客户端 IP 获取逻辑会读取 `X-Forwarded-For`，部署方必须在入口层清理外部传入值，并只信任受控代理。
- Redis 不可用时会降级为单机计数，多个 WAF 节点之间的计数不会合并。
- `robots.txt` 只在 WAF 和 Bot 模块开启时由本模块响应。

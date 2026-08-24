# 域名子黑白名单

## 生效关系

- 全局白名单与域名子白名单为“或”关系，任一命中即按白名单处理。
- 全局黑名单、临时封禁与域名子黑名单为“或”关系，子规则不能解除全局封禁。
- 全局/站点地域黑名单与域名地域子黑名单为“或”关系。
- 域名使用精确匹配，不支持通配符，避免规则意外扩大。
- 停用子规则只停用该条记录，不影响全局规则。
- 子白名单受站点白名单开关控制；子黑名单和地域子黑名单受站点黑名单开关控制。
- 同一来源同时命中白名单与黑名单时，沿用现有处理顺序，白名单优先。

## 集群同步

域名子规则保存在 `conf/global_rules/domainIpPolicy.json`，并被纳入完整集群规则快照：

1. Master 校验管理员提交的数据。
2. 完整快照先持久化到 MySQL `waf_cluster_rule_release`。
3. MySQL 成功后才发布到 Redis。
4. Node 校验版本和快照哈希后构建本地域名匹配器。
5. Node 保留最后一次可用快照，Redis 或 Master 短时不可用不影响已有规则。

## 数据格式

```json
{
  "nextId": 2,
  "rules": [
    {
      "id": 1,
      "domain": "api.example.com",
      "type": "blacklist",
      "value": "203.0.113.10",
      "comment": "测试地址",
      "state": "on"
    }
  ]
}
```

`type` 支持：

- `whitelist`：IP 或 CIDR 子白名单。
- `blacklist`：IP 或 CIDR 子黑名单。
- `region`：两位国家/地区代码，例如 `US`、`IN`。

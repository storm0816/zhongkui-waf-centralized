# Debug Session: mysql-lshift-error

**Status**: [OPEN]
**Created**: 2026-08-12
**Symptom**: `bad argument #1 to 'lshift' (number expected, got nil)` in resty/mysql.lua:170 during MySQL handshake

## Error Stack
```
[C]: in function 'lshift'
/opt/openresty/lualib/resty/mysql.lua:170: in function '_get_byte4'
/opt/openresty/lualib/resty/mysql.lua:699: in function '_read_hand_shake_packet'
/opt/openresty/lualib/resty/mysql.lua:1196: in function 'connect'
/opt/openresty/zhongkui-waf/lib/mysql_cli.lua:27: in function 'get_connection'
/opt/openresty/zhongkui-waf/lib/mysql_cli.lua:48: in function 'query'
```

## Hypotheses (3-5 Falsifiable)

| ID | Hypothesis | Falsification Condition |
|----|-----------|------------------------|
| H1 | MySQL 服务响应异常（端口非标准 MySQL 或服务未就绪），握手包为空或不完整 | 插桩打印 connect 参数 + 收到的原始握手包内容，若握手包前 4 字节非 0x0a 则确认 |
| H2 | 连接到了错误的目标（端口映射/代理返回 HTTP 或其他协议数据），握手解析失败 | 若收到的数据包开头为 `HTTP/` 或其他非 MySQL magic 字节则确认 |
| H3 | 数据库配置（host/port）有误，之前测试环境使用了非生产占位地址，与真实环境不一致 | 对比配置文件与日志中的实际连接目标 |
| H4 | OpenResty `resty/mysql` 与 MySQL 8.0+ `caching_sha2_password` 认证协议不兼容 | 查看握手包中的 plugin name，若为 caching_sha2_password 且 resty/mysql 版本较旧则确认 |
| H5 | `mysql_cli.lua` 中 `compact_arrays` 参数或 socket 超时设置导致握手包被截断 | 检查 mysql_cli.lua 连接参数 |

## Evidence Log

| Step | Timestamp | Evidence |
|------|-----------|----------|
| 1 | init | 错误堆栈已收集 |

## Fix Status
✅ FIXED - 端口从 33060 (MySQL X Protocol) 改为 33061 (传统 MySQL 协议)

## Evidence
- 33060 端口 TCP 握手包: `05 00 00 00 0b 08 05 1a 00` (X Protocol 格式)
- 33061 端口: 传统 MySQL 协议，resty.mysql 可正常握手
- 修复后 lshift 错误消失，新错误为 MySQL 用户权限: Host '10-15-108-11' is not allowed to connect

## Remaining Issue
MySQL 用户需要授权从实际 master 节点连接：
```sql
GRANT ALL PRIVILEGES ON zhongkui_waf.* TO '<mysql_user>'@'<master_ip>' IDENTIFIED BY '<mysql_password>';
FLUSH PRIVILEGES;
```

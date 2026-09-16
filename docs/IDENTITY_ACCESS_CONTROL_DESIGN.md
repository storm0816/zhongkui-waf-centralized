# LDAP、用户与角色权限设计

本文档整理 Zhongkui-WAF 中已经实现的管理台身份与权限能力，作为其他项目复用时的需求基线和技术设计参考。文档描述的是当前代码实际行为，不是理想化的通用 RBAC 方案。

## 一、总体模型

系统采用四层职责分离：

| 层次 | 责任 | 当前实现 |
| --- | --- | --- |
| 身份认证 | 判断用户名和密码是否正确 | 本地应急账号或 LDAP |
| 用户映射 | 保存用户状态、显示名、认证来源和 MFA 状态 | MySQL `waf_admin_user` |
| 授权 | 通过角色得到权限，再保护接口和页面操作 | MySQL 角色、权限及关联表 |
| 会话与审计 | 保存登录态、刷新权限、记录操作 | Redis 会话，MySQL 审计 |

核心原则：LDAP 只负责认证，不直接决定本系统权限；权限由本地角色分配。这样可以避免 LDAP 目录结构变化直接改变应用授权，同时保留本地管理员应急登录能力。

## 二、功能范围

### 1. 登录方式

- 本地 `admin`：保留为 break-glass 应急管理员，密码仍由本地 `admin` 账号机制维护。
- LDAP：企业用户使用 LDAP 账号密码登录，LDAP 密码不会写入本地数据库。
- 自动模式：用户名为 `admin` 时走本地认证，其他用户走 LDAP；登录页也支持明确选择认证方式。
- LDAP 用户首次成功登录时自动创建本地映射，默认分配 `readonly` 角色。
- 管理员可以在“基础配置 -> 用户与权限”中提前创建 LDAP 用户并指定初始角色。

### 2. 用户管理

用户记录包含：

- 用户名、显示名称
- 认证来源：`local_legacy` 或 `ldap`
- LDAP 外部标识 `external_id`
- 状态：`enabled` 或 `disabled`
- MFA 是否已绑定、是否单独要求 MFA
- 最近登录时间、创建时间、更新时间

管理操作：

- 查看用户
- 新增 LDAP 用户映射
- 分配角色
- 启用或禁用用户
- 删除 LDAP 用户映射
- 重置用户 MFA
- 对本地 `admin` 重置密码
- 对单个用户开启或取消 MFA 要求

删除 LDAP 映射不会删除 LDAP 目录中的用户；该用户下次认证成功后会重新建立本地映射并获得默认 `readonly` 角色。

### 3. 角色与权限

内置角色：

| 角色 | 默认权限 | 用途 |
| --- | --- | --- |
| `super_admin` | `read`、`manage`、`user.manage`、`release.manage` | 完整管理和发布权限 |
| `manager` | `read`、`manage` | WAF 配置管理，不能维护账号和角色 |
| `readonly` | `read` | 查看配置、日志和报表 |

当前权限码：

- `read`：读取管理台数据
- `manage`：修改 WAF 配置、规则和普通运营数据
- `user.manage`：维护用户、角色、权限关联和审计查看
- `release.manage`：程序版本发布与回滚

权限是“用户 -> 角色 -> 权限”的多对多关系。一个用户可有多个角色，最终权限为所有角色权限的并集；`manage` 自动包含 `read`。

### 4. MFA

- 使用 TOTP，验证码为 6 位，时间步长 30 秒，允许前后各一个时间窗口的漂移。
- 开启方式有两种：系统全局强制 MFA，或对指定用户单独要求 MFA。
- 用户首次需要 MFA 时，登录接口返回绑定所需密钥和 `otpauth` URI；绑定成功后再建立正式会话。
- MFA 密钥使用 `system.secret` 加密后保存到 MySQL，不保存明文密钥。
- 修改 `system.secret` 会导致已有 MFA 密钥无法解密，生产环境必须将系统密钥视为不可变密钥。
- 管理员重置 MFA 后，目标用户下次登录需要重新绑定。

### 5. 会话

- Redis Key 前缀：`waf:admin:session:`。
- 会话默认有效期 1800 秒，并在每次有效请求时滑动续期。
- Cookie 名称为 `waf_admin_session`，设置 `HttpOnly`、`SameSite=Strict`；HTTPS 下增加 `Secure`。
- 会话中缓存用户身份、角色和权限，但每次请求会从 MySQL 重新读取用户状态、角色和权限并刷新 Redis 会话。
- 因此用户被禁用或权限变化后，已有会话下一次请求即可生效，不需要等待重新登录。
- MFA 未完成时使用独立的 pending token，Redis Key 前缀为 `waf:admin:login:pending:`，有效期 300 秒。

### 6. 登录失败保护

登录失败限制键按“来源 IP + 用户名”生成，Redis 保存 300 秒窗口内的失败次数；达到 8 次后暂时拒绝继续登录。失败认证也写入审计日志，但不记录密码。

## 三、LDAP 配置设计

配置与 MySQL、Redis 共用 `conf/system.json`，不生成独立 LDAP 配置文件：

```json
{
  "ldap": {
    "state": "off",
    "servers": ["ldap://ldap.example.com:389"],
    "bind_user": "cn=readonly,dc=example,dc=com",
    "bind_password": "",
    "search_base": "ou=people,dc=example,dc=com",
    "user_attribute": "sAMAccountName",
    "bind_template": "%s",
    "start_tls": "off",
    "tls_verify": "on",
    "timeout": 5000
  }
}
```

认证流程：

1. 校验用户名格式和长度，避免把任意内容带入 LDAP 查询或 DN。
2. 若配置了连接账号、连接密码和查询基准，先用服务账号查询用户 DN。
3. 使用用户自己的密码对查询到的用户 DN 做二次绑定。
4. 绑定成功后读取用户属性和显示名称。
5. 在 MySQL 建立或读取本地用户映射，加载本地角色和权限。
6. 若该用户需要 MFA，先完成 TOTP，再创建管理台会话。

兼容模式：未配置服务账号时，使用 `bind_template` 直接生成用户绑定名；例如 `%s`、`uid=%s,ou=people,dc=example,dc=com`。生产环境优先使用 LDAPS，或使用 StartTLS，并启用证书校验。

配置页面提供“测试连接”，测试内容包括：

- LDAP 地址格式是否正确
- 服务账号绑定是否成功
- 查询基准是否可访问
- 查询是否能够返回目录条目

密码字段在读取接口中会被清空，前端不会回显已有 LDAP 连接密码。

## 四、数据表设计

应用启动时自动创建以下表，适合迁移到其他项目时作为基础 DDL：

| 表 | 作用 |
| --- | --- |
| `waf_admin_user` | 用户本地映射、状态、认证来源、MFA 和登录时间 |
| `waf_admin_role` | 角色名称、说明、是否内置 |
| `waf_admin_permission` | 权限码及说明 |
| `waf_admin_user_role` | 用户与角色的多对多关系 |
| `waf_admin_role_permission` | 角色与权限的多对多关系 |
| `waf_admin_audit_log` | 登录、用户、角色、MFA 和密码操作审计 |

关键约束：

- 用户名唯一，角色名唯一，权限码唯一。
- 用户与角色、角色与权限的关联使用联合主键，避免重复授权。
- `mfa_secret` 只保存加密值。
- `audit_log` 保存操作者、动作、目标、结果、来源 IP 和详情。
- 已有安装升级时通过 `INFORMATION_SCHEMA` 检查并补充 `mfa_required` 字段，避免直接重复执行 ALTER。

## 五、接口与权限边界

### 用户会话接口

| 接口 | 作用 |
| --- | --- |
| `POST /user/login` | 本地或 LDAP 登录，必要时返回 MFA pending 状态 |
| `POST /user/mfa/verify` | 完成 MFA 绑定或验证码校验 |
| `POST /user/logout` | 删除 Redis 会话 |
| `GET /user/me` | 返回当前用户身份、角色和权限 |
| `POST /user/password/update` | 当前本地 `admin` 修改自己的密码 |

### 用户与角色管理接口

这些接口统一要求 `user.manage`：

| 接口 | 作用 |
| --- | --- |
| `GET /access/users` | 用户列表 |
| `GET /access/roles` | 角色列表 |
| `GET /access/permissions` | 权限列表 |
| `GET /access/audit` | 审计日志 |
| `POST /access/user/create` | 新建 LDAP 用户映射 |
| `POST /access/user/roles` | 修改用户角色 |
| `POST /access/user/status` | 启用或禁用用户 |
| `POST /access/user/mfa/required` | 修改单独 MFA 要求 |
| `POST /access/user/mfa/reset` | 重置 MFA |
| `POST /access/user/delete` | 删除 LDAP 用户映射 |
| `POST /access/user/password/reset` | 超级管理员重置本地用户密码 |
| `POST /access/role/create` | 新建自定义角色 |
| `POST /access/role/permissions` | 修改角色权限 |

发布接口的写操作单独要求 `release.manage`；普通配置写操作要求 `manage`；读取接口要求 `read`。Node 不提供管理台控制台能力，管理台用户与角色逻辑只应运行在 Master 或独立控制面。

## 六、审计要求

至少记录以下动作：

- 成功或失败登录
- MFA 验证、绑定、重置
- 用户创建、删除、启停、角色调整
- 角色创建和权限调整
- 本地密码修改和重置
- 发布、回滚等高风险操作

每条审计包含：操作者用户 ID、用户名、动作、目标对象、结果、客户端 IP、详情和时间。密码、LDAP 连接密码、MFA 明文密钥和会话 token 不得写入审计详情。

## 七、安全边界与迁移建议

### 可以直接复用的部分

- 用户、角色、权限六张表的关系模型
- LDAP 服务账号查询 + 用户二次绑定流程
- Redis 会话和 pending token 模型
- TOTP MFA 的绑定、验证、加密存储和重置流程
- 统一的接口鉴权中间件和审计接口
- 最后一个超级管理员保护策略

### 迁移到其他项目时必须重新确认

- 认证字段：AD 常用 `sAMAccountName`，OpenLDAP 常用 `uid`，不能写死。
- LDAP DN 结构、查询基准、服务账号权限和 TLS 信任链。
- 应用权限码和角色初始矩阵；不要直接把 WAF 的 `manage` 等权限复制到业务系统。
- 管理台是否只允许在控制面访问，避免把用户管理接口暴露到业务节点。
- 反向代理可信来源 IP，否则登录限流、审计来源 IP 可能被伪造。
- 系统密钥的生成、备份、轮换和恢复流程；不要用模板中的 `CHANGE_ME` 进入生产。
- Redis 和 MySQL 的高可用、超时、连接池及故障降级策略。

### 不建议的做法

- 把 LDAP 用户密码保存到 MySQL、Redis、日志或审计详情。
- 直接依据 LDAP 用户组名称拼接应用权限而不做本地映射和审核。
- 只在前端隐藏按钮，不在后端接口校验权限。
- 把角色权限写死在 HTML 或 Lua 路由中，导致权限矩阵无法维护。
- 允许修改或删除最后一个启用中的超级管理员。
- 修改 `system.secret` 后不重新验证 MFA 密钥可解密性。

## 八、验收清单

1. LDAP 关闭时，本地 `admin` 可以登录；普通 LDAP 登录被拒绝。
2. LDAP 主地址不可用时，备用地址可以完成认证。
3. 服务账号可以查到用户 DN，用户密码错误时不能登录。
4. 首次 LDAP 登录自动创建用户并获得 `readonly`，重复登录不会重复建用户。
5. 禁用用户后，旧会话下一次请求立即失效。
6. 修改用户角色后，旧会话下一次请求使用新权限。
7. `readonly` 无法调用写接口，`manager` 无法调用用户管理接口，`super_admin` 可以完整操作。
8. 全局 MFA 和单用户 MFA 均能触发绑定、验证和重置流程。
9. 连续 8 次错误登录后进入 5 分钟限制，换用户名或来源 IP 的边界符合安全策略。
10. 审计中能看到成功、失败和高风险管理动作，且不包含密码、密钥和 token。
11. LDAP 连接密码不在配置读取接口和前端页面中回显。
12. MySQL、Redis 任一不可用时，系统显示可理解的错误，不泄露堆栈和连接密码。

## 九、本项目代码入口

- LDAP、登录、MFA、会话：`admin/lua/user.lua`
- 用户、角色、权限、审计、TOTP：`admin/lua/auth_store.lua`
- 用户与角色管理 API：`admin/lua/access_control.lua`
- LDAP 配置读取、保存、测试：`admin/lua/system.lua`
- 用户与权限页面：`admin/view/system/access-control.html`
- LDAP 和登录安全页面：`admin/view/system/system.html`
- 登录页面：`admin/login.html`
- 菜单入口：`admin/admin/data/menu.json`
- Master 配置模板：`conf/system-master.json`


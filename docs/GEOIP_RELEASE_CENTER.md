# GeoIP 发布中心

## 设计目标

GeoIP 数据与 WAF 程序版本分开管理。更新 MMDB 时不需要重新打程序包，也不直接覆盖所有 Node。

## 发布流程

1. 将经过确认的 MMDB 放到 Master 当前 `system.json` 配置的 GeoIP 路径。
2. 在“集群与大屏 -> 发布中心”点击“创建 GeoIP 版本”。
3. Master 校验 MMDB，并保存不可变快照、SHA-256、文件大小和数据时间。
4. 从 GeoIP 数据页选择一台 Node 灰度发布。
5. Node 下载到临时文件，校验 SHA-256，并使用固定公网 IP 执行真实查询。
6. 校验成功后备份旧 MMDB、原子替换、检查 OpenResty 配置并重载。
7. 失败时自动恢复旧 MMDB；结果通过节点心跳显示在 GeoIP 任务页。

## 数据位置

- Master 快照：`/opt/openresty/zhongkui-geoip-releases/<数据版本>/`
- Node 目标文件：以 Node `system.json` 中 `geoip.file` 为准，且必须位于 `/opt/openresty/share/GeoIP/`。
- MySQL：只保存版本元数据与发布任务，不保存 MMDB 文件内容。
- Redis：只保存带有效期的 Node 更新任务与下载令牌。

## 安全边界

- 下载接口使用随机令牌并设置有效期。
- Node 不直接执行 Master 下发的命令，只接受固定字段的 GeoIP 更新任务。
- 更新不修改 `system.json`、证书、规则和日志。
- 每个 Node 独立校验和回滚，单台失败不会影响其他节点。

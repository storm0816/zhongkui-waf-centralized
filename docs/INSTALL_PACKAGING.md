# 安装包与发布流程

## 1. 项目目录约定

- `install.sh`：Linux 安装入口，负责编译 OpenResty、安装依赖并部署 WAF。
- `waf/`：离线依赖包，包括 OpenResty、Redis、GeoIP 和编译依赖。
- `conf/system-master.json`：master 角色配置模板。
- `conf/system-node.json`：node 角色配置模板。
- `conf/system.json`：运行时配置，由安装脚本根据角色模板生成，不进入发布包。
- `dist/`：本地生成的版本安装包，不提交 Git。

发布包默认包含离线依赖，适合在没有公网下载条件的 Linux 服务器上安装。`GeoLite2-City.mmdb` 和 Redis 离线包体积较大，发布包可能超过 100 MB。

## 2. 生成安装包

在项目根目录执行：

```bash
chmod +x install.sh scripts/build_release.sh
./scripts/build_release.sh
```

脚本会从 `lib/constants.lua` 读取版本号，生成两个角色专用包：

```text
dist/zhongkui-waf-master-2.0.0.tar.gz
dist/zhongkui-waf-master-2.0.0.tar.gz.sha256
dist/zhongkui-waf-node-2.0.0.tar.gz
dist/zhongkui-waf-node-2.0.0.tar.gz.sha256
```

也可以显式指定版本和输出目录：

```bash
./scripts/build_release.sh --version 2.0.0 --output-dir /tmp/zhongkui-release
```

构建机需要保存一个未提交的 `.zhongkui.release.env`，其中保存生产 MySQL/Redis 参数。Git 内的模板始终是 `10.10.10.10` 与空口令占位值；构建脚本仅在生成压缩包时注入发布参数。发布包会排除 `.git`、`.zhongkui.private.env`、`.zhongkui.release.env`、`conf/system.json`、构建输出、历史备份和内部计划文档。生成后应先校验：

```bash
sha256sum -c dist/zhongkui-waf-master-2.0.0.tar.gz.sha256
tar -tzf dist/zhongkui-waf-master-2.0.0.tar.gz | grep -E '(^|/)(ssh|\.zhongkui\.private\.env|\.zhongkui\.release\.env)$|conf/system.json'
```

第二条命令应没有输出。

## 3. 安装前配置

解压发布包后，先检查对应角色模板中的连接信息：

```bash
tar -xzf zhongkui-waf-master-2.0.0.tar.gz
cd zhongkui-waf-master-2.0.0
```

安装时脚本会复制角色模板为 `conf/system.json`，并根据参数覆盖本机 Redis/MySQL 的连接信息。

## 4. 直接安装

解压后直接执行以下命令即可：

```bash
cd zhongkui-waf-node-2.0.0
chmod +x install.sh
sudo ./install.sh --role node
```

安装 master：

```bash
sudo ./install.sh --role master
```

本机 Redis：

```bash
sudo ./install.sh --role node --init-local-redis --redis-port 16381 --redis-password '<your-redis-password>'
```

本机 MySQL 和 Redis：

```bash
sudo ./install.sh --role master --init-local-mysql --mysql-user zhongkui --mysql-password '<your-mysql-password>' --init-local-redis --redis-port 16381 --redis-password '<your-redis-password>'
```

密码直接写在命令中，方便复制部署。角色统一使用 `--role master` 或 `--role node`。

如果需要清理重装或保留现网配置，再使用 `--fresh` 等高级参数。

## 5. 高级安装命令

外部 MySQL、外部 Redis：

```bash
sudo ./install.sh --role master
```

本机 Redis：

```bash
sudo ./install.sh --role node \
  --init-local-redis \
  --redis-port 16381 \
  --redis-password '<strong-random-password>' \
  --redis-db 0
```

本机 MySQL 和 Redis 的 master：

```bash
sudo ./install.sh --role master \
  --init-local-mysql \
  --mysql-user zhongkui \
  --mysql-password '<strong-random-password>' \
  --init-local-redis \
  --redis-port 16381 \
  --redis-password '<strong-random-password>' \
  --redis-db 0
```

启用本机初始化时，必须显式提供对应密码；不启用本机初始化时，脚本不会要求命令行密码，连接信息由模板配置提供。

## 6. 发布前检查

1. 确认版本号与 README、变更记录一致。
2. 确认角色模板中的地址、账号和密码符合目标环境。
3. 确认 `ssh`、`conf/system.json` 和 `.git` 不在压缩包内。
4. 使用 SHA256 校验包完整性。
5. 在测试机执行 `nginx -t` 和安装后检查脚本。
6. 生产发布前备份 `conf/system.json`、`conf/global.json`、规则文件、MySQL 和 Redis 数据。

完整上线验收见 [RELEASE_CHECKLIST.md](./RELEASE_CHECKLIST.md)，升级和回滚见 [DEPLOY_UPGRADE_GUIDE.md](./DEPLOY_UPGRADE_GUIDE.md)。

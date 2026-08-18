# Zhongkui-WAF 1.4.3 傻瓜式累积更新包

适用于已安装的 Zhongkui-WAF。更新包包含 1.4.2 的运行时更新和 1.4.3 多 Worker 规则同步修复。

## 一键升级

将压缩包上传到服务器，在压缩包所在目录执行：

```bash
tar -xzf zhongkui-waf-upgrade-1.4.3.tar.gz
sudo ./zhongkui-waf-upgrade-1.4.3/upgrade.sh
```

默认项目目录：

```text
/opt/openresty/zhongkui-waf
```

安装在其他目录时：

```bash
sudo ./zhongkui-waf-upgrade-1.4.3/upgrade.sh --project-root /实际/项目目录
```

`upgrade.sh` 根据自身所在位置读取更新文件，因此从任何当前工作目录调用都可以。

## 自动完成的操作

1. 校验升级包内全部文件的 SHA-256。
2. 备份即将更新的代码和 `conf/global.json`。
3. 安装 1.4.2 累积更新和 1.4.3 修复。
4. 仅向现有 `global.json` 补充缺失的 crawler/robots 配置。
5. 执行 `nginx -t`，通过后自动 reload。
6. 任一步骤失败时自动恢复备份。

升级不会修改：

- `install.sh`
- `conf/system.json`
- `conf/system-master.json`
- `conf/system-node.json`
- 站点、证书、IP 黑白名单和安全规则文件

升级后，节点的每个 Nginx Worker 都会独立加载集群规则快照，最长等待约 40 秒即可完成同步。

## 生成发布包

执行以下命令会同时生成同版本的累积更新包和完整安装包：

```bash
./scripts/build_crawler_upgrade.sh
```

输出文件包括：

- `dist/zhongkui-waf-upgrade-版本号.tar.gz`
- `dist/zhongkui-waf-版本号.tar.gz`
- 两个压缩包各自的 `.sha256` 校验文件

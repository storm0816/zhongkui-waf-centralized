# 反爬虫功能一键升级包

适用于已经安装 Zhongkui-WAF、只需要增加反爬虫和 `robots.txt` 功能的服务器。

## 升级命令

将升级包上传到服务器后执行：

```bash
tar -xzf zhongkui-waf-crawler-upgrade-1.4.2.tar.gz
cd zhongkui-waf-crawler-upgrade-1.4.2
sudo ./upgrade.sh
```

默认项目目录为：

```text
/opt/openresty/zhongkui-waf
```

如果项目安装在其他目录：

```bash
sudo ./upgrade.sh --project-root /实际/项目目录
```

## 脚本会自动完成

1. 备份即将更新的代码文件和 `conf/global.json`。
2. 更新反爬虫后台、前端和运行时代码。
3. 在现有 `conf/global.json` 中补充 `crawler` 和 `robots`，保留其他生产配置。
4. 执行 `nginx -t`。
5. 校验成功后 reload，失败则自动恢复备份。

升级不会修改：

- `install.sh`
- `conf/system.json`
- `conf/system-master.json`
- `conf/system-node.json`
- 网站、证书、黑白名单和其他规则文件

升级完成后，反爬虫默认关闭；请进入 `防护策略 -> Bot管理` 检查阈值后再开启。`robots.txt` 默认开启并允许全部抓取。

验证：

```bash
curl -i -H 'Host: 你的业务域名' http://127.0.0.1/robots.txt
```

预期返回 `HTTP 200` 和 `Content-Type: text/plain`。

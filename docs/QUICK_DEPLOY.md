# 钟馗 WAF 简明部署

适用于角色包首次安装。请使用与机器角色一致的压缩包：Master 使用
`zhongkui-waf-master-<版本>.tar.gz`，Node 使用
`zhongkui-waf-node-<版本>.tar.gz`。

## 1. 安装前保留现网站点

如果服务器上已经有 OpenResty/Nginx 业务，先备份三个位置。WAF 安装包负责
WAF 程序，不应覆盖业务静态页面或虚拟主机配置。

```bash
sudo mkdir -p /opt/zhongkui-backup
sudo cp -a /opt/openresty/nginx/conf/nginx.conf /opt/zhongkui-backup/nginx.conf
sudo cp -a /opt/openresty/nginx/conf/conf.d /opt/zhongkui-backup/conf.d 2>/dev/null || true
sudo cp -a /opt/openresty/nginx/html /opt/zhongkui-backup/html 2>/dev/null || true
```

- `nginx.conf`：WAF 主配置会生成到
  `/opt/openresty/nginx/conf/nginx.conf`。
- `conf.d/`：业务虚拟主机配置。WAF 不会替换其中的文件；若主配置需要使用它，
  保留或添加 `include /opt/openresty/nginx/conf/conf.d/*.conf;`。
- `html/`：业务静态页面。WAF 不会复制或替换该目录；仅在新装机器需要原有静态站点时，
  从备份恢复它。

## 2. 安装 Node

```bash
tar -xzf zhongkui-waf-node-<版本>.tar.gz
cd zhongkui-waf-node-<版本>
sudo ./install.sh --role node
```

Node 会将 `conf/system-node.json` 复制为运行配置
`/opt/openresty/zhongkui-waf/conf/system.json`。Node 不包含 MySQL、LDAP 管理后台
配置，也不会开放管理控制台。

## 3. 安装 Master

```bash
tar -xzf zhongkui-waf-master-<版本>.tar.gz
cd zhongkui-waf-master-<版本>
sudo ./install.sh --role master
```

Master 会将 `conf/system-master.json` 复制为运行配置，并提供管理后台。

## 4. 恢复业务文件并接入 WAF

若这是已有业务服务器，确认下面的 WAF include 位于
`/opt/openresty/nginx/conf/nginx.conf` 的 `http {}` 内：

```nginx
include /opt/openresty/zhongkui-waf/admin/conf/waf.conf;
include /opt/openresty/zhongkui-waf/admin/conf/sites.conf;
```

Master 还需要：

```nginx
include /opt/openresty/zhongkui-waf/admin/conf/admin.conf;
```

需要恢复业务站点时：

```bash
sudo cp -a /opt/zhongkui-backup/conf.d/. /opt/openresty/nginx/conf/conf.d/ 2>/dev/null || true
sudo cp -a /opt/zhongkui-backup/html/. /opt/openresty/nginx/html/ 2>/dev/null || true
```

不要直接用旧 `nginx.conf` 覆盖新配置，否则会丢失上述 WAF include。应将原有
业务 `server {}`、`conf.d` include 和必要的全局设置合并进新的主配置。

## 5. 检查并启动

```bash
sudo /opt/openresty/nginx/sbin/nginx -t
sudo systemctl restart openresty
sudo systemctl status openresty
```

通过 `nginx -t` 后再重启。Node 通过 Master 节点后台查看在线状态；Master 可访问
`http://<Master-IP>:1226`。

## 已运行服务器升级

已有 WAF 不要重复执行 `install.sh`，请解压同角色的新包后执行：

```bash
sudo ./upgrade.sh --role node
# 或：sudo ./upgrade.sh --role master
```

升级会保留当前 `conf/system.json`、站点、规则、证书及管理账号数据。

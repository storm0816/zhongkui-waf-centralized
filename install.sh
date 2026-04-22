#!/bin/bash

set -e

echo "
  ______                       _  __     _ 
 |__  / |__   ___  _ __   __ _| |/ /   _(_)
   / /| '_ \ / _ \| '_ \ / _\` | ' / | | | |
  / /_| | | | (_) | | | | (_| | . \ |_| | |
 /____|_| |_|\___/|_| |_|\__, |_|\_\__,_|_|
                         |___/             
"

ROLE="master"
INIT_LOCAL_MYSQL="off"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

while [ $# -gt 0 ]; do
    case "$1" in
        --role)
            ROLE="$2"
            shift 2
            ;;
        --role=*)
            ROLE="${1#*=}"
            shift
            ;;
        --init-local-mysql)
            INIT_LOCAL_MYSQL="on"
            shift
            ;;
        -h|--help)
            echo "Usage: ./install.sh [--role master|node] [--init-local-mysql]"
            exit 0
            ;;
        *)
            echo -e "\033[31m[未知参数: $1]\033[0m"
            echo "Usage: ./install.sh [--role master|node] [--init-local-mysql]"
            exit 1
            ;;
    esac
done

if [ "$ROLE" != "master" ] && [ "$ROLE" != "node" ]; then
    echo -e "\033[31m[role 只能是 master 或 node]\033[0m"
    exit 1
fi

echo -e "\033[34m[部署角色: $ROLE]\033[0m"

# 创建 webuser 用户
if ! id -u webuser >/dev/null 2>&1; then
    echo -e "\033[34m[创建 webuser 用户]\033[0m"
    useradd -m -s /bin/bash webuser
else
    echo -e "\033[34m[webuser 用户已存在]\033[0m"
fi

OPENRESTY_PATH=/opt/openresty
ZHONGKUI_PATH=$OPENRESTY_PATH/zhongkui-waf
GEOIP_DATABASE_PATH=/opt/openresty/share/GeoIP

cd /usr/local/src
if [ ! -f "openresty-1.25.3.2.tar.gz" ]; then
    echo -e "\033[34m[未发现 openresty-1.25.3.2.tar.gz 文件，开始下载]\033[0m"
    wget https://openresty.org/download/openresty-1.25.3.2.tar.gz
else
    echo -e "\033[34m[发现 openresty-1.25.3.2.tar.gz 文件，跳过下载]\033[0m"
fi
tar zxf openresty-1.25.3.2.tar.gz
cd openresty-1.25.3.2

./configure --prefix=$OPENRESTY_PATH \
--user=webuser \
--group=users \
--with-http_ssl_module \
--with-http_v2_module \
--with-http_realip_module \
--with-http_sub_module \
--with-http_stub_status_module \
--with-http_auth_request_module \
--with-http_secure_link_module \
--with-stream \
--with-stream_ssl_module \
--with-stream_realip_module \
--without-http_fastcgi_module \
--without-mail_pop3_module \
--without-mail_imap_module \
--without-mail_smtp_module


make && make install
echo -e "\033[34m[openresty安装成功]\033[0m"


cd /usr/local/src
if [ -d "$SCRIPT_DIR/conf" ] && [ -f "$SCRIPT_DIR/init.lua" ]; then
    echo -e "\033[34m[使用当前目录代码安装 ZhongKui-WAF]\033[0m"
    if [ -d "$ZHONGKUI_PATH" ] && [ "$(cd "$SCRIPT_DIR" && pwd)" != "$ZHONGKUI_PATH" ]; then
        BACKUP_PATH="${ZHONGKUI_PATH}.bak.$(date +%Y%m%d%H%M%S)"
        mv "$ZHONGKUI_PATH" "$BACKUP_PATH"
        echo -e "\033[34m[已备份旧目录到 $BACKUP_PATH]\033[0m"
    fi
    mkdir -p "$OPENRESTY_PATH"
    if [ "$(cd "$SCRIPT_DIR" && pwd)" != "$ZHONGKUI_PATH" ]; then
        cp -a "$SCRIPT_DIR" "$ZHONGKUI_PATH"
    fi
else
    if [ ! -f "zhongkui-waf-master.zip" ]; then
        echo -e "\033[34m[未发现 zhongkui-waf-master.zip 文件，开始下载]\033[0m"
        wget -O /usr/local/src/zhongkui-waf-master.zip https://github.com/bukaleyang/zhongkui-waf/archive/refs/heads/master.zip --no-check-certificate
    else
        echo -e "\033[34m[发现 zhongkui-waf-master.zip 文件，跳过下载]\033[0m"
    fi
    unzip zhongkui-waf-master.zip
    if [ -d "$ZHONGKUI_PATH" ]; then
        BACKUP_PATH="${ZHONGKUI_PATH}.bak.$(date +%Y%m%d%H%M%S)"
        mv "$ZHONGKUI_PATH" "$BACKUP_PATH"
        echo -e "\033[34m[已备份旧目录到 $BACKUP_PATH]\033[0m"
    fi
    mv ./zhongkui-waf-master $ZHONGKUI_PATH
fi

SYSTEM_TEMPLATE="$ZHONGKUI_PATH/conf/system-$ROLE.json"
if [ -f "$SYSTEM_TEMPLATE" ]; then
    cp "$SYSTEM_TEMPLATE" "$ZHONGKUI_PATH/conf/system.json"
    echo -e "\033[34m[已应用 $ROLE 节点配置模板]\033[0m"
else
    echo -e "\033[31m[未找到配置模板: $SYSTEM_TEMPLATE]\033[0m"
    exit 1
fi

mkdir -p $OPENRESTY_PATH/nginx/logs/hack
echo -e "\033[34m[hack目录已创建]\033[0m"
echo -e "\033[34m[zhongkui-waf安装成功]\033[0m"


cd /usr/local/src
if [ ! -f "libmaxminddb-1.7.1.tar.gz" ]; then
    echo -e "\033[34m[未发现 libmaxminddb-1.7.1.tar.gz 文件，开始下载]\033[0m"
    wget https://github.com/maxmind/libmaxminddb/releases/download/1.7.1/libmaxminddb-1.7.1.tar.gz
else
    echo -e "\033[34m[发现 libmaxminddb-1.7.1.tar.gz 文件，跳过下载]\033[0m"
fi
tar -zxf libmaxminddb-1.7.1.tar.gz
cd ./libmaxminddb-1.7.1
./configure
make && make install
echo /usr/local/lib >> /etc/ld.so.conf.d/local.conf
ldconfig
echo -e "\033[34m[libmaxminddb安装成功]\033[0m"


cd /usr/local/src
if [ ! -f "libinjection-master.zip" ]; then
    echo -e "\033[34m[未发现 libinjection-master.zip 文件，开始下载]\033[0m"
    wget -O /usr/local/src/libinjection-master.zip https://github.com/client9/libinjection/archive/refs/heads/master.zip
else
    echo -e "\033[34m[发现 libinjection-master.zip 文件，跳过下载]\033[0m"
fi
unzip libinjection-master.zip
cd ./libinjection-master
make all
mv ./src/libinjection.so $OPENRESTY_PATH/lualib/libinjection.so
echo -e "\033[34m[libinjection安装成功]\033[0m"


cd /usr/local/src
if [ ! -f "luaossl-rel-20220711.tar.gz" ]; then
    echo -e "\033[34m[未发现 luaossl-rel-20220711.tar.gz 文件，开始下载]\033[0m"
    wget -O /usr/local/src/luaossl-rel-20220711.tar.gz https://github.com/wahern/luaossl/archive/refs/tags/rel-20220711.tar.gz
else
    echo -e "\033[34m[发现 luaossl-rel-20220711.tar.gz 文件，跳过下载]\033[0m"
fi
tar -zxf luaossl-rel-20220711.tar.gz
cd ./luaossl-rel-20220711

# 安装 OpenSSL 开发库（如果尚未安装）
if command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get install -y libssl-dev pkg-config
elif command -v yum >/dev/null 2>&1; then
    yum install -y openssl-devel pkgconfig
fi

# 使用 pkg-config 获取 OpenSSL 编译参数
if command -v pkg-config >/dev/null 2>&1; then
    OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || pkg-config --cflags libssl 2>/dev/null || echo "-I/usr/include/openssl")
    OPENSSL_LDFLAGS=$(pkg-config --libs openssl 2>/dev/null || pkg-config --libs libssl 2>/dev/null || echo "-lssl -lcrypto")
else
    OPENSSL_CFLAGS="-I/usr/include/openssl"
    OPENSSL_LDFLAGS="-lssl -lcrypto"
fi

# 编译 luaossl，指定 OpenSSL 和 LuaJIT 路径
make all5.1 \
    includedir=$OPENRESTY_PATH/luajit/include/luajit-2.1 \
    CC="gcc" \
    CFLAGS="$OPENSSL_CFLAGS" \
    LDFLAGS="$OPENSSL_LDFLAGS" && \
make install5.1
echo -e "\033[34m[luaossl安装成功]\033[0m"


cd /usr/local/src
if [ ! -f "luafilesystem-master.zip" ]; then
    echo -e "\033[34m[未发现 luafilesystem-master.zip 文件，开始下载]\033[0m"
    wget -O /usr/local/src/luafilesystem-master.zip https://github.com/lunarmodules/luafilesystem/archive/refs/heads/master.zip
else
    echo -e "\033[34m[发现 luafilesystem-master.zip 文件，跳过下载]\033[0m"
fi
unzip luafilesystem-master.zip
cd ./luafilesystem-master
make INCS=-I$OPENRESTY_PATH/luajit/include/luajit-2.1
mv ./src/lfs.so $OPENRESTY_PATH/lualib/lfs.so
echo -e "\033[34m[luafilesystem安装成功]\033[0m"


# =================maxminddb数据库文件自动更新start=================

mkdir -p $GEOIP_DATABASE_PATH

# 检查是否存在 GeoLite2-City.mmdb 文件
if [ -f "/usr/local/src/GeoLite2-City.mmdb" ]; then
    echo -e "\033[34m[发现 GeoLite2-City.mmdb 文件，直接复制]\033[0m"
    cp /usr/local/src/GeoLite2-City.mmdb $GEOIP_DATABASE_PATH/
else
    echo -e "\033[34m[未发现 GeoLite2-City.mmdb 文件，安装 geoipupdate]\033[0m"
    cd /usr/local/src
    if [ ! -x "geoipupdate_6.0.0_linux_386.tar.gz" ]; then
        wget https://github.com/maxmind/geoipupdate/releases/download/v6.0.0/geoipupdate_6.0.0_linux_386.tar.gz
    fi
    tar -zxf geoipupdate_6.0.0_linux_386.tar.gz
    mv ./geoipupdate_6.0.0_linux_386/geoipupdate /usr/local/bin/geoipupdate


    if [ -x "/usr/local/bin/geoipupdate" ]; then
        # 将配置文件GeoIP.conf写入到/usr/local/etc/目录
    echo "
AccountID your AccountID
LicenseKey your LicenseKey
#EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country
EditionIDs GeoLite2-City
DatabaseDirectory $GEOIP_DATABASE_PATH
" >> /usr/local/etc/GeoIP.conf

        echo -e "\033[34m[GeoIP.conf安装成功]\033[0m"

        echo "32 8 * * 1,3 /usr/local/bin/geoipupdate" | crontab -
        echo -e "\033[34m[geoipupdate安装成功]\033[0m"

        mkdir -p $GEOIP_DATABASE_PATH
        /usr/local/bin/geoipupdate
    fi
fi
# =================maxminddb数据库文件自动更新end=================

# =================文件夹权限设置start=================

echo -e "\033[34m[设置文件夹权限]\033[0m"

# 设置 zhongkui-waf 目录权限，确保 webuser 用户有读写权限
chown -R webuser:users $OPENRESTY_PATH/zhongkui-waf
chmod -R 755 $OPENRESTY_PATH/zhongkui-waf

# 设置日志目录权限
mkdir -p $OPENRESTY_PATH/nginx/logs/hack
chown -R webuser:users $OPENRESTY_PATH/nginx/logs
chmod -R 755 $OPENRESTY_PATH/nginx/logs

# 设置 GeoIP 数据库目录权限
chown -R webuser:users $GEOIP_DATABASE_PATH
chmod -R 755 $GEOIP_DATABASE_PATH

echo -e "\033[34m[文件夹权限设置完成]\033[0m"

# =================文件夹权限设置end=================

# =================OpenResty nginx.conf 配置start=================

echo -e "\033[34m[生成 OpenResty nginx.conf]\033[0m"

ADMIN_INCLUDE=""
if [ "$ROLE" = "master" ]; then
    ADMIN_INCLUDE="    include $ZHONGKUI_PATH/admin/conf/admin.conf;"
fi

cat > $OPENRESTY_PATH/nginx/conf/nginx.conf <<EOF
worker_processes auto;

events {
    worker_connections 10240;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    keepalive_timeout 65;

    include $ZHONGKUI_PATH/admin/conf/waf.conf;
$ADMIN_INCLUDE
    include $ZHONGKUI_PATH/admin/conf/sites.conf;
}
EOF

echo -e "\033[34m[nginx.conf 已生成，当前角色: $ROLE]\033[0m"

# =================OpenResty nginx.conf 配置end=================

# =================MySQL 数据库配置start=================

if [ "$ROLE" = "master" ] && [ "$INIT_LOCAL_MYSQL" = "on" ]; then
    echo -e "\033[34m[配置 MySQL 数据库]\033[0m"

    # 检查 MySQL 是否已安装
    if ! command -v mysql >/dev/null 2>&1; then
        echo -e "\033[34m[未发现 MySQL，开始安装]\033[0m"
    
        if command -v apt-get >/dev/null 2>&1; then
            # Ubuntu/Debian
            apt-get update && apt-get install -y mysql-server
        elif command -v yum >/dev/null 2>&1; then
            # CentOS/RHEL
            yum install -y mysql-server
            systemctl start mysqld
            systemctl enable mysqld
        fi
    fi

    # 等待 MySQL 启动
    sleep 5

    # 创建 MySQL 用户和数据库
    MYSQL_PASSWORD="#rwcTjKk&6xR"
    MYSQL_USER="zhongkui"
    MYSQL_DATABASE="zhongkui_waf"

    # 执行 MySQL 命令
    echo -e "\033[34m[创建 MySQL 用户和数据库]\033[0m"
    mysql -u root -e "CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'127.0.0.1' IDENTIFIED WITH mysql_native_password BY '${MYSQL_PASSWORD}';"
    mysql -u root -e "CREATE DATABASE IF NOT EXISTS ${MYSQL_DATABASE};"
    mysql -u root -e "GRANT ALL PRIVILEGES ON ${MYSQL_DATABASE}.* TO '${MYSQL_USER}'@'127.0.0.1';"
    mysql -u root -e "FLUSH PRIVILEGES;"

    echo -e "\033[34m[MySQL 数据库配置完成]\033[0m"
else
    echo -e "\033[34m[跳过本机 MySQL 安装与初始化；请确认 conf/system.json 中的 MySQL 配置可用]\033[0m"
fi

# =================MySQL 数据库配置end=================

# =================sudo 权限配置start=================

echo -e "\033[34m[配置 webuser sudo 权限]\033[0m"

# 创建 sudoers.d 目录（如果不存在）
mkdir -p /etc/sudoers.d

# 创建 webuser 的 sudo 权限配置文件
cat > /etc/sudoers.d/webuser <<EOF
# 允许 webuser 无密码执行 nginx 命令
webuser ALL=(root) NOPASSWD: /opt/openresty/nginx/sbin/nginx -s reload, /opt/openresty/nginx/sbin/nginx -t
EOF

# 设置文件权限
chmod 440 /etc/sudoers.d/webuser

echo -e "\033[34m[sudo 权限配置完成]\033[0m"

# =================sudo 权限配置end=================

# =================systemd服务配置start=================

cat > /usr/lib/systemd/system/openresty.service <<EOF
[Unit]
Description=OpenResty
After=network.target

[Service]
Type=forking
PIDFile=/opt/openresty/nginx/logs/nginx.pid
ExecStart=/opt/openresty/nginx/sbin/nginx
ExecReload=/opt/openresty/nginx/sbin/nginx -s reload
ExecStop=/opt/openresty/nginx/sbin/nginx -s stop
User=root
Group=root
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable openresty
systemctl start openresty

echo -e "\033[34m[openresty systemd服务配置成功]\033[0m"
echo -e "\033[34m[部署完成，角色: $ROLE]\033[0m"

# =================systemd服务配置end=================

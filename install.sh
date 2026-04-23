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
INIT_LOCAL_REDIS="off"
MYSQL_USER="zhongkui_mac"
REDIS_PORT="16381"
REDIS_PASSWORD="Push@789"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="/usr/local/src"

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
        --init-local-redis)
            INIT_LOCAL_REDIS="on"
            shift
            ;;
        --mysql-user)
            if [ $# -lt 2 ]; then
                echo -e "\033[31m[--mysql-user 需要指定账号]\033[0m"
                exit 1
            fi
            MYSQL_USER="$2"
            shift 2
            ;;
        --mysql-user=*)
            MYSQL_USER="${1#*=}"
            shift
            ;;
        --redis-port)
            if [ $# -lt 2 ]; then
                echo -e "\033[31m[--redis-port 需要指定端口]\033[0m"
                exit 1
            fi
            REDIS_PORT="$2"
            shift 2
            ;;
        --redis-port=*)
            REDIS_PORT="${1#*=}"
            shift
            ;;
        --redis-password)
            if [ $# -lt 2 ]; then
                echo -e "\033[31m[--redis-password 需要指定密码]\033[0m"
                exit 1
            fi
            REDIS_PASSWORD="$2"
            shift 2
            ;;
        --redis-password=*)
            REDIS_PASSWORD="${1#*=}"
            shift
            ;;
        -h|--help)
            echo "Usage: ./install.sh [--role master|node] [--init-local-mysql] [--mysql-user USER] [--init-local-redis] [--redis-port PORT] [--redis-password PASSWORD]"
            exit 0
            ;;
        *)
            echo -e "\033[31m[未知参数: $1]\033[0m"
            echo "Usage: ./install.sh [--role master|node] [--init-local-mysql] [--mysql-user USER] [--init-local-redis] [--redis-port PORT] [--redis-password PASSWORD]"
            exit 1
            ;;
    esac
done

if [ "$ROLE" != "master" ] && [ "$ROLE" != "node" ]; then
    echo -e "\033[31m[role 只能是 master 或 node]\033[0m"
    exit 1
fi

if [ -z "$MYSQL_USER" ]; then
    echo -e "\033[31m[mysql-user 不能为空]\033[0m"
    exit 1
fi

if [ -z "$REDIS_PORT" ] || [ -z "$REDIS_PASSWORD" ]; then
    echo -e "\033[31m[redis-port 和 redis-password 不能为空]\033[0m"
    exit 1
fi

echo -e "\033[34m[部署角色: $ROLE]\033[0m"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "\033[31m[请使用 root 用户执行 install.sh]\033[0m"
    exit 1
fi

echo -e "\033[34m[检查基础依赖]\033[0m"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y build-essential wget unzip tar ca-certificates openssl libssl-dev libpcre3-dev zlib1g-dev pkg-config sudo cron
elif command -v yum >/dev/null 2>&1; then
    yum install -y gcc gcc-c++ make wget unzip tar ca-certificates openssl openssl-devel pcre-devel zlib-devel pkgconfig sudo cronie
else
    echo -e "\033[31m[未识别包管理器，请先安装 gcc/make/wget/unzip/tar/openssl-devel/pcre-devel/zlib-devel/pkg-config/sudo]\033[0m"
    exit 1
fi

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

mkdir -p "$SRC_DIR"
if [ -d "$SCRIPT_DIR/waf" ]; then
    echo -e "\033[34m[同步 waf 目录离线安装包到 $SRC_DIR]\033[0m"
    for pkg in \
        openresty-1.25.3.2.tar.gz \
        libmaxminddb-1.7.1.tar.gz \
        libinjection-master.zip \
        luaossl-rel-20220711.tar.gz \
        luafilesystem-master.zip \
        redis16381.zip \
        GeoLite2-City.mmdb
    do
        if [ -f "$SCRIPT_DIR/waf/$pkg" ] && [ ! -f "$SRC_DIR/$pkg" ]; then
            cp "$SCRIPT_DIR/waf/$pkg" "$SRC_DIR/$pkg"
            echo -e "\033[34m[已复制 $pkg]\033[0m"
        fi
    done
fi

cd "$SRC_DIR"
if [ ! -f "openresty-1.25.3.2.tar.gz" ]; then
    echo -e "\033[34m[未发现 openresty-1.25.3.2.tar.gz 文件，开始下载]\033[0m"
    wget https://openresty.org/download/openresty-1.25.3.2.tar.gz
else
    echo -e "\033[34m[发现 openresty-1.25.3.2.tar.gz 文件，跳过下载]\033[0m"
fi
rm -rf openresty-1.25.3.2
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


cd "$SRC_DIR"
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
        wget -O "$SRC_DIR/zhongkui-waf-master.zip" https://github.com/bukaleyang/zhongkui-waf/archive/refs/heads/master.zip --no-check-certificate
    else
        echo -e "\033[34m[发现 zhongkui-waf-master.zip 文件，跳过下载]\033[0m"
    fi
    rm -rf zhongkui-waf-master
    unzip -q zhongkui-waf-master.zip
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

cd "$SRC_DIR"
if [ ! -f "libmaxminddb-1.7.1.tar.gz" ]; then
    echo -e "\033[34m[未发现 libmaxminddb-1.7.1.tar.gz 文件，开始下载]\033[0m"
    wget https://github.com/maxmind/libmaxminddb/releases/download/1.7.1/libmaxminddb-1.7.1.tar.gz
else
    echo -e "\033[34m[发现 libmaxminddb-1.7.1.tar.gz 文件，跳过下载]\033[0m"
fi
rm -rf libmaxminddb-1.7.1
tar -zxf libmaxminddb-1.7.1.tar.gz
cd ./libmaxminddb-1.7.1
./configure
make && make install
echo /usr/local/lib >> /etc/ld.so.conf.d/local.conf
ldconfig
echo -e "\033[34m[libmaxminddb安装成功]\033[0m"


cd "$SRC_DIR"
if [ ! -f "libinjection-master.zip" ]; then
    echo -e "\033[34m[未发现 libinjection-master.zip 文件，开始下载]\033[0m"
    wget -O "$SRC_DIR/libinjection-master.zip" https://github.com/client9/libinjection/archive/refs/heads/master.zip
else
    echo -e "\033[34m[发现 libinjection-master.zip 文件，跳过下载]\033[0m"
fi
rm -rf libinjection-master
unzip -q libinjection-master.zip
cd ./libinjection-master

# libinjection 上游构建链包含 Python2 脚本。
# 新系统默认 python=python3 时会在生成 fingerprints 阶段报语法错。
# 这里优先使用压缩包内已生成的数据文件，避免触发 Python2 生成流程。
if [ -f "./src/Makefile" ] && [ -f "./src/fingerprints.txt" ] && [ -f "./src/sqlparse_data.json" ] && [ -f "./src/libinjection_sqli_data.h" ]; then
    sed -i 's/^sqlparse_data.json: sqlparse_map.py fingerprints$/sqlparse_data.json: sqlparse_map.py fingerprints.txt/' ./src/Makefile
    touch ./src/fingerprints.txt ./src/sqlparse_data.json ./src/libinjection_sqli_data.h
fi

make all
mv ./src/libinjection.so $OPENRESTY_PATH/lualib/libinjection.so
echo -e "\033[34m[libinjection安装成功]\033[0m"


cd "$SRC_DIR"
if [ ! -f "luaossl-rel-20220711.tar.gz" ]; then
    echo -e "\033[34m[未发现 luaossl-rel-20220711.tar.gz 文件，开始下载]\033[0m"
    wget -O "$SRC_DIR/luaossl-rel-20220711.tar.gz" https://github.com/wahern/luaossl/archive/refs/tags/rel-20220711.tar.gz
else
    echo -e "\033[34m[发现 luaossl-rel-20220711.tar.gz 文件，跳过下载]\033[0m"
fi
rm -rf luaossl-rel-20220711
tar -zxf luaossl-rel-20220711.tar.gz
cd ./luaossl-rel-20220711

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
make install5.1 \
    lua51cpath=$OPENRESTY_PATH/lualib \
    lua51path=$OPENRESTY_PATH/lualib

if [ ! -f "$OPENRESTY_PATH/lualib/_openssl.so" ] || [ ! -f "$OPENRESTY_PATH/lualib/openssl.lua" ]; then
    echo -e "\033[31m[luaossl安装失败，未找到 _openssl.so 或 openssl.lua]\033[0m"
    exit 1
fi
echo -e "\033[34m[luaossl安装成功]\033[0m"


cd "$SRC_DIR"
if [ ! -f "luafilesystem-master.zip" ]; then
    echo -e "\033[34m[未发现 luafilesystem-master.zip 文件，开始下载]\033[0m"
    wget -O "$SRC_DIR/luafilesystem-master.zip" https://github.com/lunarmodules/luafilesystem/archive/refs/heads/master.zip
else
    echo -e "\033[34m[发现 luafilesystem-master.zip 文件，跳过下载]\033[0m"
fi
rm -rf luafilesystem-master
unzip -q luafilesystem-master.zip
cd ./luafilesystem-master
make INCS=-I$OPENRESTY_PATH/luajit/include/luajit-2.1
mv ./src/lfs.so $OPENRESTY_PATH/lualib/lfs.so
echo -e "\033[34m[luafilesystem安装成功]\033[0m"


# =================maxminddb数据库文件自动更新start=================

mkdir -p $GEOIP_DATABASE_PATH

# 检查是否存在 GeoLite2-City.mmdb 文件
if [ -f "$SRC_DIR/GeoLite2-City.mmdb" ]; then
    echo -e "\033[34m[发现 GeoLite2-City.mmdb 文件，直接复制]\033[0m"
    cp "$SRC_DIR/GeoLite2-City.mmdb" $GEOIP_DATABASE_PATH/
else
    echo -e "\033[34m[未发现 GeoLite2-City.mmdb 文件，安装 geoipupdate]\033[0m"
    cd "$SRC_DIR"
    if [ ! -f "geoipupdate_6.0.0_linux_386.tar.gz" ]; then
        wget https://github.com/maxmind/geoipupdate/releases/download/v6.0.0/geoipupdate_6.0.0_linux_386.tar.gz
    fi
    rm -rf geoipupdate_6.0.0_linux_386
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

NGINX_TEMPLATE="$ZHONGKUI_PATH/waf/nginx.conf.default"
if [ ! -f "$NGINX_TEMPLATE" ]; then
    echo -e "\033[31m[未找到 nginx.conf 模板: $NGINX_TEMPLATE]\033[0m"
    exit 1
fi

sed \
    -e "s#__ZHONGKUI_PATH__#$ZHONGKUI_PATH#g" \
    -e "s#__ADMIN_INCLUDE__#$ADMIN_INCLUDE#g" \
    "$NGINX_TEMPLATE" > "$OPENRESTY_PATH/nginx/conf/nginx.conf"

echo -e "\033[34m[nginx.conf 已生成，当前角色: $ROLE]\033[0m"

# =================OpenResty nginx.conf 配置end=================

# =================Redis 配置start=================

if [ "$INIT_LOCAL_REDIS" = "on" ]; then
    echo -e "\033[34m[安装本机 Redis]\033[0m"

    if [ ! -f "$SRC_DIR/redis16381.zip" ]; then
        echo -e "\033[31m[未找到 Redis 离线包: $SRC_DIR/redis16381.zip]\033[0m"
        exit 1
    fi

    REDIS_PATH="$OPENRESTY_PATH/redis16381"
    rm -rf "$REDIS_PATH"
    unzip -q "$SRC_DIR/redis16381.zip" -d "$OPENRESTY_PATH"
    chmod +x "$REDIS_PATH"/redis-*
    rm -f "$REDIS_PATH/redis.pid"

    sed -i \
        -e 's/^bind .*/bind 0.0.0.0/' \
        -e 's/^port .*/port '"$REDIS_PORT"'/' \
        -e 's/^requirepass .*/requirepass "'"$REDIS_PASSWORD"'"/' \
        -e 's/^pidfile .*/pidfile "redis.pid"/' \
        -e 's|^logfile .*|logfile "./redis.log"|' \
        -e 's|^dir .*|dir ./|' \
        "$REDIS_PATH/redis.conf"

    cat > /usr/lib/systemd/system/redis16381.service <<EOF
[Unit]
Description=ZhongKui Redis
After=network.target

[Service]
Type=forking
WorkingDirectory=$REDIS_PATH
PIDFile=$REDIS_PATH/redis.pid
ExecStart=$REDIS_PATH/redis-server $REDIS_PATH/redis.conf
ExecStop=$REDIS_PATH/redis-cli -h 127.0.0.1 -p $REDIS_PORT -a '$REDIS_PASSWORD' shutdown
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable redis16381
    systemctl restart redis16381

    sed -i '/"redis"[[:space:]]*:/,/"rulesSort"[[:space:]]*:/ {
        s/"host": *"[^"]*"/"host": "127.0.0.1"/
        s/"password": *"[^"]*"/"password": "'"$REDIS_PASSWORD"'"/
        s/"port": *[0-9][0-9]*/"port": '"$REDIS_PORT"'/
    }' "$ZHONGKUI_PATH/conf/system.json"

    echo -e "\033[34m[Redis 安装完成: 127.0.0.1:$REDIS_PORT]\033[0m"
else
    echo -e "\033[34m[跳过本机 Redis 安装；请确认 conf/system.json 中的 Redis 配置可用]\033[0m"
fi

# =================Redis 配置end=================

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
    MYSQL_DATABASE="zhongkui_waf"

    # 执行 MySQL 命令
    echo -e "\033[34m[创建 MySQL 用户和数据库]\033[0m"
    mysql -u root -e "CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'127.0.0.1' IDENTIFIED WITH mysql_native_password BY '${MYSQL_PASSWORD}';"
    mysql -u root -e "CREATE DATABASE IF NOT EXISTS ${MYSQL_DATABASE};"
    mysql -u root -e "GRANT ALL PRIVILEGES ON ${MYSQL_DATABASE}.* TO '${MYSQL_USER}'@'127.0.0.1';"
    mysql -u root -e "FLUSH PRIVILEGES;"
    sed -i '/"mysql"[[:space:]]*:/,/"redis"[[:space:]]*:/ {
        s/"host": *"[^"]*"/"host": "127.0.0.1"/
        s/"port": *"[^"]*"/"port": "3306"/
        s/"user": *"[^"]*"/"user": "'"$MYSQL_USER"'"/
    }' "$ZHONGKUI_PATH/conf/system.json"

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

# =================安装后校验start=================

echo -e "\033[34m[执行安装后校验]\033[0m"

fail_check() {
    echo -e "\033[31m[校验失败] $1\033[0m"
    exit 1
}

for required_file in \
    "$OPENRESTY_PATH/nginx/sbin/nginx" \
    "$OPENRESTY_PATH/nginx/conf/nginx.conf" \
    "$ZHONGKUI_PATH/conf/system.json" \
    "$OPENRESTY_PATH/lualib/libinjection.so" \
    "$OPENRESTY_PATH/lualib/lfs.so" \
    "$OPENRESTY_PATH/lualib/_openssl.so" \
    "$OPENRESTY_PATH/lualib/openssl.lua" \
    "$GEOIP_DATABASE_PATH/GeoLite2-City.mmdb"
do
    [ -f "$required_file" ] || fail_check "缺少文件: $required_file"
done

systemctl is-active --quiet openresty || fail_check "openresty 服务未运行"
$OPENRESTY_PATH/nginx/sbin/nginx -t >/dev/null 2>&1 || fail_check "nginx 配置检测失败"

grep -q "include $ZHONGKUI_PATH/admin/conf/sites.conf;" "$OPENRESTY_PATH/nginx/conf/nginx.conf" || fail_check "nginx.conf 未包含 sites.conf"
if [ "$ROLE" = "master" ]; then
    grep -q "include $ZHONGKUI_PATH/admin/conf/admin.conf;" "$OPENRESTY_PATH/nginx/conf/nginx.conf" || fail_check "master 模式未包含 admin.conf"
else
    if grep -q "include $ZHONGKUI_PATH/admin/conf/admin.conf;" "$OPENRESTY_PATH/nginx/conf/nginx.conf"; then
        fail_check "node 模式不应包含 admin.conf"
    fi
fi

if [ "$INIT_LOCAL_REDIS" = "on" ]; then
    systemctl is-active --quiet redis16381 || fail_check "redis16381 服务未运行"
    "$OPENRESTY_PATH/redis16381/redis-cli" -h 127.0.0.1 -p "$REDIS_PORT" -a "$REDIS_PASSWORD" PING | grep -q PONG || fail_check "本机 Redis PING 失败"
fi

if [ "$ROLE" = "master" ] && [ "$INIT_LOCAL_MYSQL" = "on" ]; then
    mysql -u root -e "USE zhongkui_waf; SELECT 1;" >/dev/null 2>&1 || fail_check "本机 MySQL 校验失败"
fi

echo -e "\033[34m[安装后校验通过]\033[0m"
echo -e "\033[34m[部署完成，角色: $ROLE]\033[0m"

# =================安装后校验end=================

# =================systemd服务配置end=================

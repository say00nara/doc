- ## 搭建环境  
操作系统    Ubuntu 14.04.5  
Strongswan  5.5.1  
FreeRadius  2.1.12  
DaloRadius  0.9-9  
PHP 5.5.9  
Nginx   1.10.1  
Mysql   5.5.52  


- ## strongswan安装配置
下载strongswan源码  

		wget https://download.strongswan.org/strongswan-5.5.1.tar.gz

安装依赖  

    apt-get install libpam0g-dev libssl-dev build-essential
    
编译安装  

    ./configure  --enable-eap-identity --enable-eap-md5 --enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  --enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  --enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  --enable-certexpire --enable-radattr  --disable-gmp
    make && make install
    
### 创建证书和密钥
生成CA证书的私钥，并使用私钥签名CA证书

    ipsec pki --gen --outform pem > ca.pem
    ipsec pki --self --in ca.pem --dn "C=com, O=vpn, CN=VPN CA" --ca --outform pem > ca.cert.pem
    
>Tips：C 表示国家名，O 表示组织名，CN 表示通用名
    
生成服务器证书的私钥，并用CA证书签发服务器证书  

    ipsec pki --gen --outform pem > server.pem
    ipsec pki --pub --in server.pem | ipsec pki --issue --cacert ca.cert.pem \
        --cakey ca.pem --dn "C=com, O=vpn, CN=${server_name}" \
        --san="${server_name}" \
        --flag serverAuth --flag ikeIntermediate \
        --outform pem > server.cert.pem

    
> Tips：
> 
> - C和O的值必须与CA证书的一致。CN和san建议使用服务器的 IP 地址或 URL，san可设置多个。
> 
> - iOS 客户端要求 CN 必须是你的服务器的 IP 地址或 URL。
> 
> - Windows 7 除了对CN的要求之外，还要求必须显式说明这个服务器证书的用途（如用于与服务器进行认证），–flag serverAuth。
> 
> - 非 iOS 的 Mac OS X 要求了”IP 安全网络密钥互换居间（IP Security IKE Intermediate）“这种增强型密钥用法（EKU），–flag ikdeIntermediate。
> 
> - Android 和 iOS 都要求服务器别名（serverAltName）为服务器的 URL 或 IP 地址，–san。
     
**生成客户端证书**  
在接下来的 ipsec.conf 配置文件中：  
若 rightauth 配置为 eap 时客户端使用CA证书认证，可以不用生成客户端证书  
若 rightauth 配置为 pubkey 时则需要生成客户端证书 

    ipsec pki --gen --outform pem > client.pem
    ipsec pki --pub --in client.pem | ipsec pki --issue --cacert ca.cert.pem \
        --cakey ca.pem --dn "C=com, O=vpn,CN=VPN Client" \
        --outform pem > client.cert.pem
        
**生成 pkcs12 证书,用于客户端导入时使用**  
过程中会提示输入两次密码，用于导入证书时验证使用。  

    openssl pkcs12 -export -inkey client.pem -in client.cert.pem -name "client" -certfile ca.cert.pem -caname "VPN Client"  -out client.cert.p12
    
把证书放入对应目录  

    cp ca.cert.pem /usr/local/etc/ipsec.d/cacerts/
    cp server.cert.pem /usr/local/etc/ipsec.d/certs/
    cp server.pem /usr/local/etc/ipsec.d/private/
    cp client.cert.pem /usr/local/etc/ipsec.d/certs/
    cp client.pem  /usr/local/etc/ipsec.d/private/

### StrongSwan配置
编辑ipsec配置文件：/usr/local/etc/ipsec.conf  
```
config setup
	uniqueids=never     #允许多个设备同时在线

conn %default
	left=%any
	right=%any
	leftid=192.168.201.9         #服务端id，同证书生成时的cn值
	rightsourceip=10.0.0.0/24    #客户端获取的ip范围段
	leftsubnet=0.0.0.0/0         #所有流量均发往vpn通道

conn IKEv2-EAP
    keyexchange=ikev2       #VPN协议
    leftauth=pubkey
    leftcert=server.cert.pem
    rightsendcert=never
    rekey=no
    eap_identity=%any
    auto=add
    rightauth=eap-radius     #radius用户认证
    #rightauth=eap-mschapv2
```
编辑strongswan配置文件：/usr/local/etc/strongswan.conf  
```
charon {
    load_modular = yes
    duplicheck.enable = no #闭冗余检查以同时连接多个设备
    compress = yes
    plugins {

    eap-radius {    #radius认证配置标签
	servers {  
	    primary {  
		address = 127.0.0.1 #radius认证服务器地址
		secret = 123        #radius认证密钥
            }  
	}  
    } 
    include strongswan.d/charon/*.conf
    }
    
    dns1 = 223.5.5.5    #指定vpn客户端dns
    dns2 = 223.6.6.6
}
include strongswan.d/*.conf
```
编辑密码认证文件：/usr/local/etc/ipsec.secrets  （如EAP使用radius认证，则文件中EAP用户密码不生效）
```
: PSK "123"     #psk预共享密钥
: RSA server.pem
aa : XAUTH "123" 
aa %any : EAP "123" #eap认证用户名/密码
ss %any : EAP "123"
```
**日志配置**  
strongswan默认会把日志写到系统日志里，可以通过修改配置：/usr/local/etc/strongswan.d/charon-logging.conf  生成独立的日志文件。

    charon {
        filelog {
            /var/log/strongswan.log {
                append = yes
                default = 1
                flush_line = yes
                ike_name = yes
                time_format = %b %e %T
            }
        }
    }

**启动StrongSwan**  
可通过下载启动脚本或命令行方式启动 

    wget https://raw.githubusercontent.com/strongswan/strongswan/master/packages/strongswan/debian/strongswan-starter.ipsec.init -O /etc/init.d/ipsec
    或
    ipsec start
### iptables配置
要通过VPN访问外网，服务端需开启IP转发功能，编辑/etc/sysctl.conf  

    net.ipv4.ip_forward=1

运行 sysctl -p 使之生效。  

添加iptables规则：

    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -s 10.0.0.0/24  -j ACCEPT
    iptables -A INPUT -i eth0 -p esp -j ACCEPT
    iptables -A INPUT -i eth0 -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -i eth0 -p tcp --dport 500 -j ACCEPT
    iptables -A INPUT -i eth0 -p udp --dport 4500 -j ACCEPT
    iptables -A INPUT -i eth0 -p udp --dport 1701 -j ACCEPT
    iptables -A INPUT -i eth0 -p tcp --dport 1723 -j ACCEPT
    iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
    iptables -t mangle -A FORWARD -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
**filter表**条目作用为放行网络流量，其中10.0.0.0是分配给客户端的IP地址段，应与ipsec所配置的地址段相同。  
**nat表**条目作用为实现vpn客户端访问外网，eth0为外网出口网卡名称，此处应根据实际情况修改。  
**mangle表**条目作用为解决vpn连接后mtu问题导致的某些网站无法访问。

- ## FreeRadius配置  
安装freeradius和mysql  

    apt-get install freeradius  freeradius-mysql   freeradius-utils  mysql-server  
    
编辑/etc/freeradius/clients.conf  

    client 127.0.0.1 {
        ipaddr = 127.0.0.1  #freeradius服务地址
        secret = 123        #共享密钥
        require_message_authenticator = no
    }  
    
#### 启用MySQL支持  
编辑配置文件：/etc/freeradius/radiusd.conf ，取消如下注释。  

    $INCLUDE sql.conf
    
在mysql中创建radius数据库，用户并授权  

    create database radius;
    create user 'radius'@'localhost' identified by 'radpass';
    GRANT ALL on radius.* TO 'radius'@'localhost';
    
在mysql中导入freeradius数据库配置  

    use radius;
    source /etc/freeradius/sql/mysql/cui.sql;
    source /etc/freeradius/sql/mysql/ippool.sql;
    source /etc/freeradius/sql/mysql/nas.sql;
    source /etc/freeradius/sql/mysql/schema.sql;
    source /etc/freeradius/sql/mysql/wimax.sql;
    
编辑配置文件：/etc/freeradius/sql.conf ， 修改数据库连接信息。 

    server = "localhost"
    port = 3306
    login = "radius"
    password = "radpass"
    radius_db = "radius"
取消下行的注释  

    readclients = yes


编辑配置文件：/etc/freeradius/sites-enabled/default  

    找到authorize {}模块，注释掉files，去掉sql前的'#'号
    找到accounting {}模块，注释掉radutmp，去掉sql前的'#'号
    找到session {}模块，注释掉radutmp，去掉sql前的'#'号
    找到post-auth {}模块，去掉sql前的'#'号，去掉 Post-Auth-Type REJECT{} 内sql前的'#'号。 
编辑配置文件：/etc/freeradius/sites-enabled/inner-tunnel  

    找到authorize {}模块，注释掉files，去掉sql前的'#'号。
    找到session {}模块，注释掉radutmp，去掉sql前的'#'号。
    找到post-auth {}模块，去掉sql前的'#'号，去掉 Post-Auth-Type REJECT{} 内sql前的'#'号。
**配置FreeRadius对IKEv2进行认证**  
IKEv2使用MSCHAPv2进行加密，但FreeRadius默认使用md5，所以需要修改配置文件：/etc/freeradius/eap.conf  

    eap{
        default_eap_type = mschapv2
    }
- ## DaloRadius配置  
安装php环境支持和nginx，由于DaloRadius版本已停止更新，使用新版本php存在兼容性问题，因此建议使用php5。

    apt-get install php5 php5-xml php5-mysql php5-gd php5-cgi php5-fpm nginx
    
因默认软件源中没有php5版本的php-db包，所以这里通过pear安装  

    wget http://pear.php.net/go-pear.phar
    php go-pear.phar
    pear install DB
下载并配置DaloRadius

    wget http://nchc.dl.sourceforge.net/project/daloradius/daloradius/daloradius0.9-9/daloradius-0.9-9.tar.gz
    tar xf daloradius-0.9-9.tar.gz
    
    #将项目移动到web目录
    mv daloradius-0.9-9 /var/www/html/daloradius
    
    #修改用户权限
    chown -R www-data:www-data /var/www/html/daloradius
修改数据库连接设置，编辑配置文件：/var/www/html/daloradius/library/daloradius.conf.php

    $configValues['CONFIG_DB_HOST'] = 'localhost';
    $configValues['CONFIG_DB_PORT'] = '3306';
    $configValues['CONFIG_DB_USER'] = 'radius';
    $configValues['CONFIG_DB_PASS'] = 'radpass';
    $configValues['CONFIG_DB_NAME'] = 'radius';
修改共享密钥设置，此处 SHARED_SECRET 需和/etc/freeradius/clients.conf中设置的共享密钥相同

    $configValues['CONFIG_MAINT_TEST_USER_RADIUSSECRET'] = 'SHARED_SECRET';
导入daloRadius数据库配置

    mysql -u radius -p radius < /var/www/html/daloradius/contrib/db/mysql-daloradius.sql
### 配置Nginx

设置nginx对php请求的处理，编辑配置文件：/etc/nginx/sites-enabled/default

	location ~ \.php$ {
		include snippets/fastcgi-php.conf;
		fastcgi_pass unix:/var/run/php5-fpm.sock;
	}
	
	#在index参数中加入index.php
	index index.html index.htm index.php;

重启相关服务使配置生效

    service nginx restart
    service freeradius restart
    
### 登录DaloRadius创建用户  
默认用户名：administrator   密码：radius

    http://192.168.201.9/daloradius

登录后进入用户管理页，创建用户
![image](http://hoop8.com/1611A/ZGF2gwlK.png)

- ## 测试  
### 测试FreeRadius认证
使用 radtest 命令测试 freeradius 用户认证  

		radtest [user] [password] localhost 0 [shared_secret]  
    
结果返回 Access-Accept 时，说明FreeRadius工作正常  
    
    Sending Access-Request of id 124 to 127.0.0.1 port 1812
    	User-Name = "test"
    	User-Password = "test"
    	NAS-IP-Address = 127.0.1.1
    	NAS-Port = 0
    	Message-Authenticator = 0x00000000000000000000000000000000
    rad_recv: Access-Accept packet from host 127.0.0.1 port 1812, id=124, length=20  
    
### 测试VPN登录
#### OS X设置  
**导入证书**  
将此前生成的p12证书copy到需连接vpn到客户端，导入系统。默认情况下证书导入位置为［登录］，需手动移动到［系统］栏目内。
![image](http://cfxqd.img48.wal8.com/img48/560823_20161104120158/147823311985.png)
**设置vpn参数**  
++OS X++ 系统设置中默认无法修改vpn参数。需要使用 ++Apple Configurator 2++ 工具生成vpn配置文件，再把配置文件导入系统。
![image](http://cfxqd.img48.wal8.com/img48/560823_20161104120158/147823270182.png)

### **Windows 10 设置**   
**导入证书**  
![image](http://cfxqd.img48.wal8.com/img48/560823_20161104120158/147823311877.png)

**设置vpn参数**   
![image](http://cfxqd.img48.wal8.com/img48/560823_20161104120158/147823325244.png)

### **Android 手机客户端设置**  
**下载客户端**

    https://download.strongswan.org/Android/strongSwan-1.6.2.apk
**导入证书**  
将p12证书文件发送到手机并导入  
![image](http://cfxqd.img48.wal8.com/img48/560823_20161104120158/147823216589.jpeg)

**设置vpn参数**  
![image](http://cfxqd.img48.wal8.com/img48/560823_20161104120158/147823216772.jpeg)  

**测试连接**  
![image](http://cfxqd.img48.wal8.com/img48/560823_20161104120158/147823216953.jpeg)

- ## 已知的问题

1.某些版本的php-fpm pear配置不生效导致daloradius登录时报500错误，可以通过phpinfo页面检查php是否已经加载pear，如未加载需在php-fpm目录下的php.ini添加pear配置  

    include_path=".:/usr/share/pear"

2.使用5.7版本mysql与daloradius存在兼容性问题（list user页面报错等），但可以通过修改mysql配置部分解决。

3.使用pubkey（纯证书认证）+ikev2模式vpn在os x和ios上无法连接（也可能是我方式的问题，反正我没成功），windows10测试正常。


- ## 参考文章  
http://www.mynook.xyz/2016/setup-vpn-server-on-centos-by-strongswan/  
https://www.figotan.org/2016/05/04/cook-your-own-vpn/  
https://www.mawenbao.com/note/freeradius_daloradius_install_config_on_ubuntu.html  
http://weibo.com/p/230418a72b50c80102wchs  
。。。

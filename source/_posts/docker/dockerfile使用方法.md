---
title: dockerfile使用方法
date: '2022/1/22 20:29:01'
categories:
  - - docker
abbrlink: bd09f39b
description: 关于dockerfile的使用方法
tags:
---

## 如何使用Dockerfile构建

先在某个位置建立文件名为Dockerfile的文件
然后 cd 进入该目录，终端中执行命令
```shell
docker build -t ctf123 .
```
##### 注意这个命令最后有个 . 
其中ctf123是将要构建的镜像的名称

构建好之后，使用命令
```shell
docker run -i -d -P ctf456
```
这里的ctf456是容器名称

## Dockerfile中命令的使用
这个Dockerfile好像有点问题，具体我也不知道，只是方便看看命令的意思

```shell
FROM php:7.0-apache
# 引入php:7.0-apache镜像

ENV DEBIAN_FRONTEND noninteractive 

#换源，这里使用sed命令进行替换，原来的/etc/apt/sources.list里面的snapshot.debian.org替换成mirrors.ustc.edu.cn
RUN sed -i 's/snapshot.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list
RUN TZ=Asia/shanghai 
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update -y && \ 
    apt-get install -y curl \
    inetutils-ping \
    && apt-get install -y mysql-server \
    && /etc/init.d/mysql start \
    && mysqladmin -uroot password root  \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*  

# 拷贝文件 
# WORKDIR指令用于指定容器的一个目录， 容器启动时执行的命令会在该目录下执行
# 把当前目录下的东西都copy到/var/www/html/
WORKDIR  /tmp 
COPY ./ /var/www/html/


# 执行sql语句，通过mysql -e "这里面是sql语句" 的格式执行sql语句
# 这里创建了ctf这个数据库，然后创建了admin这个用户，密码是ctf，授权他对数据库ctf的select和insert权限
# 最后执行了db.sql这个文件创建数据库里面的数据，其中source后面加的文件要补充路径
RUN set -x \
    && /etc/init.d/mysql start \ 
    && mysql  -e "CREATE DATABASE  ctf  DEFAULT CHARACTER SET utf8;"  -uroot  -proot \ 
    &&  mysql -e "grant select,insert on ctf.* to 'admin'@'localhost' identified by 'ctf' "  -uroot -proot   \ 
    &&  mysql -e "use cumtctf;"  -uroot -proot \
    && mysql -e "source /var/www/html/db.sql" -uroot -proot 


# 对外暴露接口80和3306
EXPOSE  80 3306 
```


弄了快大半个月了，感谢浩哥、磊哥、冬冬和萄萄学长，学计算机真的要保护好头发，不然迟早头秃

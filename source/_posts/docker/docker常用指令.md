---
title: docker常用指令
date: '2022/1/22 20:29:01'
categories:
  - - docker
description: 关于docker的常用指令
abbrlink: f5e8ee80
tags:
---

#### 注意：
> 下面的1111代表容器id
> 下面的2222代表镜像id

#### 查看全部镜像
```shell
docker images
```

#### 查看容器
```shell
docker ps
docker ps -a
```

#### 运行容器1111
```shell
docker start 1111
```

#### 在运行的1111容器中执行命令
```shell
docker exec -it 1111 /bin/bash
```

#### 用2222这个镜像建立一个容器，用10000端口映射它的80端口，用10001端口映射它的3306端口
```shell
docker run -d -p 10000:80 -p 10001:3306 2222
```

#### 停止容器1111
```shell
sudo docker stop 1111
```

#### 删除容器1111
```shell
sudo docker rm 1111
```

#### 删除镜像2222
```shell
sudo docker rm 2222
```
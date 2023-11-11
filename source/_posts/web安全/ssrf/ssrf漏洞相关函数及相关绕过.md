---
title: ssrf漏洞相关函数和绕过技巧
date: '2022/1/23 23:15:01'
categories:
  - - web安全
    - ssrf
description: 容易产生SSRF（Server-Side Request Forgery）服务端请求伪造的常见函数，以及部分的绕过技巧
abbrlink: c5d4cd20
tags:
---


# SSRF（Server-Side Request Forgery）服务端请求伪造

## 一、容易产生SSRF漏洞的函数

> file_get_contents()、fsockopen()、curl_exec()

### 1、file_get_contents()

该函数的作用是将整个文件读入一个字符串中
```php
<?php
    if(isset($_POST['url']))
    {
        $content=file_get_contents($_POST['url']);
        $filename='images/'.rand().'img1.jpg';
        file_put_contents($filename,$content);
        echo $_POST['url'];
        $img="<img src=\"".$filename."\"/>";
    }
    echo $img;
?>
```
### 2、fsockopen()

该函数用于打开一个网络连接或者一个Unix套接字连接
```php
<?php
	function GetFile($host,$port,$link)
	{
		$fp=fsockopen($host,int($port),$errno,$errstr,30);
		if(!fp)
		{
			echo "$errstr(error number $errno)\n";
		}
		else
		{
			$out="GET $link HTTP/1.1\r\n";
			$out.="Host:$host\r\n";
			$out.="Connection:Close\r\n\r\n";
			$out.="\r\n";
			fwrite($fp,$out);
			$contents="";
			while(!feof($fp))
			{
				$contents.=fgets($fp,1024);
			}
			fclose($fp);
			return $contents;
		}
	}
?>
```
### 3、curl_exec()

该函数可以执行给定的 cURL 会话。
```php
<?php
	if(isset($_POST['url']))
	{
		$link = $_POST['url'];
		$curlobj=curl_init();
		curl_setopt($curlobj,CURLOPT_POST,0);
		curl_setopt($curlobj,CURLOPT_RETURNTRANSFER,TRUE);
		curl_setopt($curlobj,CURLOPT_URL,$link);
		$result=curl_exec($curlobj);
		curl_close($curlobj);
		$filename='../images/'.rand().'.jpg';
		file_put_contents($filename,$result);
		$img="<img src=\"".$filename."\"/>";
		echo $img;
	}
?>
```

## 二、过滤绕过技巧

**1、用@绕过**

```http://www.baidu.com@127.0.0.1```与```http://127.0.0.1```请求是相同的

该请求得到的内容都是127.0.0.1的内容，此绕过同样在URL跳转绕过中适用

**2、利用函数的解析不同进行绕过**

此处图片和解析来自：
[https://www.cnblogs.com/hetianlab/p/14012135.html](https://www.cnblogs.com/hetianlab/p/14012135.html)

> （1）readfile和parse_url解析差异，可用于绕过端口限制

![image](https://gitee.com/black_while/save_image/raw/master/ssrf/analytic_difference_of_function/analytic_difference_of_function_1.png)

readfile函数获取的端口是前面一部分的，而parse_url则是最后冒号的端口

> （2）readfile和parse_url解析host的时候也有差异

![image](https://gitee.com/black_while/save_image/raw/master/ssrf/analytic_difference_of_function/analytic_difference_of_function_2.png)

parse_url函数解析的是前面的网址，readfile则是后面的

> （3）curl和parse_url解析差异

![image](https://gitee.com/black_while/save_image/raw/master/ssrf/analytic_difference_of_function/analytic_difference_of_function_3.png)

curl解析的是第一个@后面的网址，而parse_url解析的是第二个@的网址

参考来自：
[https://blog.csdn.net/weixin_44300286/article/details/108061457](https://blog.csdn.net/weixin_44300286/article/details/108061457)
[https://www.cnblogs.com/hetianlab/p/14012135.html](https://www.cnblogs.com/hetianlab/p/14012135.html)

**3、file_get_contents()黑魔法**

> PHP的 file_get_contents() 函数在遇到不认识的伪协议头时候会将伪协议头当做文件夹，造成目录穿越漏洞，这时候只需不断往上跳转目录即可读到根目录的文件。这个方法可以在SSRF的众多协议被ban的情况下来进行读取文件

比如在buuctf2020上面的一道easy_ssrf

```php
$url = $_GET['url'];
if(preg_match('/unctf\.com/',$url)){
	if(!preg_match('/php|file|zip|bzip|zlib|base|data/i',$url)){
		$url=file_get_contents($url);
		echo($url);
	}else{
		echo('error!!');
	}
}else{
	echo("error");
}
 ```

可以通过传入```?url=abcd://unctf.com/../../../../../etc/passwd```造成目录穿透


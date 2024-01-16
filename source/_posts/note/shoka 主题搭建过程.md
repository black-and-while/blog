---
title: shoka 主题搭建过程
date: '2023/11/16 19:33:01'
categories:
  - - note
description: shoka 主题搭建过程
tags:
---

# shoka 主题搭建过程

## 主题更换

主题网站[https://hexo.io/themes/](https://hexo.io/themes/)

### 使用 shoka 主题

然后在 ```/myblog``` 目录拷贝 shoka 主题的文件到 ```./themes/shoka``` 目录下
```shell
git clone https://github.com/amehime/hexo-theme-shoka.git ./themes/shoka
```

然后删掉```/themes/shokaX```里面的```.git```文件夹

修改根目录的 ```_config.yml``` 文件中的 ```theme``` 为 ```shoka```

按照[指引](https://shoka.lostyu.me/computer-science/note/theme-shoka-doc/dependents/)安装插件

```shell
npm un hexo-renderer-marked --save
npm i hexo-renderer-multi-markdown-it --save
npm install hexo-autoprefixer --save
npm install hexo-algoliasearch --save
npm install hexo-symbols-count-time
npm install hexo-feed --save-dev
```

安装 ```hexo-feed``` 时候还是会出现冲突，卸载原来的 7.0.0 版本，换成 6.1.0
```shell
npm uninstall hexo -g
npm uninstall hexo-cli -g
npm install hexo@6.1.0 -g
```

然后重新安装一下 ```hexo-feed```
```shell
npm install hexo-feed --save-dev
```

#### 配置刚刚安装的插件

参考：https://shoka.lostyu.me/computer-science/note/theme-shoka-doc/dependents/

修改 ```./myblog``` 目录下的 ```_config.yml``` 文件
将 ```highlight``` 和 ```prismjs``` 设置为 ```false```
```shell
highlight:
  enable: false

prismjs:
  enable: false
```

然后在 ```_config.yml``` 文件末尾加上这一大段
```shell
markdown:
  render: # 渲染器设置
    html: false # 过滤 HTML 标签
    xhtmlOut: true # 使用 '/' 来闭合单标签 （比如 <br />）。
    breaks: true # 转换段落里的 '\n' 到 <br>。
    linkify: true # 将类似 URL 的文本自动转换为链接。
    typographer: 
    quotes: '“”‘’'
  plugins: # markdown-it 插件设置
    - plugin:
        name: markdown-it-toc-and-anchor
        enable: true
        options: # 文章目录以及锚点应用的 class 名称，shoka 主题必须设置成这样
          tocClassName: 'toc'
          anchorClassName: 'anchor'
    - plugin:
        name: markdown-it-multimd-table
        enable: true
        options:
          multiline: true
          rowspan: true
          headerless: true
    - plugin:
        name: ./markdown-it-furigana
        enable: true
        options:
          fallbackParens: "()"
    - plugin:
        name: ./markdown-it-spoiler
        enable: true
        options:
          title: "你知道得太多了"

minify:
  html:
    enable: true
    exclude: # 排除 hexo-feed 用到的模板文件
      - '**/json.ejs'
      - '**/atom.ejs'
      - '**/rss.ejs'
  css:
    enable: true
    exclude:
      - '**/*.min.css'
  js:
    enable: true
    mangle:
      toplevel: true
    output:
    compress:
    exclude:
      - '**/*.min.js'

autoprefixer:
  exclude:
    - '*.min.css'

algolia:
  appId: #Your appId
  apiKey: #Your apiKey
  adminApiKey: #Your adminApiKey
  chunkSize: 5000
  indexName: #"shoka"
  fields:
    - title #必须配置
    - path #必须配置
    - categories #推荐配置
    - content:strip:truncate,0,2000
    - gallery
    - photos
    - tags

#keywords建议放到顶部 Site 那里，不然可能报错缩进有问题
keywords: #站点关键词，用 “,” 分隔

feed:
    limit: 20
    order_by: "-date"
    tag_dir: false
    category_dir: false
    rss:
        enable: true
        template: "themes/shoka/layout/_alternate/rss.ejs"
        output: "rss.xml"
    atom:
        enable: true
        template: "themes/shoka/layout/_alternate/atom.ejs"
        output: "atom.xml"
    jsonFeed:
        enable: true
        template: "themes/shoka/layout/_alternate/json.ejs"
        output: "feed.json"
```

#### 代码块显示异常问题


主要是 hexo 的版本问题，可能目前还有兼容性问题
我是直接改了版本，后面看到有大佬说是新的版本有新的禁用方法，不过没有再改了

##### 新的禁用方法

[hexo 官方文档](https://hexo.io/zh-cn/docs/syntax-highlight#%E7%A6%81%E7%94%A8)上面写了关闭 “高亮代码”，有 ```7.0以前``` 和 ```7.0以后``` 的两种写法

v7.0.0及以下：
```shell
# _config.yml
highlight:
  enable: false
prismjs:
  enable: false
```
v7.0.0及以上：
```shell
# _config.yml
syntax_highlighter:  # empty
```

##### 修改版本

修改 ```./myblog``` 目录下的 ```package.json``` 文件
```shell
  "dependencies": {
    "hexo": "^7.0.0",
    "hexo-algoliasearch": "^1.0.0",
    "hexo-autoprefixer": "^2.0.0",
    "hexo-generator-archive": "^2.0.0",
    "hexo-generator-category": "^2.0.0",
    "hexo-generator-index": "^3.0.0",
    "hexo-generator-tag": "^2.0.0",
    "hexo-renderer-ejs": "^2.0.0",
    "hexo-renderer-multi-markdown-it": "^0.1.5",
    "hexo-renderer-stylus": "^3.0.0",
    "hexo-server": "^3.0.0",
    "hexo-symbols-count-time": "^0.7.1",
    "hexo-theme-landscape": "^1.0.0"
  }
```
将 ```"hexo": "^7.0.0"``` 修改为 ```"hexo": "^6.0.0"```

> 我这里不仅把依赖降级了，我把hexo也降级了，也不知道具体是需要哪个，也可能两个都要

重新全局安装 hexo 6.0
```shell
npm install -g hexo@6.0.0
```

然后在 ```./myblog``` 目录下更新依赖
```shell
npm install
```

然后重新生成就可以解决
```shell
hexo clean
hexo g
hexo s
```

> 注意：浏览器可能有缓存，记得刷新缓存



#### 自定义修改

在 ```./myblog``` 目录创建 ```_config.shoka.yml``` 文件，自定义的修改都可以放到这里

随机图床，因为某浪的 api 改了，现在只能用某度的 api 调用某浪的

修改 ```themes\shoka\scripts\helpers\engine.js``` 文件

```shell
  var parseImage = function(img, size) {
    if (img.startsWith('//') || img.startsWith('http')) {
      return img
    } else {
      return 'https://tva'+randomServer+'.sinaimg.cn/'+size+'/'+img
    }
  }
```
改成
```shell
  var parseImage = function(img, size) {
    if (img.startsWith('//') || img.startsWith('http')) {
      return img
    } else {
      return 'https://image.baidu.com/search/down?url=https://tva'+randomServer+'.sinaimg.cn/'+size+'/'+img
    }
  }
```

#### 搜索功能

全局搜索 algolia 的配置参考：https://blog.csdn.net/m0_45234510/article/details/116885792 

在 https://dashboard.algolia.com/ 网址上面，注册账号

在 Search-Index 界面，选择 Create Index ，这里命名为 ```blog-search```

在 Setting-API Keys-All API Keys 界面，选择 New API Key，填入描述信息 Description，选择 Indices 为 ```blog-search```，在 ACL 处选择 ```search```、```browse```、```addObject```、```deleteObject```、```deletelndex```、```listIndexes```、```usage``` 

修改 ```/myblog/_config.yml``` 文件中的 algolia 配置
```shell
algolia:
  appId: **********************
  apiKey: **********************
  adminApiKey: **********************
  chunkSize: 5000
  indexName: **********************
  fields:
  - title
  - path
  - categories
  - content:strip:truncate,0,2000
  - gallery
  - photos
  - tags
```

正常的推送就会自动更新 algolia 中的索引

#### 评论功能

无后端评论系统 valine 的配置参考：https://valine.js.org/quickstart.html

在 ```/myblog/_config.shoka.yml``` 文件中添加 valine 配置进行覆盖

```shell
valine:
  appId: #Your_appId
  appKey: #Your_appkey
  placeholder: ヽ(○´∀`)ﾉ♪ # Comment box placeholder
  avatar: mp # Gravatar style : mp, identicon, monsterid, wavatar, robohash, retro
  pageSize: 10 # Pagination size
  lang: en
  visitor: true # Article reading statistic
  NoRecordIP: false # Whether to record the commenter IP
  serverURLs: # When the custom domain name is enabled, fill it in here (it will be detected automatically by default, no need to fill in)
  powerMode: true
  tagMeta:
    visitor: 新朋友
    master: 主人
    friend: 小伙伴
    investor: 金主粑粑
  tagColor:
    master: "var(--color-orange)"
    friend: "var(--color-aqua)"
    investor: "var(--color-pink)"
  tagMember:
    master:
      # - hash of master@email.com
      # - hash of master2@email.com
    friend:
      # - hash of friend@email.com
      # - hash of friend2@email.com
    investor:
      # - hash of investor1@email.com
```

评论通知与管理工具建议使用这个 [Valine-Admin](https://github.com/DesertsP/Valine-Admin)

建议使用国际版

其中域名绑定这里，添加一个域名 ```leancloud.*********.top```，然后需要在自己域名的服务商（比如我这里是阿里云），添加一个子域名 ```leancloud.*********.top```，然后将 cmake 解析加进去，等几分钟之后就会显示已绑定

评论区一直卡在加载阶段，发送评论也没反应的话，需要在 leancloud 的应用中的数据库创建 ```Comment``` 这个class

valine 的 serverURLs 需要设置为``` ********.api.lncldglobal.com```，就是应用凭证下面那里的 Request 域名，里面有个 ```appId的前八位 + .api.lncldglobal.com```

其他的按照流程来就行了

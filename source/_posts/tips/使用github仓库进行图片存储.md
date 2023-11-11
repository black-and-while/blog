---
title: 使用github和gitee仓库进行图片存储
date: '2022/1/22 20:29:01'
categories:
  - - tips
abbrlink: 3a6f7d20
description: 使用github和gitee仓库进行图片存储的markdown代码注意点
tags:
---

## 使用github和gitee仓库进行图片存储

![image](https://gitee.com/black_while/how_to_use_to_save_image/raw/master/1.jpg)
![image](https://gitee.com/black_while/how_to_use_to_save_image/raw/master/1.jpg)

```shell
![image](https://github.com/****/****/raw/main/1.jpg)

![image](https://github.com/****/****/blob/main/1.jpg)

![image](https://gitee.com/****/****/raw/master/1.jpg)

![image](https://gitee.com/****/****/blob/master/1.jpg)
```

使用github和gitee仓库存放图片，其中第一个和第三个都可以显示

**注意：**
点击图片的得到的链接之后
```shell
https://github.com/****/****/img_test/blob/main/1.jpg
```
需要把blob改成raw
```shell
https://github.com/****/****/raw/main/1.jpg
```


参考来自：
[https://blog.csdn.net/m0_49227651/article/details/108314030](https://blog.csdn.net/m0_49227651/article/details/108314030)
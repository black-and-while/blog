---
title: JS 原型链污染的学习
date: '2022/10/06 16:05:01'
categories:
  - - WEB安全
description: JavaScript 常被描述为一种基于原型的语言，而如果修改了一个对象的原型，那么将影响所有和这个对象来自同一类、父祖类的对象，这就是原型链污染
tags:
abbrlink:
---


# JS 原型链污染的学习

## JS 如何创建对象

- 直接定义

```js
var test = {name:'xxx','age','1'};
console.log(test);
```

- 使用构造函数方法

```js
function test(){
    this.name = "xxx";
    this.age = "1";
}
one = new test();
console.log(one);
```

- 通过 Object 创建

```js
var test = new Object();
test.a = 3;
console.log(test.a);
```

## prototype 和 proto 用法

### prototype 的使用

在 JavaScript 中，假如我们需要要定义一个类，需要以定义“构造函数”的方式来定义。
假如说存在一个 Student 函数，也就是类 Student 的构造函数，```this.name``` 是类 Student 的一个属性，```this.show``` 是一个方法，实例化了一个对象 stu1，如下

```js
function Student(){
    this.name = "123";
    this.show = function(){
        console.log(this.name)
    }
}
stu1 = new Student();
```

但是这样会存在一个问题，每当我们新建一个类 Student 的对象时，```this.show = function()``` 就会执行一次，这个 show 方法实际上是绑定在对象上的，而不是绑定在“类”中。

如果希望在创建类的时候只创建一次 show 方法，这时候就则需要使用原型 prototype 了。

```js
function Student() {
    this.name = "123";
}

Student.prototype.show = function show() {
    console.log(this.name)
}

stu1 = new Student();
stu1.show();
```

我们可以看成，原型 prototype 是类 Student 的一个属性，所有用类 Student 实例化的对象，都将拥有这个属性中的所有内容，包括变量和方法。比如上面的对象 stu1，自动具有 ```show()``` 方法。

### proto 的使用

在上面，我们通过 Student.prototype 来访问 Student 类的原型，但是用类 Student 实例化的对象，是不能通过 prototype 访问原型的。这时候，就需要用到 proto 。

在 Student 类实例化出来的对象 stu1 中，可以通过 stu1.proto 属性来访问 Student 类的原型，如下

```js
stu1.__proto__ == Student.prototype
```

### 用法小结

- prototype 是一个类的属性，所有类对象在实例化的时候将会拥有 prototype 中的属性和方法

- 一个对象的 proto 属性，指向这个对象所在的类的 prototype 属性

## JavaScript 的原型链继承机制

假如说存在类 Father 和类 Son

```js
function Father() {
    this.first_name = 'bbb'
    this.last_name = 'aaa'
}

function Son() {
    this.first_name = 'ccc'
}

Son.prototype = new Father()

let son = new Son()
console.log(`Name: ${son.first_name} ${son.last_name}`)
```

然后用 Son 类继承了 Father 类的 last_name 属性，最后输出的是 ```Name: ccc aaa```

因为对于对象 son 来说，在调用 son.last_name 的时候，实际上 JavaScript 引擎会进行如下操作：

- 首先在对象 son 中寻找 last_name
- 如果找不到，则在 son.proto 中寻找 last_name
- 如果仍然找不到，则继续在 son.proto.proto 中寻找 last_name
- 依次寻找，直到找到 null 结束。比如，Object.prototype 的 proto 就是 null

JavaScript 的这个查找的机制，被运用在面向对象的继承中，被称作 prototype 继承链。

## 原型链污染






---
title: RSA算法
date: '2022/1/23 23:15:01'
categories:
  - - 密码学
description: 关于RSA算法的加解密算法实现及其脚本
abbrlink: 855b12c4
tags:
---

# RSA算法

## 简介
RSA是1977年由罗纳德·李维斯特（Ron Rivest）、阿迪·萨莫尔（Adi Shamir）和伦纳德·阿德曼（Leonard Adleman）一起提出的。当时他们三人都在麻省理工学院工作。RSA就是他们三人姓氏开头字母拼在一起组成的。

RSA公开密钥密码体制是一种使用不同的加密密钥与解密密钥，“由已知加密密钥推导出解密密钥在计算上是不可行的”密码体制。

在公开密钥密码体制中，加密密钥（即公开密钥）PK是公开信息，而解密密钥（即秘密密钥）SK是需要保密的。加密算法E和解密算法D也都是公开的。虽然解密密钥SK是由公开密钥PK决定的，但却不能根据PK计算出SK。  


### 安全性
对于RSA加密算法，公钥(N, e)为公钥，可以任意公开，破解RSA最直接（亦或是暴力）的方法就是分解整数N，然后计算欧拉函数φ(n)=(p-1) * (q-1),再通过d * e ≡ 1 mod φ(N)，即可计算出 d，然后就可以使用私钥(N, d)通过m = pow(c,d,N)解密明文

## 算法实现

### RSA的加解密过程

（1）选择两个大的参数，计算出模数 N = p * q
（2）计算欧拉函数 φ = (p-1) * (q-1)，然后选择一个e (1 < e < φ) ，并且e和φ互质（互质：公约数只有1的两个整数）
（3）取e的模反数d，计算方法为:e * d ≡ 1 (mod φ) 
    （模反元素：如果两个正整数e和n互质，那么一定可以找到整数d，使得 e * d - 1 被n整除，或者说e * d被n除的余数是1。这时，d就叫做e的“模反元素”。欧拉定理可以用来证明模反元素必然存在。两个整数a,b，它们除以整数M所得的余数相等：a ≡ b(mod m);
    比如说5除3余数为2，11除3余数也为2，于是可写成11 ≡ 5(mod 3)。）
（4）对明文m进行加密：c = pow(m, e, N),可以得到密文c。
（5）对密文c进行解密：m = pow(c, d, N),可以得到明文m。

> p 和 q ：大整数N的两个因子
> N：大整数N，我们称之为模数
> e 和 d：互为模反数的两个指数
> c 和 m：分别是密文和明文
> (N, e)：公钥
> (N, d)：私钥
> pow(x, y, z)：效果等效pow(x, y)1 % z， 先计算x的y次方，如果存在另一个参数z，需要再对结果进行取模。

### 具体算法

#### 大素数生成算法

（1）定义了 Euclidean_algorithm()欧几里得算法，用于实现求最大公因数。

```python
def Euclidean_algorithm(a, b):  # 欧几里得算法，即辗转相除法，求最大公因数
    if a < b:  # 把较大的数放在a的位置上
        temp = a
        a = b
        b = temp
    flag = 1
    while flag != 0:
        flag = a % b
        a = b
        b = flag
        # print(a,b)
    return a
```

（2）定义了 Fermat_judge()，即费马素性检验算法，用于判断是否为伪素数。
```python
def Fermat_judge(judge_num, security_num):  # 判断是否为伪素数，Fermat素性检验，返回True或者False
    have_select_num = []  # 存放已经使用过的检验数
    b = 0
    flag = True  # 标记judge_num是否为素数，True时候为素数
    for step in range(0, security_num):  # 重复security_num次检验
        for i in range(2, judge_num - 1):  # 挑选一个检验数
            if (i not in have_select_num) and (Euclidean_algorithm(i, judge_num) == 1):
                b = i
                have_select_num.append(i)
                break

        r = fast_mod(b, judge_num - 1, judge_num)

        if r != 1:  # r不等于1时，则judge_num为合数
            flag = False
            break

    return flag
```
（3）定义了 Miller_Rabin_judge()，即Miller_Rabin 素性检验算法，用于判断是否为强伪素数。
```python
def Miller_Rabin_judge(judge_num, security_num):  # 判断是否为强伪素数，Miller_Rabin素性检验，返回True或者False
    have_select_num = []  # 存放已经使用过的检验数
    b = 0
    flag = True  # 标记judge_num是否为素数，True时候为素数
    for step in range(0, security_num):  # 重复security_num次检验
        for i in range(2, judge_num - 1):  # 挑选一个检验数
            if (i not in have_select_num) and (Euclidean_algorithm(i, judge_num) == 1):
                b = i
                have_select_num.append(i)
                break

        s = 1
        t = 1
        while True:
            if (judge_num - 1) % pow(2, s) == 0:
                t = (judge_num - 1) // pow(2, s)
                if t % 2 == 1:
                    break
            s += 1

        r0 = fast_mod(b, t, judge_num)

        for i in range(0, s):
            if i == s - 1 and r0 != judge_num - 1:
                flag = False
                return flag

            if r0 == 1 or r0 == judge_num - 1:
                break
            else:
                temp = (r0 * r0) % judge_num
                r0 = temp

    return flag
```

（4）使用 product_prime_num()函数，用于生成指定长度的大素数。先使用 product _num()函数生成一个数，对其使用 Fermat_judge()和 Miller_Rabin_judge()，进行伪素数和强伪素数的检验，从而确定它是不是一个素数

```python
def product_prime_num(num_len):  # 生成长度为num_len的一个素数
    prime_num = 1
    while True:
        prime_num = product_num(num_len)
        if Fermat_judge(prime_num, 1):
            if Miller_Rabin_judge(prime_num, 10):
                break
        else:
            continue

    return prime_num
```
#### 加密算法

生成两个大素数 p、q，然后计算 n=p*q，计算 p*q 的欧拉函数 phi，并选取与 phi 互素的公钥 e，计算私钥 d，再计算模 n 情况下明文 m 的 e 次幂，得到密文。

```python
def RSA_encode(plaintext):  # RSA加密函数
    while True:  # 生成两个不相等的大素数
        p = product_prime_num(512)
        q = product_prime_num(512)
        if p != q:
            break
        else:
            p = product_prime_num(512)
            q = product_prime_num(512)

    n = p * q
    phi = (p - 1) * (q - 1)  # 计算p*q的欧拉函数，结果是phi

    e = random.randint(2, phi - 1)
    while True:  # 选取e，满足和phi互素
        if Euclidean_algorithm(e, phi) == 1:
            break
        else:
            e = random.randint(2, phi - 1)

    d = reverse_element(e, phi)

    # 下面对密文进行加密
    str_num = ""
    for i in plaintext:  # 先把密文转16进制，再在10进制的情况下，进行运算
        str_num += f'{ord(i):02x}'
    cryptotest = fast_mod(int(str_num, 16), e, n)

    print(f'RSA加密：')
    print(f'p的值为：\n{p}')
    print(f'q的值为：\n{q}')
    print(f'n的值为：\n{n}')
    print(f'公钥e的值为：\n{e}')
    print(f'私钥d的值为：\n{d}')
    print(f'密文c的值为：\n{cryptotest}')
```

#### 解密算法

使用私钥 d，计算模 n 情况下密文 c 的 d 次幂，得到明文

```python
def RSA_decode(cryptotest, d, n):  # RSA解密函数
    plaintext = ""
    cryptotest = int(cryptotest, 10)  # 把cryptotest, d, n转成数字
    d = int(d, 10)
    n = int(n, 10)
    plaintext_num = fast_mod(cryptotest, d, n)
    plaintext_16_str = hex(plaintext_num)
    plaintext_16_str = plaintext_16_str[2:]  # 去掉前面的0x，避免报错
    for i in range(0, len(plaintext_16_str), 2):
        plaintext += chr(int(plaintext_16_str[i:i + 2], 16))

    print(f'RSA解密：')
    print(f'明文c的值为：\n{plaintext}')
```

### 完整脚本

```python
import random

def fast_mod(bottom_num, power_num, mod_num):  # 快速幂算法
    result = 1
    while power_num != 0:
        if power_num % 2 == 1:
            power_num -= 1
            result = (result * bottom_num) % mod_num
        if power_num == 0:
            break

        power_num = power_num // 2
        bottom_num = (bottom_num * bottom_num) % mod_num
    return result


def Euclidean_algorithm(a, b):  # 欧几里得算法，即辗转相除法，求最大公因数
    if a < b:  # 把较大的数放在a的位置上
        temp = a
        a = b
        b = temp
    flag = 1
    while flag != 0:
        flag = a % b
        a = b
        b = flag
    return a


def Fermat_judge(judge_num, security_num):  # 判断是否为伪素数，Fermat素性检验，返回True或者False
    have_select_num = []  # 存放已经使用过的检验数
    b = 0
    flag = True  # 标记judge_num是否为素数，True时候为素数
    for step in range(0, security_num):  # 重复security_num次检验
        for i in range(2, judge_num - 1):  # 挑选一个检验数
            if (i not in have_select_num) and (Euclidean_algorithm(i, judge_num) == 1):
                b = i
                have_select_num.append(i)
                break

        r = fast_mod(b, judge_num - 1, judge_num)

        if r != 1:  # r不等于1时，则judge_num为合数
            flag = False
            break

    return flag


def Miller_Rabin_judge(judge_num, security_num):  # 判断是否为强伪素数，Miller_Rabin素性检验，返回True或者False
    have_select_num = []  # 存放已经使用过的检验数
    b = 0
    flag = True  # 标记judge_num是否为素数，True时候为素数
    for step in range(0, security_num):  # 重复security_num次检验
        for i in range(2, judge_num - 1):  # 挑选一个检验数
            if (i not in have_select_num) and (Euclidean_algorithm(i, judge_num) == 1):
                b = i
                have_select_num.append(i)
                break

        s = 1
        t = 1
        while True:
            if (judge_num - 1) % pow(2, s) == 0:
                t = (judge_num - 1) // pow(2, s)
                if t % 2 == 1:
                    break
            s += 1

        r0 = fast_mod(b, t, judge_num)

        for i in range(0, s):
            if i == s - 1 and r0 != judge_num - 1:
                flag = False
                return flag

            if r0 == 1 or r0 == judge_num - 1:
                break
            else:
                temp = (r0 * r0) % judge_num
                r0 = temp

    return flag


def product_num(num_len):  # 生成长度为num_len的一个随机数
    result = "1"
    while True:
        if len(result) != num_len:  # 长度不够时候继续添加长度
            result += random.choice(['0', '1'])
        else:
            if int(result, 2) % 2 != 1:  # 如果生成的数不是奇数，就再生成一个
                result = "1"
            else:
                break
    return int(result, 2)


def product_prime_num(num_len):  # 生成长度为num_len的一个素数
    prime_num = 1
    while True:
        prime_num = product_num(num_len)
        if Fermat_judge(prime_num, 1):
            if Miller_Rabin_judge(prime_num, 10):
                break
        else:
            continue

    return prime_num


def reverse_element(a, b):  # 利用sa+tb=1，即利用欧几里得算法的逆过程，求逆元，这里返回的是s，相当于是求a在模b情况下的逆元
    s0 = 1
    s1 = 0
    t0 = 0
    t1 = 1
    r1 = max(a, b)
    r0 = min(a, b)
    q1 = r1 // r0

    s2 = 0
    t2 = 0
    q0 = 0
    while True:
        s2 = s0 - q1 * s1
        t2 = t0 - q1 * t1
        temp = r1 % r0
        r1 = max(r0, temp)
        r0 = min(r0, temp)

        if r0 == 0:
            # print(f' {s1} * {a} + {t1} * {b} ')
            if t1 > 0:
                return t1
            else:
                return t1 + max(a,b)


        q1 = r1 // r0

        s0 = s1
        t0 = t1
        s1 = s2
        t1 = t2


def RSA_encode(plaintext):  # RSA加密函数
    while True:  # 生成两个不相等的大素数
        p = product_prime_num(512)
        q = product_prime_num(512)
        if p != q:
            break
        else:
            p = product_prime_num(512)
            q = product_prime_num(512)

    n = p * q
    phi = (p - 1) * (q - 1)  # 计算p*q的欧拉函数，结果是phi

    e = random.randint(2, phi - 1)
    while True:  # 选取e，满足和phi互素
        if Euclidean_algorithm(e, phi) == 1:
            break
        else:
            e = random.randint(2, phi - 1)

    d = reverse_element(e, phi)

    # 下面对密文进行加密
    str_num = ""
    for i in plaintext:  # 先把密文转16进制，再在10进制的情况下，进行运算
        str_num += f'{ord(i):02x}'
    cryptotest = fast_mod(int(str_num, 16), e, n)

    print(f'RSA加密：')
    print(f'p的值为：\n{p}')
    print(f'q的值为：\n{q}')
    print(f'n的值为：\n{n}')
    print(f'公钥e的值为：\n{e}')
    print(f'私钥d的值为：\n{d}')
    print(f'密文c的值为：\n{cryptotest}')


def RSA_decode(cryptotest, d, n):  # RSA解密函数
    plaintext = ""
    cryptotest = int(cryptotest, 10)  # 把cryptotest, d, n转成数字
    d = int(d, 10)
    n = int(n, 10)
    plaintext_num = fast_mod(cryptotest, d, n)
    plaintext_16_str = hex(plaintext_num)
    plaintext_16_str = plaintext_16_str[2:]  # 去掉前面的0x，避免报错
    for i in range(0, len(plaintext_16_str), 2):
        plaintext += chr(int(plaintext_16_str[i:i + 2], 16))

    print(f'RSA解密：')
    print(f'明文c的值为：\n{plaintext}')


if __name__ == "__main__":
    input_num = ''
    input_num = input("请选择方式：输入1为加密 输入2为解密\n")
    if input_num == "1":
        plaintext = input("请输入需要RSA加密的字符串\n")
        RSA_encode(plaintext)
    elif input_num == "2":
        cryptotest = input("请输入需要RSA解密的字符串\n")
        d = input("请输入私钥d\n")
        n = input("请输入n\n")
        RSA_decode(cryptotest, d, n)
```

## gmpy2用法 
```python
import gmpy2
gmpy2.mpz(n)#初始化一个大整数
gmpy2.mpfr(x)# 初始化一个高精度浮点数x
d = gmpy2.invert(e,n) # 求逆元，de = 1 mod n
C = gmpy2.powmod(M,e,n)# 幂取模，结果是 C = (M^e) mod n
gmpy2.is_prime(n) #素性检测
gmpy2.gcd(a,b)  #欧几里得算法，最大公约数
gmpy2.gcdext(a,b)  #扩展欧几里得算法
gmpy2.iroot(x,n) #x开n次根

```

上面gmpy2用法相关内容来自[https://blog.csdn.net/qq_42250840/article/details/105153227](https://blog.csdn.net/qq_42250840/article/details/105153227)
---
title: MD5算法
date: '2022/1/23 23:15:01'
categories:
  - - 密码学
description: 关于MD5算法的算法实现及其脚本
abbrlink: 987b536e
tags:
---

# MD5算法

## 简介
MD5信息摘要算法（英语：MD5 Message-Digest Algorithm），一种被广泛使用的密码散列函数，可以产生出一个128位（16字节）的散列值（hash value），用于确保信息传输完整一致。MD5由美国密码学家罗纳德·李维斯特（Ronald Linn Rivest）设计，于1992年公开，用以取代MD4算法。这套算法的程序在 RFC 1321 标准中被加以规范。1996年后该算法被证实存在弱点，可以被加以破解，对于需要高度安全性的数据，专家一般建议改用其他算法，如SHA-2。2004年，证实MD5算法无法防止碰撞（collision），因此不适用于安全性认证，如SSL公开密钥认证或是数字签名等用途。

## 算法实现

（1）定义了 F、G、H、I 四个函数用于运算
```python
def F(X, Y, Z):
    return (X & Y) | (~X & Z)


def G(X, Y, Z):
    return (X & Z) | (Y & ~Z)


def H(X, Y, Z):
    return (X ^ Y ^ Z)


def I(X, Y, Z):
    return Y ^ (X | ~Z)
```

（2）定义了 FF、GG、HH、II 这 4 个步函数用来进行对 512 比特分组的 4 轮*16 步骤， 共 64 次加密

```python
def FF(a, b, c, d, M, s, T, i, j):
    a = ((a + (F(b, c, d) + int(M[j], 2) + T[i]))) % pow(2, 32)
    temp = f'{a:032b}'
    result_a = temp[s:] + temp[0:s]
    result_a = (int(result_a, 2) + b) % pow(2, 32)
    (a, b, c, d) = (d, result_a, b, c)
    return (a, b, c, d)


def GG(a, b, c, d, M, s, T, i, j): # % pow(2, 32)用来限定在32位范围上
    a = ((a + (G(b, c, d) + int(M[j], 2) + T[i]))) % pow(2, 32)
    temp = f'{a:032b}'
    result_a = temp[s:] + temp[0:s]
    result_a = (int(result_a, 2) + b) % pow(2, 32)
    (a, b, c, d) = (d, result_a, b, c)
    return (a, b, c, d)


def HH(a, b, c, d, M, s, T, i, j):
    a = ((a + (H(b, c, d) + int(M[j], 2) + T[i]))) % pow(2, 32)
    temp = f'{a:032b}'
    result_a = temp[s:] + temp[0:s]
    result_a = (int(result_a, 2) + b) % pow(2, 32)
    (a, b, c, d) = (d, result_a, b, c)
    return (a, b, c, d)


def II(a, b, c, d, M, s, T, i, j):
    a = ((a + (I(b, c, d) + int(M[j], 2) + T[i]))) % pow(2, 32)
    temp = f'{a:032b}'
    result_a = temp[s:] + temp[0:s]
    result_a = (int(result_a, 2) + b) % pow(2, 32)
    (a, b, c, d) = (d, result_a, b, c)
    return (a, b, c, d)
```

（3）定义了 md5_encode()加密实现算法，对明文进行填充，然后进行分组，再进行 4 *16 轮，共 64 轮的加密，得到结果。

```python
def md5_encode(str):  # 加密实现算法

    # ABCD初始值
    A = 0x01234567
    B = 0x89ABCDEF
    C = 0xFEDCBA98
    D = 0x76543210

    # 把ABCD变成小端序
    A = int(hex(change_to_little_endian(A)), 16)
    B = int(hex(change_to_little_endian(B)), 16)
    C = int(hex(change_to_little_endian(C)), 16)
    D = int(hex(change_to_little_endian(D)), 16)

    # 保存ABCD初始值
    temp_A = A
    temp_B = B
    temp_C = C
    temp_D = D

    # 先把输入的字符串转成比特数据
    bite_str = str_to_bite(str)

    # 把比特数据分成512bite长的分组
    arr_512 = divide_to_512_bite(bite_str)

    result_A = 0
    result_B = 0
    result_C = 0
    result_D = 0

    # 循环每一个512bite，进行加密
    for message in arr_512:
        # 把512bite长的消息分成16组
        arr_16_group = divide_to_16_group(message)
        # print(arr_16_group)
        arr_temp = []
        for i in arr_16_group:
            arr_temp.append(int(i, 2))

        # 对每一组进行4轮加密
        # 第一轮
        for i in range(16):
            (A, B, C, D) = FF(A, B, C, D, arr_16_group, s1[i], T, i, M1[i])
        # 第二轮
        for i in range(16):
            (A, B, C, D) = GG(A, B, C, D, arr_16_group, s2[i], T, i + 16, M2[i])
        # 第三轮
        for i in range(16):
            (A, B, C, D) = HH(A, B, C, D, arr_16_group, s3[i], T, i + 32, M3[i])
        # 第四轮
        for i in range(16):
            (A, B, C, D) = II(A, B, C, D, arr_16_group, s4[i], T, i + 48, M4[i])
            # print(hex(A), hex(B), hex(C), hex(D))

        # 与初始值进行异或运算
        result_A = (temp_A + A) % pow(2, 32)
        result_B = (temp_B + B) % pow(2, 32)
        result_C = (temp_C + C) % pow(2, 32)
        result_D = (temp_D + D) % pow(2, 32)

    # 再把ABCD转换成小端序，然后拼接起来
    result_A = change_to_little_endian(result_A)
    result_B = change_to_little_endian(result_B)
    result_C = change_to_little_endian(result_C)
    result_D = change_to_little_endian(result_D)

    result_str = f'{result_A:08x}' + f'{result_B:08x}' + f'{result_C:08x}' + f'{result_D:08x}'
    return result_str
```

## 完整脚本
```python
def str_to_bite(str):  # 16进制变成2进制字符串
    resutl = ""
    for i in str:  # 把每一个字符变成8位的2进制表示
        temp = f'{ord(i):08b}'
        resutl += temp

    if len(resutl) % 512 == 448:  # 先加1再加0，直到模521与448同余，并加上64比特原消息长度
        resutl += f'{len(resutl):064b}'
    else:
        resutl += '1'
        while (len(resutl) % 512 != 448):
            resutl += '0'
        resutl += f'{(8 * len(str)):064b}'
    resutl_little = ""  # 转换成小端序，以32位为一组，8位、8位的交换
    for i in range((len(resutl) // 32) - 2):
        resutl_little += resutl[(24 + i * 32):(32 + i * 32)] + \
                         resutl[(16 + i * 32):(24 + i * 32)] + \
                         resutl[(8 + i * 32):(16 + i * 32)] + \
                         resutl[(0 + i * 32):(8 + i * 32)]
    resutl_little += resutl[-32:]
    resutl_little += resutl[-64:-32]
    return resutl_little


T = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
     0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
     0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8,
     0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
     0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
     0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
     0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
     0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]

s1 = [7, 12, 17, 22,
      7, 12, 17, 22,
      7, 12, 17, 22,
      7, 12, 17, 22]
s2 = [5, 9, 14, 20,
      5, 9, 14, 20,
      5, 9, 14, 20,
      5, 9, 14, 20]
s3 = [4, 11, 16, 23,
      4, 11, 16, 23,
      4, 11, 16, 23,
      4, 11, 16, 23]
s4 = [6, 10, 15, 21,
      6, 10, 15, 21,
      6, 10, 15, 21,
      6, 10, 15, 21]

M1 = [0, 1, 2, 3,
      4, 5, 6, 7,
      8, 9, 10, 11,
      12, 13, 14, 15]
M2 = [1, 6, 11, 0,
      5, 10, 15, 4,
      9, 14, 3, 8,
      13, 2, 7, 12]
M3 = [5, 8, 11, 14,
      1, 4, 7, 10,
      13, 0, 3, 6,
      9, 12, 15, 2]
M4 = [0, 7, 14, 5,
      12, 3, 10, 1,
      8, 15, 6, 13,
      4, 11, 2, 9]


def F(X, Y, Z):
    return (X & Y) | (~X & Z)


def G(X, Y, Z):
    return (X & Z) | (Y & ~Z)


def H(X, Y, Z):
    return (X ^ Y ^ Z)


def I(X, Y, Z):
    return Y ^ (X | ~Z)


# 下面是4个步函数，用来进行对512比特分组的4轮*16步骤，共64次加密

def FF(a, b, c, d, M, s, T, i, j):
    a = ((a + (F(b, c, d) + int(M[j], 2) + T[i]))) % pow(2, 32)
    temp = f'{a:032b}'
    result_a = temp[s:] + temp[0:s]
    result_a = (int(result_a, 2) + b) % pow(2, 32)
    (a, b, c, d) = (d, result_a, b, c)
    return (a, b, c, d)


def GG(a, b, c, d, M, s, T, i, j): # % pow(2, 32)用来限定在32位范围上
    a = ((a + (G(b, c, d) + int(M[j], 2) + T[i]))) % pow(2, 32)
    temp = f'{a:032b}'
    result_a = temp[s:] + temp[0:s]
    result_a = (int(result_a, 2) + b) % pow(2, 32)
    (a, b, c, d) = (d, result_a, b, c)
    return (a, b, c, d)


def HH(a, b, c, d, M, s, T, i, j):
    a = ((a + (H(b, c, d) + int(M[j], 2) + T[i]))) % pow(2, 32)
    temp = f'{a:032b}'
    result_a = temp[s:] + temp[0:s]
    result_a = (int(result_a, 2) + b) % pow(2, 32)
    (a, b, c, d) = (d, result_a, b, c)
    return (a, b, c, d)


def II(a, b, c, d, M, s, T, i, j):
    a = ((a + (I(b, c, d) + int(M[j], 2) + T[i]))) % pow(2, 32)
    temp = f'{a:032b}'
    result_a = temp[s:] + temp[0:s]
    result_a = (int(result_a, 2) + b) % pow(2, 32)
    (a, b, c, d) = (d, result_a, b, c)
    return (a, b, c, d)


def divide_to_512_bite(str):  # 将比特消息划分为512bite一组，并返回
    result = []
    divide_num = len(str) // 512  # 分组数量
    for i in range(divide_num):
        result.append(str[(i * 512):((i + 1) * 512)])

    return result


def divide_to_16_group(str):  # 将512bite消息划分为16组，并返回2进制字符串
    result = []
    len_num = 512 // 16  # 每组长度
    for i in range(16):
        result.append(str[i * len_num:(i + 1) * len_num])
    return result


def change_to_little_endian(num):  # 把输入的16进制数字转成小端序，返回16进制数字
    str = f'{num:08x}'
    temp = str[6:8] + str[4:6] + str[2:4] + str[0:2]
    result = int(temp, 16)
    return result


def md5_encode(str):  # 加密实现算法

    # ABCD初始值
    A = 0x01234567
    B = 0x89ABCDEF
    C = 0xFEDCBA98
    D = 0x76543210

    # 把ABCD变成小端序
    A = int(hex(change_to_little_endian(A)), 16)
    B = int(hex(change_to_little_endian(B)), 16)
    C = int(hex(change_to_little_endian(C)), 16)
    D = int(hex(change_to_little_endian(D)), 16)

    # 保存ABCD初始值
    temp_A = A
    temp_B = B
    temp_C = C
    temp_D = D

    # 先把输入的字符串转成比特数据
    bite_str = str_to_bite(str)

    # 把比特数据分成512bite长的分组
    arr_512 = divide_to_512_bite(bite_str)

    result_A = 0
    result_B = 0
    result_C = 0
    result_D = 0

    # 循环每一个512bite，进行加密
    for message in arr_512:
        # 把512bite长的消息分成16组
        arr_16_group = divide_to_16_group(message)
        arr_temp = []
        for i in arr_16_group:
            arr_temp.append(int(i, 2))

        # 对每一组进行4轮加密
        # 第一轮
        for i in range(16):
            (A, B, C, D) = FF(A, B, C, D, arr_16_group, s1[i], T, i, M1[i])
        # 第二轮
        for i in range(16):
            (A, B, C, D) = GG(A, B, C, D, arr_16_group, s2[i], T, i + 16, M2[i])
        # 第三轮
        for i in range(16):
            (A, B, C, D) = HH(A, B, C, D, arr_16_group, s3[i], T, i + 32, M3[i])
        # 第四轮
        for i in range(16):
            (A, B, C, D) = II(A, B, C, D, arr_16_group, s4[i], T, i + 48, M4[i])

        # 与初始值进行异或运算
        result_A = (temp_A + A) % pow(2, 32)
        result_B = (temp_B + B) % pow(2, 32)
        result_C = (temp_C + C) % pow(2, 32)
        result_D = (temp_D + D) % pow(2, 32)

    # 再把ABCD转换成小端序，然后拼接起来
    result_A = change_to_little_endian(result_A)
    result_B = change_to_little_endian(result_B)
    result_C = change_to_little_endian(result_C)
    result_D = change_to_little_endian(result_D)

    result_str = f'{result_A:08x}' + f'{result_B:08x}' + f'{result_C:08x}' + f'{result_D:08x}'
    return result_str

if __name__ == "__main__":
    plaintext = input("请输入需要md5变换的字符串\n")
    print(plaintext)
    print(f'经过md5变换的字符串：{md5_encode(plaintext)}')
```


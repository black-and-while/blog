---
title: DES算法
date: '2022/1/23 23:15:01'
categories:
  - - 密码学
description: 关于DES算法的加解密算法实现及其脚本
abbrlink: 10149c74
tags:
---

# DES算法

## 简介

DES算法为密码体制中的对称密码体制，又被称为美国数据加密标准，是1972年美国IBM公司研制的对称密码体制加密算法。 明文按64位进行分组，密钥长64位，密钥事实上是56位参与DES运算（第8、16、24、32、40、48、56、64位是校验位， 使得每个密钥都有奇数个1）分组后的明文组和56位的密钥按位替代或交换的方法形成密文组的加密方法。

## 密钥生成算法
对输入的 64 位密钥进行 PC-1 置换，然后分成 C、D 两部分，每一轮中进行循环左移，然后进行 PC-2 置换，生成子密钥

```python
def product_key(str):
    str_bite = ""
    for i in str:  # 把每一个字符变成8位的2进制表示
        str_bite += f'{ord(i):08b}'

    str_bite = 't' + str_bite
    # PC-1置换
    PC1_translate_str = ""
    for i in range(1, 57):
        PC1_translate_str += str_bite[PC1[i]]

    PC1_C = []
    PC1_D = []
    PC1_C.append(PC1_translate_str[0:28])
    PC1_D.append(PC1_translate_str[28:])

    # 生成16组C和D
    for step in range(0, 16):
        left_move_num = left_move_arr[step]
        result_C = PC1_C[step][left_move_num:] + PC1_C[step][0:left_move_num]
        result_D = PC1_D[step][left_move_num:] + PC1_D[step][0:left_move_num]
        PC1_C.append(result_C)
        PC1_D.append(result_D)

    C_add_D = []
    for step in range(1, 17):  # 对新生成的C和D，进行组合
        C_add_D.append(PC1_C[step] + PC1_D[step])

    result = []
    # PC-2置换
    for step in range(0, 16):  # 对新生成的C和D，进行PC2置换
        C_add_D[step] = 't' + C_add_D[step]
        temp_result = ""
        for i in range(1, 49):
            temp_result += C_add_D[step][PC2[i]]
        result.append(temp_result)

    return result
```

## 加密算法实现

（1）定义了 F()函数，用于实现每一轮的 F()函数运算。具体实现为，先进行 E 盒扩展置换，再与密钥进行异或运算，然后用 S 盒进行代换，再使用 P 盒进行置换运算。
```python
def F(str, key):  # 返回的字符中，开头没有t占位
    str = 't' + str
    # E扩展置换
    E_translate_str = ""
    for i in range(1, 49):
        E_translate_str += str[E[i]]

    # 密钥加
    if (len(E_translate_str) != 48 or len(key) != 48):  # 先检测str和key是否都是48位
        print("str和key须有都是48位")
        assert False

    # 按位异或
    temp = int(E_translate_str, 2) ^ int(key, 2)
    key_add_str = f'{temp:048b}'

    # S盒压缩变换
    divide_to_6_arr = divide_to_6_bite(key_add_str)  # 先分成6位一组

    S_translate_str = ""
    for step in range(len(divide_to_6_arr)):  # 每一组都需要查表转换
        divide_to_6_arr_contain = divide_to_6_arr[step]  # 取每一组的内容
        temp_i = divide_to_6_arr_contain[0] + divide_to_6_arr_contain[5]
        temp_j = divide_to_6_arr_contain[1:5]
        i = int(temp_i, 2)
        j = int(temp_j, 2)
        S_translate_str += f'{S[step][i][j]:04b}'  # 查S表得到第i行第j列的数字，并转换成2进制

    S_translate_str = 't' + S_translate_str
    # P盒置换
    P_translate_str = ""
    for i in range(1, 33):
        P_translate_str += S_translate_str[P[i]]

    return P_translate_str
```

（2）使用DES_encrypto()函数，用于实现 DES 加密的整个流程。具体实现为，先 对明文进行补全和分组，对于每一组，先进行 IP 置换，然后分成 L 和 R 各 32 位，进行 16 轮的运算，在每一轮的最后进行 IP 逆置换，最终把各个分组连接起 来构成密文。 

> 如果使用了 CBC 模式，则需要在加密前把明文分组和上一组密文分组进行异或运算。

下面的是 ECB 模式下的情况
```python
def DES_encrypto(str, key):
    # 将输入明文按64位分组
    str_bite = ""
    for i in str:  # 把每一个字符变成8位的2进制表示
        str_bite += f'{ord(i):08b}'

    while (len(str_bite) % 64 != 0):  # 不足64位的倍数时补0
        str_bite += '0'

    divide_arr = divide_to_64_bite(str_bite)

    # 将输入的密钥生成16组子密钥
    if len(key) != 8:
        print("密钥长度需要为8")
        assert False

    key_arr = product_key(key)

    # 对每一组都进行加密
    encrypto_str = ""
    for divide_arr_contain in divide_arr:
        # 用t占位，方便后面下标的处理
        divide_arr_contain = 't' + divide_arr_contain

        # IP置换
        IP_translate_str = "t"
        for i in range(1, 65):
            IP_translate_str += divide_arr_contain[IP[i]]

        L = []
        R = []
        L.append(IP_translate_str[1:33])
        R.append(IP_translate_str[33:65])

        for step in range(0, 15):
            L.append(R[step])
            temp_str1 = L[step]
            temp_str2 = F(R[step], key_arr[step])
            temp_str_num = int(temp_str1, 2) ^ int(temp_str2, 2)
            temp_str = f'{temp_str_num:032b}'
            R.append(temp_str)

        temp_str1 = L[15]
        temp_str2 = F(R[15], key_arr[15])
        temp_str_num = int(temp_str1, 2) ^ int(temp_str2, 2)
        temp_str = f'{temp_str_num:032b}'
        L.append(temp_str)
        R.append(R[15])

        # IP逆置换
        L_add_R = 't' + L[16] + R[16]
        IP_reverse_translate_str = ""
        for i in range(1, 65):
            IP_reverse_translate_str += L_add_R[IP_[i]]

        encrypto_str += IP_reverse_translate_str

    result_str = ""
    for i in range(0, len(encrypto_str), 8):
        result_str += chr(int(encrypto_str[i:i + 8], 2))

    return result_str
```

## 解密算法实现

先对密文进行分组，对于每一组，先进行 IP 置换，然后分成 L 和 R 各 32 位， 进行 16 轮的运算，在每一轮的最后进行 IP 逆置换，最终把各个分组连接起来构 成明文。

> 如果使用了 CBC 模式，则需要在解密后把结果和上一组密文分组进行异或运算。

下面的是 ECB 模式下的情况
```python
def DES_decrypto(str, key):
    # 将输入明文按64位分组
    str_bite = ""
    for i in str:  # 把每一个字符变成8位的2进制表示
        str_bite += f'{ord(i):08b}'

    if len(str_bite) % 64 != 0:
        print("密文输入有错")
        assert False

    divide_arr = divide_to_64_bite(str_bite)

    # 将输入的密钥生成16组子密钥
    if len(key) != 8:
        print("密钥长度需要为8")
        assert False

    key_arr = product_key(key)

    # 对每一组都进行解密
    decrypto_str = ""
    for divide_arr_contain in divide_arr:
        # 用t占位，方便后面下标的处理
        divide_arr_contain = 't' + divide_arr_contain

        # IP置换
        IP_translate_str = "t"
        for i in range(1, 65):
            IP_translate_str += divide_arr_contain[IP[i]]

        L = []
        R = []
        L.append(IP_translate_str[1:33])
        R.append(IP_translate_str[33:65])

        for step in range(0, 15):
            temp_str1 = L[step]
            temp_str2 = F(R[step], key_arr[15 - step])
            temp_str_num = int(temp_str1, 2) ^ int(temp_str2, 2)
            temp_str = f'{temp_str_num:032b}'
            R.append(temp_str)
            L.append(R[step])

        temp_str1 = L[15]
        temp_str2 = F(R[15], key_arr[0])
        temp_str_num = int(temp_str1, 2) ^ int(temp_str2, 2)
        temp_str = f'{temp_str_num:032b}'
        L.append(temp_str)
        R.append(R[15])

        # IP逆置换
        L_add_R = 't' + L[16] + R[16]
        IP_reverse_translate_str = ""
        for i in range(1, 65):
            IP_reverse_translate_str += L_add_R[IP_[i]]

        decrypto_str += IP_reverse_translate_str

    result_str = ""
    for i in range(0, len(decrypto_str), 8):
        if int(decrypto_str[i:i + 8], 2) == 0:
            continue
        result_str += chr(int(decrypto_str[i:i + 8], 2))

    return result_str
```

## 完整脚本

### ECB模式

```python
import base64

PC1 = [0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
left_move_arr = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
PC2 = [0, 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47,
       55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
IP = [0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40,
      32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55,
      47, 39, 31, 23, 15, 7]
IP_ = [0, 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13,
       53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33,
       1, 41, 9, 49, 17, 57, 25]
E = [0, 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20,
     21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
S = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
      [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
      [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
      [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
     [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
      [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
      [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
      [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
     [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
      [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
      [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
      [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
     [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
      [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 19],
      [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
      [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
     [[2, 12, 4, 1, 7, 10, 11, 6, 5, 8, 3, 15, 13, 0, 14, 9],
      [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 13, 3, 9, 8, 6],
      [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
      [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
     [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
      [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
      [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
      [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
     [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
      [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
      [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
      [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
     [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
      [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
      [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
      [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
P = [0, 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11,
     4, 25]


def divide_to_64_bite(str):  # 将比特消息划分为64bite一组，并返回
    result = []
    divide_num = len(str) // 64  # 分组数量
    for i in range(divide_num):
        result.append(str[(i * 64):((i + 1) * 64)])

    return result


def divide_to_6_bite(str):  # 将比特消息划分为6bite一组，并返回
    result = []
    divide_num = len(str) // 6  # 分组数量
    for i in range(divide_num):
        result.append(str[(i * 6):((i + 1) * 6)])

    return result


def F(str, key):  # 返回的字符中，开头没有t占位
    str = 't' + str
    # E扩展置换
    E_translate_str = ""
    for i in range(1, 49):
        E_translate_str += str[E[i]]

    # 密钥加
    if (len(E_translate_str) != 48 or len(key) != 48):  # 先检测str和key是否都是48位
        print("str和key须有都是48位")
        assert False

    # 按位异或
    temp = int(E_translate_str, 2) ^ int(key, 2)
    key_add_str = f'{temp:048b}'

    # S盒压缩变换
    divide_to_6_arr = divide_to_6_bite(key_add_str)  # 先分成6位一组

    S_translate_str = ""
    for step in range(len(divide_to_6_arr)):  # 每一组都需要查表转换
        divide_to_6_arr_contain = divide_to_6_arr[step]  # 取每一组的内容
        temp_i = divide_to_6_arr_contain[0] + divide_to_6_arr_contain[5]
        temp_j = divide_to_6_arr_contain[1:5]
        i = int(temp_i, 2)
        j = int(temp_j, 2)
        S_translate_str += f'{S[step][i][j]:04b}'  # 查S表得到第i行第j列的数字，并转换成2进制

    S_translate_str = 't' + S_translate_str
    # P盒置换
    P_translate_str = ""
    for i in range(1, 33):
        P_translate_str += S_translate_str[P[i]]

    return P_translate_str


def product_key(str):
    str_bite = ""
    for i in str:  # 把每一个字符变成8位的2进制表示
        str_bite += f'{ord(i):08b}'

    str_bite = 't' + str_bite
    # PC-1置换
    PC1_translate_str = ""
    for i in range(1, 57):
        PC1_translate_str += str_bite[PC1[i]]

    PC1_C = []
    PC1_D = []
    PC1_C.append(PC1_translate_str[0:28])
    PC1_D.append(PC1_translate_str[28:])

    # 生成16组C和D
    for step in range(0, 16):
        left_move_num = left_move_arr[step]
        result_C = PC1_C[step][left_move_num:] + PC1_C[step][0:left_move_num]
        result_D = PC1_D[step][left_move_num:] + PC1_D[step][0:left_move_num]
        PC1_C.append(result_C)
        PC1_D.append(result_D)

    C_add_D = []
    for step in range(1, 17):  # 对新生成的C和D，进行组合
        C_add_D.append(PC1_C[step] + PC1_D[step])

    result = []
    # PC-2置换
    for step in range(0, 16):  # 对新生成的C和D，进行PC2置换
        C_add_D[step] = 't' + C_add_D[step]
        temp_result = ""
        for i in range(1, 49):
            temp_result += C_add_D[step][PC2[i]]
        result.append(temp_result)

    return result


def DES_encrypto(str, key):
    # 将输入明文按64位分组
    str_bite = ""
    for i in str:  # 把每一个字符变成8位的2进制表示
        str_bite += f'{ord(i):08b}'

    while (len(str_bite) % 64 != 0):  # 不足64位的倍数时补0
        str_bite += '0'

    divide_arr = divide_to_64_bite(str_bite)

    # 将输入的密钥生成16组子密钥
    if len(key) != 8:
        print("密钥长度需要为8")
        assert False

    key_arr = product_key(key)

    # 对每一组都进行加密
    encrypto_str = ""
    for divide_arr_contain in divide_arr:
        # 用t占位，方便后面下标的处理
        divide_arr_contain = 't' + divide_arr_contain

        # IP置换
        IP_translate_str = "t"
        for i in range(1, 65):
            IP_translate_str += divide_arr_contain[IP[i]]

        L = []
        R = []
        L.append(IP_translate_str[1:33])
        R.append(IP_translate_str[33:65])

        for step in range(0, 15):
            L.append(R[step])
            temp_str1 = L[step]
            temp_str2 = F(R[step], key_arr[step])
            temp_str_num = int(temp_str1, 2) ^ int(temp_str2, 2)
            temp_str = f'{temp_str_num:032b}'
            R.append(temp_str)

        temp_str1 = L[15]
        temp_str2 = F(R[15], key_arr[15])
        temp_str_num = int(temp_str1, 2) ^ int(temp_str2, 2)
        temp_str = f'{temp_str_num:032b}'
        L.append(temp_str)
        R.append(R[15])

        # IP逆置换
        L_add_R = 't' + L[16] + R[16]
        IP_reverse_translate_str = ""
        for i in range(1, 65):
            IP_reverse_translate_str += L_add_R[IP_[i]]

        encrypto_str += IP_reverse_translate_str

    result_str = ""
    for i in range(0, len(encrypto_str), 8):
        result_str += chr(int(encrypto_str[i:i + 8], 2))

    return result_str


def DES_decrypto(str, key):
    # 将输入明文按64位分组
    str_bite = ""
    for i in str:  # 把每一个字符变成8位的2进制表示
        str_bite += f'{ord(i):08b}'

    if len(str_bite) % 64 != 0:
        print("密文输入有错")
        assert False

    divide_arr = divide_to_64_bite(str_bite)

    # 将输入的密钥生成16组子密钥
    if len(key) != 8:
        print("密钥长度需要为8")
        assert False

    key_arr = product_key(key)

    # 对每一组都进行解密
    decrypto_str = ""
    for divide_arr_contain in divide_arr:
        # 用t占位，方便后面下标的处理
        divide_arr_contain = 't' + divide_arr_contain

        # IP置换
        IP_translate_str = "t"
        for i in range(1, 65):
            IP_translate_str += divide_arr_contain[IP[i]]

        L = []
        R = []
        L.append(IP_translate_str[1:33])
        R.append(IP_translate_str[33:65])

        for step in range(0, 15):
            temp_str1 = L[step]
            temp_str2 = F(R[step], key_arr[15 - step])
            temp_str_num = int(temp_str1, 2) ^ int(temp_str2, 2)
            temp_str = f'{temp_str_num:032b}'
            R.append(temp_str)
            L.append(R[step])

        temp_str1 = L[15]
        temp_str2 = F(R[15], key_arr[0])
        temp_str_num = int(temp_str1, 2) ^ int(temp_str2, 2)
        temp_str = f'{temp_str_num:032b}'
        L.append(temp_str)
        R.append(R[15])

        # IP逆置换
        L_add_R = 't' + L[16] + R[16]
        IP_reverse_translate_str = ""
        for i in range(1, 65):
            IP_reverse_translate_str += L_add_R[IP_[i]]

        decrypto_str += IP_reverse_translate_str

    result_str = ""
    for i in range(0, len(decrypto_str), 8):
        if int(decrypto_str[i:i + 8], 2) == 0:
            continue
        result_str += chr(int(decrypto_str[i:i + 8], 2))

    return result_str


if __name__ == "__main__":
    input_num = ''
    input_num = input("请选择方式：输入1为加密 输入2为解密\n")
    if input_num == "1":
        plaintext = input("请输入需要DES加密的字符串\n")
        key = input("请输入DES加密需要的8字节密钥\n")
        result = DES_encrypto(plaintext, key)
        str_16 = ""
        for i in result:  # 把每一个字符变成8位的2进制表示
            str_16 += f'{ord(i):02x}'
        print(f"加密后密文用16进制表示为：{str_16}")
        print(f"加密后密文用base64表示为：{base64.b64encode(result.encode()).decode()}")
    elif input_num == "2":
        cryptotest_num = input("请输入需要DES解密的字符串的类型 1为base64输入 2为16进制输入\n")
        str_1 = input("请输入需要DES解密的字符串\n")
        if cryptotest_num == "1":
            cryptotest = base64.b64decode(str_1.encode()).decode()
        elif cryptotest_num == "2":
            cryptotest = ""
            for i in range(0, len(str_1), 2):
                cryptotest += chr(int(str_1[i:i + 2], 16))
        key = input("请输入DES解密需要的8字节密钥\n")
        result = DES_decrypto(cryptotest, key)
        print(f"解密结果为：{result}")
```

### CBC 模式

```python
import base64

PC1 = [0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
left_move_arr = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
PC2 = [0, 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47,
       55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
IP = [0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40,
      32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55,
      47, 39, 31, 23, 15, 7]
IP_ = [0, 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13,
       53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33,
       1, 41, 9, 49, 17, 57, 25]
E = [0, 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20,
     21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
S = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
      [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
      [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
      [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
     [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
      [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
      [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
      [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
     [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
      [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
      [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
      [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
     [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
      [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 19],
      [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
      [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
     [[2, 12, 4, 1, 7, 10, 11, 6, 5, 8, 3, 15, 13, 0, 14, 9],
      [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 13, 3, 9, 8, 6],
      [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
      [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
     [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
      [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
      [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
      [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
     [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
      [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
      [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
      [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
     [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
      [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
      [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
      [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
P = [0, 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11,
     4, 25]


def divide_to_64_bite(str):  # 将比特消息划分为64bite一组，并返回
    result = []
    divide_num = len(str) // 64  # 分组数量
    for i in range(divide_num):
        result.append(str[(i * 64):((i + 1) * 64)])

    return result


def divide_to_6_bite(str):  # 将比特消息划分为6bite一组，并返回
    result = []
    divide_num = len(str) // 6  # 分组数量
    for i in range(divide_num):
        result.append(str[(i * 6):((i + 1) * 6)])

    return result


def F(str, key):  # 返回的字符中，开头没有t占位
    str = 't' + str
    # E扩展置换
    E_translate_str = ""
    for i in range(1, 49):
        E_translate_str += str[E[i]]

    # 密钥加
    if (len(E_translate_str) != 48 or len(key) != 48):  # 先检测str和key是否都是48位
        print("str和key须有都是48位")
        assert False

    # 按位异或
    temp = int(E_translate_str, 2) ^ int(key, 2)
    key_add_str = f'{temp:048b}'

    # S盒压缩变换
    divide_to_6_arr = divide_to_6_bite(key_add_str)  # 先分成6位一组

    S_translate_str = ""
    for step in range(len(divide_to_6_arr)):  # 每一组都需要查表转换
        divide_to_6_arr_contain = divide_to_6_arr[step]  # 取每一组的内容
        temp_i = divide_to_6_arr_contain[0] + divide_to_6_arr_contain[5]
        temp_j = divide_to_6_arr_contain[1:5]
        i = int(temp_i, 2)
        j = int(temp_j, 2)
        S_translate_str += f'{S[step][i][j]:04b}'  # 查S表得到第i行第j列的数字，并转换成2进制

    S_translate_str = 't' + S_translate_str
    # P盒置换
    P_translate_str = ""
    for i in range(1, 33):
        P_translate_str += S_translate_str[P[i]]

    return P_translate_str


def product_key(str):
    str_bite = ""
    for i in str:  # 把每一个字符变成8位的2进制表示
        str_bite += f'{ord(i):08b}'

    str_bite = 't' + str_bite
    # PC-1置换
    PC1_translate_str = ""
    for i in range(1, 57):
        PC1_translate_str += str_bite[PC1[i]]

    PC1_C = []
    PC1_D = []
    PC1_C.append(PC1_translate_str[0:28])
    PC1_D.append(PC1_translate_str[28:])

    # 生成16组C和D
    for step in range(0, 16):
        left_move_num = left_move_arr[step]
        result_C = PC1_C[step][left_move_num:] + PC1_C[step][0:left_move_num]
        result_D = PC1_D[step][left_move_num:] + PC1_D[step][0:left_move_num]
        PC1_C.append(result_C)
        PC1_D.append(result_D)

    C_add_D = []
    for step in range(1, 17):  # 对新生成的C和D，进行组合
        C_add_D.append(PC1_C[step] + PC1_D[step])

    result = []
    # PC-2置换
    for step in range(0, 16):  # 对新生成的C和D，进行PC2置换
        C_add_D[step] = 't' + C_add_D[step]
        temp_result = ""
        for i in range(1, 49):
            temp_result += C_add_D[step][PC2[i]]
        result.append(temp_result)

    return result


def DES_encrypto(str, key, IV):
    # IV以16进制形式输入
    IV_bite = ""
    for i in IV:  # 把每一个字符变成8位的2进制表示
        IV_bite += f'{ord(i):08b}'

    # 将输入明文按64位分组
    str_bite = ""
    for i in str:  # 把每一个字符变成8位的2进制表示
        str_bite += f'{ord(i):08b}'

    while (len(str_bite) % 64 != 0):  # 不足64位的倍数时补0
        str_bite += '0'

    divide_arr = divide_to_64_bite(str_bite)

    # 将输入的密钥生成16组子密钥
    if len(key) != 8:
        print("密钥长度需要为8")
        assert False

    key_arr = product_key(key)

    # 对每一组都进行加密
    encrypto_str = ""
    for divide_arr_contain in divide_arr:
        # 先进行与上一组密文结果的异或
        temp_contain = int(divide_arr_contain,2) ^ int(IV_bite,2)
        divide_arr_contain = f'{temp_contain:064b}'

        # 用t占位，方便后面下标的处理
        divide_arr_contain = 't' + divide_arr_contain

        # IP置换
        IP_translate_str = "t"
        for i in range(1, 65):
            IP_translate_str += divide_arr_contain[IP[i]]

        L = []
        R = []
        L.append(IP_translate_str[1:33])
        R.append(IP_translate_str[33:65])

        for step in range(0, 15):
            L.append(R[step])
            temp_str1 = L[step]
            temp_str2 = F(R[step], key_arr[step])
            temp_str_num = int(temp_str1, 2) ^ int(temp_str2, 2)
            temp_str = f'{temp_str_num:032b}'
            R.append(temp_str)

        temp_str1 = L[15]
        temp_str2 = F(R[15], key_arr[15])
        temp_str_num = int(temp_str1, 2) ^ int(temp_str2, 2)
        temp_str = f'{temp_str_num:032b}'
        L.append(temp_str)
        R.append(R[15])

        # IP逆置换
        L_add_R = 't' + L[16] + R[16]
        IP_reverse_translate_str = ""
        for i in range(1, 65):
            IP_reverse_translate_str += L_add_R[IP_[i]]

        encrypto_str += IP_reverse_translate_str

        IV_bite = IP_reverse_translate_str

    result_str = ""
    for i in range(0, len(encrypto_str), 8):
        result_str += chr(int(encrypto_str[i:i + 8], 2))

    return result_str


def DES_decrypto(str, key,IV):
    # IV以16进制形式输入
    IV_bite = ""
    for i in IV:  # 把每一个字符变成8位的2进制表示
        IV_bite += f'{ord(i):08b}'

    # 将输入明文按64位分组
    str_bite = ""
    for i in str:  # 把每一个字符变成8位的2进制表示
        str_bite += f'{ord(i):08b}'

    if len(str_bite) % 64 != 0:
        print("密文输入有错")
        assert False

    divide_arr = divide_to_64_bite(str_bite)

    # 将输入的密钥生成16组子密钥
    if len(key) != 8:
        print("密钥长度需要为8")
        assert False

    key_arr = product_key(key)

    # 对每一组都进行解密
    decrypto_str = ""
    for divide_arr_contain in divide_arr:
        # 暂时保存当前密文，用于最后和IV异或运算
        temp_current_contain = divide_arr_contain

        # 用t占位，方便后面下标的处理
        divide_arr_contain = 't' + divide_arr_contain

        # IP置换
        IP_translate_str = "t"
        for i in range(1, 65):
            IP_translate_str += divide_arr_contain[IP[i]]

        L = []
        R = []
        L.append(IP_translate_str[1:33])
        R.append(IP_translate_str[33:65])

        for step in range(0, 15):
            temp_str1 = L[step]
            temp_str2 = F(R[step], key_arr[15 - step])
            temp_str_num = int(temp_str1, 2) ^ int(temp_str2, 2)
            temp_str = f'{temp_str_num:032b}'
            R.append(temp_str)
            L.append(R[step])


        temp_str1 = L[15]
        temp_str2 = F(R[15], key_arr[0])
        temp_str_num = int(temp_str1, 2) ^ int(temp_str2, 2)
        temp_str = f'{temp_str_num:032b}'
        L.append(temp_str)
        R.append(R[15])

        # IP逆置换
        L_add_R = 't' + L[16] + R[16]
        IP_reverse_translate_str = ""
        for i in range(1, 65):
            IP_reverse_translate_str += L_add_R[IP_[i]]

        # 先进行与上一组密文结果的异或
        temp_contain = int(IP_reverse_translate_str, 2) ^ int(IV_bite, 2)
        IP_reverse_translate_str = f'{temp_contain:064b}'
        IV_bite = temp_current_contain

        decrypto_str += IP_reverse_translate_str

    result_str = ""
    for i in range(0, len(decrypto_str), 8):
        if int(decrypto_str[i:i + 8], 2) == 0:
            continue
        result_str += chr(int(decrypto_str[i:i + 8], 2))

    return result_str


if __name__ == "__main__":
    input_num = ''
    IV = 0
    input_num = input("请选择方式：输入1为加密 输入2为解密\n")
    if input_num == "1":
        plaintext = input("请输入需要DES加密的字符串\n")
        key = input("请输入DES加密需要的8字节密钥\n")
        IV = input("请输入ID初始化向量\n")
        result = DES_encrypto(plaintext, key, IV)
        str_16 = ""
        for i in result:  # 把每一个字符变成8位的2进制表示
            str_16 += f'{ord(i):02x}'
        print(f"加密后密文用16进制表示为：{str_16}")
        print(f"加密后密文用base64表示为：{base64.b64encode(result.encode()).decode()}")
    elif input_num == "2":
        cryptotest_num = input("请输入需要DES解密的字符串的类型 1为base64输入 2为16进制输入\n")
        str_1 = input("请输入需要DES解密的字符串\n")
        if cryptotest_num == "1":
            cryptotest = base64.b64decode(str_1.encode()).decode()
        elif cryptotest_num == "2":
            cryptotest = ""
            for i in range(0, len(str_1), 2):
                cryptotest += chr(int(str_1[i:i + 2], 16))
        key = input("请输入DES解密需要的8字节密钥\n")
        IV = input("请输入ID初始化向量\n")
        result = DES_decrypto(cryptotest, key,IV)
        print(f"解密结果为：{result}")
```


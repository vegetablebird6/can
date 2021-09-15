import random

size = 63

# 随机生成size位二进制
a = random.getrandbits(size)
print(a)

# 将十进制转为16进制
b = hex(a)
print(b)

# 将16进制转为十进制
print(int(b,16))

# 将十进制转为二进制
print(bin(a))
import random

def generateRS(size):
    # 随机生成size位二进制
    return random.getrandbits(size)

def getbit(byte, index):
    if byte & (1 << (index - 1)):
        return 1
    else:
        return 0

# print(generateRS(16))

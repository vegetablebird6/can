import struct

from Crypto.Hash import SHA384

# t为轮次
def generateHC(oseed, k):
    list = []
    cur = oseed.encode('utf-8')
    # print(type(cur))
    for i in range(k):
        h = SHA384.new(cur)
        # h = ''.join([hex(int(h.hexdigest(),16) >> (384 - 18)).replace('0x','')]).encode(encoding='utf-8')
        h = int(h.hexdigest(), 16) >> 366
        # list.append(h.decode('utf-8'))
        list.append(h)
        # cur = h
        cur = h.to_bytes(18,byteorder='big')
    # print(list)
    return list


# generateHC(oseed=b'2FEF1',k = 4)

from Crypto.Hash import SHA256
import datetime


# t为轮次
def generateHC(oseed, groupAuthKey, k):
    list = []
    cur = oseed.encode('utf-8')
    for i in range(k):
        h = SHA256.new(cur + groupAuthKey)
        h = int(h.hexdigest(), 16) >> 231  # 256 - 25
        list.append(h)
        cur = h.to_bytes(25, byteorder='big')
    # print(list)
    return list

from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import datetime


# t为轮次
def generateHC(oseed, groupAuthKey, k):
    list = []
    cur = oseed.encode('utf-8')
    # print(type(cur))
    for i in range(k):
        h = CMAC.new(groupAuthKey, cur, ciphermod=AES, mac_len=16)
        h = int(h.hexdigest(), 16) >> 102
        # list.append(h.decode('utf-8'))
        list.append(h)
        # cur = h
        cur = h.to_bytes(26, byteorder='big')
    # print(list)
    return list

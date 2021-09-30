from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import datetime


# t为轮次
def generateHC(oseed, groupAuthKey, k):
    list = []
    cur = oseed.encode('utf-8')
    # print(type(cur))
    for i in range(k):
        h = CMAC.new(groupAuthKey,cur,ciphermod=AES,mac_len=16)
        h = int(h.hexdigest(), 16) >> 110
        # list.append(h.decode('utf-8'))
        list.append(h)
        # cur = h
        cur = h.to_bytes(18,byteorder='big')
    # print(list)
    return list

# from Crypto.Hash import HMAC, SHA256
#
# def generateHC(oseed, groupAuthKey, k):
#     list = []
#     cur = oseed.encode('utf-8')
#     # print(type(cur))
#     for i in range(k):
#         h = HMAC.new(groupAuthKey, cur, digestmod=SHA256)
#         h = int(h.hexdigest(), 16) >> 238
#         # list.append(h.decode('utf-8'))
#         list.append(h)
#         # cur = h
#         cur = h.to_bytes(18,byteorder='big')
#     print(list)
#     return list

# begin = datetime.datetime.now()
# print(generateHC(oseed=bin(35773)[2:],groupAuthKey = b'f494409468476910ce95efd1f71c8759',k = 18))
# end = datetime.datetime.now()
# print((end - begin).total_seconds())

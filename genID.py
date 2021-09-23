from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import random

from doublelinklist import DLinkList

# i为轮次
def generateID(idseed,i,num,groupAuthKey):
    round = 0
    idlist = DLinkList()
    origincmac = CMAC.new(groupAuthKey,(idseed+str(i)+str(round)).encode('utf-8'),ciphermod=AES,mac_len=16)
    # Transform c from string to binary
    cmac = int(origincmac.hexdigest(),16)
    # 剩下多少位数
    remainbit = 128
    temple = 0b11111111111
    count = 0
    while(count < num):
        if remainbit < 11:
            round += 1
            origincmac = CMAC.new(groupAuthKey, (idseed + str(i) + str(round)).encode('utf-8'), ciphermod=AES,
                                  mac_len=16)
            tempbit = 11 - remainbit
            newid = cmac << tempbit
            cmac = int(origincmac.hexdigest(),16)
            newid = newid + (cmac & (temple & tempbit))
            cmac = cmac >> tempbit
            remainbit = 128 - tempbit
        else:
            newid = cmac & temple
            cmac = cmac >> 11
            remainbit -= 11
        if idlist.add(newid) == True:
            count += 1
    return idlist


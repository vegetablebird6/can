from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def generateID(idseed, groupAuthKey):
    # roundID = 0
    cmac = CMAC.new(groupAuthKey,(idseed).encode('utf-8'),ciphermod=AES,mac_len=16)
    # Transform c from string to binary
    binary_cmac = int(cmac.hexdigest(),16)
    list = []
    m_bit = 128 - 11
    temple = 0b11111111111
    flag = False
    while(m_bit >= 11):
        b = temple << m_bit
        temp = (binary_cmac & b) >> m_bit
        for j in list:
            if (temp == j):
                flag = True
        if not flag :
            list.append(temp)
            flag = False
        m_bit -= 11
    list.sort()
    # print(list)
    return list

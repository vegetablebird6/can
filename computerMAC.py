from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def computerMAC(msg, groupAuthKey):
    bytemsg = msg.encode('utf-8')
    cmac = CMAC.new(groupAuthKey, bytemsg, ciphermod=AES, mac_len=16)
    dig = cmac.hexdigest()
    length = 110
    res = int(cmac.hexdigest(), 16) >> length
    # print(res)
    return res

# computerMAC(msg = "f494409468476910ce95e", groupAuthKey= b'f494409468476910ce95efd1f71c8759')
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def vertify(HV, groupAuthKey, RHV):
    # h = SHA384.new(HV.encode('utf-8'))
    # h = ''.join([hex(int(h.hexdigest(),16) >> (384 - 18)).replace('0x','')])
    h = CMAC.new(groupAuthKey, HV.to_bytes(18, byteorder='big'), ciphermod=AES, mac_len=16)
    h = int(h.hexdigest(), 16) >> 110
    if h == RHV:
        return True
    return False
# vertify(224527,24709)
# vertify('36d0f', '3265a')

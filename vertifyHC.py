from Crypto.Hash import SHA384
def vertify(HV, RHV):
    # h = SHA384.new(HV.encode('utf-8'))
    # h = ''.join([hex(int(h.hexdigest(),16) >> (384 - 18)).replace('0x','')])
    h = SHA384.new(HV.to_bytes(18, byteorder='big'))
    h = int(h.hexdigest(),16) >> 366
    if h == RHV:
        return True
    return False
# vertify(224527,24709)
# vertify('36d0f', '3265a')
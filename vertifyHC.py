from Crypto.Hash import SHA256

def vertify(HV, groupAuthKey, RHV):
    h = SHA256.new(HV.to_bytes(25, byteorder='big') + groupAuthKey)
    h = int(h.hexdigest(), 16) >> 231
    if h == RHV:
        return True
    return False
# vertify(224527,24709)
# vertify('36d0f', '3265a')

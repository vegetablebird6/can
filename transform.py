def datalist_to_int(datalist, dlc):
    res = 0
    for i in range(dlc):
        res += datalist[i] << ((dlc - i - 1) * 8)
    return res

def int_to_datalist(number,dlc):
    datalist = []
    while(number != 0):
        datalist.append(number % 256)
        number = number // 256
    while (len(datalist) < dlc):
        datalist.append(0)
    datalist.reverse()
    return datalist


# 测试
# datalist = [1,2,3,4]
# res = datalist_to_int(datalist,4)
# print(res)
# print(int_to_datalist(res))
import time
import can
from genID import generateID
from genHC import generateHC
from genRS import generateRS, getbit
import encryption
import transform
import computerMAC

SECU_ID = 0

K = 18
groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'
idseed = '110111111011111011'


def periodic_send(bus, ctr):
    global idseed
    count = 0
    oldseed = 197231
    newseed = 35773
    newlist = generateHC(bin(newseed)[2:], groupAuthKey, K)
    # next chain last value
    nextCLV = newlist.pop()
    # print(nextCLV)
    left_idlist = generateID(idseed, 0, 25, groupAuthKey)

    list = generateHC(bin(oldseed)[2:], groupAuthKey, K)
    list.pop()
    # print(list.pop())
    # 数据部分处理
    # 1. 得到下一个哈希种子值的最后一位
    # 2. 加密数据域
    print("Starting to send messages")
    while True:
        data = []
        data.append(0)
        data.append(0)
        idseed = generateRS(18)
        int_idseed = int(idseed, 2)
        remainbit = 18
        while remainbit > 0:
            data.append(int_idseed & 0xff)
            int_idseed = int_idseed >> 8
            remainbit -= 8
        print(data)
        dlc = len(data)
        msg = can.Message(dlc=dlc, is_extended_id=True)
        # id 部分处理
        left_id = left_idlist.getitem(SECU_ID)
        left_idlist = generateID(idseed, 0, 25, groupAuthKey)
        print(idseed)
        if count == K - 1:
            print("computer nextCLV's MAC")
            # nextCLV's MAC
            nextCLVMAC = computerMAC.computerMAC(bin(nextCLV)[2:], groupAuthKey)
            id = (left_id << 18) + nextCLVMAC
            oldseed = newseed
            list = newlist
            newseed = generateRS(K)
            newlist = generateHC(newseed, groupAuthKey, K)
            nextCLV = newlist.pop()
            lastbit = getbit(nextCLV, K)
        else:
            right_id = list.pop()
            id = (left_id << 18) + right_id
            lastbit = getbit(nextCLV, K - 1 - count)
        # print(lastbit)
        data[dlc-1] = (data[dlc-1] << 1) + lastbit
        Enctext = encryption.aesEncrypt(groupEnKey, str(ctr))
        data_temp = transform.datalist_to_int(data, dlc)
        Enctext = Enctext >> ((16 - dlc) * 8)
        Enctext = Enctext ^ data_temp
        data = transform.int_to_datalist(Enctext, dlc)
        msg.data = data
        msg.arbitration_id = id
        bus.send(msg)
        ctr = (ctr + 1) % 256
        count = (count + 1) % K
        print(data)
        # print(ctr)
        time.sleep(2)


def main():
    reset_msg = can.Message(
        arbitration_id=0x00, data=[0, 0, 0, 0, 0, 0, 0, 0], is_extended_id=False
    )
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as bus:
        bus.send(reset_msg)

        periodic_send(bus, ctr=0)

        bus.send(reset_msg)
        #
        # limited_periodic_send(bus)


    time.sleep(1)

if __name__ == '__main__':
    main()

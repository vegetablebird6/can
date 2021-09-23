import time
import can
from genID import generateID
from genHC import generateHC
from genRS import generateRS, getbit
import encryption
import transform
import computerMAC

SECU_ID = 0
RECU_ID = 1
K = 18
groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'
idseed = '110111111011111011'



def simple_periodic_send(bus, ctr):
    count = 0
    oldseed = 22022
    newseed = 35617
    newlist = generateHC(bin(newseed)[2:], K)
    # next chain last value
    nextCLV = newlist.pop()
    print(nextCLV)

    # id 部分处理
    left_idlist = generateID(idseed, 0, 25, groupAuthKey)

    list = generateHC(bin(oldseed)[2:], K)
    print(list.pop())
    # 数据部分处理
    # 1. 得到下一个哈希种子值的最后一位
    # 2. 加密数据域
    print("Starting to send messages")
    with open("Dataset.txt", "r") as file:
        while True:
            line = file.readline()
            if not line:
                break
            dataline = line.split()
            data = []
            for d in dataline:
                data.append(int(d))
            dlc = len(data)
            msg = can.Message(dlc=8, is_extended_id=True)
            left_id = left_idlist.getitem(SECU_ID)
            if count == K - 1:
                print("computer nextCLV's MAC")
                # nextCLV's MAC
                nextCLVMAC = computerMAC.computerMAC(bin(nextCLV)[2:], groupAuthKey)
                id = (left_id << 18) + nextCLVMAC
                oldseed = newseed
                list = newlist
                newseed = generateRS(K)
                newlist = generateHC(''.join([bin((newseed)).replace('0b', '')]), K)
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
            # print(ctr)
            time.sleep(0.01)
    print('over')


def main():
    reset_msg = can.Message(
        arbitration_id=0x00, data=[0, 0, 0, 0, 0, 0, 0, 0], is_extended_id=False
    )
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as bus:
        bus.send(reset_msg)

        simple_periodic_send(bus, ctr=0)

        bus.send(reset_msg)
        #
        # limited_periodic_send(bus)


    time.sleep(2)

if __name__ == '__main__':
    main()

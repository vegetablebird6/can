import time
import can
from generateID import generateID
from generateHC import generateHC
from generateRS import generateRS, getbit
import encryption
import transform
import computerMAC

ECU_ID = 0
K = 18
groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'
idseed = '110111111011111'
CTR = 0


def simple_periodic_send(bus,ctr):
    oseed = 22022
    new_seed = 35617
    new_list = generateHC(''.join([bin((new_seed)).replace('0b','')]), K)
    # next chain last value
    nextCLV = new_list.pop()
    print(nextCLV)
    # nextCLV's MAC
    nextCLVMAC = computerMAC.computerMAC(''.join([bin((nextCLV)).replace('0b','')]),groupAuthKey)

    # id 部分处理
    left_idlist = generateID(idseed, groupAuthKey)

    list = generateHC(''.join([bin((oseed)).replace('0b','')]), K)
    print(list.pop())
    # 数据部分处理
    # 1. 得到下一个哈希种子值的最后一位
    # 2. 加密数据域
    dataset = [[0, 0, 0, 0, 0, 0, 0, 0], [1, 1, 1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2, 2, 2], [3, 3, 3, 3, 3, 3, 3, 3],
               [4, 4, 4, 4, 4, 4, 4, 4], [5, 5, 5, 5, 5, 5, 5, 5], [6, 6, 6, 6, 6, 6, 6, 6], [7, 7, 7, 7, 7, 7, 7, 7],
               [8, 8, 8, 8, 8, 8, 8, 8], [9, 9, 9, 9, 9, 9, 9, 9], [10, 10, 10, 10, 10, 10, 10, 10],
               [11, 11, 11, 11, 11, 11, 11, 11],[12, 12, 12, 12, 12, 12, 12, 12], [13, 13, 13, 13, 13, 13, 13, 13],
               [14, 14, 14, 14, 14, 14, 14, 14], [15, 15, 15, 15, 15, 15, 15, 15], [0, 0, 0, 0, 0, 0, 0, 0],
               [1, 1, 1, 1, 1, 1, 1, 1]]

    print("Starting to send messages")
    msg = can.Message(dlc=8, is_extended_id=True)
    for i in range(len(dataset)):
        left_id = left_idlist[ECU_ID]
        data = dataset[i]
        dlc = len(data)
        if len(list) == 0:
            id = (left_id << 18) + nextCLVMAC
            oseed = new_seed
            list = new_list
            new_seed = generateRS(K)
            new_list = generateHC(''.join([bin((new_seed)).replace('0b','')]), K)
            nextCLV = new_list.pop()
            last_bit = getbit(nextCLV, K)
        else:
            right_id = list.pop()
            id = (left_id << 18) + right_id
            last_bit = getbit(nextCLV, K - i - 1)
        data[dlc-1] = (data[dlc-1] << 1) + last_bit
        Enctext = encryption.aesEncrypt(groupEnKey, str(ctr))
        data_temp = transform.datalist_to_int(data, dlc)
        Enctext = Enctext >> ((16 - dlc) * 8)
        Enctext = Enctext ^ data_temp
        data = transform.int_to_datalist(Enctext, dlc)
        msg.data = data
        msg.arbitration_id = id
        bus.send(msg)
        time.sleep(1)
        ctr += 1




def main():
    reset_msg = can.Message(
        arbitration_id=0x00, data=[0, 0, 0, 0, 0, 0, 0, 0], is_extended_id=False
    )
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as bus:
        bus.send(reset_msg)

        simple_periodic_send(bus, CTR)

        bus.send(reset_msg)
        #
        # limited_periodic_send(bus)


    time.sleep(2)

if __name__ == '__main__':
    main()
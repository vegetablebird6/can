import time
import can
from genID import generateID
from genHC import generateHC
from genRS import generateRS, getbit
import encryption
import transform
import computerMAC

ECU_ID = 0
K = 18
groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'
idseed = '110111111011111'


def simple_periodic_send(bus, ctr):
    oldseed = 22022
    newseed = 35617
    # 利用新seed生成新的哈希链
    newlist = generateHC(''.join([bin((newseed)).replace('0b','')]), K)
    # next chain last value
    nextCLV = newlist.pop()
    print(nextCLV)

    # id 部分处理
    left_idlist = generateID(idseed, groupAuthKey)
    # 利用旧seed生成哈希链
    list = generateHC(''.join([bin((oldseed)).replace('0b','')]), K)
    # 因为哈希链的最后一个哈希已经在接收者保存了，所以去掉
    list.pop()
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
            if ctr == 256:
                ctr = 0
            msg = can.Message(dlc=8, is_extended_id=True)
            left_id = left_idlist[ECU_ID]
            if ctr % K == K - 1:
                print("computer nextCLV's MAC")
                # nextCLV's MAC
                nextCLVMAC = computerMAC.computerMAC(''.join([bin((nextCLV)).replace('0b', '')]), groupAuthKey)
                id = (left_id << 18) + nextCLVMAC
                # 新换旧
                oldseed = newseed
                list = newlist
                # 生成新的seed值
                newseed = generateRS(K)
                # 生成新的哈希链
                newlist = generateHC(''.join([bin((newseed)).replace('0b', '')]), K)
                # 弹出并保存最后一个哈希值
                nextCLV = newlist.pop()
                # 取最后一个哈希值的首位
                lastbit = getbit(nextCLV, K)
            else:
                right_id = list.pop()
                id = (left_id << 18) + right_id
                lastbit = getbit(nextCLV, K - 1 - ctr % K)
            # print(lastbit)
            # data的最后一个字节往左移1位放下最后一个哈希值的位
            data[dlc-1] = (data[dlc-1] << 1) + lastbit
            # 加密操作
            Enctext = encryption.aesEncrypt(groupEnKey, str(ctr))
            data_temp = transform.datalist_to_int(data, dlc)
            Enctext = Enctext >> ((16 - dlc) * 8)
            Enctext = Enctext ^ data_temp
            data = transform.int_to_datalist(Enctext, dlc)
            # 封装成message
            msg.data = data
            msg.arbitration_id = id
            bus.send(msg)
            ctr += 1
            # print(ctr)
            time.sleep(1)



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

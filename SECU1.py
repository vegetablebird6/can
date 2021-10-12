import threading
import time
from threading import Thread
import can
from genID import generateID
from genHC import generateHC
from genRS import generateRS, getbit
import encryption
import transform
import computerMAC
import vertifyHC


SECU_ID = 1
RECU_ID = 0
K = 18
groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'
idseed = '110111111011111011'
# 设定一个Flag
leftidUpdate = True
mutex = threading.Lock()


def periodic_send(bus, ctr):
    global leftidUpdate
    count = 0
    oldseed = 22022
    newseed = 35617
    newlist = generateHC(bin(newseed)[2:], groupAuthKey, K)
    # next chain last value
    nextCLV = newlist.pop()
    # print(nextCLV)

    list = generateHC(bin(oldseed)[2:], groupAuthKey, K)
    list.pop()
    # print(list.pop())
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
            if leftidUpdate:
                # id 部分处理
                left_idlist = generateID(idseed, 0, 25, groupAuthKey)
                with mutex:
                    leftidUpdate = False
                left_id = left_idlist.getitem(SECU_ID)
            # if ctr % K == K - 1:
            if count == K - 1:
                # print("computer nextCLV's MAC")
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
            # print(ctr)
            time.sleep(0.01)
    print('over')


def periodic_receive(bus, ctr):
    """The loop for receiving."""
    # some known value
    count = 0
    RHV = 233431
    last_bit = 0
    global leftidUpdate
    # generate the leftid list
    global idseed
    leftidlist = generateID(idseed, 0, 25, groupAuthKey)
    # next hash chain's last value
    nextCLV = last_bit
    print("Start receiving messages")
    while True:
        try:
            # choose the leftid
            leftid = leftidlist.getitem(RECU_ID) << 18
            # set the receiver's filter
            can_filters = [{"can_id": leftid, "can_mask": 0x1ffc0000, "extended": True}]
            bus.set_filters(can_filters)
            print(idseed)
            # receive the message
            rx_msg = bus.recv()
            if rx_msg is None:
                continue

            rightid = rx_msg.arbitration_id - leftid
            if count == K - 1:
                nextCLVMAC = computerMAC.computerMAC(bin(nextCLV)[2:], groupAuthKey)
                if nextCLVMAC != rightid:
                    continue
                RHV = nextCLV
                nextCLV = 0
            else:
                if (vertifyHC.vertify(rightid, groupAuthKey, RHV) == False):
                    continue
                RHV = rightid


            Enctext = encryption.aesEncrypt(groupEnKey, str(ctr))
            data_temp = int.from_bytes(rx_msg.data, byteorder='big', signed=False)
            Enctext = Enctext >> ((16 - rx_msg.dlc) * 8)
            Enctext = Enctext ^ data_temp
            last_bit = Enctext % 2
            # print(last_bit)
            plaintext = Enctext - last_bit
            rx_msg.data = transform.int_to_datalist(plaintext, rx_msg.dlc)
            rx_msg.data[rx_msg.dlc - 1] = rx_msg.data[rx_msg.dlc - 1] >> 1
            # print(rx_msg.data)
            idseed = bin(rx_msg.data[2] + (rx_msg.data[3] << 8) + (rx_msg.data[4] << 16))[2:].zfill(K)
            leftidlist = generateID(idseed, 0, 25, groupAuthKey)
            with mutex:
                leftidUpdate = True
            ctr = (ctr + 1) % 256
            count = (count + 1) % K
            nextCLV = (nextCLV << 1) + last_bit
        except KeyboardInterrupt:
            break
    print("Stopped receiving messages")

def main():
    reset_msg = can.Message(
        arbitration_id=0x00, data=[0, 0, 0, 0, 0, 0, 0, 0], is_extended_id=False
    )
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as bus:
        bus.send(reset_msg)
        receivethread = Thread(target=periodic_receive, args=(bus, 0,))
        receivethread.start()
        periodic_send(bus, ctr=0)
        while True:
            pass
        bus.send(reset_msg)
        # limited_periodic_send(bus)


    time.sleep(1)

if __name__ == '__main__':
    main()

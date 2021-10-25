import time
import can
from genID import generateID
from genHC import generateHC
from genRS import generateRS, getbit
import encryption
import transform
import computerMAC

SECU_ID = 0

K = 26
groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'


def periodic_send(bus, ctr, idseed, oldseed, newseed):
    count = 0
    old_hash_chain = generateHC(bin(oldseed)[2:], groupAuthKey, K)
    old_hash_chain.pop()

    new_hash_chain = generateHC(bin(newseed)[2:], groupAuthKey, K)
    # next chain last value
    next_chain_value = new_hash_chain.pop()
    # print(next_chain_value)
    fake_id_list = generateID(idseed, 0, 25, groupAuthKey)

    # print(list.pop())
    # 数据部分处理
    # 1. 得到下一个哈希种子值的最后一位
    # 2. 加密数据域
    print("Starting to send messages")
    while True:
        data = []
        data.append(0)
        data.append(0)
        idseed = generateRS(26)
        int_idseed = int(idseed, 2)
        remainbit = 26
        while remainbit > 0:
            data.append(int_idseed & 0xff)
            int_idseed = int_idseed >> 8
            remainbit -= 8
        print(data)
        dlc = len(data)
        msg = can.Message(dlc=dlc + 1, is_extended_id=True)

        left_id = fake_id_list.getitem(SECU_ID)

        fake_id_list = generateID(idseed, 0, 25, groupAuthKey)
        print(idseed)
        if count == K - 1:
            print("computer next_chain_value's MAC")
            # next_chain_value's MAC
            next_chain_value_mac = computerMAC.computerMAC(bin(next_chain_value)[2:], groupAuthKey)
            m = next_chain_value_mac & 0xff
            full_id = (left_id << 18) + (next_chain_value_mac >> 8)
            oldseed = newseed
            old_hash_chain = new_hash_chain
            newseed = generateRS(K)
            new_hash_chain = generateHC(newseed, groupAuthKey, K)
            next_chain_value = new_hash_chain.pop()
            single_bit = getbit(next_chain_value, K)
        else:
            chain_value = old_hash_chain.pop()
            m = chain_value & 0xff
            right_id = chain_value >> 8
            full_id = (left_id << 18) + right_id
            single_bit = getbit(next_chain_value, K - 1 - count)
        # print(lastbit)
        enctext = encryption.aesEncrypt(groupEnKey, str(ctr))
        data_temp = transform.datalist_to_int(data, dlc)
        enctext = enctext >> ((16 - dlc) * 8)
        enctext = enctext ^ data_temp
        data = transform.int_to_datalist(enctext, dlc)
        if single_bit == 1:
            m = m ^ 0xff
        else:
            m = m ^ 0x00
        data.append(m)
        msg.data = data
        msg.arbitration_id = full_id
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
    oldseed = 197231
    newseed = 35773
    idseed = '110111111011111011'
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as bus:
        bus.send(reset_msg)

        periodic_send(bus, 0, idseed, oldseed, newseed)

        bus.send(reset_msg)
        #
        # limited_periodic_send(bus)


    time.sleep(1)

if __name__ == '__main__':
    main()

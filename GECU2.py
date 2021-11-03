import time
import can
from genID import generateID
from genHC import generateHC
from genRS import generateRS, getbit
import encryption
import transform
import computerMAC
from Crypto.Hash import SHA256


SECU_ID = 0

K = 25
groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'


def periodic_send(bus, ctr, idseed, oldseed, newseed):
    count = 0
    r = 0
    old_hash_chain = generateHC(bin(oldseed)[2:], groupAuthKey, K)
    old_hash_chain.pop()

    new_hash_chain = generateHC(bin(newseed)[2:], groupAuthKey, K)
    # next chain last value
    next_chain_value = new_hash_chain.pop()
    # print(next_chain_value)
    fake_id_list = generateID(idseed, 0, 25, groupAuthKey)

    index_source = SHA256.new(r.to_bytes(8, byteorder='big') + groupAuthKey)
    index_source = int(index_source.hexdigest(), 16)
    # print(list.pop())
    # 数据部分处理
    # 1. 得到下一个哈希种子值的最后一位
    # 2. 加密数据域
    print("Starting to send messages")
    while True:
        data = []
        data.append(0)
        data.append(0)
        idseed = generateRS(32)
        int_idseed = int(idseed, 2)
        remainbit = 32
        while remainbit > 0:
            data.append(int_idseed & 0xff)
            int_idseed = int_idseed >> 8
            remainbit -= 8
        print(data)
        dlc = len(data)
        msg = can.Message(dlc=dlc + 1, is_extended_id=True)

        index = (index_source & 0xff) % (msg.dlc * 8)
        index_source = index_source >> 8

        left_id = fake_id_list.getitem(SECU_ID)

        fake_id_list = generateID(idseed, 0, 25, groupAuthKey)
        print(idseed)
        if count == K - 1:
            print("computer next_chain_value's MAC")
            # next_chain_value's MAC
            next_chain_value_mac = computerMAC.computerMAC(bin(next_chain_value)[2:], groupAuthKey)
            print(next_chain_value_mac)
            m = next_chain_value_mac & 0x7f
            full_id = (left_id << 18) + (next_chain_value_mac >> 7)
            oldseed = newseed
            old_hash_chain = new_hash_chain
            newseed = generateRS(K)
            new_hash_chain = generateHC(newseed, groupAuthKey, K)
            next_chain_value = new_hash_chain.pop()
            single_bit = getbit(next_chain_value, K)
            r = (r + 1) % 256
            index_source = SHA256.new(r.to_bytes(8, byteorder='big') + groupAuthKey)
            index_source = int(index_source.hexdigest(), 16)
        else:
            chain_value = old_hash_chain.pop()
            m = chain_value & 0x7f
            full_id = (left_id << 18) + (chain_value >> 7)
            single_bit = getbit(next_chain_value, K - 1 - count)
        print(single_bit)
        enctext = encryption.aesEncrypt(groupEnKey, str(ctr))
        data_temp = transform.datalist_to_int(data, dlc)
        enctext = enctext >> ((16 - dlc) * 8)
        enctext = enctext ^ data_temp
        final_data = (enctext << 8) + (m << 1)

        temp = (1 << index + 1) - 1
        right_data = final_data & temp
        left_data = final_data - right_data
        final_data = left_data + (single_bit << index) + (right_data >> 1)

        data = transform.int_to_datalist(final_data, dlc + 1)
        msg.data = data
        msg.arbitration_id = full_id
        bus.send(msg)
        ctr = (ctr + 1) % 256
        count = (count + 1) % K
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

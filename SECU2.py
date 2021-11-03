import random
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
from Crypto.Hash import SHA256


SECU_ID = 1
RECU_ID = 0
K = 25
groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'
id_seed = '110111111011111011'
# 设定一个Flag
fake_id_update = True
mutex = threading.Lock()


def periodic_send(bus, ctr, oldseed, newseed):
    global fake_id_update
    count = 0
    r = 0

    old_hash_chain = generateHC(bin(oldseed)[2:], groupAuthKey, K)
    old_hash_chain.pop()

    new_hash_chain = generateHC(bin(newseed)[2:], groupAuthKey, K)
    # next chain last value
    next_chain_value = new_hash_chain.pop()

    index_source = SHA256.new(r.to_bytes(8, byteorder='big') + groupAuthKey)
    index_source = int(index_source.hexdigest(), 16)

    # print(next_chain_value)
    # print(list.pop())
    # 数据部分处理
    # 1. 得到下一个哈希种子值的最后一位
    # 2. 加密数据域
    print("Starting to send messages")
    with open("dataset2.txt", "r") as file:
        while True:
            line = file.readline()
            if not line:
                break
            length = len(line) - 1
            data = []
            for i in range(length // 2):
                data.append(int(line[2 * i:2 * (i + 1)], 16))
            dlc = length // 2
            msg = can.Message(dlc=dlc + 1, is_extended_id=True)

            index = (index_source & 0xff) % (msg.dlc * 8)
            index_source = index_source >> 8

            if fake_id_update:
                # id 部分处理
                fake_id_list = generateID(id_seed, 0, 25, groupAuthKey)
                with mutex:
                    fake_id_update = False
                left_id = fake_id_list.getitem(SECU_ID)
            # if ctr % K == K - 1:
            if count == K - 1:
                # print("computer next_chain_value's MAC")
                # next_chain_value's MAC
                next_chain_value_mac = computerMAC.computerMAC(bin(next_chain_value)[2:], groupAuthKey)
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
            time.sleep(0.05)
    print('over')


def periodic_receive(bus, ctr, receive_hash_value, nextclv_bit):
    """The loop for receiving."""
    # some known value
    count = 0

    r = 0
    index_source = SHA256.new(r.to_bytes(8, byteorder='big') + groupAuthKey)
    index_source = int(index_source.hexdigest(), 16)

    global fake_id_update
    # generate the left_id list
    global id_seed
    fake_id_list = generateID(id_seed, 0, 25, groupAuthKey)
    next_chain_value = nextclv_bit
    print("Start receiving messages")
    while True:
        try:
            # choose the left_id
            fake_id = fake_id_list.getitem(RECU_ID) << 18
            # set the receiver's filter
            can_filters = [{"can_id": fake_id, "can_mask": 0x1ffc0000, "extended": True}]
            bus.set_filters(can_filters)
            # print(id_seed)
            # receive the message
            rx_msg = bus.recv()
            if rx_msg is None:
                continue
            right_id = rx_msg.arbitration_id & 0x0003ffff
            dlc = rx_msg.dlc
            data_temp = int.from_bytes(rx_msg.data, byteorder='big', signed=False)

            index = (index_source & 0xff) % (dlc * 8)
            index_source = index_source >> 8
            temp = 1 << index
            single_bit = (data_temp & temp) >> index
            left_data = data_temp >> (index + 1) << (index + 1)
            right_data = data_temp & (temp - 1)
            data_temp = left_data + (right_data << 1)

            m = data_temp & 0xff
            hvalue = (right_id << 7) + (m >> 1)
            data_temp = data_temp // 256

            dlc = dlc - 1
            if count == K - 1:
                next_chain_value_mac = computerMAC.computerMAC(bin(next_chain_value)[2:], groupAuthKey)
                print(next_chain_value_mac)
                if next_chain_value_mac != hvalue:
                    continue
                receive_hash_value = next_chain_value
                next_chain_value = 0
                r = (r + 1) % 256
                index_source = SHA256.new(r.to_bytes(8, byteorder='big') + groupAuthKey)
                index_source = int(index_source.hexdigest(), 16)
            else:
                if not vertifyHC.vertify(hvalue, groupAuthKey, receive_hash_value):
                    continue
                receive_hash_value = hvalue
            enctext = encryption.aesEncrypt(groupEnKey, str(ctr))
            enctext = enctext >> ((16 - dlc) * 8)
            plaintext = enctext ^ data_temp
            data = transform.int_to_datalist(plaintext, dlc)
            print(count)
            print(data)
            print(id_seed)
            id_seed = bin(data[2] + (data[3] << 8) + (data[4] << 16) + (data[5] << 24))[2:].zfill(32)
            fake_id_list = generateID(id_seed, 0, 25, groupAuthKey)
            with mutex:
                fake_id_update = True

            ctr = (ctr + 1) % 256
            count = (count + 1) % K
            next_chain_value = (next_chain_value << 1) + single_bit
        except KeyboardInterrupt:
            break
    print("Stopped receiving messages")


def main():
    old_seed = 22022
    new_seed = 35617
    # next_chain_value_mac = random.getrandbits(K)
    reset_msg = can.Message(
        arbitration_id=0x00, data=[0, 0, 0, 0, 0, 0, 0, 0], is_extended_id=False
    )
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as bus:
        bus.send(reset_msg)
        receive_thread = Thread(target=periodic_receive, args=(bus, 0, 26425878, 0))
        receive_thread.start()
        periodic_send(bus, 0, old_seed, new_seed)
        receive_thread.join()
        bus.send(reset_msg)
    time.sleep(1)


if __name__ == '__main__':
    main()
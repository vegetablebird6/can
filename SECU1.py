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
K = 26
groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'
id_seed = '110111111011111011'
# 设定一个Flag
fake_id_update = True
mutex = threading.Lock()


def periodic_send(bus, ctr, oldseed, newseed):
    global fake_id_update
    count = 0
    old_hash_chain = generateHC(bin(oldseed)[2:], groupAuthKey, K)
    old_hash_chain.pop()

    new_hash_chain = generateHC(bin(newseed)[2:], groupAuthKey, K)
    # next chain last value
    next_chain_value = new_hash_chain.pop()
    # print(next_chain_value)
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
            date_line = line.split()
            data = []
            for d in date_line:
                data.append(int(d))
            dlc = len(data)
            msg = can.Message(dlc=dlc + 1, is_extended_id=True)
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
            # print(single_bit)
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
            # print(ctr)
            time.sleep(0.01)
    print('over')


def periodic_receive(bus, ctr):
    """The loop for receiving."""
    # some known value
    count = 0
    receive_hash_value = 233431
    last_bit = 0
    global fake_id_update
    # generate the left_id list
    global id_seed
    fake_id_list = generateID(id_seed, 0, 25, groupAuthKey)
    # next hash chain's last value
    next_chain_value = last_bit
    print("Start receiving messages")
    while True:
        try:
            # choose the left_id
            left_id = fake_id_list.getitem(RECU_ID) << 18
            # set the receiver's filter
            can_filters = [{"can_id": left_id, "can_mask": 0x1ffc0000, "extended": True}]
            bus.set_filters(can_filters)
            print(id_seed)
            # receive the message
            rx_msg = bus.recv()
            if rx_msg is None:
                continue

            right_id = rx_msg.arbitration_id - left_id
            if count == K - 1:
                next_chain_value_mac = computerMAC.computerMAC(bin(next_chain_value)[2:], groupAuthKey)
                if next_chain_value_mac != right_id:
                    continue
                receive_hash_value = next_chain_value
                next_chain_value = 0
            else:
                if not vertifyHC.vertify(right_id, groupAuthKey, receive_hash_value):
                    continue
                receive_hash_value = right_id

            enctext = encryption.aesEncrypt(groupEnKey, str(ctr))
            data_temp = int.from_bytes(rx_msg.data, byteorder='big', signed=False)
            enctext = enctext >> ((16 - rx_msg.dlc) * 8)
            enctext = enctext ^ data_temp
            last_bit = enctext % 2
            # print(last_bit)
            plaintext = enctext - last_bit
            rx_msg.data = transform.int_to_datalist(plaintext, rx_msg.dlc)
            rx_msg.data[rx_msg.dlc - 1] = rx_msg.data[rx_msg.dlc - 1] >> 1
            # print(rx_msg.data)
            id_seed = bin(rx_msg.data[2] + (rx_msg.data[3] << 8) + (rx_msg.data[4] << 16))[2:].zfill(K)
            fake_id_list = generateID(id_seed, 0, 25, groupAuthKey)
            with mutex:
                fake_id_update = True
            ctr = (ctr + 1) % 256
            count = (count + 1) % K
            next_chain_value = (next_chain_value << 1) + last_bit
        except KeyboardInterrupt:
            break
    print("Stopped receiving messages")


def main():
    old_seed = 22022
    new_seed = 35617
    reset_msg = can.Message(
        arbitration_id=0x00, data=[0, 0, 0, 0, 0, 0, 0, 0], is_extended_id=False
    )
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as bus:
        bus.send(reset_msg)
        # receive_thread = Thread(target=periodic_receive, args=(bus, 0,))
        # receive_thread.start()
        periodic_send(bus, 0, old_seed, new_seed)
        # receive_thread.join()
        bus.send(reset_msg)
    time.sleep(1)


if __name__ == '__main__':
    main()

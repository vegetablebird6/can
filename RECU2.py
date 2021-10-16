import can
from genID import generateID
import encryption
import transform
import computerMAC
import vertifyHC
import asyncio

# 0 为GECU，其他为普通ECU
RECU_ID = [0, 1]

SECU_ID = 2

K = 26

groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'

# 设定一个Flag
# leftidUpdate = True
# mutex = threading.Lock()


def print_message(msg):
    """Regular callback function. Can also be a coroutine."""
    print(msg)


async def receive(bus, ctr, rhv, nextclv_bit, id_seed):
    """The loop for receiving."""
    reader = can.AsyncBufferedReader()
    logger = can.Logger("logfile.asc")
    listeners = [
        # print_message,  # Callback function
        reader,  # AsyncBufferedReader() listener
        logger,  # Regular Listener object
    ]
    # Create Notifier with an explicit loop to use for scheduling of callbacks
    loop = asyncio.get_event_loop()
    notifier = can.Notifier(bus, listeners, loop=loop)
    # some known value
    fake_id_update = True
    count_list = []
    # next hash chain's last value
    nextclv = []
    num = len(RECU_ID)
    for i in range(num):
        count_list.append(0)
        nextclv.append(nextclv_bit[i])
    print("Start receiving messages")
    with open("plaintext.txt", "w") as file:
        while True:
            try:
                if fake_id_update:
                    fake_id_list = generateID(id_seed, 0, 25, groupAuthKey)

                    # with mutex:
                    #     leftidUpdate = False
                    fake_id_update = False

                    # choose the fake_id
                    fake_id = [fake_id_list.getitem(i) << 18 for i in RECU_ID]

                # set the receiver's filter
                can_filters = [{"can_id": i, "can_mask": 0x1ffc0000, "extended": True} for i in fake_id]
                bus.set_filters(can_filters)

                # receive the message
                msg = await reader.get_message()
                left_id = msg.arbitration_id & 0x1ffc0000
                right_id = msg.arbitration_id & 0x0003ffff
                dlc = msg.dlc
                data_temp = int.from_bytes(msg.data, byteorder='big', signed=False)
                m = (data_temp % 256)
                m0 = (right_id << 8) + m ^ 0x00
                m1 = (right_id << 8) + m ^ 0xff
                data_temp = data_temp // 256
                dlc = dlc - 1
                for i in range(num):
                    if left_id == fake_id[i]:
                        index = i
                        count = count_list[index]
                        break
                if count == K - 1:
                    nextCLVMAC = computerMAC.computerMAC(bin(nextclv[index])[2:], groupAuthKey)
                    if nextCLVMAC == m0:
                        single_bit = 0
                    elif nextCLVMAC == m1:
                        single_bit = 1
                    else:
                        continue
                    rhv[index] = nextclv[index]
                    nextclv[index] = 0
                else:
                    if vertifyHC.vertify(m0, groupAuthKey, rhv[index]):
                        single_bit = 0
                        chain_value = m0
                    elif vertifyHC.vertify(m1, groupAuthKey, rhv[index]):
                        single_bit = 1
                        chain_value = m1
                    else:
                        continue
                    rhv[index] = chain_value
                tempctr = ctr[index]
                enctext = encryption.aesEncrypt(groupEnKey, str(tempctr))
                enctext = enctext >> ((16 - dlc) * 8)
                plaintext = enctext ^ data_temp
                data = transform.int_to_datalist(plaintext, dlc)
                if index == 0:
                    id_seed = bin(data[2] + (data[3] << 8) + (data[4] << 16))[2:].zfill(K)
                    print(id_seed)
                    fake_id_update = True
                # print(data)
                for j in range(dlc):
                    file.write(hex(data[j])[2:].zfill(2))
                file.write('\n')
                ctr[index] = (tempctr + 1) % 256
                count_list[index] = (count + 1) % K
                nextclv[index] = (nextclv[index] << 1) + single_bit
            except KeyboardInterrupt:
                break
    notifier.stop()


if __name__ == "__main__":
    CTR = [0, 0]
    RHV = [233431, 9431269]
    nextCLV_bit = [0, 1]
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as BUS:
        asyncio.run(receive(BUS, CTR, RHV, nextCLV_bit, id_seed='110111111011111011'))

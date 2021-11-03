import can
from genID import generateID
import encryption
import transform
import computerMAC
import vertifyHC
import asyncio
from Crypto.Hash import SHA256

# 0 为GECU，其他为普通ECU
RECU_ID = [0, 1]

SECU_ID = 2

K = 25

groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'

# 设定一个Flag
# leftidUpdate = True
# mutex = threading.Lock()


def print_message(msg):
    """Regular callback function. Can also be a coroutine."""
    print(msg)


async def receive(bus, ctr, rhv, nextclv_bit, r, id_seed):
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
    index_source = []
    index = []

    # next hash chain's last value
    nextclv = []
    num = len(RECU_ID)
    for i in range(num):
        count_list.append(0)
        nextclv.append(nextclv_bit[i])
        index_source.append(int(SHA256.new(R[i].to_bytes(8, byteorder='big') + groupAuthKey).hexdigest(), 16))
        index.append(0)
    print("Start receiving messages")
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

            flag = False
            ECU_index = 0
            count = 0
            for i in range(num):
                if left_id == fake_id[i]:
                    ECU_index = i
                    count = count_list[ECU_index]
                    flag = True
                    break
            if not flag:
                continue
            index[ECU_index] = (index_source[ECU_index] & 0xff) % (dlc * 8)
            index_source[ECU_index] = index_source[ECU_index] >> 8
            temp = 1 << index[ECU_index]
            single_bit = (data_temp & temp) >> index[ECU_index]
            # print(single_bit)
            left_data = data_temp >> (index[ECU_index] + 1) << (index[ECU_index] + 1)
            right_data = data_temp & (temp - 1)
            data_temp = left_data + (right_data << 1)

            m = data_temp & 0xff
            hvalue = (right_id << 7) + (m >> 1)
            data_temp = data_temp // 256
            dlc = dlc - 1
            if count == K - 1:
                nextCLVMAC = computerMAC.computerMAC(bin(nextclv[ECU_index])[2:], groupAuthKey)
                if nextCLVMAC != hvalue:
                    continue
                rhv[ECU_index] = nextclv[ECU_index]
                nextclv[ECU_index] = 0
                r[ECU_index] = (r[ECU_index] + 1) % 256
                index_source[ECU_index] = SHA256.new(r[ECU_index].to_bytes(8, byteorder='big') + groupAuthKey)
                index_source[ECU_index] = int(index_source[ECU_index].hexdigest(), 16)
            else:
                if not vertifyHC.vertify(hvalue, groupAuthKey, rhv[ECU_index]):
                    continue
                rhv[ECU_index] = hvalue
            tempctr = ctr[ECU_index]
            enctext = encryption.aesEncrypt(groupEnKey, str(tempctr))
            enctext = enctext >> ((16 - dlc) * 8)
            plaintext = enctext ^ data_temp
            data = transform.int_to_datalist(plaintext, dlc)
            if ECU_index == 0:
                id_seed = bin(data[2] + (data[3] << 8) + (data[4] << 16) + (data[5] << 24))[2:].zfill(32)
                print(id_seed)
                fake_id_update = True
            print(count)
            for j in range(dlc):
                print(hex(data[j])[2:].zfill(2), end='')
            print()
            ctr[ECU_index] = (tempctr + 1) % 256
            count_list[ECU_index] = (count + 1) % K
            nextclv[ECU_index] = (nextclv[ECU_index] << 1) + single_bit
        except KeyboardInterrupt:
            break
    notifier.stop()


if __name__ == "__main__":
    CTR = [0, 0]
    RHV = [26425878, 1539600]
    R = [0, 0]
    nextCLV_bit = [0, 0]
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as BUS:
        asyncio.run(receive(BUS, CTR, RHV, nextCLV_bit, R, id_seed='110111111011111011'))

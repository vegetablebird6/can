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

K = 18

groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'

# 设定一个Flag
# leftidUpdate = True
# mutex = threading.Lock()


def print_message(msg):
    """Regular callback function. Can also be a coroutine."""
    print(msg)


async def receive(bus, ctr, rhv, nextclv_bit, idseed):
    """The loop for receiving."""
    reader = can.AsyncBufferedReader()
    logger = can.Logger("logfile.asc")
    listeners = [
        print_message,  # Callback function
        reader,  # AsyncBufferedReader() listener
        logger,  # Regular Listener object
    ]
    # Create Notifier with an explicit loop to use for scheduling of callbacks
    loop = asyncio.get_event_loop()
    notifier = can.Notifier(bus, listeners, loop=loop)
    # some known value
    leftidupdate = True
    countlist = []
    # next hash chain's last value
    nextclv = []
    num = len(RECU_ID)
    for i in range(num):
        countlist.append(0)
        nextclv.append(nextclv_bit[i])
    print("Start receiving messages")
    with open("plaintext.txt", "w") as file:
        while True:
            try:
                if leftidupdate:
                    fakeidlist = generateID(idseed, 0, 25, groupAuthKey)

                    # with mutex:
                    #     leftidUpdate = False
                    leftidupdate = False

                    # choose the fakeid
                    fakeid = [fakeidlist.getitem(i) << 18 for i in RECU_ID]

                # set the receiver's filter
                can_filters = [{"can_id": i, "can_mask": 0x1ffc0000, "extended": True} for i in fakeid]
                bus.set_filters(can_filters)

                # receive the message
                msg = await reader.get_message()
                leftid = msg.arbitration_id & 0x1ffc0000
                rightid = msg.arbitration_id & 0x0003ffff
                for i in range(num):
                    if leftid == fakeid[i]:
                        index = i
                        count = countlist[index]
                        break
                if count == K - 1:
                    nextCLVMAC = computerMAC.computerMAC(bin(nextclv[index])[2:], groupAuthKey)
                    if nextCLVMAC != rightid:
                        continue
                    rhv[index] = nextclv[index]
                    nextclv[index] = 0
                else:
                    if not vertifyHC.vertify(rightid, groupAuthKey, rhv[index]):
                        continue
                    rhv[index] = rightid
                tempctr = ctr[index]
                Enctext = encryption.aesEncrypt(groupEnKey, str(tempctr))
                data_temp = int.from_bytes(msg.data, byteorder='big', signed=False)
                Enctext = Enctext >> ((16 - msg.dlc) * 8)
                Enctext = Enctext ^ data_temp
                last_bit = Enctext % 2
                # print(last_bit)
                plaintext = Enctext - last_bit
                msg.data = transform.int_to_datalist(plaintext, msg.dlc)
                msg.data[msg.dlc - 1] = (msg.data[msg.dlc - 1] >> 1)
                if index == 0:
                    idseed = bin(msg.data[2] + (msg.data[3] << 8) + (msg.data[4] << 16))[2:]
                    print(idseed)
                    leftidupdate = True
                # print(msg.data)
                for j in range(msg.dlc):
                    file.write(str(msg.data[j]) + ' ')
                file.write('\n')
                ctr[index] = (tempctr + 1) % 256
                countlist[index] = (count + 1) % K
                nextclv[index] = (nextclv[index] << 1) + last_bit
            except KeyboardInterrupt:
                break
    notifier.stop()


if __name__ == "__main__":
    CTR = [0, 0]
    RHV = [233431, 60674]
    nextCLV_bit = [0, 1]
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as BUS:
        asyncio.run(receive(BUS, CTR, RHV, nextCLV_bit, idseed='110111111011111011'))

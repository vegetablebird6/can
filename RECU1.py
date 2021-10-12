import can
from genID import generateID
import encryption
import transform
import computerMAC
import vertifyHC
import asyncio

RECU_ID = 1
K = 18
SECU_ID = 2
groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'
idseed = '110111111011111011'


def print_message(msg):
    """Regular callback function. Can also be a coroutine."""
    print(msg)


async def receive(bus, ctr):
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
    count = 0
    RHV = 60674
    last_bit = 1
    # generate the leftid list
    leftidlist = generateID(idseed, 0, 25, groupAuthKey)
    # next hash chain's last value
    nextCLV = last_bit
    print("Start receiving messages")
    with open("plaintext.txt", "w") as file:
        while True:
            try:
                # choose the leftid
                leftid = leftidlist.getitem(RECU_ID) << 18
                # set the receiver's filter
                can_filters = [{"can_id": leftid, "can_mask": 0x1ffc0000, "extended": True}]
                bus.set_filters(can_filters)
                # receive the message
                msg = await reader.get_message()
                rightid = msg.arbitration_id - leftid
                # if
                if count == K - 1:
                    nextCLVMAC = computerMAC.computerMAC(bin(nextCLV)[2:], groupAuthKey)
                    if nextCLVMAC != rightid:
                        continue
                    RHV = nextCLV
                    nextCLV = 0
                else:
                    if not vertifyHC.vertify(rightid, groupAuthKey, RHV):
                        continue
                    RHV = rightid
                Enctext = encryption.aesEncrypt(groupEnKey, str(ctr))
                data_temp = int.from_bytes(msg.data, byteorder='big', signed=False)
                Enctext = Enctext >> ((16 - msg.dlc) * 8)
                Enctext = Enctext ^ data_temp
                last_bit = Enctext % 2
                # print(last_bit)
                plaintext = Enctext - last_bit
                msg.data = transform.int_to_datalist(plaintext, msg.dlc)
                msg.data[msg.dlc - 1] = (msg.data[msg.dlc - 1] >> 1)
                # print(msg.data)
                for j in range(msg.dlc):
                    file.write(str(msg.data[j]) + ' ')
                file.write('\n')
                ctr = (ctr + 1) % 256
                count = (count + 1) % K
                nextCLV = (nextCLV << 1) + last_bit
            except KeyboardInterrupt:
                break
    notifier.stop()


if __name__ == "__main__":
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as bus:
        asyncio.run(receive(bus, 0))
